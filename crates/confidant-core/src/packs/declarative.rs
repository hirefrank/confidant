//! Declarative pack rules: the evaluator and rule dispatch (#441).
//!
//! PD1: a declarative check is a **named rule kind** implemented once in
//! Rust, with typed parameters in the pack's manifest TOML. There is no
//! expression language and no WASM: the logic lives here; the manifest
//! only names, parameterizes and turns rules on/off.
//!
//! [`ExternalPack::findings`] (in `external.rs`) walks the manifest's
//! `[[rules]]` in manifest order, resolves each rule's severity through
//! the operator's `[checks]` config (a rule set `off` is skipped), and
//! dispatches to the kind's `evaluate`. A rule that panics fails closed:
//! it becomes one `E_PACK_INVALID` finding naming the rule id — pack
//! author text, the same trust level as the pack's message templates;
//! never the pack name (operator free text never echoes into findings)
//! and never the panic payload. Note the default panic hook still
//! prints panics to stderr; the guarantee here is about findings only.
//! `check` carries on either way.
//!
//! Everything here is `pub(crate)`: the trait and registry only run
//! inside `ExternalPack`'s findings, and `MergeGroups` — the merge view
//! rules share — is a crate-internal type, so the trait cannot be
//! public without leaking it. The public surface stays `Pack`.
//!
//! No filesystem, no network, no process execution: rules read what
//! `check` already loaded — ledger metadata and the pack's declared
//! plaintext front-matter fields — and emit findings only (PD8).

use std::panic::catch_unwind;
use std::sync::Mutex;

use chrono::NaiveDate;

use crate::check::{Finding, FindingCode, Severity};

use crate::config::parse_severity_token;
use crate::error::DomainError;
use crate::packs::grammars::parse_field_grammar;
use crate::packs::groups::MergeGroups;
use crate::packs::manifest::{PackManifest, RuleDecl};
use crate::vault::Vault;

/// What one rule evaluation sees. `merges` is the pack's merge view —
/// the same thing a compiled pack's rules use. Rules read plaintext
/// ledger metadata and the pack's own declared fields only (PD8/PD16).
/// `vault`/`merges`/`as_of`/`manifest` are read by the rule kinds as
/// they land (#442+); the skeleton's test kind only reads `severity`.
pub(crate) struct RuleCtx<'a> {
    #[allow(dead_code)]
    pub vault: &'a Vault,
    #[allow(dead_code)]
    pub merges: &'a MergeGroups,
    #[allow(dead_code)]
    pub as_of: NaiveDate,
    #[allow(dead_code)]
    pub manifest: &'a PackManifest,
    /// The rule's resolved severity (`off` rules never reach `evaluate`).
    #[allow(dead_code)] // read by the rule kinds as they land (#442+)
    pub severity: Severity,
}

/// One named rule kind: the single Rust implementation a manifest rule
/// dispatches to (PD1).
pub(crate) trait RuleKind: Send + Sync {
    /// The manifest's `kind` string, e.g. `"cadence-overdue"`.
    fn name(&self) -> &'static str;
    /// Kind-specific parameter validation, run at pack load so a bad
    /// pack fails closed before anything folds (the error becomes an
    /// `E_PACK_INVALID` `PackProblem`).
    fn validate(&self, rule: &RuleDecl, manifest: &PackManifest) -> Result<(), DomainError>;
    /// Evaluate the rule, appending findings. Panics are caught by the
    /// evaluator; never assume a clean exit path.
    fn evaluate(&self, ctx: &RuleCtx, rule: &RuleDecl, out: &mut Vec<Finding>);
    /// A kind with a fixed severity (never operator-tunable) returns it
    /// here; rules of such a kind omit `severity_key`. Default: none —
    /// every v1 kind's severity comes from `severity_key`.
    fn fixed_severity(&self) -> Option<Severity> {
        None
    }
}

/// Test-only rule registration (#441's acceptance needs a hook a test
/// kind can register through; production always sees the empty list).
static TEST_REGISTRY: Mutex<Option<Vec<&'static dyn RuleKind>>> = Mutex::new(None);

/// The registered rule kinds. Empty in #441: kinds arrive in their own
/// issues (#442, #443, #458, #446, #447, #448). Tests register via
/// [`with_rule_kinds_for_test`].
pub(crate) fn registered_rule_kinds() -> Vec<&'static dyn RuleKind> {
    TEST_REGISTRY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .map(std::vec::Vec::clone)
        .unwrap_or_default()
}

/// Look up a registered kind by manifest `kind` name.
pub(crate) fn rule_kind(kind: &str) -> Option<&'static dyn RuleKind> {
    registered_rule_kinds()
        .into_iter()
        .find(|k| k.name() == kind)
}

/// Run `f` with the given kinds registered (test-only). The registry is
/// swapped in for the call and always restored (drop guard), and a
/// separate mutex serializes tests that use it — `registered_rule_kinds`
/// must be able to lock while `f` runs, so the registry lock itself
/// cannot be held across `f`.
#[cfg(test)]
pub(crate) fn with_rule_kinds_for_test(kinds: Vec<&'static dyn RuleKind>, f: impl FnOnce()) {
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    {
        let mut guard = TEST_REGISTRY
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(guard.is_none(), "nested test registration is not supported");
        *guard = Some(kinds);
    }
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            *TEST_REGISTRY
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }
    }
    let _restore = Restore;
    f();
}

/// Resolve one rule's severity: the operator's `[checks]` override wins,
/// with the manifest's declared default as the fallback. `None` means
/// off: the rule is skipped entirely.
pub(crate) fn resolve_rule_severity(
    vault: &Vault,
    manifest: &PackManifest,
    rule: &RuleDecl,
) -> Option<Severity> {
    let Some(key) = &rule.severity_key else {
        return rule_kind(&rule.kind).and_then(|k| k.fixed_severity());
    };
    // The manifest loader (#435) guarantees a declared severity_key has
    // an `[[checks.severity]]` entry; be defensive anyway.
    let manifest_default = manifest
        .checks
        .severity
        .iter()
        .find(|s| s.key == *key)
        .and_then(|s| parse_severity_token(&s.default).ok())?;
    // The manifest default itself may be `off` (Ok(None)).
    manifest_default?;
    vault
        .config
        .checks
        .severity(key, manifest_default.expect("checked Some above"))
}

/// Validate one rule's params against its registered kind (PD1: the
/// logic lives in Rust; the loader refuses what a kind does not accept).
pub(crate) fn validate_rule(rule: &RuleDecl, manifest: &PackManifest) -> Result<(), DomainError> {
    let kind = rule_kind(&rule.kind).ok_or_else(|| {
        DomainError::config(format!(
            "rule '{}' has unknown rule kind '{}'",
            rule.id, rule.kind
        ))
        .with_fix("The kind is not implemented in this binary; see spec/pack-manifest.md")
    })?;
    // A rule with neither a declared severity key nor a kind-fixed
    // severity has no way to resolve: refuse at load.
    if rule.severity_key.is_none() && kind.fixed_severity().is_none() {
        return Err(DomainError::config(format!(
            "rule '{}' declares no severity_key and kind '{}' has no fixed severity",
            rule.id, rule.kind
        ))
        .with_fix(
            "Declare the key in [[checks.severity]] and set severity_key, or omit the rule",
        ));
    }
    kind.validate(rule, manifest)
}

/// Run one rule, panics converted to a fail-closed finding. The
/// finding names the rule id only: the pack name is operator free text
/// and must not echo (the #438/#494 privacy contract), the rule id is
/// pack-author text like the pack's message templates.
fn evaluate_catching_panic(
    kind: &'static dyn RuleKind,
    ctx: &RuleCtx,
    rule: &RuleDecl,
    out: &mut Vec<Finding>,
) {
    // A panic payload could carry anything; it is never unwrapped.
    let payload = catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut rule_findings = Vec::new();
        kind.evaluate(ctx, rule, &mut rule_findings);
        rule_findings
    }));
    match payload {
        Ok(rule_findings) => out.extend(rule_findings),
        Err(_) => out.push(
            Finding::new(
                FindingCode::PackInvalid,
                Severity::Error,
                format!("a rule ('{}') panicked and was not run", rule.id),
            )
            .at_file("confidant.toml")
            .with_fix("Report the pack issue to its author; remove the rule from the manifest"),
        ),
    }
}

/// The evaluator's two phases for one external pack, called from
/// `ExternalPack::findings` (manifest order, deterministic):
/// 1. field-grammar validation over person records,
/// 2. rule dispatch.
pub(crate) fn run(
    vault: &Vault,
    merges: &MergeGroups,
    as_of: NaiveDate,
    manifest: &PackManifest,
    out: &mut Vec<Finding>,
) {
    validate_declared_fields(vault, manifest, out);
    for rule in &manifest.rules {
        let Some(kind) = rule_kind(&rule.kind) else {
            // The loader rejects unknown kinds; this is defense in depth
            // for a manifest that changed under a running process.
            continue;
        };
        let Some(severity) = resolve_rule_severity(vault, manifest, rule) else {
            continue; // off (operator config or the manifest default)
        };
        let ctx = RuleCtx {
            vault,
            merges,
            as_of,
            manifest,
            severity,
        };
        evaluate_catching_panic(kind, &ctx, rule, out);
    }
}

/// Field grammar validation for an external pack (#441): every declared
/// `[[fields]]` entry is validated on every `person` record, exactly
/// like the compiled `personal@0.1` does. Messages come from the pack's
/// own `[messages."E_FRONTMATTER"]` template (loader guarantees the
/// pack declares it when it declares fields).
fn validate_declared_fields(vault: &Vault, manifest: &PackManifest, out: &mut Vec<Finding>) {
    if manifest.fields.is_empty() {
        return;
    }
    let mut records: Vec<&crate::record::Record> = vault.records.values().collect();
    records.sort_by(|a, b| a.id.cmp(&b.id));
    for rec in records {
        if rec.kind != crate::record::RecordKind::Person {
            continue;
        }
        for field in &manifest.fields {
            let Some(raw) = rec.field(&field.name) else {
                continue;
            };
            if parse_field_grammar(&field.grammar, field.name.as_str(), raw).is_some() {
                continue;
            }
            push_external_field_error(rec, manifest, &field.name, out);
        }
    }
}

/// `E_FRONTMATTER` with the pack's own message template.
fn push_external_field_error(
    rec: &crate::record::Record,
    manifest: &PackManifest,
    key: &str,
    out: &mut Vec<Finding>,
) {
    let msg = manifest.render_message(
        "E_FRONTMATTER",
        "default",
        &[
            ("key", &key),
            ("problem", &"does not match its declared grammar"),
        ],
    );
    let fix = manifest
        .render_fix(
            "E_FRONTMATTER",
            "default",
            &[("fix", &"Fix the value or remove the key")],
        )
        .unwrap_or_else(|| "Fix the value or remove the key".to_owned());
    let mut finding = Finding::new(FindingCode::Frontmatter, Severity::Error, msg)
        .at_file(&rec.path)
        .for_id(&rec.id)
        .with_fix(fix);
    if let Some(line) = rec.field_lines.get(key) {
        finding = finding.at_line(*line);
    }
    out.push(finding);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_vault;
    use crate::packs::manifest::parse_manifest_external;
    use crate::record::RecordKind;
    use std::collections::HashMap;

    /// A test rule kind: emits one finding tagged with the rule id, or
    /// panics.
    struct TestKind {
        name: &'static str,
        panic_on_evaluate: bool,
    }

    impl TestKind {
        fn leaked(name: &'static str) -> &'static dyn RuleKind {
            Box::leak(Box::new(TestKind {
                name,
                panic_on_evaluate: false,
            }))
        }
        fn leaked_panic(name: &'static str) -> &'static dyn RuleKind {
            Box::leak(Box::new(TestKind {
                name,
                panic_on_evaluate: true,
            }))
        }
    }

    impl RuleKind for TestKind {
        fn name(&self) -> &'static str {
            self.name
        }
        fn validate(&self, _rule: &RuleDecl, _manifest: &PackManifest) -> Result<(), DomainError> {
            Ok(())
        }
        fn evaluate(&self, ctx: &RuleCtx, rule: &RuleDecl, out: &mut Vec<Finding>) {
            if self.panic_on_evaluate {
                panic!("SENTINEL-TEST-PANIC");
            }
            out.push(
                Finding::new(
                    FindingCode::Pack("W_TEST_KIND_CODE"),
                    ctx.severity,
                    format!("rule {}", rule.id),
                )
                .at_file("confidant.toml"),
            );
        }
    }

    pub(super) fn as_of() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 8).unwrap()
    }

    /// Manifest with one `[[rules]]` entry of the given kind.
    fn manifest_with_rules(rules_toml: &str) -> PackManifest {
        let text = format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_TEST_KIND_CODE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[checks.severity]]
key = "example-pack.test_rule"
default = "warning"

{rules}

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"

[messages."W_TEST_KIND_CODE"]
default = "test rule"
"#,
            rules = rules_toml
        );
        parse_manifest_external(&text).expect("fixture manifest should parse")
    }

    /// A vault fixture: confidant.toml with `[checks]` overrides, a
    /// person record with an optional extra field.
    fn fixture_vault(operator_checks: &str, person_extra: Option<&str>) -> Vault {
        let dir = tempfile::tempdir().unwrap();
        let extra = person_extra.unwrap_or("");
        std::fs::create_dir_all(dir.path().join("people/p-01J9Z3K4QF0000000000000000")).unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            format!(
                "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-08\"\n{operator_checks}\n"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path()
                .join("people/p-01J9Z3K4QF0000000000000000/profile.md"),
            format!(
                "---\nid: p-01J9Z3K4QF0000000000000000\ntype: person\nname: Ada Example{extra}\n---\n\nFake person.\n"
            ),
        )
        .unwrap();
        // `dir` drops at the end of this function, removing the vault
        // files: harmless — `load_vault` reads everything into memory
        // before returning, and the tests only read the loaded vault.
        load_vault(dir.path()).expect("fixture vault should load")
    }

    pub(super) fn empty_merges() -> MergeGroups {
        MergeGroups::new(HashMap::new())
    }

    #[test]
    fn dispatch_runs_rules_in_manifest_order() {
        crate::packs::declarative::with_rule_kinds_for_test(
            vec![TestKind::leaked("test-rule")],
            || {
                // Parse inside the hook: the kind list must be live.
                let manifest = manifest_with_rules(
                    "[[rules]]\nid = \"rule_b\"\nkind = \"test-rule\"\ncode = \"W_TEST_KIND_CODE\"\nseverity_key = \"example-pack.test_rule\"\n\n[[rules]]\nid = \"rule_a\"\nkind = \"test-rule\"\ncode = \"W_TEST_KIND_CODE\"\nseverity_key = \"example-pack.test_rule\"\n",
                );
                let vault = fixture_vault("", None);
                let mut out = Vec::new();
                run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
                // The manifest lists rule_b before rule_a: findings
                // follow manifest order, not id order.
                assert_eq!(out.len(), 2, "both rules ran: {out:?}");
                let messages: Vec<&String> = out.iter().map(|f| &f.message).collect();
                assert!(
                    messages[0].contains("rule_b") && messages[1].contains("rule_a"),
                    "expected manifest order: {out:?}"
                );
            },
        );
    }

    #[test]
    fn rule_severity_off_skips_rule() {
        crate::packs::declarative::with_rule_kinds_for_test(
            vec![TestKind::leaked("test-rule")],
            || {
                let manifest = manifest_with_rules(
                    "[[rules]]\nid = \"my_rule\"\nkind = \"test-rule\"\ncode = \"W_TEST_KIND_CODE\"\nseverity_key = \"example-pack.test_rule\"\n",
                );
                let vault = fixture_vault("example-pack.test_rule = \"off\"\n", None);
                let mut out = Vec::new();
                run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
                assert!(out.is_empty(), "an off rule must not run: {out:?}");
            },
        );
    }

    #[test]
    fn rule_severity_error_vs_warning_from_config() {
        crate::packs::declarative::with_rule_kinds_for_test(
            vec![TestKind::leaked("test-rule")],
            || {
                let manifest = manifest_with_rules(
                    "[[rules]]\nid = \"my_rule\"\nkind = \"test-rule\"\ncode = \"W_TEST_KIND_CODE\"\nseverity_key = \"example-pack.test_rule\"\n",
                );
                // No operator override: the manifest default (warning).
                let vault = fixture_vault("", None);
                let mut out = Vec::new();
                run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
                assert_eq!(out[0].severity, Severity::Warning, "{out:?}");

                // Operator override: error.
                let vault = fixture_vault("example-pack.test_rule = \"error\"\n", None);
                let mut out = Vec::new();
                run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
                assert_eq!(out[0].severity, Severity::Error, "{out:?}");
            },
        );
    }

    #[test]
    fn unknown_kind_rejected_by_loader() {
        // "nope" is not a registered kind: the manifest loader refuses
        // the pack (the fixture is otherwise valid TOML, so this really
        // is the kind check firing).
        let err = parse_manifest_external(&manifest_with_rules_text_kind("nope"))
            .expect_err("unknown kind must be refused");
        assert!(err.to_string().contains("unknown rule kind"), "{err:?}");
    }

    fn manifest_with_rules_text_kind(kind: &str) -> String {
        format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_TEST_KIND_CODE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[rules]]
id = "my_rule"
kind = "{kind}"
code = "W_TEST_KIND_CODE"
severity_key = "example-pack.test_rule"

[[checks.severity]]
key = "example-pack.test_rule"
default = "warning"

[messages."E_FRONTMATTER"]
default = "front matter key '{{key}}' {{problem}}"
default_fix = "{{fix}}"

[messages."W_TEST_KIND_CODE"]
default = "test rule"
"#
        )
    }

    #[test]
    fn known_rule_kinds_match_manifest_list() {
        crate::packs::declarative::with_rule_kinds_for_test(
            vec![
                TestKind::leaked("test-rule"),
                TestKind::leaked("other-rule"),
            ],
            || {
                let names = crate::packs::manifest::known_rule_kinds();
                assert_eq!(names, vec!["test-rule", "other-rule"]);
            },
        );
        // Outside the hook the list is empty. Run this inside an
        // empty-kinds hook: it holds the serial lock, so no parallel
        // test can have kinds registered while we assert.
        crate::packs::declarative::with_rule_kinds_for_test(vec![], || {
            assert!(crate::packs::manifest::known_rule_kinds().is_empty());
        });
    }

    #[test]
    fn field_grammar_error_reported_as_e_frontmatter() {
        // A manifest declaring a cadence field (no rules).
        let text = r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_TEST_KIND_CODE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[fields]]
name = "cadence"
grammar = "cadence"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"

[messages."W_TEST_KIND_CODE"]
default = "test rule"
"#;
        let manifest = parse_manifest_external(text).unwrap();
        let vault = fixture_vault("", Some("\ncadence: soon"));
        let mut out = Vec::new();
        run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].code, FindingCode::Frontmatter);
        assert!(
            out[0].message.contains("front matter key 'cadence'"),
            "message from the pack's template: {out:?}"
        );
    }

    #[test]
    fn field_grammar_valid_values_no_finding() {
        let text = r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "W_TEST_KIND_CODE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[fields]]
name = "cadence"
grammar = "cadence"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"

[messages."W_TEST_KIND_CODE"]
default = "test rule"
"#;
        let manifest = parse_manifest_external(text).unwrap();
        let vault = fixture_vault("", Some("\ncadence: 30d"));
        let mut out = Vec::new();
        run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
        assert!(out.is_empty(), "valid value must not report: {out:?}");
    }

    #[test]
    fn panicking_rule_becomes_pack_invalid_finding() {
        crate::packs::declarative::with_rule_kinds_for_test(
            vec![TestKind::leaked_panic("test-rule")],
            || {
                let manifest = manifest_with_rules(
                    "[[rules]]\nid = \"my_rule\"\nkind = \"test-rule\"\ncode = \"W_TEST_KIND_CODE\"\nseverity_key = \"example-pack.test_rule\"\n",
                );
                let vault = fixture_vault("", None);
                let mut out = Vec::new();
                run(&vault, &empty_merges(), as_of(), &manifest, &mut out);
                assert_eq!(out.len(), 1, "{out:?}");
                assert_eq!(out[0].code, FindingCode::PackInvalid);
                assert!(
                    !format!("{:?}", out).contains("SENTINEL-TEST-PANIC"),
                    "panic payload must never surface: {out:?}"
                );
            },
        );
    }

    #[test]
    fn pack_code_maps_to_enum_variant_when_equal() {
        // Only E_FRONTMATTER is accepted as a builtin emission claim
        // (the spec example's); other builtins stay refused (PD13,
        // #494 review).
        use std::sync::OnceLock;
        static S1: OnceLock<&'static str> = OnceLock::new();
        let s1 = S1.get_or_init(|| Box::leak("E_FRONTMATTER".to_owned().into_boxed_str()));
        assert_eq!(
            FindingCode::from_pack_str_or_builtin(s1).unwrap(),
            FindingCode::Frontmatter
        );
        static S3: OnceLock<&'static str> = OnceLock::new();
        let s3 = S3.get_or_init(|| Box::leak("W_CADENCE_OVERDUE".to_owned().into_boxed_str()));
        assert!(FindingCode::from_pack_str_or_builtin(s3).is_err());
        static S2: OnceLock<&'static str> = OnceLock::new();
        let s2 = S2.get_or_init(|| Box::leak("W_EXAMPLE_THING".to_owned().into_boxed_str()));
        assert_eq!(
            FindingCode::from_pack_str_or_builtin(s2).unwrap(),
            FindingCode::Pack("W_EXAMPLE_THING")
        );
    }

    #[test]
    fn fixtures_use_person_kind() {
        // Guard the fixture's shape: the person record is a person.
        let vault = fixture_vault("", None);
        assert!(vault.records.values().all(|r| r.kind == RecordKind::Person));
    }
}
