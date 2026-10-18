//! Pack manifest types, parser, and validation (`spec/pack-manifest.md`).
//!
//! Step 2 of #295: the types and loader for `packs/<name>/manifest.toml`.
//! Nothing loads a manifest yet and no pack reads its claims from one, so
//! this changes no behaviour. Steps 4-5 wire the packs up; step 6
//! generalizes the drift test against these types.
//!
//! The loader is strict: unknown keys are an error (a typo fails loudly
//! rather than silently doing nothing), and every semantic rule in the
//! spec's schema section is checked.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::check::FindingCode;
use crate::error::DomainError;
use crate::id::Prefix;

/// Schema version this loader implements (`manifest_version` in the file).
/// A file declaring any other version is rejected rather than guessed at.
pub const MANIFEST_VERSION: u32 = 1;

/// Schema version for external pack manifests (`manifest_version = 2`).
/// Parsed by [`parse_manifest_external`]; `parse_manifest` (v1, compiled)
/// still rejects 2.
pub const MANIFEST_VERSION_V2: u32 = 2;

/// Rule kinds an external pack may declare (`[[rules]]`). Derived from
/// the evaluator's registered kinds (#441) so the manifest's list and
/// what actually runs cannot drift. Starts empty; each kind's own issue
/// appends its kind to `rule_kinds()` (PD1). Until a kind lands, any
/// `[[rules]]` entry is rejected as an unknown kind.
pub fn known_rule_kinds() -> Vec<&'static str> {
    crate::packs::declarative::registered_rule_kinds()
        .iter()
        .map(|k| k.name())
        .collect()
}

/// Core ledger verbs no external pack may claim (PD8 rule 1).
const CORE_VERBS_V2: &[&str] = &["alias", "merge", "stage", "balance", "touch"];

/// Core record types no external pack may claim (PD8 rule 2).
const CORE_RECORD_TYPES: &[&str] = &["person", "org", "deal", "interaction", "note", "edge"];

/// Pack names reserved for the compiled packs (PD14).
const RESERVED_PACK_NAMES: &[&str] = &["coaching", "personal"];

/// Check a pack name against the v2 grammar `^[a-z][a-z0-9-]{1,31}$`.
/// PD14: an external pack name matches `^[a-z][a-z0-9-]{1,31}$` (2..32
/// chars, lowercase start). Used by the manifest loader and by the
/// lockfile (#437).
pub(crate) fn is_valid_pack_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    // 2..32 chars total: first is [a-z], rest are [a-z0-9-].
    if bytes.len() < 2 || bytes.len() > 32 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Check a rule id against `^[a-z][a-z0-9_]*$`.
fn is_valid_rule_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Field grammars a manifest may name (spec §6). Canonical list lives in
/// [`grammars`](crate::packs::grammars); re-exported here so the loader's
/// validation reads the same frozen list the parser registry dispatches.
pub use crate::packs::grammars::KNOWN_GRAMMARS;

/// Record ID types a verb may constrain its ledger ID to (spec §4,
/// today's `Prefix`).
const KNOWN_ID_TYPES: &[(&str, Prefix)] = &[
    ("person", Prefix::Person),
    ("org", Prefix::Org),
    ("deal", Prefix::Deal),
    ("interaction", Prefix::Interaction),
    ("note", Prefix::Note),
    ("edge", Prefix::Edge),
    ("package", Prefix::Package),
];

/// Severity values a `[checks]` severity default may take.
const KNOWN_SEVERITIES: &[&str] = &["error", "warning", "off"];

fn manifest_err(message: impl Into<String>) -> DomainError {
    DomainError::config(message).with_file("manifest.toml")
}

/// The `[pack]` table: identity and skill-text reference.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackInfo {
    /// Short pack name, e.g. `"personal"`. The full name is
    /// `"{name}@{version}"`, matching today's `Pack::name()`.
    pub name: String,
    /// Pack version, e.g. `"0.1"`.
    pub version: String,
    /// Skill text path relative to the pack directory, today `"SKILL.md"`.
    /// Referenced, never duplicated.
    pub skill: String,
    /// Exact spec versions this pack supports (v2 only). Absent in v1
    /// files; v2 requires it non-empty with each entry non-empty.
    #[serde(default)]
    pub requires_spec: Vec<String>,
}

/// Parse an `id_type` name (`person`, `org`, …) into a [`Prefix`].
/// The derived `Deserialize` on `Prefix` expects variant names, not the
/// manifest's lowercase names, so this is wired via `deserialize_with`.
fn deserialize_id_type<'de, D>(deserializer: D) -> Result<Option<Prefix>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    KNOWN_ID_TYPES
        .iter()
        .find(|(name, _)| *name == s)
        .map(|(_, prefix)| Some(*prefix))
        .ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown id_type '{s}'; expected one of: {}",
                KNOWN_ID_TYPES
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

/// One `[[verbs]]` entry: a ledger verb the pack owns.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerbDecl {
    pub name: String,
    /// The verb-to-ID-type claim (today's `verb_id_type`); `None` for
    /// verbs with no ID-type claim.
    #[serde(default, deserialize_with = "deserialize_id_type")]
    pub id_type: Option<Prefix>,
}

/// One `[[fields]]` entry: a front-matter field the pack owns.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FieldDecl {
    pub name: String,
    /// Names one of [`KNOWN_GRAMMARS`]; Rust supplies the parser.
    pub grammar: String,
}

/// One `[[edge_kinds]]` entry: an edge kind the pack introduces.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdgeKindDecl {
    pub name: String,
    pub symmetric: bool,
}

/// One `[[checks.severity]]` entry.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeverityCheck {
    /// Namespaced `<pack-name>.<rule>`, e.g. `"personal.cadence_overdue"`.
    pub key: String,
    /// One of `error`, `warning`, `off`.
    pub default: String,
}

/// One `[[checks.int]]` entry.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IntCheck {
    /// Namespaced `<pack-name>.<rule>`.
    pub key: String,
    pub default: i64,
}

/// One `[[rules]]` entry (v2 only): a named invocation of a rule kind.
/// The kind-specific parameters are kept raw in `params`; each kind's
/// own issue validates them. No `deny_unknown_fields` here: `params`
/// flattens every key the named fields don't claim, so an unknown key —
/// a typo of a generic key included (`severity_kye`, `cod`) — lands in
/// `params` instead of failing to deserialize. A *missing* generic key
/// still fails, the manifest parser only checks the fixed generic keys,
/// and each rule kind must validate its own `params` strictly.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct RuleDecl {
    /// Unique within the pack; matches `^[a-z][a-z0-9_]*$`.
    pub id: String,
    /// One of [`KNOWN_RULE_KINDS`].
    pub kind: String,
    /// The finding code this rule emits; must be in `finding_codes`.
    pub code: String,
    /// Optional declared `[[checks.severity]]` key (full namespaced key).
    /// Kinds with a fixed severity omit it.
    #[serde(default)]
    pub severity_key: Option<String>,
    /// Kind-specific parameters, kept raw.
    #[serde(flatten)]
    pub params: toml::Table,
}

/// The `[checks]` table: keys this pack owns, with defaults.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChecksDecl {
    #[serde(default)]
    pub severity: Vec<SeverityCheck>,
    #[serde(default)]
    pub int: Vec<IntCheck>,
}

/// A parsed and validated pack manifest. All names are owned strings;
/// steps 4-5 compare these against the compiled `&'static` slices.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackManifest {
    /// Schema version of the file; must equal [`MANIFEST_VERSION`].
    pub manifest_version: u32,
    /// Record types this pack owns (empty for both packs today).
    pub record_types: Vec<String>,
    /// Balance metrics this pack's fold computes.
    pub balance_metrics: Vec<String>,
    /// Finding codes this pack's fold/findings can emit. Must match the
    /// `[messages]` keys exactly.
    pub finding_codes: Vec<String>,
    pub pack: PackInfo,
    /// Verbs this pack owns. Empty when the pack owns none.
    #[serde(default)]
    pub verbs: Vec<VerbDecl>,
    /// Front-matter fields this pack owns. Empty when the pack owns none.
    #[serde(default)]
    pub fields: Vec<FieldDecl>,
    /// Edge kinds this pack introduces. Empty when the pack owns none.
    #[serde(default)]
    pub edge_kinds: Vec<EdgeKindDecl>,
    #[serde(default)]
    pub checks: ChecksDecl,
    /// Declarative rules (v2 only). Empty for v1 and for v2 packs that
    /// declare none yet.
    #[serde(default)]
    pub rules: Vec<RuleDecl>,
    /// Finding message and fix templates, one table per code:
    /// `messages[code][variant] = template`. Every code in
    /// `finding_codes` needs a table with at least one variant, and every
    /// table key must be in `finding_codes`.
    pub messages: BTreeMap<String, BTreeMap<String, String>>,
}

/// Check one message template: `{placeholder}` substitution only — no
/// conditionals, no expressions, no filters. Braces must balance and
/// placeholders must be non-empty plain identifiers.
fn check_template(template: &str) -> Result<(), String> {
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c == '{' {
            let mut name = String::new();
            let mut closed = false;
            for c in chars.by_ref() {
                if c == '}' {
                    closed = true;
                    break;
                }
                if c == '{' {
                    return Err("nested '{' inside a placeholder".to_string());
                }
                name.push(c);
            }
            if !closed {
                return Err("unclosed '{'".to_string());
            }
            if name.is_empty() {
                return Err("empty placeholder '{}'".to_string());
            }
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!(
                    "placeholder '{{{name}}}' is not a plain identifier"
                ));
            }
        } else if c == '}' {
            return Err("unmatched '}'".to_string());
        }
    }
    Ok(())
}

fn check_unique(names: &[String], what: &str) -> Result<(), DomainError> {
    let mut seen = BTreeSet::new();
    for name in names {
        if name.trim().is_empty() {
            return Err(manifest_err(format!("{what} names must be non-empty"))
                .with_fix("Remove the empty entry or give it a name"));
        }
        if !seen.insert(name) {
            return Err(manifest_err(format!("duplicate {what} name '{name}'"))
                .with_fix("Each name may be declared only once"));
        }
    }
    Ok(())
}

impl PackManifest {
    fn validate(&self) -> Result<(), DomainError> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(manifest_err(format!(
                "manifest_version {} is not supported (this loader implements {})",
                self.manifest_version, MANIFEST_VERSION
            ))
            .with_fix("Set manifest_version = 1 or upgrade the CLI"));
        }

        self.validate_common()
    }

    /// Validate an external (v2) pack manifest: the v2 schema from #431
    /// plus the capability limits (PD8). Called by
    /// [`parse_manifest_external`]; the finding wrapper (`E_PACK_INVALID`)
    /// comes in #438, so errors here are `DomainError::config`.
    fn validate_external(&self) -> Result<(), DomainError> {
        if self.manifest_version != MANIFEST_VERSION_V2 {
            return Err(manifest_err(format!(
                "manifest_version {} is not an external pack manifest (this loader expects {})",
                self.manifest_version, MANIFEST_VERSION_V2
            ))
            .with_fix("Set manifest_version = 2 for external packs"));
        }

        // PD14: name grammar and reserved names.
        if !is_valid_pack_name(&self.pack.name) {
            return Err(manifest_err(format!(
                "[pack].name '{}' is not a valid external pack name (must match ^[a-z][a-z0-9-]{{1,31}}$)",
                self.pack.name
            ))
            .with_fix("Use a lowercase name with dashes, e.g. name = \"example-pack\""));
        }
        if RESERVED_PACK_NAMES.contains(&self.pack.name.as_str()) {
            return Err(manifest_err(format!(
                "[pack].name '{}' is reserved for a compiled pack",
                self.pack.name
            ))
            .with_fix("Choose a different pack name"));
        }

        // PD11: requires_spec is required in v2, non-empty, each entry non-empty.
        if self.pack.requires_spec.is_empty() {
            return Err(
                manifest_err("[pack].requires_spec must be non-empty for external packs").with_fix(
                    "List the spec versions this pack supports, e.g. requires_spec = [\"0.1\"]",
                ),
            );
        }
        for spec in &self.pack.requires_spec {
            if spec.trim().is_empty() {
                return Err(
                    manifest_err("[pack].requires_spec entries must be non-empty")
                        .with_fix("Remove the empty entry or give it a spec version"),
                );
            }
        }

        // PD13: every finding_codes entry must pass the shape and collision
        // rules. Leak once at load time (same Box::leak pattern as #434).
        // A builtin code is allowed as an *emission claim* (#441): the v2
        // spec example (spec/pack-manifest.md §2) lists `E_FRONTMATTER`
        // this way, with the pack supplying only a template shell.
        for code in &self.finding_codes {
            let leaked: &'static str = Box::leak(code.clone().into_boxed_str());
            FindingCode::from_pack_str_or_builtin(leaked).map_err(|e| {
                manifest_err(format!("finding code '{code}' is invalid: {e}")).with_fix(
                    "Codes must match ^[EW]_[A-Z0-9_]{2,40}$; a pack-own code must not collide with an existing code",
                )
            })?;
        }

        // PD8 rule 1: no core verbs.
        for verb in &self.verbs {
            if CORE_VERBS_V2.contains(&verb.name.as_str()) {
                return Err(manifest_err(format!(
                    "verb '{}' is a core verb and cannot be claimed by an external pack",
                    verb.name
                ))
                .with_fix("Remove the verb or choose a different name"));
            }
        }

        // PD8 rule 2: no core record types.
        for record_type in &self.record_types {
            if CORE_RECORD_TYPES.contains(&record_type.as_str()) {
                return Err(manifest_err(format!(
                    "record type '{record_type}' is a core record type and cannot be claimed by an external pack",
                ))
                .with_fix("Remove the record type or choose a different name"));
            }
        }

        // PD8 rule 3: no core edge kinds.
        for edge_kind in &self.edge_kinds {
            if crate::packs::CORE_EDGE_KINDS
                .iter()
                .any(|k| k.name == edge_kind.name)
            {
                return Err(manifest_err(format!(
                    "edge kind '{}' is a core edge kind and cannot be claimed by an external pack",
                    edge_kind.name
                ))
                .with_fix("Remove the edge kind or choose a different name"));
            }
        }

        // PD8 rule 4 is covered by the from_pack_str collision check above.

        // Skill path must be a plain file name (no `/`, no `..`).
        if self.pack.skill.contains('/') || self.pack.skill.contains("..") {
            return Err(manifest_err(format!(
                "[pack].skill '{}' must be a plain file name (no `/`, no `..`)",
                self.pack.skill
            ))
            .with_fix("Use a plain file name like skill = \"SKILL.md\""));
        }

        // Rules validation: IDs first (validity + uniqueness), then the
        // per-rule checks. The ID pass runs separately so duplicate IDs are
        // caught even though KNOWN_RULE_KINDS is empty (kind check would
        // fire first otherwise).
        let mut seen_rule_ids = BTreeSet::new();
        for rule in &self.rules {
            if !is_valid_rule_id(&rule.id) {
                return Err(manifest_err(format!(
                    "rule id '{}' is not valid (must match ^[a-z][a-z0-9_]*$)",
                    rule.id
                ))
                .with_fix("Use a lowercase id with underscores, e.g. id = \"my_rule\""));
            }
            if !seen_rule_ids.insert(&rule.id) {
                return Err(manifest_err(format!("duplicate rule id '{}'", rule.id))
                    .with_fix("Each rule id may be declared only once"));
            }
        }
        let severity_keys: BTreeSet<&str> = self
            .checks
            .severity
            .iter()
            .map(|s| s.key.as_str())
            .collect();
        for rule in &self.rules {
            // A rule's code must be a pack-own code (#494 review): a
            // builtin as a rule's code would let a pack emit core
            // security findings with a re-worded meaning.
            if FindingCode::is_builtin_code(&rule.code) {
                return Err(manifest_err(format!(
                    "rule '{}' emits builtin code '{}'; a rule's code must be a pack-own code",
                    rule.id, rule.code
                ))
                .with_fix(
                    "Declare a pack-own code (e.g. W_<PACK>_<RULE>) in finding_codes and use it",
                ));
            }
            if !known_rule_kinds().contains(&rule.kind.as_str()) {
                return Err(manifest_err(format!(
                    "rule '{}' has unknown rule kind '{}'",
                    rule.id, rule.kind
                ))
                .with_fix("The kind list is empty until a kind issue adds its name"));
            }
            if !self.finding_codes.contains(&rule.code) {
                return Err(manifest_err(format!(
                    "rule '{}' emits code '{}' which is not in finding_codes",
                    rule.id, rule.code
                ))
                .with_fix("Add the code to finding_codes or use a declared code"));
            }
            if let Some(key) = &rule.severity_key {
                if !severity_keys.contains(key.as_str()) {
                    return Err(manifest_err(format!(
                        "rule '{}' names undeclared severity_key '{}'",
                        rule.id, key
                    ))
                    .with_fix("Declare the key in [[checks.severity]] or omit severity_key"));
                }
            }
        }

        // Fields: validating declared fields emits `E_FRONTMATTER`
        // through the pack's own message template (#441), so a pack that
        // declares fields must declare that code and template.
        if !self.fields.is_empty() && !self.finding_codes.iter().any(|c| c == "E_FRONTMATTER") {
            return Err(manifest_err(
                "a pack that declares fields must list E_FRONTMATTER in finding_codes",
            )
            .with_fix(
                "Add \"E_FRONTMATTER\" to finding_codes and a [messages.\"E_FRONTMATTER\"] table with a `default` variant",
            ));
        }

        self.validate_common()
    }

    fn validate_common(&self) -> Result<(), DomainError> {
        if self.pack.name.trim().is_empty() {
            return Err(manifest_err("[pack].name must be non-empty")
                .with_fix("Set the pack's short name, e.g. name = \"personal\""));
        }
        if self.pack.name.contains('@') {
            return Err(manifest_err(format!(
                "[pack].name '{}' must not contain '@'; the version goes in [pack].version",
                self.pack.name
            )));
        }
        if self.pack.version.trim().is_empty() {
            return Err(manifest_err("[pack].version must be non-empty")
                .with_fix("Set the pack version, e.g. version = \"0.1\""));
        }
        if self.pack.version.contains('@') {
            return Err(manifest_err(
                "[pack].version must not contain '@'; the full name is \"{name}@{version}\"",
            ));
        }
        if self.pack.skill.trim().is_empty() {
            return Err(manifest_err("[pack].skill must be non-empty")
                .with_fix("Reference the skill text, e.g. skill = \"SKILL.md\""));
        }

        check_unique(&self.record_types, "record type")?;
        check_unique(&self.balance_metrics, "balance metric")?;
        check_unique(&self.finding_codes, "finding code")?;

        let verb_names: Vec<String> = self.verbs.iter().map(|v| v.name.clone()).collect();
        check_unique(&verb_names, "verb")?;
        let field_names: Vec<String> = self.fields.iter().map(|f| f.name.clone()).collect();
        check_unique(&field_names, "field")?;
        for field in &self.fields {
            if !KNOWN_GRAMMARS.contains(&field.grammar.as_str()) {
                return Err(manifest_err(format!(
                    "field '{}' names unknown grammar '{}'; expected one of: {}",
                    field.name,
                    field.grammar,
                    KNOWN_GRAMMARS.join(", ")
                ))
                .with_fix("Adding a grammar is a spec change plus a Rust parser — never a manifest-only change"));
            }
        }
        let edge_names: Vec<String> = self.edge_kinds.iter().map(|e| e.name.clone()).collect();
        check_unique(&edge_names, "edge kind")?;

        // [checks] keys are namespaced <pack-name>.<rule>; a pack may only
        // declare keys under its own name. `as_of` stays core-owned.
        let prefix = format!("{}.", self.pack.name);
        for entry in self
            .checks
            .severity
            .iter()
            .map(|s| &s.key)
            .chain(self.checks.int.iter().map(|i| &i.key))
        {
            if !entry.starts_with(&prefix) || entry.len() == prefix.len() {
                return Err(manifest_err(format!(
                    "checks key '{entry}' is not namespaced to this pack; keys must look like '{prefix}<rule>'"
                ))
                .with_fix("The `as_of` key stays core-owned and cannot be declared here"));
            }
        }
        for check in &self.checks.severity {
            if !KNOWN_SEVERITIES.contains(&check.default.as_str()) {
                return Err(manifest_err(format!(
                    "checks key '{}' has bad severity default '{}'; expected one of: {}",
                    check.key,
                    check.default,
                    KNOWN_SEVERITIES.join(", ")
                )));
            }
        }

        // Every finding code needs a [messages.<CODE>] table with at least
        // one variant, and every [messages] key must be a finding code —
        // no orphan text, no undocumented codes.
        for code in &self.finding_codes {
            match self.messages.get(code) {
                None => {
                    return Err(manifest_err(format!(
                        "finding code '{code}' has no [messages.\"{code}\"] table"
                    ))
                    .with_fix("Add one table per code, with at least one variant"))
                }
                Some(variants) if variants.is_empty() => {
                    return Err(manifest_err(format!(
                        "[messages.\"{code}\"] must declare at least one variant"
                    )))
                }
                _ => {}
            }
        }
        for code in self.messages.keys() {
            if !self.finding_codes.contains(code) {
                return Err(
                    manifest_err(format!("[messages.\"{code}\"] is not in finding_codes"))
                        .with_fix("Add the code to finding_codes or remove the table"),
                );
            }
        }
        for (code, variants) in &self.messages {
            for (variant, template) in variants {
                if variant.trim().is_empty() {
                    return Err(manifest_err(format!(
                        "[messages.\"{code}\"] has an empty variant name"
                    )));
                }
                check_template(template).map_err(|detail| {
                    manifest_err(format!(
                        "[messages.\"{code}\"].{variant} is not a plain template: {detail}"
                    ))
                    .with_fix("Templates allow {{placeholder}} substitution only — no conditionals or expressions")
                })?;
            }
        }

        Ok(())
    }
}

/// Parse and validate a pack manifest (`packs/<name>/manifest.toml`).
/// Returns the manifest on success; nothing is loaded from disk and no
/// pack reads its claims from it yet (steps 4-5).
pub fn parse_manifest(text: &str) -> Result<PackManifest, DomainError> {
    let manifest: PackManifest = toml::from_str(text).map_err(|err| {
        manifest_err(format!("manifest.toml is not valid TOML: {err}")).with_fix(
            "Top-level keys (record_types, balance_metrics, finding_codes) must come before the first [table] header",
        )
    })?;
    manifest.validate()?;
    Ok(manifest)
}

/// Parse and validate an external (v2) pack manifest. Requires
/// `manifest_version = 2` and applies the v2 schema plus capability
/// limits (PD8). Returns the manifest on success; nothing is read from
/// disk.
pub fn parse_manifest_external(text: &str) -> Result<PackManifest, DomainError> {
    let manifest: PackManifest = toml::from_str(text).map_err(|err| {
        manifest_err(format!("manifest.toml is not valid TOML: {err}")).with_fix(
            "Top-level keys (record_types, balance_metrics, finding_codes) must come before the first [table] header",
        )
    })?;
    manifest.validate_external()?;
    Ok(manifest)
}

/// Render a message template: `{placeholder}` substitution only — no
/// conditionals, no expressions, no filters (the loader already rejected
/// anything else). A placeholder the caller does not supply is a render
/// error: the manifest is compile-time data and the code must supply
/// every placeholder the template names (spec §7). Extra args are
/// ignored.
fn render_template(template: &str, args: &[(&str, &dyn std::fmt::Display)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '{' {
            out.push(c);
            continue;
        }
        let mut name = String::new();
        for c in chars.by_ref() {
            if c == '}' {
                break;
            }
            name.push(c);
        }
        let value = args.iter().find(|(k, _)| *k == name).unwrap_or_else(|| {
            panic!("manifest template names placeholder '{{{name}}}' with no value supplied")
        });
        out.push_str(&value.1.to_string());
    }
    out
}

impl PackManifest {
    /// Render a finding message (`messages[code][variant]`), substituting
    /// `{placeholder}` with the supplied values. Panics when the code or
    /// variant is missing, or when a placeholder has no value: the
    /// manifest is compile-time data, so a bad lookup is a programming
    /// error (spec §7: text in the manifest, selection in Rust).
    pub fn render_message(
        &self,
        code: &str,
        variant: &str,
        args: &[(&str, &dyn std::fmt::Display)],
    ) -> String {
        let template = self
            .messages
            .get(code)
            .and_then(|variants| variants.get(variant))
            .unwrap_or_else(|| panic!("manifest has no [messages.\"{code}\"].{variant}"));
        render_template(template, args)
    }

    /// Render the `<variant>_fix` template, or `None` when the manifest
    /// declares no fix for this variant.
    pub fn render_fix(
        &self,
        code: &str,
        variant: &str,
        args: &[(&str, &dyn std::fmt::Display)],
    ) -> Option<String> {
        let fix_variant = format!("{variant}_fix");
        let template = self.messages.get(code)?.get(&fix_variant)?;
        Some(render_template(template, args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid manifest exercising every section.
    fn valid_toml() -> String {
        r#"
manifest_version = 1
record_types = []
balance_metrics = ["sessions_remaining"]
finding_codes = ["E_WRONG", "W_LATE"]

[pack]
name = "coaching"
version = "0.1"
skill = "SKILL.md"

[[verbs]]
name = "session"
id_type = "person"

[[verbs]]
name = "note"

[[fields]]
name = "birthday"
grammar = "recurring-date"

[[edge_kinds]]
name = "mentor"
symmetric = false

[checks]
[[checks.severity]]
key = "coaching.wrong_thing"
default = "warning"

[[checks.int]]
key = "coaching.lookback_days"
default = 7

[messages."E_WRONG"]
default = "wrong {id}"
default_fix = "fix {id}"

[messages."W_LATE"]
default = "late"
"#
        .to_string()
    }

    #[test]
    fn parses_valid_manifest() {
        let m = parse_manifest(&valid_toml()).unwrap();
        assert_eq!(m.manifest_version, 1);
        assert_eq!(m.pack.name, "coaching");
        assert_eq!(m.pack.version, "0.1");
        assert_eq!(m.balance_metrics, vec!["sessions_remaining".to_string()]);
        assert_eq!(m.verbs.len(), 2);
        assert_eq!(m.verbs[0].id_type, Some(Prefix::Person));
        assert_eq!(m.verbs[1].id_type, None);
        assert_eq!(m.fields[0].grammar, "recurring-date");
        assert!(!m.edge_kinds[0].symmetric);
        assert_eq!(m.checks.severity[0].default, "warning");
        assert_eq!(m.checks.int[0].default, 7);
        assert_eq!(m.messages["E_WRONG"]["default"], "wrong {id}".to_string());
    }

    #[test]
    fn minimal_manifest_with_defaults() {
        let text = r#"
manifest_version = 1
record_types = []
balance_metrics = []
finding_codes = ["E_X"]

[pack]
name = "tiny"
version = "0.1"
skill = "SKILL.md"

[messages."E_X"]
default = "x"
"#;
        let m = parse_manifest(text).unwrap();
        assert!(m.verbs.is_empty());
        assert!(m.fields.is_empty());
        assert!(m.edge_kinds.is_empty());
        assert!(m.checks.severity.is_empty());
        assert!(m.checks.int.is_empty());
    }

    #[test]
    fn rejects_invalid_toml() {
        let err = parse_manifest("manifest_version = ").unwrap_err();
        assert!(err.to_string().contains("not valid TOML"));
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let text = valid_toml() + "bogus_key = 1\n";
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("bogus_key"), "{err:?}");
    }

    #[test]
    fn rejects_unknown_key_in_verb() {
        let text = valid_toml().replace("name = \"session\"", "name = \"session\"\nbogus = true");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err:?}");
    }

    #[test]
    fn rejects_wrong_manifest_version() {
        let text = valid_toml().replace("manifest_version = 1", "manifest_version = 2");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err:?}");
    }

    #[test]
    fn rejects_duplicate_verb_names() {
        let text = valid_toml().replace(
            "[[verbs]]\nname = \"note\"",
            "[[verbs]]\nname = \"session\"",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("duplicate verb"), "{err:?}");
    }

    #[test]
    fn rejects_duplicate_field_names() {
        let text = valid_toml() + "[[fields]]\nname = \"birthday\"\ngrammar = \"cadence\"\n";
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("duplicate field"), "{err:?}");
    }

    #[test]
    fn rejects_duplicate_edge_kind_names() {
        let text = valid_toml() + "[[edge_kinds]]\nname = \"mentor\"\nsymmetric = true\n";
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("duplicate edge kind"), "{err:?}");
    }

    #[test]
    fn rejects_duplicate_finding_codes() {
        let text = valid_toml().replace(
            "finding_codes = [\"E_WRONG\", \"W_LATE\"]",
            "finding_codes = [\"E_WRONG\", \"E_WRONG\"]",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(
            err.to_string().contains("duplicate finding code"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_balance_metrics() {
        let text = valid_toml().replace(
            "balance_metrics = [\"sessions_remaining\"]",
            "balance_metrics = [\"sessions_remaining\", \"sessions_remaining\"]",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(
            err.to_string().contains("duplicate balance metric"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_unknown_grammar() {
        let text =
            valid_toml().replace("grammar = \"recurring-date\"", "grammar = \"fancy-regex\"");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("unknown grammar"), "{err:?}");
    }

    #[test]
    fn rejects_unknown_id_type() {
        let text = valid_toml().replace("id_type = \"person\"", "id_type = \"human\"");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("unknown id_type"), "{err:?}");
    }

    #[test]
    fn rejects_bad_template_unclosed() {
        let text = valid_toml().replace("wrong {id}", "wrong {id");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("unclosed"), "{err:?}");
    }

    #[test]
    fn rejects_bad_template_empty_placeholder() {
        let text = valid_toml().replace("wrong {id}", "wrong {}");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("empty placeholder"), "{err:?}");
    }

    #[test]
    fn rejects_bad_template_unmatched_close() {
        let text = valid_toml().replace("wrong {id}", "wrong {id}}");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("unmatched"), "{err:?}");
    }

    #[test]
    fn rejects_bad_template_nested() {
        let text = valid_toml().replace("wrong {id}", "wrong {{id}}");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("nested"), "{err:?}");
    }

    #[test]
    fn rejects_code_without_messages_table() {
        let text = valid_toml().replace(
            "finding_codes = [\"E_WRONG\", \"W_LATE\"]",
            "finding_codes = [\"E_WRONG\", \"W_LATE\", \"E_MISSING\"]",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("no [messages"), "{err:?}");
    }

    #[test]
    fn rejects_orphan_messages_table() {
        let text = valid_toml() + "[messages.\"E_ORPHAN\"]\ndefault = \"orphan\"\n";
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("not in finding_codes"), "{err:?}");
    }

    #[test]
    fn rejects_empty_messages_table() {
        // A table header with no variants under it.
        let text = valid_toml().replace(
            "[messages.\"W_LATE\"]\ndefault = \"late\"",
            "[messages.\"W_LATE\"]",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("at least one variant"), "{err:?}");
    }

    #[test]
    fn rejects_checks_key_wrong_namespace() {
        let text = valid_toml().replace(
            "key = \"coaching.wrong_thing\"",
            "key = \"personal.wrong_thing\"",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("not namespaced"), "{err:?}");
    }

    #[test]
    fn rejects_checks_key_core_owned() {
        let text = valid_toml().replace("key = \"coaching.wrong_thing\"", "key = \"as_of\"");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("not namespaced"), "{err:?}");
    }

    #[test]
    fn rejects_bad_severity_default() {
        let text = valid_toml().replace("default = \"warning\"", "default = \"loud\"");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("bad severity"), "{err:?}");
    }

    #[test]
    fn rejects_empty_pack_name() {
        let text = valid_toml().replace("name = \"coaching\"\nversion", "name = \"\"\nversion");
        // Note: the first `name = "coaching"` is under [pack]; verbs use
        // `name = "session"` so this replace is scoped to the pack table.
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("[pack].name"), "{err:?}");
    }

    #[test]
    fn rejects_pack_name_with_at() {
        let text = valid_toml().replace(
            "[pack]\nname = \"coaching\"",
            "[pack]\nname = \"coaching@0.1\"",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("must not contain '@'"), "{err:?}");
    }

    #[test]
    fn rejects_empty_finding_code() {
        let text = valid_toml().replace(
            "finding_codes = [\"E_WRONG\", \"W_LATE\"]",
            "finding_codes = [\"E_WRONG\", \"\"]",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("non-empty"), "{err:?}");
    }

    /// A minimal valid v2 manifest from spec §13.6.
    fn valid_v2_toml() -> String {
        r#"
manifest_version = 2

record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "E_EXAMPLE_FIELD"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[fields]]
name = "example_field"
grammar = "non-empty-string"

[checks]
[[checks.severity]]
key = "example-pack.example_rule"
default = "warning"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"

[messages."E_EXAMPLE_FIELD"]
default = "example field '{key}' {problem}"
default_fix = "{fix}"
"#
        .to_string()
    }

    #[test]
    fn external_accepts_spec_example() {
        let m = parse_manifest_external(&valid_v2_toml()).unwrap();
        assert_eq!(m.manifest_version, 2);
        assert_eq!(m.pack.name, "example-pack");
        assert_eq!(m.pack.requires_spec, vec!["0.1".to_string()]);
        assert!(m.rules.is_empty());
    }

    #[test]
    fn external_accepts_no_rules() {
        // Valid v2 with no [[rules]] at all.
        let m = parse_manifest_external(&valid_v2_toml()).unwrap();
        assert!(m.rules.is_empty());
    }

    #[test]
    fn external_rejects_v1_version() {
        let text = valid_v2_toml().replace("manifest_version = 2", "manifest_version = 1");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(
            err.to_string()
                .contains("manifest_version 1 is not an external pack manifest"),
            "{err:?}"
        );
    }

    #[test]
    fn external_rejects_missing_requires_spec() {
        let text = valid_v2_toml().replace("requires_spec = [\"0.1\"]\n", "");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("requires_spec"), "{err:?}");
    }

    #[test]
    fn external_rejects_empty_requires_spec() {
        let text = valid_v2_toml().replace("requires_spec = [\"0.1\"]", "requires_spec = []");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("requires_spec"), "{err:?}");
    }

    #[test]
    fn external_rejects_reserved_name() {
        let text = valid_v2_toml().replace("name = \"example-pack\"", "name = \"coaching\"");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err:?}");
    }

    #[test]
    fn external_rejects_bad_name() {
        for bad in ["Bad_Name", "a", &"a".repeat(33)] {
            let text =
                valid_v2_toml().replace("name = \"example-pack\"", &format!("name = \"{bad}\""));
            let err = parse_manifest_external(&text).unwrap_err();
            assert!(err.to_string().contains("name"), "{bad}: {err:?}");
        }
    }

    #[test]
    fn external_rejects_core_verb() {
        for verb in ["touch", "merge"] {
            let text = valid_v2_toml() + &format!("\n[[verbs]]\nname = \"{verb}\"\n");
            let err = parse_manifest_external(&text).unwrap_err();
            assert!(err.to_string().contains("core verb"), "{verb}: {err:?}");
        }
    }

    #[test]
    fn external_rejects_core_edge_kind() {
        let text = valid_v2_toml() + "\n[[edge_kinds]]\nname = \"married\"\nsymmetric = true\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("core edge kind"), "{err:?}");
    }

    #[test]
    fn external_rejects_core_record_type() {
        let text = valid_v2_toml().replace("record_types = []", "record_types = [\"person\"]");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("core record type"), "{err:?}");
    }

    #[test]
    fn external_accepts_builtin_code_as_emission_claim() {
        // #441: a builtin code in finding_codes is an emission claim
        // (the pack emits it with its own template shell) — the v2 spec
        // example lists E_FRONTMATTER exactly this way. The semantics
        // stay core's; the fixture itself proves E_FRONTMATTER parses.
        let m = parse_manifest_external(&valid_v2_toml()).unwrap();
        assert!(m.finding_codes.iter().any(|c| c == "E_FRONTMATTER"));
    }

    #[test]
    fn external_rejects_bad_finding_code_shape() {
        let text = valid_v2_toml()
            .replace(
                "finding_codes = [\"E_EXAMPLE_FIELD\"]",
                "finding_codes = [\"w_x\"]",
            )
            .replace("[messages.\"E_EXAMPLE_FIELD\"]", "[messages.\"w_x\"]");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("finding code"), "{err:?}");
    }

    #[test]
    fn external_rejects_unknown_rule_kind() {
        let text = valid_v2_toml()
            + "\n[[rules]]\nid = \"my_rule\"\nkind = \"nope\"\ncode = \"E_EXAMPLE_FIELD\"\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("unknown rule kind"), "{err:?}");
    }

    #[test]
    fn external_rejects_rule_code_not_declared() {
        // With an empty KNOWN_RULE_KINDS, the kind check fires first.
        // Once kinds are added, this will verify the code-must-be-declared check.
        let text = valid_v2_toml()
            + "\n[[rules]]\nid = \"my_rule\"\nkind = \"cadence-overdue\"\ncode = \"E_UNDECLARED\"\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("unknown rule kind"), "{err:?}");
    }

    #[test]
    fn external_rejects_rule_severity_key_undeclared() {
        // With an empty KNOWN_RULE_KINDS, the kind check fires first.
        // Once kinds are added, this will verify the severity_key check.
        let text = valid_v2_toml()
            + "\n[[rules]]\nid = \"my_rule\"\nkind = \"cadence-overdue\"\ncode = \"E_EXAMPLE_FIELD\"\nseverity_key = \"example-pack.undeclared\"\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("unknown rule kind"), "{err:?}");
    }

    #[test]
    fn external_rejects_duplicate_rule_id() {
        // Duplicate IDs are checked before kind, so this hits the duplicate
        // check even with an empty kind list.
        let text = valid_v2_toml()
            + "\n[[rules]]\nid = \"dup\"\nkind = \"nope\"\ncode = \"E_EXAMPLE_FIELD\"\n"
            + "\n[[rules]]\nid = \"dup\"\nkind = \"nope\"\ncode = \"E_EXAMPLE_FIELD\"\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("duplicate rule id"), "{err:?}");
    }

    #[test]
    fn external_rejects_skill_path_traversal() {
        let text = valid_v2_toml().replace("skill = \"SKILL.md\"", "skill = \"../x.md\"");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("skill"), "{err:?}");
    }

    #[test]
    fn external_rejects_unknown_top_level_key() {
        let text = valid_v2_toml() + "bogus_key = 1\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("bogus_key"), "{err:?}");
    }
}
