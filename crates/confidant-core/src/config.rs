//! Vault `confidant.toml` and user-level discovery config.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::Deserialize;

use crate::check::{Finding, FindingCode, Severity};
use crate::error::DomainError;
use crate::ledger::parse_strict_date;

pub const SPEC_VERSION: &str = "0.1";
pub const MAX_GAP_DAYS: u64 = 3650;

/// `[checks]` severity keys, from the pack manifests (#345, #433).
/// `as_of` stays core-owned and is listed separately in `KNOWN_TOP_LEVEL`.
fn known_severity_keys<'a>(manifests: &[&'a crate::packs::manifest::PackManifest]) -> Vec<&'a str> {
    let mut keys = Vec::new();
    for m in manifests {
        for s in &m.checks.severity {
            // The manifest stores owned Strings; the keys are 'static
            // because the manifest itself lives for 'static.
            keys.push(s.key.as_str());
        }
    }
    keys
}

/// `[checks]` integer keys, from the pack manifests (#345, #433).
fn known_int_keys<'a>(manifests: &[&'a crate::packs::manifest::PackManifest]) -> Vec<&'a str> {
    let mut keys = Vec::new();
    for m in manifests {
        for i in &m.checks.int {
            keys.push(i.key.as_str());
        }
    }
    keys
}

/// Default for a `[checks]` integer key, from the pack manifest that
/// declares it (#345, #433). Panics on an unknown key: callers only ask about
/// keys in `known_int_keys()`.
fn int_key_default(manifests: &[&crate::packs::manifest::PackManifest], key: &str) -> u64 {
    for m in manifests {
        for i in &m.checks.int {
            if i.key == key {
                return u64::try_from(i.default).expect("manifest int default fits in u64");
            }
        }
    }
    panic!("unknown [checks] int key '{key}'")
}

const KNOWN_TOP_LEVEL: &[&str] = &["as_of"];

/// A vault's `confidant.toml`.
#[derive(Clone, Debug, Deserialize)]
pub struct VaultConfig {
    pub spec: String,
    #[serde(default)]
    pub packs: Vec<String>,
    pub vault_id: String,
    #[serde(default)]
    pub checks: ChecksConfig,
}

/// `[checks]` table. Unknown keys are `E_CONFIG` findings.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ChecksConfig {
    pub as_of: Option<String>,
    #[serde(flatten)]
    pub rules: BTreeMap<String, toml::Value>,
    /// Resolved integer values for every declared `[checks]` int key,
    /// keyed by the full dotted key (#433). Filled by `VaultConfig::parse`
    /// (defaults from manifests) and updated by `config_findings()` (file
    /// overrides with validation). Not serialized.
    #[serde(skip)]
    pub ints: BTreeMap<String, u64>,
}

impl ChecksConfig {
    fn lookup(&self, dotted: &str) -> Option<&toml::Value> {
        if let Some(v) = self.rules.get(dotted) {
            return Some(v);
        }
        let mut parts = dotted.split('.');
        let mut value = self.rules.get(parts.next()?)?;
        for part in parts {
            value = value.get(part)?;
        }
        Some(value)
    }

    pub fn severity(&self, key: &str, default: Severity) -> Option<Severity> {
        match self.lookup(key) {
            None => Some(default),
            Some(toml::Value::String(s)) => match parse_severity_token(s) {
                Ok(Some(sev)) => Some(sev),
                Ok(None) => None,
                Err(()) => Some(default),
            },
            _ => Some(default),
        }
    }

    pub fn date_upcoming_days(&self) -> u64 {
        self.ints["personal.date_upcoming_days"]
    }

    /// Generic accessor for any declared `[checks]` int key (#433).
    /// Returns `None` for unknown keys.
    pub fn int(&self, key: &str) -> Option<u64> {
        self.ints.get(key).copied()
    }
}

/// Token to severity; `off` is `Ok(None)`, an unknown token is `Err`.
/// `pub(crate)`: the manifest loader's severity default and the
/// declarative evaluator (#441) both parse it.
pub(crate) fn parse_severity_token(s: &str) -> Result<Option<Severity>, ()> {
    match s {
        "error" => Ok(Some(Severity::Error)),
        "warning" => Ok(Some(Severity::Warning)),
        "off" => Ok(None),
        _ => Err(()),
    }
}

impl VaultConfig {
    /// Replace the `packs = [...]` array in a `confidant.toml` text,
    /// preserving comments and everything else (`toml_edit`). `pack` install
    /// and removal go through this so an operator's comments survive (#440).
    pub fn set_packs(text: &str, packs: &[String]) -> Result<String, DomainError> {
        let mut doc: toml_edit::DocumentMut = text
            .parse()
            .map_err(|e| DomainError::config(format!("confidant.toml is not valid TOML: {e}")))?;
        match doc.get_mut("packs").and_then(toml_edit::Item::as_array_mut) {
            Some(array) => {
                array.clear();
                for pack in packs {
                    array.push(pack.as_str());
                }
            }
            None => {
                let mut array = toml_edit::Array::new();
                for pack in packs {
                    array.push(pack.as_str());
                }
                // A root key-value: `toml_edit` writes the root's key-values
                // before any `[table]`, so this cannot land inside `[checks]`.
                doc.as_table_mut().insert(
                    "packs",
                    toml_edit::Item::Value(toml_edit::Value::Array(array)),
                );
            }
        }
        Ok(doc.to_string())
    }

    pub fn parse(text: &str) -> Result<Self, DomainError> {
        let mut cfg: Self = toml::from_str(text).map_err(|err| {
            DomainError::config(format!("confidant.toml is not valid TOML: {err}"))
        })?;
        if cfg.vault_id.trim().is_empty() {
            return Err(DomainError::config(
                "confidant.toml is missing a non-empty vault_id",
            ));
        }
        if cfg.spec.trim().is_empty() {
            return Err(DomainError::config("confidant.toml is missing spec"));
        }
        // Fill [checks] int defaults from the pack manifests (#433).
        // `config_findings()` applies file overrides with validation.
        let manifests = crate::packs::pack_manifests_for_config();
        for m in &manifests {
            for i in &m.checks.int {
                let default = u64::try_from(i.default).expect("manifest int default fits in u64");
                cfg.checks.ints.insert(i.key.clone(), default);
            }
        }
        Ok(cfg)
    }

    pub fn has_pack(&self, name: &str) -> bool {
        self.packs.iter().any(|p| p == name)
    }

    /// #656: the `name@version` pin when the vault lists `name` but the
    /// pack's manifest is absent from `manifests`, i.e. the pack did not
    /// resolve. When it did resolve, or `name` is not listed at all,
    /// `None`: the key is then judged normally (a typo under a resolved
    /// pack still points at the spec).
    ///
    /// Only a valid pin may be echoed: any other `packs` entry is operator
    /// free text (#490, #501).
    fn unresolved_pack_pin<'a>(
        &'a self,
        manifests: &[&crate::packs::manifest::PackManifest],
        name: &str,
    ) -> Option<&'a str> {
        if manifests.iter().any(|m| m.pack.name == name) {
            return None;
        }
        self.packs.iter().find_map(|listed| {
            let (listed_name, _) = listed.split_once('@')?;
            (listed_name == name && crate::packs::lock::is_valid_pack_pin(listed))
                .then_some(listed.as_str())
        })
    }

    /// Semantic `[checks]` problems as `E_CONFIG` findings. Never panics.
    pub fn config_findings(&mut self) -> Vec<Finding> {
        let manifests = crate::packs::pack_manifests_for_config();
        self.config_findings_with(&manifests)
    }

    /// `config_findings` with an explicit manifest list (#433). The vault
    /// load path calls this with the loaded external manifests appended
    /// to the compiled ones (#438); tests inject an extra manifest to
    /// prove the generic mechanism.
    pub fn config_findings_with(
        &mut self,
        manifests: &[&crate::packs::manifest::PackManifest],
    ) -> Vec<Finding> {
        let severity_keys = known_severity_keys(manifests);
        let int_keys = known_int_keys(manifests);
        let mut findings = Vec::new();
        if let Some(as_of) = self.checks.as_of.as_deref() {
            if parse_iso_date(as_of).is_err() {
                findings.push(
                    Finding::new(
                        FindingCode::Config,
                        Severity::Error,
                        format!("[checks].as_of '{as_of}' is not YYYY-MM-DD"),
                    )
                    .at_file("confidant.toml")
                    .with_fix("Use a zero-padded calendar date such as 2026-10-08"),
                );
            }
        }

        let mut seen = BTreeSet::new();
        collect_keys(self.checks.rules.iter(), "", &mut seen);

        for key in &seen {
            if key == "as_of" || KNOWN_TOP_LEVEL.contains(&key.as_str()) {
                continue;
            }
            if severity_keys.contains(&key.as_str()) {
                match self.checks.lookup(key) {
                    Some(toml::Value::String(s)) => {
                        if parse_severity_token(s).is_err() {
                            findings.push(
                                Finding::new(
                                    FindingCode::Config,
                                    Severity::Error,
                                    format!("[checks] {key} = '{s}' is not error, warning, or off"),
                                )
                                .at_file("confidant.toml")
                                .with_fix("Use error, warning, or off (not warn/disable)"),
                            );
                        }
                    }
                    Some(_) => findings.push(
                        Finding::new(
                            FindingCode::Config,
                            Severity::Error,
                            format!("[checks] {key} must be a string"),
                        )
                        .at_file("confidant.toml"),
                    ),
                    None => {}
                }
                continue;
            }
            if int_keys.contains(&key.as_str()) {
                let default = int_key_default(manifests, key);
                let value = self.checks.lookup(key).cloned();
                match value {
                    Some(toml::Value::Integer(n)) if n < 0 => {
                        findings.push(
                            Finding::new(
                                FindingCode::Config,
                                Severity::Error,
                                format!("[checks] {key} must be non-negative (got {n})"),
                            )
                            .at_file("confidant.toml"),
                        );
                        self.checks.ints.insert(key.clone(), default);
                    }
                    Some(toml::Value::Integer(n)) => {
                        let n = n as u64;
                        if n > MAX_GAP_DAYS {
                            findings.push(
                                Finding::new(
                                    FindingCode::Config,
                                    Severity::Error,
                                    format!(
                                        "[checks] {key} = {n} exceeds the cap of {MAX_GAP_DAYS}"
                                    ),
                                )
                                .at_file("confidant.toml")
                                .with_fix(format!("Use a value between 0 and {MAX_GAP_DAYS}")),
                            );
                            self.checks.ints.insert(key.clone(), MAX_GAP_DAYS);
                        } else {
                            self.checks.ints.insert(key.clone(), n);
                        }
                    }
                    Some(_) => {
                        findings.push(
                            Finding::new(
                                FindingCode::Config,
                                Severity::Error,
                                format!("[checks] {key} must be a non-negative integer"),
                            )
                            .at_file("confidant.toml"),
                        );
                        self.checks.ints.insert(key.clone(), default);
                    }
                    None => {}
                }
                continue;
            }
            // Legacy bare pack key: `[checks] <pack> = <value>` is accepted
            // when `<pack>` is a known pack name (#433; was hard-coded to
            // the pack names). Only the key itself matches a pack name:
            // a *leaf* under a pack name is not automatically known. A
            // declared leaf (`example-pack.gap_days`) was already
            // accepted above by the severity/int key checks; an undeclared
            // one (`example-pack.bogus`, or a typo) is still an unknown key
            // rather than a silently ignored config line.
            if manifests.iter().any(|m| m.pack.name == key.as_str()) {
                continue;
            }
            // #656: a key under a listed pack that did not resolve (no
            // lockfile pin, bad hash, unreadable manifest) is unknown only
            // because the pack is missing. Point at the pack, not the spec,
            // which does not define the pack's keys.
            if let Some(pin) = self.unresolved_pack_pin(manifests, first_segment(key)) {
                findings.push(unresolved_pack_key_finding(key, pin));
                continue;
            }
            findings.push(
                Finding::new(
                    FindingCode::Config,
                    Severity::Error,
                    format!("unknown [checks] key '{key}'"),
                )
                .at_file("confidant.toml")
                .with_fix("See spec/0.1.md for the keys defined in 0.1"),
            );
        }

        // Empty `[checks.<name>]` tables produce no leaf keys above; reject
        // them when `<name>` is not a known pack (#433).
        for (top_key, value) in &self.checks.rules {
            if matches!(value, toml::Value::Table(_))
                && top_key != "as_of"
                && !manifests.iter().any(|m| m.pack.name == top_key.as_str())
            {
                // Only report if no leaf keys were already reported (avoid
                // duplicates when the table has content).
                let prefix = format!("{top_key}.");
                let has_leaf = seen.iter().any(|k| k.starts_with(&prefix));
                if !has_leaf {
                    // #656: same pack-not-resolved carve-out as above.
                    match self.unresolved_pack_pin(manifests, top_key) {
                        Some(pin) => findings.push(unresolved_pack_key_finding(top_key, pin)),
                        None => findings.push(
                            Finding::new(
                                FindingCode::Config,
                                Severity::Error,
                                format!("unknown [checks] key '{top_key}'"),
                            )
                            .at_file("confidant.toml")
                            .with_fix("See spec/0.1.md for the keys defined in 0.1"),
                        ),
                    }
                }
            }
        }

        // [crypto] tables in older configs are unknown tables: readers that
        // do not know them ignore them silently (no spec bump needed).
        findings
    }
}

fn collect_keys<'a, I>(map: I, prefix: &str, out: &mut BTreeSet<String>)
where
    I: IntoIterator<Item = (&'a String, &'a toml::Value)>,
{
    for (k, v) in map {
        let dotted = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            toml::Value::Table(t) => collect_keys(t.iter(), &dotted, out),
            _ => {
                out.insert(dotted);
            }
        }
    }
}

/// The pack name a `[checks]` key belongs to: its first dotted segment.
fn first_segment(key: &str) -> &str {
    key.split('.').next().unwrap_or(key)
}

/// #656: an unknown `[checks]` key under a listed pack that did not resolve
/// is not a typo, so the generic spec pointer would be wrong. The validated
/// pin is safe to echo (#490), and the `E_PACK_UNKNOWN` (or other pack
/// problem) finding already names it.
fn unresolved_pack_key_finding(key: &str, pin: &str) -> Finding {
    Finding::new(
        FindingCode::Config,
        Severity::Error,
        format!("[checks] key '{key}' requires pack {pin}, which is not installed"),
    )
    .at_file("confidant.toml")
    .with_fix(format!(
        "Run `confidant pack add <https-url> --yes` to install/pin {pin}, or remove the [checks] key"
    ))
}

/// `~/.config/confidant/config.toml`
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UserConfig {
    pub default_vault: Option<String>,
    #[serde(default)]
    pub vaults: BTreeMap<String, String>,
}

impl UserConfig {
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        toml::from_str(text)
            .map_err(|err| DomainError::invalid(format!("user config is not valid TOML: {err}")))
    }

    pub fn named(&self, name: &str) -> Option<PathBuf> {
        self.vaults.get(name).map(expand_tilde)
    }

    pub fn default_path(&self) -> Option<PathBuf> {
        self.default_vault.as_ref().map(expand_tilde)
    }
}

fn expand_tilde(raw: &String) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let mut p = PathBuf::from(home);
            p.push(rest);
            return p;
        }
    }
    PathBuf::from(raw)
}

pub fn parse_iso_date(s: &str) -> Result<chrono::NaiveDate, DomainError> {
    parse_strict_date(s)
        .ok_or_else(|| DomainError::invalid(format!("date '{s}' is not YYYY-MM-DD")))
}

#[cfg(test)]
mod tests {
    use super::{VaultConfig, MAX_GAP_DAYS};
    use crate::check::{Finding, Severity};

    /// Run config validation with the neutral external example-pack manifest
    /// appended, the way a vault load does for an external pack (#438).
    fn config_findings_with_example_pack(cfg: &mut VaultConfig) -> Vec<Finding> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/packs/example-pack/manifest.toml"
        );
        let text = std::fs::read_to_string(path).expect("example pack manifest");
        let manifest =
            crate::packs::manifest::parse_manifest_external(&text).expect("example pack manifest");
        let mut manifests = crate::packs::pack_manifests_for_config();
        manifests.push(&manifest);
        cfg.config_findings_with(&manifests)
    }

    #[test]
    fn parses_architecture_example() {
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
packs = ["example-pack@0.1"]
vault_id = "abc"

[checks]
example-pack.require_duration = "error"
example-pack.balance_nonnegative = "error"
example-pack.gap_days = 45
"#,
        )
        .unwrap();
        assert!(config_findings_with_example_pack(&mut cfg).is_empty());
        assert_eq!(cfg.spec, "0.1");
        assert!(cfg.has_pack("example-pack@0.1"));
        assert_eq!(
            cfg.checks
                .severity("example-pack.require_duration", Severity::Warning),
            Some(Severity::Error)
        );
        assert_eq!(cfg.checks.int("example-pack.gap_days"), Some(45));
        assert_eq!(
            cfg.checks.severity("example-pack.notes", Severity::Warning),
            Some(Severity::Warning)
        );
    }

    #[test]
    fn off_disables_rule() {
        let cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks]
example-pack.notes = "off"
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.checks.severity("example-pack.notes", Severity::Warning),
            None
        );
    }

    #[test]
    fn warn_alias_and_huge_days_are_e_config() {
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks]
example-pack.notes = "warn"
example-pack.gap = "disable"
example-pack.gap_days = 999999
unknown_key = true
"#,
        )
        .unwrap();
        let findings = config_findings_with_example_pack(&mut cfg);
        assert!(findings.iter().any(|f| f.code.as_str() == "E_CONFIG"));
        assert_eq!(cfg.checks.int("example-pack.gap_days"), Some(MAX_GAP_DAYS));
        assert!(findings.iter().any(|f| f.message.contains("warn")));
        assert!(findings.iter().any(|f| f.message.contains("unknown")));
    }

    #[test]
    fn config_int_key_default_applies() {
        // Vault with no [checks]: defaults come from the manifests (#433).
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
"#,
        )
        .unwrap();
        assert!(cfg.config_findings().is_empty());
        assert_eq!(cfg.checks.int("personal.date_upcoming_days"), Some(7));
        assert_eq!(cfg.checks.date_upcoming_days(), 7);
        // Coaching is external now, so its defaults arrive only with its
        // manifest (the vault load appends it, #449).
        assert_eq!(cfg.checks.int("example-pack.gap_days"), None);
    }

    #[test]
    fn config_int_key_override_and_cap() {
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks]
personal.date_upcoming_days = 3651
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert!(findings
            .iter()
            .any(|f| f.message.contains("exceeds the cap of 3650")));
        assert_eq!(cfg.checks.int("personal.date_upcoming_days"), Some(3650));
        assert_eq!(cfg.checks.date_upcoming_days(), 3650);
    }

    #[test]
    fn config_int_key_negative_is_error() {
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks]
personal.date_upcoming_days = -1
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert!(findings
            .iter()
            .any(|f| f.message.contains("must be non-negative")));
        // Falls back to the manifest default.
        assert_eq!(cfg.checks.int("personal.date_upcoming_days"), Some(7));
        assert_eq!(cfg.checks.date_upcoming_days(), 7);
    }

    #[test]
    fn config_unknown_key_still_rejected() {
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks]
bogus.key = 1
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert!(findings
            .iter()
            .any(|f| f.message.contains("unknown [checks] key 'bogus.key'")));
    }

    #[test]
    fn config_unknown_key_under_known_pack_rejected() {
        // A leaf under a known pack name is not automatically known: a
        // typo must still be an `E_CONFIG` unknown key rather than being
        // silently accepted (or silently defaulted) (#433 review).
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks]
personal.bogus = 1
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("unknown [checks] key 'personal.bogus'")),
            "expected an unknown-key finding, got {findings:?}"
        );

        // The same shape with an undeclared severity key.
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks]
personal.date_upcoming_dayz = 5
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert!(
            findings.iter().any(|f| f
                .message
                .contains("unknown [checks] key 'personal.date_upcoming_dayz'")),
            "expected an unknown-key finding, got {findings:?}"
        );
    }

    #[test]
    fn config_legacy_nested_pack_table_declared_keys_still_accepted() {
        // The legacy `[checks.<pack>]` table form keeps working for keys
        // the pack actually declares (#433).
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks.personal]
date_upcoming_days = 10
"#,
        )
        .unwrap();
        assert!(
            cfg.config_findings().is_empty(),
            "legacy nested table should be accepted"
        );
        assert_eq!(cfg.checks.int("personal.date_upcoming_days"), Some(10));
        assert_eq!(cfg.checks.date_upcoming_days(), 10);
    }

    #[test]
    fn config_nested_pack_table_ignored() {
        // Legacy `[checks.<pack>]` table form is accepted for known packs.
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks.personal]
"#,
        )
        .unwrap();
        assert!(cfg.config_findings().is_empty());

        // Unknown pack names are rejected.
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks.unknownpack]
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert!(findings
            .iter()
            .any(|f| f.message.contains("unknown [checks] key")));
    }

    #[test]
    fn config_unresolved_listed_pack_keys_point_at_the_pack() {
        // #656: a listed pack with no lockfile pin resolves to no manifest,
        // so its own keys are "unknown" only because the pack is missing.
        // They must point at `pack add`, not at a spec page that does not
        // define them: one finding per key, none with the spec pointer.
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
packs = ["example-pack@0.1"]
vault_id = "abc"
[checks]
example-pack.require_duration = "error"
example-pack.gap_days = 45
example-pack.bogus = "warning"
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert_eq!(findings.len(), 3, "one finding per key: {findings:?}");
        for f in &findings {
            assert_eq!(f.code.as_str(), "E_CONFIG");
            assert!(
                f.message
                    .contains("requires pack example-pack@0.1, which is not installed"),
                "{f:?}"
            );
        }
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("'example-pack.require_duration'")),
            "{findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("'example-pack.gap_days'")),
            "{findings:?}"
        );
        for f in &findings {
            let fix = f.fix.as_deref().expect("a fix");
            assert!(fix.contains("confidant pack add"), "{f:?}");
            assert!(!fix.contains("spec/0.1.md"), "{f:?}");
        }
    }

    #[test]
    fn config_unresolved_listed_pack_bare_and_empty_table_keys() {
        // #656: the legacy bare pack key and an empty `[checks.<pack>]`
        // table reach the same carve-out.
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
packs = ["other-pack@0.1"]
vault_id = "abc"
[checks]
other-pack = "error"
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0]
                .message
                .contains("'other-pack' requires pack other-pack@0.1"),
            "{findings:?}"
        );
        assert!(!findings[0]
            .fix
            .as_deref()
            .unwrap_or("")
            .contains("spec/0.1.md"));

        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
packs = ["other-pack@0.1"]
vault_id = "abc"
[checks.other-pack]
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0]
                .message
                .contains("'other-pack' requires pack other-pack@0.1"),
            "{findings:?}"
        );
    }

    #[test]
    fn config_resolved_pack_typo_still_points_at_spec() {
        // #656: with the pack resolved (manifest present), declared keys are
        // accepted and a bogus leaf is the normal E_CONFIG typo, spec
        // pointer included.
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
packs = ["example-pack@0.1"]
vault_id = "abc"
[checks]
example-pack.require_duration = "error"
example-pack.balance_nonnegative = "error"
example-pack.bogus = "warning"
"#,
        )
        .unwrap();
        let findings = config_findings_with_example_pack(&mut cfg);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0]
                .message
                .contains("unknown [checks] key 'example-pack.bogus'"),
            "{findings:?}"
        );
        assert!(findings[0]
            .fix
            .as_deref()
            .unwrap_or("")
            .contains("spec/0.1.md"));
    }

    #[test]
    fn config_non_pack_key_unchanged_by_pack_listing() {
        // #656: keys under no listed pack keep today's generic finding, even
        // when the vault lists a pack whose keys are separately carved out.
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
packs = ["example-pack@0.1"]
vault_id = "abc"
[checks]
bogus.key = 1
otherpack.thing = "error"
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert_eq!(findings.len(), 2, "{findings:?}");
        for f in &findings {
            assert!(f.message.starts_with("unknown [checks] key"), "{f:?}");
            assert!(
                f.fix.as_deref().unwrap_or("").contains("spec/0.1.md"),
                "{f:?}"
            );
        }
    }

    #[test]
    fn config_unresolved_pack_requires_a_valid_pin() {
        // #656: a listing that is not a valid `name@version` pin is operator
        // free text (#490, #501). It gets no carve-out and is never echoed.
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
packs = ["other-pack@nightly"]
vault_id = "abc"
[checks]
example-pack.require_duration = "error"
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0]
                .message
                .contains("unknown [checks] key 'example-pack.require_duration'"),
            "{findings:?}"
        );
        assert!(!findings[0].message.contains("nightly"), "{findings:?}");
    }

    #[test]
    fn config_example_pack_key_works_generically() {
        use crate::packs::manifest::{ChecksDecl, IntCheck, PackInfo, PackManifest};
        use std::collections::BTreeMap;

        // A test-only manifest for a hypothetical third pack (#433).
        // Proves the [checks] machinery is generic, not per-pack.
        let example_manifest = PackManifest {
            manifest_version: 1,
            record_types: Vec::new(),
            balance_metrics: Vec::new(),
            finding_codes: Vec::new(),
            pack: PackInfo {
                name: "example".to_string(),
                version: "0.1".to_string(),
                skill: "SKILL.md".to_string(),
                // v2-only; absent in a v1 manifest (#435).
                requires_spec: Vec::new(),
            },
            verbs: Vec::new(),
            fields: Vec::new(),
            edge_kinds: Vec::new(),
            checks: ChecksDecl {
                severity: Vec::new(),
                int: vec![IntCheck {
                    key: "example.window_days".to_string(),
                    default: 5,
                }],
            },
            // v2-only `[[rules]]` (#435); empty for a v1 manifest.
            rules: Vec::new(),
            // v2-only `[context]` (#594); absent for a v1 manifest.
            context: None,
            messages: BTreeMap::new(),
            // #550: a hand-built manifest in tests is treated as external;
            // `may_emit_builtin_codes` still allows v1's builtin codes.
            origin: crate::packs::manifest::PackOrigin::External,
        };

        let mut manifests = crate::packs::pack_manifests_for_config();
        manifests.push(&example_manifest);

        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks]
example.window_days = 10
"#,
        )
        .unwrap();
        // The key is accepted (no E_CONFIG) and the override is readable
        // via the generic accessor.
        let findings = cfg.config_findings_with(&manifests);
        assert!(findings.is_empty());
        assert_eq!(cfg.checks.int("example.window_days"), Some(10));
    }

    #[test]
    fn set_packs_preserves_comments_and_rewrites_in_place() {
        let text = "spec = \"0.1\"\n# which packs this vault enables\npacks = [\"example-pack@0.1\"]\nvault_id = \"x\"\n\n[checks]\nas_of = \"2026-10-08\"\n";
        let out = VaultConfig::set_packs(
            text,
            &["example-pack@0.1".to_owned(), "other-pack@0.1".to_owned()],
        )
        .unwrap();
        assert!(out.contains("# which packs this vault enables"), "{out}");
        assert!(
            out.contains("packs = [\"example-pack@0.1\", \"other-pack@0.1\"]"),
            "{out}"
        );
        assert!(
            out.find("packs").unwrap() < out.find("[checks]").unwrap(),
            "{out}"
        );
        assert_eq!(
            VaultConfig::parse(&out).unwrap().packs,
            vec!["example-pack@0.1", "other-pack@0.1"]
        );
    }

    #[test]
    fn set_packs_inserts_a_root_key_before_tables() {
        // A vault may omit `packs`; the inserted key must land before
        // `[checks]`, not inside it.
        let text = "spec = \"0.1\"\nvault_id = \"x\"\n\n[checks]\nas_of = \"2026-10-08\"\n";
        let out = VaultConfig::set_packs(text, &["example-pack@0.1".to_owned()]).unwrap();
        assert!(
            out.find("packs").unwrap() < out.find("[checks]").unwrap(),
            "{out}"
        );
        assert_eq!(
            VaultConfig::parse(&out).unwrap().packs,
            vec!["example-pack@0.1"]
        );
    }
}
