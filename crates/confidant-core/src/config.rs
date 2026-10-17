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
    /// Optional `[inbox]` table. Unknown tables are ignored by readers that
    /// do not know them, so this is backward compatible (no spec bump).
    #[serde(default)]
    pub inbox: InboxConfig,
    /// Optional `[crypto]` table (spec §2). Unknown tables are ignored by
    /// readers that do not know them, so this is backward compatible (no
    /// spec bump).
    #[serde(default)]
    pub crypto: CryptoConfig,
}

/// Optional `[inbox]` table: the vault's public inbox key (age X25519,
/// `age1...`). Outside tools encrypt intake items to this key and push them
/// to the `inbox` branch. The private half never lives in the vault.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct InboxConfig {
    #[serde(default)]
    pub pubkey: Option<String>,
}

/// Optional `[crypto]` table (spec §2, issue #148).
///
/// `mode` is `"encrypted"` (the default when absent) or `"plaintext"`.
/// `"plaintext"` is ONLY for vaults that hold no real data (demo vault,
/// fixtures): it permits plaintext writes while the vault is structurally
/// plaintext, and can never downgrade an encrypted vault (a `mode =
/// "plaintext"` declaration combined with an `enc:` envelope or any `keys/`
/// tree is `E_CONFIG`). Unknown keys are `E_CONFIG` (typo detection, same
/// as `[checks]`).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct CryptoConfig {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, toml::Value>,
}

impl CryptoConfig {
    /// Unknown `[crypto]` keys, sorted (typo detection).
    pub fn extra_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.extra.keys().cloned().collect();
        keys.sort();
        keys
    }
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

    pub fn paid_session_gap_days(&self) -> u64 {
        self.ints["coaching.paid_session_gap_days"]
    }

    pub fn pps_lookback_days(&self) -> u64 {
        self.ints["coaching.pps_lookback_days"]
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

fn parse_severity_token(s: &str) -> Result<Option<Severity>, ()> {
    match s {
        "error" => Ok(Some(Severity::Error)),
        "warning" => Ok(Some(Severity::Warning)),
        "off" => Ok(None),
        _ => Err(()),
    }
}

impl VaultConfig {
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
            // coaching/personal). Only the key itself matches a pack name:
            // a *leaf* under a pack name is not automatically known. A
            // declared leaf (`coaching.paid_session_gap_days`) was already
            // accepted above by the severity/int key checks; an undeclared
            // one (`coaching.bogus`, or a typo) is still an unknown key
            // rather than a silently ignored config line.
            if manifests.iter().any(|m| m.pack.name == key.as_str()) {
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
                    findings.push(
                        Finding::new(
                            FindingCode::Config,
                            Severity::Error,
                            format!("unknown [checks] key '{top_key}'"),
                        )
                        .at_file("confidant.toml")
                        .with_fix("See spec/0.1.md for the keys defined in 0.1"),
                    );
                }
            }
        }

        // [crypto] table: unknown keys and bad mode values are E_CONFIG.
        for problem in crate::crypto_mode::crypto_config_problems(self) {
            findings.push(
                Finding::new(FindingCode::Config, Severity::Error, problem)
                    .at_file("confidant.toml")
                    .with_fix("See spec/0.1.md §2 for the [crypto] table"),
            );
        }
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

/// `~/.config/confidant/config.toml`
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UserConfig {
    pub default_vault: Option<String>,
    #[serde(default)]
    pub vaults: BTreeMap<String, String>,
    /// Optional `[trust]` table: signing key IDs (as shown by
    /// `git log --format=%GK`) whose commits the operator trusts.
    /// `confidant inbox` requires every inbox-branch commit that adds or
    /// changes an item to be signed by one of these keys (ADR-10), and
    /// refuses the run entirely when this list is empty unless
    /// `--allow-unsigned` is passed. Lives outside the vault, never inside it.
    #[serde(default)]
    pub trust: TrustConfig,
    /// Optional `[inbox]` table in the user config: the operator's out-of-band
    /// pin of the vault's inbox public key. `confidant inbox` (and `check`)
    /// error when the vault's `[inbox].pubkey` differs from this pin — the
    /// vault copy is informational only and anyone with git write access can
    /// change it. Set once from the `age-keygen` output; lives outside the
    /// vault, never inside it.
    #[serde(default)]
    pub inbox: InboxUserConfig,
}

/// Optional `[trust]` table in the user config.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TrustConfig {
    #[serde(default)]
    pub signers: Vec<String>,
}

/// Optional `[inbox]` table in the user config: the operator's out-of-band
/// pin of the vault's inbox public key (age `age1...`). Compared against the
/// vault's `confidant.toml [inbox].pubkey` by `confidant inbox` and `check`;
/// a mismatch is a hard error (possible key substitution).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct InboxUserConfig {
    #[serde(default)]
    pub pubkey: Option<String>,
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
    use crate::check::Severity;

    #[test]
    fn parses_architecture_example() {
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
packs = ["coaching@0.1"]
vault_id = "abc"

[checks]
coaching.require_duration = "error"
coaching.balance_nonnegative = "error"
coaching.paid_session_gap_days = 45
"#,
        )
        .unwrap();
        assert!(cfg.config_findings().is_empty());
        assert_eq!(cfg.spec, "0.1");
        assert!(cfg.has_pack("coaching@0.1"));
        assert_eq!(
            cfg.checks
                .severity("coaching.require_duration", Severity::Warning),
            Some(Severity::Error)
        );
        assert_eq!(cfg.checks.paid_session_gap_days(), 45);
        // Default comes from the coaching manifest's [checks] table (#345).
        assert_eq!(cfg.checks.pps_lookback_days(), 180);
        assert_eq!(
            cfg.checks
                .severity("coaching.session_notes", Severity::Warning),
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
coaching.session_notes = "off"
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.checks
                .severity("coaching.session_notes", Severity::Warning),
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
coaching.session_notes = "warn"
coaching.paid_session_gap = "disable"
coaching.paid_session_gap_days = 999999
unknown_key = true
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert!(findings.iter().any(|f| f.code.as_str() == "E_CONFIG"));
        assert_eq!(cfg.checks.paid_session_gap_days(), MAX_GAP_DAYS);
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
        assert_eq!(cfg.checks.int("coaching.paid_session_gap_days"), Some(45));
        assert_eq!(cfg.checks.int("personal.date_upcoming_days"), Some(7));
        // The accessors read from the same map.
        assert_eq!(cfg.checks.paid_session_gap_days(), 45);
        assert_eq!(cfg.checks.date_upcoming_days(), 7);
    }

    #[test]
    fn config_int_key_override_and_cap() {
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks]
coaching.paid_session_gap_days = 3651
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert!(findings
            .iter()
            .any(|f| f.message.contains("exceeds the cap of 3650")));
        assert_eq!(cfg.checks.int("coaching.paid_session_gap_days"), Some(3650));
        assert_eq!(cfg.checks.paid_session_gap_days(), 3650);
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
coaching.bogus = 1
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("unknown [checks] key 'coaching.bogus'")),
            "expected an unknown-key finding, got {findings:?}"
        );

        // The same shape with an undeclared severity key.
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks]
coaching.paid_session_gap_dayz = 5
"#,
        )
        .unwrap();
        let findings = cfg.config_findings();
        assert!(
            findings.iter().any(|f| f
                .message
                .contains("unknown [checks] key 'coaching.paid_session_gap_dayz'")),
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
[checks.coaching]
paid_session_gap_days = 10
"#,
        )
        .unwrap();
        assert!(
            cfg.config_findings().is_empty(),
            "legacy nested table should be accepted"
        );
        assert_eq!(cfg.checks.int("coaching.paid_session_gap_days"), Some(10));
        assert_eq!(cfg.checks.paid_session_gap_days(), 10);
    }

    #[test]
    fn config_nested_pack_table_ignored() {
        // Legacy `[checks.<pack>]` table form is accepted for known packs.
        let mut cfg = VaultConfig::parse(
            r#"
spec = "0.1"
vault_id = "abc"
[checks.coaching]
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
            messages: BTreeMap::new(),
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
}
