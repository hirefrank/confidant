//! Vault `confidant.toml` and user-level discovery config.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::str::FromStr;

use serde::Deserialize;

use crate::check::{Finding, FindingCode, Severity};
use crate::error::DomainError;

pub const SPEC_VERSION: &str = "0.1";
pub const COACHING_PACK: &str = "coaching@0.1";
pub const MAX_GAP_DAYS: u64 = 3650;
pub const DEFAULT_GAP_DAYS: u64 = 45;

const KNOWN_SEVERITY_KEYS: &[&str] = &[
    "coaching.require_duration",
    "coaching.balance_nonnegative",
    "coaching.session_notes",
    "coaching.paid_session_gap",
];
const KNOWN_INT_KEYS: &[&str] = &["coaching.paid_session_gap_days"];
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
    #[serde(skip)]
    pub gap_days: u64,
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
        self.gap_days
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
        cfg.checks.gap_days = DEFAULT_GAP_DAYS;
        Ok(cfg)
    }

    pub fn has_pack(&self, name: &str) -> bool {
        self.packs.iter().any(|p| p == name)
    }

    pub fn coaching_enabled(&self) -> bool {
        self.has_pack(COACHING_PACK)
    }

    /// Semantic `[checks]` problems as `E_CONFIG` findings. Never panics.
    pub fn config_findings(&mut self) -> Vec<Finding> {
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
            if KNOWN_SEVERITY_KEYS.contains(&key.as_str()) {
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
            if KNOWN_INT_KEYS.contains(&key.as_str()) {
                match self.checks.lookup(key) {
                    Some(toml::Value::Integer(n)) if *n < 0 => {
                        findings.push(
                            Finding::new(
                                FindingCode::Config,
                                Severity::Error,
                                format!("[checks] {key} must be non-negative (got {n})"),
                            )
                            .at_file("confidant.toml"),
                        );
                        self.checks.gap_days = DEFAULT_GAP_DAYS;
                    }
                    Some(toml::Value::Integer(n)) => {
                        let n = *n as u64;
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
                            self.checks.gap_days = MAX_GAP_DAYS;
                        } else {
                            self.checks.gap_days = n;
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
                        self.checks.gap_days = DEFAULT_GAP_DAYS;
                    }
                    None => {}
                }
                continue;
            }
            if key == "coaching" {
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
    chrono::NaiveDate::from_str(s)
        .map_err(|_| DomainError::invalid(format!("date '{s}' is not YYYY-MM-DD")))
}

#[cfg(test)]
mod tests {
    use super::{VaultConfig, COACHING_PACK, MAX_GAP_DAYS};
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
        assert!(cfg.has_pack(COACHING_PACK));
        assert_eq!(
            cfg.checks
                .severity("coaching.require_duration", Severity::Warning),
            Some(Severity::Error)
        );
        assert_eq!(cfg.checks.paid_session_gap_days(), 45);
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
}
