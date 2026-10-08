//! Vault `confidant.toml` and user-level discovery config.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use serde::Deserialize;

use crate::check::Severity;
use crate::error::DomainError;

pub const SPEC_VERSION: &str = "0.1";
pub const COACHING_PACK: &str = "coaching@0.1";

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

/// `[checks]` table. Known keys are documented in spec/0.1.md; unknown keys
/// are ignored so older CLIs can read newer vaults.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ChecksConfig {
    pub as_of: Option<String>,
    #[serde(flatten)]
    pub rules: BTreeMap<String, toml::Value>,
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
                Err(_) => Some(default),
            },
            _ => Some(default),
        }
    }

    pub fn u64_or(&self, key: &str, default: u64) -> u64 {
        match self.lookup(key) {
            Some(toml::Value::Integer(n)) if *n >= 0 => *n as u64,
            Some(toml::Value::String(s)) => s.parse().unwrap_or(default),
            _ => default,
        }
    }
}

fn parse_severity_token(s: &str) -> Result<Option<Severity>, ()> {
    match s {
        "error" => Ok(Some(Severity::Error)),
        "warning" | "warn" => Ok(Some(Severity::Warning)),
        "off" | "disable" | "disabled" => Ok(None),
        _ => Err(()),
    }
}

impl VaultConfig {
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        let cfg: Self = toml::from_str(text).map_err(|err| {
            DomainError::invalid(format!("confidant.toml is not valid TOML: {err}"))
        })?;
        if cfg.vault_id.trim().is_empty() {
            return Err(DomainError::invalid(
                "confidant.toml is missing a non-empty vault_id",
            ));
        }
        if cfg.spec.trim().is_empty() {
            return Err(DomainError::invalid("confidant.toml is missing spec"));
        }
        Ok(cfg)
    }

    pub fn has_pack(&self, name: &str) -> bool {
        self.packs.iter().any(|p| p == name)
    }

    pub fn coaching_enabled(&self) -> bool {
        self.has_pack(COACHING_PACK)
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
    use super::{VaultConfig, COACHING_PACK};
    use crate::check::Severity;

    #[test]
    fn parses_architecture_example() {
        let cfg = VaultConfig::parse(
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
        assert_eq!(cfg.spec, "0.1");
        assert!(cfg.has_pack(COACHING_PACK));
        assert_eq!(
            cfg.checks
                .severity("coaching.require_duration", Severity::Warning),
            Some(Severity::Error)
        );
        assert_eq!(cfg.checks.u64_or("coaching.paid_session_gap_days", 0), 45);
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
}
