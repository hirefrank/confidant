//! Vault discovery order (ADR-11).

use std::path::{Path, PathBuf};

use crate::config::UserConfig;
use crate::error::DomainError;

/// Inputs for discovery. The CLI fills this from flags, env, and the user
/// config file; tests inject paths directly.
#[derive(Clone, Debug, Default)]
pub struct Discovery {
    pub flag: Option<PathBuf>,
    pub env: Option<String>,
    pub cwd: PathBuf,
    pub user_config: Option<UserConfig>,
}

pub fn resolve(discovery: &Discovery) -> Result<PathBuf, DomainError> {
    if let Some(flag) = &discovery.flag {
        return existing_vault(flag);
    }
    if let Some(env) = &discovery.env {
        if let Some(cfg) = &discovery.user_config {
            if let Some(named) = cfg.named(env) {
                return existing_vault(&named);
            }
        }
        return existing_vault(Path::new(env));
    }
    if let Some(found) = walk_up(&discovery.cwd) {
        return Ok(found);
    }
    if let Some(cfg) = &discovery.user_config {
        if let Some(default) = cfg.default_path() {
            return existing_vault(&default);
        }
    }
    Err(DomainError::vault_not_found())
}

fn existing_vault(path: &Path) -> Result<PathBuf, DomainError> {
    let candidate = if path.join("confidant.toml").is_file() {
        path.to_path_buf()
    } else if path.is_file() && path.file_name().is_some_and(|n| n == "confidant.toml") {
        path.parent().unwrap_or(path).to_path_buf()
    } else {
        return Err(DomainError::vault_not_found()
            .with_fix(format!("No confidant.toml at {}", path.display())));
    };
    candidate.canonicalize().map_err(|_| {
        DomainError::vault_not_found().with_fix(format!("No confidant.toml at {}", path.display()))
    })
}

fn walk_up(start: &Path) -> Option<PathBuf> {
    let mut dir = start
        .canonicalize()
        .ok()
        .unwrap_or_else(|| start.to_path_buf());
    loop {
        if dir.join("confidant.toml").is_file() {
            return dir.canonicalize().ok();
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn load_user_config(home: Option<&Path>) -> Option<UserConfig> {
    let home = home?;
    let path = home.join(".config/confidant/config.toml");
    let text = std::fs::read_to_string(path).ok()?;
    UserConfig::parse(&text).ok()
}

#[cfg(test)]
mod tests {
    use super::{resolve, Discovery};
    use std::fs;

    #[test]
    fn flag_wins() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"x\"\n",
        )
        .unwrap();
        let d = Discovery {
            flag: Some(dir.path().to_path_buf()),
            env: Some("/does-not-exist".into()),
            cwd: std::env::temp_dir(),
            user_config: None,
        };
        let got = resolve(&d).unwrap();
        assert_eq!(got, dir.path().canonicalize().unwrap());
    }

    #[test]
    fn walk_up_from_nested() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"x\"\n",
        )
        .unwrap();
        let nested = dir.path().join("people").join("nested");
        fs::create_dir_all(&nested).unwrap();
        let d = Discovery {
            flag: None,
            env: None,
            cwd: nested,
            user_config: None,
        };
        assert_eq!(resolve(&d).unwrap(), dir.path().canonicalize().unwrap());
    }

    #[test]
    fn missing_fails_clearly() {
        let d = Discovery {
            flag: None,
            env: None,
            cwd: std::env::temp_dir(),
            user_config: None,
        };
        let err = resolve(&d).unwrap_err();
        assert_eq!(err.code(), "E_VAULT_NOT_FOUND");
    }
}
