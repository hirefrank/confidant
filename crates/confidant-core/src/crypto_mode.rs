//! Structural crypto mode: is this vault encrypted, and may writers write
//! plaintext? (Spec 3, issue #148.)
//!
//! The decision is **structural-first, declaration-narrowing-only** (§2.2):
//! a vault is *encrypted* if it has any `enc:` envelope file or any `keys/`
//! tree at all — including a half-initialized `keys/` with only
//! `keys/operator.toml` and no client manifest. Such a vault must never fall
//! into the plaintext branch. A `[crypto] mode = "plaintext"` declaration
//! can only permit plaintext writes while the vault is already structurally
//! plaintext; it can never downgrade an encrypted vault.

use std::path::Path;

use crate::config::VaultConfig;
use crate::error::DomainError;

/// Record-file collections. `FileChange::WriteFile` targets under one of
/// these are record content and go through the encryption transform;
/// everything else (ledger, `confidant.toml`, inbox) stays plaintext by
/// design.
const RECORD_COLLECTIONS: &[&str] = &["people", "orgs", "deals", "interactions", "notes", "edges"];

/// True when `path` (vault-relative) is a record file. Used by the write
/// layer so a future command that writes records cannot bypass encryption.
pub fn is_record_path(path: &Path) -> bool {
    let mut components = path.components();
    let first = components.next().and_then(|c| c.as_os_str().to_str());
    matches!(first, Some(dir) if RECORD_COLLECTIONS.contains(&dir))
}

/// Keyless structural test: does this vault hold any encryption material?
///
/// True when `keys/` holds any key material at all (a manifest, the operator
/// certificate, an epoch file — a half-initialized `keys/` is encrypted,
/// not plaintext) or when any record file carries an `enc:` envelope
/// header. A bare `keys/.gitkeep` placeholder is not key material.
pub fn is_structurally_encrypted(root: &Path) -> bool {
    if has_keys_tree(&root.join("keys")) {
        return true;
    }
    for collection in RECORD_COLLECTIONS {
        let dir = root.join(collection);
        if has_envelope_file(&dir) {
            return true;
        }
    }
    false
}

/// True when `keys/` contains anything but the git placeholder. Any real
/// entry — `operator.toml`, a client directory, an epoch file — means the
/// vault has begun key initialization and must never take the plaintext
/// branch.
fn has_keys_tree(keys_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(keys_dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".gitkeep" {
            continue;
        }
        return true;
    }
    false
}

/// Recursively scan `dir` for a file whose front matter carries an `enc:`
/// header. Reads only the head of each file; unreadable entries are
/// skipped (a broken vault is `check`'s problem, not this predicate's).
fn has_envelope_file(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            if has_envelope_file(&path) {
                return true;
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        if is_envelope_bytes(&read_head(&path)) {
            return true;
        }
    }
    false
}

/// Read the first 4 KiB of a file (enough for any envelope header).
fn read_head(path: &Path) -> Vec<u8> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(4096);
    if let Ok(mut f) = std::fs::File::open(path) {
        let mut chunk = [0u8; 4096];
        if let Ok(n) = f.read(&mut chunk) {
            buf.extend_from_slice(&chunk[..n]);
        }
    }
    buf
}

/// Keyless envelope sniff: front matter opens with `---` and carries an
/// `enc:` header line before the closing `---`. This is the same shape
/// `confidant-crypt`'s `envelope::parse` accepts; it never decrypts.
pub fn is_envelope_bytes(head: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    let mut lines = text.lines();
    if lines.next() != Some("---") {
        return false;
    }
    for line in lines {
        if line == "---" {
            break;
        }
        // A header key named exactly `enc` (values are `name: value`).
        if line.split_once(':').map(|(k, _)| k.trim()) == Some("enc") {
            return true;
        }
    }
    false
}

/// Count record files by envelope vs plaintext. Used by `doctor`; reports
/// code + count only, never names or paths.
pub fn count_record_mix(root: &Path) -> (u64, u64) {
    let mut encrypted = 0u64;
    let mut plaintext = 0u64;
    for collection in RECORD_COLLECTIONS {
        count_mix_dir(&root.join(collection), &mut encrypted, &mut plaintext);
    }
    (encrypted, plaintext)
}

fn count_mix_dir(dir: &Path, encrypted: &mut u64, plaintext: &mut u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_dir() {
            count_mix_dir(&path, encrypted, plaintext);
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        // Only count plausible record files; skip stray files.
        let is_record = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("md") || e.eq_ignore_ascii_case("cfd"))
            .unwrap_or(false);
        if !is_record {
            continue;
        }
        if is_envelope_bytes(&read_head(&path)) {
            *encrypted += 1;
        } else {
            *plaintext += 1;
        }
    }
}

/// What the writer does with record content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteMode {
    /// Structurally encrypted vault: writers must encrypt. No fallback.
    Encrypted,
    /// Structurally plaintext vault with an explicit `mode = "plaintext"`:
    /// writers keep today's plaintext behavior.
    Plaintext,
}

/// Semantic problems with the `[crypto]` table, as message strings. Shared
/// by `config_findings` (which wraps them in `E_CONFIG` findings) and the
/// write path (which fails closed).
pub fn crypto_config_problems(config: &VaultConfig) -> Vec<String> {
    let mut problems = Vec::new();
    for key in config.crypto.extra_keys() {
        problems.push(format!("unknown [crypto] key '{key}'"));
    }
    if let Some(mode) = config.crypto.mode.as_deref() {
        if mode != "encrypted" && mode != "plaintext" {
            problems.push(format!(
                "[crypto] mode = '{mode}' is not \"encrypted\" or \"plaintext\""
            ));
        }
    }
    problems
}

/// Resolve the writer mode for this vault. Fails closed: any contradiction
/// or unkeyed vault without the explicit opt-out is an error, never silent
/// plaintext.
///
/// Decision tree (§2.2):
/// - structurally encrypted + `mode = "plaintext"` → `E_CONFIG`
///   (the declaration cannot downgrade an encrypted vault);
/// - structurally encrypted → [`WriteMode::Encrypted`];
/// - structurally plaintext + `mode = "plaintext"` → [`WriteMode::Plaintext`];
/// - structurally plaintext otherwise → fail closed with a fix pointing at
///   `confidant init`.
pub fn resolve_write_mode(root: &Path, config: &VaultConfig) -> Result<WriteMode, DomainError> {
    if let Some(problem) = crypto_config_problems(config).into_iter().next() {
        return Err(
            DomainError::config(problem).with_fix("See spec/0.1.md §2 for the [crypto] table")
        );
    }
    let structural = is_structurally_encrypted(root);
    let plaintext_declared = config.crypto.mode.as_deref() == Some("plaintext");
    if structural && plaintext_declared {
        return Err(DomainError::config(
            "confidant.toml declares [crypto] mode = \"plaintext\" but the vault \
             is structurally encrypted (it has an `enc:` envelope or a `keys/` tree); \
             the declaration cannot downgrade an encrypted vault",
        )
        .with_fix("Remove the `[crypto] mode = \"plaintext\"` line"));
    }
    if structural {
        return Ok(WriteMode::Encrypted);
    }
    if plaintext_declared {
        return Ok(WriteMode::Plaintext);
    }
    Err(DomainError::invalid(
        "vault has no keys and does not opt out of encryption; \
         refusing to write plaintext",
    )
    .with_fix(
        "Run `confidant init` to key the vault, or declare \
               `[crypto] mode = \"plaintext\"` in confidant.toml for a vault \
               that holds no real data",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn record_path_classifier() {
        assert!(is_record_path(Path::new("people/p-ABC/profile.md")));
        assert!(is_record_path(Path::new("people/p-ABC/notes/n-XYZ.md")));
        assert!(is_record_path(Path::new("orgs/o-ABC/org.md")));
        assert!(is_record_path(Path::new("deals/d-ABC/deal.md")));
        assert!(is_record_path(Path::new(
            "interactions/i-ABC/interaction.md"
        )));
        assert!(!is_record_path(Path::new("ledger/2026/10.cfd")));
        assert!(!is_record_path(Path::new("confidant.toml")));
        assert!(!is_record_path(Path::new("keys/p-ABC/recipients.toml")));
    }

    #[test]
    fn envelope_sniff() {
        let env = b"---\nid: p-01ABC\ntype: person\nno-ai: false\nenc: xchacha20poly1305\nkey_id: p-01ABC/e0\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\nAQID\n";
        assert!(is_envelope_bytes(env));
        let plain = b"---\nid: p-01ABC\ntype: person\nname: \"Ada\"\n---\n\nBio.\n";
        assert!(!is_envelope_bytes(plain));
        assert!(!is_envelope_bytes(b"not front matter"));
        assert!(!is_envelope_bytes(b""));
    }

    #[test]
    fn structural_half_initialized_keys_is_encrypted() {
        let dir = vault_dir();
        let root = dir.path();
        assert!(!is_structurally_encrypted(root));
        // Half-initialized keys/: operator cert only, no manifests.
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/operator.toml"), "x = 1\n").unwrap();
        assert!(
            is_structurally_encrypted(root),
            "any keys/ tree at all is structurally encrypted"
        );
    }

    #[test]
    fn gitkeep_placeholder_is_not_a_keys_tree() {
        let dir = vault_dir();
        let root = dir.path();
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys/.gitkeep"), "").unwrap();
        assert!(
            !is_structurally_encrypted(root),
            "a bare .gitkeep is not key material"
        );
    }

    #[test]
    fn structural_envelope_is_encrypted() {
        let dir = vault_dir();
        let root = dir.path();
        let env = "---\nid: p-01ABC\ntype: person\nno-ai: false\nenc: xchacha20poly1305\nkey_id: p-01ABC/e0\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\nAQID\n";
        std::fs::create_dir_all(root.join("people/p-01ABC")).unwrap();
        std::fs::write(root.join("people/p-01ABC/profile.md"), env).unwrap();
        assert!(is_structurally_encrypted(root));
    }

    fn test_config(mode: Option<&str>) -> VaultConfig {
        let toml = match mode {
            Some(m) => format!(
                "spec = \"0.1\"\nvault_id = \"01TEST00000000000000000000\"\n[crypto]\nmode = \"{m}\"\n"
            ),
            None => "spec = \"0.1\"\nvault_id = \"01TEST00000000000000000000\"\n".to_string(),
        };
        VaultConfig::parse(&toml).unwrap()
    }

    #[test]
    fn mode_plaintext_declared_writes_plaintext() {
        let dir = vault_dir();
        let cfg = test_config(Some("plaintext"));
        assert_eq!(
            resolve_write_mode(dir.path(), &cfg).unwrap(),
            WriteMode::Plaintext
        );
    }

    #[test]
    fn mode_unkeyed_no_opt_out_fails_closed() {
        let dir = vault_dir();
        let cfg = test_config(None);
        let err = resolve_write_mode(dir.path(), &cfg).unwrap_err();
        assert!(
            err.fix().unwrap_or("").contains("confidant init"),
            "fix should point at init, got: {:?}",
            err.fix()
        );
    }

    #[test]
    fn mode_plaintext_with_keys_is_e_config() {
        let dir = vault_dir();
        std::fs::create_dir_all(dir.path().join("keys")).unwrap();
        std::fs::write(dir.path().join("keys/operator.toml"), "x = 1\n").unwrap();
        let cfg = test_config(Some("plaintext"));
        let err = resolve_write_mode(dir.path(), &cfg).unwrap_err();
        assert!(err.to_string().contains("cannot downgrade"));
    }

    #[test]
    fn mode_bad_value_is_e_config() {
        let dir = vault_dir();
        let cfg = test_config(Some("rot13"));
        assert!(resolve_write_mode(dir.path(), &cfg).is_err());
    }
}
