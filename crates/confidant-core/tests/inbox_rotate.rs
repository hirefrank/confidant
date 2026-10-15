//! Tests for `inbox rotate` / `inbox rotate --finish` (issue #77,
//! crypto-design §8a.3 tests 17–18): drain-then-destroy rotation.
//!
//! Runs `run_inbox_rotate` against a `MemoryKeychain` so no test touches
//! the real OS keychain. All data is fake.

use std::path::Path;
use std::process::Command;

use confidant_core::inbox::{run_inbox_rotate, InboxRotateOptions};
use confidant_crypt::keychain::{self, MemoryKeychain};
use tempfile::TempDir;

const PID: &str = "p-01M3TC5H00MPJG000000000000";

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .expect("git failed to run");
    assert!(
        out.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

struct Repo {
    dir: TempDir,
}

impl Repo {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        git(root, &["init", "-b", "main", "-q"]);
        git(root, &["config", "user.name", "Test"]);
        git(root, &["config", "user.email", "test@example.com"]);
        std::fs::write(
            root.join("confidant.toml"),
            "spec = \"0.1\"\npacks = [\"coaching@0.1\"]\nvault_id = \"inbox-rotate-vault\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join(format!("people/{PID}"))).unwrap();
        std::fs::write(
            root.join(format!("people/{PID}/profile.md")),
            format!("---\nid: {PID}\ntype: person\nname: Test Person\n---\n\nFake.\n"),
        )
        .unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "init"]);
        Self { dir }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Orphan `inbox` branch holding the given age-encrypted items.
    fn with_encrypted_inbox(&self, files: &[(&str, Vec<u8>)]) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(self.root())
            .args(["branch", "-D", "inbox"])
            .output();
        git(self.root(), &["checkout", "-q", "--orphan", "inbox"]);
        git(self.root(), &["rm", "-q", "-rf", "."]);
        for (name, bytes) in files {
            std::fs::write(self.root().join(name), bytes).unwrap();
        }
        git(self.root(), &["add", "."]);
        git(self.root(), &["commit", "-q", "-m", "drop items"]);
        git(self.root(), &["checkout", "-q", "main"]);
    }

    /// Set the vault's advertised `[inbox].pubkey` (committed).
    fn set_vault_pubkey(&self, pubkey: &str) {
        let path = self.root().join("confidant.toml");
        let mut toml = std::fs::read_to_string(&path).unwrap();
        if toml.contains("[inbox]") {
            // Replace the existing pubkey line.
            let mut out = String::new();
            for line in toml.lines() {
                if line.trim_start().starts_with("pubkey") {
                    out.push_str(&format!("pubkey = \"{pubkey}\"\n"));
                } else {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            toml = out;
        } else {
            toml.push_str(&format!("\n[inbox]\npubkey = \"{pubkey}\"\n"));
        }
        std::fs::write(&path, toml).unwrap();
        git(self.root(), &["add", "confidant.toml"]);
        git(self.root(), &["commit", "-q", "-m", "set inbox pubkey"]);
    }

    fn vault_pubkey(&self) -> Option<String> {
        let text = std::fs::read_to_string(self.root().join("confidant.toml")).unwrap();
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("pubkey") {
                let rest = rest.trim().strip_prefix('=').unwrap().trim();
                return Some(rest.trim_matches('"').to_string());
            }
        }
        None
    }
}

/// Serializes env access across tests; unsets the inbox/keychain vars so
/// the `MemoryKeychain` backend is authoritative (env would shadow it, and
/// `CONFIDANT_KEYCHAIN=off` would blank the backend reads).
struct EnvGuard {
    saved: Vec<(&'static str, Option<String>)>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl EnvGuard {
    fn lock() -> Self {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let vars = [
            "CONFIDANT_INBOX_KEY",
            "CONFIDANT_INBOX_KEY_PREVIOUS",
            "CONFIDANT_KEYCHAIN",
        ];
        let saved = vars.iter().map(|v| (*v, std::env::var(v).ok())).collect();
        let g = EnvGuard { saved, _lock };
        for v in vars {
            std::env::remove_var(v);
        }
        g
    }
    fn keychain_off(&self) {
        std::env::set_var("CONFIDANT_KEYCHAIN", "off");
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in self.saved.drain(..) {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

fn ssh_keygen(args: &[&str]) -> Option<std::process::Output> {
    match Command::new("ssh-keygen").args(args).output() {
        Ok(out) => Some(out),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if std::env::var_os("CI").is_some() {
                panic!("ssh-keygen is not installed and CI is set: signing tests must not skip");
            }
            None
        }
        Err(_) => None,
    }
}

/// Configure SSH commit signing on the repo; `None` when ssh-keygen is
/// missing (the drain's merge commit must be signed).
fn require_commit_signing(r: &Repo) -> bool {
    let keydir = TempDir::new().unwrap();
    let key = keydir.path().join("key");
    let key_s = key.to_str().unwrap().to_string();
    let gen = match ssh_keygen(&["-t", "ed25519", "-N", "", "-q", "-f", &key_s]) {
        Some(g) if g.status.success() => g,
        _ => {
            eprintln!("SKIP: ssh-keygen unavailable");
            return false;
        }
    };
    let _ = gen;
    let pubkey = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let allowed = keydir.path().join("allowed_signers");
    std::fs::write(
        &allowed,
        format!("test@example.com namespaces=\"git\" {pubkey}"),
    )
    .unwrap();
    // Keep the keydir alive for the test duration.
    std::mem::forget(keydir);
    for (k, v) in [
        ("gpg.format", "ssh"),
        ("user.signingkey", key_s.as_str()),
        ("gpg.ssh.allowedSignersFile", allowed.to_str().unwrap()),
    ] {
        git(r.root(), &["config", k, v]);
    }
    true
}

fn bech32(id: &age::x25519::Identity) -> String {
    use age::secrecy::ExposeSecret;
    id.to_string().expose_secret().to_owned()
}

fn encrypt_item(plaintext: &str, recipient: &str) -> Vec<u8> {
    confidant_crypt::age_wrap::wrap_to_recipient(plaintext.as_bytes(), recipient).unwrap()
}

const RECORD_ITEM: &str = "confidant-inbox/1\nkind: record\npath: people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG000000000001.md\n---\n---\nid: n-01M3TC5H00MPJG000000000001\ntype: note\n---\n\nFake note.\n";
const RECORD_ITEM_2: &str = "confidant-inbox/1\nkind: record\npath: people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG000000000002.md\n---\n---\nid: n-01M3TC5H00MPJG000000000002\ntype: note\n---\n\nSecond fake note.\n";
const RECORD_ITEM_3: &str = "confidant-inbox/1\nkind: record\npath: people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG000000000003.md\n---\n---\nid: n-01M3TC5H00MPJG000000000003\ntype: note\n---\n\nThird fake note.\n";

fn rotate_opts(finish: bool, pinned_pubkey: Option<String>) -> InboxRotateOptions {
    InboxRotateOptions {
        finish,
        allow_unsigned: true,
        trusted_signers: Vec::new(),
        pinned_pubkey,
    }
}

/// §8a.3 test 17: rotate installs the new keypair and the old key still
/// decrypts during the window; --finish drains leftovers, destroys the
/// old key, and old-key items then fail closed with `E_INBOX_CRYPTO`.
#[test]
fn rotate_drain_then_destroy() {
    let _g = EnvGuard::lock();
    let repo = Repo::new();
    if !require_commit_signing(&repo) {
        return;
    }

    let backend = MemoryKeychain::new();
    let home = TempDir::new().unwrap();
    let user_config = home.path().join(".config/confidant/config.toml");

    // Install the old inbox key.
    let old_id = age::x25519::Identity::generate();
    let old_recipient = old_id.to_public().to_string();
    keychain::rotate_inbox_key_with(&backend, None, &bech32(&old_id)).unwrap();
    repo.set_vault_pubkey(&old_recipient);

    // An item encrypted to the old key, waiting on the inbox branch.
    repo.with_encrypted_inbox(&[("item1.age", encrypt_item(RECORD_ITEM, &old_recipient))]);

    // --- `inbox rotate`: drains, installs the new keypair, updates pins.
    let outcome = run_inbox_rotate(
        repo.root(),
        &backend,
        None,
        &repo.root().join("confidant.toml"),
        &user_config,
        &rotate_opts(false, Some(old_recipient.clone())),
    )
    .unwrap();
    assert!(!outcome.lost_key);
    assert!(!outcome.old_key_destroyed);
    let drain = outcome.drain.expect("rotate must drain");
    assert_eq!(drain.merged, 1);
    let new_recipient = outcome
        .new_recipient
        .expect("rotate must install a new key");
    assert_ne!(new_recipient, old_recipient);
    assert!(new_recipient.starts_with("age1"));

    // Pins updated: the vault's advertised pubkey (committed) and the
    // user-config pin.
    assert_eq!(repo.vault_pubkey().as_deref(), Some(new_recipient.as_str()));
    let user_toml = std::fs::read_to_string(&user_config).unwrap();
    assert!(
        user_toml.contains(&format!("pubkey = \"{new_recipient}\"")),
        "user-config pin not updated:\n{user_toml}"
    );

    // The old key is still present in the previous slot: the window is open.
    let keys = confidant_core::InboxKeys::load_opt_with(&backend, None)
        .unwrap()
        .expect("inbox key must be enrolled");
    assert!(keys.has_previous());
    assert_eq!(keys.current_recipient(), new_recipient);

    // A second rotate inside the window refuses.
    let err = run_inbox_rotate(
        repo.root(),
        &backend,
        None,
        &repo.root().join("confidant.toml"),
        &user_config,
        &rotate_opts(false, Some(new_recipient.clone())),
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("rotate --finish"),
        "unexpected error: {err:#}"
    );

    // --- `inbox rotate --finish`: drains what is left, destroys the key.
    repo.with_encrypted_inbox(&[("item2.age", encrypt_item(RECORD_ITEM_2, &old_recipient))]);
    let outcome = run_inbox_rotate(
        repo.root(),
        &backend,
        None,
        &repo.root().join("confidant.toml"),
        &user_config,
        &rotate_opts(true, Some(new_recipient.clone())),
    )
    .unwrap();
    assert!(outcome.old_key_destroyed);
    let drain = outcome.drain.expect("finish must drain");
    assert_eq!(drain.merged, 1, "old-key item must drain during the window");

    // The old key is gone from the keychain.
    let keys = confidant_core::InboxKeys::load_opt_with(&backend, None)
        .unwrap()
        .expect("inbox key must be enrolled");
    assert!(!keys.has_previous());

    // --finish is idempotent.
    let outcome = run_inbox_rotate(
        repo.root(),
        &backend,
        None,
        &repo.root().join("confidant.toml"),
        &user_config,
        &rotate_opts(true, Some(new_recipient.clone())),
    )
    .unwrap();
    assert!(!outcome.old_key_destroyed);
    assert!(outcome.drain.is_none());

    // An item sent to the old key now fails closed with E_INBOX_CRYPTO.
    repo.with_encrypted_inbox(&[("item3.age", encrypt_item(RECORD_ITEM_3, &old_recipient))]);
    let keys = std::sync::Arc::new(
        confidant_core::InboxKeys::load_opt_with(&backend, None)
            .unwrap()
            .unwrap(),
    );
    let owned = keys.clone();
    let decrypt = move |b: &[u8]| owned.decrypt(b);
    let err = confidant_core::run_inbox(
        repo.root(),
        &confidant_core::InboxOptions {
            dry_run: false,
            trusted_signers: Vec::new(),
            allow_unsigned: true,
            pinned_pubkey: Some(new_recipient.clone()),
            ..Default::default()
        },
        &decrypt,
        Some(&keys),
        None,
        None,
    )
    .unwrap_err();
    let code = confidant_core::DomainError::of(&err).map(|d| d.code().to_string());
    assert_eq!(code.as_deref(), Some("E_INBOX_CRYPTO"));
}

/// §8a.2 lost-key path: with no old key enrolled, `inbox rotate` skips
/// the drain and there is no `--finish` to run.
#[test]
fn rotate_lost_key_skips_drain() {
    let _g = EnvGuard::lock();
    let repo = Repo::new();
    if !require_commit_signing(&repo) {
        return;
    }

    let backend = MemoryKeychain::new();
    let home = TempDir::new().unwrap();
    let user_config = home.path().join(".config/confidant/config.toml");

    let outcome = run_inbox_rotate(
        repo.root(),
        &backend,
        None,
        &repo.root().join("confidant.toml"),
        &user_config,
        &rotate_opts(false, None),
    )
    .unwrap();
    assert!(outcome.lost_key);
    assert!(outcome.drain.is_none());
    assert!(!outcome.old_key_destroyed);
    let new_recipient = outcome.new_recipient.expect("must install a new key");
    assert_eq!(repo.vault_pubkey().as_deref(), Some(new_recipient.as_str()));

    // --finish with no previous key is a no-op.
    let outcome = run_inbox_rotate(
        repo.root(),
        &backend,
        None,
        &repo.root().join("confidant.toml"),
        &user_config,
        &rotate_opts(true, Some(new_recipient)),
    )
    .unwrap();
    assert!(!outcome.old_key_destroyed);
}

/// Must-fix 1: with `CONFIDANT_KEYCHAIN=off`, both `rotate` and `--finish`
/// refuse instead of taking the lost-key path and half-rotating the real
/// backend (drain skipped, real key moved into the previous slot, nothing
/// reported pending).
#[test]
fn rotate_refuses_with_kill_switch() {
    let _g = EnvGuard::lock();
    let repo = Repo::new();

    let backend = MemoryKeychain::new();
    let home = TempDir::new().unwrap();
    let user_config = home.path().join(".config/confidant/config.toml");

    // A real key enrolled in the backend.
    let old_id = age::x25519::Identity::generate();
    let old_recipient = old_id.to_public().to_string();
    keychain::rotate_inbox_key_with(&backend, None, &bech32(&old_id)).unwrap();
    repo.set_vault_pubkey(&old_recipient);

    _g.keychain_off();

    for finish in [false, true] {
        let err = run_inbox_rotate(
            repo.root(),
            &backend,
            None,
            &repo.root().join("confidant.toml"),
            &user_config,
            &rotate_opts(finish, Some(old_recipient.clone())),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("CONFIDANT_KEYCHAIN=off"),
            "unexpected error: {err:#}"
        );
    }

    // The backend is untouched: no half-rotation happened.
    std::env::remove_var("CONFIDANT_KEYCHAIN");
    let keys = confidant_core::InboxKeys::load_opt_with(&backend, None)
        .unwrap()
        .expect("inbox key must still be enrolled");
    assert!(!keys.has_previous(), "previous slot must be empty");
    assert_eq!(keys.current_recipient(), old_recipient);
    assert!(
        !user_config.exists(),
        "no pin file should have been written"
    );
}

/// Must-fix 3 + item 7: the pin write fails closed instead of clobbering.
/// A user-config path that can't be read (here: a directory) errors rather
/// than being overwritten with only `[inbox]`; a non-table `[inbox]`
/// value is a config error, not a panic.
#[test]
fn rotate_pin_write_fails_closed() {
    let _g = EnvGuard::lock();
    let repo = Repo::new();
    if !require_commit_signing(&repo) {
        return;
    }

    let backend = MemoryKeychain::new();
    let home = TempDir::new().unwrap();

    let old_id = age::x25519::Identity::generate();
    let old_recipient = old_id.to_public().to_string();
    keychain::rotate_inbox_key_with(&backend, None, &bech32(&old_id)).unwrap();
    repo.set_vault_pubkey(&old_recipient);
    repo.with_encrypted_inbox(&[("item1.age", encrypt_item(RECORD_ITEM, &old_recipient))]);

    // Case 1: the user-config path is a directory (read fails with
    // EISDIR, not NotFound) — must error, not overwrite.
    let user_config_dir = home.path().join(".config/confidant/config.toml");
    std::fs::create_dir_all(&user_config_dir).unwrap();
    let err = run_inbox_rotate(
        repo.root(),
        &backend,
        None,
        &repo.root().join("confidant.toml"),
        &user_config_dir,
        &rotate_opts(false, Some(old_recipient.clone())),
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("refusing to overwrite"),
        "unexpected error: {err:#}"
    );
    assert!(
        user_config_dir.is_dir(),
        "the directory must not have been replaced by a file"
    );

    // Case 2: `[inbox]` exists but isn't a table — a config error, not a
    // toml_edit panic. Fresh backend and repo so the rotate runs cleanly
    // up to the user-config write.
    let repo2 = Repo::new();
    if !require_commit_signing(&repo2) {
        return;
    }
    let backend2 = MemoryKeychain::new();
    let old_id2 = age::x25519::Identity::generate();
    let old_recipient2 = old_id2.to_public().to_string();
    keychain::rotate_inbox_key_with(&backend2, None, &bech32(&old_id2)).unwrap();
    repo2.set_vault_pubkey(&old_recipient2);
    let user_config_file = home.path().join("other.confidant/config.toml");
    std::fs::create_dir_all(user_config_file.parent().unwrap()).unwrap();
    std::fs::write(&user_config_file, "inbox = \"x\"\n[trust]\nsigners = []\n").unwrap();
    let err = run_inbox_rotate(
        repo2.root(),
        &backend2,
        None,
        &repo2.root().join("confidant.toml"),
        &user_config_file,
        &rotate_opts(false, Some(old_recipient2.clone())),
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("not a table"),
        "unexpected error: {err:#}"
    );
    // The [trust] table must still be there — nothing was clobbered.
    let text = std::fs::read_to_string(&user_config_file).unwrap();
    assert!(text.contains("[trust]"), "config was clobbered:\n{text}");
}

/// #106: when the keychain already holds the new key (previous slot occupied)
/// but the vault pin still advertises the old pubkey, `inbox rotate` resumes
/// the pin update instead of refusing.
#[test]
fn rotate_resumes_when_pins_lag_keychain() {
    let _g = EnvGuard::lock();
    let repo = Repo::new();
    if !require_commit_signing(&repo) {
        return;
    }

    let backend = MemoryKeychain::new();
    let home = TempDir::new().unwrap();
    let user_config = home.path().join(".config/confidant/config.toml");

    let old_id = age::x25519::Identity::generate();
    let old_recipient = old_id.to_public().to_string();
    keychain::rotate_inbox_key_with(&backend, None, &bech32(&old_id)).unwrap();
    repo.set_vault_pubkey(&old_recipient);

    let new_id = age::x25519::Identity::generate();
    let new_recipient = new_id.to_public().to_string();
    keychain::rotate_inbox_key_with(&backend, None, &bech32(&new_id)).unwrap();
    assert_eq!(repo.vault_pubkey().as_deref(), Some(old_recipient.as_str()));

    let outcome = run_inbox_rotate(
        repo.root(),
        &backend,
        None,
        &repo.root().join("confidant.toml"),
        &user_config,
        &rotate_opts(false, Some(old_recipient.clone())),
    )
    .unwrap();
    assert!(outcome.drain.is_none());
    assert_eq!(
        outcome.new_recipient.as_deref(),
        Some(new_recipient.as_str())
    );
    assert_eq!(repo.vault_pubkey().as_deref(), Some(new_recipient.as_str()));
    let user_toml = std::fs::read_to_string(&user_config).unwrap();
    assert!(user_toml.contains(&format!("pubkey = \"{new_recipient}\"")));
}

/// #106: vault pin already matches the keychain; only the user-config pin lags.
#[test]
fn rotate_resumes_user_pin_only() {
    let _g = EnvGuard::lock();
    let repo = Repo::new();
    if !require_commit_signing(&repo) {
        return;
    }

    let backend = MemoryKeychain::new();
    let home = TempDir::new().unwrap();
    let user_config = home.path().join(".config/confidant/config.toml");

    let old_id = age::x25519::Identity::generate();
    keychain::rotate_inbox_key_with(&backend, None, &bech32(&old_id)).unwrap();

    let new_id = age::x25519::Identity::generate();
    let new_recipient = new_id.to_public().to_string();
    keychain::rotate_inbox_key_with(&backend, None, &bech32(&new_id)).unwrap();
    repo.set_vault_pubkey(&new_recipient);

    let outcome = run_inbox_rotate(
        repo.root(),
        &backend,
        None,
        &repo.root().join("confidant.toml"),
        &user_config,
        &rotate_opts(false, Some(new_recipient.clone())),
    )
    .unwrap();
    assert_eq!(
        outcome.new_recipient.as_deref(),
        Some(new_recipient.as_str())
    );
    let user_toml = std::fs::read_to_string(&user_config).unwrap();
    assert!(user_toml.contains(&format!("pubkey = \"{new_recipient}\"")));
}
