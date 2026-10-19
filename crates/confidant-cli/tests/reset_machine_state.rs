//! `confidant reset --machine-state` (#638).
//!
//! The command clears state *outside* a vault so `init --create` starts
//! clean. Tests use an isolated `HOME` for the config dir and
//! `CONFIDANT_TEST_KEYCHAIN_DIR` (the file-backed backend the inbox
//! rotation tests use) so CI never touches a real Secret Service; all data
//! is fake.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

/// A hermetic reset test context: temp HOME, temp working directory (so no
/// walk-up can find a real vault), temp keychain, and a fake "live" vault.
struct Harness {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    keychain: PathBuf,
    cwd: PathBuf,
    vault: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let keychain = tmp.path().join("keychain");
        let cwd = tmp.path().join("work");
        let vault = tmp.path().join("vault");
        for dir in [&home, &keychain, &cwd, &vault] {
            std::fs::create_dir_all(dir).unwrap();
        }
        // A live-looking vault: discovery needs confidant.toml, the guard
        // keys off keys/. The sentinel proves reset never writes inside it.
        std::fs::write(
            vault.join("confidant.toml"),
            "spec = \"0.1\"\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(vault.join("keys")).unwrap();
        std::fs::write(vault.join("keys/sentinel.txt"), "do not touch\n").unwrap();
        std::fs::write(vault.join("ledger.cfd"), "fake ledger\n").unwrap();

        Harness {
            _tmp: tmp,
            home,
            keychain,
            cwd,
            vault,
        }
    }

    fn config_dir(&self) -> PathBuf {
        self.home.join(".config/confidant")
    }

    fn config(&self) -> PathBuf {
        self.config_dir().join("config.toml")
    }

    /// Populate every piece of state the command is supposed to clear,
    /// plus one unrelated config key and a comment.
    fn write_fixture(&self) {
        let config_dir = self.config_dir();
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            self.config(),
            format!(
                "default_vault = \"{}\"\n\
                 \n\
                 [vaults]\n\
                 work = \"{}\"\n\
                 \n\
                 [trust]\n\
                 signers = [\"signer-a\", \"signer-b\"]\n\
                 \n\
                 [inbox]\n\
                 pubkey = \"age1fakeinbox\"\n\
                 \n\
                 # keep this comment\n\
                 [ui]\n\
                 theme = \"dark\"\n",
                // The intended reset case: the old default vault is gone.
                // A live vault is exercised explicitly in the guard test.
                self._tmp.path().join("retired-vault").display(),
                self._tmp.path().join("other-vault").display(),
            ),
        )
        .unwrap();
        std::fs::write(config_dir.join("trust.toml"), "operator = \"fake\"\n").unwrap();
        std::fs::write(
            config_dir.join("manifest-seq.toml"),
            "[01TEST00000000000000000000]\nseq = 1\n",
        )
        .unwrap();
        std::fs::write(
            config_dir.join("inbox-rotation-pending.toml"),
            "vault_id = \"01TEST00000000000000000000\"\n",
        )
        .unwrap();
        for (name, value) in [
            ("device.key", "not-a-real-key"),
            ("confidant.operator-key", "not-real-hex"),
            ("confidant-inbox.inbox-key", "not-real-inbox-key"),
            (
                "confidant-inbox.inbox-key-previous",
                "not-real-previous-key",
            ),
        ] {
            std::fs::write(self.keychain.join(name), value).unwrap();
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(bin());
        cmd.args(args)
            .current_dir(&self.cwd)
            .env("HOME", &self.home)
            .env("CONFIDANT_TEST_KEYCHAIN_DIR", &self.keychain)
            // Belt and braces: if the binary was built without
            // `test-overrides`, keychain writes refuse instead of touching
            // a developer's real keychain.
            .env("CONFIDANT_KEYCHAIN", "off")
            .env_remove("CONFIDANT_VAULT")
            .env_remove("CONFIDANT_DEVICE_KEY")
            .env_remove("CONFIDANT_INBOX_KEY")
            .env_remove("CONFIDANT_OPERATOR_KEY")
            .env_remove("CONFIDANT_TEST_DEVICE_KEY")
            .env_remove("CONFIDANT_TEST_OPERATOR_KEY")
            .env_remove("CONFIDANT_TEST_FORCE_INTERACTIVE")
            .env_remove("CONFIDANT_TEST_PROMPT_ANSWERS");
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }

    fn reset_json(&self, extra: &[&str]) -> (Output, Value) {
        let mut args = vec!["reset", "--machine-state", "--json"];
        args.extend(extra);
        let out = self.run(&args);
        let value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout is not JSON ({e}); status={}; stdout={}; stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out, value)
    }

    fn keychain_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.keychain)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Every path and byte under a directory, for "nothing was touched"
    /// assertions.
    fn snapshot(&self, root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
            let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().collect();
            entries.sort_by_key(|e| e.path());
            for entry in entries {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push((path.clone(), std::fs::read(&path).unwrap()));
                }
            }
        }
        let mut out = Vec::new();
        walk(root, &mut out);
        out
    }

    fn assert_everything_present(&self) {
        let config_dir = self.config_dir();
        for name in [
            "trust.toml",
            "manifest-seq.toml",
            "inbox-rotation-pending.toml",
        ] {
            assert!(
                config_dir.join(name).is_file(),
                "{name} was removed when it should not have been"
            );
        }
        assert_eq!(
            self.keychain_entries(),
            vec![
                "confidant-inbox.inbox-key",
                "confidant-inbox.inbox-key-previous",
                "confidant.operator-key",
                "device.key",
            ]
        );
        let config = std::fs::read_to_string(self.config()).unwrap();
        assert!(config.contains("default_vault"), "{config}");
        assert!(config.contains("[vaults]"), "{config}");
        assert!(config.contains("signers"), "{config}");
        assert!(config.contains("pubkey"), "{config}");
        assert!(config.contains("# keep this comment"), "{config}");
        assert!(config.contains("theme = \"dark\""), "{config}");
    }
}

#[test]
fn dry_run_lists_every_item_and_mutates_nothing() {
    let h = Harness::new();
    h.write_fixture();
    let config_before = std::fs::read_to_string(h.config()).unwrap();
    let keychain_before = h.keychain_entries();
    let vault_before = h.snapshot(&h.vault);

    let (out, v) = h.reset_json(&["--dry-run"]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // JSON shape: machine-state, not vault-scoped. The fixture's
    // default_vault points at a retired (gone) vault, so discovery finds
    // nothing to guard.
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["command"], "reset");
    assert_eq!(v["scope"], "machine-state");
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["changed"], true);
    assert!(v["vault"].is_null(), "{v}");
    assert!(v["vault_guard"].is_null(), "{v}");

    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 11, "{items:?}");
    for item in items {
        assert_eq!(item["present"], true, "{item}");
        match item["kind"].as_str().unwrap() {
            "file" => assert!(item["path"].as_str().unwrap().ends_with(".toml")),
            "config-key" => assert!(item.get("key").is_some(), "{item}"),
            "keychain" => {
                assert!(item.get("service").is_some(), "{item}");
                assert!(item.get("account").is_some(), "{item}");
            }
            other => panic!("unexpected item kind {other}: {item}"),
        }
    }

    assert_eq!(
        std::fs::read_to_string(h.config()).unwrap(),
        config_before,
        "dry-run rewrote config.toml"
    );
    assert_eq!(
        h.keychain_entries(),
        keychain_before,
        "dry-run deleted a key"
    );
    assert_eq!(
        h.snapshot(&h.vault),
        vault_before,
        "dry-run touched the vault"
    );
    h.assert_everything_present();
}

#[test]
fn removal_clears_all_state_and_keeps_unrelated_config() {
    let h = Harness::new();
    h.write_fixture();
    let vault_before = h.snapshot(&h.vault);

    let (out, v) = h.reset_json(&["--yes", "--no-input"]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["dry_run"], false);
    assert_eq!(v["changed"], true);
    assert!(v["vault"].is_null(), "{v}");

    let config_dir = h.config_dir();
    for name in [
        "trust.toml",
        "manifest-seq.toml",
        "inbox-rotation-pending.toml",
    ] {
        assert!(!config_dir.join(name).exists(), "{name} survived the reset");
    }
    assert!(
        h.keychain_entries().is_empty(),
        "keychain entries survived: {:?}",
        h.keychain_entries()
    );

    let config = std::fs::read_to_string(h.config()).unwrap();
    for gone in [
        "default_vault",
        "[vaults]",
        "[trust]",
        "signers",
        "[inbox]",
        "pubkey",
    ] {
        assert!(!config.contains(gone), "{gone} survived:\n{config}");
    }
    assert!(config.contains("# keep this comment"), "{config}");
    assert!(config.contains("[ui]"), "{config}");
    assert!(config.contains("theme = \"dark\""), "{config}");
    // Still valid TOML after the rewrite.
    let parsed: toml::Value = toml::from_str(&config).unwrap();
    assert_eq!(
        parsed["ui"]["theme"],
        toml::Value::String("dark".to_owned())
    );

    assert_eq!(
        h.snapshot(&h.vault),
        vault_before,
        "reset modified the vault"
    );
}

#[test]
fn inline_config_tables_are_removed_too() {
    // TOML allows `vaults = { … }` as well as `[vaults]`; both must clear.
    let h = Harness::new();
    h.write_fixture();
    std::fs::write(
        h.config(),
        format!(
            "default_vault = \"{}\"\n\
             vaults = {{ work = \"{}\" }}\n\
             trust = {{ signers = [\"signer-a\"] }}\n\
             inbox = {{ pubkey = \"age1fakeinbox\" }}\n\
             keep = \"yes\"\n",
            h._tmp.path().join("retired-vault").display(),
            h._tmp.path().join("other-vault").display(),
        ),
    )
    .unwrap();

    let (out, v) = h.reset_json(&["--yes", "--no-input"]);
    assert!(out.status.success(), "{v}");
    let config = std::fs::read_to_string(h.config()).unwrap();
    assert!(!config.contains("default_vault"), "{config}");
    assert!(!config.contains("vaults"), "{config}");
    assert!(!config.contains("trust"), "{config}");
    assert!(!config.contains("inbox"), "{config}");
    let parsed: toml::Value = toml::from_str(&config).unwrap();
    assert_eq!(parsed["keep"], toml::Value::String("yes".to_owned()));
}

#[test]
fn guard_refuses_live_vault_and_force_allows_without_touching_it() {
    let h = Harness::new();
    h.write_fixture();
    let vault_before = h.snapshot(&h.vault);
    let vault_arg = h.vault.display().to_string();

    // Dry-run is safe, but it still refuses: showing a plan that would
    // break a live vault invites the follow-up --yes.
    let (out, v) = h.reset_json(&["--dry-run", "--vault", &vault_arg]);
    assert_eq!(out.status.code(), Some(1), "{v}");

    let (out, v) = h.reset_json(&["--yes", "--no-input", "--vault", &vault_arg]);
    assert_eq!(out.status.code(), Some(1), "{v}");
    assert_eq!(v["ok"], false, "{v}");
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains(&vault_arg), "{message}");
    assert!(message.contains("keys/"), "{message}");
    assert!(
        message.contains("break"),
        "the refusal must say removal would break the vault: {message}"
    );
    h.assert_everything_present();
    assert_eq!(
        h.snapshot(&h.vault),
        vault_before,
        "refusal touched the vault"
    );

    let (out, v) = h.reset_json(&["--yes", "--no-input", "--force", "--vault", &vault_arg]);
    assert!(out.status.success(), "{v}");
    assert_eq!(v["changed"], true, "{v}");
    assert_eq!(v["vault_guard"]["vault"], vault_arg, "{v}");
    assert_eq!(v["vault_guard"]["initialized"], true, "{v}");
    assert_eq!(v["vault_guard"]["forced"], true, "{v}");
    assert!(h.keychain_entries().is_empty());
    assert_eq!(
        h.snapshot(&h.vault),
        vault_before,
        "--force must still never touch the vault"
    );
}

#[test]
fn deleted_vault_path_does_not_block_reset() {
    // The intended case: the old vault is already gone, but a stale
    // --vault / CONFIDANT_VAULT / default_vault still points at it.
    let h = Harness::new();
    h.write_fixture();
    let missing = h._tmp.path().join("already-deleted-vault");
    let missing_arg = missing.display().to_string();

    let (out, v) = h.reset_json(&["--yes", "--no-input", "--vault", &missing_arg]);
    assert!(
        out.status.success(),
        "stderr={}; {v}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(v["changed"], true, "{v}");
    assert!(v["vault_guard"].is_null(), "{v}");
    assert!(h.keychain_entries().is_empty());
}

#[test]
fn second_run_reports_nothing_to_remove_and_exits_zero() {
    let h = Harness::new();
    h.write_fixture();

    let (out, _) = h.reset_json(&["--yes", "--no-input"]);
    assert!(out.status.success());

    let (out, v) = h.reset_json(&["--yes", "--no-input"]);
    assert!(out.status.success(), "{v}");
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["changed"], false, "{v}");
    for item in v["items"].as_array().unwrap() {
        assert_eq!(item["present"], false, "{item}");
    }

    let human = h.run(&["reset", "--machine-state", "--yes", "--no-input"]);
    assert!(human.status.success());
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(stdout.contains("nothing to remove"), "{stdout}");
}

#[test]
fn no_input_without_yes_is_a_usage_error_and_changes_nothing() {
    let h = Harness::new();
    h.write_fixture();

    let (out, v) = h.reset_json(&["--no-input"]);
    assert_eq!(out.status.code(), Some(2), "{v}");
    assert_eq!(v["ok"], false, "{v}");
    assert!(
        v["error"]["message"].as_str().unwrap().contains("--yes"),
        "{v}"
    );
    h.assert_everything_present();
}

#[test]
fn dry_run_and_yes_are_mutually_exclusive() {
    let h = Harness::new();
    h.write_fixture();

    let (out, v) = h.reset_json(&["--dry-run", "--yes"]);
    assert_eq!(out.status.code(), Some(2), "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--dry-run"),
        "{v}"
    );
    h.assert_everything_present();
}

#[test]
fn human_output_names_the_plan_and_the_scope() {
    let h = Harness::new();
    h.write_fixture();

    let out = h.run(&["reset", "--machine-state", "--dry-run"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("would remove"), "{stdout}");
    assert!(stdout.contains("trust.toml"), "{stdout}");
    assert!(stdout.contains("default_vault"), "{stdout}");
    assert!(stdout.contains("confidant/device-key"), "{stdout}");
    assert!(stdout.contains("dry run: nothing was changed"), "{stdout}");
    h.assert_everything_present();
}
