//! Tests for `confidant reindex` (#37): the CLI builds the QMD search
//! corpus from the §12 cleared set.
//!
//! Content tests use a throwaway copy of the plaintext demo vault, so the
//! checked-out tree is never written to. Encrypted-vault tests live in
//! `encrypted_reads.rs`. All data is fake.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

/// The checked-out plaintext demo vault (never written to: callers copy it).
fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

/// Copy `src` into `dst` recursively (a throwaway vault a test may write to).
fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}

fn run(vault: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .arg("--vault")
        .arg(vault)
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Vault-relative file paths under `dir`, POSIX-separated.
fn walk_files(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            walk_files(&entry.path(), base, out);
        } else {
            let rel = entry.path().strip_prefix(base).unwrap().to_path_buf();
            out.insert(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

fn corpus_files(vault: &Path) -> BTreeSet<String> {
    let corpus = vault.join(".confidant/qmd-corpus");
    let mut out = BTreeSet::new();
    walk_files(&corpus, &corpus, &mut out);
    out
}

/// True if any corpus file contains `needle`.
fn corpus_contains(vault: &Path, needle: &str) -> bool {
    let corpus = vault.join(".confidant/qmd-corpus");
    corpus_files(vault).iter().any(|rel| {
        std::fs::read_to_string(corpus.join(rel))
            .map(|text| text.contains(needle))
            .unwrap_or(false)
    })
}

fn git(vault: &Path, args: &[&str]) {
    let st = Command::new("git")
        .current_dir(vault)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?} failed");
}

/// The corpus file set is exactly the §12 cleared set: cleared record files,
/// plus cleared ledger files and their `.cfd.md` mirrors. `no-ai` records
/// and their ledger lines are out. (#120's test, mirrored onto the corpus.)
#[test]
fn reindex_corpus_matches_allowlist_exactly() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault");
    copy_dir(&demo(), &vault);

    let allow = run(&vault, &["allowlist", "--json", "--no-input"]);
    assert!(
        allow.status.success(),
        "allowlist failed: {}",
        stderr(&allow)
    );
    let av: serde_json::Value = serde_json::from_slice(&allow.stdout).unwrap();

    let reindex = run(&vault, &["reindex", "--json", "--no-input"]);
    assert!(
        reindex.status.success(),
        "reindex failed: {}",
        stderr(&reindex)
    );
    let rv: serde_json::Value = serde_json::from_slice(&reindex.stdout).unwrap();
    assert_eq!(rv["ok"], true);
    assert_eq!(rv["skipped_encrypted"], 0);
    assert_eq!(rv["refused_envelopes"], 0);
    assert!(rv["corpus"]
        .as_str()
        .unwrap()
        .ends_with(".confidant/qmd-corpus"));

    // Expected = cleared record files ∪ cleared ledger files (+ .cfd.md).
    let mut expected: BTreeSet<String> = BTreeSet::new();
    for f in av["cleared_files"].as_array().unwrap() {
        expected.insert(f.as_str().unwrap().to_string());
    }
    for e in av["cleared_ledger_lines"].as_array().unwrap() {
        let file = e["file"].as_str().unwrap().to_string();
        expected.insert(format!("{file}.md"));
        expected.insert(file);
    }
    assert_eq!(corpus_files(&vault), expected, "corpus set != cleared set");

    // The no-ai person's content never enters the corpus.
    assert!(
        !corpus_contains(&vault, "Cam Sample"),
        "no-ai content leaked into the corpus"
    );
    // Ciphertext framing never enters either.
    assert!(!corpus_contains(&vault, "enc:"));

    // Ledger parity: the `.cfd` keeps exactly the cleared lines, and the
    // mirror is byte-identical (QMD's `**/*.md` only matches the mirror).
    let ledger = vault.join(".confidant/qmd-corpus/ledger/2026/10.cfd");
    let cfd = std::fs::read_to_string(&ledger).unwrap();
    let kept_lines = av["cleared_ledger_lines"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["file"] == "ledger/2026/10.cfd")
        .count();
    assert_eq!(cfd.lines().count(), kept_lines, "{cfd}");
    let mirror =
        std::fs::read_to_string(vault.join(".confidant/qmd-corpus/ledger/2026/10.cfd.md")).unwrap();
    assert_eq!(cfd, mirror);
}

/// A plaintext vault builds with no keys at all (B2): identical to the old
/// skill build, no device key or trust anchor needed.
#[test]
fn reindex_plaintext_vault_needs_no_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault");
    copy_dir(&demo(), &vault);

    let out = Command::new(bin())
        .args(["reindex", "--json", "--no-input", "--vault"])
        .arg(&vault)
        .env_remove("CONFIDANT_DEVICE_KEY")
        .env_remove("CONFIDANT_TEST_DEVICE_KEY")
        .output()
        .unwrap();
    assert!(out.status.success(), "reindex failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["records_decrypted"], 0);
    assert_eq!(v["skipped_encrypted"], 0);
    assert!(v["records_copied"].as_u64().unwrap() > 0);
    assert!(v["files_copied"].as_u64().unwrap() >= v["records_copied"].as_u64().unwrap());
}

/// B3: refuse unless the corpus is git-ignored, then build with the corpus
/// dir 0700 and every file 0600.
#[test]
fn reindex_gitignore_refusal_and_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault");
    copy_dir(&demo(), &vault);
    git(&vault, &["init", "-q"]);

    // Phase 1: a git repo without `.confidant/` ignored refuses, writes
    // nothing, and names the fix.
    let out = run(&vault, &["reindex", "--json", "--no-input"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["code"], "E_REINDEX_REFUSED");
    assert!(
        v["error"]["fix"].as_str().unwrap().contains(".gitignore"),
        "{v}"
    );
    assert!(
        !vault.join(".confidant/qmd-corpus").exists(),
        "refusal must write no corpus"
    );

    // Phase 2: ignore `.confidant/`, rebuild, and check permissions.
    std::fs::write(vault.join(".gitignore"), ".confidant/\n").unwrap();
    let out = run(&vault, &["reindex", "--json", "--no-input"]);
    assert!(out.status.success(), "reindex failed: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let corpus = vault.join(".confidant/qmd-corpus");
        let dir_mode = std::fs::metadata(&corpus).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "corpus dir mode {dir_mode:o}");
        for rel in corpus_files(&vault) {
            let file_mode = std::fs::metadata(corpus.join(&rel))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600, "{rel} mode {file_mode:o}");
        }
        // Nested record directories are 0700 too.
        let nested = corpus.join("people");
        if nested.is_dir() {
            let mode = std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "nested dir mode {mode:o}");
        }
    }
}

/// The qmd-index skill delegates the corpus to `confidant reindex` and no
/// longer walks the vault. Behavioral assertion (a fake `confidant` records
/// the argv it receives; a fake `qmd` absorbs registration): it survives any
/// rewrite of the script's internals, unlike asserting on source text.
#[cfg(unix)]
#[test]
fn qmd_index_skill_delegates_to_reindex() {
    use std::os::unix::fs::PermissionsExt;

    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../skills/qmd-search/bin/qmd-index.py");
    if !script.is_file() {
        return; // skill not checked out
    }

    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault");
    std::fs::create_dir_all(&vault).unwrap();
    std::fs::write(
        vault.join("confidant.toml"),
        "spec = \"0.1\"\nvault_id = \"01TEST00000000000000000000\"\n",
    )
    .unwrap();

    let bindir = tmp.path().join("bin");
    std::fs::create_dir_all(&bindir).unwrap();
    let log = tmp.path().join("calls.log");

    // Fake `confidant`: record argv and emit a valid reindex --json payload
    // without building anything (proving the skill didn't walk the vault).
    let corpus = vault.join(".confidant/qmd-corpus");
    let fake_confidant = bindir.join("fake-confidant");
    let body = format!(
        "#!/bin/sh\necho \"confidant $*\" >> {log}\nprintf '%s' '{{\"ok\":true,\"corpus\":\"{corpus}\",\"files_copied\":2,\"records_copied\":1,\"records_decrypted\":1,\"ledger_lines_kept\":1,\"skipped_encrypted\":0,\"refused_envelopes\":0}}'\n",
        log = log.display(),
        corpus = corpus.display(),
    );
    std::fs::write(&fake_confidant, body).unwrap();
    std::fs::set_permissions(&fake_confidant, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Fake `qmd`: absorb collection registration.
    let fake_qmd = bindir.join("qmd");
    std::fs::write(
        &fake_qmd,
        format!("#!/bin/sh\necho \"qmd $*\" >> {}\nexit 0\n", log.display()),
    )
    .unwrap();
    std::fs::set_permissions(&fake_qmd, std::fs::Permissions::from_mode(0o755)).unwrap();

    let path = format!(
        "{}:{}",
        bindir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = match Command::new("python3")
        .arg(&script)
        .args(["--vault"])
        .arg(&vault)
        .args(["--cli"])
        .arg(&fake_confidant)
        .arg("--i-confirm-encrypted-disk")
        .env("PATH", path)
        .output()
    {
        Ok(out) => out,
        Err(_) => return, // python3 unavailable: skip
    };
    assert!(
        out.status.success(),
        "qmd-index failed: {}\n{}",
        stderr(&out),
        stdout(&out)
    );

    let calls = std::fs::read_to_string(&log).unwrap();
    // Delegation: the CLI was invoked with `reindex`.
    assert!(
        calls
            .lines()
            .any(|l| l.starts_with("confidant ") && l.contains(" reindex ")),
        "confidant reindex was not invoked:\n{calls}"
    );
    // The skill registered the corpus the CLI reported.
    assert!(
        calls
            .lines()
            .any(|l| l.starts_with("qmd ") && l.contains("collection add ")),
        "qmd collection add was not invoked:\n{calls}"
    );
    // The skill no longer builds the corpus itself: the fake CLI never
    // wrote it, so its absence proves the script didn't walk the vault.
    assert!(
        !corpus.exists(),
        "the skill built the corpus; it must only delegate"
    );
}
