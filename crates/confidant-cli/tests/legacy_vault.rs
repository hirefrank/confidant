//! #821: a ≤0.7 encrypted vault fails closed on every read path.
//!
//! All data is fake. The read-only sniff never decrypts; these tests pin the
//! one clear command code and the absence of file paths, ids, record names,
//! and parse-error streams.

use std::io::Write;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_confidant")
}

const PERSON: &str = "p-01M3TC5H00MPJG000000000101";

fn write_config(root: &Path) {
    std::fs::write(
        root.join("confidant.toml"),
        "spec = \"0.1\"\nvault_id = \"01M3TC5H00MPJG005VQC00000B\"\n\n[checks]\nas_of = \"2026-10-08\"\n",
    )
    .unwrap();
}

fn person_dir(root: &Path) -> std::path::PathBuf {
    root.join(format!("people/{PERSON}"))
}

fn write_plaintext_person(root: &Path) {
    let dir = person_dir(root);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("profile.md"),
        format!("---\nid: {PERSON}\ntype: person\nname: Robin Example\n---\n\nFake person.\n"),
    )
    .unwrap();
}

fn write_encrypted_person(root: &Path) {
    let dir = person_dir(root);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("profile.md"),
        format!(
            "---\nid: {PERSON}\ntype: person\nname: Robin Example\nenc: xchacha20poly1305\nkey_id: {PERSON}/e0\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\n\nAQID\n"
        ),
    )
    .unwrap();
}

fn write_keys_tree(root: &Path) {
    std::fs::create_dir_all(root.join("keys/shared")).unwrap();
    std::fs::write(root.join("keys/operator.toml"), "fake operator\n").unwrap();
}

fn write_encrypted_ledger(root: &Path) {
    std::fs::create_dir_all(root.join("ledger/2026")).unwrap();
    std::fs::write(root.join("ledger/2026/10.cfd"), "enc: xchacha20poly1305\n").unwrap();
}

fn run(args: &[&str], vault: &Path) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .arg("--vault")
        .arg(vault)
        .output()
        .unwrap()
}

fn json_of(out: &std::process::Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}); status={}; stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn assert_legacy_error(v: &Value, command: &str) {
    assert_eq!(v["ok"], false, "{command}: {v}");
    assert_eq!(
        v["error"]["code"], "E_VAULT_LEGACY_ENCRYPTED",
        "{command}: {v}"
    );
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains("encrypted Confidant ≤0.7"), "{message}");
    assert!(message.contains("confidant init"), "{message}");
    for leak in ["people/", "ledger/", "keys/", PERSON, "Robin Example"] {
        assert!(
            !message.contains(leak),
            "{command} message leaked {leak}: {message}"
        );
    }
}

#[test]
fn check_refuses_a_keys_tree_with_one_error() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path());
    write_keys_tree(dir.path());

    let out = run(["check", "--json", "--no-input"].as_slice(), dir.path());
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let v = json_of(&out);
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["summary"]["errors"], 1, "{v}");
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{v}");
    let finding = &findings[0];
    assert_eq!(finding["code"], "E_VAULT_LEGACY_ENCRYPTED");
    assert_eq!(finding["severity"], "error");
    assert!(finding.get("file").is_none(), "{finding}");
    assert!(finding.get("line").is_none(), "{finding}");
    assert!(finding.get("id").is_none(), "{finding}");
    let dumped = serde_json::to_string(findings).unwrap();
    for leak in ["people/", "ledger/", "keys/", "operator.toml", PERSON] {
        assert!(!dumped.contains(leak), "findings leaked {leak}: {dumped}");
    }
    assert!(!dumped.contains("E_PARSE"), "{dumped}");
}

#[test]
fn check_refuses_an_enc_frontmatter_header() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path());
    write_encrypted_person(dir.path());

    let out = run(["check", "--json", "--no-input"].as_slice(), dir.path());
    assert_eq!(out.status.code(), Some(1));
    let v = json_of(&out);
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{v}");
    assert_eq!(findings[0]["code"], "E_VAULT_LEGACY_ENCRYPTED");
    let dumped = serde_json::to_string(findings).unwrap();
    for leak in ["people/", PERSON, "Robin Example", "E_PARSE"] {
        assert!(!dumped.contains(leak), "findings leaked {leak}: {dumped}");
    }
}

#[test]
fn check_refuses_an_enc_ledger_line() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path());
    write_encrypted_ledger(dir.path());

    let out = run(["check", "--json", "--no-input"].as_slice(), dir.path());
    assert_eq!(out.status.code(), Some(1));
    let v = json_of(&out);
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{v}");
    assert_eq!(findings[0]["code"], "E_VAULT_LEGACY_ENCRYPTED");
    let dumped = serde_json::to_string(findings).unwrap();
    for leak in ["ledger/", "10.cfd", "E_PARSE"] {
        assert!(!dumped.contains(leak), "findings leaked {leak}: {dumped}");
    }
}

#[test]
fn plaintext_vault_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path());
    write_plaintext_person(dir.path());

    let check = run(["check", "--json", "--no-input"].as_slice(), dir.path());
    assert_eq!(check.status.code(), Some(0));
    let v = json_of(&check);
    assert_eq!(v["ok"], true, "{v}");
    assert!(!v.to_string().contains("E_VAULT_LEGACY_ENCRYPTED"), "{v}");

    let find = run(
        ["find", "Robin", "--json", "--no-input"].as_slice(),
        dir.path(),
    );
    assert!(find.status.success());
    let v = json_of(&find);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["matches"].as_array().unwrap().len(), 1, "{v}");

    let context = run(
        ["context", PERSON, "--json", "--no-input"].as_slice(),
        dir.path(),
    );
    assert!(context.status.success());
    let v = json_of(&context);
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["entity"]["id"], PERSON);
}

#[test]
fn find_and_context_refuse_a_legacy_vault() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path());
    write_encrypted_person(dir.path());

    for (command, args) in [
        ("find", ["find", "Robin", "--json", "--no-input"]),
        ("context", ["context", PERSON, "--json", "--no-input"]),
    ] {
        let out = run(args.as_slice(), dir.path());
        assert_eq!(out.status.code(), Some(1), "{command}: {out:?}");
        let v = json_of(&out);
        assert_legacy_error(&v, command);
        assert!(
            v.get("matches").is_none() && v.get("entity").is_none(),
            "{command} returned a partial payload: {v}"
        );
    }
}

#[test]
fn allowlist_resolve_and_alias_refuse_a_legacy_vault() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path());
    write_encrypted_person(dir.path());

    for (command, args) in [
        ("allowlist", vec!["allowlist", "--json", "--no-input"]),
        ("resolve", vec!["resolve", "Robin", "--json", "--no-input"]),
        (
            "alias resolve",
            vec![
                "alias",
                "resolve",
                "email",
                "robin@example.invalid",
                "--json",
                "--no-input",
            ],
        ),
    ] {
        let out = run(args.as_slice(), dir.path());
        assert_eq!(out.status.code(), Some(1), "{command}: {out:?}");
        let v = json_of(&out);
        assert_legacy_error(&v, command);
    }
}

/// The MCP `check`, `find`, and `context` tools shell out to the same CLI, so
/// the same gates apply. One legacy vault, three tool calls, three codes.
#[test]
fn mcp_check_find_and_context_surface_the_legacy_code() {
    let dir = tempfile::tempdir().unwrap();
    write_config(dir.path());
    write_encrypted_person(dir.path());

    let mut child = Command::new(bin())
        .args(["mcp", "--vault"])
        .arg(dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        for message in [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check","arguments":{}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find","arguments":{"query":"Robin"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"context","arguments":{"person":"p-01M3TC5H00MPJG000000000101"}}}"#,
        ] {
            writeln!(stdin, "{message}").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let responses: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(responses.len(), 3, "{responses:?}");

    let body = |index: usize| -> Value {
        let text = responses[index]["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        serde_json::from_str(text).unwrap()
    };

    let check = body(0);
    assert_eq!(check["ok"], false, "{check}");
    assert_eq!(
        check["findings"][0]["code"], "E_VAULT_LEGACY_ENCRYPTED",
        "{check}"
    );
    assert!(
        !check.to_string().contains("E_PARSE"),
        "check streamed parse errors: {check}"
    );

    for (index, command) in [(1, "find"), (2, "context")] {
        let response = body(index);
        assert_legacy_error(&response, command);
    }
}
