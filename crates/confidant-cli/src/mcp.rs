//! Thin MCP server over stdio.
//!
//! This is a JSON-RPC 2.0 (newline-delimited) wrapper that shells out to
//! this very binary (`std::env::current_exe`) with `--json` for every tool
//! call. There is exactly one implementation of each operation — the CLI's —
//! so the MCP surface can never diverge from it (ADR-7: thin MCP server
//! wrapping the CLI, never a second way in).
//!
//! Supported: `initialize`, `notifications/initialized`, `tools/list`,
//! `tools/call`. Everything else is `-32601`.

use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use serde_json::{json, Value};

const PROTOCOL_VERSION: &str = "2024-11-05";

pub fn run(vault: &Path) -> anyhow::Result<ExitCode> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(resp) = handle(&line, vault) {
            let mut out = stdout.lock();
            writeln!(out, "{}", serde_json::to_string(&resp)?)?;
            out.flush()?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn handle(line: &str, vault: &Path) -> Option<Value> {
    let msg: Value = match serde_json::from_str(line) {
        Ok(m) => m,
        Err(_) => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {"code": -32700, "message": "parse error"},
            }))
        }
    };
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let respond = |result: Value| -> Option<Value> {
        id.clone()
            .map(|id| json!({"jsonrpc": "2.0", "id": id, "result": result}))
    };
    let err = |code: i32, message: String| -> Option<Value> {
        id.clone().map(
            |id| json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
        )
    };
    match method {
        "initialize" => respond(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "confidant", "version": env!("CARGO_PKG_VERSION")},
        })),
        "notifications/initialized" => None,
        "tools/list" => respond(json!({ "tools": tools() })),
        "tools/call" => {
            let params = msg.get("params").cloned().unwrap_or(json!({}));
            match call_tool(&params, vault) {
                Ok(text) => respond(json!({ "content": [{"type": "text", "text": text}] })),
                Err(e) => respond(json!({
                    "content": [{"type": "text", "text": e}],
                    "isError": true,
                })),
            }
        }
        _ => {
            if id.is_some() {
                err(-32601, format!("method not found: {method}"))
            } else {
                None
            }
        }
    }
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": schema,
    })
}

fn obj(required: &[&str], props: Value) -> Value {
    json!({
        "type": "object",
        "required": required,
        "properties": props,
        "additionalProperties": false,
    })
}

fn str_prop(desc: &str) -> Value {
    json!({"type": "string", "description": desc})
}

fn tools() -> Vec<Value> {
    vec![
        tool("check", "Run the vault check engine.", obj(&[], json!({}))),
        tool(
            "find",
            "Search records and ledger lines.",
            obj(
                &["query"],
                json!({"query": str_prop("Case-insensitive substring.")}),
            ),
        ),
        tool(
            "context",
            "Context bundle for one person. Honors no-ai and --exclude-private.",
            obj(
                &["person"],
                json!({
                    "person": str_prop("Opaque person id (p-…)."),
                    "exclude_private": {"type": "boolean", "description": "Strip name, profile, and bodies."},
                }),
            ),
        ),
        tool(
            "log_session",
            "Append a session ledger line. One commit; check-gated.",
            obj(
                &["person", "duration"],
                json!({
                    "person": str_prop("Opaque person id (p-…)."),
                    "duration": str_prop("Like 60m or 1h30m."),
                    "tag": str_prop("Billing tag: paid, pps, or comp."),
                    "date": str_prop("YYYY-MM-DD; default today."),
                    "note": str_prop("Session note text; creates a note record."),
                    "src": str_prop("Source token."),
                    "request_id": str_prop("Idempotency key."),
                    "dry_run": {"type": "boolean", "description": "Show the logical change only."},
                }),
            ),
        ),
        tool(
            "import_ledger",
            "Bulk-append ledger lines from a file. One commit; check-gated.",
            obj(
                &["file"],
                json!({
                    "file": str_prop("Path to a file of ledger lines."),
                    "request_id": str_prop("Idempotency key."),
                    "dry_run": {"type": "boolean", "description": "Show the logical change only."},
                }),
            ),
        ),
        tool(
            "note_add",
            "Create a note record under people/<person>/notes/. One commit; check-gated.",
            obj(
                &["person", "body_file"],
                json!({
                    "person": str_prop("Opaque person id (p-…)."),
                    "body_file": str_prop("Path to a file holding the note body."),
                    "date": str_prop("YYYY-MM-DD; default today."),
                    "no_ai": {"type": "boolean", "description": "Mark the note no-ai."},
                    "request_id": str_prop("Idempotency key."),
                    "dry_run": {"type": "boolean", "description": "Show the logical change only."},
                }),
            ),
        ),
        tool(
            "schema",
            "The agent-contract JSON Schema.",
            obj(&[], json!({})),
        ),
        tool("doctor", "Vault health checks.", obj(&[], json!({}))),
    ]
}

fn get_str(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| format!("missing required argument: {key}"))
}

fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(|v| v.as_str()).map(str::to_owned)
}

fn get_bool(args: &Value, key: &str) -> bool {
    args.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// Build the CLI argv for a tool call and run it via `current_exe`.
fn call_tool(params: &Value, vault: &Path) -> Result<String, String> {
    let name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| "missing tool name".to_owned())?;
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    // Globals first: every tool call is machine-readable, vault-pinned,
    // and non-interactive.
    let mut cli: Vec<String> = vec![
        "--json".to_owned(),
        "--no-input".to_owned(),
        "--vault".to_owned(),
        vault.display().to_string(),
    ];
    if get_bool(&args, "dry_run") {
        cli.push("--dry-run".to_owned());
    }
    if let Some(r) = opt_str(&args, "request_id") {
        cli.push("--request-id".to_owned());
        cli.push(r);
    }

    match name {
        "check" => cli.push("check".to_owned()),
        "find" => {
            cli.push("find".to_owned());
            cli.push(get_str(&args, "query")?);
        }
        "context" => {
            cli.push("context".to_owned());
            cli.push(get_str(&args, "person")?);
            if get_bool(&args, "exclude_private") {
                cli.push("--exclude-private".to_owned());
            }
        }
        "log_session" => {
            cli.push("log".to_owned());
            cli.push("session".to_owned());
            cli.push(get_str(&args, "person")?);
            cli.push(get_str(&args, "duration")?);
            if let Some(t) = opt_str(&args, "tag") {
                cli.push(t);
            }
            for (flag, key) in [("--date", "date"), ("--note", "note"), ("--src", "src")] {
                if let Some(v) = opt_str(&args, key) {
                    cli.push(flag.to_owned());
                    cli.push(v);
                }
            }
        }
        "import_ledger" => {
            cli.push("import".to_owned());
            cli.push("--file".to_owned());
            cli.push(get_str(&args, "file")?);
        }
        "note_add" => {
            cli.push("note".to_owned());
            cli.push("add".to_owned());
            cli.push("--person".to_owned());
            cli.push(get_str(&args, "person")?);
            cli.push("--body-file".to_owned());
            cli.push(get_str(&args, "body_file")?);
            if let Some(d) = opt_str(&args, "date") {
                cli.push("--date".to_owned());
                cli.push(d);
            }
            if get_bool(&args, "no_ai") {
                cli.push("--no-ai".to_owned());
            }
        }
        "schema" => cli.push("schema".to_owned()),
        "doctor" => cli.push("doctor".to_owned()),
        _ => return Err(format!("unknown tool: {name}")),
    }

    let exe = std::env::current_exe().map_err(|e| format!("cannot find CLI binary: {e}"))?;
    let out = std::process::Command::new(exe)
        .args(&cli)
        .output()
        .map_err(|e| format!("cannot run CLI: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let detail = stderr.trim();
        Err(if detail.is_empty() {
            format!("confidant {} failed with no message", cli.join(" "))
        } else {
            format!("confidant {} failed: {detail}", cli.join(" "))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_round_trip() {
        let resp = handle(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            Path::new("/tmp"),
        )
        .unwrap();
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(resp["id"], 1);
    }

    #[test]
    fn initialized_notification_gets_no_response() {
        assert!(handle(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            Path::new("/tmp"),
        )
        .is_none());
    }

    #[test]
    fn tools_list_names_all_tools() {
        let resp = handle(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            Path::new("/tmp"),
        )
        .unwrap();
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for expected in [
            "check",
            "find",
            "context",
            "log_session",
            "import_ledger",
            "note_add",
            "schema",
            "doctor",
        ] {
            assert!(names.contains(&expected), "missing tool {expected}");
        }
    }

    #[test]
    fn unknown_method_is_32601() {
        let resp = handle(
            r#"{"jsonrpc":"2.0","id":3,"method":"nope"}"#,
            Path::new("/tmp"),
        )
        .unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn parse_error_has_null_id() {
        let resp = handle("not json", Path::new("/tmp")).unwrap();
        assert_eq!(resp["error"]["code"], -32700);
        assert!(resp["id"].is_null());
    }
}
