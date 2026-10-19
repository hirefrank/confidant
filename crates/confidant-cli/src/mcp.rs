//! Thin MCP server over stdio.
//!
//! This is a JSON-RPC 2.0 (newline-delimited) wrapper that shells out to
//! this very binary (`std::env::current_exe`) with `--json` for every tool
//! call. There is exactly one implementation of each operation — the CLI's —
//! so the MCP surface can never diverge from it (ADR-7: thin MCP server
//! wrapping the CLI, never a second way in).
//!
//! Pack scope (#178, #232): the server instance may be configured with a
//! ceiling (`confidant mcp --packs coaching@0.1`). Every `find` / `context`
//! call runs under that ceiling; a per-call `packs` argument can only
//! narrow it, never widen it. The ceiling is validated by the CLI
//! sub-invocation (unknown / disabled pack = hard error); the widen check
//! here is a string-subset check, so it holds even for unvalidated names.
//!
//! Supported: `initialize`, `notifications/initialized`, `tools/list`,
//! `tools/call`. Everything else is `-32601`.

use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use serde_json::{json, Value};

const PROTOCOL_VERSION: &str = "2024-11-05";

pub fn run(vault: &Path, ceiling: Option<String>) -> anyhow::Result<ExitCode> {
    let ceiling_set: Option<BTreeSet<String>> = ceiling.map(|raw| {
        raw.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    });
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(resp) = handle(&line, vault, &ceiling_set) {
            let mut out = stdout.lock();
            writeln!(out, "{}", serde_json::to_string(&resp)?)?;
            out.flush()?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Effective `packs` for one tool call under a ceiling: `None` means
/// unscoped (no `--packs` flag). A per-call list must be a subset of the
/// ceiling, else it is an error (never widen, #232 Q1).
fn effective_packs(
    ceiling: &Option<BTreeSet<String>>,
    per_call: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, String> {
    let Some(names) = per_call else {
        return Ok(ceiling.as_ref().map(|c| c.iter().cloned().collect()));
    };
    if let Some(allowed) = ceiling {
        for name in &names {
            if !allowed.contains(name) {
                return Err(format!(
                    "per-call scope {name} is outside the connection's pack scope"
                ));
            }
        }
    }
    Ok(Some(names))
}

fn handle(line: &str, vault: &Path, ceiling: &Option<BTreeSet<String>>) -> Option<Value> {
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
            match call_tool(&params, vault, ceiling) {
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
            "Search records and ledger lines. Honors the connection's pack scope; an optional packs list can only narrow it.",
            obj(
                &["query"],
                json!({"query": str_prop("Case-insensitive substring."),
                    "packs": {"type": "array", "items": {"type": "string"}, "description": "Pack scope for this call (subset of the connection's scope). Unset = the connection's scope."}}),
            ),
        ),
        tool(
            "context",
            "Context bundle for one person. Honors no-ai; private data is stripped by default. Honors the connection's pack scope; an optional packs list can only narrow it.",
            obj(
                &["person"],
                json!({
                    "person": str_prop("Opaque person id (p-…)."),
                    "exclude_private": {"type": "boolean", "description": "Strip name, profile, and bodies. Default true: private data is stripped unless explicitly set to false."},
                    "packs": {"type": "array", "items": {"type": "string"}, "description": "Pack scope for this call (subset of the connection's scope). Unset = the connection's scope."},
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
            "log_touch",
            "Append a personal touchpoint ledger line (call, text, email, meet, meal, event, gift, or other). One commit; check-gated.",
            obj(
                &["person", "kind"],
                json!({
                    "person": str_prop("Opaque person id (p-…)."),
                    "kind": str_prop("Touchpoint kind: call, text, email, meet, meal, event, gift, or other."),
                    "date": str_prop("YYYY-MM-DD; default today."),
                    "note": str_prop("Touchpoint note text; creates a note record."),
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
        tool(
            "pack_skill",
            "Agent-facing skill text for the vault's packs: fields, verbs, findings and what to do about them. Honors the connection's pack scope; an optional packs list can only narrow it.",
            obj(
                &[],
                json!({
                    "pack": {"type": "string", "description": "Pack name, e.g. coaching@0.1. Unset = combined skill generated from the effective scope."},
                    "packs": {"type": "array", "items": {"type": "string"}, "description": "Pack scope for this call (subset of the connection's scope). Unset = the connection's scope."},
                }),
            ),
        ),
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

/// Privacy default for the `context` tool (#50): strip private data unless
/// the caller explicitly opts in with `exclude_private: false`.
///
/// Backward compatibility: callers that passed `exclude_private: true`
/// get the same behavior as before (stripped); callers that passed
/// `exclude_private: false` explicitly keep getting private data. Only
/// callers that passed nothing change — and they change toward the
/// privacy-safe default, which is the point of #50.
fn context_strips_private(args: &Value) -> bool {
    !matches!(
        args.get("exclude_private").and_then(|v| v.as_bool()),
        Some(false)
    )
}

fn opt_packs(args: &Value) -> Option<Vec<String>> {
    args.get("packs").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
    })
}

/// Build the CLI argv for a tool call and run it via `current_exe`.
fn call_tool(
    params: &Value,
    vault: &Path,
    ceiling: &Option<BTreeSet<String>>,
) -> Result<String, String> {
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
            // Flags first, then `--` before the agent-supplied positional:
            // a query of `--packs=…` must be a needle, never a flag
            // (today it only fails closed via clap's duplicate-flag error).
            if let Some(packs) = effective_packs(ceiling, opt_packs(&args))? {
                cli.push("--packs".to_owned());
                cli.push(packs.join(","));
            }
            cli.push("--".to_owned());
            cli.push(get_str(&args, "query")?);
        }
        "context" => {
            cli.push("context".to_owned());
            if let Some(packs) = effective_packs(ceiling, opt_packs(&args))? {
                cli.push("--packs".to_owned());
                cli.push(packs.join(","));
            }
            if context_strips_private(&args) {
                cli.push("--exclude-private".to_owned());
            }
            cli.push("--".to_owned());
            cli.push(get_str(&args, "person")?);
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
        "log_touch" => {
            cli.push("log".to_owned());
            cli.push("touch".to_owned());
            cli.push(get_str(&args, "person")?);
            cli.push(get_str(&args, "kind")?);
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
        "pack_skill" => {
            cli.push("help".to_owned());
            match opt_str(&args, "pack") {
                Some(p) => cli.push(format!("pack:{p}")),
                None => cli.push("pack".to_owned()),
            }
            if let Some(packs) = effective_packs(ceiling, opt_packs(&args))? {
                cli.push("--packs".to_owned());
                cli.push(packs.join(","));
            }
        }
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
    } else if !stdout.trim().is_empty() {
        // JSON mode writes the error envelope to stdout; stderr is empty.
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
            &None,
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
            &None,
        )
        .is_none());
    }

    #[test]
    fn tools_list_never_exposes_the_operator_only_record_reads() {
        // #389 Q5 / #216: `record show --for-edit` decrypts no-ai records,
        // and `record edit` rewrites records. Neither may be reachable from
        // an agent connection, so neither appears in the tool whitelist —
        // which is the only way MCP can invoke the CLI (`call_tool` maps
        // known names to argv and rejects everything else).
        let resp = handle(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            Path::new("/tmp"),
            &None,
        )
        .unwrap();
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for forbidden in [
            "record_show",
            "record_edit",
            "record_resolve",
            "record_list",
            "note_show",
            "note_edit",
            "pack",
            "pack_add",
            "pack_list",
            "pack_verify",
            "pack_remove",
            "pack_update",
            "for_edit",
            "for_operator",
            "show",
            "edit",
            "list",
            "resolve",
        ] {
            assert!(
                !names.contains(&forbidden),
                "{forbidden:?} is exposed over MCP: {names:?}"
            );
        }
        // And an agent asking for it by name is refused. The refusal is an
        // `isError` tool result (not a JSON-RPC error), so assert on that.
        let resp = handle(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"record_show","arguments":{"id":"p-01ABC"}}}"#,
            Path::new("/tmp"),
            &None,
        )
        .unwrap();
        assert_eq!(
            resp["result"]["isError"],
            serde_json::json!(true),
            "an unknown tool name must be refused: {resp}"
        );
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .contains("unknown tool"),
            "{resp}"
        );
        // #557: the note read/edit pair is operator-only for the same reason.
        let resp = handle(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"note_edit","arguments":{"id":"n-01ABC","file":"x.md"}}}"#,
            Path::new("/tmp"),
            &None,
        )
        .unwrap();
        assert_eq!(
            resp["result"]["isError"],
            serde_json::json!(true),
            "an unknown tool name must be refused: {resp}"
        );
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .contains("unknown tool"),
            "{resp}"
        );
    }

    /// PD10 (#445): pack install/update/remove is operator-only, never
    /// reachable over MCP. The whitelist is the only way MCP can invoke the
    /// CLI (`call_tool` maps known names to argv and rejects everything
    /// else), so asserting no such tool is listed — and that a call by name
    /// is refused — pins the property.
    #[test]
    fn mcp_whitelist_has_no_pack_tools() {
        let whitelist = tools();
        let names: Vec<&str> = whitelist
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for forbidden in [
            "pack",
            "pack_add",
            "pack_list",
            "pack_verify",
            "pack_remove",
            "pack_update",
        ] {
            assert!(
                !names.contains(&forbidden),
                "{forbidden:?} is exposed over MCP: {names:?}"
            );
            // An agent asking for it by name is refused (an `isError` tool
            // result, not a JSON-RPC error).
            let resp = handle(
                &format!(
                    r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"{forbidden}","arguments":{{}}}}}}"#
                ),
                Path::new("/tmp"),
                &None,
            )
            .unwrap();
            assert_eq!(
                resp["result"]["isError"], true,
                "{forbidden} must be refused: {resp}"
            );
            assert!(
                resp["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("unknown tool"),
                "{forbidden}: {resp}"
            );
        }
        // `pack_skill` is the one pack-shaped tool and it only reads skill
        // text; it is not an install path.
        assert!(names.contains(&"pack_skill"));
    }

    /// #558 / #559: `record list` is the operator-only roster. The
    /// `--for-operator` flag gates `no-ai` visibility, so no agent path may
    /// reach the command or the flag. The whitelist is the only way MCP can
    /// invoke the CLI (`call_tool` maps known names to argv and rejects
    /// everything else), so asserting no such tool is listed — and that a
    /// call by name is refused — pins the property. The schemas are also
    /// checked so a future tool cannot smuggle the flag in as an argument.
    #[test]
    fn mcp_whitelist_has_no_roster_tool_or_operator_flag() {
        let whitelist = tools();
        let names: Vec<&str> = whitelist
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for forbidden in ["record_list", "record_list_for_operator", "list", "roster"] {
            assert!(
                !names.contains(&forbidden),
                "{forbidden:?} is exposed over MCP: {names:?}"
            );
            let resp = handle(
                &format!(
                    r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"{forbidden}","arguments":{{}}}}}}"#
                ),
                Path::new("/tmp"),
                &None,
            )
            .unwrap();
            assert_eq!(
                resp["result"]["isError"], true,
                "{forbidden} must be refused: {resp}"
            );
            assert!(
                resp["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("unknown tool"),
                "{forbidden}: {resp}"
            );
        }
        // No tool schema advertises the operator flag, so even a tool built
        // on `record list` later cannot pass it through `tools/call`.
        for t in &whitelist {
            let schema = t["inputSchema"].to_string();
            assert!(
                !schema.contains("for_operator"),
                "tool {} exposes for_operator: {schema}",
                t["name"]
            );
        }
    }

    #[test]
    fn tools_list_names_all_tools() {
        let resp = handle(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            Path::new("/tmp"),
            &None,
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
            "log_touch",
            "import_ledger",
            "note_add",
            "schema",
            "doctor",
            "pack_skill",
        ] {
            assert!(names.contains(&expected), "missing tool {expected}");
        }
    }

    #[test]
    fn unknown_method_is_32601() {
        let resp = handle(
            r#"{"jsonrpc":"2.0","id":3,"method":"nope"}"#,
            Path::new("/tmp"),
            &None,
        )
        .unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn parse_error_has_null_id() {
        let resp = handle("not json", Path::new("/tmp"), &None).unwrap();
        assert_eq!(resp["error"]["code"], -32700);
        assert!(resp["id"].is_null());
    }

    #[test]
    fn context_strips_private_by_default() {
        // #50: absent -> strip (the new privacy-safe default).
        assert!(context_strips_private(&json!({})));
        assert!(context_strips_private(&json!({"person": "p-01"})));
    }

    #[test]
    fn context_exclude_private_true_still_strips() {
        // Backward compatible: explicit true keeps the old behavior.
        assert!(context_strips_private(&json!({"exclude_private": true})));
    }

    #[test]
    fn context_exclude_private_false_opts_in() {
        // The only way to get private data: explicitly set false.
        assert!(!context_strips_private(&json!({"exclude_private": false})));
    }

    #[test]
    fn context_strips_private_ignores_non_bool() {
        // Non-boolean values fail closed toward stripping.
        assert!(context_strips_private(&json!({"exclude_private": "yes"})));
        assert!(context_strips_private(&json!({"exclude_private": 1})));
    }

    #[test]
    fn effective_packs_narrows_never_widens() {
        let ceiling: Option<BTreeSet<String>> =
            Some(["coaching@0.1".to_string()].into_iter().collect());
        // No per-call scope: the ceiling.
        assert_eq!(
            effective_packs(&ceiling, None).unwrap(),
            Some(vec!["coaching@0.1".to_string()])
        );
        // Narrowing to a subset of the ceiling is fine.
        assert_eq!(
            effective_packs(&ceiling, Some(vec!["coaching@0.1".to_string()])).unwrap(),
            Some(vec!["coaching@0.1".to_string()])
        );
        // Widening past the ceiling is an error (#232 acceptance).
        let err = effective_packs(
            &ceiling,
            Some(vec!["coaching@0.1".to_string(), "testpack@0.1".to_string()]),
        )
        .unwrap_err();
        assert!(err.contains("outside"));
        // No ceiling: per-call resolves as-is; none stays unscoped.
        assert_eq!(
            effective_packs(&None, Some(vec!["testpack@0.1".to_string()])).unwrap(),
            Some(vec!["testpack@0.1".to_string()])
        );
        assert_eq!(effective_packs(&None, None).unwrap(), None);
    }

    #[test]
    fn per_call_widening_is_an_mcp_error() {
        // #232 acceptance: a scoped call never widens past the ceiling.
        let ceiling: Option<BTreeSet<String>> =
            Some(["coaching@0.1".to_string()].into_iter().collect());
        let resp = handle(
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"find","arguments":{"query":"Ada","packs":["coaching@0.1","testpack@0.1"]}}}"#,
            Path::new("/tmp"),
            &ceiling,
        )
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("outside"));
    }
}
