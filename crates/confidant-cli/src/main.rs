//! `confidant` — local-first, git-backed, encrypted CRM.
//!
//! Read commands (`check`, `find`, `context`, `doctor`, `schema`, `help`)
//! never mutate the vault. Write commands (`log session`, `import`,
//! `note add`) funnel through the [`write`] pipeline: one commit per write,
//! `check` runs before every commit and a failing check blocks the write.
//! `mcp` is a thin stdio JSON-RPC wrapper around this binary — never a
//! second way in.
//!
//! [`write`]: confidant_core::write

mod mcp;

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use confidant_core::check::parse_fail_on;
use confidant_core::config::parse_iso_date;
use confidant_core::context::build_context;
use confidant_core::discover::{load_user_config, resolve, Discovery};
use confidant_core::error::DomainError;
use confidant_core::id::{Prefix, RecordId};
use confidant_core::ledger::{parse_duration_minutes, parse_strict_date};
use confidant_core::record::{Record, RecordKind};
use confidant_core::schema::contract_schema;
use confidant_core::write::{
    apply_write, require_git_repo, FileChange, PendingWrite, WriteOptions, WriteOutcome,
};
use confidant_core::{check_vault, load_vault, search, CheckOptions};

#[derive(Parser, Debug)]
#[command(
    name = "confidant",
    version,
    disable_help_subcommand = true,
    about = "Plain-text, git-native CRM for one operator and their agents.",
    after_help = "Examples:\n  \
        confidant check --vault ./examples/demo-vault\n  \
        confidant log session p-01H… 60m paid --json --no-input\n  \
        confidant context p-01H… --json\n  \
        CONFIDANT_VAULT=./examples/demo-vault confidant find goals --json"
)]
struct Cli {
    /// Vault directory (ADR-11, first).
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    /// Machine-readable JSON on stdout. Every object includes `vault`.
    #[arg(long, global = true)]
    json: bool,

    /// Never prompt; fail instead (ADR-7).
    #[arg(long, global = true)]
    no_input: bool,

    /// Show the logical change; write nothing, commit nothing (writes only).
    #[arg(long, global = true)]
    dry_run: bool,

    /// Idempotency key for this write (HMAC idempotency, ADR-7).
    ///
    /// Must carry at least 128 bits of entropy (at least 22 characters):
    /// the Request-Hash trailer HMACs the canonical request with the raw id
    /// as key, and trailers are permanent, so a guessable id lets anyone with
    /// repo read access confirm guesses about note contents offline, even
    /// after shredding. Generate a ULID or UUIDv4 once and reuse it on retry.
    #[arg(long, global = true)]
    request_id: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Validate the vault and print findings (read-only).
    Check {
        /// Fail when a finding reaches this severity (default: error).
        #[arg(long, default_value = "error")]
        fail_on: String,
        /// Date gap rules use (YYYY-MM-DD). Overrides [checks].as_of.
        #[arg(long)]
        as_of: Option<String>,
    },
    /// Scan plaintext records and ledger lines.
    Find {
        /// Case-insensitive substring.
        query: String,
        /// Max hits to print.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Append to the ledger (one commit per write).
    Log {
        #[command(subcommand)]
        action: LogAction,
    },
    /// Bulk-append ledger lines from a file (one commit).
    Import {
        /// File of ledger lines, one per line.
        #[arg(long)]
        file: PathBuf,
    },
    /// Manage notes (one commit per write).
    Note {
        #[command(subcommand)]
        action: NoteAction,
    },
    /// Context bundle for one person (honors no-ai).
    Context {
        /// Opaque person id (p-…).
        person: String,
        /// Strip private data (name, profile, bodies).
        #[arg(long)]
        exclude_private: bool,
    },
    /// Vault health checks (the crypto check reports encryption availability).
    Doctor,
    /// Print the agent-contract JSON Schema.
    Schema,
    /// Show help (with --json, the machine-readable form).
    Help { topic: Option<String> },
    /// Thin MCP server over stdio wrapping this CLI.
    Mcp,
    /// Write a fake vault of N people for search benchmarks (hidden).
    #[command(hide = true)]
    BenchGen {
        dir: PathBuf,
        #[arg(long, default_value_t = 400)]
        people: usize,
        #[arg(long, default_value_t = 5)]
        notes: usize,
        /// Fill note bodies with no-space CJK prose (quadratic-scan guard).
        #[arg(long)]
        cjk: bool,
    },
}

#[derive(Subcommand, Debug)]
enum LogAction {
    /// Append a session ledger line, e.g. `log session p-… 60m paid`.
    Session {
        /// Opaque person id (p-…).
        person: String,
        /// Duration like 60m or 1h30m.
        duration: String,
        /// Billing tag (paid, pps, comp).
        tag: Option<String>,
        /// Session date YYYY-MM-DD (default today).
        #[arg(long)]
        date: Option<String>,
        /// Session note text (creates a note record).
        #[arg(long)]
        note: Option<String>,
        /// Source token, stored as src:<value>.
        #[arg(long)]
        src: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum NoteAction {
    /// Create a note record under people/<person>/notes/.
    Add {
        /// Opaque person id (p-…).
        #[arg(long)]
        person: String,
        /// Note date YYYY-MM-DD (default today).
        #[arg(long)]
        date: Option<String>,
        /// Mark this note no-ai.
        #[arg(long)]
        no_ai: bool,
        /// File holding the note body.
        #[arg(long)]
        body_file: PathBuf,
    },
}

fn main() -> ExitCode {
    let json_hint = std::env::args_os().any(|a| a == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            if json_hint && err.use_stderr() {
                let _ = print_error(
                    true,
                    None,
                    &DomainError::usage(err.to_string().trim().to_owned()),
                );
                return ExitCode::from(2);
            }
            err.exit();
        }
    };
    let vault_flag = cli.vault.clone();
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            let json = std::env::args_os().any(|a| a == "--json");
            let domain = DomainError::of(&error)
                .cloned()
                .unwrap_or_else(|| DomainError::internal(format!("{error:#}")));
            // Best-effort resolved vault for the envelope (ADR-11).
            let vault = discover(vault_flag.as_deref())
                .ok()
                .map(|p| p.display().to_string());
            let _ = print_error(json, vault.as_deref(), &domain);
            ExitCode::from(domain.exit_code() as u8)
        }
    }
}

macro_rules! vault_or {
    ($root:expr, $json:expr) => {
        match load_vault_or($root, $json) {
            Ok(v) => v,
            Err(code) => return Ok(code),
        }
    };
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let json = cli.json;

    // `schema` and `help` work without a vault; everything else needs one.
    // Every JSON response still carries the resolved vault (possibly null).
    let needs_vault = !matches!(cli.command, Command::Schema | Command::Help { .. });
    let vault_root: Option<PathBuf> = match discover(cli.vault.as_deref()) {
        Ok(root) => Some(root),
        Err(err) => {
            if needs_vault {
                print_error(json, None, &err)?;
                return Ok(ExitCode::from(err.exit_code() as u8));
            }
            None
        }
    };

    match &cli.command {
        Command::BenchGen {
            dir,
            people,
            notes,
            cjk,
        } => {
            let (unique, common) =
                confidant_core::bench::generate_realistic_vault(dir, *people, *notes, *cjk)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
                        "vault": dir.canonicalize().unwrap_or_else(|_| dir.clone()).display().to_string(),
                        "people": people,
                        "notes_per_person": notes,
                        "unique_token": unique,
                        "common_token": common,
                    })
                );
            } else {
                println!("wrote {people} people × {notes} notes at {}", dir.display());
                println!("unique token: {unique}");
                println!("common token: {common}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Check { fail_on, as_of } => {
            let root = vault_root.unwrap();
            let fail_on = parse_fail_on(fail_on)?;
            let as_of = match as_of.as_deref() {
                None => None,
                Some(s) => Some(parse_iso_date(s).map_err(|_| {
                    DomainError::usage(format!(
                        "--as-of '{s}' is not a zero-padded calendar date YYYY-MM-DD"
                    ))
                })?),
            };
            let vault = vault_or!(&root, json);
            let report = check_vault(
                &vault,
                &CheckOptions {
                    as_of,
                    fail_on: Some(fail_on),
                },
            );
            if json {
                serde_json::to_writer(io::stdout(), &report)?;
                println!();
            } else {
                print_check_human(&report)?;
            }
            if report.ok {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(1))
            }
        }
        Command::Find { query, limit } => {
            if query.trim().is_empty() {
                return Err(anyhow::Error::new(DomainError::usage(
                    "find requires a non-empty query",
                )));
            }
            let root = vault_root.unwrap();
            let vault = vault_or!(&root, json);
            if vault.config.spec != confidant_core::SPEC_VERSION {
                print_error(
                    json,
                    Some(&vault.root.display().to_string()),
                    &DomainError::spec_unsupported(&vault.config.spec),
                )?;
                return Ok(ExitCode::from(1));
            }
            let result = match search(&vault, query) {
                Ok(result) => result,
                Err(err) => {
                    print_error(json, Some(&vault.root.display().to_string()), &err)?;
                    return Ok(ExitCode::from(err.exit_code() as u8));
                }
            };
            let hits: Vec<_> = result.hits.into_iter().take(*limit).collect();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
                        "vault": vault.root.display().to_string(),
                        "query": query,
                        "matches": hits,
                        "findings": result.findings,
                    })
                );
            } else {
                for f in &result.findings {
                    writeln!(
                        io::stdout(),
                        "{:<7}  {}  {}",
                        f.severity.label(),
                        f.code.as_str(),
                        f.message
                    )?;
                }
                for hit in &hits {
                    let id = hit.id.as_deref().unwrap_or("-");
                    writeln!(
                        io::stdout(),
                        "{id}\t{}:{}\t{}",
                        hit.path,
                        hit.line,
                        hit.excerpt
                    )?;
                }
                writeln!(io::stdout(), "{} matches", hits.len())?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Log { action } => {
            let root = vault_root.unwrap();
            match action {
                LogAction::Session {
                    person,
                    duration,
                    tag,
                    date,
                    note,
                    src,
                } => cmd_log_session(
                    &cli,
                    &root,
                    person,
                    duration,
                    tag.clone(),
                    date.clone(),
                    note.clone(),
                    src.clone(),
                ),
            }
        }
        Command::Import { file } => {
            let root = vault_root.unwrap();
            cmd_import(&cli, &root, file)
        }
        Command::Note { action } => {
            let root = vault_root.unwrap();
            match action {
                NoteAction::Add {
                    person,
                    date,
                    no_ai,
                    body_file,
                } => cmd_note_add(&cli, &root, person, date.clone(), *no_ai, body_file),
            }
        }
        Command::Context {
            person,
            exclude_private,
        } => {
            let root = vault_root.unwrap();
            cmd_context(&cli, &root, person, !exclude_private)
        }
        Command::Doctor => {
            let root = vault_root.unwrap();
            cmd_doctor(&cli, &root)
        }
        Command::Schema => cmd_schema(&cli, vault_root.as_deref()),
        Command::Help { topic } => cmd_help(&cli, vault_root.as_deref(), topic.clone()),
        Command::Mcp => {
            let root = vault_root.unwrap();
            mcp::run(&root)
        }
    }
}

fn load_vault_or(root: &Path, json: bool) -> Result<confidant_core::Vault, ExitCode> {
    match load_vault(root) {
        Ok(v) => Ok(v),
        Err(err) => {
            let _ = print_error(json, Some(&root.display().to_string()), &err);
            Err(ExitCode::from(err.exit_code() as u8))
        }
    }
}

// ---------------------------------------------------------------------------
// Write commands
// ---------------------------------------------------------------------------

fn write_options(cli: &Cli) -> WriteOptions {
    WriteOptions {
        dry_run: cli.dry_run,
        no_input: cli.no_input,
        request_id: cli.request_id.clone(),
    }
}

/// Standard --json envelope for successful write outcomes.
fn ok_envelope(root: &Path, extra: serde_json::Value) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("ok".to_owned(), serde_json::Value::Bool(true));
    map.insert(
        "schema_version".to_owned(),
        serde_json::Value::String(confidant_core::check::JSON_SCHEMA_VERSION.to_owned()),
    );
    map.insert(
        "vault".to_owned(),
        serde_json::Value::String(root.display().to_string()),
    );
    if let serde_json::Value::Object(obj) = extra {
        map.extend(obj);
    }
    serde_json::Value::Object(map)
}

/// Print a [`WriteOutcome`] and return the exit code.
/// A check-blocked write prints the check report (exit 1): the caller sees
/// exactly why the commit did not happen.
fn finish_write(
    cli: &Cli,
    root: &Path,
    command: &str,
    outcome: WriteOutcome,
    extra: serde_json::Value,
) -> anyhow::Result<ExitCode> {
    match outcome {
        WriteOutcome::Applied { commit, files } => {
            if cli.json {
                let mut obj = serde_json::json!({
                    "command": command,
                    "commit": commit,
                    "files": files,
                });
                if let serde_json::Value::Object(e) = extra {
                    obj.as_object_mut().unwrap().extend(e);
                }
                println!("{}", ok_envelope(root, obj));
            } else {
                println!(
                    "committed {} ({} file(s))",
                    &commit[..8.min(commit.len())],
                    files.len()
                );
                for f in &files {
                    println!("  {f}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        WriteOutcome::DryRun { preview } => {
            if cli.json {
                let changes: Vec<serde_json::Value> = preview
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "path": p.path,
                            "action": p.action,
                            "content": p.content,
                        })
                    })
                    .collect();
                let mut obj = serde_json::json!({
                    "command": command,
                    "dry_run": true,
                    "commit": serde_json::Value::Null,
                    "changes": changes,
                });
                if let serde_json::Value::Object(e) = extra {
                    obj.as_object_mut().unwrap().extend(e);
                }
                println!("{}", ok_envelope(root, obj));
            } else {
                println!("dry run — no files written, no commit:");
                for p in &preview {
                    println!("--- {} ({})", p.path, p.action);
                    println!("{}", p.content);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        WriteOutcome::Idempotent { commit } => {
            if cli.json {
                println!(
                    "{}",
                    ok_envelope(
                        root,
                        serde_json::json!({
                            "command": command,
                            "idempotent": true,
                            "commit": commit,
                        })
                    )
                );
            } else {
                println!(
                    "already applied (commit {})",
                    &commit[..8.min(commit.len())]
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        WriteOutcome::CheckBlocked { report } => {
            if cli.json {
                serde_json::to_writer(io::stdout(), &report)?;
                println!();
            } else {
                writeln!(io::stderr(), "write blocked: check failed")?;
                print_check_human(&report)?;
            }
            Ok(ExitCode::from(1))
        }
    }
}

fn parse_person_arg(vault: &confidant_core::Vault, raw: &str) -> anyhow::Result<RecordId> {
    let id = RecordId::parse(raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a record id: {raw}"))).context(
            "write commands take an opaque person id; use `confidant find <name>` to look one up",
        )
    })?;
    match vault.records.get(&id) {
        Some(r) if r.kind == RecordKind::Person => Ok(id),
        _ => Err(
            anyhow::Error::new(DomainError::not_found(format!("no person with id {raw}")))
                .context("use `confidant find <name>` to look up the id"),
        ),
    }
}

fn parse_date_arg(raw: &Option<String>) -> anyhow::Result<chrono::NaiveDate> {
    match raw {
        Some(s) => parse_strict_date(s)
            .ok_or_else(|| anyhow::Error::new(DomainError::usage(format!("not YYYY-MM-DD: {s}")))),
        None => Ok(chrono::Utc::now().date_naive()),
    }
}

fn month_path(date: &chrono::NaiveDate) -> PathBuf {
    use chrono::Datelike;
    PathBuf::from(format!("ledger/{}/{:02}.cfd", date.year(), date.month()))
}

#[allow(clippy::too_many_arguments)]
fn cmd_log_session(
    cli: &Cli,
    root: &Path,
    person_raw: &str,
    duration: &str,
    tag: Option<String>,
    date_raw: Option<String>,
    note: Option<String>,
    src: Option<String>,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    let person = parse_person_arg(&vault, person_raw)?;
    if parse_duration_minutes(duration).is_none() {
        return Err(anyhow::Error::new(DomainError::usage(format!(
            "bad duration '{duration}'; use like 60m or 1h30m"
        ))));
    }
    let date = parse_date_arg(&date_raw)?;

    // An inline --note becomes its own note record, referenced from the line.
    let mut changes = Vec::new();
    let mut note_arg: Option<String> = None;
    let mut note_body: Option<String> = None;
    if let Some(text) = note {
        let nid = RecordId::new(Prefix::Note, confidant_core::write::new_ulid())
            .map_err(|e| anyhow::anyhow!("generated bad note id: {e}"))?;
        let rel = PathBuf::from(format!("people/{person}/notes/{nid}.md"));
        let rec = Record {
            id: nid.clone(),
            kind: RecordKind::Note,
            path: rel.display().to_string(),
            name: None,
            fields: BTreeMap::from([
                ("person".to_owned(), person.to_string()),
                ("date".to_owned(), date.to_string()),
            ]),
            body: text.clone(),
            source: String::new(),
            body_start_line: 0,
        };
        changes.push(FileChange::WriteFile {
            path: rel,
            contents: confidant_core::format_record(&rec),
        });
        note_arg = Some(format!("note:{nid}"));
        note_body = Some(text);
    }

    let mut parts = vec![
        date.to_string(),
        "session".to_owned(),
        person.to_string(),
        duration.to_owned(),
    ];
    if let Some(t) = &tag {
        parts.push(t.clone());
    }
    if let Some(n) = &note_arg {
        parts.push(n.clone());
    }
    if let Some(s) = &src {
        parts.push(format!("src:{s}"));
    }
    let line = parts.join(" ");
    changes.push(FileChange::AppendLines {
        path: month_path(&date),
        lines: vec![line.clone()],
    });

    let canonical = format!(
        "log-session/v1\nperson={person}\ndate={date}\nduration={duration}\ntag={}\nnote={}\nsrc={}\n",
        tag.as_deref().unwrap_or(""),
        note_body.as_deref().unwrap_or(""),
        src.as_deref().unwrap_or(""),
    );
    let summary = format!(
        "session {person} {duration}{}",
        tag.as_deref().map(|t| format!(" {t}")).unwrap_or_default()
    );
    let outcome = apply_write(
        root,
        PendingWrite {
            changes,
            summary,
            canonical_request: canonical,
        },
        &write_options(cli),
    )?;
    finish_write(
        cli,
        root,
        "log-session",
        outcome,
        serde_json::json!({"lines": [line]}),
    )
}

fn cmd_import(cli: &Cli, root: &Path, file: &Path) -> anyhow::Result<ExitCode> {
    let text = std::fs::read_to_string(file).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            file.display()
        )))
    })?;
    // Validate every line before touching the vault.
    let mut entries = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        match confidant_core::parse_line(raw) {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) => {}
            Err(msg) => {
                return Err(anyhow::Error::new(
                    DomainError::invalid(format!("{}:{}: {msg}", file.display(), idx + 1))
                        .with_file(file.display().to_string())
                        .with_line(idx as u32 + 1)
                        .with_fix("Fix the line so it matches DATE VERB ID ARGS…"),
                ));
            }
        }
    }
    if entries.is_empty() {
        return Err(anyhow::Error::new(DomainError::usage(
            "import file has no ledger lines",
        )));
    }

    let mut by_file: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    for entry in &entries {
        by_file
            .entry(month_path(&entry.date))
            .or_default()
            .push(confidant_core::format_entry(entry));
    }
    let total = entries.len();
    let lines: Vec<String> = by_file.values().flatten().cloned().collect();
    let changes: Vec<FileChange> = by_file
        .into_iter()
        .map(|(path, file_lines)| FileChange::AppendLines {
            path,
            lines: file_lines,
        })
        .collect();

    let outcome = apply_write(
        root,
        PendingWrite {
            changes,
            summary: format!("import {total} ledger lines"),
            canonical_request: format!("import/v1\n{text}"),
        },
        &write_options(cli),
    )?;
    finish_write(
        cli,
        root,
        "import",
        outcome,
        serde_json::json!({"lines": lines}),
    )
}

fn cmd_note_add(
    cli: &Cli,
    root: &Path,
    person_raw: &str,
    date_raw: Option<String>,
    no_ai: bool,
    body_file: &Path,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    let person = parse_person_arg(&vault, person_raw)?;
    let date = parse_date_arg(&date_raw)?;
    let body = std::fs::read_to_string(body_file).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            body_file.display()
        )))
    })?;

    let nid = RecordId::new(Prefix::Note, confidant_core::write::new_ulid())
        .map_err(|e| anyhow::anyhow!("generated bad note id: {e}"))?;
    let rel = PathBuf::from(format!("people/{person}/notes/{nid}.md"));
    let mut fields = BTreeMap::from([
        ("person".to_owned(), person.to_string()),
        ("date".to_owned(), date.to_string()),
    ]);
    if no_ai {
        fields.insert("no-ai".to_owned(), "true".to_owned());
    }
    let rec = Record {
        id: nid.clone(),
        kind: RecordKind::Note,
        path: rel.display().to_string(),
        name: None,
        fields,
        body: body.clone(),
        source: String::new(),
        body_start_line: 0,
    };
    let outcome = apply_write(
        root,
        PendingWrite {
            changes: vec![FileChange::WriteFile {
                path: rel.clone(),
                contents: confidant_core::format_record(&rec),
            }],
            summary: format!("note {person} {nid}"),
            canonical_request: format!(
                "note-add/v1\nperson={person}\ndate={date}\nno_ai={no_ai}\nbody={body}"
            ),
        },
        &write_options(cli),
    )?;
    finish_write(
        cli,
        root,
        "note-add",
        outcome,
        serde_json::json!({
            "id": nid.to_string(),
            "path": rel.display().to_string(),
        }),
    )
}

// ---------------------------------------------------------------------------
// context
// ---------------------------------------------------------------------------

fn cmd_context(
    cli: &Cli,
    root: &Path,
    person_raw: &str,
    include_private: bool,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    let person = RecordId::parse(person_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a record id: {person_raw}"))).context(
            "`context` takes an opaque person id; use `confidant find <name>` to look one up",
        )
    })?;
    let bundle = build_context(&vault, &person, include_private).ok_or_else(|| {
        anyhow::Error::new(DomainError::not_found(format!(
            "no person with id {person_raw}"
        )))
        .context("use `confidant find <name>` to look up the id")
    })?;
    if cli.json {
        let value = serde_json::to_value(&bundle).unwrap_or(serde_json::Value::Null);
        println!("{}", ok_envelope(root, value));
    } else {
        let p = &bundle.person;
        println!(
            "{} {}{}",
            p.id,
            p.name.as_deref().unwrap_or("(name withheld)"),
            if p.no_ai { " [no-ai]" } else { "" }
        );
        if let Some(c) = &bundle.coaching {
            println!("sessions remaining: {}", c.sessions_remaining);
            println!("icf hours: {:.2}", c.icf_hours);
        }
        println!(
            "notes: {}, interactions: {}",
            bundle.notes.len(),
            bundle.interactions.len()
        );
        if !bundle.aliases.is_empty() {
            println!("aliases: {}", bundle.aliases.join(", "));
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

struct DoctorCheck {
    id: &'static str,
    status: &'static str,
    message: String,
}

fn cmd_doctor(cli: &Cli, root: &Path) -> anyhow::Result<ExitCode> {
    let mut checks: Vec<DoctorCheck> = Vec::new();

    checks.push(DoctorCheck {
        id: "vault-discovery",
        status: "ok",
        message: format!("vault resolved to {}", root.display()),
    });

    match require_git_repo(root, cli.no_input) {
        Ok(()) => checks.push(DoctorCheck {
            id: "git-repo",
            status: "ok",
            message: "vault is a git repository".to_owned(),
        }),
        Err(_) => checks.push(DoctorCheck {
            id: "git-repo",
            status: "error",
            message: "vault is not a git repository; writes need git".to_owned(),
        }),
    }

    let identity: Vec<String> = ["user.name", "user.email"]
        .iter()
        .map(|k| {
            confidant_core::write::git(root, &["config", "--get", k], cli.no_input)
                .map(|v| v.trim().to_owned())
                .unwrap_or_default()
        })
        .collect();
    if identity.iter().all(|v| !v.is_empty()) {
        checks.push(DoctorCheck {
            id: "git-identity",
            status: "ok",
            message: format!("git identity is {} <{}>", identity[0], identity[1]),
        });
    } else {
        checks.push(DoctorCheck {
            id: "git-identity",
            status: "error",
            message: "git user.name / user.email are not configured; commits will fail".to_owned(),
        });
    }

    match load_vault(root) {
        Ok(vault) => {
            if vault.config.spec == confidant_core::SPEC_VERSION {
                checks.push(DoctorCheck {
                    id: "spec",
                    status: "ok",
                    message: "vault spec 0.1 supported".to_owned(),
                });
            } else {
                checks.push(DoctorCheck {
                    id: "spec",
                    status: "error",
                    message: format!("unsupported vault spec: {}", vault.config.spec),
                });
            }
            let report = check_vault(&vault, &CheckOptions::default());
            if report.summary.errors > 0 {
                checks.push(DoctorCheck {
                    id: "check",
                    status: "error",
                    message: format!(
                        "check reports {} error(s); writes are blocked until fixed",
                        report.summary.errors
                    ),
                });
            } else if report.summary.warnings > 0 {
                checks.push(DoctorCheck {
                    id: "check",
                    status: "warning",
                    message: format!("check reports {} warning(s)", report.summary.warnings),
                });
            } else {
                checks.push(DoctorCheck {
                    id: "check",
                    status: "ok",
                    message: "check is clean".to_owned(),
                });
            }
        }
        Err(e) => checks.push(DoctorCheck {
            id: "vault-load",
            status: "error",
            message: format!("cannot load vault: {e}"),
        }),
    }

    // PR B owns crypto (ADR-13). `is_available()` tells us whether this build
    // can encrypt at all — when it can't, say plainly that content is
    // unencrypted rather than reporting "unknown".
    if confidant_crypt::is_available() {
        checks.push(DoctorCheck {
            id: "crypto",
            status: "ok",
            message: "encryption available; key health not assessed in this milestone".to_owned(),
        });
    } else {
        checks.push(DoctorCheck {
            id: "crypto",
            status: "warning",
            message: "encryption not available in this build; vault content is stored as plaintext"
                .to_owned(),
        });
    }

    let ok = !checks.iter().any(|c| c.status == "error");
    if cli.json {
        let items: Vec<serde_json::Value> = checks
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "status": c.status,
                    "message": c.message,
                })
            })
            .collect();
        let mut extra = serde_json::Map::new();
        extra.insert("checks".to_owned(), serde_json::Value::Array(items));
        let mut envelope = ok_envelope(root, serde_json::Value::Object(extra));
        envelope["ok"] = serde_json::Value::Bool(ok);
        println!("{envelope}");
    } else {
        for c in &checks {
            println!("{:7} {}: {}", c.status, c.id, c.message);
        }
    }
    if ok {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

// ---------------------------------------------------------------------------
// schema / help
// ---------------------------------------------------------------------------

fn cmd_schema(cli: &Cli, vault: Option<&Path>) -> anyhow::Result<ExitCode> {
    let schema = contract_schema();
    if cli.json {
        let root = vault.map(|v| v.display().to_string()).unwrap_or_default();
        println!(
            "{}",
            ok_envelope(Path::new(&root), serde_json::json!({"contract": schema}))
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&schema)?);
    }
    Ok(ExitCode::SUCCESS)
}

fn help_json_value() -> serde_json::Value {
    let commands: Vec<serde_json::Value> = Cli::command()
        .get_subcommands()
        .map(|sc| {
            serde_json::json!({
                "name": sc.get_name(),
                "about": sc.get_about().map(|s| s.to_string()),
                "args": sc.get_arguments().map(|a| serde_json::json!({
                    "id": a.get_id().as_str(),
                    "help": a.get_help().map(|s| s.to_string()),
                    "required": a.is_required_set(),
                })).collect::<Vec<_>>(),
                "subcommands": sc.get_subcommands()
                    .map(|s| s.get_name().to_owned())
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({ "commands": commands })
}

fn cmd_help(cli: &Cli, vault: Option<&Path>, topic: Option<String>) -> anyhow::Result<ExitCode> {
    if cli.json {
        // Generated from the live clap definitions, so it cannot drift.
        let root = vault.map(|v| v.display().to_string()).unwrap_or_default();
        println!("{}", ok_envelope(Path::new(&root), help_json_value()));
        return Ok(ExitCode::SUCCESS);
    }
    let mut cmd = Cli::command();
    match topic {
        None => {
            cmd.print_help()?;
            println!();
        }
        Some(t) => {
            let found = cmd
                .get_subcommands()
                .find(|sc| sc.get_name() == t || sc.get_aliases().any(|a| a == t));
            match found {
                Some(sc) => {
                    let mut sc = sc.clone();
                    sc.print_help()?;
                    println!();
                }
                None => {
                    return Err(anyhow::Error::new(DomainError::usage(format!(
                        "no such command: {t}"
                    ))));
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn discover(flag: Option<&std::path::Path>) -> Result<PathBuf, DomainError> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let discovery = Discovery {
        flag: flag.map(PathBuf::from),
        env: std::env::var("CONFIDANT_VAULT").ok(),
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        user_config: load_user_config(home.as_deref()),
    };
    resolve(&discovery)
}

fn print_check_human(report: &confidant_core::CheckReport) -> io::Result<()> {
    let mut out = io::stdout();
    for f in &report.findings {
        write!(out, "{:<7}  {}", f.severity.label(), f.code.as_str())?;
        if let Some(file) = &f.file {
            write!(out, "  {file}")?;
            if let Some(line) = f.line {
                write!(out, ":{line}")?;
            }
        }
        if let Some(id) = &f.id {
            write!(out, "  {id}")?;
        }
        writeln!(out)?;
        writeln!(out, "    {}", f.message)?;
        if let Some(fix) = &f.fix {
            writeln!(out, "    fix: {fix}")?;
        }
    }
    if report.findings.is_empty() {
        writeln!(
            out,
            "ok  {} records, {} ledger entries",
            report.summary.records, report.summary.ledger_entries
        )?;
    } else {
        writeln!(
            out,
            "{} error(s), {} warning(s)",
            report.summary.errors, report.summary.warnings
        )?;
    }
    Ok(())
}

fn print_error(json: bool, vault: Option<&str>, err: &DomainError) -> io::Result<()> {
    if json {
        let body = serde_json::json!({
            "ok": false,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": vault,
            "error": err.to_json(),
        });
        writeln!(io::stdout(), "{body}")?;
    } else {
        writeln!(io::stderr(), "error: {} ({})", err.message(), err.code())?;
        if let Some(fix) = err.fix() {
            writeln!(io::stderr(), "  fix: {fix}")?;
        }
    }
    Ok(())
}
