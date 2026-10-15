//! `confidant` — local-first, git-backed, encrypted relationship memory.
//!
//! Read commands (`check`, `find`, `context`, `doctor`, `schema`, `help`)
//! never mutate the vault. Write commands (`log session`, `import`,
//! `note add`) funnel through the [`write`] pipeline: one commit per write,
//! `check` runs before every commit and a failing check blocks the write.
//! `mcp` is a thin stdio JSON-RPC wrapper around this binary — never a
//! second way in.
//!
//! [`write`]: confidant_core::write

mod embedded;
mod mcp;
mod record_crypto;
mod record_decrypt;
mod setup;

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use confidant_core::check::parse_fail_on;
use confidant_core::config::parse_iso_date;
use confidant_core::config::UserConfig;
use confidant_core::context::build_context;
use confidant_core::discover::{load_user_config, resolve, Discovery};
use confidant_core::error::DomainError;
use confidant_core::id::{Prefix, RecordId};
use confidant_core::ledger::{parse_duration_minutes, parse_strict_date, Arg, LedgerEntry};
use confidant_core::packs::{resolve_enabled, ALL_PACKS};
use confidant_core::record::{main_record_path, Record, RecordKind};
use confidant_core::schema::contract_schema;
use confidant_core::scope::{owner_labels, parse_pack_list, resolve_scope, PackScope};
use confidant_core::write::{
    apply_write, apply_write_with_encryptor, require_git_repo, FileChange, PendingWrite,
    WriteOptions, WriteOutcome,
};
use confidant_core::{check_vault, load_vault, search, CheckOptions};
use confidant_core::{ContentHook, ContentOutcome};
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "confidant",
    version,
    disable_help_subcommand = true,
    about = "Relationship memory you own: plain-text records in a git repo.",
    after_help = "Examples:\n  \
        confidant check --vault ./examples/demo-vault\n  \
        confidant log session p-01H… 60m paid --json --no-input\n  \
        confidant context p-01H… --json\n  \
        CONFIDANT_VAULT=./examples/demo-vault confidant find goals --json"
)]
struct Cli {
    /// Vault directory.
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    /// Machine-readable JSON on stdout. Every object includes `vault`.
    #[arg(long, global = true)]
    json: bool,

    /// Never prompt; fail instead.
    #[arg(long, global = true)]
    no_input: bool,

    /// Show the logical change; write nothing, commit nothing (writes only).
    #[arg(long, global = true)]
    dry_run: bool,

    /// Idempotency key for this write.
    ///
    /// Must be unguessable and at least 22 characters — use a ULID or
    /// UUIDv4. Generate once and reuse it on retry.
    #[arg(long, global = true)]
    request_id: Option<String>,

    /// Pack scope for agent-facing reads (`find`, `context`, `allowlist`,
    /// `mcp`). Comma-separated pack names, e.g. `coaching@0.1`. Unset =
    /// all enabled packs. Naming an unknown or disabled pack is a hard
    /// error. Ignored by `check` / `doctor` (always unscoped) and
    /// by writes.
    #[arg(long, global = true)]
    packs: Option<String>,

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
    /// Print the cleared set (cleared record files and ledger lines)
    /// for index-time corpus exclusion.
    ///
    /// Read-only: emits opaque paths and line numbers only, never content.
    /// The query-time allowlist stays the authority; this only narrows what
    /// an indexer copies into its local corpus.
    Allowlist,
    /// Rebuild the local search corpus under `<vault>/.confidant/qmd-corpus/`.
    ///
    /// Cleared records are decrypted through the read path, so `no-ai`
    /// records stay out by construction. Refuses (writes nothing) when an
    /// encrypted record cannot be decrypted, or when the corpus path is not
    /// git-ignored — a corpus that silently omits records is worse than none.
    Reindex,
    /// Merge the encrypted `inbox` git branch into the current branch.
    ///
    /// Outside tools push age-encrypted items to the `inbox` branch; this
    /// decrypts them, runs `check` on the merged vault, commits the merge,
    /// and clears the inbox. Requires a clean tree; every commit that adds
    /// or changes an item must be signed by a `[trust]` signer, and the run
    /// refuses without signers unless `--allow-unsigned` is passed.
    /// No webhooks, no CI keys.
    Inbox {
        /// Decrypt and plan, but commit nothing and clear nothing.
        #[arg(long)]
        dry_run: bool,
        /// Proceed without verifying inbox branch signatures. Only for
        /// setups that have not configured `[trust] signers` yet.
        #[arg(long)]
        allow_unsigned: bool,
        /// Defer items by stem (repeatable): merge everything except these.
        /// Skipped items stay on the `inbox` branch for the next run.
        /// Refused during `inbox rotate`.
        #[arg(long)]
        skip: Vec<String>,
        /// Rotate the inbox encryption key (drain-then-destroy).
        #[command(subcommand)]
        action: Option<InboxAction>,
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
    /// Create person/org/deal/interaction records from a file (one commit).
    Record {
        #[command(subcommand)]
        action: RecordAction,
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
    Doctor {
        /// Clear the pending inbox-rotation reminder (written by `keys shred`
        /// on a non-inbox device). Requires confirmation unless --no-input.
        #[arg(long)]
        clear_pending_inbox_rotation: bool,
    },
    /// Initialize the vault's trust anchor and keys (first device).
    ///
    /// Generates the operator key, a 24-word recovery phrase (shown once on
    /// stderr), and this device's key; writes the trust anchor to
    /// ~/.config/confidant/trust.toml; creates the vault lookup key and the
    /// vault:shared client. Requires a git repo with a clean tree.
    Init {
        /// Proceed even if a trust anchor already exists (re-initialization).
        #[arg(long)]
        force: bool,
    },
    /// Recover the vault on a new device from the recovery phrase.
    ///
    /// The phrase arrives via stdin or --phrase-file only (never as an
    /// argument). Requires a fresh device (no device key enrolled yet).
    Recover {
        /// File containing the 24-word recovery phrase (alternative to stdin).
        #[arg(long)]
        phrase_file: Option<PathBuf>,
        /// Explicit trust-anchor file to load (outside the vault) instead of
        /// `~/.config/confidant/trust.toml` or the `keys/`-tree rebuild. The
        /// phrase must still match the anchor's recovery key. Validated
        /// before anything is written to the config dir.
        #[arg(long, value_name = "FILE")]
        anchor_file: Option<PathBuf>,
    },
    /// Manage per-client encryption keys (init-client, rotate, revoke, shred).
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Print the agent-contract JSON Schema.
    Schema,
    /// Show help (with --json, the machine-readable form).
    Help { topic: Option<String> },
    /// Thin MCP server over stdio wrapping this CLI.
    Mcp,
    /// Install embedded skills into agent skill dirs (no vault needed).
    ///
    /// Materializes the skills shipped in this binary to a versioned share
    /// dir and symlinks (or copies) each skill into the target agents.
    Setup {
        /// Target agents: auto (default), all, or comma-separated names.
        #[arg(long, default_value = "auto")]
        agent: String,
        /// Replace existing non-symlink skill dirs (older installs).
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Copy skills instead of symlinking.
        #[arg(long, default_value_t = false)]
        copy: bool,
        /// Show every path as it is created/linked.
        #[arg(long, short = 'v', default_value_t = false)]
        verbose: bool,
    },
    /// Update the binary (when an updater is available) and re-link skills.
    Update {
        /// Target agents: auto (default), all, or comma-separated names.
        #[arg(long, default_value = "auto")]
        agent: String,
        /// Replace existing non-symlink skill dirs.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Show every path as it is created/linked.
        #[arg(long, short = 'v', default_value_t = false)]
        verbose: bool,
    },
    /// List supported agents and detection status (no vault needed).
    Agents {
        /// Show every path as it is created/linked.
        #[arg(long, short = 'v', default_value_t = false)]
        verbose: bool,
    },
    /// Print the installed skills location (no vault needed).
    Which {
        /// Print only the skills dir path (for `$(…)` use).
        #[arg(long, default_value_t = false)]
        skills_dir: bool,
    },
    /// Print the optional routing snippet for project instruction files.
    Routing,
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
        /// Enable personal@0.1 and write a touch-heavy ledger (#188).
        #[arg(long)]
        touch: bool,
        /// Encrypt every record so find/check measure the decrypt path (#188).
        #[arg(long)]
        encrypted: bool,
    },
}

#[derive(Subcommand, Debug)]
enum KeysAction {
    /// Initialize a client's key tree (first epoch, current recipients).
    InitClient {
        /// Client id (e.g. a person id, or `vault:shared`).
        client_id: String,
    },
    /// Rotate a client's data key (new epoch, re-wrap to current recipients).
    Rotate {
        /// Client id.
        client_id: String,
    },
    /// Revoke recipients from a client (removes wrappings across all epochs).
    Revoke {
        /// Client id.
        client_id: String,
        /// Recipient key ids to revoke.
        key_ids: Vec<String>,
    },
    /// Crypto-shred a client: destroy its key tree, re-wrap all remaining
    /// clients to fresh recipients, rotate recovery. The anchor is re-pinned
    /// before any other key operation.
    Shred {
        /// Client id to shred.
        client_id: String,
    },
    /// Add a new device: two-step ceremony.
    ///
    /// On the new device, `keys device-add --initiate` generates the keypair
    /// locally and emits a request carrying only the public key + a label —
    /// the private key never leaves the device. On an already-enrolled
    /// device, `keys device-add --from-request <file>` verifies the
    /// fingerprint out of band, re-wraps every client's every retained
    /// epoch plus the vault lookup key to the new device, and commits.
    DeviceAdd {
        /// Generate a device-add request on this (new) device. The request
        /// carries only the public key + label. Needs no vault.
        #[arg(long)]
        initiate: bool,
        /// Add the device described by the request file (on an enrolled
        /// device). The request's fingerprint must be verified out of band:
        /// interactive confirmation, or --fingerprint-verified with
        /// --no-input.
        #[arg(long, value_name = "FILE")]
        from_request: Option<PathBuf>,
        /// Human label for the new device (with --initiate).
        #[arg(long)]
        label: Option<String>,
        /// Write the request to FILE instead of stdout (with --initiate).
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Confirm the request fingerprint was verified out of band.
        /// Required with --no-input (with --from-request).
        #[arg(long)]
        fingerprint_verified: bool,
        /// Overwrite an already-enrolled device key (with --initiate).
        /// Without this, --initiate refuses if a device key exists.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand, Debug)]
enum InboxAction {
    /// Rotate the inbox encryption key (drain-then-destroy).
    ///
    /// Drains the inbox with a normal run, generates a new X25519 keypair
    /// in the OS keychain, and updates `confidant.toml [inbox].pubkey` and
    /// the user-config pin. Re-pin every outside tool to the new key, then
    /// run `inbox rotate --finish` to destroy the old private key.
    ///
    /// When the old key is unavailable (lost, compromised, or revoked
    /// inbox device), the drain is skipped and there is no `--finish` to
    /// run: old-key items fail closed with `E_INBOX_CRYPTO` and the tools
    /// drop them again from source.
    Rotate {
        /// Finish a pending rotation: drain anything still encrypted to
        /// the old key, then destroy the old private key from the keychain.
        /// After this, items sent to the old key fail with `E_INBOX_CRYPTO`.
        #[arg(long)]
        finish: bool,
        /// Proceed without verifying inbox branch signatures during the drain.
        #[arg(long)]
        allow_unsigned: bool,
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
        /// On keychain failure with --note, encrypt the note to the
        /// pinned inbox pubkey and queue it to the `inbox` branch
        /// instead of failing closed. Without the flag the
        /// command prompts, unless --no-input/--json (then it fails
        /// closed).
        #[arg(long)]
        fallback_inbox: bool,
    },
    /// Append a personal touchpoint ledger line, e.g. `log touch p-… coffee`.
    Touch {
        /// Opaque person id (p-…).
        person: String,
        /// Touchpoint kind: call, text, coffee, gift, or meet.
        kind: String,
        /// Touchpoint date YYYY-MM-DD (default today).
        #[arg(long)]
        date: Option<String>,
        /// Touchpoint note text (creates a note record).
        #[arg(long)]
        note: Option<String>,
        /// Source token, stored as src:<value>.
        #[arg(long)]
        src: Option<String>,
        /// On keychain failure with --note, encrypt the note to the
        /// pinned inbox pubkey and queue it to the `inbox` branch
        /// instead of failing closed.
        #[arg(long)]
        fallback_inbox: bool,
    },
}

#[derive(Subcommand, Debug)]
enum RecordAction {
    /// Add a record from a markdown file (front matter must include id and type).
    Add {
        #[arg(long)]
        file: PathBuf,
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
                .map(|(p, _)| p.display().to_string());
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
    // `device-add --initiate` runs on a brand-new device that has no vault
    // yet; everything else needs one.
    // `setup` / `update` / `agents` / `which` / `routing` manage the
    // installed skills and never touch a vault.
    let needs_vault = !matches!(
        cli.command,
        Command::Schema
            | Command::Help { .. }
            | Command::Setup { .. }
            | Command::Update { .. }
            | Command::Agents { .. }
            | Command::Which { .. }
            | Command::Routing
            | Command::BenchGen { .. }
            | Command::Keys {
                action: KeysAction::DeviceAdd { initiate: true, .. },
            }
    );
    let vault_root: Option<PathBuf>;
    let user_config: Option<UserConfig>;
    match discover(cli.vault.as_deref()) {
        Ok((root, user)) => {
            vault_root = Some(root);
            user_config = user;
        }
        Err(err) => {
            if needs_vault {
                print_error(json, None, &err)?;
                return Ok(ExitCode::from(err.exit_code() as u8));
            }
            vault_root = None;
            user_config = None;
        }
    };

    match &cli.command {
        Command::BenchGen {
            dir,
            people,
            notes,
            cjk,
            touch,
            encrypted,
        } => {
            let (unique, common) = confidant_core::bench::generate_realistic_vault(
                dir, *people, *notes, *cjk, *touch,
            )?;
            if *encrypted {
                encrypt_bench_vault(dir)?;
            }
            if json {
                print_json(&ok_envelope(
                    Some(dir),
                    serde_json::json!({
                        "people": people,
                        "notes_per_person": notes,
                        "unique_token": unique,
                        "common_token": common,
                    }),
                ))?;
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
            let pinned_inbox_pubkey = user_config.as_ref().and_then(|u| u.inbox.pubkey.clone());
            let report = check_vault(
                &vault,
                &CheckOptions {
                    as_of,
                    fail_on: Some(fail_on),
                    pinned_inbox_pubkey,
                },
            );
            if json {
                print_json(&report)?;
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
            let root = vault_root.unwrap();
            cmd_find(json, &root, query, *limit, cli.packs.as_deref())
        }
        Command::Allowlist => {
            let root = vault_root.unwrap();
            // Spec 4: the allowlist is a read path — decrypted records
            // participate, skipped ones are excluded by omission.
            let vault = match load_vault_for_reads(&root, json) {
                Ok(v) => v,
                Err(code) => return Ok(code),
            };
            if vault.config.spec != confidant_core::SPEC_VERSION {
                print_error(
                    json,
                    Some(&vault.root.display().to_string()),
                    &DomainError::spec_unsupported(&vault.config.spec),
                )?;
                return Ok(ExitCode::from(1));
            }
            if vault.ledger_unread_count > 0 {
                let err = DomainError::ledger_unreadable(vault.ledger_unread_count);
                print_error(json, Some(&vault.root.display().to_string()), &err)?;
                return Ok(ExitCode::from(err.exit_code() as u8));
            }
            let (scope, _scope_names) = match resolve_cli_scope(&vault, cli.packs.as_deref()) {
                Ok(pair) => pair,
                Err(err) => {
                    print_error(json, Some(&vault.root.display().to_string()), &err)?;
                    return Ok(ExitCode::from(err.exit_code() as u8));
                }
            };
            // #178: scope the cleared set, and annotate each entry with its
            // owning packs (for index-time consumers — the QMD index
            // carries ownership via this output; query-time filtering
            // stays in `find`). `owning_packs` is [] for unattributed
            // items, ["core"] for core-owned items.
            let mut owning_packs: serde_json::Map<String, Value> = serde_json::Map::new();
            let mut files: Vec<String> = Vec::new();
            for (path, owners) in confidant_core::cleared_record_owners(&vault) {
                if !scope.allows(&owners) {
                    continue;
                }
                owning_packs.insert(
                    path.clone(),
                    Value::Array(
                        owner_labels(&owners)
                            .into_iter()
                            .map(|s| Value::String(s.to_owned()))
                            .collect(),
                    ),
                );
                files.push(path);
            }
            let mut ledger: Vec<serde_json::Value> = Vec::new();
            for (file, line, owners) in confidant_core::cleared_ledger_line_owners(&vault) {
                if !scope.allows(&owners) {
                    continue;
                }
                ledger.push(serde_json::json!({
                    "file": file,
                    "line": line,
                    "owning_packs": owner_labels(&owners),
                }));
            }
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
                        "vault": vault.root.display().to_string(),
                        "cleared_files": files,
                        "cleared_ledger_lines": ledger,
                        "owning_packs": owning_packs,
                        "scope": _scope_names,
                    })
                );
            } else {
                for f in &files {
                    writeln!(io::stdout(), "{f}")?;
                }
                for entry in &ledger {
                    writeln!(
                        io::stdout(),
                        "{}:{}",
                        entry["file"].as_str().unwrap_or(""),
                        entry["line"].as_u64().unwrap_or(0)
                    )?;
                }
                writeln!(
                    io::stdout(),
                    "{} file(s), {} ledger line(s) cleared",
                    files.len(),
                    ledger.len()
                )?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Reindex => {
            let root = vault_root.unwrap();
            cmd_reindex(json, &root)
        }
        Command::Inbox {
            dry_run,
            allow_unsigned,
            skip,
            action,
        } => {
            let root = vault_root.unwrap();
            match action {
                Some(InboxAction::Rotate {
                    finish,
                    allow_unsigned: rotate_unsigned,
                }) => {
                    // #318: `--skip` is refused during a rotate drain —
                    // leftovers encrypted to the old key must not survive
                    // `--finish` (§8a.3).
                    if !skip.is_empty() {
                        return Err(anyhow::Error::new(DomainError::usage(
                            "--skip is refused during `inbox rotate`: finish or drop old-key items before rotating",
                        )));
                    }
                    cmd_inbox_rotate(&root, user_config.as_ref(), json, *finish, *rotate_unsigned)
                }
                None => cmd_inbox(
                    json,
                    &root,
                    user_config.as_ref(),
                    *dry_run,
                    *allow_unsigned,
                    skip,
                ),
            }
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
                    fallback_inbox,
                } => cmd_log_session(
                    &cli,
                    &root,
                    user_config.as_ref(),
                    person,
                    duration,
                    tag.clone(),
                    date.clone(),
                    note.clone(),
                    src.clone(),
                    *fallback_inbox,
                ),
                LogAction::Touch {
                    person,
                    kind,
                    date,
                    note,
                    src,
                    fallback_inbox,
                } => cmd_log_touch(
                    &cli,
                    &root,
                    user_config.as_ref(),
                    person,
                    kind,
                    date.clone(),
                    note.clone(),
                    src.clone(),
                    *fallback_inbox,
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
        Command::Record { action } => {
            let root = vault_root.unwrap();
            match action {
                RecordAction::Add { file } => cmd_record_add(&cli, &root, file),
            }
        }
        Command::Context {
            person,
            exclude_private,
        } => {
            let root = vault_root.unwrap();
            cmd_context(&cli, &root, person, !exclude_private)
        }
        Command::Doctor {
            clear_pending_inbox_rotation,
        } => {
            let root = vault_root.unwrap();
            cmd_doctor(
                &cli,
                &root,
                user_config.as_ref(),
                *clear_pending_inbox_rotation,
            )
        }
        Command::Init { force } => {
            let root = vault_root.unwrap();
            cmd_init(&cli, &root, *force)
        }
        Command::Recover {
            phrase_file,
            anchor_file,
        } => {
            let root = vault_root.unwrap();
            cmd_recover(&cli, &root, phrase_file.as_deref(), anchor_file.as_deref())
        }
        Command::Keys { action } => {
            match action {
                // --initiate runs on a new device with no vault; every other
                // keys action needs the vault.
                KeysAction::DeviceAdd {
                    initiate,
                    from_request,
                    label,
                    output,
                    fingerprint_verified,
                    force,
                } => {
                    // B6: flag combinations are usage errors (exit 2).
                    if *initiate && from_request.is_some() {
                        return Err(anyhow::Error::new(DomainError::usage(
                            "--initiate and --from-request are mutually exclusive",
                        )));
                    }
                    if !initiate && (label.is_some() || output.is_some()) {
                        return Err(anyhow::Error::new(DomainError::usage(
                            "--label and --output only make sense with --initiate",
                        )));
                    }
                    if *initiate {
                        cmd_keys_device_add_initiate(
                            &cli,
                            label.as_deref(),
                            output.as_deref(),
                            *force,
                        )
                    } else {
                        let root = vault_root.unwrap();
                        cmd_keys_device_add_from_request(
                            &cli,
                            &root,
                            from_request.as_deref(),
                            *fingerprint_verified,
                        )
                    }
                }
                _ => {
                    let root = vault_root.unwrap();
                    match action {
                        KeysAction::InitClient { client_id } => {
                            cmd_keys_init_client(&cli, &root, client_id)
                        }
                        KeysAction::Rotate { client_id } => cmd_keys_rotate(&cli, &root, client_id),
                        KeysAction::Revoke { client_id, key_ids } => {
                            cmd_keys_revoke(&cli, &root, client_id, key_ids)
                        }
                        KeysAction::Shred { client_id } => cmd_keys_shred(&cli, &root, client_id),
                        KeysAction::DeviceAdd { .. } => {
                            unreachable!("handled by the outer match arm")
                        }
                    }
                }
            }
        }
        Command::Schema => cmd_schema(&cli, vault_root.as_deref()),
        Command::Help { topic } => cmd_help(&cli, vault_root.as_deref(), topic.clone()),
        Command::Setup {
            agent,
            force,
            copy,
            verbose,
        } => cmd_setup(&cli, agent, *force, *copy, *verbose),
        Command::Update {
            agent,
            force,
            verbose,
        } => cmd_update(&cli, agent, *force, *verbose),
        Command::Agents { verbose } => cmd_agents(&cli, *verbose),
        Command::Which { skills_dir } => cmd_which(&cli, *skills_dir),
        Command::Routing => cmd_routing(&cli),
        Command::Mcp => {
            let root = vault_root.unwrap();
            mcp::run(&root, cli.packs.clone())
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

/// Resolve `--packs` against the vault's enabled packs (#178). Returns
/// the scope plus the pack names that actually apply (for JSON output).
/// Naming an unknown or disabled pack is a usage error (exit 2).
fn resolve_cli_scope(
    vault: &confidant_core::Vault,
    raw: Option<&str>,
) -> Result<(PackScope, Vec<String>), DomainError> {
    let requested = raw.map(parse_pack_list);
    let (enabled, _) = resolve_enabled(&vault.config.packs, ALL_PACKS);
    let scope = resolve_scope(requested.as_deref(), &enabled)?;
    let names = scope.names(&enabled);
    Ok((scope, names))
}

/// Load the vault for a read command (`find`/`context`, spec 4). Two-phase:
/// phase 1 loads without the hook to get the vault id for AAD; phase 2
/// reloads with the decryptor hook so envelopes decrypt (or skip + count).
/// Reads never fail for a missing key — that is a per-record skip (⚠2).
fn load_vault_for_reads(root: &Path, json: bool) -> Result<confidant_core::Vault, ExitCode> {
    let probe = match load_vault(root) {
        Ok(v) => v,
        Err(err) => {
            let _ = print_error(json, Some(&root.display().to_string()), &err);
            return Err(ExitCode::from(err.exit_code() as u8));
        }
    };
    let decryptor = std::sync::Arc::new(record_decrypt::RecordDecryptor::for_reads(
        root,
        &probe.config.vault_id,
    ));
    match confidant_core::load_vault_with_hook(root, Some(decryptor.hook())) {
        Ok(v) => Ok(v),
        Err(err) => {
            let _ = print_error(json, Some(&root.display().to_string()), &err);
            Err(ExitCode::from(err.exit_code() as u8))
        }
    }
}

fn is_broken_pipe(err: &serde_json::Error) -> bool {
    err.io_error_kind() == Some(io::ErrorKind::BrokenPipe)
}

fn print_json<T: serde::Serialize>(value: &T) -> io::Result<()> {
    let mut out = io::stdout().lock();
    if let Err(err) = serde_json::to_writer(&mut out, value) {
        if is_broken_pipe(&err) {
            return Ok(());
        }
        return Err(err.into());
    }
    match writeln!(out) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(err),
    }
}

fn vault_json(root: Option<&Path>) -> Value {
    match root {
        Some(p) => Value::String(p.display().to_string()),
        None => Value::Null,
    }
}

/// Standard `--json` envelope for successful command output.
fn ok_envelope(root: Option<&Path>, extra: Value) -> Value {
    let mut map = serde_json::Map::new();
    if let Value::Object(obj) = extra {
        map.extend(obj);
    }
    map.insert("ok".to_owned(), Value::Bool(true));
    map.insert(
        "schema_version".to_owned(),
        Value::String(confidant_core::check::JSON_SCHEMA_VERSION.to_owned()),
    );
    map.insert("vault".to_owned(), vault_json(root));
    Value::Object(map)
}

fn fail_command(json: bool, vault: Option<&str>, err: &anyhow::Error) -> anyhow::Result<ExitCode> {
    let domain = DomainError::of(err)
        .cloned()
        .unwrap_or_else(|| DomainError::internal(format!("{err:#}")));
    print_error(json, vault, &domain)?;
    Ok(ExitCode::from(domain.exit_code() as u8))
}

fn cmd_find(
    json: bool,
    root: &Path,
    query: &str,
    limit: usize,
    packs: Option<&str>,
) -> anyhow::Result<ExitCode> {
    if query.trim().is_empty() {
        return Err(anyhow::Error::new(DomainError::usage(
            "find requires a non-empty query",
        )));
    }
    let vault = match load_vault_for_reads(root, json) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let vault_path = vault.root.display().to_string();
    if vault.config.spec != confidant_core::SPEC_VERSION {
        print_error(
            json,
            Some(&vault_path),
            &DomainError::spec_unsupported(&vault.config.spec),
        )?;
        return Ok(ExitCode::from(1));
    }
    let (scope, scope_names) = match resolve_cli_scope(&vault, packs) {
        Ok(pair) => pair,
        Err(err) => {
            print_error(json, Some(&vault_path), &err)?;
            return Ok(ExitCode::from(err.exit_code() as u8));
        }
    };
    let result = match search(&vault, query, &scope) {
        Ok(result) => result,
        Err(err) => {
            print_error(json, Some(&vault_path), &err)?;
            return Ok(ExitCode::from(err.exit_code() as u8));
        }
    };
    let hits: Vec<_> = result.hits.into_iter().take(limit).collect();
    if json {
        print_json(&ok_envelope(
            Some(&vault.root),
            serde_json::json!({
                "query": query,
                "matches": hits,
                "findings": result.findings,
                "skipped_encrypted": result.skipped_encrypted,
                "refused_envelopes": result.refused_envelopes,
                "scope": scope_names,
            }),
        ))?;
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
        // ⚠2a: never silently empty — the skip/refuse counts are always
        // visible when nonzero.
        if result.skipped_encrypted > 0 {
            writeln!(
                io::stdout(),
                "skipped_encrypted: {}",
                result.skipped_encrypted
            )?;
        }
        if result.refused_envelopes > 0 {
            writeln!(
                io::stdout(),
                "refused_envelopes: {}",
                result.refused_envelopes
            )?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `<vault>/.confidant/qmd-corpus/` — the QMD search corpus (ADR-6).
const QMD_CORPUS_REL: &str = ".confidant/qmd-corpus";
/// Sibling temp dir the corpus is built into before an atomic rename into
/// [`QMD_CORPUS_REL`], so a failed build never leaves a partial corpus.
const QMD_CORPUS_TMP_REL: &str = ".confidant/qmd-corpus.tmp";
/// `<vault>/.confidant/qmd/` — the skill's QMD store (index.sqlite holds the
/// plaintext FTS chunks + embeddings). The CLI does not build it, but `keys
/// shred` deletes it alongside the corpus so shredded plaintext cannot linger.
const QMD_STORE_REL: &str = ".confidant/qmd";

/// `confidant reindex` (ADR-6): rebuild the local search corpus from the
/// §12 cleared set, decrypting through the read path.
///
/// The corpus is a plaintext mirror of cleared vault content, so this fails
/// closed twice: an encrypted record this device cannot decrypt aborts the
/// whole build (a corpus that silently omits records is worse than none),
/// and the corpus must be git-ignored in the vault's repo.
fn cmd_reindex(json: bool, root: &Path) -> anyhow::Result<ExitCode> {
    let vault = match load_vault_for_reads(root, json) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let vault_path = vault.root.display().to_string();
    if vault.config.spec != confidant_core::SPEC_VERSION {
        print_error(
            json,
            Some(&vault_path),
            &DomainError::spec_unsupported(&vault.config.spec),
        )?;
        return Ok(ExitCode::from(1));
    }
    if vault.ledger_unread_count > 0 {
        let err = DomainError::ledger_unreadable(vault.ledger_unread_count);
        print_error(json, Some(&vault_path), &err)?;
        return Ok(ExitCode::from(err.exit_code() as u8));
    }

    // B1/B4: refuse rather than build a corpus that silently omits encrypted
    // records. `find` skips and counts; a corpus cannot afford to.
    let skipped = vault.skipped_encrypted;
    let refused = vault.refused_envelopes;
    if skipped > 0 || refused > 0 {
        let err = DomainError::reindex_unreadable(skipped, refused);
        return refuse_reindex(json, &vault_path, &err, skipped, refused);
    }
    if let Err(err) = ensure_corpus_gitignored(&vault.root) {
        return refuse_reindex(json, &vault_path, &err, 0, 0);
    }

    let stats = match build_reindex_corpus(&vault) {
        Ok(stats) => stats,
        Err(err) => return fail_command(json, Some(&vault_path), &err),
    };
    let corpus = vault.root.join(QMD_CORPUS_REL);
    if json {
        print_json(&ok_envelope(
            Some(&vault.root),
            serde_json::json!({
                "corpus": corpus.display().to_string(),
                "files_copied": stats.files_copied,
                "records_copied": stats.records_copied,
                "records_decrypted": stats.records_decrypted,
                "ledger_lines_kept": stats.ledger_lines_kept,
                // Reuse find's count vocabulary so an agent can tell "0
                // decrypted because refused" from "0 decrypted because
                // empty" (ADR-7). Both are always zero on success.
                "skipped_encrypted": 0,
                "refused_envelopes": 0,
            }),
        ))?;
    } else {
        println!(
            "corpus: {} ({} file(s))",
            corpus.display(),
            stats.files_copied
        );
        println!(
            "records: {} copied, {} decrypted",
            stats.records_copied, stats.records_decrypted
        );
        println!("ledger lines kept: {}", stats.ledger_lines_kept);
    }
    Ok(ExitCode::SUCCESS)
}

/// Print a reindex refusal. JSON keeps the ADR-7 error envelope and adds the
/// skip/refuse counts so a caller never has to parse the message.
fn refuse_reindex(
    json: bool,
    vault: &str,
    err: &DomainError,
    skipped: u32,
    refused: u32,
) -> anyhow::Result<ExitCode> {
    if json {
        print_json(&serde_json::json!({
            "ok": false,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": vault,
            "error": err.to_json(),
            "skipped_encrypted": skipped,
            "refused_envelopes": refused,
        }))?;
    } else {
        writeln!(io::stderr(), "error: {} ({})", err.message(), err.code())?;
        if let Some(fix) = err.fix() {
            writeln!(io::stderr(), "  fix: {fix}")?;
        }
    }
    Ok(ExitCode::from(err.exit_code() as u8))
}

/// Port of the skill's gitignore guardrail (`qmd-index.py`): refuse unless
/// `.confidant/` is git-ignored (it holds the corpus, the QMD store, and the
/// build temp dir). git absent or the vault not being a repo is a note, not
/// a refusal (there is nothing to commit with), matching the skill.
fn ensure_corpus_gitignored(root: &Path) -> Result<(), DomainError> {
    let git_dir = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--git-dir"])
        .output();
    match git_dir {
        Err(_) => {
            eprintln!(
                "warning: git not found; cannot check that `.confidant/` is \
                 git-ignored. The corpus is a plaintext mirror — add \
                 `.confidant/` to `.gitignore` before this vault is ever committed."
            );
            return Ok(());
        }
        Ok(out) if !out.status.success() => {
            eprintln!(
                "warning: this vault is not a git repo yet; the `.confidant/` \
                 gitignore check is skipped. Add `.confidant/` to `.gitignore` \
                 before initializing a repo and committing."
            );
            return Ok(());
        }
        Ok(_) => {}
    }
    // Probe `.confidant/` (which contains the corpus, the QMD store, and the
    // build temp dir) rather than each child separately. `check-ignore -q`
    // exits 0 when the path is ignored; the probe file need not exist.
    let ignored = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["check-ignore", "-q", ".confidant/.probe"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if ignored {
        Ok(())
    } else {
        Err(DomainError::reindex_not_ignored(
            &[".confidant/".to_string()],
            &root.display().to_string(),
        ))
    }
}

/// Corpus build statistics for `reindex --json`.
struct ReindexStats {
    files_copied: usize,
    records_copied: usize,
    records_decrypted: usize,
    ledger_lines_kept: usize,
}

/// Rebuild `<vault>/.confidant/qmd-corpus/` from the §12 cleared set. The
/// allowlist comes from `cleared_record_paths` / `cleared_ledger_lines`
/// (never reimplemented here), so `no-ai` records are excluded by
/// construction. Built into a temp dir and renamed into place atomically.
fn build_reindex_corpus(vault: &confidant_core::Vault) -> anyhow::Result<ReindexStats> {
    let corpus = vault.root.join(QMD_CORPUS_REL);
    // Build into a sibling temp dir on the same filesystem, then rename into
    // place: the old corpus survives until the rename succeeds, so a failed
    // build never leaves a partial corpus behind.
    let tmp = vault.root.join(QMD_CORPUS_TMP_REL);
    if tmp.exists() {
        std::fs::remove_dir_all(&tmp)?;
    }
    std::fs::create_dir_all(&tmp)?;
    // The corpus dir is 0700 from the start (not only after the build), so
    // plaintext never exists in a world-readable directory.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))?;
    }

    let cleared_records = confidant_core::cleared_record_paths(vault);
    let cleared_ledger = confidant_core::cleared_ledger_lines(vault);

    let mut stats = ReindexStats {
        files_copied: 0,
        records_copied: 0,
        records_decrypted: 0,
        ledger_lines_kept: 0,
    };

    for rec in vault.records.values() {
        if !cleared_records.contains(&rec.path) {
            continue;
        }
        let dst = tmp.join(&rec.path);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_corpus_file(&dst, rec.source.as_bytes())?;
        stats.files_copied += 1;
        stats.records_copied += 1;
        if record_file_is_envelope(&vault.root, &rec.path) {
            stats.records_decrypted += 1;
        }
    }

    for (file, lines) in &cleared_ledger {
        let text = std::fs::read_to_string(vault.root.join(file)).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read ledger file for the corpus: {e}"
            )))
        })?;
        let keep: std::collections::HashSet<u32> = lines.iter().copied().collect();
        let mut kept = String::new();
        for (idx, line) in text.split_inclusive('\n').enumerate() {
            if keep.contains(&(idx as u32 + 1)) {
                kept.push_str(line);
                stats.ledger_lines_kept += 1;
            }
        }
        let dst = tmp.join(file);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_corpus_file(&dst, kept.as_bytes())?;
        stats.files_copied += 1;
        // QMD collections match `**/*.md` only, so mirror each `.cfd` as a
        // sibling `.cfd.md` (as the skill did). The query script maps hits
        // back to the real `.cfd` path for verification.
        let mirror = tmp.join(format!("{file}.md"));
        write_corpus_file(&mirror, kept.as_bytes())?;
        stats.files_copied += 1;
    }

    harden_corpus_permissions(&tmp)?;
    if corpus.exists() {
        std::fs::remove_dir_all(&corpus)?;
    }
    std::fs::rename(&tmp, &corpus)?;
    Ok(stats)
}

/// True when the on-disk record file is a §14 envelope (i.e. its corpus
/// entry came from decrypting through the CLI).
fn record_file_is_envelope(root: &Path, rel: &str) -> bool {
    let mut head = [0u8; 4096];
    let Ok(mut file) = std::fs::File::open(root.join(rel)) else {
        return false;
    };
    use std::io::Read;
    let n = file.read(&mut head).unwrap_or(0);
    confidant_core::crypto_mode::is_envelope_bytes(&head[..n])
}

/// Write a corpus file with mode `0600` from the start, so plaintext never
/// exists with default (world-readable) permissions.
fn write_corpus_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// Corpus dirs `0700`, files `0600` (B3). Applied recursively after the
/// build as a final sweep over every nested directory created for record
/// paths (the corpus root and files are already created with their final
/// mode; this re-asserts it).
fn harden_corpus_permissions(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                harden_corpus_permissions(&entry.path())?;
            } else if file_type.is_file() {
                std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Delete this device's local search index (the QMD corpus, the QMD store,
/// and any leftover build temp dir). Called by `keys shred`: the corpus is a
/// plaintext mirror that may hold the shredded client's content, and it is
/// now stale. Best-effort — returns a warning per path that could not be
/// removed (empty when everything was absent or deleted).
fn delete_search_index(root: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    for rel in [QMD_CORPUS_REL, QMD_CORPUS_TMP_REL, QMD_STORE_REL] {
        let path = root.join(rel);
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warnings.push(format!(
                "could not delete the local search index at {rel}: {e}; \
                 delete it manually (it may hold the shredded client's plaintext)"
            )),
        }
    }
    warnings
}

fn cmd_inbox(
    json: bool,
    root: &Path,
    user_config: Option<&UserConfig>,
    dry_run: bool,
    allow_unsigned: bool,
    skip: &[String],
) -> anyhow::Result<ExitCode> {
    let vault_path = root.display().to_string();
    let trusted_signers = user_config
        .map(|u| u.trust.signers.clone())
        .unwrap_or_default();
    let pinned_pubkey = user_config.and_then(|u| u.inbox.pubkey.clone());
    let inbox_keys: Option<std::sync::Arc<confidant_core::InboxKeys>> =
        match confidant_core::InboxKeys::load_opt() {
            Ok(keys) => keys.map(std::sync::Arc::new),
            Err(err) => return fail_command(json, Some(&vault_path), &err),
        };
    let decrypt = {
        let keys = inbox_keys.clone();
        move |ciphertext: &[u8]| match &keys {
            Some(k) => k.decrypt(ciphertext),
            None => Err(anyhow::Error::new(DomainError::inbox_crypto(
                "no inbox key enrolled".to_string(),
            ))),
        }
    };
    // Lazily built on the first RecordWrite into an encrypted vault, so
    // ledger-only drains still work without the device key (#213). The
    // encryptor is cached across items in one run. The closure is `move`
    // (owns its captures) because `EncryptFn` is `dyn Fn + 'static`.
    let encryptor: std::cell::RefCell<Option<record_crypto::RecordEncryptor>> =
        std::cell::RefCell::new(None);
    let root_owned = root.to_path_buf();
    let encrypt = move |path: &std::path::Path, plaintext: &[u8]| -> anyhow::Result<Vec<u8>> {
        let mut slot = encryptor.borrow_mut();
        if slot.is_none() {
            let vault = confidant_core::load_vault(&root_owned)?;
            *slot = match record_crypto::RecordEncryptor::for_vault(&root_owned, &vault)? {
                Some(enc) => Some(enc),
                None => {
                    return Err(anyhow::Error::new(DomainError::invalid(
                        "vault declares plaintext, but the drain expected a record encryptor",
                    )));
                }
            };
        }
        slot.as_ref()
            .expect("record encryptor initialised above")
            .encrypt_file(path, plaintext)
    };
    // Same lazy construction for the retry idempotency check (#213
    // follow-up): the decryptor is only built when a record path already
    // exists on an encrypted vault, so the common path never touches the
    // device key. Decrypted bytes are compared in core, never logged
    // (AGENTS.md rule 4).
    let decryptor: std::cell::RefCell<Option<record_crypto::RecordEncryptor>> =
        std::cell::RefCell::new(None);
    let root_owned_for_decrypt = root.to_path_buf();
    let decrypt_existing = move |path: &std::path::Path,
                                 envelope: &[u8]|
          -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let mut slot = decryptor.borrow_mut();
        if slot.is_none() {
            let vault = confidant_core::load_vault(&root_owned_for_decrypt)?;
            *slot =
                match record_crypto::RecordEncryptor::for_vault(&root_owned_for_decrypt, &vault)? {
                    Some(enc) => Some(enc),
                    None => {
                        return Err(anyhow::Error::new(DomainError::invalid(
                            "vault holds an encrypted record, but no record encryptor is available",
                        )));
                    }
                };
        }
        let plaintext = slot
            .as_ref()
            .expect("record encryptor initialised above")
            .decrypt_existing(path, envelope)?;
        Ok(Zeroizing::new(plaintext))
    };
    let report = match confidant_core::run_inbox(
        root,
        &confidant_core::InboxOptions {
            dry_run,
            trusted_signers,
            allow_unsigned,
            pinned_pubkey,
            skip: skip.to_vec(),
            is_rotate_drain: false,
        },
        &decrypt,
        inbox_keys.as_deref(),
        Some(&encrypt),
        Some(&decrypt_existing),
    ) {
        Ok(report) => report,
        Err(err) => return fail_command(json, Some(&vault_path), &err),
    };
    if json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "branch": report.branch,
                "dry_run": report.dry_run,
                "empty": report.empty,
                "merged": report.merged,
                "cleared": report.cleared,
                "items": report.items.iter().map(|i| serde_json::json!({
                    "name": i.name,
                    "kind": i.kind,
                    "target": i.target,
                    "action": i.action,
                })).collect::<Vec<_>>(),
                "skipped": report.skipped.iter().map(|s| serde_json::json!({
                    "name": s.name,
                    "kind": s.kind,
                    "target": s.target,
                })).collect::<Vec<_>>(),
                "warnings": report.warnings,
            }),
        ))?;
    } else {
        if report.empty {
            println!("inbox: nothing to do (no inbox branch)");
        } else if report.dry_run {
            println!(
                "inbox: dry run — {} item(s) would merge, {} already present, {} deferred (--skip)",
                report.merged,
                report.items.len() - report.merged,
                report.skipped.len()
            );
        } else {
            println!(
                "inbox: {} item(s) merged into {}, {} cleared, {} deferred (--skip)",
                report.merged,
                report.branch,
                report.cleared,
                report.skipped.len()
            );
        }
        for i in &report.items {
            println!("  {}  {:<6}  {}  {}", i.name, i.kind, i.target, i.action);
        }
        for s in &report.skipped {
            println!("  {}  {:<6}  {}  deferred", s.name, s.kind, s.target);
        }
        for w in &report.warnings {
            println!("warning: {w}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// Write commands
// ---------------------------------------------------------------------------

fn write_options(cli: &Cli) -> WriteOptions {
    WriteOptions {
        dry_run: cli.dry_run,
        no_input: cli.no_input,
        request_id: cli.request_id.clone(),
        agent_id: std::env::var("CONFIDANT_AGENT_ID")
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty()),
    }
}

/// #180: when a pending write creates `person` records in an encrypted
/// vault, create each missing client key in the same commit.
///
/// The key is created with the exact `keys init-client` logic (union of
/// current recipients, #160 unchanged) via [`staged_keys_mutation`], then
/// `git add`ed so the record write's commit sweeps it in — `apply_write`
/// only adds its own pending files. Returns the client ids whose keys
/// were created, so the caller can roll them back on failure and report
/// them on success.
///
/// Skips are deliberate, and each preserves the pre-#180 error:
/// - dry run: no mutation at all (the preview shows plaintext, and the
///   encryptor never runs, so no key is needed);
/// - unparseable change or routing failure: the encryptor reports the
///   canonical error later;
/// - epoch file already exists: the key is there (a re-add, a repair, or
///   a complete dir left by a crashed earlier attempt — the staged swap
///   only ever moves whole trees), so nothing is created.
fn ensure_person_client_keys(
    root: &Path,
    vault: &confidant_core::vault::Vault,
    pending: &PendingWrite,
    opts: &WriteOptions,
) -> anyhow::Result<Vec<String>> {
    if opts.dry_run {
        return Ok(Vec::new());
    }
    let mut wanted: Vec<String> = Vec::new();
    for change in &pending.changes {
        let FileChange::WriteFile { path, contents } = change else {
            continue;
        };
        if !confidant_core::crypto_mode::is_record_path(path) {
            continue;
        }
        let provisional = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("record.md");
        let Ok(rec) = confidant_core::record::parse_record(contents, provisional) else {
            continue;
        };
        if rec.kind != RecordKind::Person {
            continue;
        }
        let id = rec.id.to_string();
        let Ok(client_id) = confidant_crypt::client_id_for_record("person", Some(id.as_str()))
        else {
            continue;
        };
        if !wanted.contains(&client_id) {
            wanted.push(client_id);
        }
    }
    if wanted.is_empty() {
        return Ok(Vec::new());
    }

    let config_dir = confidant_config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    // Loaded lazily: a write whose keys already exist must not fail for
    // want of an operator key (the encryptor path needs only the device
    // key).
    let mut key_material: Option<(confidant_crypt::anchor::Anchor, ed25519_dalek::SigningKey)> =
        None;
    let mut created = Vec::new();
    for client_id in wanted {
        if root.join("keys").join(&client_id).join("epoch").exists() {
            continue;
        }
        if key_material.is_none() {
            let (anchor, _warnings) =
                confidant_crypt::anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
            let operator_sk = load_operator_sk(&anchor)?;
            key_material = Some((anchor, operator_sk));
        }
        let (anchor, operator_sk) = key_material.as_ref().unwrap();
        staged_keys_mutation(root, vault, &config_dir, |store| {
            let recipients = keys_current_recipients(store, anchor)?;
            store
                .init_client(&client_id, &recipients, anchor, operator_sk)
                .map_err(anyhow::Error::new)
        })?;
        // Stage the new tree so the record write's commit (which only
        // `git add`s its pending files) sweeps it into the same commit.
        let keys_rel = format!("keys/{client_id}");
        if let Err(e) = confidant_core::write::git(root, &["add", "--", &keys_rel], opts.no_input) {
            let _ = std::fs::remove_dir_all(root.join("keys").join(&client_id));
            return Err(e);
        }
        created.push(client_id);
    }
    Ok(created)
}

/// Roll back key dirs created by [`ensure_person_client_keys`] after a
/// failed write: unstage, then remove. Best-effort — cleanup must not
/// mask the original failure. Only ever touches dirs this write created
/// (brand-new client ids), never pre-existing keys.
fn rollback_created_keys(root: &Path, created: &[String], opts: &WriteOptions) {
    for client_id in created {
        let keys_rel = format!("keys/{client_id}");
        let _ = confidant_core::write::git(root, &["reset", "--", &keys_rel], opts.no_input);
        let _ = std::fs::remove_dir_all(root.join("keys").join(client_id));
    }
}

/// Apply a record write through the encryption transform (spec 3).
///
/// Builds the [`record_crypto::RecordEncryptor`] for this vault: on an
/// encrypted vault the record `WriteFile`s become §14 envelopes; on a
/// `mode = "plaintext"` vault this is plain [`apply_write`]. Any
/// fail-closed mode error (unkeyed vault, `[crypto]` contradiction, key
/// failure) surfaces here, before anything is applied.
///
/// Returns the outcome plus the client ids whose keys were auto-created
/// for new `person` records (#180); the second element is empty unless
/// a key was created.
///
/// Ledger-only writes (no `WriteFile` changes) skip the encryptor
/// entirely: ledger lines stay plaintext by design, so no key is ever
/// needed for them. That keeps a broken keychain from blocking
/// `log session` with no `--note` (#176). Any write carrying a record
/// file goes through the encryptor as before.
fn apply_record_write(
    root: &Path,
    vault: &confidant_core::vault::Vault,
    pending: PendingWrite,
    opts: &WriteOptions,
) -> anyhow::Result<(WriteOutcome, Vec<String>)> {
    let needs_encryptor = pending
        .changes
        .iter()
        .any(|c| matches!(c, FileChange::WriteFile { .. }));
    if !needs_encryptor {
        return Ok((apply_write(root, pending, opts)?, Vec::new()));
    }
    match record_crypto::RecordEncryptor::for_vault(root, vault)? {
        Some(enc) => {
            // #180: create a missing person key in the same commit as
            // the person record. On any non-Applied outcome the created
            // key dirs are rolled back, so a failed write keeps nothing:
            // no orphan keys/<id>/, no person without a key.
            let created = ensure_person_client_keys(root, vault, &pending, opts)?;
            let result = apply_write_with_encryptor(root, pending, opts, &move |p, b| {
                enc.encrypt_file(p, b)
            });
            match result {
                Ok(outcome) if matches!(outcome, WriteOutcome::Applied { .. }) => {
                    Ok((outcome, created))
                }
                Ok(outcome) => {
                    rollback_created_keys(root, &created, opts);
                    Ok((outcome, Vec::new()))
                }
                Err(e) => {
                    rollback_created_keys(root, &created, opts);
                    Err(e)
                }
            }
        }
        None => Ok((apply_write(root, pending, opts)?, Vec::new())),
    }
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
                print_json(&ok_envelope(Some(root), obj))?;
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
                print_json(&ok_envelope(Some(root), obj))?;
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
                print_json(&ok_envelope(
                    Some(root),
                    serde_json::json!({
                        "command": command,
                        "idempotent": true,
                        "commit": commit,
                    }),
                ))?;
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
                print_json(&report)?;
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
/// `confidant inbox rotate [--finish]` (drain-then-destroy, §8a.3).
///
/// The inbox private key lives in the OS keychain (never a file); rotation
/// is a keychain operation, so the keychain's own refusals surface here
/// directly: it refuses while `CONFIDANT_INBOX_KEY` / `_PREVIOUS` are set
/// (unset them first) and while a previous key is still present (run
/// `--finish` first).
fn cmd_inbox_rotate(
    root: &Path,
    user_config: Option<&UserConfig>,
    json: bool,
    finish: bool,
    allow_unsigned: bool,
) -> anyhow::Result<ExitCode> {
    use confidant_core::inbox::{run_inbox_rotate, InboxRotateOptions};

    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        DomainError::usage("inbox rotate needs $HOME to update the user-config pin")
    })?;
    let user_config_path = home.join(".config/confidant/config.toml");
    let vault_config_path = root.join("confidant.toml");

    let backend = keychain_backend();
    let outcome = match run_inbox_rotate(
        root,
        &*backend,
        None,
        &vault_config_path,
        &user_config_path,
        &InboxRotateOptions {
            finish,
            allow_unsigned,
            trusted_signers: user_config
                .map(|u| u.trust.signers.clone())
                .unwrap_or_default(),
            pinned_pubkey: user_config.and_then(|u| u.inbox.pubkey.clone()),
        },
    ) {
        Ok(outcome) => outcome,
        Err(err) => {
            let domain = DomainError::of(&err)
                .cloned()
                .unwrap_or_else(|| DomainError::internal(format!("{err:#}")));
            print_error(json, Some(&root.display().to_string()), &domain)?;
            return Ok(ExitCode::from(domain.exit_code() as u8));
        }
    };

    if json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "finish": finish,
                "drained": outcome.drain.as_ref().map(|d| d.merged),
                "new_recipient": outcome.new_recipient,
                "old_key_destroyed": outcome.old_key_destroyed,
                "lost_key": outcome.lost_key,
            }),
        ))?;
    } else if finish {
        if outcome.old_key_destroyed {
            let merged = outcome.drain.as_ref().map(|d| d.merged).unwrap_or(0);
            println!(
                "inbox: rotation finished — {merged} leftover item(s) drained, old private key destroyed"
            );
            println!("inbox: items sent to the old key now fail with E_INBOX_CRYPTO");
        } else {
            println!("inbox: nothing to finish (no previous inbox key)");
        }
    } else if outcome.lost_key {
        println!(
            "inbox: rotated to {} (no old key found — drain skipped, no --finish needed)",
            outcome.new_recipient.as_deref().unwrap_or("?")
        );
        println!("inbox: re-pin every outside tool to the new key; old-key items fail with E_INBOX_CRYPTO");
    } else {
        println!(
            "inbox: rotated to {}",
            outcome.new_recipient.as_deref().unwrap_or("?")
        );
        println!("inbox: re-pin every outside tool to the new key, then run `confidant inbox rotate --finish`");
    }
    Ok(ExitCode::SUCCESS)
}

#[allow(clippy::too_many_arguments)]
fn cmd_log_session(
    cli: &Cli,
    root: &Path,
    user_config: Option<&UserConfig>,
    person_raw: &str,
    duration: &str,
    tag: Option<String>,
    date_raw: Option<String>,
    note: Option<String>,
    src: Option<String>,
    fallback_inbox: bool,
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
    let mut note_write: Option<(PathBuf, String)> = None;
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
            field_lines: BTreeMap::new(),
        };
        let contents = confidant_core::format_record(&rec);
        // The #213 fallback queues this same pair as an inbox record item.
        note_write = Some((rel.clone(), contents.clone()));
        changes.push(FileChange::WriteFile {
            path: rel,
            contents,
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
    // #176: a session WITH a note needs the device key (the note record
    // is encrypted). Probe the key early so a keychain failure fails
    // closed here with a note-specific fix, instead of surfacing the
    // generic encryptor error ("no device key enrolled") from
    // `apply_record_write`. The probe is read-only; the encryptor loads
    // the key again on the normal path. Gated on encrypted vaults: a
    // plaintext vault needs no key for the note either.
    //
    // #213: on probe failure the note can go to the inbox instead — the
    // drain now encrypts record items. `--fallback-inbox` queues it
    // without asking; interactively the command prompts; under
    // --no-input/--json it fails closed with a fix pointing at the flag.
    if note_body.is_some() {
        let mode = confidant_core::crypto_mode::resolve_write_mode(root, &vault.config)
            .map_err(anyhow::Error::new)?;
        if matches!(mode, confidant_core::crypto_mode::WriteMode::Encrypted)
            && device_key_bech32().is_err()
        {
            let queue = if fallback_inbox {
                true
            } else if cli.no_input || cli.json {
                false
            } else {
                prompt_fallback_inbox()?
            };
            if queue {
                let (note_rel, note_contents) =
                    note_write.expect("note write present when a note was given");
                return queue_session_note_to_inbox(
                    cli,
                    root,
                    &vault,
                    user_config,
                    &line,
                    &note_rel,
                    &note_contents,
                );
            }
            return Err(note_keychain_error());
        }
    }
    let (outcome, _) = apply_record_write(
        root,
        &vault,
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

#[allow(clippy::too_many_arguments)]
fn cmd_log_touch(
    cli: &Cli,
    root: &Path,
    user_config: Option<&UserConfig>,
    person_raw: &str,
    kind: &str,
    date_raw: Option<String>,
    note: Option<String>,
    src: Option<String>,
    fallback_inbox: bool,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    let (enabled, _) = resolve_enabled(&vault.config.packs, ALL_PACKS);
    // Find the pack that owns the `touch` verb (#185/#323) — the same routing
    // `check` uses — instead of gating on a hardcoded pack name.
    let Some(owner) = enabled.iter().find(|p| p.verbs().contains(&"touch")) else {
        return Err(anyhow::Error::new(
            DomainError::invalid("log touch requires pack personal@0.1")
                .with_fix("Add \"personal@0.1\" to packs in confidant.toml"),
        ));
    };
    let person = parse_person_arg(&vault, person_raw)?;
    // Validate the kind through the owning pack's trait. A synthetic
    // single-token entry exercises exactly the `log touch` kind grammar:
    // `validate_touch_args_enabled` on one token is `is_valid_touch_kind`.
    let probe = LedgerEntry {
        date: chrono::NaiveDate::from_ymd_opt(2000, 1, 1).expect("probe date"),
        verb: "touch".to_owned(),
        id: RecordId::new(Prefix::Person, confidant_core::write::new_ulid())
            .map_err(|e| anyhow::anyhow!("generated bad probe id: {e}"))?,
        args: vec![Arg::Token(kind.to_owned())],
        comment: None,
    };
    if !owner.validate_verb_args("touch", &probe).unwrap_or(true) {
        return Err(anyhow::Error::new(DomainError::usage(format!(
            "bad touch kind '{kind}'; use one of: call, text, coffee, gift, meet"
        ))));
    }
    let date = parse_date_arg(&date_raw)?;

    let mut changes = Vec::new();
    let mut note_arg: Option<String> = None;
    let mut note_body: Option<String> = None;
    let mut note_write: Option<(PathBuf, String)> = None;
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
            field_lines: BTreeMap::new(),
        };
        let contents = confidant_core::format_record(&rec);
        note_write = Some((rel.clone(), contents.clone()));
        changes.push(FileChange::WriteFile {
            path: rel,
            contents,
        });
        note_arg = Some(format!("note:{nid}"));
        note_body = Some(text);
    }

    let mut parts = vec![
        date.to_string(),
        "touch".to_owned(),
        person.to_string(),
        kind.to_owned(),
    ];
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
        "log-touch/v1\nperson={person}\ndate={date}\nkind={kind}\nnote={}\nsrc={}\n",
        note_body.as_deref().unwrap_or(""),
        src.as_deref().unwrap_or(""),
    );
    let summary = format!("touch {person} {kind}");
    if note_body.is_some() {
        let mode = confidant_core::crypto_mode::resolve_write_mode(root, &vault.config)
            .map_err(anyhow::Error::new)?;
        if matches!(mode, confidant_core::crypto_mode::WriteMode::Encrypted)
            && device_key_bech32().is_err()
        {
            let queue = if fallback_inbox {
                true
            } else if cli.no_input || cli.json {
                false
            } else {
                prompt_fallback_inbox()?
            };
            if queue {
                let (note_rel, note_contents) =
                    note_write.expect("note write present when a note was given");
                return queue_session_note_to_inbox(
                    cli,
                    root,
                    &vault,
                    user_config,
                    &line,
                    &note_rel,
                    &note_contents,
                );
            }
            return Err(note_keychain_error());
        }
    }
    let (outcome, _) = apply_record_write(
        root,
        &vault,
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
        "log-touch",
        outcome,
        serde_json::json!({"lines": [line]}),
    )
}

/// Interactive prompt for the #213 fallback: queue the note to the inbox
/// instead of failing closed. Only an explicit `y`/`yes` queues; anything
/// else (including EOF) fails closed.
fn prompt_fallback_inbox() -> anyhow::Result<bool> {
    use std::io::Write as _;
    eprint!(
        "The device key cannot be loaded, so the note cannot be encrypted. \
         Queue the session (ledger line + note) to the inbox instead? \
         It will merge once the keychain is back. [y/N] "
    );
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes"))
}

/// Queue a session's ledger line + note record to the `inbox` branch
/// (#213 fallback): both items are age-encrypted to the pinned inbox
/// pubkey and committed with a signed commit. Nothing is written to
/// main, so no plaintext ever lands on the main branch.
///
/// The ledger line carries `src:fallback/<ulid>` as its provenance
/// token (in addition to any operator `--src`), so the drain's
/// idempotency skips it on re-import. The note record item carries the
/// exact bytes a normal write would have produced, so the drained
/// result matches a normal write.
#[allow(clippy::too_many_arguments)]
fn queue_session_note_to_inbox(
    cli: &Cli,
    root: &Path,
    vault: &confidant_core::Vault,
    user_config: Option<&UserConfig>,
    line: &str,
    note_rel: &Path,
    note_contents: &str,
) -> anyhow::Result<ExitCode> {
    use confidant_core::QueueItem;
    // The pin is the verification: the fallback encrypts to the pinned
    // key, never to the vault-advertised copy alone. A missing pin, or a
    // mismatch, refuses (E_INBOX_UNTRUSTED) — stricter than the drain,
    // which only warns on a missing pin.
    let pinned = user_config
        .and_then(|u| u.inbox.pubkey.clone())
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    let vault_pubkey = vault
        .config
        .inbox
        .pubkey
        .clone()
        .unwrap_or_default()
        .trim()
        .to_string();
    let recipient = match pinned {
        None => {
            return Err(anyhow::Error::new(
                DomainError::inbox_untrusted(
                    "no [inbox].pubkey pinned in ~/.config/confidant/config.toml; \
                     the fallback cannot verify which key it would encrypt to",
                )
                .with_fix(
                    "Pin the vault's inbox key in ~/.config/confidant/config.toml \
                     [inbox] pubkey, then re-run with --fallback-inbox",
                ),
            ));
        }
        Some(pinned) if pinned == vault_pubkey => pinned,
        Some(_) => {
            return Err(anyhow::Error::new(
                DomainError::inbox_untrusted(
                    "vault [inbox].pubkey does not match the pinned key in user config; \
                     refusing — possible key substitution",
                )
                .with_fix(
                    "Check which key is right (the pin in ~/.config/confidant/config.toml \
                     is the operator's out-of-band copy), fix the wrong one, then re-run \
                     with --fallback-inbox",
                ),
            ));
        }
    };

    let batch = confidant_core::write::new_ulid();
    let ledger_line = format!("{line} src:fallback/{batch}");
    let items = vec![
        QueueItem {
            stem: batch.clone(),
            plaintext: format!("confidant-inbox/1\nkind: ledger\n---\n{ledger_line}\n"),
        },
        QueueItem {
            stem: format!("{batch}-note"),
            plaintext: format!(
                "confidant-inbox/1\nkind: record\npath: {}\n---\n{note_contents}",
                note_rel.display()
            ),
        },
    ];
    let stems: Vec<&str> = items.iter().map(|i| i.stem.as_str()).collect();

    if cli.dry_run {
        // The real run refuses without commit signing configured
        // (E_INBOX_UNTRUSTED from the queue gate); the dry run must
        // report the same refusal rather than a `would queue` the real
        // run could never satisfy.
        if !confidant_core::inbox::queue_signing_configured(root)? {
            return Err(anyhow::Error::new(
                DomainError::inbox_signing_unconfigured().with_fix(
                    "Configure commit signing (`git config commit.gpgsign true` and a \
                     `user.signingkey`), then re-run with --fallback-inbox",
                ),
            ));
        }
        if cli.json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "dry_run": true,
                    "queued": false,
                    "fallback_inbox": true,
                    "items": stems,
                }),
            ))?;
        } else {
            println!(
                "dry run — would queue {} item(s) to inbox: {}",
                items.len(),
                stems.join(", ")
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    let tip = match confidant_core::queue_items(root, &items, &recipient) {
        Ok(tip) => tip,
        Err(err) if DomainError::of(&err).map(|d| d.code()) == Some("E_INBOX_UNTRUSTED") => {
            // The only E_INBOX_UNTRUSTED `queue_items` produces is the
            // commit-signing gate; re-point its fix at this command.
            return Err(anyhow::Error::new(
                DomainError::inbox_signing_unconfigured().with_fix(
                    "Configure commit signing (`git config commit.gpgsign true` and a \
                     `user.signingkey`), then re-run with --fallback-inbox",
                ),
            ));
        }
        Err(err) => return Err(err),
    };
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "queued": true,
                "fallback_inbox": true,
                "items": stems,
                "tip": tip,
            }),
        ))?;
    } else {
        println!("queued to inbox; run `confidant inbox` when the keychain is back");
    }
    Ok(ExitCode::SUCCESS)
}

/// Fail-closed error for `log session --note` when the device key cannot
/// load. The generic encryptor error ("no device key enrolled") misleads
/// when the keychain is merely broken, so the note case names the real
/// situation and the way out: log the session without the note now (the
/// ledger line needs no key), then add the note once the keychain is
/// back. Nothing was written.
fn note_keychain_error() -> anyhow::Error {
    anyhow::Error::new(
        DomainError::invalid(
            "cannot load the device key, so the note cannot be encrypted; nothing was written \
             (the keychain may be unavailable, or this device may not be enrolled)",
        )
        .with_fix(
            "Re-run with --fallback-inbox to queue the note to the inbox (it drains once \
             the keychain is back), or re-run without --note to log the session now (the \
             ledger line needs no key), then add the note with `confidant note add` once \
             the keychain is back. If this device was never enrolled, run \
             `confidant init` (new vault) or `confidant recover` (new device) instead.",
        ),
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
        field_lines: BTreeMap::new(),
    };
    let (outcome, _) = apply_record_write(
        root,
        &vault,
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

fn cmd_record_add(cli: &Cli, root: &Path, file: &Path) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    let text = std::fs::read_to_string(file).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            file.display()
        )))
    })?;
    let provisional = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "record.md".to_owned());
    let rec = confidant_core::parse_record(&text, &provisional)
        .map_err(|e| anyhow::Error::new(DomainError::invalid(e.message).with_fix(e.fix)))?;
    if rec.kind == RecordKind::Note {
        return Err(anyhow::Error::new(DomainError::usage(
            "record add does not create notes; use `confidant note add --body-file`",
        )));
    }
    let rel = main_record_path(&rec)
        .map_err(|e| anyhow::Error::new(DomainError::invalid(e.message).with_fix(e.fix)))?;
    if root.join(&rel).exists() {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!("{} already exists", rel.display()))
                .with_fix("Pick a fresh id in the record file, or edit the existing record"),
        ));
    }
    let contents = confidant_core::format_record(&rec);
    let id = rec.id.to_string();
    // #179: a multi-person interaction mirrors one minimal touchpoint per
    // `with:` participant (date + own id, nothing else) so each
    // participant's cadence updates. The touchpoints land in the same
    // write (same commit) as the interaction record. The writer validates
    // shape (parse, person prefix, not the primary, no duplicates);
    // existence is `check`'s job (keyed check), like every other
    // front-matter reference.
    let mut touch_lines: Vec<String> = Vec::new();
    let mut touch_change: Option<FileChange> = None;
    if rec.kind == RecordKind::Interaction {
        if let Some(raw) = rec.field("with") {
            let with = confidant_core::record::parse_with_list(raw).ok_or_else(|| {
                anyhow::Error::new(
                    DomainError::invalid(
                        "front matter key 'with' is not a bracketed list of person IDs",
                    )
                    .with_fix("Use with: [p-<ULID>, p-<ULID>]"),
                )
            })?;
            if !with.is_empty() {
                let date_raw = rec.field("date").ok_or_else(|| {
                    anyhow::Error::new(
                        DomainError::invalid(
                            "interaction with with: needs a date (touchpoints are dated)",
                        )
                        .with_fix("Add date: YYYY-MM-DD to the interaction"),
                    )
                })?;
                let date = parse_strict_date(date_raw).ok_or_else(|| {
                    anyhow::Error::new(DomainError::invalid("interaction date is not YYYY-MM-DD"))
                })?;
                let primary = rec.person();
                let mut seen: Vec<RecordId> = Vec::new();
                for participant in &with {
                    if participant.prefix() != Prefix::Person {
                        return Err(anyhow::Error::new(
                            DomainError::invalid("with: entries must be person ids")
                                .with_fix("Use p-<ULID> ids in with:"),
                        ));
                    }
                    if Some(participant) == primary.as_ref() {
                        return Err(anyhow::Error::new(
                            DomainError::invalid("with: lists the interaction's own person")
                                .with_fix("Remove the primary person from with:"),
                        ));
                    }
                    if seen.contains(participant) {
                        return Err(anyhow::Error::new(
                            DomainError::invalid("with: lists the same participant twice")
                                .with_fix("List each participant once in with:"),
                        ));
                    }
                    seen.push(participant.clone());
                    touch_lines.push(format!("{date} touch {participant}"));
                }
                touch_change = Some(FileChange::AppendLines {
                    path: month_path(&date),
                    lines: touch_lines.clone(),
                });
            }
        }
    }
    let mut changes = vec![FileChange::WriteFile {
        path: rel.clone(),
        contents,
    }];
    if let Some(change) = touch_change {
        changes.push(change);
    }
    let (outcome, created_keys) = apply_record_write(
        root,
        &vault,
        PendingWrite {
            changes,
            summary: format!("record {id}"),
            canonical_request: format!("record-add/v1\npath={}\nbody={}", rel.display(), text),
        },
        &write_options(cli),
    )?;
    // #180: surface the auto-created key. JSON carries it (only when
    // non-empty, so existing output is unchanged otherwise); human
    // output prints the notice after the commit line.
    let mut extra = serde_json::json!({
        "id": id,
        "path": rel.display().to_string(),
    });
    if !created_keys.is_empty() {
        extra["created_keys"] = serde_json::json!(created_keys);
    }
    // #179: the mirrored touchpoints, only when any were written.
    if !touch_lines.is_empty() {
        extra["touchpoints"] = serde_json::json!(touch_lines);
    }
    let result = finish_write(cli, root, "record-add", outcome, extra);
    if !cli.json {
        for key in &created_keys {
            println!("created key for {key}");
        }
    }
    result
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
    let vault = match load_vault_for_reads(root, cli.json) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let person = RecordId::parse(person_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a record id: {person_raw}"))).context(
            "`context` takes an opaque person id; use `confidant find <name>` to look one up",
        )
    })?;
    let (scope, _scope_names) = match resolve_cli_scope(&vault, cli.packs.as_deref()) {
        Ok(pair) => pair,
        Err(err) => {
            print_error(cli.json, Some(&vault.root.display().to_string()), &err)?;
            return Ok(ExitCode::from(err.exit_code() as u8));
        }
    };
    let bundle = match build_context(&vault, &person, include_private, &scope) {
        Some(b) => b,
        None => {
            // ⚠2b: the person's key is absent (their record is an envelope
            // this device cannot read) is a hard error, not "not found".
            if record_decrypt::person_has_envelope(&vault.root, &person.to_string()) {
                return Err(anyhow::Error::new(
                    DomainError::invalid(format!(
                        "cannot decrypt records for {person_raw}: this device has no key for them"
                    ))
                    .with_fix(
                        "Run `confidant recover` on this device, or ask an enrolled device to add it via `confidant keys device-add`",
                    ),
                ));
            }
            return Err(anyhow::Error::new(DomainError::not_found(format!(
                "no person with id {person_raw}"
            )))
            .context("use `confidant find <name>` to look up the id"));
        }
    };
    if cli.json {
        let value = serde_json::to_value(&bundle)?;
        print_json(&ok_envelope(Some(root), value))?;
    } else {
        let p = &bundle.person;
        println!(
            "{} {}{}",
            p.id,
            p.name.as_deref().unwrap_or("(name withheld)"),
            if p.no_ai { " [no-ai]" } else { "" }
        );
        // #178: show the scope that applied, so a scoped bundle is never
        // mistaken for the whole record.
        if !bundle.scope.is_empty() && matches!(scope, PackScope::Only(_)) {
            println!("scope: {}", bundle.scope.join(", "));
        }
        if let Some(c) = &bundle.coaching {
            println!("sessions remaining: {}", c.sessions_remaining);
            println!("icf hours: {:.2}", c.icf_hours);
        }
        println!(
            "notes: {}, interactions: {}, touchpoints: {}",
            bundle.notes.len(),
            bundle.interactions.len(),
            bundle.touchpoints.len()
        );
        if !bundle.aliases.is_empty() {
            println!("aliases: {}", bundle.aliases.join(", "));
        }
        // ⚠2: the bundle carries what was skipped, never silent.
        if bundle.skipped_encrypted > 0 {
            println!("skipped_encrypted: {}", bundle.skipped_encrypted);
        }
        if bundle.refused_envelopes > 0 {
            println!("refused_envelopes: {}", bundle.refused_envelopes);
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

/// Latest GitHub Release endpoint (#165). Release builds always use the
/// real endpoint. `test-overrides` builds use `CONFIDANT_TEST_RELEASES_URL`
/// when set, and an unroutable loopback URL otherwise, so the test suite
/// never touches the network (the connection is refused instantly and the
/// check degrades to "unknown", exactly as an offline user would see).
fn releases_url() -> String {
    #[cfg(feature = "test-overrides")]
    {
        std::env::var("CONFIDANT_TEST_RELEASES_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:9/".to_owned())
    }
    #[cfg(not(feature = "test-overrides"))]
    {
        "https://api.github.com/repos/hirefrank/confidant/releases/latest".to_owned()
    }
}

/// `ok` message whenever staleness cannot be determined: offline, DNS
/// failure, timeout, non-200, or malformed JSON. Staleness is
/// informational, so `doctor` must never error or warn an offline user.
const STALENESS_UNKNOWN: &str = "staleness unknown (could not reach github releases)";

/// `ok` message when the operator disables the staleness checks outright
/// with `CONFIDANT_OFFLINE=1`: no request is made and no release tag is
/// fetched (see README and docs/privacy.md).
const STALENESS_DISABLED: &str = "staleness check disabled (CONFIDANT_OFFLINE=1)";

/// True when the operator has opted out of the outbound release check with
/// `CONFIDANT_OFFLINE`. Unset or empty means normal behaviour; any other
/// value (conventionally `1`) skips the fetch entirely.
fn staleness_offline() -> bool {
    std::env::var("CONFIDANT_OFFLINE")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// The `tag_name` of the latest GitHub Release, or `None` if it cannot be
/// fetched for any reason. A single failure mode (offline, timeout,
/// non-200, bad JSON) all collapse to `None`; only the parsed tag name is
/// ever returned, never the response body.
fn latest_release_tag() -> Option<String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(3)))
        .build()
        .into();
    let mut response = agent
        .get(&releases_url())
        .header("User-Agent", "confidant-cli")
        .header("Accept", "application/vnd.github+json")
        .call()
        .ok()?;
    let body = response.body_mut().read_to_string().ok()?;
    let value: Value = serde_json::from_str(&body).ok()?;
    value.get("tag_name")?.as_str().map(str::to_owned)
}

/// Parse a release tag like `v1.2.3` into `(major, minor, patch)`. The
/// leading `v` is optional and any suffix on the patch (e.g. `-rc.1`) is
/// ignored: `/releases/latest` never returns a prerelease, so dropping the
/// suffix cannot mask one. Returns `None` for anything that is not
/// `major.minor.patch`, which the caller treats the same as "unknown".
fn parse_release_version(tag: &str) -> Option<(u64, u64, u64)> {
    let trimmed = tag.trim().trim_start_matches('v');
    let mut parts = trimmed.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch: String = parts
        .next()?
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    Some((major, minor, patch.parse::<u64>().ok()?))
}

/// Build the CLI staleness check given the latest release tag (or `None`
/// when it could not be fetched). Warning-only; ahead and equal are `ok`.
/// With `offline`, the fetch was skipped and the check reports `ok`
/// "disabled".
fn cli_staleness_check(latest: Option<String>, offline: bool) -> DoctorCheck {
    let local = env!("CARGO_PKG_VERSION");
    let (status, message) = if offline {
        ("ok", STALENESS_DISABLED.to_owned())
    } else {
        match latest {
            None => ("ok", STALENESS_UNKNOWN.to_owned()),
            Some(tag) => match (parse_release_version(local), parse_release_version(&tag)) {
                (Some(local_v), Some(latest_v)) if local_v < latest_v => (
                    "warning",
                    format!(
                        "confidant-cli {local} is behind the latest release {tag}; \
                         update with `cargo install confidant-cli`"
                    ),
                ),
                (Some(local_v), Some(latest_v)) if local_v > latest_v => (
                    "ok",
                    format!(
                        "confidant-cli {local} is ahead of the latest release {tag} (dev build)"
                    ),
                ),
                (Some(_), Some(_)) => (
                    "ok",
                    format!("confidant-cli {local} matches the latest release {tag}"),
                ),
                _ => ("ok", STALENESS_UNKNOWN.to_owned()),
            },
        }
    };
    DoctorCheck {
        id: "cli-staleness",
        status,
        message,
    }
}

/// Minimum git version Confidant relies on. SSH commit signing landed in
/// git 2.34, and inbox signature checks read
/// `git log --format=%G?/%GK`, so verifying signatures needs at least
/// this version when signers are SSH keys. GPG signers work on older
/// git, but the signer list holds opaque key IDs, so any configured
/// signer is treated as possibly SSH (see `git_version_check`).
const MIN_GIT_VERSION: (u64, u64, u64) = (2, 34, 0);

/// Parse `git --version` output into `(major, minor, patch)`. Handles
/// real-world suffixes: `git version 2.39.3 (Apple Git-145)` and
/// `git version 2.47.1.windows.1`. Missing minor/patch default to 0.
/// Returns `None` when no leading version number can be read.
fn parse_git_version(output: &str) -> Option<(u64, u64, u64)> {
    let token = output
        .trim()
        .strip_prefix("git version ")?
        .split_whitespace()
        .next()?;
    let mut parts = token.split('.');
    let leading_digits = |s: &str| -> Option<u64> {
        let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            None
        } else {
            digits.parse().ok()
        }
    };
    let major = leading_digits(parts.next()?)?;
    let minor = parts.next().and_then(leading_digits).unwrap_or(0);
    let patch = parts.next().and_then(leading_digits).unwrap_or(0);
    Some((major, minor, patch))
}

/// Build the `git-version` doctor check from a parsed `git --version`
/// result. `has_signers` is whether the user config lists `[trust]`
/// signers: below the floor that means signature verification is in use
/// and the check is an `error`; with no signers configured it is a
/// `warning`, since nothing verifies signatures today. `None` (git
/// missing or unparseable output) is a `warning`: the `git-repo` check
/// already errors when the vault is not a git repository, and an
/// unparseable version string is an odd environment, not a known-bad git.
fn git_version_check_from(version: Option<(u64, u64, u64)>, has_signers: bool) -> DoctorCheck {
    let floor = format!(
        "{}.{}.{}",
        MIN_GIT_VERSION.0, MIN_GIT_VERSION.1, MIN_GIT_VERSION.2
    );
    match version {
        Some(v) if v >= MIN_GIT_VERSION => DoctorCheck {
            id: "git-version",
            status: "ok",
            message: format!(
                "git {}.{}.{} (>= {floor}; SSH-signed inbox commits supported)",
                v.0, v.1, v.2
            ),
        },
        Some(v) => DoctorCheck {
            id: "git-version",
            status: if has_signers { "error" } else { "warning" },
            message: format!(
                "git {}.{}.{} is below the minimum {floor}; upgrade git to >= {floor} for SSH-signed inbox commits",
                v.0, v.1, v.2
            ),
        },
        None => DoctorCheck {
            id: "git-version",
            status: "warning",
            message: format!(
                "could not determine git version; SSH-signed inbox commits need git >= {floor}"
            ),
        },
    }
}

/// The `git-version` doctor check: runs `git --version` and compares
/// against `MIN_GIT_VERSION`. See `git_version_check_from` for the
/// status rules.
fn git_version_check(has_signers: bool) -> DoctorCheck {
    let version = std::process::Command::new("git")
        .arg("--version")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| parse_git_version(&String::from_utf8_lossy(&out.stdout)));
    git_version_check_from(version, has_signers)
}

/// `keys-staging` doctor check (#175): leftover `.confidant/keys.stage`,
/// `.confidant/keys.old`, or staged seq tracker from an interrupted or
/// crashed keys operation. Leftovers with `keys/` intact are a warning
/// (the next keys mutation repairs them); `keys/` missing is an error.
fn keys_staging_check(root: &Path) -> DoctorCheck {
    let keys_dir = root.join("keys");
    let mut leftovers: Vec<&str> = Vec::new();
    if keys_stage_dir(root).exists() {
        leftovers.push("keys.stage");
    }
    if keys_old_dir(root).exists() {
        leftovers.push("keys.old");
    }
    if let Some(config_dir) = confidant_config_dir() {
        if keys_staged_tracker_path(&config_dir).exists() {
            leftovers.push("manifest-seq.stage.toml");
        }
    }
    if leftovers.is_empty() {
        return DoctorCheck {
            id: "keys-staging",
            status: "ok",
            message: "no leftover keys/ staging state".to_owned(),
        };
    }
    let detail = leftovers.join(", ");
    if keys_dir.exists() {
        DoctorCheck {
            id: "keys-staging",
            status: "warning",
            message: format!(
                "leftover keys/ staging state ({detail}) from an interrupted operation; the next keys device-add or revoke repairs it"
            ),
        }
    } else {
        DoctorCheck {
            id: "keys-staging",
            status: "error",
            message: format!(
                "keys/ is missing with leftover staging state ({detail}); re-run the interrupted keys command — it repairs staging leftovers before starting"
            ),
        }
    }
}

/// Skills link health for `setup`-managed installs. Skills ship in the
/// binary and are linked into agent skill dirs by `confidant setup`; there
/// is no checkout to compare against a release tag. Warning-only: missing
/// links never fail `doctor`.
///
/// Only agents `setup` actually targeted (dirs containing at least one
/// confidant-owned entry) count toward the warning; detected-but-never-
/// targeted agents are reported, not warned about. Entries sharing one dir
/// (e.g. `muse`/`agents` both map to `.agents/skills`) are counted once.
fn skills_links_check() -> DoctorCheck {
    let home = match setup::home_dir() {
        Ok(h) => h,
        Err(e) => {
            return DoctorCheck {
                id: "skills-links",
                status: "warning",
                message: format!("cannot determine home directory: {e:#}"),
            };
        }
    };
    let health: Vec<setup::AgentHealth> = match setup::skills_dir_override() {
        Some(dir) => vec![setup::agent_health_for_dir("custom", &dir)],
        None => setup::agents_health(&home),
    };
    // Dedupe entries that resolve to the same dir.
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut unique: Vec<&setup::AgentHealth> = Vec::new();
    for h in &health {
        if seen.iter().any(|d| d == &h.dir) {
            continue;
        }
        seen.push(h.dir.clone());
        unique.push(h);
    }
    let targeted: Vec<_> = unique.iter().filter(|h| h.detected && h.targeted).collect();
    if targeted.is_empty() {
        return DoctorCheck {
            id: "skills-links",
            status: "ok",
            message: "no agents set up; run `confidant setup --agent auto` to install skills"
                .to_owned(),
        };
    }
    let total_expected: usize = targeted.iter().map(|h| h.total).sum();
    let total_linked: usize = targeted.iter().map(|h| h.linked).sum();
    if total_linked == total_expected {
        let names: Vec<_> = targeted.iter().map(|h| h.name.as_str()).collect();
        DoctorCheck {
            id: "skills-links",
            status: "ok",
            message: format!(
                "skills linked ({total_linked}/{total_expected}) for {}",
                names.join(", ")
            ),
        }
    } else {
        let mut parts = Vec::new();
        for h in targeted {
            parts.push(format!("{} {}/{}", h.name, h.linked, h.total));
        }
        DoctorCheck {
            id: "skills-links",
            status: "warning",
            message: format!(
                "skills missing (linked {total_linked}/{total_expected}: {}); run `confidant setup --agent auto`",
                parts.join(", ")
            ),
        }
    }
}

fn cmd_doctor(
    cli: &Cli,
    root: &Path,
    user_config: Option<&UserConfig>,
    clear_pending_inbox_rotation: bool,
) -> anyhow::Result<ExitCode> {
    let mut checks: Vec<DoctorCheck> = Vec::new();

    // #105: handle --clear-pending-inbox-rotation first (explicit operator action).
    if clear_pending_inbox_rotation {
        let path = pending_inbox_rotation_path()?;
        if path.exists() {
            if !cli.no_input {
                // Require confirmation unless --no-input.
                eprintln!(
                    "Clear the pending inbox-rotation reminder at {}? [y/N]",
                    path.display()
                );
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    eprintln!("not cleared");
                    return Ok(ExitCode::SUCCESS);
                }
            }
            std::fs::remove_file(&path)?;
            eprintln!("cleared pending inbox-rotation reminder");
        } else {
            eprintln!("no pending inbox-rotation reminder to clear");
        }
        return Ok(ExitCode::SUCCESS);
    }

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

    // #174: minimum git version. SSH signing landed in git 2.34, and
    // inbox signature checks read `%G?`/`%GK`, so signature verification
    // needs at least that version. Signers are opaque key IDs, so any
    // configured signer counts as possibly SSH (error below the floor);
    // with no signers configured nothing verifies signatures, so below
    // the floor is a warning.
    let has_signers = user_config
        .map(|u| !u.trust.signers.is_empty())
        .unwrap_or(false);
    checks.push(git_version_check(has_signers));

    // #175: leftover keys/ staging state from an interrupted swap.
    checks.push(keys_staging_check(root));

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
            // #73: key-manifest health. A corrupt recipients.toml used to
            // read as seq 0, indistinguishable from "no manifest yet".
            // Report corrupt manifests as errors naming the client; absent
            // manifests (and a vault with no keys/ tree at all) are normal
            // and stay quiet.
            let keys_dir = root.join("keys");
            if keys_dir.is_dir() {
                // The seq tracker is mandatory (issue #134); resolve its
                // conventional location from HOME. A tracker we cannot load
                // is reported, not skipped: without it the replay check is
                // a no-op.
                match confidant_config_dir() {
                    None => checks.push(DoctorCheck {
                        id: "crypto-manifests",
                        status: "error",
                        message: "cannot locate the config dir (HOME unset); \
                                  the manifest seq tracker cannot be checked"
                            .to_owned(),
                    }),
                    Some(config_dir) => {
                        match confidant_crypt::lifecycle::KeyStore::with_config_dir(
                            keys_dir,
                            &vault.config.vault_id,
                            &config_dir,
                        ) {
                            Err(e) => checks.push(DoctorCheck {
                                id: "crypto-manifests",
                                status: "error",
                                message: format!("manifest seq tracker unreadable: {e}"),
                            }),
                            Ok(store) => {
                                let mut corrupt: Vec<String> = Vec::new();
                                let mut valid = 0u64;
                                for client_id in store.manifest_clients() {
                                    match store.manifest_state(&client_id) {
                                        confidant_crypt::lifecycle::ManifestState::Valid(_) => {
                                            valid += 1
                                        }
                                        confidant_crypt::lifecycle::ManifestState::Corrupt(
                                            reason,
                                        ) => {
                                            corrupt.push(format!("{client_id} ({reason})"));
                                        }
                                        confidant_crypt::lifecycle::ManifestState::Absent => {}
                                    }
                                }
                                if corrupt.is_empty() {
                                    checks.push(DoctorCheck {
                                        id: "crypto-manifests",
                                        status: "ok",
                                        message: if valid == 0 {
                                            "no key manifests yet".to_owned()
                                        } else {
                                            format!("{valid} key manifest(s) parse")
                                        },
                                    });
                                } else {
                                    checks.push(DoctorCheck {
                                        id: "crypto-manifests",
                                        status: "error",
                                        message: format!(
                                            "corrupt key manifest(s); fix or re-init before crypto operations: {}",
                                            corrupt.join("; ")
                                        ),
                                    });
                                }
                                // #154 must-fix 4: surface degraded git history,
                                // which makes the shredded-client / retired-recovery
                                // checks fail open.
                                if let Some(reason) = store.history_degraded_reason() {
                                    checks.push(DoctorCheck {
                                        id: "shred-history",
                                        status: "warning",
                                        message: reason,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => checks.push(DoctorCheck {
            id: "vault-load",
            status: "error",
            message: format!("cannot load vault: {e}"),
        }),
    }

    // PR B owns crypto (ADR-13). `is_available()` tells us whether this build
    // can encrypt at all; `writes_encrypted()` tells us whether the CLI write
    // path actually does. Since spec 3, record writes encrypt by default on
    // encrypted vaults; `mode = "plaintext"` is a per-vault opt-out for
    // vaults that hold no real data, and never re-flips this global flag.
    // The check reports the effective mode so the opt-out is always visible.
    if confidant_crypt::writes_encrypted() {
        let mode_desc = match load_vault(root) {
            Ok(vault) => {
                match confidant_core::crypto_mode::resolve_write_mode(root, &vault.config) {
                    Ok(confidant_core::crypto_mode::WriteMode::Encrypted) => {
                        "record writes encrypt by default; this vault is encrypted"
                    }
                    Ok(confidant_core::crypto_mode::WriteMode::Plaintext) => {
                        "record writes encrypt by default; this vault opts out (`mode = \"plaintext\"`)"
                    }
                    Err(_) => {
                        "record writes encrypt by default; this vault is unkeyed (writes fail closed)"
                    }
                }
            }
            Err(_) => "record writes encrypt by default; vault unreadable",
        };
        checks.push(DoctorCheck {
            id: "crypto",
            status: "ok",
            message: mode_desc.to_owned(),
        });
    } else if confidant_crypt::is_available() {
        checks.push(DoctorCheck {
            id: "crypto",
            status: "warning",
            message:
                "crypto library present, CLI not wired yet, vault content is stored as plaintext"
                    .to_owned(),
        });
    } else {
        checks.push(DoctorCheck {
            id: "crypto",
            status: "warning",
            message: "encryption not available in this build; vault content is stored as plaintext"
                .to_owned(),
        });
    }

    // #105: report pending inbox rotation as a warning until explicitly cleared.
    if let Ok(pending_path) = pending_inbox_rotation_path() {
        if pending_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&pending_path) {
                // Extract shredded_client for the message (opaque id).
                let client = content
                    .lines()
                    .find(|l| l.starts_with("shredded_client"))
                    .and_then(|l| l.split('=').nth(1))
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .unwrap_or_else(|| "<unknown>".to_string());
                checks.push(DoctorCheck {
                    id: "inbox-rotation-pending",
                    status: "warning",
                    message: format!(
                        "inbox rotation pending after `keys shred {client}` on a non-inbox device; \
                         run `confidant inbox rotate --finish` on the inbox device, then \
                         `confidant doctor --clear-pending-inbox-rotation`"
                    ),
                });
            }
        }
    }

    // Spec 3 (⚠1, B6): report the plaintext vs encrypted record-file mix.
    // Existing plaintext records are never encrypted in place, so a mix is
    // expected during (and after) the transition — this is informational.
    // Code + count only; never names or paths.
    {
        let (encrypted, plaintext) = confidant_core::crypto_mode::count_record_mix(root);
        checks.push(DoctorCheck {
            id: "record-encryption-mix",
            status: "ok",
            message: format!("{encrypted} encrypted, {plaintext} plaintext record files"),
        });
    }

    // #165: staleness vs the latest GitHub Release. Warning-only: a stale
    // install is never an error, so exit-code semantics are unchanged. Any
    // network failure degrades to `ok` "unknown" (offline-first):
    // staleness is informational, so `doctor` must not punish offline users.
    //
    // `CONFIDANT_OFFLINE=1` opts out entirely: the fetch is skipped before
    // any request is made and the check reports `ok` "disabled". See the
    // README Privacy section and docs/privacy.md for the disclosure.
    // Skills ship in the binary and are version-locked to it, so there is
    // no separate skills checkout to compare — `skills-links` below reports
    // link health instead.
    {
        let offline = staleness_offline();
        let latest = if offline { None } else { latest_release_tag() };
        checks.push(cli_staleness_check(latest, offline));
        checks.push(skills_links_check());
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
        let mut envelope = ok_envelope(Some(root), serde_json::Value::Object(extra));
        envelope["ok"] = serde_json::Value::Bool(ok);
        print_json(&envelope)?;
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

// ---------------------------------------------------------------------------
// init / recover (milestone 2 key ceremony)
// ---------------------------------------------------------------------------

/// Display the recovery phrase exactly once on stderr, per the channel
/// rules (spec ⚠4): never on stdout, never in `--json` output. Prompts
/// for confirmation unless `--no-input` (then prints a louder warning).
fn display_phrase_once(no_input: bool, phrase: &zeroize::Zeroizing<String>) -> io::Result<()> {
    eprintln!("=================================================================");
    eprintln!("RECOVERY PHRASE — write it down now. It will not be shown again.");
    eprintln!("=================================================================");
    eprintln!("{}", phrase.as_str());
    eprintln!("=================================================================");
    if no_input {
        eprintln!("WARNING: --no-input was passed, so this phrase was not confirmed.");
        eprintln!("Store it somewhere safe (paper, password manager) before continuing.");
    } else {
        eprint!("Have you written down the recovery phrase? [y/N] ");
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            eprintln!("WARNING: phrase not confirmed. Store it safely before continuing.");
        }
    }
    Ok(())
}

/// Resolve the device key for init/recover: the `CONFIDANT_DEVICE_KEY`
/// env var (tests) or a fresh keypair stored via the keychain module.
/// Returns `(bech32_secret, recipient_string)`.
///
/// `CONFIDANT_TEST_DEVICE_KEY` (only with the `test-overrides` feature,
/// which CI enables via --all-features and release builds never do)
/// provides the key without counting as an enrollment for the B13
/// fresh-device check.
fn provision_device_key() -> anyhow::Result<(String, String)> {
    use age::secrecy::ExposeSecret;
    use std::str::FromStr;
    // Test keychain dir (test builds only): read the device key from the
    // file instead of generating/storing. Used by the shred rotation test.
    #[cfg(feature = "test-overrides")]
    if let Some(dir) = test_keychain_dir() {
        let bech32 = std::fs::read_to_string(dir.join("device.key")).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read test device key: {e}"
            )))
        })?;
        let id = age::x25519::Identity::from_str(bech32.trim()).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!("bad test device key: {e}")))
        })?;
        let recipient = id.to_public().to_string();
        return Ok((bech32.trim().to_string(), recipient));
    }
    // Test override: provides a key without enrolling (B13 ignores it).
    // Feature-gated so production binaries never honor it.
    #[cfg(feature = "test-overrides")]
    if let Ok(test_key) = std::env::var("CONFIDANT_TEST_DEVICE_KEY") {
        let trimmed = test_key.trim();
        if !trimmed.is_empty() {
            let id = age::x25519::Identity::from_str(trimmed).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "CONFIDANT_TEST_DEVICE_KEY is not a valid age identity: {e}"
                )))
            })?;
            let recipient = id.to_public().to_string();
            return Ok((trimmed.to_string(), recipient));
        }
    }
    if let Ok(env_key) = std::env::var(confidant_crypt::keychain::DEVICE_KEY_ENV) {
        let trimmed = env_key.trim();
        if !trimmed.is_empty() {
            // Test path: the env var IS the enrolled key; parse it for the
            // recipient and skip the keychain write.
            let id = age::x25519::Identity::from_str(trimmed).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "{} is not a valid age identity: {e}",
                    confidant_crypt::keychain::DEVICE_KEY_ENV
                )))
            })?;
            let recipient = id.to_public().to_string();
            return Ok((trimmed.to_string(), recipient));
        }
    }
    // Production path: generate and enroll via the keychain module.
    let id = age::x25519::Identity::generate();
    let bech32 = id.to_string().expose_secret().to_owned();
    confidant_crypt::keychain::store_device_key(&bech32).map_err(anyhow::Error::new)?;
    let recipient = id.to_public().to_string();
    Ok((bech32, recipient))
}

fn cmd_init(cli: &Cli, root: &Path, force: bool) -> anyhow::Result<ExitCode> {
    use confidant_crypt::{
        anchor, lifecycle::KeyStore, manifest::SHARED_CLIENT_ID, recovery::Recovery,
    };
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let json = cli.json;
    let no_input = cli.no_input;

    // Config dir (off-vault, per design §4).
    let config_dir = confidant_config_dir().ok_or_else(|| {
        anyhow::Error::new(DomainError::invalid(
            "HOME is not set; cannot locate the operator config dir",
        ))
    })?;

    // B1: refuse if the anchor already exists — it is a trust root and is
    // never silently replaced. With --force the existing anchor is
    // replaced, but only AFTER every check and key step succeeds (never
    // deleted up front: a failed init must not leave the device
    // anchorless).
    let trust_path = config_dir.join(anchor::TRUST_FILE);
    let trust_exists = trust_path.exists();
    if trust_exists && !force {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "trust anchor already exists at {}; refusing to overwrite (run `confidant recover` on a new device, or pass --force)",
                trust_path.display()
            ))
            .with_fix("Run `confidant recover` with the recovery phrase on a new device"),
        ));
    }

    // Git repo + clean tree required.
    require_git_repo(root, no_input)?;
    let status = confidant_core::write::git(root, &["status", "--porcelain"], no_input)?;
    if !status.trim().is_empty() {
        return Err(anyhow::Error::new(
            DomainError::invalid("vault tree is not clean; commit or stash changes first")
                .with_fix("Run `git status` in the vault and clean the tree"),
        ));
    }

    // B2: generate operator key, recovery phrase, and device keypair.
    // None of this material is ever written into the vault.
    // Test override (test-overrides feature only): CONFIDANT_TEST_OPERATOR_KEY
    // provides the hex seed.
    #[cfg(feature = "test-overrides")]
    let operator_sk = test_operator_key().unwrap_or_else(|| SigningKey::generate(&mut OsRng));
    #[cfg(not(feature = "test-overrides"))]
    let operator_sk = SigningKey::generate(&mut OsRng);
    let recovery = Recovery::generate();
    let (_device_bech32, device_recipient) = provision_device_key()?;

    // Persist the operator signing key to the OS keychain (needed for
    // `keys` commands to sign manifests). This is never skipped when
    // CONFIDANT_DEVICE_KEY is set — the key must be persisted even in
    // headless/test environments. In tests (CONFIDANT_KEYCHAIN=off),
    // the keychain write is refused; the test harness provides the key
    // via CONFIDANT_TEST_OPERATOR_KEY instead.
    if let Err(e) =
        confidant_crypt::keychain::store_operator_key(&hex::encode(operator_sk.to_bytes()))
    {
        if confidant_crypt::keychain::keychain_switch().map_err(anyhow::Error::new)?
            != confidant_crypt::keychain::KeychainSwitch::Off
        {
            return Err(anyhow::Error::new(e));
        }
        // Kill switch set: test mode; the harness provides the key via env.
    }

    // B3: build the anchor in memory. It is persisted atomically only
    // after every fallible key step succeeds (below): if the KeyStore
    // work fails, no anchor pins a recovery key whose phrase was never
    // shown, and a retry is clean.
    let anchor = anchor::Anchor {
        operator: operator_sk.verifying_key(),
        recovery: recovery.verifying_key(),
        recovery_age: recovery.age_identity().to_recipient_string(),
        source: trust_path.clone(),
    };

    // B4 + B6: KeyStore via with_config_dir (mandatory seq tracker).
    // Initialize the vault lookup key and the vault:shared client (⚠6).
    let vault = load_vault(root)?;
    // Spec 3 (§2.2): keys must never coexist with a plaintext declaration.
    // `init` on a vault declaring `[crypto] mode = "plaintext"` is a hard
    // error — the opt-out is a pre-`init` declaration only.
    if vault.config.crypto.mode.as_deref() == Some("plaintext") {
        return Err(anyhow::Error::new(
            DomainError::config(
                "confidant.toml declares [crypto] mode = \"plaintext\", but `init` \
                 creates vault keys; keys must never coexist with a plaintext declaration",
            )
            .with_fix(
                "Remove the `[crypto] mode = \"plaintext\"` line, or run `init` in a fresh vault",
            ),
        ));
    }
    let keys_dir = root.join("keys");
    let mut store =
        KeyStore::with_config_dir(keys_dir.clone(), &vault.config.vault_id, &config_dir)
            .map_err(anyhow::Error::new)?;
    store
        .init_lookup_key(std::slice::from_ref(&device_recipient), &operator_sk)
        .map_err(anyhow::Error::new)?;
    let mut recipients = confidant_crypt::manifest::RecipientMap::new();
    recipients.insert(
        "device-0".to_string(),
        confidant_crypt::manifest::RecipientEntry {
            age_pubkey: device_recipient.clone(),
            label: "device-0".to_string(),
            scope_ref: String::new(),
        },
    );
    store
        .init_client(SHARED_CLIENT_ID, &recipients, &anchor, &operator_sk)
        .map_err(anyhow::Error::new)?;

    // Fresh-device recovery: write the operator-pubkey certificate
    // (signed by the recovery key) so a device with no trust.toml can
    // rebuild trust from the keys/ tree. Committed with the keys/ tree.
    anchor::write_operator_cert(
        &keys_dir,
        &vault.config.vault_id,
        &operator_sk.verifying_key(),
        recovery.signing_key(),
    )
    .map_err(anyhow::Error::new)?;

    // Commit the keys/ tree: check first (readers skip keys/, so it
    // passes), one commit. The .age files are binary, so they go through
    // the repo's git helper rather than the String-based FileChange.
    let pre = check_vault(&vault, &CheckOptions::default());
    if !pre.ok {
        return Err(anyhow::Error::new(DomainError::invalid(
            "check failed before committing the keys/ tree; refusing to commit a broken vault",
        )));
    }
    stage_keys(root, no_input)?;
    confidant_core::write::git(
        root,
        &["commit", "-m", "init: trust anchor and vault keys"],
        no_input,
    )?;
    let commit = confidant_core::write::git(root, &["rev-parse", "HEAD"], no_input)?
        .trim()
        .to_owned();

    // Persist the anchor now that everything succeeded. Atomic
    // temp-and-rename: a crash never leaves a half-written trust.toml.
    // With --force this replaces the previous anchor.
    if trust_exists {
        anchor::replace(
            &config_dir,
            root,
            &anchor.operator,
            &anchor.recovery,
            &anchor.recovery_age,
        )
        .map_err(anyhow::Error::new)?;
    } else {
        anchor::save(
            &config_dir,
            root,
            &anchor.operator,
            &anchor.recovery,
            &anchor.recovery_age,
        )
        .map_err(anyhow::Error::new)?;
    }

    // B5: phrase exactly once on stderr; stdout JSON carries ok, vault,
    // and opaque paths — no phrase, no key material.
    display_phrase_once(no_input, &recovery.phrase())?;

    if json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "anchor": trust_path.display().to_string(),
                "keys_dir": keys_dir.display().to_string(),
                "commit": commit,
            }),
        ))?;
    } else {
        println!("initialized trust anchor at {}", trust_path.display());
        println!("committed keys/ tree ({})", &commit[..8.min(commit.len())]);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_recover(
    cli: &Cli,
    root: &Path,
    phrase_file: Option<&Path>,
    anchor_file: Option<&Path>,
) -> anyhow::Result<ExitCode> {
    use confidant_crypt::{
        anchor, keychain,
        lifecycle::KeyStore,
        manifest::{RecipientEntry, RecipientMap, RECOVERY_KEY_ID, VAULT_CLIENT_ID},
        recovery::Recovery,
    };

    let json = cli.json;
    let no_input = cli.no_input;

    // B7: phrase via stdin or --phrase-file only — never argv.
    // Wrapped in Zeroizing: the plaintext phrase is wiped on drop.
    let phrase: zeroize::Zeroizing<String> = if let Some(path) = phrase_file {
        zeroize::Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| {
                    anyhow::Error::new(DomainError::usage(format!(
                        "--phrase-file {} unreadable: {e}",
                        path.display()
                    )))
                })?
                .trim()
                .to_string(),
        )
    } else {
        let mut buf = String::new();
        use std::io::Read;
        io::stdin().read_to_string(&mut buf).map_err(|e| {
            anyhow::Error::new(DomainError::usage(format!(
                "cannot read phrase from stdin: {e}"
            )))
        })?;
        zeroize::Zeroizing::new(buf.trim().to_string())
    };
    if phrase.is_empty() {
        return Err(anyhow::Error::new(DomainError::usage(
            "recovery phrase is required via stdin or --phrase-file",
        )));
    }

    // B8: validate (typo-in-word-N errors; never echoes the word).
    let old_recovery = Recovery::from_phrase(&phrase).map_err(anyhow::Error::new)?;
    let old_identity = old_recovery.age_identity().to_age_identity().map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!("bad recovery identity: {e}")))
    })?;

    // B13: recover requires a fresh device. A device key available via
    // the OS keychain or CONFIDANT_DEVICE_KEY means this device already
    // went through init (the CONFIDANT_TEST_DEVICE_KEY override does not
    // count — it is how tests provide the new key).
    let device_enrolled = keychain::device_key().is_ok();
    if device_enrolled {
        return Err(anyhow::Error::new(
            DomainError::invalid(
                "this device already has a device key enrolled; recover is for fresh devices",
            )
            .with_fix("To add this device to the vault, wait for #66 (device add)"),
        ));
    }

    let config_dir = confidant_config_dir().ok_or_else(|| {
        anyhow::Error::new(DomainError::invalid(
            "HOME is not set; cannot locate the operator config dir",
        ))
    })?;

    require_git_repo(root, no_input)?;
    let status = confidant_core::write::git(root, &["status", "--porcelain"], no_input)?;
    if !status.trim().is_empty() {
        return Err(anyhow::Error::new(DomainError::invalid(
            "vault tree is not clean; commit or stash changes first",
        )));
    }

    let vault = load_vault(root)?;
    let keys_dir = root.join("keys");

    // Load the trust anchor. Three sources, in order of explicitness:
    // 1. `--anchor-file <path>` (#152): load exactly this file; the phrase
    //    must match its recovery key (fail closed). No keys/-tree fallback:
    //    an explicit anchor that does not match is an error, never a cue to
    //    rebuild from the vault.
    // 2. The device's `~/.config/confidant/trust.toml`.
    // 3. On a fresh device (no trust.toml, no config backup), rebuild it
    //    from the vault's keys/ tree: the operator certificate (written at
    //    init, signed by the recovery key) is verified against the
    //    phrase-derived recovery pubkey. This is the lost-device path — the
    //    phrase alone re-establishes trust.
    //
    // Nothing is written to the config dir until this succeeds.
    let check_recovery = |a: &anchor::Anchor| -> anyhow::Result<()> {
        if a.recovery != old_recovery.verifying_key() {
            return Err(anyhow::Error::new(DomainError::invalid(
                "recovery phrase does not match this vault's trust anchor",
            )));
        }
        // The X25519 recovery recipient is a separate HKDF branch of the
        // phrase; it must match too, or a tampered anchor file could get a
        // forged recipient recorded in the denylist and the real retired
        // recipient missed (#154 must-fix 1).
        if a.recovery_age != old_recovery.age_identity().to_recipient_string() {
            return Err(anyhow::Error::new(DomainError::invalid(
                "recovery phrase does not match this vault's trust anchor (recovery recipient)",
            )));
        }
        Ok(())
    };
    let anchor = if let Some(path) = anchor_file {
        let a = anchor::load_from(path, root).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "--anchor-file {} rejected: {e}",
                path.display()
            )))
        })?;
        check_recovery(&a)?;
        // #154 must-fix 3: the supplied operator key may only be accepted
        // when the vault has no operator certificate (the pre-cert case the
        // backup exists for). When a cert is present it must verify against
        // the phrase-derived recovery key and name the same operator — so a
        // tampered anchor backup can never get the recovery key to certify
        // an attacker's operator key.
        if keys_dir.join(anchor::OPERATOR_CERT_FILE).exists() {
            let cert_operator = anchor::verify_operator_cert(
                &keys_dir,
                &vault.config.vault_id,
                &old_recovery.verifying_key(),
            )
            .map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "operator certificate present but does not verify against the phrase; \
                     refusing the supplied --anchor-file: {e}"
                )))
            })?;
            if cert_operator != a.operator {
                return Err(anyhow::Error::new(DomainError::invalid(
                    "--anchor-file's operator key does not match this vault's operator \
                     certificate; refusing",
                )));
            }
        }
        a
    } else {
        match anchor::load(&config_dir, root) {
            Ok((a, _warnings)) => {
                // The phrase must be for THIS vault: the recovery public key
                // in the anchor must match the phrase-derived one.
                check_recovery(&a)?;
                a
            }
            Err(_) => {
                let operator_pubkey = anchor::verify_operator_cert(
                    &keys_dir,
                    &vault.config.vault_id,
                    &old_recovery.verifying_key(),
                )
                .map_err(anyhow::Error::new)?;
                anchor::Anchor {
                    operator: operator_pubkey,
                    recovery: old_recovery.verifying_key(),
                    recovery_age: old_recovery.age_identity().to_recipient_string(),
                    source: config_dir.join(anchor::TRUST_FILE),
                }
            }
        }
    };
    let operator_pubkey = anchor.operator;
    let mut store =
        KeyStore::with_config_dir(keys_dir.clone(), &vault.config.vault_id, &config_dir)
            .map_err(anyhow::Error::new)?;

    // B9: unwrap every initialized client's keys through their recovery
    // wrappings. The vault lookup key is device-only (B12 handles it).
    let mut clients: Vec<String> = store
        .manifest_clients()
        .into_iter()
        .filter(|c| c != VAULT_CLIENT_ID)
        .collect();
    clients.sort();
    let mut data_keys: Vec<(String, confidant_crypt::keys::DataKey)> = Vec::new();
    for client_id in &clients {
        let epoch = store.current_epoch(client_id).map_err(anyhow::Error::new)?;
        let key = store
            .unwrap_data_key(client_id, RECOVERY_KEY_ID, epoch, &old_identity, &anchor)
            .map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot unwrap keys for client {client_id} via recovery: {e}"
                )))
            })?;
        data_keys.push((client_id.clone(), key));
    }

    // B10: new device key, enrolled.
    let (_new_bech32, new_recipient) = provision_device_key()?;
    let mut new_recipients = RecipientMap::new();
    new_recipients.insert(
        "device-0".to_string(),
        RecipientEntry {
            age_pubkey: new_recipient.clone(),
            label: "device-0".to_string(),
            scope_ref: String::new(),
        },
    );

    // B11: rotate the recovery identity, then re-pin the anchor BEFORE any
    // other key operation (#99 ordering). The recovery Ed25519 key is a
    // trust-anchor signing member, so it authorizes the re-signing.
    let client_refs: Vec<&str> = clients.iter().map(|s| s.as_str()).collect();
    let new_recovery = store
        .rotate_recovery(
            &client_refs,
            old_recovery.signing_key(),
            &anchor,
            &old_identity,
        )
        .map_err(anyhow::Error::new)?;

    // Show the new phrase BEFORE swapping the anchor: if anything below
    // fails, the operator still holds the phrase for the rotated
    // recovery. (B5 channel rules: stderr once, never in --json stdout.)
    display_phrase_once(no_input, &new_recovery.phrase())?;

    // Re-pin: atomically replace trust.toml with the new recovery halves
    // (operator unchanged). Temp-file + rename: a crash never leaves a
    // half-written or missing anchor.
    let trust_path = config_dir.join(anchor::TRUST_FILE);
    anchor::replace(
        &config_dir,
        root,
        &operator_pubkey,
        &new_recovery.verifying_key(),
        &new_recovery.age_identity().to_recipient_string(),
    )
    .map_err(anyhow::Error::new)?;

    // Re-sign the manifests with the new recovery key. `rotate_recovery`
    // signed them with the OLD recovery key, but the re-pinned anchor
    // only trusts the new one — without this, every subsequent
    // verification fails. Verify against the OLD anchor (still valid
    // for the old signatures).
    for client_id in &clients {
        store
            .resign_manifest(client_id, &anchor, new_recovery.signing_key())
            .map_err(anyhow::Error::new)?;
    }

    // Re-sign the operator certificate with the new recovery key. It was
    // signed at init (or the previous recover) by the OLD recovery key;
    // without this, the next fresh-device recover with the NEW phrase
    // fails verify_operator_cert ("recovery phrase does not match this
    // vault") — a silent lockout. The operator pubkey is unchanged.
    anchor::write_operator_cert(
        &keys_dir,
        &vault.config.vault_id,
        &operator_pubkey,
        new_recovery.signing_key(),
    )
    .map_err(anyhow::Error::new)?;

    // Authorize the new device on every client (same path #66 reuses):
    // re-wrap each data key to the new device + new recovery.
    // Note: this drops every OTHER device's wrappings — recover is the
    // lost-device path, so only the new device is enrolled. Use
    // `keys device-add` (#66) to enroll additional devices afterwards.
    let (new_anchor, _) = anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
    for (client_id, key) in &data_keys {
        store
            .rewrap_recipients(
                client_id,
                key,
                &new_recipients,
                &new_anchor,
                new_recovery.signing_key(),
            )
            .map_err(anyhow::Error::new)?;
    }

    // B12: fresh lookup key (never restored, #142), re-wrapped to the new
    // device; the alias index rebuilds from the decrypted alias values
    // (design §10) — the local .confidant/ index is gitignored and
    // rebuilt on demand.
    store
        .init_lookup_key(
            std::slice::from_ref(&new_recipient),
            new_recovery.signing_key(),
        )
        .map_err(anyhow::Error::new)?;

    // Commit: check first, one commit.
    let vault2 = load_vault(root)?;
    let pre = check_vault(&vault2, &CheckOptions::default());
    if !pre.ok {
        return Err(anyhow::Error::new(DomainError::invalid(
            "check failed before committing the recovered keys/ tree",
        )));
    }
    stage_keys(root, no_input)?;
    confidant_core::write::git(
        root,
        &[
            "commit",
            "-m",
            "recover: re-wrap keys to new device, rotate recovery",
        ],
        no_input,
    )?;
    let commit = confidant_core::write::git(root, &["rev-parse", "HEAD"], no_input)?
        .trim()
        .to_owned();

    // The new phrase was already displayed (once, on stderr) before the
    // anchor swap above — it is not repeated here.
    //
    // #154 must-fix 4: warn — do not fail — when git history is degraded, so
    // the operator knows the shredded-client / retired-recovery checks only
    // saw the working tree.
    let history_warning = store.history_degraded_reason();
    let warnings: Vec<String> = history_warning.iter().cloned().collect();
    if let Some(w) = &history_warning {
        eprintln!("warning: {w}");
    }
    if json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "anchor": trust_path.display().to_string(),
                "keys_dir": keys_dir.display().to_string(),
                "commit": commit,
                "clients_recovered": clients,
                "warnings": warnings,
                "note": "only this device is enrolled now; other devices' wrappings were dropped (lost-device recovery)",
            }),
        ))?;
    } else {
        println!("recovered {} client(s); anchor re-pinned", clients.len());
        println!("committed ({})", &commit[..8.min(commit.len())]);
        println!("note: only this device is enrolled now; other devices' wrappings were dropped (lost-device recovery). Enroll more devices with `keys device-add`.");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_schema(cli: &Cli, vault: Option<&Path>) -> anyhow::Result<ExitCode> {
    let schema = contract_schema();
    if cli.json {
        print_json(&ok_envelope(vault, serde_json::json!({"contract": schema})))?;
    } else {
        println!("{}", serde_json::to_string_pretty(&schema)?);
    }
    Ok(ExitCode::SUCCESS)
}

fn setup_result_json(result: &setup::SetupResult) -> Value {
    let agents: Vec<Value> = result
        .agents
        .iter()
        .map(|a| {
            serde_json::json!({
                "name": a.name,
                "dir": a.dir.display().to_string(),
                "linked": a.links.iter().filter(|l| !matches!(l.outcome, setup::LinkOutcome::SkippedExists)).count(),
                "skipped": a.links.iter().filter(|l| matches!(l.outcome, setup::LinkOutcome::SkippedExists)).count(),
                "skills": a.links.iter().map(|l| serde_json::json!({
                    "skill": l.skill,
                    "dest": l.dest.display().to_string(),
                    "outcome": l.outcome.as_str(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({
        "skills_dir": result.skills_dir.display().to_string(),
        "home": result.home.display().to_string(),
        "version": result.version,
        "agents": agents,
        "unknown_agents": result.unknown_agents,
        "linked": result.linked_count(),
        "skipped": result.skipped_count(),
    })
}

fn cmd_setup(
    cli: &Cli,
    agent: &str,
    force: bool,
    copy: bool,
    verbose: bool,
) -> anyhow::Result<ExitCode> {
    match setup::run_setup(agent, force, copy) {
        Ok(result) => {
            if cli.json {
                print_json(&ok_envelope(None, setup_result_json(&result)))?;
            } else {
                if verbose {
                    for line in &result.verbose_lines {
                        println!("{line}");
                    }
                }
                for unknown in &result.unknown_agents {
                    eprintln!("warning: unknown agent '{unknown}' — skipped");
                }
                let labels = result.agent_labels().join(", ");
                println!("Confidant skills installed");
                println!("  skills   {} → {labels}", result.skills_dir.display());
                println!("  version  {}", result.version);
                println!(
                    "  linked   {} ({} skipped)",
                    result.linked_count(),
                    result.skipped_count()
                );
                if result.skipped_count() > 0 {
                    println!("  replace existing dirs with: confidant setup --force");
                }
                println!();
                println!("Next:");
                println!("  1. Set CONFIDANT_VAULT to your vault (or use --vault).");
                println!("  2. Run `confidant check --json --no-input` against it.");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => Err(err),
    }
}

fn cmd_update(cli: &Cli, agent: &str, force: bool, verbose: bool) -> anyhow::Result<ExitCode> {
    // Self-update via the cargo-dist updater is not yet wired: `update`
    // reports the latest release and re-links skills from this binary.
    // Honor CONFIDANT_OFFLINE=1 like `doctor` (no network at all).
    let offline = staleness_offline();
    let latest = if offline { None } else { latest_release_tag() };
    let local = env!("CARGO_PKG_VERSION");
    // Behind-ness is computed once and shared by the human and JSON paths.
    // `None` when the check is disabled or the release couldn't be fetched.
    let behind: Option<bool> = latest.as_deref().and_then(|tag| {
        parse_release_version(local)
            .zip(parse_release_version(tag))
            .map(|(l, r)| l < r)
    });
    let upgrade_cmd =
        "update the binary first (re-run the installer or `cargo install confidant-cli`), then re-run `confidant setup`.";
    if cli.json {
        let update_info = match &latest {
            None if offline => {
                serde_json::json!({"status": "disabled", "message": STALENESS_DISABLED, "behind": Value::Null})
            }
            None => {
                serde_json::json!({"status": "unknown", "message": STALENESS_UNKNOWN, "behind": Value::Null})
            }
            Some(tag) => {
                serde_json::json!({"status": "fetched", "latest": tag, "local": local, "behind": behind})
            }
        };
        if behind == Some(true) {
            // Never re-link from a behind binary: the installed skills would
            // be stale on arrival. Tell the operator how to upgrade instead.
            let value = serde_json::json!({
                "update": update_info,
                "message": format!("confidant {local} is behind; {upgrade_cmd}"),
            });
            print_json(&ok_envelope(None, value))?;
            return Ok(ExitCode::SUCCESS);
        }
        let result = setup::run_setup(agent, force, false)?;
        let mut value = setup_result_json(&result);
        if let Value::Object(ref mut obj) = value {
            obj.insert("update".to_owned(), update_info);
        }
        print_json(&ok_envelope(None, value))?;
        return Ok(ExitCode::SUCCESS);
    }
    if offline {
        println!("{STALENESS_DISABLED}");
    } else {
        match &latest {
            None => println!("{STALENESS_UNKNOWN}"),
            Some(tag) => {
                if behind == Some(true) {
                    println!("confidant {local} is behind the latest release {tag}; {upgrade_cmd}");
                    return Ok(ExitCode::SUCCESS);
                }
                println!("confidant {local} is current (latest: {tag}). Re-linking skills…");
            }
        }
    }
    // Re-link from this binary. `force` is the operator's own flag: owned
    // entries are re-pointed regardless, unowned entries need it.
    let result = setup::run_setup(agent, force, false)?;
    if verbose {
        for line in &result.verbose_lines {
            println!("{line}");
        }
    }
    for unknown in &result.unknown_agents {
        eprintln!("warning: unknown agent '{unknown}' — skipped");
    }
    println!(
        "re-linked {} skills → {}",
        result.linked_count(),
        result.agent_labels().join(", ")
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_agents(cli: &Cli, verbose: bool) -> anyhow::Result<ExitCode> {
    let home = setup::home_dir()?;
    let health = setup::agents_health(&home);
    if cli.json {
        let agents: Vec<Value> = health
            .iter()
            .map(|h| {
                serde_json::json!({
                    "name": h.name,
                    "path": h.dir.display().to_string(),
                    "detected": h.detected,
                    "linked": h.linked,
                    "total": h.total,
                })
            })
            .collect();
        print_json(&ok_envelope(None, serde_json::json!({"agents": agents})))?;
    } else {
        for h in &health {
            let status = if h.detected { "detected" } else { "" };
            if verbose || h.detected {
                println!("{}\t{}\t{status}", h.name, h.dir.display());
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_which(cli: &Cli, skills_dir_only: bool) -> anyhow::Result<ExitCode> {
    let home = setup::confidant_home()?;
    let skills_dir = setup::skills_version_dir()?;
    let version = env!("CARGO_PKG_VERSION").to_owned();
    if skills_dir_only && !cli.json {
        println!("{}", skills_dir.display());
        return Ok(ExitCode::SUCCESS);
    }
    if cli.json {
        print_json(&ok_envelope(
            None,
            serde_json::json!({
                "skills_dir": skills_dir.display().to_string(),
                "home": home.display().to_string(),
                "version": version,
            }),
        ))?;
    } else {
        println!("skills_dir={}", skills_dir.display());
        println!("home={}", home.display());
        println!("version={version}");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_routing(cli: &Cli) -> anyhow::Result<ExitCode> {
    if cli.json {
        print_json(&ok_envelope(
            None,
            serde_json::json!({"snippet": setup::ROUTING_SNIPPET}),
        ))?;
    } else {
        print!("{}", setup::ROUTING_SNIPPET);
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
    // Pack skill topics (#189) are served from the embedded pack SKILL.md
    // files, filtered to enabled packs in scope. They need the vault (to
    // resolve enablement) and their own JSON shape, so they run before the
    // generic clap-help paths below.
    if let Some(t) = topic.as_deref() {
        if t == "pack" || t.starts_with("pack:") {
            return cmd_help_pack(cli, vault, t);
        }
    }
    if cli.json {
        // Generated from the live clap definitions, so it cannot drift.
        print_json(&ok_envelope(vault, help_json_value()))?;
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

/// Serve pack skill text (#189): `help pack` prints the combined skill
/// generated from the enabled packs in scope; `help pack:<name>` prints
/// one pack's skill. Only enabled packs are shown, and the `--packs`
/// scope applies (#178): unscoped shows all enabled packs, and naming an
/// unknown or disabled pack is a usage error.
fn cmd_help_pack(cli: &Cli, vault: Option<&Path>, topic: &str) -> anyhow::Result<ExitCode> {
    let root = vault.ok_or_else(|| {
        anyhow::Error::new(
            DomainError::not_found("pack skills need a vault to resolve enabled packs")
                .with_fix("Pass --vault, set CONFIDANT_VAULT, or run inside a vault directory"),
        )
    })?;
    let v = vault_or!(root, cli.json);
    let (_scope, names) =
        resolve_cli_scope(&v, cli.packs.as_deref()).map_err(anyhow::Error::new)?;

    let (packs, text) = match topic.strip_prefix("pack:") {
        Some(name) => {
            if name.is_empty() {
                return Err(anyhow::Error::new(DomainError::usage(
                    "empty pack name: use `help pack:<name>`, e.g. `help pack:coaching@0.1`",
                )));
            }
            if !names.iter().any(|n| n == name) {
                let known = ALL_PACKS.iter().any(|p| p.name() == name);
                return Err(anyhow::Error::new(
                    DomainError::not_found(if known {
                        format!(
                        "pack `{name}` is not enabled in this vault or is outside the --packs scope"
                    )
                    } else {
                        format!("unknown pack `{name}`")
                    })
                    .with_fix("Enable it in confidant.toml `packs = [...]` or widen --packs"),
                ));
            }
            let text = embedded::pack_skill_text(name).ok_or_else(|| {
                anyhow::Error::new(DomainError::internal(format!(
                    "pack `{name}` is enabled but ships no SKILL.md"
                )))
            })?;
            (vec![name.to_owned()], text.to_owned())
        }
        None => {
            debug_assert_eq!(topic, "pack");
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            let text = embedded::combined_pack_skill(&refs).ok_or_else(|| {
                anyhow::Error::new(DomainError::internal("an enabled pack ships no SKILL.md"))
            })?;
            (names.clone(), text)
        }
    };

    if cli.json {
        print_json(&ok_envelope(
            vault,
            serde_json::json!({ "topic": topic, "packs": packs, "skill": text }),
        ))?;
    } else {
        println!("{text}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Test-only operator key override (CONFIDANT_TEST_OPERATOR_KEY).
/// Only compiled with the `test-overrides` feature — never in release
/// builds. Returns None if the env var is unset or empty.
#[cfg(feature = "test-overrides")]
fn test_operator_key() -> Option<ed25519_dalek::SigningKey> {
    let test_key = std::env::var("CONFIDANT_TEST_OPERATOR_KEY").ok()?;
    let trimmed = test_key.trim();
    if trimmed.is_empty() {
        return None;
    }
    let seed = Zeroizing::new(hex::decode(trimmed).ok()?);
    let seed_array: [u8; 32] = seed.as_slice().try_into().ok()?;
    Some(ed25519_dalek::SigningKey::from_bytes(&seed_array))
}

/// `~/.config/confidant`: the operator config dir, where `trust.toml` and
/// the manifest seq tracker live. `None` when `HOME` is unset.
pub(crate) fn confidant_config_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join("confidant"))
}

fn discover(flag: Option<&std::path::Path>) -> Result<(PathBuf, Option<UserConfig>), DomainError> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let user_config = load_user_config(home.as_deref());
    let discovery = Discovery {
        flag: flag.map(PathBuf::from),
        env: std::env::var("CONFIDANT_VAULT").ok(),
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        user_config: user_config.clone(),
    };
    resolve(&discovery).map(|root| (root, user_config))
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

/// Load the operator Ed25519 signing key from the keychain.
fn load_operator_sk(
    _anchor: &confidant_crypt::anchor::Anchor,
) -> anyhow::Result<ed25519_dalek::SigningKey> {
    use confidant_crypt::keychain;
    // Test override (test-overrides feature only): CONFIDANT_TEST_OPERATOR_KEY
    // provides the hex seed directly.
    #[cfg(feature = "test-overrides")]
    if let Some(sk) = test_operator_key() {
        return Ok(sk);
    }
    let seed_bytes = keychain::operator_key().map_err(|_| {
        anyhow::Error::new(DomainError::invalid(
            "no operator key enrolled; run `confidant init` first".to_string(),
        ))
    })?;
    let seed_hex = Zeroizing::new(String::from_utf8_lossy(&seed_bytes).into_owned());
    let seed =
        Zeroizing::new(hex::decode(seed_hex.trim()).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!("bad operator key: {e}")))
        })?);
    let seed_array: [u8; 32] = seed.as_slice().try_into().map_err(|_| {
        anyhow::Error::new(DomainError::invalid("bad operator key length".to_string()))
    })?;
    let seed_array = Zeroizing::new(seed_array);
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed_array))
}

/// Validate a client id at the CLI boundary (B1). Malformed shape is a
/// usage error (exit 2); reserved-id misuse is E_INVALID.
fn validate_keys_client_id(client_id: &str) -> anyhow::Result<()> {
    confidant_crypt::manifest::validate_client_id(client_id).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("reserved") {
            anyhow::Error::new(DomainError::invalid(format!(
                "reserved client id {client_id:?}: {msg}"
            )))
        } else {
            anyhow::Error::new(DomainError::usage(format!("bad client id: {msg}")))
        }
    })
}

/// Load the device identity for `keys` commands (B7). Unkeyed runs fail
/// closed with a message pointing at `init`/`recover`.
pub(crate) fn keys_device_identity() -> anyhow::Result<Box<dyn age::Identity + Send>> {
    let bech32 = device_key_bech32()?;
    let identity: age::x25519::Identity = bech32
        .trim()
        .parse()
        .map_err(|e| anyhow::Error::new(DomainError::invalid(format!("bad device key: {e}"))))?;
    Ok(Box::new(identity))
}

/// Derive the recipient key id for a device from its age pubkey.
///
/// Stable and unique per device: `device-` + 8 chars from the pubkey.
/// Char-based (not byte-indexed) so a short/malformed pubkey cannot panic;
/// callers validate the pubkey parses as an age recipient first.
fn device_key_id(age_pubkey: &str) -> String {
    let suffix: String = age_pubkey.chars().skip(8).take(8).collect();
    format!("device-{suffix}")
}

/// Build the recipient map from the anchor + device keychain for `keys`
/// commands. Currently the only recipient is this device; #66 adds more.
/// Build the recipient map for `keys init-client`: the union of
/// verified recipients from all initialized clients (every enrolled
/// device), so a new client is usable from every device. Falls back to
/// the local device when no client exists yet.
fn keys_current_recipients(
    store: &mut confidant_crypt::lifecycle::KeyStore,
    anchor: &confidant_crypt::anchor::Anchor,
) -> anyhow::Result<confidant_crypt::manifest::RecipientMap> {
    use confidant_crypt::manifest::RecipientEntry;
    let mut map = std::collections::BTreeMap::new();
    for client in store.manifest_clients() {
        let (_, recipients, _) = store
            .verified_recipients(&client, anchor)
            .map_err(anyhow::Error::new)?;
        map.extend(recipients);
    }
    if map.is_empty() {
        // No clients yet: the local device is device-0, matching init.
        let device_bech32 = device_key_bech32()?;
        let device_identity: age::x25519::Identity = device_bech32.trim().parse().map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!("bad device key: {e}")))
        })?;
        let device_recipient = device_identity.to_public().to_string();
        map.insert(
            "device-0".to_string(),
            RecipientEntry {
                age_pubkey: device_recipient,
                label: "device-0".to_string(),
                scope_ref: String::new(),
            },
        );
    }
    Ok(map)
}

/// Test-only keychain directory (with the `test-overrides` feature).
/// When set, the shred device-key rotation reads/writes
/// `$DIR/device.key` (0600) instead of the OS keychain, so the rotation
/// is testable where no Secret Service exists. Never honored in release
/// builds.
#[cfg(feature = "test-overrides")]
fn test_keychain_dir() -> Option<std::path::PathBuf> {
    std::env::var("CONFIDANT_TEST_KEYCHAIN_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(std::path::PathBuf::from)
}

/// Whether a device key is enrolled on this device: the test keychain dir
/// (test builds only, the stand-in for the OS keychain), the OS keychain,
/// or — handled separately by the caller — `CONFIDANT_DEVICE_KEY`.
/// `--initiate` uses this so the test keychain dir counts as enrolled,
/// exactly like the OS keychain.
fn device_key_enrolled() -> anyhow::Result<bool> {
    #[cfg(feature = "test-overrides")]
    if let Some(dir) = test_keychain_dir() {
        return Ok(dir.join("device.key").is_file());
    }
    match confidant_crypt::keychain::device_key() {
        Ok(_) => Ok(true),
        Err(confidant_crypt::error::Error::NoKey(_)) => Ok(false),
        Err(e) => Err(anyhow::Error::new(DomainError::invalid(format!(
            "cannot check device key: {e}"
        )))),
    }
}

/// Keychain backend for this process's key operations: the production OS
/// keychain, or — in test builds with `CONFIDANT_TEST_KEYCHAIN_DIR` — a
/// small file-backed backend so the inbox rotation can be exercised end to
/// end (CI has no Secret Service). Never selected in release builds.
fn keychain_backend() -> Box<dyn confidant_crypt::keychain::KeychainBackend> {
    #[cfg(feature = "test-overrides")]
    if let Some(dir) = test_keychain_dir() {
        return Box::new(FileKeychain::new(dir));
    }
    Box::new(confidant_crypt::keychain::OsKeychain)
}

/// File-backed [`KeychainBackend`] for tests (`test-overrides` only): one
/// file per `service.account`, mode 0600. The device key has its own fixed
/// `device.key` path ([`device_key_bech32`]); this covers the inbox slots
/// the rotation reads and writes.
///
/// [`KeychainBackend`]: confidant_crypt::keychain::KeychainBackend
#[cfg(feature = "test-overrides")]
struct FileKeychain {
    dir: std::path::PathBuf,
}

#[cfg(feature = "test-overrides")]
impl FileKeychain {
    fn new(dir: std::path::PathBuf) -> Self {
        FileKeychain { dir }
    }

    fn path(&self, service: &str, account: &str) -> std::path::PathBuf {
        self.dir.join(format!("{service}.{account}"))
    }
}

#[cfg(feature = "test-overrides")]
impl confidant_crypt::keychain::KeychainBackend for FileKeychain {
    fn get_password(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<Zeroizing<String>>, confidant_crypt::error::Error> {
        match std::fs::read_to_string(self.path(service, account)) {
            Ok(s) => Ok(Some(Zeroizing::new(s))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(confidant_crypt::error::Error::Keychain(format!(
                "cannot read test keychain entry {service}/{account}: {e}"
            ))),
        }
    }

    fn set_password(
        &self,
        service: &str,
        account: &str,
        password: &str,
    ) -> Result<(), confidant_crypt::error::Error> {
        let path = self.path(service, account);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                confidant_crypt::error::Error::Keychain(format!(
                    "cannot create test keychain dir: {e}"
                ))
            })?;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        opts.open(&path)
            .and_then(|mut f| f.write_all(password.as_bytes()))
            .map_err(|e| {
                confidant_crypt::error::Error::Keychain(format!(
                    "cannot write test keychain entry {service}/{account}: {e}"
                ))
            })
    }

    fn delete_credential(
        &self,
        service: &str,
        account: &str,
    ) -> Result<(), confidant_crypt::error::Error> {
        match std::fs::remove_file(self.path(service, account)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(confidant_crypt::error::Error::Keychain(format!(
                "cannot delete test keychain entry {service}/{account}: {e}"
            ))),
        }
    }
}

/// This device's secret key (Bech32): `$DIR/device.key` when
/// `CONFIDANT_TEST_KEYCHAIN_DIR` is set (test builds only), else the OS
/// keychain. Single helper — every `keys` command goes through this so
/// the test dir is never bypassed.
pub(crate) fn device_key_bech32() -> anyhow::Result<Zeroizing<String>> {
    #[cfg(feature = "test-overrides")]
    if let Some(dir) = test_keychain_dir() {
        let path = dir.join("device.key");
        let bech32 = std::fs::read_to_string(&path).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read test device key at {}: {e}",
                path.display()
            )))
        })?;
        return Ok(Zeroizing::new(bech32.trim().to_string()));
    }
    let bytes = confidant_crypt::keychain::device_key().map_err(|_| {
        anyhow::Error::new(DomainError::invalid(
            "no device key enrolled; run `confidant init` (new vault) or `confidant recover` (new device) first".to_string(),
        ))
    })?;
    Ok(Zeroizing::new(
        String::from_utf8_lossy(&bytes).trim().to_owned(),
    ))
}

/// Store the rotated device key: test keychain dir first (test builds
/// only), then the OS keychain.
fn store_rotated_device_key(bech32: &Zeroizing<String>) -> anyhow::Result<()> {
    #[cfg(feature = "test-overrides")]
    if let Some(dir) = test_keychain_dir() {
        let path = dir.join("device.key");
        // 0600; this is the test-only keychain stand-in, so overwrite the
        // test device key outright (create + truncate).
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        let mut f = opts.open(&path).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot write test device key at {}: {e}",
                path.display()
            )))
        })?;
        f.write_all(bech32.as_bytes()).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot write test device key: {e}"
            )))
        })?;
        return Ok(());
    }
    confidant_crypt::keychain::store_device_key(bech32).map_err(anyhow::Error::new)
}

/// Build the recipient set for re-wrapping after shred: a FRESH keypair
/// for this device only, generated in memory. Shred re-wraps to fresh
/// keypairs (the strict pubkey-reuse check in `KeyStore::shred` forbids
/// any historical pubkey): other devices are NOT carried over — they
/// must re-enroll via `keys device-add` (surfaced in the output).
///
/// Returns the fresh private key (Bech32) alongside the recipient map.
/// The caller stores it only AFTER `KeyStore::shred` returns Ok: a
/// refused shred (verify-first) must leave this device's key unchanged.
/// Fails closed when `CONFIDANT_DEVICE_KEY` is set — an env-var key
/// cannot be rotated from here (the new private key would have nowhere
/// to go), so the operator must use the OS keychain for shred.
fn keys_shred_fresh_recipients(
) -> anyhow::Result<(Zeroizing<String>, confidant_crypt::manifest::RecipientMap)> {
    use age::secrecy::ExposeSecret;
    use confidant_crypt::manifest::{RecipientEntry, RecipientMap};
    if let Ok(v) = std::env::var(confidant_crypt::keychain::DEVICE_KEY_ENV) {
        if !v.trim().is_empty() {
            return Err(anyhow::Error::new(DomainError::invalid(
                "shred rotates this device's key, but CONFIDANT_DEVICE_KEY is set so the new key cannot be stored; unset it and enroll via the OS keychain first".to_string(),
            ).with_fix("Unset CONFIDANT_DEVICE_KEY and run `confidant init` or `recover` to enroll this device in the OS keychain, then retry shred")));
        }
    }
    let id = age::x25519::Identity::generate();
    let bech32 = Zeroizing::new(id.to_string().expose_secret().to_owned());
    let recipient = id.to_public().to_string();
    let mut map = RecipientMap::new();
    // One key-id scheme everywhere: the local device is always device-0,
    // matching init.
    map.insert(
        "device-0".to_string(),
        RecipientEntry {
            age_pubkey: recipient,
            label: "device-0".to_string(),
            scope_ref: String::new(),
        },
    );
    Ok((bech32, map))
}

fn cmd_keys_init_client(cli: &Cli, root: &Path, client_id: &str) -> anyhow::Result<ExitCode> {
    use confidant_crypt::anchor;
    validate_keys_client_id(client_id)?;
    // B1: init-client accepts vault:shared (routes to keys/shared/).
    // shred refuses both reserved ids (handled in cmd_keys_shred).

    let config_dir = confidant_config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    let (anchor, _warnings) = anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
    let _identity = keys_device_identity()?;
    let operator_sk = load_operator_sk(&anchor)?;

    let vault = load_vault(root)?;
    // #220: init-client runs against a staged copy of keys/; the
    // pre-commit check runs inside staged_keys_mutation before the swap,
    // so a failure leaves keys/ (and the seq tracker) exactly as they were.
    staged_keys_mutation(root, &vault, &config_dir, |store| {
        let recipients = keys_current_recipients(store, &anchor)?;
        store
            .init_client(client_id, &recipients, &anchor, &operator_sk)
            .map_err(anyhow::Error::new)
    })?;

    // B2: one commit (check already ran before the swap).
    let no_input = cli.no_input;
    stage_keys(root, no_input)?;
    confidant_core::write::git(
        root,
        &["commit", "-m", &format!("keys: init-client {client_id}")],
        no_input,
    )?;

    if cli.json {
        print_json(&serde_json::json!({
            "ok": true,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": root.to_string_lossy(),
            "client_id": client_id,
            "epoch": 1,
        }))?;
    } else {
        println!("initialized client {client_id} (epoch 1)");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_keys_rotate(cli: &Cli, root: &Path, client_id: &str) -> anyhow::Result<ExitCode> {
    use confidant_crypt::anchor;
    validate_keys_client_id(client_id)?;

    let config_dir = confidant_config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    let (anchor, _warnings) = anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
    let _identity = keys_device_identity()?;
    let operator_sk = load_operator_sk(&anchor)?;

    let vault = load_vault(root)?;
    // #220: rotate runs against a staged copy of keys/; the pre-commit
    // check runs inside staged_keys_mutation before the swap, so a
    // failure leaves keys/ (and the seq tracker) exactly as they were.
    let new_epoch = staged_keys_mutation(root, &vault, &config_dir, |store| {
        store
            .rotate(client_id, &anchor, &operator_sk)
            .map_err(anyhow::Error::new)?;
        store.current_epoch(client_id).map_err(anyhow::Error::new)
    })?;

    // B2: one commit (check already ran before the swap).
    let no_input = cli.no_input;
    stage_keys(root, no_input)?;
    confidant_core::write::git(
        root,
        &[
            "commit",
            "-m",
            &format!("keys: rotate {client_id} to epoch {new_epoch}"),
        ],
        no_input,
    )?;

    if cli.json {
        print_json(&serde_json::json!({
            "ok": true,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": root.to_string_lossy(),
            "client_id": client_id,
            "epoch": new_epoch,
        }))?;
    } else {
        println!("rotated client {client_id} to epoch {new_epoch}");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_keys_revoke(
    cli: &Cli,
    root: &Path,
    client_id: &str,
    key_ids: &[String],
) -> anyhow::Result<ExitCode> {
    use confidant_crypt::anchor;
    validate_keys_client_id(client_id)?;

    let config_dir = confidant_config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    let (anchor, _warnings) = anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
    let _identity = keys_device_identity()?;
    let operator_sk = load_operator_sk(&anchor)?;

    let key_id_refs: Vec<&str> = key_ids.iter().map(|s| s.as_str()).collect();
    let vault = load_vault(root)?;
    // #175: revoke runs against a staged copy of keys/; the pre-commit
    // check runs inside staged_keys_mutation before the swap, so a
    // failure leaves keys/ (and the seq tracker) exactly as they were.
    staged_keys_mutation(root, &vault, &config_dir, |store| {
        store
            .revoke(client_id, &key_id_refs, &operator_sk, &anchor)
            .map_err(anyhow::Error::new)
    })?;

    // B2: one commit (check already ran before the swap).
    let no_input = cli.no_input;
    stage_keys(root, no_input)?;
    confidant_core::write::git(
        root,
        &[
            "commit",
            "-m",
            &format!("keys: revoke {} from {client_id}", key_ids.join(",")),
        ],
        no_input,
    )?;

    if cli.json {
        print_json(&serde_json::json!({
            "ok": true,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": root.to_string_lossy(),
            "client_id": client_id,
            "revoked": key_ids,
        }))?;
    } else {
        println!("revoked {} from {client_id}", key_ids.join(", "));
    }
    Ok(ExitCode::SUCCESS)
}

/// Version of the `keys device-add` request document.
const DEVICE_ADD_REQUEST_VERSION: u32 = 1;

/// A `keys device-add` request: public key + label only. The private key
/// never leaves the new device, so this document is safe to transfer by
/// file, paste, or QR (design §6).
#[derive(serde::Serialize, serde::Deserialize)]
struct DeviceAddRequest {
    version: u32,
    pubkey: String,
    label: String,
}

/// `keys device-add --initiate`: run on the new device. Generates the
/// keypair locally, enrolls the device key per the keychain rules, and
/// emits the request (pubkey + label only). Touches nothing else — no
/// vault. The fingerprint goes to stderr so the operator can verify it
/// out of band; the request goes to stdout (or --output).
/// Validate a device-add request label: restrict charset and length, reject
/// control characters (it flows into the commit message, manifest, and
/// stderr — a hand-edited request file must not inject terminal escapes).
/// Used by both `--initiate` and `--from-request`.
fn validate_device_label(raw: &str) -> anyhow::Result<String> {
    // Reject control characters outright (including newlines/ESC) rather
    // than stripping them (#153 nit 6): stripping silently turns a hostile
    // label into a different one, so the operator never learns the request
    // was tampered with.
    if raw.chars().any(|c| c.is_control()) {
        return Err(anyhow::Error::new(DomainError::usage(
            "label must not contain control characters",
        )));
    }
    let cleaned = raw.trim();
    if cleaned.is_empty() {
        return Err(anyhow::Error::new(DomainError::usage(
            "label must not be empty",
        )));
    }
    if cleaned.len() > 64 {
        return Err(anyhow::Error::new(DomainError::usage(
            "label must be at most 64 characters",
        )));
    }
    // ASCII only (#153 nit 6): labels travel into commit messages and the
    // manifest, so keep them to a predictable, terminal-safe set.
    if !cleaned
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || " -_.()".contains(c))
    {
        return Err(anyhow::Error::new(DomainError::usage(
            "label may contain only ASCII letters, numbers, spaces, and -_.()",
        )));
    }
    Ok(cleaned.to_string())
}

fn cmd_keys_device_add_initiate(
    cli: &Cli,
    label: Option<&str>,
    output: Option<&Path>,
    force: bool,
) -> anyhow::Result<ExitCode> {
    // Refuse to overwrite an already-enrolled device key (same check as
    // recover's B13): running --initiate on an enrolled device would
    // replace its keychain entry and lock it out. --force overrides the
    // refusal, but not the confirmation below.
    use confidant_crypt::keychain;
    // Check via the keychain directly (not the env override): if a
    // device key is enrolled, refuse.
    let enrolled = device_key_enrolled()?;
    // Also check the env var (headless/test): if set, a key is enrolled.
    let env_enrolled = std::env::var(keychain::DEVICE_KEY_ENV)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let already_enrolled = enrolled || env_enrolled;
    // #153 nit 4: with CONFIDANT_DEVICE_KEY set, `--initiate` cannot
    // generate a fresh keypair — `provision_device_key()` would re-emit the
    // env key, and the enrolled device later refuses that pubkey as
    // already-seen. Fail closed up front, like shred does.
    if env_enrolled {
        return Err(anyhow::Error::new(
            DomainError::invalid(
                "cannot --initiate a fresh device key while CONFIDANT_DEVICE_KEY is set \
                 (the request would re-emit the enrolled key)",
            )
            .with_fix(
                "Unset CONFIDANT_DEVICE_KEY and enroll this device's key in the OS keychain \
                 (run `confidant recover` on a new device), then retry `keys device-add --initiate`",
            ),
        ));
    }
    if already_enrolled && !force {
        return Err(anyhow::Error::new(DomainError::invalid(
            "a device key is already enrolled; refusing to overwrite (use --force to replace it)",
        )));
    }
    // Item 5: --force on --initiate replaces the enrolled device key.
    // Confirm interactively unless --no-input, and say plainly that the
    // old key's access from this device is lost — worded for the
    // re-enroll-after-shred case, the main reason to reach for --force.
    if already_enrolled && force && !cli.no_input {
        eprintln!("WARNING: a device key is already enrolled on this device.");
        eprintln!("--force will replace it: the old key will no longer work from here.");
        eprintln!(
            "After a `keys shred` dropped this device, re-enrolling with a fresh key is \
             how it rejoins; the shredded client's history stays unopenable by the old key."
        );
        eprint!("Replace the enrolled device key? [y/N] ");
        use std::io::Write;
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            return Err(anyhow::Error::new(DomainError::invalid(
                "device key replacement not confirmed; refusing",
            )));
        }
    }

    // Item 6: validate the label BEFORE provisioning the key. A bad label
    // must not store a key and then error — the retry would need --force
    // to clean up the mess.
    // (Shared validator with --from-request: a hand-edited request can
    // inject controls into the commit message/manifest/stderr.)
    let label = validate_device_label(label.unwrap_or("device"))?;
    let (_bech32, recipient) = provision_device_key()?;
    let fingerprint = confidant_crypt::keychain::pubkey_fingerprint(&recipient);
    let key_id = device_key_id(&recipient);

    let request = DeviceAddRequest {
        version: DEVICE_ADD_REQUEST_VERSION,
        pubkey: recipient.clone(),
        label: label.clone(),
    };
    let toml_body = toml::to_string(&request).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot serialize device-add request: {e}"
        )))
    })?;
    let document =
        format!("# confidant device-add request — public key only, safe to transfer\n{toml_body}");

    // Fingerprint on stderr (human channel), always — it is what the
    // operator compares against on the enrolled device.
    eprintln!("new device key fingerprint: {fingerprint}");
    eprintln!(
        "show this fingerprint on the enrolled device and confirm it matches before approving"
    );

    if cli.json {
        print_json(&serde_json::json!({
            "ok": true,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": null,
            "fingerprint": fingerprint,
            "label": label,
            "key_id": key_id,
            "pubkey": recipient,
            "request": document,
        }))?;
    } else if let Some(path) = output {
        // 0644 explicit: the request carries only the public key + label,
        // safe to transfer. Deliberate, not a default.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(path)
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(document.as_bytes())
                })
                .map_err(|e| {
                    anyhow::Error::new(DomainError::invalid(format!(
                        "cannot write device-add request to {}: {e}",
                        path.display()
                    )))
                })?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, &document).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot write device-add request to {}: {e}",
                    path.display()
                )))
            })?;
        }
        eprintln!("wrote device-add request to {}", path.display());
    } else {
        print!("{document}");
    }
    Ok(ExitCode::SUCCESS)
}

/// `keys device-add --from-request <file>`: run on an already-enrolled
/// device. Verifies the fingerprint out of band, re-wraps every client's
/// every retained epoch plus the vault lookup key to the new device, and
/// commits (one commit, check first, signed by the operator key).
fn cmd_keys_device_add_from_request(
    cli: &Cli,
    root: &Path,
    from_request: Option<&Path>,
    fingerprint_verified: bool,
) -> anyhow::Result<ExitCode> {
    use confidant_crypt::{anchor, manifest::RecipientEntry};

    // B6: exactly one mode; --from-request is required here.
    let request_path = from_request.ok_or_else(|| {
        anyhow::Error::new(DomainError::usage(
            "keys device-add needs exactly one of --initiate or --from-request <file>",
        ))
    })?;

    // Parse the request. Anything malformed is E_INVALID-class: fail
    // closed, nothing mutated (B6).
    let raw = std::fs::read_to_string(request_path).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read device-add request {}: {e}",
            request_path.display()
        )))
    })?;
    let request: DeviceAddRequest = toml::from_str(&raw).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "malformed device-add request {}: {e}",
            request_path.display()
        )))
    })?;
    if request.version != DEVICE_ADD_REQUEST_VERSION {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "unsupported device-add request version {} (want {})",
            request.version, DEVICE_ADD_REQUEST_VERSION
        ))));
    }
    request
        .pubkey
        .parse::<age::x25519::Recipient>()
        .map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "device-add request has a bad pubkey: {e}"
            )))
        })?;
    let key_id = device_key_id(&request.pubkey);
    let fingerprint = confidant_crypt::keychain::pubkey_fingerprint(&request.pubkey);
    // Validate the label too: the request file is hand-editable, and the
    // label flows into the commit message, manifest, and stderr.
    // Malformed labels are E_INVALID-class (B6): fail closed.
    let label = validate_device_label(&request.label).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "device-add request has a bad label: {e}"
        )))
    })?;

    // Fingerprint verification is mandatory (design §7): the operator
    // must confirm the fingerprint matches what the new device showed.
    // No silent trust of a transferred file.
    if cli.no_input {
        if !fingerprint_verified {
            return Err(anyhow::Error::new(DomainError::usage(
                "--from-request with --no-input requires --fingerprint-verified: \
                 verify the request fingerprint out of band first",
            )));
        }
    } else {
        eprintln!("new device request:");
        eprintln!("  label:       {label}");
        eprintln!("  pubkey:      {}", request.pubkey);
        eprintln!("  fingerprint: {fingerprint}");
        eprint!("Does this fingerprint match the one shown on the new device? [y/N] ");
        use std::io::Write;
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            return Err(anyhow::Error::new(DomainError::invalid(
                "fingerprint not confirmed; refusing to add the device",
            )));
        }
    }

    let config_dir = confidant_config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    let (anchor, _warnings) = anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
    let identity = keys_device_identity()?;
    let operator_sk = load_operator_sk(&anchor)?;

    let vault = load_vault(root)?;
    // #175: device-add runs against a staged copy of keys/; the
    // pre-commit check runs inside staged_keys_mutation before the swap,
    // so a failure leaves keys/ (and the seq tracker) exactly as they
    // were. No more "restore with git checkout -- keys/" recovery hints.
    let clients = staged_keys_mutation(root, &vault, &config_dir, |store| {
        // #154 must-fix 4: the retired-recovery / shredded-client
        // denylist is load-bearing here, so fail closed rather than warn
        // when history is unreadable (shallow clone, missing git, git log
        // failure).
        if let Some(reason) = store.history_degraded_reason() {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "refusing device-add: {reason}; the retired-recipient denylist would be \
                 incomplete and could re-open a shredded client"
            ))));
        }
        let entry = RecipientEntry {
            age_pubkey: request.pubkey.clone(),
            label: label.clone(),
            scope_ref: String::new(),
        };
        // B2: every initialized client's every retained epoch + the
        // lookup key, all through KeyStore; verify-first inside
        // add_recipient.
        store
            .add_recipient(&key_id, &entry, identity.as_ref(), &anchor, &operator_sk)
            .map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "device-add failed; keys/ was not modified (nothing was committed): {e}"
                )))
            })
    })?;

    // One commit, signed by the operator key (design §6). Check already
    // ran inside staged_keys_mutation, before the swap.
    let no_input = cli.no_input;
    stage_keys(root, no_input)?;
    confidant_core::write::git(
        root,
        &[
            "commit",
            "-m",
            &format!("keys: device-add {key_id} ({label})"),
        ],
        no_input,
    )?;

    if cli.json {
        print_json(&serde_json::json!({
            "ok": true,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": root.to_string_lossy(),
            "fingerprint": fingerprint,
            "label": label,
            "key_id": key_id,
            "clients": clients,
            "client_count": clients.len(),
        }))?;
    } else {
        println!(
            "added device {key_id} ({label}) to {} client(s)",
            clients.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Staging paths for the atomic `keys/` swap (#175). All scratch lives
/// under the git-ignored `.confidant/` dir (keys staging) or the config
/// dir (seq-tracker staging), so a leftover is never committed and never
/// mistaken for vault content.
fn keys_stage_dir(root: &Path) -> PathBuf {
    root.join(".confidant").join("keys.stage")
}

fn keys_old_dir(root: &Path) -> PathBuf {
    root.join(".confidant").join("keys.old")
}

/// Staged copy of the seq tracker: same directory as the real tracker,
/// so the success-path rename is atomic (same filesystem). The staged
/// tracker holds the marks for ALL vaults (copied through), not just
/// this one.
fn keys_staged_tracker_path(config_dir: &Path) -> PathBuf {
    config_dir.join("manifest-seq.stage.toml")
}

/// Remove a file or directory, best-effort. Used for staging cleanup,
/// where a leftover is repaired on the next run anyway.
fn remove_path_best_effort(path: &Path) {
    if path.is_dir() {
        let _ = std::fs::remove_dir_all(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

/// Copy a directory tree: files via `fs::copy`, subdirectories
/// recursively. Symlinks are refused (keys/ is CLI-managed and must not
/// contain them) — fail closed rather than follow or silently drop one.
fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &target)?;
        } else {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "unexpected symlink in keys/ tree at {}",
                entry.path().display()
            ))));
        }
    }
    Ok(())
}

/// Durable marker for a keys shred operation that finished staging and
/// check. See issue 220 and Frank's roll-forward decision on issue 290.
///
/// Written inside the stage dir after `check` passes; after the swap it
/// lives in `keys/` (the stage was renamed there). Presence means "roll
/// forward, never back": the swap and the out-of-tree promotions (anchor
/// re-pin, device key) must complete before any other key operation runs.
///
/// The marker carries the new anchor material and the new device private key
/// so `repair_keys_staging` can finish the promotions after a crash. It is
/// written with 0600 permissions under git-ignored `.confidant/` (pre-swap)
/// and removed before the shred commit (post-swap), so it is never committed.
/// Rolling back after a crash would restore the destroyed keys and undo the
/// shred — hence roll-forward.
const SHRED_MARKER_FILE: &str = ".confidant-shred-marker.toml";
const SHRED_MARKER_VERSION: u32 = 1;

#[derive(serde::Serialize, serde::Deserialize)]
struct ShredStageMarker {
    version: u32,
    /// New recovery verifying key (hex) for the anchor re-pin.
    recovery_verifying_key_hex: String,
    /// New recovery age recipient for the anchor re-pin.
    recovery_age_recipient: String,
    /// Fresh device private key (bech32) to promote to the keychain.
    /// Sensitive: 0600 file, git-ignored, removed before commit.
    device_key_bech32: String,
    /// Whether the new recovery phrase was shown to the operator.
    /// If a crash happened before display, the operator never got the
    /// phrase; the success output must not claim otherwise.
    phrase_displayed: bool,
}

fn shred_marker_in_stage(stage: &Path) -> PathBuf {
    stage.join(SHRED_MARKER_FILE)
}

fn shred_marker_in_keys(keys_dir: &Path) -> PathBuf {
    keys_dir.join(SHRED_MARKER_FILE)
}

/// Write the shred marker with 0600 permissions (it holds a private key).
fn write_shred_marker(path: &Path, marker: &ShredStageMarker) -> anyhow::Result<()> {
    let text = toml::to_string(marker).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot serialize shred marker: {e}"
        )))
    })?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let mut f = opts.open(path).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot write shred marker at {}: {e}",
            path.display()
        )))
    })?;
    f.write_all(text.as_bytes()).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot write shred marker: {e}"
        )))
    })?;
    Ok(())
}

fn read_shred_marker(path: &Path) -> anyhow::Result<ShredStageMarker> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read shred marker at {}: {e}",
            path.display()
        )))
    })?;
    let marker: ShredStageMarker = toml::from_str(&text)
        .map_err(|e| anyhow::Error::new(DomainError::invalid(format!("bad shred marker: {e}"))))?;
    if marker.version != SHRED_MARKER_VERSION {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "unsupported shred marker version {}",
            marker.version
        ))));
    }
    Ok(marker)
}

/// Repair leftover staging state from a crashed or failed keys operation
/// (#175). Runs before every staged keys mutation. The swap order makes
/// every window unambiguous:
///
/// - `keys.old` + `keys/` both present: the swap completed, `keys/` is the
///   new tree — delete the old tree.
/// - `keys.old` present + `keys/` missing: crash mid-swap, before the
///   stage was renamed in — restore the old tree.
/// - No `keys.old`: any stage / staged tracker is a leftover from a
///   failed op (keys/ was never touched) — delete it.
/// - `keys/` missing + stage present + no `keys.old`: inconsistent (the
///   copy never deletes keys/) — refuse to guess.
///
/// A shred marker (`#220`) takes precedence over all of the above: it
/// means the stage passed `check` and the operation must roll forward.
fn repair_keys_staging(root: &Path, config_dir: &Path) -> anyhow::Result<()> {
    let keys_dir = root.join("keys");
    let old = keys_old_dir(root);
    let stage = keys_stage_dir(root);
    let staged_tracker = keys_staged_tracker_path(config_dir);
    // #220: shred roll-forward marker. A marker means the stage passed
    // `check`; the shred must roll forward to completion (swap, re-pin,
    // device-key promotion), never roll back — rolling back would restore
    // the destroyed keys and undo the shred.
    if shred_marker_in_stage(&stage).exists() || shred_marker_in_keys(&keys_dir).exists() {
        return repair_shred_marker(root, config_dir);
    }
    if old.exists() {
        if keys_dir.exists() {
            remove_path_best_effort(&old);
        } else {
            std::fs::rename(&old, &keys_dir)?;
            remove_path_best_effort(&stage);
            remove_path_best_effort(&staged_tracker);
            return Ok(());
        }
    } else if !keys_dir.exists() && stage.exists() {
        return Err(anyhow::Error::new(DomainError::invalid(
            "keys/ is missing but a staging copy exists with no backup; refusing to guess which tree is canonical — inspect .confidant/keys.stage/ and restore keys/ by hand",
        )));
    }
    remove_path_best_effort(&stage);
    remove_path_best_effort(&staged_tracker);
    Ok(())
}

/// Roll a crashed `keys shred` forward from its durable marker (#220).
/// The marker is in the stage dir (pre-swap crash) or in `keys/` (the
/// stage was renamed there by the swap). Every step is idempotent, so a
/// second crash mid-repair is safe to retry.
///
/// Crash-point behavior (Frank's decision on #290):
/// - Marker in stage, no swap yet: finish the swap, then re-pin, then
///   clear the marker.
/// - Marker in `keys/`: the swap is done; finish the re-pin and the
///   device-key promotion from the marker's material, then clear it.
/// - Mid-swap (`keys/` missing, `keys.old` present): complete the swap
///   first, then proceed as above.
fn repair_shred_marker(root: &Path, config_dir: &Path) -> anyhow::Result<()> {
    use confidant_crypt::anchor;
    let keys_dir = root.join("keys");
    let old = keys_old_dir(root);
    let stage = keys_stage_dir(root);
    let staged_tracker = keys_staged_tracker_path(config_dir);
    let real_tracker = confidant_crypt::manifest::seq_tracker_path(config_dir);
    let marker_in_stage = shred_marker_in_stage(&stage);
    let marker_in_keys = shred_marker_in_keys(&keys_dir);

    // Load the marker from wherever it is (stage pre-swap, keys/ post-swap).
    let marker_in_stage_exists = marker_in_stage.exists();
    let marker_path = if marker_in_stage_exists {
        marker_in_stage.clone()
    } else {
        marker_in_keys.clone()
    };
    let marker = read_shred_marker(&marker_path)?;

    // Ensure the swap is complete.
    if marker_in_stage_exists {
        // Pre-swap crash (or mid-swap): the new tree is still in the stage.
        if keys_dir.exists() {
            // Pre-swap: keys/ holds the old tree. Do the swap now.
            std::fs::rename(&keys_dir, &old).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot stage old keys/ aside during shred repair: {e}"
                )))
            })?;
            std::fs::rename(&stage, &keys_dir).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot complete interrupted keys/ swap during shred repair: {e}"
                )))
            })?;
        } else if old.exists() {
            // Mid-swap: keys/ -> keys.old happened, stage -> keys/ did not.
            // Complete the swap.
            std::fs::rename(&stage, &keys_dir).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot complete interrupted keys/ swap during shred repair: {e}"
                )))
            })?;
        } else if stage.exists() {
            // keys/ missing with no backup but the stage exists: the
            // pre-swap rename of keys/ -> keys.old never happened. Move the
            // stage into place directly.
            std::fs::rename(&stage, &keys_dir).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot complete interrupted keys/ swap during shred repair: {e}"
                )))
            })?;
        } else {
            // Marker was in the stage, but the stage is gone and keys/
            // is missing. Fail closed rather than guess.
            return Err(anyhow::Error::new(DomainError::invalid(
                "shred marker was in the stage, but both the stage and keys/ are missing; refusing to guess — inspect .confidant/ and restore by hand",
            )));
        }
    } else if !keys_dir.exists() {
        // Marker in keys/ but keys/ is missing: the swap moved the marker
        // but keys/ vanished afterwards. Fail closed.
        return Err(anyhow::Error::new(DomainError::invalid(
            "shred marker exists but keys/ is missing; refusing to guess — inspect .confidant/ and restore by hand",
        )));
    }
    // keys/ now holds the new tree (marker inside it).
    // The old tree is shred's destroy target; remove it best-effort.
    remove_path_best_effort(&old);

    // Promote the staged seq tracker (same-directory rename, atomic).
    if staged_tracker.exists() {
        std::fs::rename(&staged_tracker, &real_tracker).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot promote staged seq tracker during shred repair: {e}"
            )))
        })?;
    }

    // Re-pin the trust anchor from the marker's material (idempotent:
    // temp-and-rename with the same bytes is a no-op in effect).
    let (anchor, _warnings) = anchor::load(config_dir, root).map_err(anyhow::Error::new)?;
    let recovery_vk_bytes = hex::decode(&marker.recovery_verifying_key_hex).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "bad recovery key in shred marker: {e}"
        )))
    })?;
    let recovery_vk =
        ed25519_dalek::VerifyingKey::from_bytes(&recovery_vk_bytes.try_into().map_err(|_| {
            anyhow::Error::new(DomainError::invalid(
                "bad recovery key length in shred marker",
            ))
        })?)
        .map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "bad recovery key in shred marker: {e}"
            )))
        })?;
    anchor::replace(
        config_dir,
        root,
        &anchor.operator,
        &recovery_vk,
        &marker.recovery_age_recipient,
    )
    .map_err(anyhow::Error::new)?;

    // Promote the fresh device key from the marker (idempotent: overwrites
    // the keychain entry with the same bytes).
    store_rotated_device_key(&zeroize::Zeroizing::new(marker.device_key_bech32.clone())).map_err(
        |e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot promote device key during shred repair: {e}"
            )))
        },
    )?;

    // All promotions done: clear the marker. It lives in keys/ now (the
    // stage was renamed there); it must never be committed.
    let marker_in_keys = shred_marker_in_keys(&keys_dir);
    if marker_in_keys.exists() {
        std::fs::remove_file(&marker_in_keys).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot clear shred marker at {}: {e}",
                marker_in_keys.display()
            )))
        })?;
    }
    Ok(())
}

/// Run a `keys shred` through the staged path with roll-forward (#220,
/// Frank's decision on #290). Operation order:
/// 1. Stage `keys/` and mutate the copy (re-wrap remaining clients to
///    fresh recipients, rotate recovery wrapping, re-sign operator cert
///    into the stage).
/// 2. Run `check` on the staged tree.
/// 3. Record a durable marker inside the stage dir (complete + checked,
///    with the new anchor material and the new device key).
/// 4. Atomically swap the staged `keys/` into place.
/// 5. Re-pin the trust anchor and promote the device key from the marker.
/// 6. Remove the marker.
///
/// Why roll forward: shred exists to destroy the old keys; rolling back
/// after a crash would restore them and undo the shred. The marker makes
/// every crash point recoverable via `repair_keys_staging`.
///
/// The recovery phrase is displayed BEFORE the swap (step 3.5): once the
/// swap lands, the tree is wrapped to that phrase, so a crash before
/// display would lose it. The success output confirms the phrase.
#[allow(clippy::too_many_arguments)]
fn staged_shred_mutation(
    root: &Path,
    vault: &confidant_core::Vault,
    config_dir: &Path,
    anchor: &confidant_crypt::anchor::Anchor,
    operator_sk: &ed25519_dalek::SigningKey,
    identity: &dyn age::Identity,
    client_id: &str,
    all_refs: &[&str],
    new_recipients: &confidant_crypt::manifest::RecipientMap,
    fresh_device_key: &zeroize::Zeroizing<String>,
    deleted_edges: usize,
    stripped_interactions: usize,
    no_input: bool,
) -> anyhow::Result<confidant_crypt::lifecycle::ShredOutcome> {
    use confidant_crypt::{
        anchor,
        lifecycle::KeyStore,
        manifest::{self, SeqTracker},
    };
    repair_keys_staging(root, config_dir)?;
    let keys_dir = root.join("keys");
    let stage = keys_stage_dir(root);
    let old = keys_old_dir(root);
    let staged_tracker = keys_staged_tracker_path(config_dir);
    let real_tracker = manifest::seq_tracker_path(config_dir);

    // Step 1: stage the tree and the seq tracker (same as staged_keys_mutation).
    let mut store = match (|| -> anyhow::Result<KeyStore> {
        if keys_dir.exists() {
            copy_dir_recursive(&keys_dir, &stage)?;
        } else {
            std::fs::create_dir_all(&stage)?;
        }
        if real_tracker.exists() {
            std::fs::copy(&real_tracker, &staged_tracker)?;
        }
        let seq = SeqTracker::load(&staged_tracker).map_err(anyhow::Error::new)?;
        Ok(KeyStore::new(stage.clone(), &vault.config.vault_id, seq)
            .with_committed_keys_dir(keys_dir.clone()))
    })() {
        Ok(s) => s,
        Err(e) => {
            remove_path_best_effort(&stage);
            remove_path_best_effort(&staged_tracker);
            return Err(e);
        }
    };

    // Mutate the stage: re-wrap remaining clients, rotate recovery.
    // On failure the stage is discarded; keys/ and the anchor untouched.
    let outcome = match store.shred(
        client_id,
        all_refs,
        new_recipients,
        operator_sk,
        anchor,
        identity,
        deleted_edges,
        stripped_interactions,
    ) {
        Ok(o) => o,
        Err(e) => {
            remove_path_best_effort(&stage);
            remove_path_best_effort(&staged_tracker);
            return Err(anyhow::Error::new(e));
        }
    };

    // Re-sign the operator cert into the STAGE (not the live keys_dir):
    // it was signed by the OLD recovery key, and the new tree must carry
    // a cert the NEW recovery key verifies.
    let new_recovery = outcome.new_recovery();
    if let Err(e) = anchor::write_operator_cert(
        &stage,
        &vault.config.vault_id,
        &anchor.operator,
        new_recovery.signing_key(),
    ) {
        remove_path_best_effort(&stage);
        remove_path_best_effort(&staged_tracker);
        return Err(anyhow::Error::new(e));
    }

    // Step 2: check before the swap. (See the #209 note in
    // staged_keys_mutation: check reads keys/ only for crypto-mode
    // detection, so the pre-loaded vault view is equivalent.)
    let pre = check_vault(vault, &CheckOptions::default());
    if !pre.ok {
        remove_path_best_effort(&stage);
        remove_path_best_effort(&staged_tracker);
        return Err(anyhow::Error::new(DomainError::invalid(
            "check failed before committing keys/ tree; nothing was committed and keys/ was not modified",
        )));
    }

    // Step 3: durable marker (complete + checked), with the new anchor
    // material and the new device key for the post-swap promotions.
    let hex = |k: &[u8]| k.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let marker = ShredStageMarker {
        version: SHRED_MARKER_VERSION,
        recovery_verifying_key_hex: hex(new_recovery.verifying_key().as_bytes()),
        recovery_age_recipient: new_recovery.age_identity().to_recipient_string(),
        device_key_bech32: fresh_device_key.as_str().to_owned(),
        phrase_displayed: false,
    };
    let marker_path = shred_marker_in_stage(&stage);
    if let Err(e) = write_shred_marker(&marker_path, &marker) {
        remove_path_best_effort(&stage);
        remove_path_best_effort(&staged_tracker);
        return Err(e);
    }

    // Step 3.5: show the phrase BEFORE the swap. Once the swap lands the
    // tree is wrapped to this phrase; a crash before display would lose it.
    let phrase = outcome.recovery_phrase_for_display();
    if let Err(e) = display_phrase_once(no_input, &phrase) {
        remove_path_best_effort(&stage);
        remove_path_best_effort(&staged_tracker);
        remove_path_best_effort(&marker_path);
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "cannot display recovery phrase: {e}"
        ))));
    }
    let marker = ShredStageMarker {
        phrase_displayed: true,
        ..marker
    };
    if let Err(e) = write_shred_marker(&marker_path, &marker) {
        remove_path_best_effort(&stage);
        remove_path_best_effort(&staged_tracker);
        return Err(e);
    }

    // Step 4: swap (keys/ -> keys.old, stage -> keys/).
    if keys_dir.exists() {
        if let Err(e) = std::fs::rename(&keys_dir, &old) {
            remove_path_best_effort(&stage);
            remove_path_best_effort(&staged_tracker);
            remove_path_best_effort(&marker_path);
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "keys/ swap failed before anything moved ({e}); keys/ was not modified"
            ))));
        }
    }
    if let Err(e) = std::fs::rename(&stage, &keys_dir) {
        let _ = repair_keys_staging(root, config_dir);
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "keys/ swap failed mid-swap ({e}); staging leftovers were repaired"
        ))));
    }
    // The marker is now in keys/; it must be removed before commit.

    // Promote the staged seq tracker (same-directory rename, atomic).
    if staged_tracker.exists() {
        if let Err(e) = std::fs::rename(&staged_tracker, &real_tracker) {
            let _ = repair_keys_staging(root, config_dir);
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "seq tracker promotion failed ({e}); staging leftovers were repaired"
            ))));
        }
    }

    // Step 5: re-pin the anchor and promote the device key from the marker.
    // Both are idempotent, so a crash here is safe to retry via repair.
    if let Err(e) = anchor::replace(
        config_dir,
        root,
        &anchor.operator,
        &new_recovery.verifying_key(),
        &new_recovery.age_identity().to_recipient_string(),
    ) {
        let _ = repair_keys_staging(root, config_dir);
        return Err(anyhow::Error::new(e));
    }
    if let Err(e) = store_rotated_device_key(fresh_device_key) {
        let _ = repair_keys_staging(root, config_dir);
        return Err(e);
    }

    // Step 6: remove the marker (in keys/ now). It must never be committed.
    let marker_in_keys = shred_marker_in_keys(&keys_dir);
    if marker_in_keys.exists() {
        if let Err(e) = std::fs::remove_file(&marker_in_keys) {
            let _ = repair_keys_staging(root, config_dir);
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "cannot clear shred marker at {}: {e}",
                marker_in_keys.display()
            ))));
        }
    }

    // Cleanup of the old tree is best-effort; the next run repairs a leftover.
    remove_path_best_effort(&old);
    Ok(outcome)
}

/// Run a `keys/` mutation atomically (#175): stage the tree aside,
/// mutate the stage, check, then swap the stage into place. A failure
/// at any point before the swap leaves `keys/` (and the seq tracker)
/// exactly as they were; on failure only the staging copies are deleted.
///
/// The staged `KeyStore` reads git history from the COMMITTED tree
/// (`with_committed_keys_dir`), so the shredded-pubkey denylist sees the
/// same history as the unstaged path.
///
/// Ordering matters: the keys swap runs BEFORE the tracker rename. A
/// crash between them leaves the new tree with the old tracker, which is
/// consistent (manifest seqs are >= the old high-water marks, so the
/// next operation just picks higher seqs). The reverse order would leave
/// the old tree with a new tracker, and verification would refuse the
/// old manifests as stale.
///
/// `vault` is the already-loaded vault: `check` runs against it before
/// the swap. Check never reads `keys/` contents (only whether the tree
/// exists), so no vault view over the stage is needed.
fn staged_keys_mutation<T>(
    root: &Path,
    vault: &confidant_core::Vault,
    config_dir: &Path,
    mutate: impl FnOnce(&mut confidant_crypt::lifecycle::KeyStore) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    use confidant_crypt::{
        lifecycle::KeyStore,
        manifest::{self, SeqTracker},
    };
    repair_keys_staging(root, config_dir)?;
    let keys_dir = root.join("keys");
    let stage = keys_stage_dir(root);
    let old = keys_old_dir(root);
    let staged_tracker = keys_staged_tracker_path(config_dir);
    let real_tracker = manifest::seq_tracker_path(config_dir);

    // Stage the tree (full copy, including any uncommitted operator work)
    // and the seq tracker. The tracker is staged in the config dir so
    // the success-path rename is atomic. Any failure here cleans up the
    // partial stage, so a failed setup leaves no leftovers.
    let mut store = match (|| -> anyhow::Result<KeyStore> {
        if keys_dir.exists() {
            copy_dir_recursive(&keys_dir, &stage)?;
        } else {
            std::fs::create_dir_all(&stage)?;
        }
        if real_tracker.exists() {
            std::fs::copy(&real_tracker, &staged_tracker)?;
        }
        let seq = SeqTracker::load(&staged_tracker).map_err(anyhow::Error::new)?;
        Ok(KeyStore::new(stage.clone(), &vault.config.vault_id, seq)
            .with_committed_keys_dir(keys_dir.clone()))
    })() {
        Ok(s) => s,
        Err(e) => {
            remove_path_best_effort(&stage);
            remove_path_best_effort(&staged_tracker);
            return Err(e);
        }
    };

    // Mutate the stage. On failure the stage + staged tracker are deleted
    // and keys/ + the real tracker are untouched.
    let result = match mutate(&mut store) {
        Ok(v) => v,
        Err(e) => {
            remove_path_best_effort(&stage);
            remove_path_best_effort(&staged_tracker);
            return Err(e);
        }
    };

    // Pre-commit check before the swap, so a failing check also leaves
    // keys/ untouched.
    //
    // #209: this check runs against the pre-loaded `vault`, which reflects
    // the LIVE keys/ tree, not the staged copy. That is correct today
    // because `check` reads keys/ only for crypto-mode detection — whether
    // keys/ *exists* (`crypto_mode::is_structurally_encrypted`), which a
    // staged swap never changes (it replaces keys/ contents, not its
    // presence). If `check` ever starts reading the *contents* of keys/
    // (manifests, the seq tracker, wrapping files), it must be re-pointed
    // at the staged tree here so a bad staged tree fails the check before
    // the swap. Do not "fix" this today by making `check` read the stage:
    // there is nothing for it to read there yet.
    let pre = check_vault(vault, &CheckOptions::default());
    if !pre.ok {
        remove_path_best_effort(&stage);
        remove_path_best_effort(&staged_tracker);
        return Err(anyhow::Error::new(DomainError::invalid(
            "check failed before committing keys/ tree; nothing was committed and keys/ was not modified",
        )));
    }

    // Swap: keys/ -> keys.old, stage -> keys/.
    if keys_dir.exists() {
        if let Err(e) = std::fs::rename(&keys_dir, &old) {
            remove_path_best_effort(&stage);
            remove_path_best_effort(&staged_tracker);
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "keys/ swap failed before anything moved ({e}); keys/ was not modified"
            ))));
        }
    }
    if let Err(e) = std::fs::rename(&stage, &keys_dir) {
        // Mid-swap: repair restores keys.old -> keys/.
        let _ = repair_keys_staging(root, config_dir);
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "keys/ swap failed mid-swap ({e}); staging leftovers were repaired, keys/ was restored"
        ))));
    }

    // Tracker rename (same directory, atomic). Keys-swap-first: new tree +
    // old tracker is consistent (and self-healing — the next operation
    // re-derives high-water marks from the manifests), so even a failure
    // here cannot brick the vault. Best-effort rollback, then repair.
    if staged_tracker.exists() {
        if let Err(e) = std::fs::rename(&staged_tracker, &real_tracker) {
            remove_path_best_effort(&keys_dir);
            if std::fs::rename(&old, &keys_dir).is_ok() {
                remove_path_best_effort(&staged_tracker);
            }
            let _ = repair_keys_staging(root, config_dir);
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "seq tracker update failed ({e}); keys/ was rolled back and nothing was committed"
            ))));
        }
    }

    // Cleanup of the old tree is best-effort; the next run repairs a leftover.
    remove_path_best_effort(&old);
    Ok(result)
}

/// Remove leftover `keys/.confidant-tmp-*` files from a crashed atomic
/// write, then stage the `keys/` tree. The recovery-recipients denylist is
/// written via temp-and-rename; a hard crash can leave the temp behind, and
/// a bare `git add -- keys` would commit it (#156 nit 1).
fn stage_keys(root: &Path, no_input: bool) -> anyhow::Result<()> {
    let keys_dir = root.join("keys");
    if let Ok(entries) = std::fs::read_dir(&keys_dir) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(".confidant-tmp-")
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    confidant_core::write::git(root, &["add", "--", "keys"], no_input)?;
    Ok(())
}

/// Path to the pending inbox-rotation reminder file (#105, ⚠5).
fn pending_inbox_rotation_path() -> anyhow::Result<std::path::PathBuf> {
    let config_dir = confidant_config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    Ok(config_dir.join("inbox-rotation-pending.toml"))
}

/// Write the pending-rotation reminder (device-local, never in the vault).
fn write_pending_inbox_rotation(vault_id: &str, shredded_client: &str) -> anyhow::Result<()> {
    let path = pending_inbox_rotation_path()?;
    let recorded_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let content = format!(
        "# Inbox rotation pending after `keys shred {shredded_client}`.\n\
         # The inbox key was NOT rotated on this device (it does not hold the inbox key).\n\
         # Run `confidant inbox rotate --finish` ON THE INBOX DEVICE, then clear this\n\
         # reminder with `confidant doctor --clear-pending-inbox-rotation`.\n\
         vault_id = {vault_id:?}\n\
         shredded_client = {shredded_client:?}\n\
         recorded_at = {recorded_at:?}\n"
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // 0600 from creation: it names the shredded client (opaque id, but still).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?
            .write_all(content.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, content)?;
    }
    Ok(())
}

/// Working-tree rollback for `keys shred` (#320).
///
/// Edge deletions and interaction rewrites mutate the working tree BEFORE
/// `KeyStore::shred` runs. If any later step refuses, the mutations must be
/// undone: a re-run cannot rediscover them (e.g. a deleted edge no longer
/// names the shredded person, so the `ls-files` stage step is skipped and
/// the edge stays in HEAD under `vault:shared` — a privacy leak, not just
/// a dirty tree).
///
/// The guard records `(vault-relative path, pre-mutation bytes)` for every
/// mutation. While armed, dropping the guard restores every recorded file
/// best-effort. Call `disarm()` once the shred succeeds (the mutations are
/// then intentional). `restore()` restores immediately and returns the paths
/// that could not be restored, so the caller can tell the operator to
/// `git checkout` them before re-running.
struct ShredTreeGuard<'a> {
    root: &'a Path,
    snapshots: Vec<(String, Vec<u8>)>,
    armed: bool,
}

impl<'a> ShredTreeGuard<'a> {
    fn new(root: &'a Path) -> Self {
        ShredTreeGuard {
            root,
            snapshots: Vec::new(),
            armed: true,
        }
    }

    /// Record a mutation. Call for every working-tree write/delete between
    /// creation and `disarm()`, BEFORE the mutation happens.
    fn record(&mut self, path: String, before: Vec<u8>) {
        if self.armed {
            self.snapshots.push((path, before));
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.snapshots.clear();
    }

    /// Restore all recorded files now. Returns vault-relative paths that
    /// could not be restored. Disarms the guard (drop becomes a no-op).
    fn restore(&mut self) -> Vec<String> {
        let mut failed = Vec::new();
        for (path, bytes) in &self.snapshots {
            let full = self.root.join(path);
            let ok = full
                .parent()
                .map(|p| std::fs::create_dir_all(p).is_ok())
                .unwrap_or(true)
                && std::fs::write(&full, bytes).is_ok();
            if !ok {
                failed.push(path.clone());
            }
        }
        self.disarm();
        failed
    }
}

impl Drop for ShredTreeGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.restore();
        }
    }
}

/// Restore the working tree after a refused shred step. When the restore
/// itself was incomplete, the operator is told exactly which paths need a
/// manual `git checkout` before re-running.
fn shred_restore(guard: &mut ShredTreeGuard, err: anyhow::Error) -> anyhow::Error {
    let unrestored = guard.restore();
    if unrestored.is_empty() {
        err
    } else {
        err.context(format!(
            "working tree could not be fully restored: {}; run `git checkout -- <path>` for each listed path before re-running",
            unrestored.join(", ")
        ))
    }
}

/// Delete every edge record naming `client_id` from the working tree
/// (#179). Runs BEFORE `KeyStore::shred` destroys keys: edge discovery
/// needs decryption (edges live under `vault:shared`, so `a` / `b` sit
/// inside the ciphertext in encrypted vaults), and a failure here must
/// abort before any irreversible key destruction. Returns the deleted
/// vault-relative paths, for staging into the same signed shred commit.
///
/// Plan-then-apply (#320): every refusal check and every read happens
/// before the first deletion; each deletion is recorded in `guard` so a
/// later refusal rolls the tree back.
///
/// Fail-closed, edge-scoped: refuses when any *edge's* ends cannot be
/// determined — an undecryptable or tampered edge envelope, a `no-ai`
/// shell, a malformed edge file, or an edge with a missing/malformed
/// end — because an unseen edge might name the shredded person.
/// Skipped or refused envelopes *outside* `edges/` do not block shred:
/// after `keys shred` of person A, A's leftover envelopes stay in the
/// tree and become undecryptable, and shredding B must still proceed
/// when every edge reads fine.
fn delete_edges_naming(
    root: &Path,
    client_id: &str,
    guard: &mut ShredTreeGuard,
) -> anyhow::Result<Vec<String>> {
    // Keyed load: decrypts edge envelopes via the current device key.
    // (Same probe-then-keyed pattern as `load_vault_for_reads`.)
    let probe = load_vault(root)?;
    let decryptor = std::sync::Arc::new(record_decrypt::RecordDecryptor::for_reads(
        root,
        &probe.config.vault_id,
    ));
    // Wrap the decrypt hook to record per-path outcomes under `edges/`.
    // Record files load on worker threads, hence the mutexes.
    let edge_skipped = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let edge_refused = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let inner = decryptor.hook();
    let hook: ContentHook = std::sync::Arc::new({
        let edge_skipped = std::sync::Arc::clone(&edge_skipped);
        let edge_refused = std::sync::Arc::clone(&edge_refused);
        move |path: &str, bytes: &[u8]| {
            let outcome = inner(path, bytes);
            if path.starts_with("edges/") {
                match outcome {
                    ContentOutcome::Skipped => {
                        edge_skipped.lock().unwrap().push(path.to_string());
                    }
                    ContentOutcome::Refused => {
                        edge_refused.lock().unwrap().push(path.to_string());
                    }
                    _ => {}
                }
            }
            outcome
        }
    });
    let vault =
        confidant_core::load_vault_with_hook(root, Some(hook)).map_err(anyhow::Error::new)?;
    let edge_skipped = edge_skipped.lock().unwrap();
    if !edge_skipped.is_empty() {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "cannot determine every edge naming {client_id}: {} edge envelope(s) could not be decrypted on this device; refusing to shred",
            edge_skipped.len()
        )).with_fix(
            "Run shred from a device that can decrypt every edge, or resolve the undecryptable edge files first",
        )));
    }
    let edge_refused = edge_refused.lock().unwrap();
    if !edge_refused.is_empty() {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "cannot determine every edge naming {client_id}: {} edge envelope(s) were refused as tampered or corrupt; refusing to shred",
            edge_refused.len()
        )).with_fix(
            "Resolve the refused edge envelopes first (check reports them as unreadable)",
        )));
    }
    // A load finding on an edge file means an edge record could not be
    // parsed — its ends are unknown.
    if let Some(bad) = vault
        .load_findings
        .iter()
        .find(|f| f.file.as_deref().is_some_and(|p| p.starts_with("edges/")))
    {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "cannot determine every edge naming {client_id}: an edge file could not be parsed ({}); refusing to shred",
            bad.file.as_deref().unwrap_or("edges/")
        )).with_fix(
            "Fix or remove the unparseable edge file, then re-run shred",
        )));
    }
    // PLAN (#320): collect every edge naming `client_id` — with its bytes —
    // before touching the tree. The malformed-end refusal lives here, so a
    // refusal leaves the tree untouched.
    let mut plan: Vec<(String, Vec<u8>)> = Vec::new();
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Edge {
            continue;
        }
        let (Some(a), Some(b)) = (rec.edge_end("a"), rec.edge_end("b")) else {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "cannot determine every edge naming {client_id}: edge {} has a missing or malformed end; refusing to shred",
                rec.id
            )).with_fix(
                "Fix the edge's a/b ends, then re-run shred",
            )));
        };
        if a.to_string() == client_id || b.to_string() == client_id {
            let path = root.join(&rec.path);
            let bytes = std::fs::read(&path).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot read edge file {}: {e}",
                    rec.path
                )))
            })?;
            plan.push((rec.path.clone(), bytes));
        }
    }
    // APPLY: nothing above can refuse any more. Record each deletion in the
    // guard BEFORE it happens, so a mid-loop IO error still rolls back.
    let mut deleted = Vec::new();
    for (path, bytes) in plan {
        let full = root.join(&path);
        guard.record(path.clone(), bytes);
        std::fs::remove_file(&full).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot delete edge file {path}: {e}"
            )))
        })?;
        // Best-effort: drop the now-empty edge directory.
        if let Some(parent) = full.parent() {
            let _ = std::fs::remove_dir(parent);
        }
        deleted.push(path);
    }
    Ok(deleted)
}

/// #258: remove a shredded person from every interaction's `with:` list,
/// re-encrypting each affected interaction through the normal write path
/// (`record_crypto`), before any key destruction. Returns the rewritten
/// vault-relative paths, for staging into the same signed shred commit.
///
/// Plan-then-apply (#320): every refusal check, every `with:` parse, every
/// encryption, and every pre-rewrite read happens before the first write;
/// each write is recorded in `guard` so a later refusal rolls the tree
/// back.
///
/// Mirrors [`delete_edges_naming`]: discovery decrypts with the pre-shred
/// device key, and a tampered / unparseable / genuinely-undecryptable
/// interaction fails closed before shred touches a key. The rewritten
/// envelopes stage into the same signed shred commit (their paths are
/// already tracked).
///
/// An interaction envelope that is `Skipped` (this device can't unwrap its
/// data key) is treated one of two ways: if its primary is still a live
/// client, that is a real failure and shred refuses; if the primary was
/// shredded earlier, its `with:` list is unreachable and nothing is lost by
/// skipping it (the history-residue warning already covers it). This keeps a
/// later shred from being blocked by a previous shred's leftovers (#259's
/// edge fix, applied to interactions). A skipped envelope whose bytes
/// cannot be read or parsed, or whose key id does not name a determinable
/// client, fails closed: an unseen primary might be live.
fn strip_participant_from_interactions(
    root: &Path,
    client_id: &str,
    live_clients: &HashSet<String>,
    guard: &mut ShredTreeGuard,
) -> anyhow::Result<Vec<String>> {
    // Keyed load: decrypts interaction envelopes via the current device key.
    let probe = load_vault(root)?;
    let decryptor = std::sync::Arc::new(record_decrypt::RecordDecryptor::for_reads(
        root,
        &probe.config.vault_id,
    ));
    let ixn_skipped = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let ixn_refused = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let inner = decryptor.hook();
    let hook: ContentHook = std::sync::Arc::new({
        let ixn_skipped = std::sync::Arc::clone(&ixn_skipped);
        let ixn_refused = std::sync::Arc::clone(&ixn_refused);
        move |path: &str, bytes: &[u8]| {
            let outcome = inner(path, bytes);
            if path.starts_with("interactions/") {
                match outcome {
                    ContentOutcome::Skipped => {
                        ixn_skipped.lock().unwrap().push(path.to_string());
                    }
                    ContentOutcome::Refused => {
                        ixn_refused.lock().unwrap().push(path.to_string());
                    }
                    _ => {}
                }
            }
            outcome
        }
    });
    let vault =
        confidant_core::load_vault_with_hook(root, Some(hook)).map_err(anyhow::Error::new)?;
    // A `Skipped` interaction whose primary is still live is a real failure:
    // this device should be able to decrypt every live client (the strand
    // check below enforces it), so a live-but-undecryptable interaction means
    // we cannot tell whether its `with:` names `client_id`. A `Skipped`
    // interaction whose primary was already shredded is unreachable — skip.
    // Anything we cannot read or parse fails closed (#320): an unseen
    // primary might be live, and silently skipping would risk leaving a
    // `with:` entry naming the shredded person behind.
    let ixn_skipped = ixn_skipped.lock().unwrap();
    let mut live_undecryptable: Vec<String> = Vec::new();
    for path in ixn_skipped.iter() {
        let bytes = std::fs::read(root.join(path)).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot determine every interaction naming {client_id}: cannot re-read skipped envelope {path}: {e}"
            )))
        })?;
        let env = confidant_crypt::envelope::parse(&bytes).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot determine every interaction naming {client_id}: skipped envelope {path} does not parse: {e}"
            )))
        })?;
        // `envelope::parse` already validated the key id shape
        // (`<client>/e<epoch>`); failure here is unreachable, but fail
        // closed rather than silently defaulting to an empty client.
        let (client, _) = env.key_id.rsplit_once("/e").ok_or_else(|| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot determine every interaction naming {client_id}: skipped envelope {path} has an undeterminable client"
            )))
        })?;
        if live_clients.contains(client) {
            live_undecryptable.push(path.clone());
        }
    }
    if !live_undecryptable.is_empty() {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "cannot determine every interaction naming {client_id}: {} interaction envelope(s) under a live primary could not be decrypted on this device; refusing to shred",
            live_undecryptable.len()
        )).with_fix(
            "Run shred from a device enrolled for every live client, or resolve the undecryptable interaction files first",
        )));
    }
    let ixn_refused = ixn_refused.lock().unwrap();
    if !ixn_refused.is_empty() {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "cannot determine every interaction naming {client_id}: {} interaction envelope(s) were refused as tampered or corrupt; refusing to shred",
            ixn_refused.len()
        )).with_fix(
            "Resolve the refused interaction envelopes first (check reports them as unreadable)",
        )));
    }
    if let Some(bad) = vault.load_findings.iter().find(|f| {
        f.file
            .as_deref()
            .is_some_and(|p| p.starts_with("interactions/"))
    }) {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "cannot determine every interaction naming {client_id}: an interaction file could not be parsed ({}); refusing to shred",
            bad.file.as_deref().unwrap_or("interactions/")
        )).with_fix(
            "Fix or remove the unparseable interaction file, then re-run shred",
        )));
    }

    // Shred requires a keyed vault; the encryptor is the same write path an
    // ordinary `record edit` uses (epoch selection + outer no-ai stamping).
    let encryptor = record_crypto::RecordEncryptor::for_vault(root, &vault)?.ok_or_else(|| {
        anyhow::Error::new(DomainError::invalid("shred requires an encrypted vault"))
    })?;

    // PLAN (#320): parse every `with:`, encrypt every rewrite, and read
    // every original BEFORE touching the tree. Any refusal or encryption
    // failure happens here, with the tree untouched.
    struct PlannedRewrite {
        path: String,
        original: Vec<u8>,
        envelope: Vec<u8>,
    }
    let mut plan: Vec<PlannedRewrite> = Vec::new();
    for rec in vault.records.values() {
        if rec.kind != RecordKind::Interaction {
            continue;
        }
        let Some(raw_with) = rec.field("with") else {
            continue;
        };
        let Some(mut with) = confidant_core::record::parse_with_list(raw_with) else {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "cannot determine whether interaction {} names {client_id}: its `with:` list is malformed; refusing to shred",
                rec.id
            )).with_fix(
                "Fix the interaction's `with:` list, then re-run shred",
            )));
        };
        let before = with.len();
        with.retain(|id| id.to_string() != client_id);
        if with.len() == before {
            continue;
        }
        let mut edited = rec.clone();
        edited
            .fields
            .insert("with".to_owned(), format_with_list(&with));
        let plaintext = confidant_core::format_record(&edited);
        let envelope = encryptor
            .encrypt_file(std::path::Path::new(&rec.path), plaintext.as_bytes())
            .map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot re-encrypt interaction {}: {e}",
                    rec.id
                )))
            })?;
        let full_path = root.join(&rec.path);
        let original = std::fs::read(&full_path).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot re-read interaction {} before rewrite: {e}",
                rec.id
            )))
        })?;
        plan.push(PlannedRewrite {
            path: rec.path.clone(),
            original,
            envelope,
        });
    }
    // APPLY: nothing above can refuse any more. Record each rewrite in the
    // guard BEFORE it happens, so a mid-loop IO error still rolls back.
    let mut rewritten = Vec::new();
    for r in plan {
        let full = root.join(&r.path);
        guard.record(r.path.clone(), r.original);
        std::fs::write(&full, &r.envelope).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot write re-encrypted interaction {}: {e}",
                r.path
            )))
        })?;
        rewritten.push(r.path);
    }
    Ok(rewritten)
}

/// Serialize a participant list as a `with:` value (`[p-A, p-B]`).
fn format_with_list(ids: &[confidant_core::id::RecordId]) -> String {
    let inner = ids
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

/// #188: encrypt every record in a freshly generated plaintext bench vault,
/// so the benchmark measures the decrypt path. Uses the test-overrides key
/// sources (`CONFIDANT_DEVICE_KEY` + `CONFIDANT_TEST_OPERATOR_KEY` +
/// `CONFIDANT_KEYCHAIN=off`), so it needs the `--all-features` build and no
/// OS keychain. The plaintext is deleted before re-encrypting (the production
/// `encrypt_file` refuses to rewrite plaintext in place, ⚠1) — fine for a
/// throwaway bench vault that is never committed.
fn encrypt_bench_vault(root: &Path) -> anyhow::Result<()> {
    use age::secrecy::ExposeSecret;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    // Throwaway device + operator keys, injected via env (no OS keychain).
    let device = age::x25519::Identity::generate();
    let device_secret = device.to_string().expose_secret().to_owned();
    let operator = SigningKey::generate(&mut OsRng);
    let operator_hex = hex::encode(operator.to_bytes());
    std::env::set_var(confidant_crypt::keychain::DEVICE_KEY_ENV, &device_secret);
    std::env::set_var("CONFIDANT_TEST_OPERATOR_KEY", &operator_hex);
    std::env::set_var("CONFIDANT_KEYCHAIN", "off");

    // Isolate the operator config dir: `init` writes trust.toml under
    // `$HOME/.config/confidant`, which must never touch the operator's real
    // config during a benchmark. Point HOME at a throwaway dir OUTSIDE the
    // vault (the anchor module refuses a trust anchor inside the vault, by
    // design §4) and record its path in the vault so measuring later just
    // re-exports the same HOME (see the hint at the end of this function).
    // Both the subprocesses below and the in-process encryptor use it.
    let bench_home = std::env::temp_dir().join(format!(
        "confidant-bench-home-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&bench_home)?;
    std::env::set_var("HOME", &bench_home);

    let exe = std::env::current_exe()?;
    let run = |args: &[&str], root: &Path| -> anyhow::Result<()> {
        let out = std::process::Command::new(&exe)
            .args(args)
            .arg("--vault")
            .arg(root)
            .output()?;
        anyhow::ensure!(
            out.status.success(),
            "{} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(())
    };

    // `bench-gen` writes files but no git repo; `init` needs one (and an
    // identity) for its commit-per-write.
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["init", "-q"])
        .output()?;
    anyhow::ensure!(out.status.success(), "git init failed");
    for (key, value) in [("user.email", "bench@example.com"), ("user.name", "Bench")] {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["config", key, value])
            .output()?;
        anyhow::ensure!(out.status.success(), "git config {key} failed");
    }
    // Commit the generated files so `init` sees a clean tree.
    for args in [&["add", "-A"][..], &["commit", "-qm", "bench vault"][..]] {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()?;
        anyhow::ensure!(out.status.success(), "git {} failed", args.join(" "));
    }

    // init: operator cert, device key, shared + lookup clients, anchor.
    run(&["init", "--no-input"], root)?;

    // The vault is now structurally encrypted (keys/ exists) but records are
    // still plaintext; load it to enumerate person ids and record paths.
    let vault = confidant_core::load_vault(root).map_err(anyhow::Error::new)?;
    let persons: Vec<String> = vault
        .records
        .values()
        .filter(|r| r.kind == RecordKind::Person)
        .map(|r| r.id.to_string())
        .collect();
    for pid in &persons {
        run(&["keys", "init-client", pid, "--no-input"], root)?;
    }

    // Encrypt each record in place: delete the plaintext first so the
    // production `encrypt_file` (⚠1) treats it as a fresh write.
    let encryptor = record_crypto::RecordEncryptor::for_vault(root, &vault)?
        .ok_or_else(|| anyhow::anyhow!("bench vault is not encrypted after init"))?;
    for rec in vault.records.values() {
        let path = root.join(&rec.path);
        let content = std::fs::read(&path)?;
        std::fs::remove_file(&path)?;
        let envelope = encryptor
            .encrypt_file(std::path::Path::new(&rec.path), &content)
            .map_err(|e| anyhow::anyhow!("encrypt {}: {e}", rec.path))?;
        std::fs::write(&path, &envelope)?;
    }
    // Leave the throwaway device key beside the vault (0600, never
    // committed — written after the last git commit above) so the benchmark
    // can actually decrypt when measuring. The secret itself is never
    // printed; only file paths are. Reads also need the throwaway trust
    // anchor, which lives in the throwaway bench HOME whose path is
    // recorded beside the vault (likewise uncommitted, and not a secret).
    let key_path = root.join(".bench-device-key");
    write_corpus_file(&key_path, device_secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("write bench device key: {e}"))?;
    let home_path = root.join(".bench-home-path");
    std::fs::write(&home_path, bench_home.to_string_lossy().as_bytes())
        .map_err(|e| anyhow::anyhow!("write bench home path: {e}"))?;
    eprintln!(
        "bench vault encrypted; measure with HOME=$(cat {}) CONFIDANT_DEVICE_KEY=$(cat {})",
        home_path.display(),
        key_path.display()
    );
    Ok(())
}

fn cmd_keys_shred(cli: &Cli, root: &Path, client_id: &str) -> anyhow::Result<ExitCode> {
    use confidant_crypt::{anchor, lifecycle::KeyStore};
    validate_keys_client_id(client_id)?;
    // B1: shred refuses both reserved ids.
    if client_id == confidant_crypt::manifest::VAULT_CLIENT_ID
        || client_id == confidant_crypt::manifest::SHARED_CLIENT_ID
    {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "refusing to shred reserved client id {client_id:?}"
        ))));
    }

    let config_dir = confidant_config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;

    // #105 B4: load the inbox keypair once, through the same backend the
    // rotation below will use, and refuse while the rotation window is
    // already open. Fail closed on keychain errors; `NoKey` just means no
    // inbox key on this device (the window is not open, and shred records
    // the device-local reminder instead).
    let backend = keychain_backend();
    let inbox_keys = confidant_core::inbox::InboxKeys::load_opt_with(&*backend, Some(&config_dir))
        .map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot check inbox rotation window: {e}"
            )))
        })?;
    if let Some(keys) = &inbox_keys {
        if keys.has_previous() {
            return Err(anyhow::Error::new(DomainError::invalid(
                "inbox rotation window is already open (previous inbox key present); run `confidant inbox rotate --finish` first".to_string(),
            )));
        }
    }

    let (anchor, _warnings) = anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
    let identity = keys_device_identity()?;
    let operator_sk = load_operator_sk(&anchor)?;

    // Collect all initialized clients for the strand check via
    // manifest_clients() (not read_dir): it maps keys/shared to
    // vault:shared correctly and only lists verified manifests.
    // Skip vault:lookup (keys/vault) — shred handles it separately.
    let vault = load_vault(root)?;
    let keys_dir = root.join("keys");
    let store = KeyStore::with_config_dir(keys_dir.clone(), &vault.config.vault_id, &config_dir)
        .map_err(anyhow::Error::new)?;
    // Live clients (for the interaction-with: check below): every client
    // whose key still exists, minus the reserved lookup id. An interaction
    // under a client NOT in this set was shredded earlier and is skipped.
    let all_clients: Vec<String> = store
        .manifest_clients()
        .into_iter()
        .filter(|c| c != confidant_crypt::manifest::VAULT_CLIENT_ID)
        .collect();
    let live_clients: std::collections::HashSet<String> = all_clients.iter().cloned().collect();
    // #179: delete edges naming the shredded person BEFORE destroying
    // keys — discovery needs decryption, and a failure must abort before
    // any irreversible key destruction. The deletions stage into the same
    // signed shred commit below.
    // #320: the edge deletions and interaction rewrites below mutate the
    // working tree BEFORE `KeyStore::shred` runs. The guard records every
    // mutation and rolls the tree back if ANY later step refuses — a strip
    // refusal after the edges are gone, a mid-loop IO error, a
    // `keys_shred_fresh_recipients` failure, or a `store.shred` refusal.
    // Without this, a re-run cannot rediscover the mutations (a deleted
    // edge no longer names the shredded person), and the edge stays in
    // HEAD under `vault:shared`: a privacy leak, not just a dirty tree.
    // Disarmed once shred succeeds, when the mutations become intentional.
    let mut guard = ShredTreeGuard::new(root);
    let deleted_edges = match delete_edges_naming(root, client_id, &mut guard) {
        Ok(v) => v,
        Err(e) => return Err(shred_restore(&mut guard, e)),
    };
    // #258: strip the shredded person from every interaction `with:` list
    // the same way — before key destruction, through the normal write path,
    // staged into the same shred commit.
    let stripped_interactions =
        match strip_participant_from_interactions(root, client_id, &live_clients, &mut guard) {
            Ok(v) => v,
            Err(e) => return Err(shred_restore(&mut guard, e)),
        };
    let all_refs: Vec<&str> = all_clients.iter().map(|s| s.as_str()).collect();

    // Fresh recipients for the re-wrap: a fresh keypair for THIS device
    // only, generated in memory. The fresh private key is NOT stored yet:
    // it is stored only after `KeyStore::shred` returns Ok. A refused
    // shred (verify-first) must leave this device's key unchanged, or the
    // device is locked out of the still-unshredded vault.
    // Other devices are NOT carried over — their old pubkeys would keep
    // the shredded history openable (strict pubkey-reuse check in
    // KeyStore::shred). They must re-enroll via `keys device-add`.
    let (fresh_device_key, new_recipients) = match keys_shred_fresh_recipients() {
        Ok(v) => v,
        Err(e) => return Err(shred_restore(&mut guard, e)),
    };

    // #220: shred runs against a staged copy of keys/ with roll-forward
    // (Frank's decision on #290). The mutation, check, marker, swap,
    // anchor re-pin and device-key promotion all happen inside
    // staged_shred_mutation; a crash at any point is recoverable via
    // repair_keys_staging. B5: verify-first, strand check and the
    // history-derived destroy list all come from KeyStore::shred —
    // do not weaken them.
    let outcome = match staged_shred_mutation(
        root,
        &vault,
        &config_dir,
        &anchor,
        &operator_sk,
        identity.as_ref(),
        client_id,
        &all_refs,
        &new_recipients,
        &fresh_device_key,
        deleted_edges.len(),
        stripped_interactions.len(),
        cli.no_input,
    ) {
        Ok(outcome) => outcome,
        Err(e) => return Err(shred_restore(&mut guard, e)),
    };
    // The staged swap landed and the out-of-tree promotions completed:
    // the working-tree mutations above are now intentional. Disarm the
    // guard before any further fallible step.
    guard.disarm();

    // Delete this device's local search index (the QMD corpus + store): it
    // is a plaintext mirror that may hold the shredded client's content, and
    // it is now stale. Deleted ASAP so a later fallible step cannot leave it
    // behind; other devices' indexes are unaffected (see the leftover
    // warnings). Best-effort: failures become warnings, not errors.
    let search_index_warnings = delete_search_index(root);

    // #220: the anchor re-pin, operator-cert re-sign (into the staged
    // tree), device-key promotion and phrase display all happened inside
    // staged_shred_mutation before the swap. The check ran there too.
    // B2: one commit.
    let no_input = cli.no_input;
    stage_keys(root, no_input)?;
    // #179: stage the deleted edge files (deletions only, exact paths) so
    // they land in the same signed shred commit. Only tracked paths: an
    // edge file that was never committed has nothing to stage. Per-path,
    // so unrelated unstaged changes under edges/ are not swept in.
    if !deleted_edges.is_empty() {
        let mut ls_args: Vec<&str> = vec!["ls-files", "-z", "--"];
        ls_args.extend(deleted_edges.iter().map(String::as_str));
        let listed = confidant_core::write::git(root, &ls_args, no_input)?;
        let tracked: Vec<&str> = listed.split('\0').filter(|s| !s.is_empty()).collect();
        if !tracked.is_empty() {
            let mut add_args: Vec<&str> = vec!["add", "--"];
            add_args.extend(tracked);
            confidant_core::write::git(root, &add_args, no_input)?;
        }
    }
    // #258: stage the re-encrypted interaction files (modifications only,
    // exact paths) so they land in the same signed shred commit. They are
    // tracked (the interactions existed before the shred), so a plain
    // `git add` stages the modification without sweeping unrelated files.
    if !stripped_interactions.is_empty() {
        let mut add_args: Vec<&str> = vec!["add", "--"];
        add_args.extend(stripped_interactions.iter().map(String::as_str));
        confidant_core::write::git(root, &add_args, no_input)?;
    }
    confidant_core::write::git(
        root,
        &["commit", "-m", &format!("keys: shred {client_id}")],
        no_input,
    )?;

    // #105 B5: inbox interplay. The CLI decides (not the crypt layer):
    // if this device holds the inbox key, run the rotation path now
    // (anchor already re-pinned above). Otherwise write the device-local
    // reminder.
    let mut inbox_rotated = false;
    if inbox_keys.is_some() {
        // Run the inbox rotation on this device, through the same backend
        // the window check used.
        let vault_config = root.join("confidant.toml");
        let user_config = config_dir.join("config.toml");
        let opts = confidant_core::inbox::InboxRotateOptions {
            finish: false,
            allow_unsigned: false,
            trusted_signers: Vec::new(),
            pinned_pubkey: None,
        };
        confidant_core::inbox::run_inbox_rotate(
            root,
            &*backend,
            Some(&config_dir),
            &vault_config,
            &user_config,
            &opts,
        )
        .map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!("inbox rotation failed: {e}")))
        })?;
        inbox_rotated = true;
    } else {
        // Off-inbox device: write the reminder (⚠5, #105 B3).
        write_pending_inbox_rotation(&vault.config.vault_id, client_id)?;
    }

    // #154 must-fix 4: warn (do not fail) when git history is degraded, so
    // the operator knows the shredded-client / retired-recovery checks only
    // saw the working tree.
    let mut shred_warnings = outcome.warnings.clone();
    if let Some(w) = store.history_degraded_reason() {
        eprintln!("warning: {w}");
        shred_warnings.push(w);
    }
    let search_index_deleted = search_index_warnings.is_empty();
    shred_warnings.extend(search_index_warnings);

    if cli.json {
        print_json(&serde_json::json!({
            "ok": true,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": root.to_string_lossy(),
            "client_id": client_id,
            "destroy_key_ids": outcome.destroy_key_ids,
            "warnings": shred_warnings,
            "deleted_edges": &deleted_edges,
            "stripped_interactions": stripped_interactions.len(),
            "inbox_rotated": inbox_rotated,
            "device_key_rotated": true,
            "search_index_deleted": search_index_deleted,
            "note": "this device was re-enrolled with a fresh keypair; other devices must re-enroll via `keys device-add`",
        }))?;
    } else {
        println!("shredded client {client_id}");
        println!("device key rotated: this device was re-enrolled with a fresh keypair");
        println!("other devices were removed: re-enroll them with `keys device-add`");
        if !deleted_edges.is_empty() {
            println!(
                "deleted {} edge(s) naming {client_id} (same commit)",
                deleted_edges.len()
            );
        }
        if !stripped_interactions.is_empty() {
            println!(
                "re-encrypted {} interaction(s) to remove {client_id} from their participant lists (same commit)",
                stripped_interactions.len()
            );
        }
        if search_index_deleted {
            println!("local search index deleted (re-run `confidant reindex` to rebuild)");
        }
        if inbox_rotated {
            println!(
                "inbox key rotated (run `confidant inbox rotate --finish` to destroy the old key)"
            );
        } else {
            println!(
                "inbox rotation pending: this device does not hold the inbox key; reminder written"
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn print_error(json: bool, vault: Option<&str>, err: &DomainError) -> io::Result<()> {
    if json {
        let body = serde_json::json!({
            "ok": false,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": vault,
            "error": err.to_json(),
        });
        print_json(&body)?;
    } else {
        writeln!(io::stderr(), "error: {} ({})", err.message(), err.code())?;
        if let Some(fix) = err.fix() {
            writeln!(io::stderr(), "  fix: {fix}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{git_version_check_from, parse_git_version, MIN_GIT_VERSION};

    #[test]
    fn parse_git_version_handles_real_world_strings() {
        // Apple Git carries a parenthesised suffix.
        assert_eq!(
            parse_git_version("git version 2.39.3 (Apple Git-145)"),
            Some((2, 39, 3))
        );
        // Windows appends `.windows.N` after the patch.
        assert_eq!(
            parse_git_version("git version 2.47.1.windows.1"),
            Some((2, 47, 1))
        );
        assert_eq!(parse_git_version("git version 2.34.0"), Some((2, 34, 0)));
        // Missing patch defaults to 0.
        assert_eq!(parse_git_version("git version 2.34"), Some((2, 34, 0)));
        // Trailing newline from the real command output.
        assert_eq!(parse_git_version("git version 2.43.0\n"), Some((2, 43, 0)));
        // No version number to read.
        assert_eq!(parse_git_version("git version abc"), None);
        assert_eq!(parse_git_version("not git output"), None);
        assert_eq!(parse_git_version(""), None);
    }

    #[test]
    fn git_version_check_status_rules() {
        // At or above the floor is ok either way.
        let c = git_version_check_from(Some(MIN_GIT_VERSION), true);
        assert_eq!(c.status, "ok");
        assert!(c.message.contains("2.34.0"));
        let c = git_version_check_from(Some((2, 50, 0)), false);
        assert_eq!(c.status, "ok");

        // Below the floor: error with signers (signature verification in
        // use), warning without (nothing verifies signatures).
        let c = git_version_check_from(Some((2, 33, 0)), true);
        assert_eq!(c.status, "error");
        assert!(c.message.contains("upgrade git to >= 2.34.0"));
        assert!(c.message.contains("SSH-signed inbox commits"));
        let c = git_version_check_from(Some((2, 33, 0)), false);
        assert_eq!(c.status, "warning");
        assert!(c.message.contains("upgrade git to >= 2.34.0"));

        // Undetermined version is a warning, never an error.
        let c = git_version_check_from(None, true);
        assert_eq!(c.status, "warning");
    }

    /// Snapshot a directory tree as sorted (relative path, bytes) pairs,
    /// for byte-identical comparisons of `keys/`.
    fn snapshot_tree(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        fn walk(
            dir: &std::path::Path,
            base: &std::path::Path,
            out: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
        ) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let p = entry.path();
                if p.is_dir() {
                    walk(&p, base, out);
                } else if p.is_file() {
                    out.push((
                        p.strip_prefix(base).unwrap().to_path_buf(),
                        std::fs::read(&p).unwrap(),
                    ));
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

    /// Minimal vault dir (confidant.toml only) + a fake `keys/` tree +
    /// a seq tracker, for staging-helper tests.
    fn staging_fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("vault");
        let config_dir = tmp.path().join("config");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            root.join("confidant.toml"),
            "spec = \"0.1\"\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("keys/client-a/wrapped")).unwrap();
        std::fs::write(root.join("keys/client-a/recipients.toml"), "seq = 1\n").unwrap();
        std::fs::write(root.join("keys/client-a/wrapped/abc.age"), b"wrapped").unwrap();
        std::fs::write(
            root.join("keys/recovery-recipients.toml"),
            "recipients = []\n",
        )
        .unwrap();
        std::fs::write(
            config_dir.join("manifest-seq.toml"),
            "[01TEST00000000000000000000]\nclient-a = 3\n",
        )
        .unwrap();
        (tmp, root, config_dir)
    }

    #[test]
    fn staged_keys_mutation_failure_leaves_keys_and_tracker_untouched() {
        // #175: a failing mutation must leave keys/ byte-identical, the
        // real tracker untouched, and no staging leftovers. The helper
        // cannot distinguish "before" vs "mid" mutation — the cleanup
        // path is identical — so a failing closure proves the mechanics;
        // the CLI check-failure tests prove a fully-mutated stage is
        // discarded too.
        use super::{keys_old_dir, keys_stage_dir, keys_staged_tracker_path, staged_keys_mutation};
        let (_tmp, root, config_dir) = staging_fixture();
        let before = snapshot_tree(&root.join("keys"));
        let vault = confidant_core::load_vault(&root).unwrap();
        let err =
            staged_keys_mutation(&root, &vault, &config_dir, |_store| -> anyhow::Result<()> {
                Err(anyhow::anyhow!("injected failure"))
            })
            .unwrap_err();
        assert!(err.to_string().contains("injected failure"));
        assert_eq!(snapshot_tree(&root.join("keys")), before);
        assert_eq!(
            std::fs::read_to_string(config_dir.join("manifest-seq.toml")).unwrap(),
            "[01TEST00000000000000000000]\nclient-a = 3\n"
        );
        assert!(!keys_stage_dir(&root).exists());
        assert!(!keys_old_dir(&root).exists());
        assert!(!keys_staged_tracker_path(&config_dir).exists());
    }

    #[test]
    fn repair_keys_staging_restores_mid_swap() {
        // Crash after the first rename: keys/ missing, keys.old holds
        // the old tree, stage + staged tracker are stale.
        use super::{keys_old_dir, keys_stage_dir, keys_staged_tracker_path, repair_keys_staging};
        let (_tmp, root, config_dir) = staging_fixture();
        std::fs::create_dir_all(root.join(".confidant")).unwrap();
        std::fs::rename(root.join("keys"), keys_old_dir(&root)).unwrap();
        std::fs::create_dir_all(keys_stage_dir(&root)).unwrap();
        std::fs::write(keys_stage_dir(&root).join("sentinel"), b"stale").unwrap();
        std::fs::write(keys_staged_tracker_path(&config_dir), b"stale").unwrap();
        repair_keys_staging(&root, &config_dir).unwrap();
        assert!(root.join("keys/client-a/recipients.toml").is_file());
        assert!(!keys_old_dir(&root).exists());
        assert!(!keys_stage_dir(&root).exists());
        assert!(!keys_staged_tracker_path(&config_dir).exists());
    }

    #[test]
    fn repair_keys_staging_cleans_completed_swap() {
        // Swap completed (keys/ is the new tree), cleanup never ran:
        // keys.old is deleted, keys/ is untouched.
        use super::{keys_old_dir, repair_keys_staging};
        let (_tmp, root, config_dir) = staging_fixture();
        let before = snapshot_tree(&root.join("keys"));
        std::fs::create_dir_all(keys_old_dir(&root)).unwrap();
        std::fs::write(keys_old_dir(&root).join("sentinel"), b"old").unwrap();
        repair_keys_staging(&root, &config_dir).unwrap();
        assert_eq!(snapshot_tree(&root.join("keys")), before);
        assert!(!keys_old_dir(&root).exists());
    }

    #[test]
    fn repair_keys_staging_refuses_inconsistent_state() {
        // keys/ missing with a stage but no backup: the copy never
        // deletes keys/, so this means external interference — refuse
        // to guess.
        use super::{keys_stage_dir, repair_keys_staging};
        let (_tmp, root, config_dir) = staging_fixture();
        std::fs::remove_dir_all(root.join("keys")).unwrap();
        std::fs::create_dir_all(keys_stage_dir(&root)).unwrap();
        assert!(repair_keys_staging(&root, &config_dir).is_err());
    }

    /// Fixture for shred-marker repair tests: a vault root with keys/,
    /// a config dir with a valid trust.toml, and a test keychain dir.
    /// Returns (tmp, root, config_dir, keychain_dir, operator_sk).
    ///
    /// NOTE: the marker tests manipulate the process-global
    /// `CONFIDANT_TEST_KEYCHAIN_DIR`; they take `KEYCHAIN_ENV_LOCK` to
    /// serialize against each other.
    static KEYCHAIN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn shred_marker_fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("vault");
        let config_dir = tmp.path().join("config");
        let keychain_dir = tmp.path().join("keychain");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&keychain_dir).unwrap();
        // Minimal vault.
        std::fs::write(
            root.join("confidant.toml"),
            "spec = \"0.1\"\npacks = []\nvault_id = \"01TEST00000000000000000000\"\n",
        )
        .unwrap();
        // Old keys/ tree (sentinel to distinguish from the new tree).
        std::fs::create_dir_all(root.join("keys")).unwrap();
        std::fs::write(root.join("keys").join("OLD_TREE"), b"old").unwrap();
        // Valid trust.toml with generated keys.
        let operator_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let recovery_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let hex = |k: &[u8]| k.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let trust_toml = format!(
            "[trust]\noperator_pubkey = \"{}\"\nrecovery_pubkey = \"{}\"\nrecovery_age_recipient = \"age1ql5z7k2dpq6x9x8v4n3m2l1k0j9h8g7f6d5s4a3\"\n",
            hex(operator_sk.verifying_key().as_bytes()),
            hex(recovery_sk.verifying_key().as_bytes()),
        );
        std::fs::write(config_dir.join("trust.toml"), trust_toml).unwrap();
        // Test keychain with an old device key.
        std::fs::write(keychain_dir.join("device.key"), b"OLD_DEVICE_KEY").unwrap();
        // Point the test keychain at our dir.
        std::env::set_var("CONFIDANT_TEST_KEYCHAIN_DIR", &keychain_dir);
        (tmp, root, config_dir, keychain_dir)
    }

    fn write_test_marker(path: &std::path::Path, recovery_vk_hex: &str, device_key: &str) {
        use super::{write_shred_marker, ShredStageMarker, SHRED_MARKER_VERSION};
        let marker = ShredStageMarker {
            version: SHRED_MARKER_VERSION,
            recovery_verifying_key_hex: recovery_vk_hex.to_owned(),
            recovery_age_recipient: "age1ql5z7k2dpq6x9x8v4n3m2l1k0j9h8g7f6d5s4a3".to_string(),
            device_key_bech32: device_key.to_owned(),
            phrase_displayed: true,
        };
        write_shred_marker(path, &marker).unwrap();
    }

    #[test]
    fn shred_marker_pre_swap_rolls_forward() {
        let _env_guard = KEYCHAIN_ENV_LOCK.lock().unwrap();
        // #220: crash after check, before swap (marker in stage). Repair
        // must finish the swap, re-pin the anchor, promote the device key,
        // and clear the marker — never discard the stage.
        use super::{
            keys_stage_dir, repair_keys_staging, shred_marker_in_keys, shred_marker_in_stage,
        };
        let (_tmp, root, config_dir, _keychain) = shred_marker_fixture();
        let stage = keys_stage_dir(&root);
        std::fs::create_dir_all(&stage).unwrap();
        // New tree in the stage (sentinel).
        std::fs::write(stage.join("NEW_TREE"), b"new").unwrap();
        // Marker in the stage with new anchor material and device key.
        let new_recovery_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let new_vk_hex: String = new_recovery_sk
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        write_test_marker(
            &shred_marker_in_stage(&stage),
            &new_vk_hex,
            "NEW_DEVICE_KEY",
        );
        let old_anchor = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();

        repair_keys_staging(&root, &config_dir).unwrap();

        // Swap completed: keys/ holds the new tree, old tree gone.
        assert!(root.join("keys/NEW_TREE").is_file());
        assert!(!root.join("keys/OLD_TREE").exists());
        assert!(!root.join(".confidant/keys.old").exists());
        assert!(!stage.exists());
        // Marker cleared (was in stage, now in keys/, now removed).
        assert!(!shred_marker_in_keys(&root.join("keys")).exists());
        // Anchor re-pinned to the new recovery key.
        let new_anchor = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();
        assert_ne!(new_anchor, old_anchor);
        assert!(new_anchor.contains(&new_vk_hex));
        // Device key promoted.
        let device_key = std::fs::read_to_string(_keychain.join("device.key")).unwrap();
        assert_eq!(device_key, "NEW_DEVICE_KEY");
    }

    #[test]
    fn shred_marker_post_swap_finishes_promotions() {
        let _env_guard = KEYCHAIN_ENV_LOCK.lock().unwrap();
        // #220: crash after swap, before re-pin (marker in keys/).
        // Repair must finish the re-pin and device-key promotion from the
        // marker, then clear it.
        use super::{repair_keys_staging, shred_marker_in_keys};
        let (_tmp, root, config_dir, _keychain) = shred_marker_fixture();
        let keys_dir = root.join("keys");
        // Simulate post-swap: new tree in keys/ with marker inside.
        std::fs::write(keys_dir.join("NEW_TREE"), b"new").unwrap();
        std::fs::remove_file(keys_dir.join("OLD_TREE")).unwrap();
        let new_recovery_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let new_vk_hex: String = new_recovery_sk
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        write_test_marker(
            &shred_marker_in_keys(&keys_dir),
            &new_vk_hex,
            "NEW_DEVICE_KEY",
        );
        let old_anchor = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();

        repair_keys_staging(&root, &config_dir).unwrap();

        // Marker cleared, anchor re-pinned, device key promoted.
        assert!(!shred_marker_in_keys(&keys_dir).exists());
        let new_anchor = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();
        assert_ne!(new_anchor, old_anchor);
        assert!(new_anchor.contains(&new_vk_hex));
        let device_key = std::fs::read_to_string(_keychain.join("device.key")).unwrap();
        assert_eq!(device_key, "NEW_DEVICE_KEY");
        // keys/ untouched apart from marker removal.
        assert!(keys_dir.join("NEW_TREE").is_file());
    }

    #[test]
    fn shred_no_marker_discards_stage() {
        let _env_guard = KEYCHAIN_ENV_LOCK.lock().unwrap();
        // #220: crash during mutate/check (no marker). The stage is
        // discarded; keys/ and the anchor are untouched.
        use super::{keys_stage_dir, repair_keys_staging};
        let (_tmp, root, config_dir, _keychain) = shred_marker_fixture();
        let stage = keys_stage_dir(&root);
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("PARTIAL"), b"partial").unwrap();
        let keys_before: Vec<_> = std::fs::read_dir(root.join("keys"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        let anchor_before = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();
        let device_before = std::fs::read_to_string(_keychain.join("device.key")).unwrap();

        repair_keys_staging(&root, &config_dir).unwrap();

        // Stage discarded, keys/ byte-identical, anchor and device key untouched.
        assert!(!stage.exists());
        let keys_after: Vec<_> = std::fs::read_dir(root.join("keys"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(keys_before, keys_after);
        assert_eq!(
            std::fs::read_to_string(config_dir.join("trust.toml")).unwrap(),
            anchor_before
        );
        assert_eq!(
            std::fs::read_to_string(_keychain.join("device.key")).unwrap(),
            device_before
        );
    }

    #[cfg(unix)]
    #[test]
    fn staged_keys_mutation_copy_failure_leaves_no_leftovers() {
        // #175: a symlink in keys/ makes the staged copy fail — the
        // partial stage must be cleaned up, not left behind.
        use super::{keys_old_dir, keys_stage_dir, keys_staged_tracker_path, staged_keys_mutation};
        let (_tmp, root, config_dir) = staging_fixture();
        std::os::unix::fs::symlink(
            root.join("keys/client-a/recipients.toml"),
            root.join("keys/link.toml"),
        )
        .unwrap();
        let vault = confidant_core::load_vault(&root).unwrap();
        let err =
            staged_keys_mutation(&root, &vault, &config_dir, |_store| -> anyhow::Result<()> {
                Ok(())
            })
            .unwrap_err();
        assert!(err.to_string().contains("symlink"));
        assert!(root.join("keys/link.toml").exists());
        assert!(!keys_stage_dir(&root).exists());
        assert!(!keys_old_dir(&root).exists());
        assert!(!keys_staged_tracker_path(&config_dir).exists());
    }

    #[test]
    fn copy_dir_recursive_copies_tree_and_refuses_symlink() {
        use super::copy_dir_recursive;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"a").unwrap();
        std::fs::write(src.join("sub/b.txt"), b"b").unwrap();
        copy_dir_recursive(&src, &dst).unwrap();
        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"a");
        assert_eq!(std::fs::read(dst.join("sub/b.txt")).unwrap(), b"b");

        #[cfg(unix)]
        {
            let src2 = tmp.path().join("src2");
            let dst2 = tmp.path().join("dst2");
            std::fs::create_dir_all(&src2).unwrap();
            std::fs::write(src2.join("real.txt"), b"real").unwrap();
            std::os::unix::fs::symlink(src2.join("real.txt"), src2.join("link.txt")).unwrap();
            assert!(copy_dir_recursive(&src2, &dst2).is_err());
        }
    }
}
