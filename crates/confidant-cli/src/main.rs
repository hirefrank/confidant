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
mod record_crypto;
mod record_decrypt;

use std::collections::BTreeMap;
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
use confidant_core::ledger::{parse_duration_minutes, parse_strict_date};
use confidant_core::record::{main_record_path, Record, RecordKind};
use confidant_core::schema::contract_schema;
use confidant_core::write::{
    apply_write, apply_write_with_encryptor, require_git_repo, FileChange, PendingWrite,
    WriteOptions, WriteOutcome,
};
use confidant_core::{check_vault, load_vault, search, CheckOptions};
use serde_json::Value;
use zeroize::Zeroizing;

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
    /// Must be unguessable and at least 22 characters (use a ULID or
    /// UUIDv4 — a ULID carries 80 random bits plus a timestamp):
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
    /// Print the section-12 cleared set (cleared record files and ledger
    /// lines) for index-time corpus exclusion (issue #38).
    ///
    /// Read-only: emits opaque paths and line numbers only, never content.
    /// The query-time allowlist stays the authority; this only narrows what
    /// an indexer copies into its local corpus.
    Allowlist,
    /// Rebuild the local QMD search corpus under
    /// `<vault>/.confidant/qmd-corpus/` (ADR-6).
    ///
    /// The CLI owns corpus content, §12 clearance, decryption, and
    /// permissions; the `qmd-search` skill only registers/embeds on top.
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
        /// Rotate the inbox encryption key (drain-then-destroy, §8a.3).
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
    /// Add a new device: two-step ceremony (design §6).
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
    /// Rotate the inbox encryption key (drain-then-destroy, §8a.3).
    ///
    /// Drains the inbox with a normal run, generates a new X25519 keypair
    /// in the OS keychain, and updates `confidant.toml [inbox].pubkey` and
    /// the user-config pin. Re-pin every outside tool to the new key, then
    /// run `inbox rotate --finish` to destroy the old private key.
    ///
    /// When the old key is unavailable (lost, compromised, or revoked
    /// inbox device), the drain is skipped and there is no `--finish` to
    /// run: old-key items fail closed with `E_INBOX_CRYPTO` and the tools
    /// drop them again from source (§8a.2).
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
    let needs_vault = !matches!(
        cli.command,
        Command::Schema
            | Command::Help { .. }
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
        } => {
            let (unique, common) =
                confidant_core::bench::generate_realistic_vault(dir, *people, *notes, *cjk)?;
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
            cmd_find(json, &root, query, *limit)
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
            let files: Vec<String> = confidant_core::cleared_record_paths(&vault)
                .into_iter()
                .collect();
            let mut ledger: Vec<serde_json::Value> = Vec::new();
            for (file, lines) in confidant_core::cleared_ledger_lines(&vault) {
                for line in lines {
                    ledger.push(serde_json::json!({"file": file, "line": line}));
                }
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
            action,
        } => {
            let root = vault_root.unwrap();
            match action {
                Some(InboxAction::Rotate {
                    finish,
                    allow_unsigned: rotate_unsigned,
                }) => {
                    cmd_inbox_rotate(&root, user_config.as_ref(), json, *finish, *rotate_unsigned)
                }
                None => cmd_inbox(json, &root, user_config.as_ref(), *dry_run, *allow_unsigned),
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
            cmd_doctor(&cli, &root, *clear_pending_inbox_rotation)
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

fn cmd_find(json: bool, root: &Path, query: &str, limit: usize) -> anyhow::Result<ExitCode> {
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
    let result = match search(&vault, query) {
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
                "note: git not found; skipping gitignore check \
                 (nothing to commit the corpus with)"
            );
            return Ok(());
        }
        Ok(out) if !out.status.success() => {
            eprintln!("note: vault is not a git repo; skipping gitignore check");
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
        std::fs::write(&dst, rec.source.as_bytes())?;
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
        std::fs::write(&dst, kept.as_bytes())?;
        stats.files_copied += 1;
        // QMD collections match `**/*.md` only, so mirror each `.cfd` as a
        // sibling `.cfd.md` (as the skill did). The query script maps hits
        // back to the real `.cfd` path for verification.
        let mirror = tmp.join(format!("{file}.md"));
        std::fs::write(&mirror, kept.as_bytes())?;
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

/// Corpus dirs `0700`, files `0600` (B3). Applied recursively after the
/// build so every nested directory created for record paths is covered.
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

fn cmd_inbox(
    json: bool,
    root: &Path,
    user_config: Option<&UserConfig>,
    dry_run: bool,
    allow_unsigned: bool,
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
    let report = match confidant_core::run_inbox(
        root,
        &confidant_core::InboxOptions {
            dry_run,
            trusted_signers,
            allow_unsigned,
            pinned_pubkey,
        },
        &decrypt,
        inbox_keys.as_deref(),
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
                "warnings": report.warnings,
            }),
        ))?;
    } else {
        if report.empty {
            println!("inbox: nothing to do (no inbox branch)");
        } else if report.dry_run {
            println!(
                "inbox: dry run — {} item(s) would merge, {} would be skipped",
                report.merged,
                report.items.len() - report.merged
            );
        } else {
            println!(
                "inbox: {} item(s) merged into {}, {} cleared",
                report.merged, report.branch, report.cleared
            );
        }
        for i in &report.items {
            println!("  {}  {:<6}  {}  {}", i.name, i.kind, i.target, i.action);
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

/// Apply a record write through the encryption transform (spec 3).
///
/// Builds the [`record_crypto::RecordEncryptor`] for this vault: on an
/// encrypted vault the record `WriteFile`s become §14 envelopes; on a
/// `mode = "plaintext"` vault this is plain [`apply_write`]. Any
/// fail-closed mode error (unkeyed vault, `[crypto]` contradiction, key
/// failure) surfaces here, before anything is applied.
fn apply_record_write(
    root: &Path,
    vault: &confidant_core::vault::Vault,
    pending: PendingWrite,
    opts: &WriteOptions,
) -> anyhow::Result<WriteOutcome> {
    match record_crypto::RecordEncryptor::for_vault(root, vault)? {
        Some(enc) => {
            apply_write_with_encryptor(root, pending, opts, &move |p, b| enc.encrypt_file(p, b))
        }
        None => apply_write(root, pending, opts),
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
            field_lines: BTreeMap::new(),
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
    let outcome = apply_record_write(
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
    let outcome = apply_record_write(
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
    let outcome = apply_record_write(
        root,
        &vault,
        PendingWrite {
            changes: vec![FileChange::WriteFile {
                path: rel.clone(),
                contents,
            }],
            summary: format!("record {id}"),
            canonical_request: format!("record-add/v1\npath={}\nbody={}", rel.display(), text),
        },
        &write_options(cli),
    )?;
    finish_write(
        cli,
        root,
        "record-add",
        outcome,
        serde_json::json!({
            "id": id,
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
    let vault = match load_vault_for_reads(root, cli.json) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let person = RecordId::parse(person_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a record id: {person_raw}"))).context(
            "`context` takes an opaque person id; use `confidant find <name>` to look one up",
        )
    })?;
    let bundle = match build_context(&vault, &person, include_private) {
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

fn cmd_doctor(
    cli: &Cli,
    root: &Path,
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
    use confidant_crypt::{anchor, lifecycle::KeyStore};
    validate_keys_client_id(client_id)?;
    // B1: init-client accepts vault:shared (routes to keys/shared/).
    // shred refuses both reserved ids (handled in cmd_keys_shred).

    let config_dir = confidant_config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    let (anchor, _warnings) = anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
    let _identity = keys_device_identity()?;
    let operator_sk = load_operator_sk(&anchor)?;

    let vault = load_vault(root)?;
    let keys_dir = root.join("keys");
    let mut store = KeyStore::with_config_dir(keys_dir, &vault.config.vault_id, &config_dir)
        .map_err(anyhow::Error::new)?;
    let recipients = keys_current_recipients(&mut store, &anchor)?;
    store
        .init_client(client_id, &recipients, &anchor, &operator_sk)
        .map_err(anyhow::Error::new)?;

    // B2: one commit, check first.
    let no_input = cli.no_input;
    let pre = check_vault(&vault, &CheckOptions::default());
    if !pre.ok {
        return Err(anyhow::Error::new(DomainError::invalid(
            "check failed before committing keys/ tree",
        )));
    }
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
    use confidant_crypt::{anchor, lifecycle::KeyStore};
    validate_keys_client_id(client_id)?;

    let config_dir = confidant_config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    let (anchor, _warnings) = anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
    let _identity = keys_device_identity()?;
    let operator_sk = load_operator_sk(&anchor)?;

    let vault = load_vault(root)?;
    let keys_dir = root.join("keys");
    let mut store = KeyStore::with_config_dir(keys_dir, &vault.config.vault_id, &config_dir)
        .map_err(anyhow::Error::new)?;
    let _key = store
        .rotate(client_id, &anchor, &operator_sk)
        .map_err(anyhow::Error::new)?;
    let new_epoch = store.current_epoch(client_id).map_err(anyhow::Error::new)?;

    // B2: one commit, check first.
    let no_input = cli.no_input;
    let vault = load_vault(root)?;
    let pre = check_vault(&vault, &CheckOptions::default());
    if !pre.ok {
        return Err(anyhow::Error::new(DomainError::invalid(
            "check failed before committing keys/ tree",
        )));
    }
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
    use confidant_crypt::{anchor, lifecycle::KeyStore};
    validate_keys_client_id(client_id)?;

    let config_dir = confidant_config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    let (anchor, _warnings) = anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
    let _identity = keys_device_identity()?;
    let operator_sk = load_operator_sk(&anchor)?;

    let key_id_refs: Vec<&str> = key_ids.iter().map(|s| s.as_str()).collect();
    let vault = load_vault(root)?;
    let keys_dir = root.join("keys");
    let mut store = KeyStore::with_config_dir(keys_dir, &vault.config.vault_id, &config_dir)
        .map_err(anyhow::Error::new)?;
    store
        .revoke(client_id, &key_id_refs, &operator_sk, &anchor)
        .map_err(anyhow::Error::new)?;

    // B2: one commit, check first.
    let no_input = cli.no_input;
    let vault = load_vault(root)?;
    let pre = check_vault(&vault, &CheckOptions::default());
    if !pre.ok {
        return Err(anyhow::Error::new(DomainError::invalid(
            "check failed before committing keys/ tree",
        )));
    }
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
    use confidant_crypt::{anchor, lifecycle::KeyStore, manifest::RecipientEntry};

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
    let keys_dir = root.join("keys");
    let mut store = KeyStore::with_config_dir(keys_dir, &vault.config.vault_id, &config_dir)
        .map_err(anyhow::Error::new)?;
    // #154 must-fix 4: the retired-recovery / shredded-client denylist is
    // load-bearing here, so fail closed rather than warn when history is
    // unreadable (shallow clone, missing git, git log failure).
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
    // B2: every initialized client's every retained epoch + the lookup
    // key, all through KeyStore; verify-first inside add_recipient.
    // Item 7: add_recipient writes client-by-client, so an IO failure
    // mid-write can leave keys/ half-updated and uncommitted. Nothing is
    // committed on this path, so point at the exact recovery command
    // instead of attempting an in-code restore (which could clobber the
    // operator's own uncommitted work).
    let clients = store
        .add_recipient(&key_id, &entry, identity.as_ref(), &anchor, &operator_sk)
        .map_err(|e| {
            anyhow::Error::new(
                DomainError::invalid(format!(
                    "device-add failed; keys/ may be partially updated (nothing was committed): {e}"
                ))
                .with_fix(format!(
                    "inspect with `git -C {} status -- keys/`, then restore tracked files with \
                     `git -C {} checkout -- keys/` and delete any new untracked {key_id}*.age wrappings",
                    root.display(),
                    root.display(),
                )),
            )
        })?;

    // One commit, check first, signed by the operator key (design §6).
    let no_input = cli.no_input;
    let vault = load_vault(root)?;
    let pre = check_vault(&vault, &CheckOptions::default());
    if !pre.ok {
        // keys/ was already re-wrapped above; point at the exact recovery
        // command (#153 nit 5), matching add_recipient's own error path.
        return Err(anyhow::Error::new(
            DomainError::invalid(
                "check failed before committing keys/ tree; nothing was committed",
            )
            .with_fix(format!(
                "inspect with `git -C {} status -- keys/`, then restore tracked files with \
                 `git -C {} checkout -- keys/` and delete any new untracked {key_id}*.age wrappings",
                root.display(),
                root.display(),
            )),
        ));
    }
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
    let mut store =
        KeyStore::with_config_dir(keys_dir.clone(), &vault.config.vault_id, &config_dir)
            .map_err(anyhow::Error::new)?;
    let all_clients: Vec<String> = store
        .manifest_clients()
        .into_iter()
        .filter(|c| c != confidant_crypt::manifest::VAULT_CLIENT_ID)
        .collect();
    let all_refs: Vec<&str> = all_clients.iter().map(|s| s.as_str()).collect();

    // Fresh recipients for the re-wrap: a fresh keypair for THIS device
    // only, generated in memory. The fresh private key is NOT stored yet:
    // it is stored only after `KeyStore::shred` returns Ok. A refused
    // shred (verify-first) must leave this device's key unchanged, or the
    // device is locked out of the still-unshredded vault.
    // Other devices are NOT carried over — their old pubkeys would keep
    // the shredded history openable (strict pubkey-reuse check in
    // KeyStore::shred). They must re-enroll via `keys device-add`.
    let (fresh_device_key, new_recipients) = keys_shred_fresh_recipients()?;

    // B5: verify-first, strand check, history-derived destroy list all come
    // from KeyStore::shred — do not weaken them.
    let outcome = store
        .shred(
            client_id,
            &all_refs,
            &new_recipients,
            &operator_sk,
            &anchor,
            identity.as_ref(),
        )
        .map_err(anyhow::Error::new)?;

    // Shred's checks passed and the vault was re-wrapped to the fresh
    // keypair: store the fresh private key now. (If shred had refused,
    // the old key would still be enrolled and this device could keep
    // reading the vault.)
    store_rotated_device_key(&fresh_device_key)?;

    // B5: the CLI re-pins the anchor itself (new recovery halves) BEFORE
    // any other key operation. #99 ordering: anchor re-pinned before the
    // inbox rotation below. Uses atomic temp-and-rename replace (the
    // anchor already exists — save would refuse to overwrite).
    let no_input = cli.no_input;
    let new_recovery = outcome.new_recovery();
    anchor::replace(
        &config_dir,
        root,
        &anchor.operator,
        &new_recovery.verifying_key(),
        &new_recovery.age_identity().to_recipient_string(),
    )
    .map_err(anyhow::Error::new)?;

    // Re-sign the operator certificate with the new recovery key: it was
    // signed by the OLD recovery key, and without this a fresh-device
    // recover with the NEW phrase fails verify_operator_cert (silent
    // lockout). Same staleness bug as #149's recover path.
    anchor::write_operator_cert(
        &keys_dir,
        &vault.config.vault_id,
        &anchor.operator,
        new_recovery.signing_key(),
    )
    .map_err(anyhow::Error::new)?;

    // Show the new phrase BEFORE any further fallible steps (commit,
    // inbox rotation): if they fail, the operator still has the phrase.
    let phrase = outcome.recovery_phrase_for_display();
    display_phrase_once(no_input, &phrase)?;

    // B2: one commit, check first.
    let vault = load_vault(root)?;
    let pre = check_vault(&vault, &CheckOptions::default());
    if !pre.ok {
        return Err(anyhow::Error::new(DomainError::invalid(
            "check failed before committing keys/ tree",
        )));
    }
    stage_keys(root, no_input)?;
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

    if cli.json {
        print_json(&serde_json::json!({
            "ok": true,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": root.to_string_lossy(),
            "client_id": client_id,
            "destroy_key_ids": outcome.destroy_key_ids,
            "warnings": shred_warnings,
            "inbox_rotated": inbox_rotated,
            "device_key_rotated": true,
            "note": "this device was re-enrolled with a fresh keypair; other devices must re-enroll via `keys device-add`",
        }))?;
    } else {
        println!("shredded client {client_id}");
        println!("device key rotated: this device was re-enrolled with a fresh keypair");
        println!("other devices were removed: re-enroll them with `keys device-add`");
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
