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
mod pack_fetch;
mod pack_init;
mod record_crypto;
mod record_decrypt;
mod record_resolve;
mod setup;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
#[cfg(not(feature = "test-overrides"))]
use std::io::IsTerminal;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use confidant_core::check::parse_fail_on;
use confidant_core::config::parse_iso_date;
use confidant_core::config::UserConfig;
use confidant_core::context::build_context;
use confidant_core::discover::{load_user_config, resolve, Discovery};
use confidant_core::error::{DomainError, ErrorKind};
use confidant_core::id::{Prefix, RecordId};
use confidant_core::ledger::{parse_duration_minutes, parse_strict_date};
use confidant_core::packs::dir::read_pack_dir;
use confidant_core::packs::lock::read_lockfile;
use confidant_core::record::{main_record_path, Record, RecordKind};
use confidant_core::schema::contract_schema;
use confidant_core::scope::{owner_labels, parse_pack_list, resolve_scope, PackScope};
use confidant_core::write::{
    apply_write, apply_write_repairing, apply_write_with_encryptor, require_git_repo, FileChange,
    PendingWrite, WriteOptions, WriteOutcome,
};
use confidant_core::{check_vault, load_vault, search, search_for_operator, CheckOptions};
use confidant_core::{ContentHook, ContentOutcome};
use serde_json::Value;
use zeroize::Zeroizing;

/// Attach a `DomainError` fix hint to an `anyhow::Error`.
///
/// `DomainError::with_fix` returns the domain error, so
/// `anyhow::Error::new(DomainError::…)` would lose it. This keeps the fix on
/// the common `Err(anyhow::Error::new(DomainError::…).with_fix(…))` shape.
/// A non-`DomainError` error is returned unchanged (it has no fix slot).
trait FixExt {
    fn with_fix(self, fix: &str) -> Self;
}

impl FixExt for anyhow::Error {
    fn with_fix(self, fix: &str) -> Self {
        match DomainError::of(&self) {
            Some(domain) => anyhow::Error::new(domain.clone().with_fix(fix)),
            None => self,
        }
    }
}

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

    /// Pack scope for reads (`find`, `context`, `allowlist`,
    /// `record list`) and `mcp`. Comma-separated pack names, e.g.
    /// `example-pack@0.1`. Unset = all enabled packs. Naming an unknown or
    /// disabled pack is a hard error. `init --create` also uses it to seed
    /// the vault's `packs` list, where only packs built into this binary
    /// are accepted. Ignored by `check` / `doctor` (always unscoped) and by
    /// other writes.
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
    ///
    /// Operator-only flag: `--for-operator` includes `no-ai` records the
    /// default (agent) allowlist hides. It is never passed by MCP.
    Find {
        /// Case-insensitive substring.
        query: String,
        /// Max hits to print.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Include `no-ai` records, decrypted through the operator read
        /// path (the same mechanism as `record show --for-edit`).
        #[arg(long)]
        for_operator: bool,
    },
    /// Print the cleared set (cleared record files and ledger lines)
    /// for index-time corpus exclusion.
    ///
    /// Read-only: emits opaque paths and line numbers only, never content.
    /// The query-time allowlist stays the authority; this only narrows what
    /// an indexer copies into its local corpus.
    Allowlist,
    /// Resolve a person by `p-<ULID>` or exact display name (read-only).
    ///
    /// A display name matches the §12 cleared set exactly (trimmed,
    /// case-insensitive, whole-string), so `no-ai: notes` people resolve by
    /// name and `no-ai: true` people only by id. Names are canonicalized
    /// across merges; an ambiguous name fails closed (`E_AMBIGUOUS_PERSON`).
    Resolve {
        /// A `p-<ULID>` or an exact display name (cleared records only).
        query: String,
    },
    /// Add or resolve person aliases (email/phone/handle → keyed HMAC).
    ///
    /// The raw alias value is PII: it is read from stdin or `--value-file`
    /// only, never an argument, and never echoed in output or errors.
    /// Operator-only.
    Alias {
        #[command(subcommand)]
        action: AliasAction,
    },
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
        /// Discard items by stem (repeatable) without merging them: remove
        /// them from the `inbox` branch in one signed commit. For an item
        /// the operator chose not to apply after `record resolve
        /// --from-inbox`. Unknown stems fail closed (`E_INBOX_SKIP`); a
        /// moved tip refuses (`E_INBOX_RACE`).
        #[arg(long)]
        discard: Vec<String>,
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
    /// Fetch and review a candidate pack (read-only; writes nothing).
    ///
    /// Operator-only: `pack` is not in the MCP tool whitelist.
    Pack {
        #[command(subcommand)]
        action: PackAction,
    },
    /// Context bundle for one person (honors no-ai).
    ///
    /// Operator-only flag: `--for-operator` includes `no-ai` records the
    /// default (agent) allowlist hides. It is never passed by MCP.
    Context {
        /// Opaque person id (p-…) or an exact display name (cleared people
        /// only; see `confidant resolve`).
        person: String,
        /// Strip private data: name, profile, bodies, and the personal pack's
        /// PII fields (`birthday`, `dates`, `relationship`, `location`,
        /// `emails`, `phones`, `links`, `tags`).
        #[arg(long)]
        exclude_private: bool,
        /// Include `no-ai` records, decrypted through the operator read
        /// path (the same mechanism as `record show --for-edit`).
        #[arg(long)]
        for_operator: bool,
    },
    /// Vault health checks (the crypto check reports encryption availability).
    Doctor {
        /// Clear the pending inbox-rotation reminder (written by `keys shred`
        /// on a non-inbox device). Requires confirmation unless --no-input.
        #[arg(long)]
        clear_pending_inbox_rotation: bool,
    },
    /// Clear this machine's Confidant state so a new vault starts clean.
    ///
    /// Machine state only: this command never reads, writes, or deletes
    /// anything inside a vault. It removes `trust.toml`, `manifest-seq.toml`
    /// and `inbox-rotation-pending.toml` from `~/.config/confidant/`, the
    /// `default_vault`, `[vaults]`, `[trust].signers` and `[inbox].pubkey`
    /// entries from `config.toml`, and this machine's device, operator and
    /// inbox keys from the OS keychain.
    ///
    /// It refuses when any resolvable vault has a `keys/` tree, because
    /// removing the anchor and keys would break it. It checks `--vault`,
    /// `CONFIDANT_VAULT` (a path or a `[vaults]` name), a walk-up from the
    /// current directory, `default_vault`, and every `[vaults]` entry — even
    /// when discovery itself would fail — and names every initialized vault
    /// in the error. `--force` overrides the guard only for vaults you have
    /// retired. Use the global `--dry-run` to see the plan; `--yes` (or an
    /// interactive `y`) is required to remove anything. JSON always reports
    /// `"vault": null`: this command is machine state, not vault-scoped.
    Reset {
        /// Machine state only. Required: there is no vault-scoped reset.
        #[arg(long, required = true)]
        machine_state: bool,
        /// Remove without asking. Required with --no-input or --json.
        #[arg(long)]
        yes: bool,
        /// Proceed even when a resolvable vault has a keys/ tree.
        #[arg(long)]
        force: bool,
    },
    /// Initialize the vault's trust anchor and keys (first device).
    ///
    /// Generates the operator key, a 24-word recovery phrase (shown once on
    /// stderr, or written to `--phrase-out`), and this device's key; writes
    /// the trust anchor to ~/.config/confidant/trust.toml; creates the vault
    /// lookup key and the vault:shared client. Requires a git repo with a
    /// clean tree. This is for a *new* vault. To put an existing vault on
    /// another device, clone it and run `keys device-add` (not `init`;
    /// `recover` only if every enrolled device is lost).
    ///
    /// With `--create`, an empty or absent vault directory is scaffolded
    /// first: the directory is created, `git init` runs when needed and the
    /// branch is set to `main`, `.gitignore` gains `.confidant/`, and a
    /// minimal `confidant.toml` is written (its `packs` list comes from the
    /// global `--packs` flag, defaulting to `[]`) and committed. `--remote
    /// <url>` then adds `origin` (it does not push). Only packs built into
    /// this binary (today the implicit `personal@0.2`) may be listed: an
    /// external pack is vendored into an existing vault by `confidant pack
    /// add`, so install it after `init`. The key steps then run unchanged.
    ///
    /// `--dry-run` runs every preflight check and reports the plan without
    /// creating a directory, writing a file, making a commit, generating
    /// keys, adding a remote, or touching the keychain.
    Init {
        /// Replace an existing trust anchor after initialization succeeds.
        /// Never re-initializes an existing `keys/` tree (that is refused).
        #[arg(long)]
        force: bool,
        /// Scaffold the vault directory (create, `git init`, `.gitignore`,
        /// `confidant.toml`, committed skeleton) before initializing keys.
        #[arg(long)]
        create: bool,
        /// Write the 24-word recovery phrase to this new file (mode 0600)
        /// instead of printing it. Refuses to overwrite. The phrase never
        /// appears on stdout, stderr, or in JSON; move the file offline and
        /// delete it after writing the phrase down.
        #[arg(long, value_name = "PATH")]
        phrase_out: Option<PathBuf>,
        /// Add `git remote origin URL` after scaffolding. Does not push
        /// (credentials and host keys stay yours). Requires `--create`.
        #[arg(long, value_name = "URL", requires = "create")]
        remote: Option<String>,
    },
    /// Recover the vault after every enrolled device is lost.
    ///
    /// The phrase arrives via stdin or --phrase-file only (never as an
    /// argument). Requires a fresh device (no device key enrolled yet).
    /// Rotates to a new recovery phrase and drops other devices' wrappings.
    /// To add a second device while one is still enrolled, clone the vault
    /// and run `keys device-add` instead.
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
    /// Launch the terminal UI (`confidant-tui` on PATH).
    ///
    /// Finds `confidant-tui` on PATH and runs it with any extra arguments;
    /// the environment is inherited, so `CONFIDANT_VAULT` and `CONFIDANT_BIN`
    /// pass through. An explicit `--vault` on this command is forwarded to
    /// the TUI the same way. Needs a `confidant` binary on PATH that speaks
    /// the same agent contract — install both with
    /// `cargo install confidant-cli confidant-tui`.
    Tui {
        /// Arguments passed through verbatim to `confidant-tui`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
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
        /// Write a touch-heavy ledger (#188).
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
    /// Verify a saved recovery phrase against this vault (read-only).
    ///
    /// The phrase arrives via stdin or `--phrase-file` only (never as an
    /// argument). Works on an enrolled device and on a fresh device: it
    /// needs no device key and writes nothing (no config dir, no `keys/`,
    /// no git, no keychain). Exits 0 only when the phrase matches the
    /// pinned public halves and opens every current client's wrapping.
    VerifyRecovery {
        /// File containing the 24-word recovery phrase (alternative to stdin).
        #[arg(long)]
        phrase_file: Option<PathBuf>,
    },
    /// Add a new device: two-step ceremony.
    ///
    /// On the new device, `keys device-add --initiate` emits a request
    /// carrying only the public key + a label — the private key never
    /// leaves the device. With an OS keychain it generates and stores the
    /// keypair. On a headless host, set `CONFIDANT_DEVICE_KEY` to this
    /// device's age identity first; `--initiate` uses that value and does
    /// not write a keychain. On an already-enrolled device,
    /// `keys device-add --from-request <file>` verifies the fingerprint
    /// out of band, re-wraps every client's every retained epoch plus the
    /// vault lookup key to the new device, and commits.
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
        /// Opaque person id (p-…) or an exact display name (cleared people
        /// only; see `confidant resolve`).
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
    /// Append a personal touchpoint ledger line, e.g. `log touch p-… meal`.
    Touch {
        /// Opaque person id (p-…) or an exact display name (cleared people
        /// only; see `confidant resolve`).
        person: String,
        /// Touchpoint kind: call, text, email, meet, meal, event, gift, or other.
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
enum AliasAction {
    /// Append an alias ledger line: `DATE alias <p-ULID> KIND hmac:HEX`.
    ///
    /// The raw value (email, phone, or handle) is read from stdin or
    /// `--value-file` only — never an argument — and is never echoed in
    /// output, errors, or logs. One commit; check-gated.
    Add {
        /// Opaque person id (p-…) or an exact display name (cleared people
        /// only; see `confidant resolve`).
        person: String,
        /// Alias kind: email, phone, or handle.
        kind: String,
        /// File holding the alias value (alternative to stdin).
        #[arg(long, value_name = "FILE")]
        value_file: Option<PathBuf>,
        /// Alias date YYYY-MM-DD (default today).
        #[arg(long)]
        date: Option<String>,
    },
    /// Resolve a `kind` + value alias to the canonical person (read-only).
    ///
    /// The raw value is read from stdin or `--value-file` only — never an
    /// argument. Honors `no-ai` like other reads: an alias on a `no-ai: true`
    /// person is not surfaced.
    Resolve {
        /// Alias kind: email, phone, or handle.
        kind: String,
        /// File holding the alias value (alternative to stdin).
        #[arg(long, value_name = "FILE")]
        value_file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum PackAction {
    /// Scaffold a local external pack directory (no vault needed).
    ///
    /// Writes `manifest.toml`, `SKILL.md`, `<version>.md` and `README.md`.
    /// The directory must be new or empty; nothing is overwritten and a
    /// symlink is refused. The generated pack is validated before the
    /// command succeeds. `--dry-run` prints the plan and writes nothing.
    Init {
        /// Directory to create (or an empty directory to fill).
        dir: PathBuf,
        /// Pack name (default: the directory basename).
        #[arg(long)]
        name: Option<String>,
        /// Pack version, `major.minor` (default: 0.1).
        #[arg(long)]
        version: Option<String>,
    },
    /// Fetch a candidate pack, validate it, and print a review report.
    ///
    /// Writes nothing to the vault unless `--yes` is given: with it, the
    /// reviewed files are vendored, pinned in `confidant.lock`, added to
    /// `packs` in `confidant.toml`, checked and committed once (PD10).
    Add {
        /// `https://` git URL, optionally `#<ref>` (tag, branch or commit).
        url: Option<String>,
        /// Fetch from a local directory instead of the network.
        #[arg(long)]
        from_dir: Option<PathBuf>,
        /// Path inside the fetched repository holding the pack.
        #[arg(long)]
        subdir: Option<String>,
        /// Apply the install (vendor, lock, add to `packs`, commit).
        #[arg(long)]
        yes: bool,
    },
    /// List installed external packs and their verification status.
    List,
    /// Verify vendored pack files against `confidant.lock` (exit 1 on mismatch).
    Verify {
        /// Only this pack (default: every installed pack).
        name: Option<String>,
    },
    /// Remove an installed pack: files, lockfile entry and `packs` entry.
    Remove {
        /// Pack name as installed (without `@version`).
        name: String,
        /// Apply the removal.
        #[arg(long)]
        yes: bool,
    },
    /// Update an installed pack to a new rev, printing the diff first.
    Update {
        /// Pack name as installed (without `@version`).
        name: String,
        /// New git rev: a full 40-hex commit, or a tag/branch name.
        #[arg(long)]
        rev: Option<String>,
        /// Update from a local directory instead of the network.
        #[arg(long)]
        from_dir: Option<PathBuf>,
        /// Apply the update.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum RecordAction {
    /// Add a record from a markdown file (front matter must include id and type).
    Add {
        #[arg(long)]
        file: PathBuf,
    },
    /// Replace an existing main record's file from a markdown file.
    Edit {
        /// Opaque record id (p-…, o-…, d-…, i-…). Must match `id:` in the file.
        id: String,
        /// Markdown file holding the new version of the record.
        #[arg(long)]
        file: PathBuf,
    },
    /// List the vault's records of one kind, one entry each.
    ///
    /// Operator-only. This command is never exposed over MCP (`mcp.rs` maps
    /// a fixed tool whitelist), and without `--for-operator` it lists only
    /// the §12 cleared set, so `no-ai: true` records are absent. With
    /// `--for-operator` an operator may see them, with a tri-state
    /// `no_ai` (`"true"`, `"notes"`, `"false"`). The resolved vault path
    /// stays in the JSON envelope (ADR-7).
    List {
        /// Include `no-ai` records, decrypted through the operator read
        /// path (the same mechanism as `record show --for-edit`).
        #[arg(long)]
        for_operator: bool,
        /// Record kind to list.
        #[arg(long, value_enum, default_value_t = RosterKind::Person)]
        kind: RosterKind,
    },
    /// Print one record's decrypted text, to prepare an edit.
    ///
    /// Operator-only. This command is never exposed over MCP (`mcp.rs` maps
    /// a fixed tool whitelist), and `--for-edit` is required so a bare
    /// invocation cannot print a decrypted record body.
    Show {
        /// Opaque record id (p-…, o-…, d-…, i-…, e-…).
        id: String,
        /// Acknowledge the operator-only edit read. Required.
        #[arg(long)]
        for_edit: bool,
    },
    /// Resolve a merge conflict on a record.
    ///
    /// Operator-only. This command is never exposed over MCP (`mcp.rs` maps
    /// a fixed tool whitelist). Exactly one action flag is required; a bare
    /// invocation is a usage error. `--show` prints both sides (#453);
    /// `--take` keeps one side byte for byte (#454); `--merged-file` and
    /// `--edit` land in #455.
    ///
    /// `--from-inbox <stem>` switches the conflict source from git conflict
    /// markers to an inbox item (#457): `ours` is the current record on
    /// main, `theirs` is the inbox item's plaintext. The actions are the
    /// same; `--take theirs` encrypts the item through the `record edit`
    /// path (there is no envelope to keep byte for byte).
    #[command(group(
        clap::ArgGroup::new("resolve_action").required(true).multiple(false)
    ))]
    Resolve {
        /// Opaque record id (p-…, o-…, d-…, e-…).
        id: String,
        /// Resolve against an inbox item instead of git conflict markers.
        /// The stem is the item's file stem on the `inbox` branch.
        #[arg(long)]
        from_inbox: Option<String>,
        /// Print both decrypted versions to stdout.
        #[arg(long, group = "resolve_action")]
        show: bool,
        /// Keep one side's version byte for byte, staged but not committed.
        #[arg(long, value_enum, group = "resolve_action")]
        take: Option<Side>,
        /// Hand-merge from a file outside the vault (see #455).
        #[arg(long, group = "resolve_action")]
        merged_file: Option<PathBuf>,
        /// Hand-merge in $VISUAL/$EDITOR with 0600 scratch files (see #455).
        #[arg(long, group = "resolve_action")]
        edit: bool,
        /// Skip inbox signature verification for `--from-inbox` write
        /// actions (same escape hatch as `inbox --allow-unsigned`).
        #[arg(long, requires = "from_inbox")]
        allow_unsigned: bool,
    },
}

/// Which side of a merge conflict to keep (`record resolve --take`).
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum Side {
    Ours,
    Theirs,
}

impl Side {
    /// The CLI spelling used in output (`--json` and human text).
    pub(crate) fn name(self) -> &'static str {
        match self {
            Side::Ours => "ours",
            Side::Theirs => "theirs",
        }
    }
}

/// Record kinds `record list --kind` accepts (#558).
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum RosterKind {
    Person,
    Org,
    Deal,
}

impl RosterKind {
    /// The core record kind this filter names.
    pub(crate) fn record_kind(self) -> RecordKind {
        match self {
            RosterKind::Person => RecordKind::Person,
            RosterKind::Org => RecordKind::Org,
            RosterKind::Deal => RecordKind::Deal,
        }
    }
}

#[derive(Subcommand, Debug)]
enum NoteAction {
    /// Create a note record under people/<person>/notes/.
    Add {
        /// Opaque person id (p-…) or an exact display name (cleared people
        /// only; see `confidant resolve`).
        #[arg(long)]
        person: String,
        /// Note date YYYY-MM-DD (default today).
        #[arg(long)]
        date: Option<String>,
        /// Mark this note no-ai.
        #[arg(long)]
        no_ai: bool,
        /// Force the note id (`n-<ULID>`) instead of minting one. Used by
        /// the TUI apply so the reviewed dry-run and the commit name the
        /// same note (#611); the id comes from the proposal manifest.
        #[arg(long)]
        id: Option<String>,
        /// File holding the note body.
        #[arg(long)]
        body_file: PathBuf,
    },
    /// Print one note's decrypted text, to prepare an edit.
    ///
    /// Operator-only. This command is never exposed over MCP (`mcp.rs` maps
    /// a fixed tool whitelist), and `--for-edit` is required so a bare
    /// invocation cannot print a decrypted note body. Notes are where
    /// `no-ai` prose lives, so `no-ai` notes are decrypted in full here
    /// (same operator path as `record show --for-edit`).
    Show {
        /// Opaque note id (n-…).
        id: String,
        /// Acknowledge the operator-only edit read. Required.
        #[arg(long)]
        for_edit: bool,
    },
    /// Replace an existing note's file from a markdown file or the editor.
    ///
    /// Operator-only (never exposed over MCP). Exactly one source is
    /// required: `--file` reads the new note from a markdown file, `--edit`
    /// opens $VISUAL/$EDITOR on 0600 scratch under `.confidant/` (the #455
    /// convention). The write goes through the normal pipeline, so in an
    /// encrypted vault it re-encrypts, runs `check` before the commit, and
    /// makes one commit; identical bytes report `unchanged` and commit
    /// nothing.
    #[command(group(
        clap::ArgGroup::new("note_edit_source").required(true).multiple(false)
    ))]
    Edit {
        /// Opaque note id (n-…).
        id: String,
        /// Markdown file holding the new version of the note.
        #[arg(long, group = "note_edit_source")]
        file: Option<PathBuf>,
        /// Edit the note in $VISUAL/$EDITOR with 0600 scratch files.
        #[arg(long, group = "note_edit_source")]
        edit: bool,
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

    // Bootstrap (#539): `confidant init --create` scaffolds the vault before
    // discovery, because discovery requires `confidant.toml`. Runs first so
    // the key steps (which require a clean tree) see a committed skeleton.
    // Without `--create` this is a no-op and `init`'s behaviour is unchanged.
    //
    // #651: a scaffold is held in an armed guard until the key steps and the
    // anchor save succeed, so any failure removes only what this command
    // created. #649: with `--dry-run` the guard is never created because
    // bootstrap writes nothing and returns `DryRun` instead.
    let mut scaffold = match &cli.command {
        Command::Init { force, create, .. } => match bootstrap_vault(&cli, *create, *force)? {
            BootstrapPlan::DryRun => return Ok(ExitCode::SUCCESS),
            BootstrapPlan::Continue(scaffold) => scaffold,
        },
        _ => None,
    };

    // `schema` and `help` work without a vault; everything else needs one.
    // Every JSON response still carries the resolved vault (possibly null).
    // `device-add --initiate` runs on a brand-new device that has no vault
    // yet; everything else needs one.
    // `setup` / `update` / `agents` / `which` / `routing` / `tui` manage the
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
            | Command::Tui { .. }
            | Command::BenchGen { .. }
            | Command::Reset { .. }
            | Command::Pack { .. }
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
        Command::Find {
            query,
            limit,
            for_operator,
        } => {
            let root = vault_root.unwrap();
            cmd_find(
                json,
                &root,
                query,
                *limit,
                cli.packs.as_deref(),
                *for_operator,
            )
        }
        Command::Resolve { query } => {
            let root = vault_root.unwrap();
            cmd_resolve(&cli, &root, query)
        }
        Command::Alias { action } => {
            let root = vault_root.unwrap();
            match action {
                AliasAction::Add {
                    person,
                    kind,
                    value_file,
                    date,
                } => cmd_alias_add(
                    &cli,
                    &root,
                    person,
                    kind,
                    value_file.as_deref(),
                    date.clone(),
                ),
                AliasAction::Resolve { kind, value_file } => {
                    cmd_alias_resolve(&cli, &root, kind, value_file.as_deref())
                }
            }
        }
        Command::Allowlist => {
            let root = vault_root.unwrap();
            // Spec 4: the allowlist is a read path — decrypted records
            // participate, skipped ones are excluded by omission.
            let vault = match load_vault_for_reads(&root, json, false) {
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
            discard,
            action,
        } => {
            let root = vault_root.unwrap();
            // #457: `--discard` removes items without merging. It does not
            // combine with the drain or with rotate.
            if !discard.is_empty() {
                if action.is_some() {
                    return Err(anyhow::Error::new(DomainError::usage(
                        "`inbox --discard` does not combine with `inbox rotate`",
                    )));
                }
                return cmd_inbox_discard(json, &root, discard);
            }
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
                    id,
                    body_file,
                } => cmd_note_add(
                    &cli,
                    &root,
                    person,
                    date.clone(),
                    *no_ai,
                    id.as_deref(),
                    body_file,
                ),
                NoteAction::Show { id, for_edit } => cmd_note_show(&cli, &root, id, *for_edit),
                NoteAction::Edit { id, file, edit } => {
                    cmd_note_edit(&cli, &root, id, file.as_deref(), *edit)
                }
            }
        }
        Command::Pack { action } => match action {
            PackAction::Init { dir, name, version } => {
                cmd_pack_init(&cli, dir, name.as_deref(), version.as_deref())
            }
            PackAction::Add {
                url,
                from_dir,
                subdir,
                yes,
            } => cmd_pack_add(
                &cli,
                vault_root.as_deref(),
                url.as_deref(),
                from_dir.as_deref(),
                subdir.as_deref(),
                *yes,
            ),
            PackAction::List => {
                cmd_pack_list(&cli, vault_root.as_deref()).map_err(pack_fetch::escape_domain_error)
            }
            PackAction::Verify { name } => {
                cmd_pack_verify(&cli, vault_root.as_deref(), name.as_deref())
                    .map_err(pack_fetch::escape_domain_error)
            }
            PackAction::Remove { name, yes } => {
                cmd_pack_remove(&cli, vault_root.as_deref(), name.clone(), *yes)
                    .map_err(pack_fetch::escape_domain_error)
            }
            PackAction::Update {
                name,
                rev,
                from_dir,
                yes,
            } => cmd_pack_update(
                &cli,
                vault_root.as_deref(),
                name.clone(),
                rev.as_deref(),
                from_dir.as_deref(),
                *yes,
            )
            .map_err(pack_fetch::escape_domain_error),
        },
        Command::Record { action } => {
            let root = vault_root.unwrap();
            match action {
                RecordAction::Add { file } => cmd_record_add(&cli, &root, file),
                RecordAction::Edit { id, file } => cmd_record_edit(&cli, &root, id, file),
                RecordAction::List { for_operator, kind } => {
                    cmd_record_list(&cli, &root, kind.record_kind(), *for_operator)
                }
                RecordAction::Show { id, for_edit } => cmd_record_show(&cli, &root, id, *for_edit),
                RecordAction::Resolve {
                    id,
                    from_inbox,
                    show,
                    take,
                    merged_file,
                    edit,
                    allow_unsigned,
                } => cmd_record_resolve(
                    &cli,
                    &root,
                    user_config.as_ref(),
                    id,
                    from_inbox.as_deref(),
                    *show,
                    *take,
                    merged_file.as_deref(),
                    *edit,
                    *allow_unsigned,
                ),
            }
        }
        Command::Context {
            person,
            exclude_private,
            for_operator,
        } => {
            let root = vault_root.unwrap();
            cmd_context(&cli, &root, person, !exclude_private, *for_operator)
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
        Command::Reset { yes, force, .. } => cmd_reset_machine_state(&cli, *yes, *force),
        Command::Init {
            force, phrase_out, ..
        } => {
            let root = vault_root.unwrap();
            cmd_init(&cli, &root, *force, scaffold.take(), phrase_out.as_deref())
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
                        KeysAction::VerifyRecovery { phrase_file } => {
                            cmd_keys_verify_recovery(&cli, &root, phrase_file.as_deref())
                        }
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
        Command::Tui { args } => cmd_tui(&cli, args),
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
    let (enabled, _) = vault.pack_registry().resolve_enabled(&vault.config.packs);
    let scope = resolve_scope(
        requested.as_deref(),
        &enabled,
        vault.pack_registry().implicit(),
    )?;
    let names = scope.names(&enabled);
    Ok((scope, names))
}

/// Load the vault for a read command (`find`/`context`, spec 4). Two-phase:
/// phase 1 loads without the hook to get the vault id for AAD; phase 2
/// reloads with the decryptor hook so envelopes decrypt (or skip + count).
/// Reads never fail for a missing key — that is a per-record skip (⚠2).
/// Load the vault for a read command, decrypting record envelopes.
///
/// `operator` selects the reader mode: `false` is the agent read path
/// (`no-ai` records come back as keyless shells), `true` is the operator
/// edit path, used only by `record show --for-edit` (#216).
fn load_vault_for_reads(
    root: &Path,
    json: bool,
    operator: bool,
) -> Result<confidant_core::Vault, ExitCode> {
    let probe = match load_vault(root) {
        Ok(v) => v,
        Err(err) => {
            let _ = print_error(json, Some(&root.display().to_string()), &err);
            return Err(ExitCode::from(err.exit_code() as u8));
        }
    };
    let decryptor = std::sync::Arc::new(if operator {
        record_decrypt::RecordDecryptor::for_edit(root, &probe.config.vault_id)
    } else {
        record_decrypt::RecordDecryptor::for_reads(root, &probe.config.vault_id)
    });
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

/// Quote one argument for the `next_steps` command hint. This is display
/// text, not an exec path: single quotes keep spaces (and `$`, `;`, …) in a
/// copied command from splitting.
fn shell_quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '~'));
    if safe {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// `pack init <dir>`: scaffold a local external pack (#674).
///
/// No vault is needed and nothing outside `dir` is touched. The generated
/// pack is read back with the installer's readers before success is
/// reported, so a scaffold cannot be born broken.
fn cmd_pack_init(
    cli: &Cli,
    dir: &Path,
    name: Option<&str>,
    version: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let report = pack_init::init(dir, name, version, cli.dry_run)
        .map_err(pack_fetch::escape_domain_error)?;
    let dir_arg = shell_quote(&report.dir.display().to_string());
    let review = format!("confidant pack add --from-dir {dir_arg}");
    let install = format!("{review} --yes");

    if cli.json {
        print_json(&ok_envelope(
            None,
            serde_json::json!({
                "command": "pack-init",
                "dry_run": report.dry_run,
                "dir": report.dir.display().to_string(),
                "name": report.name,
                "version": report.version,
                "files": report.files,
                "next_steps": {
                    "review": review,
                    "install": install,
                },
            }),
        ))?;
        return Ok(ExitCode::SUCCESS);
    }

    let verb = if report.dry_run {
        "would create"
    } else {
        "created"
    };
    println!(
        "{verb} {}@{} in {}",
        pack_fetch::escape_line(&report.name),
        pack_fetch::escape_line(&report.version),
        pack_fetch::escape_line(&report.dir.display().to_string())
    );
    println!("files:");
    for file in &report.files {
        println!("  {file}");
    }
    println!("next:");
    println!("  review   {}", pack_fetch::escape_line(&review));
    println!("  install  {}", pack_fetch::escape_line(&install));
    if report.dry_run {
        println!("dry run: nothing was written");
    }
    Ok(ExitCode::SUCCESS)
}

/// Fetch a candidate pack, validate it, and print a review report (#439),
/// or apply the install with `--yes` (#440).
///
/// Without `--yes` it is read-only: the fetch happens in a temp directory and
/// nothing under the vault is created. Operator-only: `pack` is not in the
/// MCP tool whitelist.
fn cmd_pack_add(
    cli: &Cli,
    vault_root: Option<&Path>,
    url: Option<&str>,
    from_dir: Option<&Path>,
    subdir: Option<&str>,
    yes: bool,
) -> anyhow::Result<ExitCode> {
    // The pack reader, manifest parser and git all quote untrusted
    // repository text; escape it before any error reaches the terminal or
    // the JSON error envelope (#499).
    cmd_pack_add_inner(cli, vault_root, url, from_dir, subdir, yes)
        .map_err(pack_fetch::escape_domain_error)
}

/// #694: refuse `pack add --yes` before the generic pre-check when the
/// vault already references the pack without listing it. The pre-check
/// cannot pass while the pack's `[checks]` keys are unresolvable, and an
/// unlisted vendored copy is an ambiguous install state rather than
/// something the add should silently paper over. Both cases have the same
/// one-line fix: list the exact `name@version` (or remove the dependent
/// `[checks]` keys) first.
fn preflight_unlisted_pack(
    root: &Path,
    cfg: &confidant_core::config::VaultConfig,
    report: &pack_fetch::PackReport,
) -> anyhow::Result<()> {
    let has_checks = checks_reference_pack(cfg, &report.name);
    let rel = vendored_rel(&report.name, &report.version);
    // Fail closed on an unreadable `packs/` entry: treat it as present.
    let vendored = confidant_core::paths::exists(root, Path::new(&rel)).unwrap_or(true);
    if !has_checks && !vendored {
        return Ok(());
    }
    let name = pack_fetch::escape_line(&report.name);
    let version = pack_fetch::escape_line(&report.version);
    let rel = pack_fetch::escape_line(&rel);
    let listed = format!("{name}@{version}");
    let checks_fix = format!(
        "Add \"{listed}\" to `packs` in confidant.toml first (or remove the [checks] keys under `{name}.`), then re-run `confidant pack add`"
    );
    let (message, fix) = match (has_checks, vendored) {
        (true, true) => (
            format!(
                "{listed} is not listed in `packs`, but the vault already vendors it at {rel} and sets its [checks] keys"
            ),
            checks_fix,
        ),
        (true, false) => (
            format!(
                "{listed} is not listed in `packs`, but the vault already sets its [checks] keys; the pre-write check cannot pass until the pack is listed"
            ),
            checks_fix,
        ),
        (false, true) => (
            format!("{listed} is already vendored at {rel} but is not listed in `packs`"),
            format!(
                "Add \"{listed}\" to `packs` in confidant.toml to use the vendored copy, then re-run `confidant pack add`"
            ),
        ),
        (false, false) => unreachable!("preflight requires a reason"),
    };
    Err(anyhow::Error::new(DomainError::invalid(message)).with_fix(&fix))
}

/// Whether any `[checks]` leaf in `cfg` names `name` or sits under it
/// (`name.` prefix). Dotted TOML keys and `[checks.name]` tables both parse
/// as nested tables, so walk the tree to the leaves.
fn checks_reference_pack(cfg: &confidant_core::config::VaultConfig, name: &str) -> bool {
    fn walk<'a, I>(prefix: &str, entries: I, name: &str) -> bool
    where
        I: IntoIterator<Item = (&'a String, &'a toml::Value)>,
    {
        entries.into_iter().any(|(key, value)| {
            let dotted = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            if dotted == name || dotted.starts_with(&format!("{name}.")) {
                return true;
            }
            match value {
                toml::Value::Table(table) => walk(&dotted, table.iter(), name),
                _ => false,
            }
        })
    }
    walk("", cfg.checks.rules.iter(), name)
}

/// #694: a stderr hint after `pack add --yes` is blocked, tailored to the
/// findings that name this pack's data. Returns `None` when the block is
/// unrelated (for example a pack conflict), so the hint never misdiagnoses.
fn pack_add_blocked_hint(
    report: &confidant_core::check::CheckReport,
    name: &str,
    version: &str,
) -> Option<String> {
    let listed = format!(
        "{}@{}",
        pack_fetch::escape_line(name),
        pack_fetch::escape_line(version)
    );
    let sets_checks = report
        .findings
        .iter()
        .any(|finding| finding.code.as_str() == "E_CONFIG");
    let uses_ledger = report.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "E_UNKNOWN_VERB" | "E_UNKNOWN_METRIC" | "E_UNKNOWN_EDGE_KIND"
        )
    });
    let mut lines = Vec::new();
    if sets_checks {
        lines.push(format!(
            "hint: the findings above name [checks] keys the vault already carries for {listed}; add \"{listed}\" to `packs` in confidant.toml (or remove those keys), then re-run `confidant pack add`"
        ));
    }
    if uses_ledger {
        lines.push(format!(
            "hint: the findings above name ledger entries that use {listed}'s verbs, metrics, or edge kinds; migrate or remove those lines first, then re-run `confidant pack add`"
        ));
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// #694: a stderr hint after `pack remove --yes` is blocked. The report
/// still prints unchanged and the exit stays 1; this only names the
/// workaround.
fn pack_remove_blocked_hint(name: &str) -> String {
    let name = pack_fetch::escape_line(name);
    format!(
        "hint: the vault still uses {name}'s verbs, metrics, [checks] keys, or edge kinds, so removing the pack would leave orphan data. Remove or migrate those entries (and drop the [checks] keys) first, or keep the pack installed. An explicit orphan flag is tracked in #696 and is not available yet."
    )
}

fn cmd_pack_add_inner(
    cli: &Cli,
    vault_root: Option<&Path>,
    url: Option<&str>,
    from_dir: Option<&Path>,
    subdir: Option<&str>,
    yes: bool,
) -> anyhow::Result<ExitCode> {
    let source = pack_fetch::parse_add_source(url, from_dir)?;
    let fetched = pack_fetch::fetch(&source, subdir.unwrap_or(""))?;
    let report = pack_fetch::describe(&fetched)?;
    // A reserved or compiled name can never be installed from outside the
    // binary (PD14), so refuse before the report either way.
    refuse_uninstallable(&report.name, &report.version)?;

    if yes {
        let root = vault_root_required(vault_root, "pack add --yes")?;
        let cfg_text = read_config_text(root)?;
        let cfg =
            confidant_core::config::VaultConfig::parse(&cfg_text).map_err(anyhow::Error::new)?;
        let listed_id = format!("{}@{}", report.name, report.version);
        // #694: the vault may already carry this pack's data or its vendored
        // copy without listing the pack. The pre-check would then refuse the
        // install with a generic finding, so name the exact listing change
        // first. A listing for another version of the same name is left to
        // the one-version-at-a-time refusal below.
        let listed_name = cfg.packs.iter().any(|listed| {
            listed == &report.name
                || listed
                    .split_once('@')
                    .is_some_and(|(name, _)| name == report.name)
        });
        if !listed_name {
            preflight_unlisted_pack(root, &cfg, &report)?;
        }
        let lock = read_lockfile_or_empty(root)?;
        if let Some(entry) = lock.find(&report.name, &report.version) {
            if entry.hash == report.hash {
                // Same pin, same bytes: nothing to write (PD10 idempotence).
                if cli.json {
                    print_json(&ok_envelope(
                        Some(root),
                        serde_json::json!({
                            "command": "pack-add",
                            "unchanged": true,
                            "pack": {"name": report.name, "version": report.version, "hash": report.hash},
                        }),
                    ))?;
                } else {
                    println!(
                        "{}@{} is already installed at this hash; nothing to do",
                        pack_fetch::escape_line(&report.name),
                        pack_fetch::escape_line(&report.version)
                    );
                }
                return Ok(ExitCode::SUCCESS);
            }
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "{}@{} is already installed with a different hash",
                report.name, report.version
            )))
            .with_fix("Use `confidant pack update <name> --rev <ref>` to move it"));
        }
        // One version at a time: installing a second version of the same name
        // side by side leaves `pack update` unable to tell which to move, so
        // refuse up front and point at `update` (which replaces in place).
        if let Some(other) = lock.packs.iter().find(|e| e.name == report.name) {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "{}@{} is already installed; {}@{} cannot be added alongside it",
                report.name, other.version, report.name, report.version
            )))
            .with_fix(
                "Use `confidant pack update <name> --rev <ref>` to replace the installed version",
            ));
        }
        let files = read_pack_dir(&fetched.pack_dir).map_err(anyhow::Error::new)?;
        // Pin the reviewed bytes to the written bytes: `report` came from an
        // earlier read of the same directory, so a `--from-dir` source that
        // changed in between must be refused rather than vendored un-reviewed.
        if files.hash != report.hash {
            return Err(anyhow::Error::new(DomainError::conflict(
                "the pack directory changed between the review and the write",
            ))
            .with_fix("Re-run `confidant pack add` and review the report again"));
        }
        // #612: the pack may already be listed in `confidant.toml` with no
        // lockfile pin (a lost lock, a bad merge, a partial restore). That is
        // the exact `E_PACK_UNKNOWN` the pre-check reports and this write
        // repairs by writing the pin, so route it through the repairing path;
        // the post-check still gates the commit. With no such listing the
        // pre-check runs as usual.
        let unpinned_listing = cfg.packs.iter().any(|listed| listed == &listed_id);
        let changes = install_changes(root, &report, &files, &fetched, None)?;
        let summary = format!(
            "pack: add {}@{} ({})",
            report.name,
            report.version,
            short_hash(&report.hash)
        );
        let pending = PendingWrite {
            changes,
            canonical_request: summary.clone(),
            summary,
        };
        let outcome = if unpinned_listing {
            apply_write_repairing(root, pending, &write_options(cli))?
        } else {
            apply_write(root, pending, &write_options(cli))?
        };
        // #694: the check report still prints unchanged (exit 1); this only
        // adds a stderr hint, so `--json` stdout stays valid.
        let hint = match &outcome {
            WriteOutcome::CheckBlocked {
                report: check_report,
            } => pack_add_blocked_hint(check_report, &report.name, &report.version),
            _ => None,
        };
        let code = finish_write(
            cli,
            root,
            "pack-add",
            outcome,
            serde_json::json!({
                "pack": {"name": report.name, "version": report.version, "hash": report.hash},
            }),
        )?;
        if let Some(hint) = hint {
            writeln!(io::stderr(), "{hint}")?;
        }
        return Ok(code);
    }
    if cli.json {
        let payload = report.to_json(&fetched.source, &fetched.rev, &fetched.subdir);
        print_json(&ok_envelope(vault_root, payload))?;
    } else {
        // Everything here except `rev` (40 hex) and `hash` (ours) comes from
        // an untrusted repository, so control characters are escaped before
        // they reach the terminal: a hostile SKILL.md must not be able to
        // hide the lines the operator is meant to read (PD10).
        println!(
            "pack    {}@{}",
            pack_fetch::escape_line(&report.name),
            pack_fetch::escape_line(&report.version)
        );
        println!("source  {}", pack_fetch::escape_line(&fetched.source));
        println!(
            "rev     {}",
            if fetched.rev.is_empty() {
                "(none: local directory)"
            } else {
                fetched.rev.as_str()
            }
        );
        println!(
            "subdir  {}",
            if fetched.subdir.is_empty() {
                "(root)".to_string()
            } else {
                pack_fetch::escape_line(&fetched.subdir)
            }
        );
        for line in report.human_lines() {
            println!("{line}");
        }
        println!("nothing was written: applying a pack is a separate step");
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// pack install / list / verify / remove / update (#440)
// ---------------------------------------------------------------------------

/// The vault root, or a clear error for a command that needs one.
fn vault_root_required<'a>(root: Option<&'a Path>, what: &str) -> anyhow::Result<&'a Path> {
    root.ok_or_else(|| {
        anyhow::Error::new(DomainError::vault_not_found()).context(format!("{what} needs a vault"))
    })
}

/// Refuse to install a reserved (`personal`) or built-in pack (PD14).
/// Both can only come from the binary. An external pack is an ordinary
/// pack since #449.
fn refuse_uninstallable(name: &str, version: &str) -> anyhow::Result<()> {
    use confidant_core::packs::manifest::is_reserved_pack_name;
    if is_reserved_pack_name(name) {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "pack name '{name}' is reserved for a built-in pack"
        )))
        .with_fix("Choose a different pack name"));
    }
    let listed = format!("{name}@{version}");
    if confidant_core::packs::registry::PackRegistry::compiled()
        .all()
        .iter()
        .any(|p| p.name() == listed)
    {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "{listed} is compiled into this binary"
        )))
        .with_fix("Remove the listing; a compiled pack is always available"));
    }
    Ok(())
}

/// `<vault>/confidant.lock`, parsed; an absent file is an empty lockfile.
fn read_lockfile_or_empty(root: &Path) -> anyhow::Result<confidant_core::packs::lock::Lockfile> {
    match std::fs::read_to_string(root.join("confidant.lock")) {
        Ok(text) => confidant_core::packs::lock::Lockfile::parse(&text).map_err(anyhow::Error::new),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(confidant_core::packs::lock::Lockfile { packs: Vec::new() })
        }
        Err(e) => Err(anyhow::anyhow!("cannot read confidant.lock: {e}")),
    }
}

fn read_config_text(root: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(root.join("confidant.toml"))
        .map_err(|e| anyhow::anyhow!("cannot read confidant.toml: {e}"))
}

/// Vendored directory for a pack, relative to the vault root.
fn vendored_rel(name: &str, version: &str) -> String {
    format!("packs/{name}@{version}")
}

/// The first 12 hex characters of a `sha256:<hex>` hash, for a commit subject
/// or report header. Slicing the whole string would show only the prefix
/// (`sha256:abcde`), because the algorithm label is 7 bytes long.
fn short_hash(hash: &str) -> String {
    hash.strip_prefix("sha256:")
        .unwrap_or(hash)
        .chars()
        .take(12)
        .collect()
}

/// One change set that installs `report`'s files and pins them: the vendored
/// tree, the lockfile entry, and the `packs` listing (PD4/PD5/PD10).
///
/// `replace` is an existing `name@version` this install supersedes (an
/// update): its lock entry drops and its `packs` listing is replaced, so the
/// config is rewritten exactly once.
fn install_changes(
    root: &Path,
    report: &pack_fetch::PackReport,
    files: &confidant_core::packs::dir::PackDir,
    fetched: &pack_fetch::Fetched,
    replace: Option<&str>,
) -> anyhow::Result<Vec<FileChange>> {
    let base = vendored_rel(&report.name, &report.version);
    let mut changes: Vec<FileChange> = files
        .files
        .iter()
        .map(|(rel, bytes)| FileChange::WriteBytes {
            path: PathBuf::from(format!("{base}/{rel}")),
            contents: bytes.clone(),
        })
        .collect();

    changes.push(lockfile_change(root, report, fetched, replace)?);

    let cfg_text = read_config_text(root)?;
    let mut packs = confidant_core::config::VaultConfig::parse(&cfg_text)
        .map_err(anyhow::Error::new)?
        .packs;
    if let Some(old) = replace {
        packs.retain(|p| p != old);
    }
    let listed = format!("{}@{}", report.name, report.version);
    if !packs.contains(&listed) {
        packs.push(listed);
    }
    changes.push(FileChange::WriteFile {
        path: PathBuf::from("confidant.toml"),
        contents: confidant_core::config::VaultConfig::set_packs(&cfg_text, &packs)
            .map_err(anyhow::Error::new)?,
    });
    Ok(changes)
}

/// The `confidant.lock` change for installing `report`: drop the pin named
/// by `replace` (when re-vendoring a version) and upsert the fetched one.
fn lockfile_change(
    root: &Path,
    report: &pack_fetch::PackReport,
    fetched: &pack_fetch::Fetched,
    replace: Option<&str>,
) -> anyhow::Result<FileChange> {
    let mut lock = read_lockfile_or_empty(root)?;
    if let Some(old) = replace {
        if let Some((name, version)) = old.split_once('@') {
            lock.remove(name, version);
        }
    }
    lock.upsert(confidant_core::packs::lock::LockEntry {
        name: report.name.clone(),
        version: report.version.clone(),
        source: fetched.source.clone(),
        rev: fetched.rev.clone(),
        subdir: fetched.subdir.clone(),
        hash: report.hash.clone(),
    });
    Ok(FileChange::WriteFile {
        path: PathBuf::from("confidant.lock"),
        contents: lock.to_toml(),
    })
}

/// `DeleteFile` changes for every regular file in a vendored pack dir.
///
/// Lists with [`confidant_core::paths::read_dir`], which refuses to follow a
/// symbolic link at any depth, so a planted `packs/<id>` (or `packs/`)
/// symlink can never steer a delete into files outside the vault (#440). A
/// non-regular entry (a symlink, a directory, a special file) is refused
/// before any change is built: `apply_write` applies its change list in order
/// without rolling back a mid-list failure, so queuing one would delete the
/// earlier files and then fail, leaving a half-deleted pack (#529 review). A
/// missing vendored tree is not an error — removal must still clean up the
/// lockfile and listing — but an unlistable one is.
fn delete_vendored_changes(
    root: &Path,
    name: &str,
    version: &str,
) -> anyhow::Result<Vec<FileChange>> {
    let rel = vendored_rel(name, version);
    let rel_path = Path::new(&rel);
    let listing = match confidant_core::paths::read_dir(root, rel_path) {
        Ok(listing) => listing,
        Err(error) => {
            // A missing vendored tree is not an error — removal must still
            // clean up the lockfile and listing. Anything else (a symlink,
            // an unreadable tree) fails closed rather than guessing.
            if !confidant_core::paths::exists(root, rel_path).unwrap_or(true) {
                return Ok(Vec::new());
            }
            return Err(error);
        }
    };
    if let Some((entry, cause)) = listing.errors.first() {
        return Err(anyhow::Error::new(
            DomainError::pack_invalid(format!(
                "cannot list {}: {}: {cause}",
                pack_fetch::escape_line(&rel),
                pack_fetch::escape_line(entry)
            ))
            .with_fix("Restore the vendored tree (git checkout -- packs) and retry"),
        ));
    }
    let mut out = Vec::new();
    for entry in listing.entries {
        // Refuse before any delete is queued: a mid-list refusal inside
        // `apply_write` would have already unlinked the earlier files.
        if !entry.kind.is_file() {
            return Err(anyhow::Error::new(
                DomainError::pack_invalid(format!(
                    "cannot remove {}: {} is {}",
                    pack_fetch::escape_line(&rel),
                    pack_fetch::escape_line(&entry.name),
                    describe_non_regular(entry.kind)
                ))
                .with_fix(
                    "Restore the vendored tree (git checkout -- packs) or remove the entry, then retry",
                ),
            ));
        }
        out.push(FileChange::DeleteFile {
            path: PathBuf::from(&rel).join(&entry.name),
        });
    }
    Ok(out)
}

/// Describe a directory entry that is not a regular file, for a refusal
/// message. `File` is unreachable (callers check `is_file` first) but keeps
/// the match exhaustive.
fn describe_non_regular(kind: confidant_core::paths::EntryKind) -> &'static str {
    use confidant_core::paths::EntryKind;
    match kind {
        EntryKind::Symlink => "a symbolic link",
        EntryKind::Directory => "a directory",
        EntryKind::Other => "a special file",
        EntryKind::File => "a regular file",
    }
}

/// `pack update` reviews the change with `git diff --no-index`, which follows
/// symlinks. The vendored tree is checked with the vault's no-follow helpers
/// first, so a planted `packs/<id>` symlink (or a symlinked file inside) cannot
/// feed content from outside the vault into the review (PD12). A tree that is
/// not a real directory of regular files is "cannot diff".
fn ensure_vendored_tree_diffable(root: &Path, name: &str, version: &str) -> anyhow::Result<()> {
    let rel = vendored_rel(name, version);
    let cannot_diff = |detail: String| {
        anyhow::Error::new(
            DomainError::pack_invalid(format!("cannot diff {rel}: {detail}")).with_fix(
                "Restore the vendored tree (git checkout -- packs) or remove the pack, then retry",
            ),
        )
    };
    let listing = confidant_core::paths::read_dir(root, Path::new(&rel))
        .map_err(|error| cannot_diff(pack_fetch::escape_line(&format!("{error:#}"))))?;
    if let Some((entry, cause)) = listing.errors.first() {
        return Err(cannot_diff(format!(
            "cannot list {}: {}",
            pack_fetch::escape_line(entry),
            pack_fetch::escape_line(cause)
        )));
    }
    if listing.entries.iter().any(|entry| !entry.kind.is_file()) {
        return Err(cannot_diff(
            "the vendored tree holds a non-regular entry (a symlink or directory)".to_owned(),
        ));
    }
    Ok(())
}

/// Verification status of one installed pack (PD12: fail closed).
struct PackStatus {
    name: String,
    version: String,
    source: String,
    rev: String,
    hash: String,
    status: &'static str,
}

impl PackStatus {
    fn verify(root: &Path, entry: &confidant_core::packs::lock::LockEntry) -> Self {
        let rel = vendored_rel(&entry.name, &entry.version);
        let rel_path = Path::new(&rel);
        let dir = root.join(&rel);
        // `read_pack_dir` takes a path and follows a symlink at the tree root,
        // so classify with the vault's no-follow helpers first: a planted
        // `packs/<id>` symlink (or a symlinked file inside) is `invalid`,
        // never read (#529).
        let status = match confidant_core::paths::exists(root, rel_path) {
            // Only a definite absence is `missing`; a helper error fails
            // closed as `invalid` rather than masquerading as absent.
            Ok(false) => "missing",
            Err(_) => "invalid",
            Ok(true) => match confidant_core::paths::read_dir(root, rel_path) {
                Ok(listing)
                    if listing.errors.is_empty()
                        && listing.entries.iter().all(|e| e.kind.is_file()) =>
                {
                    // The no-follow check above and this `read_pack_dir` are
                    // separate syscalls: a tree swapped for a symlink in
                    // between would still be followed. That window is local
                    // only (an attacker with vault write access), and
                    // `read_pack_dir` refuses symlinked entries inside the
                    // tree, so the tree is not re-read to close it.
                    match read_pack_dir(&dir) {
                        Ok(packed) if packed.hash == entry.hash => "ok",
                        Ok(_) => "tampered",
                        Err(_) => "invalid",
                    }
                }
                _ => "invalid",
            },
        };
        Self {
            name: entry.name.clone(),
            version: entry.version.clone(),
            source: entry.source.clone(),
            rev: entry.rev.clone(),
            hash: entry.hash.clone(),
            status,
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "rev": self.rev,
            "hash": self.hash,
            "status": self.status,
        })
    }

    fn print_human(&self) {
        println!(
            "{:<20} {:<8} {:<8} {:<12} {}",
            pack_fetch::escape_line(&self.name),
            pack_fetch::escape_line(&self.version),
            self.status,
            if self.rev.is_empty() {
                "(dir)".to_owned()
            } else {
                // A hand-edited non-ASCII rev must not panic a byte slice.
                self.rev.chars().take(8).collect()
            },
            pack_fetch::escape_line(&self.source)
        );
    }
}

/// `pack list`: installed packs and their verification status. Read-only and
/// offline.
fn cmd_pack_list(cli: &Cli, vault_root: Option<&Path>) -> anyhow::Result<ExitCode> {
    let root = vault_root_required(vault_root, "pack list")?;
    let lock = read_lockfile_or_empty(root)?;
    let statuses: Vec<PackStatus> = lock
        .packs
        .iter()
        .map(|e| PackStatus::verify(root, e))
        .collect();
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "command": "pack-list",
                "packs": statuses.iter().map(PackStatus::to_json).collect::<Vec<_>>(),
            }),
        ))?;
    } else if statuses.is_empty() {
        println!("no external packs installed");
    } else {
        for status in &statuses {
            status.print_human();
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `pack verify [name]`: re-hash the vendored trees against the lockfile.
/// Exit 1 on any mismatch.
fn cmd_pack_verify(
    cli: &Cli,
    vault_root: Option<&Path>,
    name: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let root = vault_root_required(vault_root, "pack verify")?;
    let lock = read_lockfile_or_empty(root)?;
    let selected: Vec<&confidant_core::packs::lock::LockEntry> = match name {
        Some(name) => {
            let matching: Vec<_> = lock.packs.iter().filter(|e| e.name == name).collect();
            if matching.is_empty() {
                return Err(anyhow::Error::new(DomainError::not_found(format!(
                    "pack '{name}' is not installed"
                )))
                .with_fix("Run `confidant pack list` to see installed packs"));
            }
            matching
        }
        None => lock.packs.iter().collect(),
    };
    let statuses: Vec<PackStatus> = selected
        .iter()
        .map(|e| PackStatus::verify(root, e))
        .collect();
    let ok = statuses.iter().all(|s| s.status == "ok");
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "command": "pack-verify",
                "ok": ok,
                "packs": statuses.iter().map(PackStatus::to_json).collect::<Vec<_>>(),
            }),
        ))?;
    } else if statuses.is_empty() {
        println!("no external packs installed");
    } else {
        for status in &statuses {
            status.print_human();
        }
        if !ok {
            eprintln!(
                "pack verify: a vendored tree does not match confidant.lock; \
                 reinstall with `confidant pack add` or fix the lockfile"
            );
        }
    }
    Ok(ExitCode::from(if ok { 0 } else { 1 }))
}

/// Whether `version` is safe to join into `<root>/packs/<name>@<version>`:
/// one path segment, not `.`/`..`, portable across Windows (no `/`, `\`, `:`,
/// or control characters). Mirrors the lockfile's own `subdir` rule so a
/// hand-edited `confidant.toml` listing can never steer a delete out of the
/// vendored tree.
pub(crate) fn is_safe_version_part(version: &str) -> bool {
    !version.is_empty()
        && version != "."
        && version != ".."
        && !version.contains('/')
        && !version.contains('\\')
        && !version.contains(':')
        && !version.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// The `name@version` ids of vendored pack directories under
/// `<root>/packs` for `name`, listed without following a symbolic link
/// (#440). A missing `packs/` is an empty list; an unlistable one fails
/// closed. Ids whose version is not a single safe path segment are skipped.
fn vendored_ids_for(root: &Path, name: &str) -> anyhow::Result<Vec<String>> {
    let listing = match confidant_core::paths::read_dir(root, Path::new("packs")) {
        Ok(listing) => listing,
        Err(error) => {
            // A missing `packs/` is not an error (there is simply nothing
            // vendored); anything else — including a planted `packs` symlink,
            // which the no-follow reader refuses — fails closed.
            if !confidant_core::paths::exists(root, Path::new("packs")).unwrap_or(true) {
                return Ok(Vec::new());
            }
            return Err(error);
        }
    };
    if let Some((entry, cause)) = listing.errors.first() {
        return Err(anyhow::anyhow!(
            "cannot list packs/: {}: {cause}",
            pack_fetch::escape_line(entry)
        ));
    }
    let prefix = format!("{name}@");
    let mut ids = Vec::new();
    for entry in listing.entries {
        if !entry.kind.is_directory() {
            continue;
        }
        let Some(version) = entry.name.strip_prefix(&prefix) else {
            continue;
        };
        if is_safe_version_part(version) {
            ids.push(format!("{name}@{version}"));
        }
    }
    Ok(ids)
}

/// `pack remove <name>`: delete the vendored files, the lockfile entries and
/// the `packs` listing. Needs `--yes`.
///
/// #612: the pack's install state is keyed off every source — the lockfile,
/// the `confidant.toml` listing, and the vendored tree — not the lockfile
/// alone. When `confidant.lock` is missing (a lost lock, a bad merge, a
/// partial restore) the listing and the vendored directory still identify the
/// pack, so removal is the escape `check`'s `E_PACK_UNKNOWN` fix can point at.
fn cmd_pack_remove(
    cli: &Cli,
    vault_root: Option<&Path>,
    name: String,
    yes: bool,
) -> anyhow::Result<ExitCode> {
    let root = vault_root_required(vault_root, "pack remove")?;
    let mut lock = read_lockfile_or_empty(root)?;
    let lock_entries: Vec<confidant_core::packs::lock::LockEntry> = lock
        .packs
        .iter()
        .filter(|e| e.name == name)
        .cloned()
        .collect();

    let cfg_text = read_config_text(root)?;
    let cfg_packs = confidant_core::config::VaultConfig::parse(&cfg_text)
        .map_err(anyhow::Error::new)?
        .packs;

    // Well-formed `name@version` ids to delete (the vendored tree) and
    // un-pin (the lockfile): the lock entries plus any safe listing.
    // `drop_listings` is every `confidant.toml` entry for this name, including
    // one that is not a well-formed id (a bare `example-pack`), so a malformed
    // listing is repaired too.
    let mut ids: BTreeSet<String> = lock_entries.iter().map(|e| e.id()).collect();
    let mut drop_listings: BTreeSet<String> = BTreeSet::new();
    for listed in &cfg_packs {
        let matches_name = listed == &name
            || listed
                .split_once('@')
                .is_some_and(|(listed_name, _)| listed_name == name);
        if !matches_name {
            continue;
        }
        drop_listings.insert(listed.clone());
        if let Some((_, version)) = listed.split_once('@') {
            if is_safe_version_part(version) {
                ids.insert(listed.clone());
            }
        }
    }
    // The vendored tree is the last resort: only when neither the lockfile nor
    // the listing names the pack (a listing hand-edited away, a partial
    // restore) is it consulted. A healthy removal keeps its prior behaviour.
    if lock_entries.is_empty() && drop_listings.is_empty() {
        ids.extend(vendored_ids_for(root, &name)?);
    }
    if ids.is_empty() && drop_listings.is_empty() {
        return Err(anyhow::Error::new(DomainError::not_found(format!(
            "pack '{name}' is not installed"
        )))
        .with_fix("Run `confidant pack list` to see installed packs"));
    }
    let listed: Vec<String> = ids
        .iter()
        .chain(drop_listings.iter().filter(|l| !ids.contains(*l)))
        .cloned()
        .collect();

    if !yes {
        if cli.json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "command": "pack-remove",
                    "dry_run": true,
                    "would_remove": listed,
                }),
            ))?;
        } else {
            println!("would remove (pass --yes to apply):");
            for id in &listed {
                // A hand-edited lockfile or listing id must not hide itself.
                println!("  {}", pack_fetch::escape_line(id));
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    let mut changes = Vec::new();
    for id in &ids {
        // Ids are always `name@version` (the lockfile's id, or a validated
        // listing / vendored name); the name half carries no `@`.
        let (id_name, id_version) = id.split_once('@').expect("ids are name@version");
        changes.extend(delete_vendored_changes(root, id_name, id_version)?);
        lock.remove(id_name, id_version);
    }
    // A lockfile that is absent stays absent: removing the last pin must not
    // conjure an empty `confidant.lock` (a vault with no external packs has
    // no lockfile).
    let lock_exists =
        confidant_core::paths::exists(root, Path::new("confidant.lock")).unwrap_or(true);
    if lock_exists {
        changes.push(FileChange::WriteFile {
            path: PathBuf::from("confidant.lock"),
            contents: lock.to_toml(),
        });
    }
    let mut packs = cfg_packs;
    packs.retain(|p| !drop_listings.contains(p));
    changes.push(FileChange::WriteFile {
        path: PathBuf::from("confidant.toml"),
        contents: confidant_core::config::VaultConfig::set_packs(&cfg_text, &packs)
            .map_err(anyhow::Error::new)?,
    });

    let summary = format!("pack: remove {}", listed.join(", "));
    let pending = PendingWrite {
        changes,
        canonical_request: summary.clone(),
        summary,
    };
    // #612: with no lockfile entry for this pack the pre-check reports exactly
    // the `E_PACK_UNKNOWN` this removal repairs, so the write goes through the
    // repairing path. Its post-check still gates the commit, so a removal can
    // never commit a vault that is still broken. With a lock entry the
    // pre-check runs as usual.
    let outcome = if lock_entries.is_empty() {
        apply_write_repairing(root, pending, &write_options(cli))?
    } else {
        apply_write(root, pending, &write_options(cli))?
    };
    if matches!(outcome, WriteOutcome::Applied { .. }) {
        for id in &ids {
            if let Some((id_name, id_version)) = id.split_once('@') {
                let _ = std::fs::remove_dir(root.join(vendored_rel(id_name, id_version)));
            }
        }
    }
    let blocked = matches!(outcome, WriteOutcome::CheckBlocked { .. });
    let code = finish_write(
        cli,
        root,
        "pack-remove",
        outcome,
        serde_json::json!({ "removed": listed }),
    )?;
    // #694: the report still prints unchanged (exit 1); this only adds a
    // stderr hint, so `--json` stdout stays valid.
    if blocked {
        writeln!(io::stderr(), "{}", pack_remove_blocked_hint(&name))?;
    }
    Ok(code)
}

/// `pack update <name> --rev <ref>`: re-fetch a new rev, print the diff, and
/// (with `--yes`) re-vendor, re-pin and commit.
fn cmd_pack_update(
    cli: &Cli,
    vault_root: Option<&Path>,
    name: String,
    rev: Option<&str>,
    from_dir: Option<&Path>,
    yes: bool,
) -> anyhow::Result<ExitCode> {
    let root = vault_root_required(vault_root, "pack update")?;
    let lock = read_lockfile_or_empty(root)?;
    let matching: Vec<&confidant_core::packs::lock::LockEntry> =
        lock.packs.iter().filter(|e| e.name == name).collect();
    let entry = match matching.as_slice() {
        [] => {
            return Err(anyhow::Error::new(DomainError::not_found(format!(
                "pack '{name}' is not installed"
            )))
            .with_fix("Run `confidant pack list` to see installed packs"))
        }
        [entry] => *entry,
        _ => {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "pack '{name}' is installed at more than one version"
            )))
            .with_fix("Remove the version you do not want, then update again"))
        }
    };
    let source = match (rev, from_dir) {
        (Some(_), Some(_)) => {
            return Err(anyhow::Error::new(DomainError::usage(
                "pass either --rev or --from-dir, not both",
            ))
            .with_fix(
                "Use `pack update <name> --rev <ref>` or `pack update <name> --from-dir <path>`",
            ))
        }
        (None, None) => {
            return Err(anyhow::Error::new(DomainError::usage(
                "pack update needs --rev or --from-dir",
            ))
            .with_fix(
                "Use `pack update <name> --rev <ref>` or `pack update <name> --from-dir <path>`",
            ))
        }
        (Some(rev), None) => {
            if entry.source == "dir" {
                return Err(anyhow::Error::new(DomainError::invalid(format!(
                    "pack '{name}' was installed from a directory, so it has no git source to fetch --rev from"
                )))
                .with_fix("Use `pack update <name> --from-dir <path>` instead"));
            }
            pack_fetch::Source::Https {
                url: entry.source.clone(),
                git_ref: Some(rev.to_owned()),
            }
        }
        (None, Some(dir)) => pack_fetch::parse_add_source(None, Some(dir))?,
    };
    let fetched = pack_fetch::fetch(&source, &entry.subdir)?;
    let report = pack_fetch::describe(&fetched)?;
    refuse_uninstallable(&report.name, &report.version)?;
    if report.name != entry.name {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "the fetched pack is {}, not {}",
            report.name, entry.name
        )))
        .with_fix("Update that pack instead, or add this one"));
    }

    let old_dir = root.join(vendored_rel(&entry.name, &entry.version));
    ensure_vendored_tree_diffable(root, &entry.name, &entry.version)?;
    let diff = pack_fetch::diff_dirs(&old_dir, &fetched.pack_dir)?;
    let new_files = read_pack_dir(&fetched.pack_dir).map_err(anyhow::Error::new)?;
    if new_files.hash != report.hash {
        return Err(anyhow::Error::new(DomainError::conflict(
            "the pack directory changed between the review and the write",
        ))
        .with_fix("Re-run `confidant pack update` and review the diff again"));
    }

    // `--from-dir` on a git-installed pack rewrites the lock `source` to
    // `dir` and drops the rev: say so, rather than silently losing the pin.
    let source_changed = entry.source != fetched.source;
    if source_changed && !cli.json {
        println!(
            "note    the lock source changes from {} to {}",
            pack_fetch::escape_line(&entry.source),
            pack_fetch::escape_line(&fetched.source)
        );
    }

    if !yes {
        // Review gate before applying (PD10): the diff is the whole point of
        // an update.
        let escaped_diff = pack_fetch::escape_text(&diff);
        if cli.json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "command": "pack-update",
                    "dry_run": true,
                    "pack": {"name": report.name, "version": report.version, "hash": report.hash},
                    "from_version": entry.version,
                    "source_changed": source_changed,
                    "diff": diff,
                }),
            ))?;
        } else {
            println!(
                "{}: {}@{} -> {}@{} ({}..)",
                pack_fetch::escape_line(&report.name),
                pack_fetch::escape_line(&entry.name),
                pack_fetch::escape_line(&entry.version),
                pack_fetch::escape_line(&report.name),
                pack_fetch::escape_line(&report.version),
                short_hash(&report.hash)
            );
            // The diff is `git diff --no-index` over untrusted files: escape
            // control and bidi characters so a hostile pack cannot hide or
            // reorder the lines the operator reviews (#499/PD10).
            print!("{escaped_diff}");
            println!("pass --yes to apply");
        }
        return Ok(ExitCode::SUCCESS);
    }

    // A pin that would not move: the version/source/rev/subdir match and the
    // listing already names it. What to do then depends on the tree and the
    // lock hash.
    //
    // Re-vendoring here instead would emit a `DeleteFile` and a rewrite of
    // every path, and `apply_write`'s Unchanged guard checks each change on
    // its own: the path a `DeleteFile` targets still exists because the same
    // list rewrites it, so the guard misses the net no-op and the empty
    // changeset fails `git commit` with an empty message (#602). The guard's
    // comment says it exists precisely to avoid that empty commit; the
    // delete+rewrite list is what defeated it. Reading the tree off disk
    // (rather than trusting the lock hash) keeps a tampered tree out of this
    // branch: its hash no longer matches the fetched pack, so it falls
    // through to the normal path, where the pre-check reports the mismatch.
    let extra = serde_json::json!({
        "pack": {
            "name": report.name.clone(),
            "version": report.version.clone(),
            "hash": report.hash.clone(),
        },
        "from_version": entry.version.clone(),
        "source_changed": source_changed,
    });
    let pin_metadata_unchanged = entry.version == report.version
        && entry.source == fetched.source
        && entry.rev == fetched.rev
        && entry.subdir == fetched.subdir;
    let listed = {
        let cfg_text = read_config_text(root)?;
        confidant_core::config::VaultConfig::parse(&cfg_text)
            .map_err(anyhow::Error::new)?
            .packs
            .iter()
            .any(|p| p == &format!("{}@{}", report.name, report.version))
    };
    let tree_matches = read_pack_dir(&old_dir).is_ok_and(|dir| dir.hash == report.hash);
    if tree_matches && pin_metadata_unchanged && listed {
        if entry.hash == report.hash {
            // Nothing to do: tree, pin and listing are all current.
            return finish_write(cli, root, "pack-update", WriteOutcome::Unchanged, extra);
        }
        // #606: the installed tree matches the fetched pack but the lock hash
        // is stale. Rewrite the pin so `pack update` is usable as the repair.
        // The stale pin is an E_PACK_HASH error to the pre-check, so the
        // write goes through the repairing path; the post-check still gates
        // the commit, so this cannot leave the vault broken.
        let summary = format!(
            "pack: update {}@{} -> {}@{} ({})",
            entry.name,
            entry.version,
            report.name,
            report.version,
            short_hash(&report.hash)
        );
        let pending = PendingWrite {
            changes: vec![lockfile_change(root, &report, &fetched, None)?],
            canonical_request: summary.clone(),
            summary,
        };
        let outcome = apply_write_repairing(root, pending, &write_options(cli))?;
        return finish_write(cli, root, "pack-update", outcome, extra);
    }

    // Re-vendor: clear the old version's files, then write the new tree and
    // rewrite `confidant.lock`/`confidant.toml` once (the old listing is
    // replaced, not appended).
    let mut changes = delete_vendored_changes(root, &entry.name, &entry.version)?;
    let replace = format!("{}@{}", entry.name, entry.version);
    changes.extend(install_changes(
        root,
        &report,
        &new_files,
        &fetched,
        Some(&replace),
    )?);
    let summary = format!(
        "pack: update {}@{} -> {}@{} ({})",
        entry.name,
        entry.version,
        report.name,
        report.version,
        short_hash(&report.hash)
    );
    let pending = PendingWrite {
        changes,
        canonical_request: summary.clone(),
        summary,
    };
    let outcome = apply_write(root, pending, &write_options(cli))?;
    // A version change leaves the old, now-empty directory behind (git does
    // not track directories). Best-effort cleanup after a successful apply.
    if report.version != entry.version && matches!(outcome, WriteOutcome::Applied { .. }) {
        let _ = std::fs::remove_dir(root.join(vendored_rel(&entry.name, &entry.version)));
    }
    finish_write(cli, root, "pack-update", outcome, extra)
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

/// Human-output banner for `--for-operator` (#572). Operator mode must be
/// unmistakable so a screen share cannot silently show data the agent view
/// hides. JSON carries `for_operator: true` instead.
const OPERATOR_MODE_BANNER: &str = "OPERATOR MODE: no-ai records included (--for-operator)";

fn cmd_find(
    json: bool,
    root: &Path,
    query: &str,
    limit: usize,
    packs: Option<&str>,
    for_operator: bool,
) -> anyhow::Result<ExitCode> {
    if query.trim().is_empty() {
        return Err(anyhow::Error::new(DomainError::usage(
            "find requires a non-empty query",
        )));
    }
    // Operator mode (#572) loads through the operator decrypt path (the
    // same mechanism as `record show --for-edit`); the default stays the
    // agent read path (`no-ai` records come back as keyless shells and are
    // then excluded by the §12 allowlist).
    let vault = match load_vault_for_reads(root, json, for_operator) {
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
    let result = match if for_operator {
        search_for_operator(&vault, query, &scope)
    } else {
        search(&vault, query, &scope)
    } {
        Ok(result) => result,
        Err(err) => {
            print_error(json, Some(&vault_path), &err)?;
            return Ok(ExitCode::from(err.exit_code() as u8));
        }
    };
    let hits: Vec<_> = result.hits.into_iter().take(limit).collect();
    // #386: optional ranked-search hint. Present only when qmd is on PATH
    // and the corpus exists; never changes matches, ordering, or exit status.
    let qmd_hint = qmd_hint_for_find(&vault.root);
    if json {
        let mut data = serde_json::json!({
                "query": query,
                "matches": hits,
                "findings": result.findings,
                "skipped_encrypted": result.skipped_encrypted,
                "refused_envelopes": result.refused_envelopes,
                "scope": scope_names,
        });
        if let (Some(hint), Some(obj)) = (qmd_hint.as_deref(), data.as_object_mut()) {
            obj.insert(
                "hint".to_owned(),
                serde_json::Value::String(hint.to_owned()),
            );
        }
        // Operator mode (#572): present only with the flag, so an agent's
        // JSON is byte-for-byte unchanged.
        if for_operator {
            if let Some(obj) = data.as_object_mut() {
                obj.insert("for_operator".to_owned(), serde_json::Value::Bool(true));
            }
        }
        print_json(&ok_envelope(Some(&vault.root), data))?;
    } else {
        if for_operator {
            writeln!(io::stdout(), "{OPERATOR_MODE_BANNER}")?;
        }
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
        if let Some(hint) = qmd_hint.as_deref() {
            eprintln!("{hint}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// #386: optional `find` ranked-search hint. `Some` only when `qmd` is on
/// PATH and `<vault>/.confidant/qmd-corpus/` exists; otherwise `None`
/// (the install suggestion stays in `doctor` and `setup`).
fn qmd_hint_for_find(root: &Path) -> Option<String> {
    find_on_path("qmd")?;
    if !root.join(QMD_CORPUS_REL).is_dir() {
        return None;
    }
    Some("qmd index available; use the qmd-search skill for ranked results".to_owned())
}

/// #386: optional `setup` note when `qmd` is not on PATH. Informational
/// only: no prompt, no failure, no exit-status change. Search falls back
/// to `confidant find` without qmd.
fn qmd_setup_note() -> Option<String> {
    if find_on_path("qmd").is_some() {
        return None;
    }
    Some(
        "Note: `qmd` not found on PATH — search falls back to `confidant find`. \
         For ranked search, install with `npm install -g @tobilu/qmd` (optional)."
            .to_owned(),
    )
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
    let vault = match load_vault_for_reads(root, json, false) {
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
pub(crate) fn ensure_corpus_gitignored(root: &Path) -> Result<(), DomainError> {
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

/// Corpus dirs `0700`, files `0600` (B3). Applied recursively after the
/// build as a final sweep over every nested directory created for record
/// paths (the corpus root and files are already created with their final
/// mode; this re-asserts it).
fn harden_corpus_permissions(dir: &Path) -> std::io::Result<()> {
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
    apply_record_write_inner(root, vault, pending, opts, HashMap::new())
}

/// #410: like [`apply_record_write`], but the encryptor is built with
/// `mode_overrides` — the no-ai modes this changeset is about to give to
/// person records — so children encrypted in the same commit are stamped
/// from the person's new mode. Only `record edit` on a person whose mode
/// changes supplies a non-empty map.
fn apply_record_write_inner(
    root: &Path,
    vault: &confidant_core::vault::Vault,
    pending: PendingWrite,
    opts: &WriteOptions,
    mode_overrides: HashMap<String, confidant_crypt::envelope::NoAi>,
) -> anyhow::Result<(WriteOutcome, Vec<String>)> {
    let needs_encryptor = pending
        .changes
        .iter()
        .any(|c| matches!(c, FileChange::WriteFile { .. }));
    if !needs_encryptor {
        return Ok((apply_write(root, pending, opts)?, Vec::new()));
    }
    match record_crypto::RecordEncryptor::for_vault(root, vault)?
        .map(|enc| enc.with_mode_overrides(mode_overrides))
    {
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
        WriteOutcome::Unchanged => {
            if cli.json {
                let mut obj = serde_json::json!({ "command": command, "unchanged": true });
                if let serde_json::Value::Object(e) = extra {
                    obj.as_object_mut().unwrap().extend(e);
                }
                print_json(&ok_envelope(Some(root), obj))?;
            } else {
                println!("no changes; nothing committed");
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

/// A `--person` / positional person argument resolved to a canonical person
/// (#537). `matched_name` is `Some` only for an exact display-name argument,
/// so a write resolved by name can echo the pick (Refinement B) while a
/// write by `p-<ULID>` keeps its previous output.
struct ResolvedPersonArg {
    id: RecordId,
    matched_name: Option<String>,
}

impl ResolvedPersonArg {
    /// JSON object echoing the resolved person, or `None` for an id argument
    /// (so id writes produce byte-identical output).
    fn echo_json(&self) -> Option<Value> {
        self.matched_name
            .as_ref()
            .map(|name| serde_json::json!({ "id": self.id.to_string(), "name": name }))
    }
}

/// The vault loaded through the agent read path (`operator: false`), so
/// cleared people's names decrypt. Unlike [`load_vault_for_reads`] this
/// returns the classified error instead of printing it: the write commands
/// resolve names *in addition to* loading their own (un-hooked) vault, and
/// the error must reach the top-level handler once.
fn load_read_vault(root: &Path) -> anyhow::Result<confidant_core::Vault> {
    let probe = confidant_core::load_vault(root).map_err(anyhow::Error::new)?;
    let decryptor = std::sync::Arc::new(record_decrypt::RecordDecryptor::for_reads(
        root,
        &probe.config.vault_id,
    ));
    confidant_core::load_vault_with_hook(root, Some(decryptor.hook())).map_err(anyhow::Error::new)
}

/// Map a failed name resolution to the command-error layer. The not-found
/// fix is deliberately generic (Refinement A): it must not confirm that a
/// hidden `no-ai: true` person exists.
fn person_resolve_error(
    query: &str,
    err: confidant_core::resolve::PersonResolveError,
) -> anyhow::Error {
    use confidant_core::resolve::PersonResolveError;
    match err {
        PersonResolveError::NotFound => anyhow::Error::new(
            DomainError::not_found(format!("no person matches '{query}'")).with_fix(
                "Use an exact display name (trimmed, case-insensitive) or the p-<ULID>; if this \
                 person is `no-ai: true`, pass their p-<ULID>",
            ),
        ),
        PersonResolveError::Ambiguous { candidates } => {
            let ids: Vec<String> = candidates.iter().map(RecordId::to_string).collect();
            anyhow::Error::new(DomainError::ambiguous_person(query, &ids))
        }
    }
}

/// Resolve a `--person` / positional person argument: a `p-<ULID>` against
/// the already-loaded write vault (its id and type sit in the plaintext
/// envelope header, so a `no-ai: true` person stays addressable by id without
/// decrypting), or an exact display name against the `for_reads` cleared set.
fn resolve_person_arg(
    root: &Path,
    vault: &confidant_core::Vault,
    raw: &str,
) -> anyhow::Result<ResolvedPersonArg> {
    if let Ok(id) = RecordId::parse(raw) {
        return match vault.records.get(&id) {
            Some(r) if r.kind == RecordKind::Person => Ok(ResolvedPersonArg {
                id,
                matched_name: None,
            }),
            _ => Err(anyhow::Error::new(DomainError::not_found(format!(
                "no person with id {raw}"
            )))),
        };
    }
    let read_vault = load_read_vault(root)?;
    match confidant_core::resolve::resolve_person(&read_vault, raw) {
        Ok(m) => {
            // Belt-and-braces (#537 review): never echo a canonical the §12
            // cleared set excludes, even if resolution ever regresses. A
            // cleared person merged into a `no-ai: true` person must not
            // print (or serialize) that hidden person's name; fall back to
            // the same generic not-found as a miss.
            if !confidant_core::cleared_record_ids(&read_vault).contains(&m.id) {
                return Err(person_resolve_error(
                    raw,
                    confidant_core::resolve::PersonResolveError::NotFound,
                ));
            }
            // Echo the canonical person's own name; fall back to the query
            // for the rare merged-away name whose canonical has none.
            let matched_name = read_vault
                .records
                .get(&m.id)
                .and_then(|r| r.name.clone())
                .or_else(|| Some(raw.trim().to_owned()));
            Ok(ResolvedPersonArg {
                id: m.id,
                matched_name,
            })
        }
        Err(err) => Err(person_resolve_error(raw, err)),
    }
}

/// Refinement B (#537): a write resolved by exact display name prints the
/// resolved `p-<ULID>` (and name) so a wrong pick is immediately visible.
/// Id writes print nothing extra; under `--json` the envelope carries it.
///
/// The line is printed before the remaining validation (bad duration, bad
/// touch kind, keychain/inbox fallback), so it says "resolving to" rather
/// than claiming a completed write: the human may still see an error and no
/// commit after it (#537 review).
fn announce_resolved_person(cli: &Cli, person: &ResolvedPersonArg) {
    if cli.json {
        return;
    }
    if let Some(name) = &person.matched_name {
        println!("resolving to {} ({name})", person.id);
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

/// #457: `confidant inbox --discard <stem>...` — remove items from the
/// `inbox` branch without merging them.
///
/// For an item the operator chose not to apply (e.g. after `record
/// resolve <id> --from-inbox <stem> --take ours`). Exactly one signed
/// commit (`inbox: discard N item(s)`); the main worktree is never
/// touched. Fails closed on unknown stems (`E_INBOX_SKIP`), a moved tip
/// (`E_INBOX_RACE`), and missing signing config (`E_INBOX_UNTRUSTED`).
fn cmd_inbox_discard(json: bool, root: &Path, discard: &[String]) -> anyhow::Result<ExitCode> {
    let vault_path = root.display().to_string();
    let new_tip = match confidant_core::inbox::discard_inbox_items(root, discard) {
        Ok(tip) => tip,
        Err(err) => return fail_command(json, Some(&vault_path), &err),
    };
    if json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "command": "inbox-discard",
                "discarded": discard.len(),
                "stems": discard,
                "tip": new_tip,
            }),
        ))?;
    } else {
        println!("inbox: discarded {} item(s)", discard.len(),);
        for s in discard {
            println!("  {s}");
        }
    }
    Ok(ExitCode::SUCCESS)
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
    let person = resolve_person_arg(root, &vault, person_raw)?;
    announce_resolved_person(cli, &person);
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
        let rel = PathBuf::from(format!("people/{}/notes/{nid}.md", person.id));
        let rec = Record {
            id: nid.clone(),
            kind: RecordKind::Note,
            path: rel.display().to_string(),
            name: None,
            fields: BTreeMap::from([
                ("person".to_owned(), person.id.to_string()),
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
        person.id.to_string(),
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
        "log-session/v1\nperson={}\ndate={date}\nduration={duration}\ntag={}\nnote={}\nsrc={}\n",
        person.id,
        tag.as_deref().unwrap_or(""),
        note_body.as_deref().unwrap_or(""),
        src.as_deref().unwrap_or(""),
    );
    let summary = format!(
        "session {} {duration}{}",
        person.id,
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
                    &person,
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
    let mut extra = serde_json::json!({"lines": [line]});
    if let Some(echo) = person.echo_json() {
        extra["person"] = echo;
    }
    finish_write(cli, root, "log-session", outcome, extra)
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
    // #551: the built-in personal pack is implicit, so `touch` is always
    // owned by an enabled pack; the #510 enable gate is gone.
    let person = resolve_person_arg(root, &vault, person_raw)?;
    announce_resolved_person(cli, &person);
    // #510: the kind grammar is core-owned; validate against the core list
    // directly instead of probing the owning pack's trait.
    if !confidant_core::touch::is_valid_touch_kind(kind) {
        return Err(anyhow::Error::new(DomainError::usage(format!(
            "bad touch kind '{kind}'; use one of: {}",
            confidant_core::touch::TOUCH_KINDS.join(", ")
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
        let rel = PathBuf::from(format!("people/{}/notes/{nid}.md", person.id));
        let rec = Record {
            id: nid.clone(),
            kind: RecordKind::Note,
            path: rel.display().to_string(),
            name: None,
            fields: BTreeMap::from([
                ("person".to_owned(), person.id.to_string()),
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
        person.id.to_string(),
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
        "log-touch/v1\nperson={}\ndate={date}\nkind={kind}\nnote={}\nsrc={}\n",
        person.id,
        note_body.as_deref().unwrap_or(""),
        src.as_deref().unwrap_or(""),
    );
    let summary = format!("touch {} {kind}", person.id);
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
                    &person,
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
    let mut extra = serde_json::json!({"lines": [line]});
    if let Some(echo) = person.echo_json() {
        extra["person"] = echo;
    }
    finish_write(cli, root, "log-touch", outcome, extra)
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

// ---------------------------------------------------------------------------
// #376: `update` / `setup` offers — install-method detection, shared y/N
// prompt, and an injectable command runner.
// ---------------------------------------------------------------------------

/// How this binary was installed, for the `confidant update` offer (#376).
/// Only install methods with a reliable, testable signal are detected;
/// anything else is `Unknown` and falls back to the generic upgrade
/// wording (no offer to run anything).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallMethod {
    /// The binary lives in `<cargo-home>/bin`. This covers `cargo install`;
    /// the cargo-dist shell installer also targets `CARGO_HOME`, so an
    /// installer-based setup lands here too and gets the `cargo install`
    /// command, which is a working upgrade path for both.
    CargoInstall,
    Unknown,
}

impl InstallMethod {
    fn as_str(self) -> &'static str {
        match self {
            InstallMethod::CargoInstall => "cargo-install",
            InstallMethod::Unknown => "unknown",
        }
    }

    /// The single update command to print for this method, or `None` when
    /// the method is unknown (the caller prints the generic wording).
    fn update_command(self) -> Option<&'static str> {
        match self {
            InstallMethod::CargoInstall => Some("cargo install confidant-cli"),
            InstallMethod::Unknown => None,
        }
    }

    /// Program + argv to run when the operator confirms the offer.
    fn run_spec(self) -> Option<(&'static std::ffi::OsStr, &'static [&'static str])> {
        match self {
            InstallMethod::CargoInstall => {
                Some((std::ffi::OsStr::new("cargo"), &["install", "confidant-cli"]))
            }
            InstallMethod::Unknown => None,
        }
    }
}

/// Detect the install method from the running binary's path (#376). The
/// path is injected so the detection is unit-testable; production passes
/// `std::env::current_exe()`.
fn detect_install_method(exe_path: &Path) -> InstallMethod {
    // Normalize separators so Windows-style paths stay detectable on any
    // platform (unit tests run on Linux/macOS/Windows alike).
    let normalized = exe_path.to_string_lossy().replace('\\', "/");
    if normalized.contains("/.cargo/bin/") {
        return InstallMethod::CargoInstall;
    }
    InstallMethod::Unknown
}

/// The binary path the update/check offers reason about. Under
/// `test-overrides`, `CONFIDANT_TEST_EXE_PATH` overrides
/// `std::env::current_exe()` so integration tests can force a known
/// install method (the real test binary is not under `.cargo/bin`).
fn offer_exe_path() -> PathBuf {
    #[cfg(feature = "test-overrides")]
    if let Ok(p) = std::env::var("CONFIDANT_TEST_EXE_PATH") {
        return PathBuf::from(p);
    }
    std::env::current_exe().unwrap_or_default()
}

/// Whether `update` may offer to run the update command itself (#376): the
/// install method must be known and replacing the running binary must be
/// safe. `self_replace_safe` is injected for tests; production passes `true`
/// (unix always allows overwriting the running binary).
fn offerable_update(method: InstallMethod, self_replace_safe: bool) -> bool {
    method.run_spec().is_some() && self_replace_safe
}

#[cfg(feature = "test-overrides")]
static TEST_PROMPT_ANSWER_IDX: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Next scripted answer from `CONFIDANT_TEST_PROMPT_ANSWERS`
/// (newline-separated, consumed in prompt order), or `None` when the hook
/// is unset or exhausted.
#[cfg(feature = "test-overrides")]
fn test_prompt_answer() -> Option<String> {
    let list = std::env::var("CONFIDANT_TEST_PROMPT_ANSWERS").ok()?;
    let idx = TEST_PROMPT_ANSWER_IDX.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    list.split('\n').nth(idx).map(str::to_owned)
}

/// Shared y/N prompt for the `update` and `setup` offers (#376). Matches
/// the `prompt_fallback_inbox` style: stderr, `[y/N]`, default No — only an
/// explicit `y`/`yes` confirms, EOF fails closed.
///
/// Never prompts (returns `false`) when the session is non-interactive: no
/// TTY on stdin, `--no-input`, or `--json`. Nothing is ever run without an
/// explicit confirmation.
fn confirm_yn(question: &str, no_input: bool, json: bool) -> anyhow::Result<bool> {
    #[cfg(feature = "test-overrides")]
    let interactive = std::env::var("CONFIDANT_TEST_FORCE_INTERACTIVE").is_ok();
    #[cfg(not(feature = "test-overrides"))]
    let interactive = std::io::stdin().is_terminal();
    if !interactive || no_input || json {
        return Ok(false);
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    // Integration-test hook: piped stdin is never a TTY, so tests supply
    // answers (one per line, in prompt order) instead of typing. Unset =
    // read stdin as usual (a closed pipe reads EOF and fails closed).
    #[cfg(feature = "test-overrides")]
    if let Some(answer) = test_prompt_answer() {
        let answer = answer.trim();
        return Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"));
    }
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes"))
}

/// Runs a command the operator explicitly confirmed (#376). Production
/// spawns it and reports a non-zero exit as an error. Under
/// `test-overrides`, `CONFIDANT_TEST_COMMAND_RECORDER` names a file the
/// rendered command is appended to instead of executing — tests never run
/// a real install or a real `check`. `CONFIDANT_TEST_COMMAND_FAIL=1`
/// simulates a failure after recording.
fn run_offered_command(
    display: &str,
    program: &std::ffi::OsStr,
    args: &[&str],
) -> anyhow::Result<()> {
    #[cfg(feature = "test-overrides")]
    if let Ok(path) = std::env::var("CONFIDANT_TEST_COMMAND_RECORDER") {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        use std::io::Write as _;
        writeln!(f, "{display}")?;
        if std::env::var("CONFIDANT_TEST_COMMAND_FAIL").is_ok() {
            anyhow::bail!("simulated command failure (CONFIDANT_TEST_COMMAND_FAIL)");
        }
        return Ok(());
    }
    let status = std::process::Command::new(program).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("`{display}` exited with status {status}")
    }
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
    person: &ResolvedPersonArg,
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
            let mut obj = serde_json::json!({
                "dry_run": true,
                "queued": false,
                "fallback_inbox": true,
                "items": stems,
            });
            if let Some(echo) = person.echo_json() {
                obj["person"] = echo;
            }
            print_json(&ok_envelope(Some(root), obj))?;
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
        let mut obj = serde_json::json!({
            "queued": true,
            "fallback_inbox": true,
            "items": stems,
            "tip": tip,
        });
        if let Some(echo) = person.echo_json() {
            obj["person"] = echo;
        }
        print_json(&ok_envelope(Some(root), obj))?;
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
             `confidant init` (new vault), clone this vault and `confidant keys device-add`, \
             or `confidant recover` only if every enrolled device is lost.",
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
    // #611: appending commits the whole month file (`git add`), so an
    // unrelated uncommitted line in it would be swept into this commit.
    // Refuse before writing anything; the dry run still previews. This is
    // the ledger-append step of the proposal flow, which the TUI cannot
    // check itself (it never reads the vault). Other append paths are out
    // of this fix's scope.
    if !cli.dry_run {
        require_git_repo(root, cli.no_input)?;
        for path in by_file.keys() {
            if !confidant_core::paths::exists(root, path)? {
                continue;
            }
            let rel = path.to_string_lossy();
            let status = confidant_core::write::git(
                root,
                &["status", "--porcelain", "--", &rel],
                cli.no_input,
            )?;
            if !status.trim().is_empty() {
                return Err(anyhow::Error::new(
                    DomainError::conflict(format!(
                        "{} has uncommitted changes; appending would commit them too",
                        path.display()
                    ))
                    .with_fix("Commit, stash, or discard your changes to that file, then retry"),
                ));
            }
        }
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
    forced_id: Option<&str>,
    body_file: &Path,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    let person = resolve_person_arg(root, &vault, person_raw)?;
    announce_resolved_person(cli, &person);
    let date = parse_date_arg(&date_raw)?;
    let body = std::fs::read_to_string(body_file).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            body_file.display()
        )))
    })?;

    // #611: the TUI passes the manifest's own note id so the reviewed
    // dry-run and the commit name the same note. Without `--id` the id is
    // minted here, exactly as before.
    let nid = match forced_id {
        Some(raw) => parse_note_id(raw, "note add")?,
        None => RecordId::new(Prefix::Note, confidant_core::write::new_ulid())
            .map_err(|e| anyhow::anyhow!("generated bad note id: {e}"))?,
    };
    let rel = PathBuf::from(format!("people/{}/notes/{nid}.md", person.id));
    let mut fields = BTreeMap::from([
        ("person".to_owned(), person.id.to_string()),
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
    let canonical_request = format!(
        "note-add/v1\nperson={}\ndate={date}\nno_ai={no_ai}\nbody={body}",
        person.id
    );
    // A forced id must not overwrite an existing note. A genuine retry
    // (progress file lost after the commit) is recognized by its
    // request-id trailer, and apply_write reports it idempotent; only an
    // id we cannot account for refuses. A minted id is unique by
    // construction, so this only runs for `--id`.
    if forced_id.is_some() {
        ensure_note_target_free(root, &rel, &nid, cli, &canonical_request)?;
    }
    let (outcome, _) = apply_record_write(
        root,
        &vault,
        PendingWrite {
            changes: vec![FileChange::WriteFile {
                path: rel.clone(),
                contents: confidant_core::format_record(&rec),
            }],
            summary: format!("note {} {nid}", person.id),
            canonical_request,
        },
        &write_options(cli),
    )?;
    let mut extra = serde_json::json!({
        "id": nid.to_string(),
        "path": rel.display().to_string(),
    });
    if let Some(echo) = person.echo_json() {
        extra["person"] = echo;
    }
    finish_write(cli, root, "note-add", outcome, extra)
}

/// Refuse a forced note id whose target already exists, unless this exact
/// request already committed it (then the write pipeline reports it
/// idempotent and never rewrites). `--id` exists for the TUI's #611
/// dry-run→apply binding; a collision means a stale or hand-edited
/// manifest, which must not silently overwrite a note.
fn ensure_note_target_free(
    root: &Path,
    rel: &Path,
    nid: &RecordId,
    cli: &Cli,
    canonical_request: &str,
) -> anyhow::Result<()> {
    if !confidant_core::paths::exists(root, rel)? {
        return Ok(());
    }
    let opts = write_options(cli);
    if let Some(rid) = opts.request_id.as_deref() {
        let (id_hash, _) = confidant_core::write::idempotency_digests(rid, canonical_request);
        if confidant_core::write::find_request_commit(root, &id_hash, opts.no_input)?.is_some() {
            return Ok(());
        }
    }
    Err(anyhow::Error::new(
        DomainError::already_exists(format!("note {nid} already exists at {}", rel.display()))
            .with_fix("Pick a fresh note id, or edit the existing note with `confidant note edit`"),
    ))
}

// ---------------------------------------------------------------------------
// note show (operator-only) / note edit (#557)
// ---------------------------------------------------------------------------

/// Parse a positional note id: a usage error (exit 2, ADR-7) for a
/// malformed id or a non-note prefix. `verb` labels the error context.
fn parse_note_id(id_raw: &str, verb: &str) -> anyhow::Result<RecordId> {
    let id = RecordId::parse(id_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a note id: {id_raw}"))).context(format!(
            "`{verb}` takes an opaque note id; use `confidant find <name>` to look one up"
        ))
    })?;
    if id.prefix() != Prefix::Note {
        return Err(anyhow::Error::new(DomainError::usage(format!(
            "not a note id: {id_raw}"
        ))));
    }
    Ok(id)
}

/// Vault-relative path of a note file under `people/<person>/notes/` when
/// the loaded vault has no record for it, located by scanning the owner
/// directories. `None` when no note file matches. Used to tell an
/// unreadable note apart from a missing one in the error, never to derive
/// a write target.
fn note_path_for(root: &Path, id: &RecordId) -> Option<PathBuf> {
    let file = format!("{id}.md");
    let people = std::fs::read_dir(root.join("people")).ok()?;
    for entry in people.flatten() {
        if entry.path().join("notes").join(&file).is_file() {
            return Some(PathBuf::from(format!(
                "people/{}/notes/{file}",
                entry.file_name().to_string_lossy()
            )));
        }
    }
    None
}

/// Fail-closed error for a note id whose file exists on disk but did not
/// load: an envelope this device cannot decrypt, or a file that is not a
/// readable note. Mirrors `record show`'s ladder; never names the body.
fn note_unreadable_error(id_raw: &str, rel: &Path, bytes: &[u8]) -> anyhow::Error {
    if confidant_core::crypto_mode::is_envelope_bytes(bytes) {
        anyhow::Error::new(
            DomainError::invalid(format!(
                "cannot read {id_raw}: this device cannot decrypt it"
            ))
            .with_fix(
                "Run `confidant recover` on this device, or ask an enrolled device to add it via `confidant keys device-add`",
            ),
        )
    } else {
        anyhow::Error::new(
            DomainError::invalid(format!(
                "cannot read {id_raw}: {} is not a readable note",
                rel.display()
            ))
            .with_fix("Run `confidant check` for the finding on that file"),
        )
    }
}

/// The decrypted plaintext of one note file, through the operator read
/// path (`RecordDecryptor::for_edit`), for the editor round trip. Fail
/// closed per outcome; never logs the body.
fn note_plaintext(root: &Path, vault_id: &str, rel: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(root.join(rel)).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            rel.display()
        )))
    })?;
    if !confidant_core::crypto_mode::is_envelope_bytes(&bytes) {
        return String::from_utf8(bytes).map_err(|_| {
            anyhow::Error::new(DomainError::invalid(format!(
                "{} is not valid UTF-8",
                rel.display()
            )))
        });
    }
    match record_decrypt::RecordDecryptor::for_edit(root, vault_id)
        .decrypt_bytes(&rel.to_string_lossy(), &bytes)
    {
        ContentOutcome::Content(plaintext) => String::from_utf8(plaintext).map_err(|_| {
            anyhow::Error::new(DomainError::invalid(format!(
                "{} does not decrypt to valid UTF-8",
                rel.display()
            )))
        }),
        ContentOutcome::NoAiShell { .. } => Err(anyhow::Error::new(DomainError::internal(
            "operator decryptor returned a no-ai shell for a note",
        ))),
        ContentOutcome::Skipped => Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "cannot edit {}: this device cannot decrypt the note",
                rel.display()
            ))
            .with_fix(
                "Run `confidant recover` on this device, or ask an enrolled device to add it via `confidant keys device-add`",
            ),
        )),
        ContentOutcome::Refused => Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "cannot edit {}: the envelope failed authentication",
                rel.display()
            ))
            .with_fix("The envelope is tampered or corrupt; restore it from git history"),
        )),
    }
}

/// #557: print one note's decrypted text so the operator can edit it.
///
/// Operator-only by construction: `mcp.rs` maps a fixed tool whitelist to
/// argv and this command is not in it, so no agent connection can reach
/// it. `--for-edit` is required rather than optional so a bare invocation
/// can never print a decrypted note body. Unlike the agent read path,
/// `no-ai` notes are decrypted in full (`RecordDecryptor::for_edit`):
/// notes are where `no-ai` prose lives, and the operator's tooling is the
/// only window onto it (spec §12 is unchanged for agents).
fn cmd_note_show(cli: &Cli, root: &Path, id_raw: &str, for_edit: bool) -> anyhow::Result<ExitCode> {
    if !for_edit {
        return Err(anyhow::Error::new(DomainError::usage(
            "note show is operator-only and exists to prepare an edit; pass --for-edit",
        )));
    }
    let vault = match load_vault_for_reads(root, cli.json, true) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    if vault.config.spec != confidant_core::SPEC_VERSION {
        return Err(anyhow::Error::new(DomainError::spec_unsupported(
            &vault.config.spec,
        )));
    }
    let id = parse_note_id(id_raw, "note show")?;
    let Some(rec) = vault.records.get(&id) else {
        // A file that is on disk but did not load is a problem with that
        // file. Only claim a decryption failure when the file really is an
        // envelope (as `record show` does).
        if let Some(rel) = note_path_for(root, &id) {
            if let Ok(bytes) = std::fs::read(root.join(&rel)) {
                return Err(note_unreadable_error(id_raw, &rel, &bytes));
            }
        }
        return Err(anyhow::Error::new(DomainError::not_found(format!(
            "no note with id {id_raw}"
        )))
        .context("use `confidant find <name>` to look up the id"));
    };
    let text = rec.source.clone();
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "id": id.to_string(),
                "type": rec.kind.as_str(),
                "path": rec.path,
                "no_ai": rec.no_ai(),
                "for_edit": true,
                "text": text,
            }),
        ))?;
    } else {
        // Byte-for-byte on stdout, so it can be redirected into an editor
        // or a file and edited in place.
        print!("{text}");
    }
    Ok(ExitCode::SUCCESS)
}

/// #557: replace an existing note's file from `--file` or the editor.
///
/// The write goes through [`apply_record_write`], so in an encrypted vault
/// it re-encrypts with a fresh nonce, runs `check` before the commit, and
/// makes one commit — exactly like `record edit`; an unchanged body reuses
/// the existing ciphertext and reports `unchanged` with no commit. The
/// target path is the note's existing location, never a path the caller or
/// the edited text chose: a note's `person:` must keep matching its
/// directory (a change re-routes the client key and, in an encrypted
/// vault, is invisible to the post-write `check`, so it is refused before
/// encryption).
fn cmd_note_edit(
    cli: &Cli,
    root: &Path,
    id_raw: &str,
    file: Option<&Path>,
    edit: bool,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    if vault.config.spec != confidant_core::SPEC_VERSION {
        return Err(anyhow::Error::new(DomainError::spec_unsupported(
            &vault.config.spec,
        )));
    }
    let id = parse_note_id(id_raw, "note edit")?;
    // Sweep stale `--edit` scratch from a crashed earlier run (#455
    // convention). Harmless for a `--file` edit and for a dry run: it only
    // zero-overwrites and removes `.confidant/notes/`.
    record_resolve::sweep_stale_note_scratch(root);
    // Pin the existing file first: the edit can never move the note. A note
    // that is on disk but did not load is reported for what it is rather
    // than as missing.
    let rel = match vault.records.get(&id) {
        Some(rec) if rec.kind == RecordKind::Note => PathBuf::from(&rec.path),
        Some(_) => {
            return Err(anyhow::Error::new(DomainError::not_found(format!(
                "no note with id {id_raw}"
            ))))
        }
        None => match note_path_for(root, &id) {
            Some(rel) => {
                if let Ok(bytes) = std::fs::read(root.join(&rel)) {
                    return Err(note_unreadable_error(id_raw, &rel, &bytes));
                }
                return Err(anyhow::Error::new(DomainError::not_found(format!(
                    "no note with id {id_raw}"
                ))));
            }
            None => {
                return Err(anyhow::Error::new(DomainError::not_found(format!(
                    "no note with id {id_raw}"
                )))
                .context("use `confidant find <name>` to look up the id"))
            }
        },
    };
    // The owner implied by the path, so the person check below never trusts
    // the edited text.
    let owner =
        confidant_core::id::person_id_from_path(&rel.to_string_lossy()).ok_or_else(|| {
            anyhow::Error::new(DomainError::internal(format!(
                "note {id_raw} does not live under people/<person>/notes/"
            )))
        })?;
    let (text, provisional) = if let Some(file) = file {
        let text = std::fs::read_to_string(file).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read {}: {e}",
                file.display()
            )))
        })?;
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "note.md".to_owned());
        (text, name)
    } else {
        // `--edit`: open the operator's editor on 0600 scratch (#455
        // convention). Fail fast if no editor is configured, before any
        // plaintext scratch exists.
        debug_assert!(edit, "clap requires --file or --edit");
        let current = note_plaintext(root, &vault.config.vault_id, &rel)?;
        record_resolve::resolve_editor()?;
        let (mut guard, scratch) = record_resolve::setup_note_edit_scratch(root, &id, &current)?;
        let result = record_resolve::run_note_editor(&scratch).and_then(|()| {
            std::fs::read_to_string(&scratch).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot read {}: {e}",
                    scratch.display()
                )))
            })
        });
        // Explicit cleanup on every path; drop after is a no-op.
        guard.cleanup();
        (result?, "note.md".to_owned())
    };
    let rec = confidant_core::parse_record(&text, &provisional)
        .map_err(|e| anyhow::Error::new(DomainError::invalid(e.message).with_fix(e.fix)))?;
    if rec.kind != RecordKind::Note {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "note edit takes a note; the file's type is {}",
            rec.kind.as_str()
        ))));
    }
    if rec.id != id {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!("the file's id is {}, not {id_raw}", rec.id))
                .with_fix("Edit the note the file names, or fix `id:` in the file"),
        ));
    }
    // An envelope is ciphertext, not note plaintext: re-encrypting it would
    // bury a second layer. Point at the operator read instead.
    if rec.field("enc").is_some() {
        return Err(anyhow::Error::new(
            DomainError::invalid("the file is an encrypted note envelope, not note text")
                .with_fix(
                    "Use `confidant note show <id> --for-edit` to get the text, edit that, then re-run `note edit`",
                ),
        ));
    }
    // Fail closed before encrypting (#412-style). The post-write `check`
    // runs against the envelope in an encrypted vault, so a note whose
    // `person:` no longer matches its directory would otherwise be
    // committed and only surface on decrypt.
    if rec.person().as_ref() != Some(&owner) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "the edited note's person does not match its location ({}); a note cannot move",
                rel.display()
            ))
            .with_fix("Keep `person:` as it is, or use `note add` for a note on another person"),
        ));
    }
    let contents = confidant_core::format_record(&rec);
    // Fail closed when the stored file is an envelope this device cannot
    // decrypt, naming the real cause instead of re-encrypting over it.
    let existing = std::fs::read(root.join(&rel)).unwrap_or_default();
    if confidant_core::crypto_mode::is_envelope_bytes(&existing) {
        if let Some(enc) = record_crypto::RecordEncryptor::for_vault(root, &vault)? {
            enc.decrypt_existing(&rel, &existing).map_err(|_| {
                anyhow::Error::new(
                    DomainError::invalid(format!(
                        "cannot edit {id_raw}: this device cannot decrypt the note"
                    ))
                    .with_fix(
                        "Run `confidant recover` on this device, or ask an enrolled device to add it via `confidant keys device-add`",
                    ),
                )
            })?;
        }
    }
    let (outcome, _created) = apply_record_write(
        root,
        &vault,
        PendingWrite {
            changes: vec![FileChange::WriteFile {
                path: rel.clone(),
                contents,
            }],
            summary: format!("note {id}"),
            canonical_request: format!("note-edit/v1\npath={}\nbody={text}", rel.display()),
        },
        &write_options(cli),
    )?;
    finish_write(
        cli,
        root,
        "note-edit",
        outcome,
        serde_json::json!({ "id": id.to_string(), "path": rel.display().to_string() }),
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
    // #179/#505: an interaction mirrors one minimal touchpoint per person
    // involved (date + own id, nothing else) so cadence updates: one for the
    // primary `person:` and one per `with:` participant. A logged interaction
    // therefore counts as contact for everyone on it, while the check rules
    // stay ledger-only. The touchpoints land in the same write (same commit)
    // as the interaction record. The writer validates shape (parse, person
    // prefix, not the primary, no duplicates); existence is `check`'s job
    // (keyed check), like every other front-matter reference.
    let mut touch_lines: Vec<String> = Vec::new();
    let mut touch_change: Option<FileChange> = None;
    if rec.kind == RecordKind::Interaction {
        let primary = rec.person();
        let mut with: Vec<RecordId> = Vec::new();
        if let Some(raw) = rec.field("with") {
            with = confidant_core::record::parse_with_list(raw).ok_or_else(|| {
                anyhow::Error::new(
                    DomainError::invalid(
                        "front matter key 'with' is not a bracketed list of person IDs",
                    )
                    .with_fix("Use with: [p-<ULID>, p-<ULID>]"),
                )
            })?;
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
            }
        }
        // A `with:` list keeps the hard date requirement (#179). A
        // primary-only interaction mirrors only when it carries a usable
        // date; a dateless one still writes, it just counts as no contact.
        let date = if with.is_empty() {
            rec.field("date").and_then(parse_strict_date)
        } else {
            let date_raw = rec.field("date").ok_or_else(|| {
                anyhow::Error::new(
                    DomainError::invalid(
                        "interaction with with: needs a date (touchpoints are dated)",
                    )
                    .with_fix("Add date: YYYY-MM-DD to the interaction"),
                )
            })?;
            Some(parse_strict_date(date_raw).ok_or_else(|| {
                anyhow::Error::new(DomainError::invalid("interaction date is not YYYY-MM-DD"))
            })?)
        };
        if let Some(date) = date {
            if let Some(primary) = &primary {
                touch_lines.push(format!("{date} touch {primary}"));
            }
            for participant in &with {
                touch_lines.push(format!("{date} touch {participant}"));
            }
            if !touch_lines.is_empty() {
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
    // #179/#505: the mirrored touchpoints (primary first, then `with:`
    // participants), only when any were written.
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

/// Vault-relative main file path for a record id, derived from its prefix.
///
/// `None` for the prefixes this pair of commands does not handle: a note's
/// file lives at `people/<person>/notes/<id>.md` (not the collection/main
/// layout), and a package has no record file at all.
pub(crate) fn main_path_for(id: &RecordId) -> Option<PathBuf> {
    let prefix = id.prefix();
    if matches!(prefix, Prefix::Note | Prefix::Package) {
        return None;
    }
    Some(PathBuf::from(format!(
        "{}/{}/{}",
        prefix.collection()?,
        id,
        prefix.main_filename()?
    )))
}

/// Ids `record show` / `record edit` / `record resolve` do not handle,
/// refused as usage errors (exit 2, ADR-7) rather than looked up and
/// reported as missing.
///
/// Any `confidant <command>` hint in these messages must name a real
/// subcommand; `prefix_hint_names_an_existing_subcommand` enforces it so a
/// deleted command cannot leave a dead-end hint behind (#542).
pub(crate) fn reject_unsupported_prefix(id: &RecordId) -> anyhow::Result<()> {
    match id.prefix() {
        Prefix::Note => Err(anyhow::Error::new(DomainError::usage(
            "notes are not read or edited by `record`; their files live under people/<person>/notes/",
        ))),
        Prefix::Package => Err(anyhow::Error::new(DomainError::usage(
            "a package is a ledger id, not a record; use `confidant context <person>` to see a person's package balance",
        ))),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// record list (operator-only roster, #558)
// ---------------------------------------------------------------------------

/// #558: list the vault's records of one kind, one entry each.
///
/// Operator-only by construction: `mcp.rs` maps a fixed tool whitelist to
/// argv and this command is not in it, so no agent connection can reach it.
/// Without `--for-operator` the vault loads through the agent read path and
/// the roster is the §12 cleared set, so `no-ai: true` records are absent
/// (never present with a nulled name). With `--for-operator` the operator
/// decrypt path is used (`RecordDecryptor::for_edit`, the same mechanism as
/// `record show --for-edit`) and entries carry the tri-state `no_ai`
/// (`"true"` | `"notes"` | `"false"`) the #559 ruling specifies.
fn cmd_record_list(
    cli: &Cli,
    root: &Path,
    kind: RecordKind,
    for_operator: bool,
) -> anyhow::Result<ExitCode> {
    let vault = match load_vault_for_reads(root, cli.json, for_operator) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let vault_path = vault.root.display().to_string();
    if vault.config.spec != confidant_core::SPEC_VERSION {
        print_error(
            cli.json,
            Some(&vault_path),
            &DomainError::spec_unsupported(&vault.config.spec),
        )?;
        return Ok(ExitCode::from(1));
    }
    let (scope, scope_names) = match resolve_cli_scope(&vault, cli.packs.as_deref()) {
        Ok(pair) => pair,
        Err(err) => {
            print_error(cli.json, Some(&vault_path), &err)?;
            return Ok(ExitCode::from(err.exit_code() as u8));
        }
    };
    let roster = confidant_core::build_roster(&vault, kind, &scope, for_operator);
    if cli.json {
        print_json(&ok_envelope(
            Some(&vault.root),
            serde_json::to_value(&roster)?,
        ))?;
    } else {
        // #572: make operator mode unmistakable on a screen share, like
        // `find` / `context`. Without the flag the output is unchanged.
        if for_operator {
            writeln!(io::stdout(), "{OPERATOR_MODE_BANNER}")?;
        }
        for entry in &roster.records {
            let badge = match entry.no_ai {
                "true" => "\t[no-ai]",
                "notes" => "\t[no-ai: notes]",
                _ => "",
            };
            // Escape the name so a tab, newline, or terminal escape in a
            // display name cannot break the one-entry-per-line layout
            // (`escape_line` also neutralizes bidi/format characters).
            // `--json` is untouched: there the name is a JSON string.
            writeln!(
                io::stdout(),
                "{}\t{}{badge}",
                entry.id,
                confidant_core::packs::untrusted::escape_line(&entry.name)
            )?;
        }
        let noun = if kind == RecordKind::Person {
            "people"
        } else {
            "records"
        };
        writeln!(
            io::stdout(),
            "{} {noun} ({})",
            roster.records.len(),
            kind.as_str()
        )?;
        // ⚠2: never silently empty — the skip/refuse counts are always
        // visible when nonzero, and a scoped call names the scope that
        // applied (like `context`).
        if matches!(scope, PackScope::Only(_)) && !scope_names.is_empty() {
            writeln!(io::stdout(), "scope: {}", scope_names.join(", "))?;
        }
        if roster.skipped_encrypted > 0 {
            writeln!(
                io::stdout(),
                "skipped_encrypted: {}",
                roster.skipped_encrypted
            )?;
        }
        if roster.refused_envelopes > 0 {
            writeln!(
                io::stdout(),
                "refused_envelopes: {}",
                roster.refused_envelopes
            )?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// record show (operator-only) / record edit (#216)
// ---------------------------------------------------------------------------

/// #216: print one record's decrypted text so the operator can edit it.
///
/// Operator-only by construction: `mcp.rs` maps a fixed tool whitelist to
/// argv and this command is not in it, so no agent connection can reach it.
/// `--for-edit` is required rather than optional so that a bare invocation
/// can never print a decrypted record body — the flag is the operator
/// stating the intent to edit. Unlike the agent read path, `no-ai` records
/// are decrypted in full (`RecordDecryptor::for_edit`), because the
/// operator may edit them (spec §12 is unchanged for agents).
fn cmd_record_show(
    cli: &Cli,
    root: &Path,
    id_raw: &str,
    for_edit: bool,
) -> anyhow::Result<ExitCode> {
    if !for_edit {
        return Err(anyhow::Error::new(DomainError::usage(
            "record show is operator-only and exists to prepare an edit; pass --for-edit",
        )));
    }
    let vault = match load_vault_for_reads(root, cli.json, true) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    if vault.config.spec != confidant_core::SPEC_VERSION {
        return Err(anyhow::Error::new(DomainError::spec_unsupported(
            &vault.config.spec,
        )));
    }
    let id = RecordId::parse(id_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a record id: {id_raw}"))).context(
            "`record show` takes an opaque record id; use `confidant find <name>` to look one up",
        )
    })?;
    reject_unsupported_prefix(&id)?;
    let Some(rec) = vault.records.get(&id) else {
        // A file that is on disk but did not load is a problem with that
        // file. Only claim a decryption failure when the file really is an
        // envelope: a plaintext record that failed to parse is a different
        // error, and `check` already reports it (⚠2b, as in `context`).
        if let Some(rel) = main_path_for(&id) {
            if let Ok(bytes) = std::fs::read(root.join(&rel)) {
                if confidant_core::crypto_mode::is_envelope_bytes(&bytes) {
                    return Err(anyhow::Error::new(
                        DomainError::invalid(format!(
                            "cannot read {id_raw}: this device cannot decrypt it"
                        ))
                        .with_fix(
                            "Run `confidant recover` on this device, or ask an enrolled device to add it via `confidant keys device-add`",
                        ),
                    ));
                }
                return Err(anyhow::Error::new(
                    DomainError::invalid(format!(
                        "cannot read {id_raw}: {} is not a readable record",
                        rel.display()
                    ))
                    .with_fix("Run `confidant check` for the finding on that file"),
                ));
            }
        }
        return Err(anyhow::Error::new(DomainError::not_found(format!(
            "no record with id {id_raw}"
        )))
        .context("use `confidant find <name>` to look up the id"));
    };
    let text = rec.source.clone();
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "id": id.to_string(),
                "type": rec.kind.as_str(),
                "path": rec.path,
                "no_ai": rec.no_ai(),
                "for_edit": true,
                "text": text,
            }),
        ))?;
    } else {
        // Byte-for-byte on stdout, so it can be redirected into an editor
        // or a file and edited in place.
        print!("{text}");
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// record resolve (operator-only) (#453, part of #219)
// ---------------------------------------------------------------------------

/// #453: print both decrypted versions of a conflicted record so the
/// operator can resolve a merge conflict.
///
/// Operator-only by construction: `mcp.rs` maps a fixed tool whitelist to
/// argv and this command is not in it. Decryption runs through the operator
/// decryptor (`RecordDecryptor::for_edit`), so `no-ai` records are shown in
/// full; plaintext goes to stdout only, never to logs or error messages.
/// The read half of resolution: `--take`, `--merged-file` and `--edit`
/// land in #454/#455.
#[allow(clippy::too_many_arguments)]
fn cmd_record_resolve(
    cli: &Cli,
    root: &Path,
    user_config: Option<&UserConfig>,
    id_raw: &str,
    from_inbox: Option<&str>,
    show: bool,
    take: Option<Side>,
    merged_file: Option<&Path>,
    edit: bool,
    allow_unsigned: bool,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    if vault.config.spec != confidant_core::SPEC_VERSION {
        return Err(anyhow::Error::new(DomainError::spec_unsupported(
            &vault.config.spec,
        )));
    }
    let id = RecordId::parse(id_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a record id: {id_raw}"))).context(
            "`record resolve` takes an opaque record id; use `confidant find <name>` to look one up",
        )
    })?;
    // Sweep stale `--edit` scratch from a crashed earlier run (CD5). This
    // runs for every resolve action, not just `--edit`. It also runs
    // under `--dry-run`, deliberately: cleaning up zeroed scratch left
    // behind by a previous crashed run is recovery of this command's own
    // local state, not a vault write, and `--dry-run` promises the vault
    // stays untouched, not the scratch dir. (#487 item 1.)
    record_resolve::sweep_stale_scratch(root);
    if let Some(stem) = from_inbox {
        return cmd_record_resolve_from_inbox(
            cli,
            root,
            &vault,
            user_config,
            &id,
            id_raw,
            stem,
            show,
            take,
            merged_file,
            edit,
            allow_unsigned,
        );
    }
    if show {
        let sides = record_resolve::load_sides(root, &vault.config.vault_id, &id)?;
        let ours_text = String::from_utf8_lossy(&sides.ours_bytes);
        let theirs_text = String::from_utf8_lossy(&sides.theirs_bytes);
        if cli.json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "id": id.to_string(),
                    "path": sides.path,
                    "ours": { "label": sides.ours_label, "text": ours_text },
                    "theirs": { "label": sides.theirs_label, "text": theirs_text },
                }),
            ))?;
        } else {
            println!("== ours ({}) ==", sides.ours_label);
            println!("{ours_text}");
            println!("== theirs ({}) ==", sides.theirs_label);
            println!("{theirs_text}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(side) = take {
        // #454: install one side byte for byte, stage it, print the next
        // git step. Both sides were decrypted by `load_sides`, so the
        // operator has seen what they discard (CD7).
        let sides = record_resolve::load_sides(root, &vault.config.vault_id, &id)?;
        // #465: `--dry-run` verifies both sides are decryptable (same
        // CD7 read the real write needs) but writes nothing.
        if cli.dry_run {
            return print_resolve_dry_run(
                cli,
                root,
                &id,
                "take",
                &sides.path,
                ResolveDryRunDetail {
                    side: Some(side.name()),
                    merged_file: None,
                    from_inbox: None,
                    next: None,
                },
            );
        }
        let outcome = record_resolve::take_side(root, cli.no_input, &sides, side)?;
        if cli.json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "command": "record-resolve",
                    "action": "take",
                    "side": side.name(),
                    "id": id.to_string(),
                    "path": sides.path,
                    "staged": true,
                    "next": outcome.next,
                }),
            ))?;
        } else {
            println!(
                "Kept the {} side of {} ({}); staged.",
                side.name(),
                id,
                sides.path.display()
            );
            println!("Next: {}", outcome.next);
        }
        return Ok(ExitCode::SUCCESS);
    }
    // Only --merged-file/--edit remain; the flags are accepted so the
    // interface does not change when they land.
    if let Some(merged_path) = merged_file {
        // #455: hand-merge from a file outside the vault. The operator's
        // file is validated like `record edit --file` and re-encrypted
        // through the same path; it is staged, never committed (CD6).
        let sides = record_resolve::load_sides(root, &vault.config.vault_id, &id)?;
        // CD5: refuse ANY path inside the vault tree, no `.confidant/`
        // exception, so a plaintext merge file cannot be committed by
        // accident.
        let canonical = record_resolve::refuse_vault_path(root, merged_path)?;
        let text = std::fs::read_to_string(&canonical).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read {}: {e}",
                canonical.display()
            )))
        })?;
        // #473: refuse an unfinished merge before it is re-encrypted.
        record_resolve::refuse_merged_conflict_markers(
            &text,
            &format!("the merged file {}", canonical.display()),
        )
        .map_err(anyhow::Error::new)?;
        let provisional = canonical
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "record.md".to_owned());
        let prepared = prepare_record_write(
            root,
            &vault,
            PrepareSpec {
                id: &id,
                id_raw,
                text: &text,
                provisional: &provisional,
                summary: format!("record-resolve {id}"),
                canonical_prefix: "record-resolve/v1",
                allow_conflict: true,
            },
        )?;
        // Defense in depth: the merged record must name the conflicted
        // file's own path.
        if prepared.rel != sides.path {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "the merged record belongs at {}, not {}",
                prepared.rel.display(),
                sides.path.display()
            ))));
        }
        let rekeyed = record_resolve::rekeyed_for_merge(&sides, &prepared.rec);
        // #465: `--dry-run` runs the full read-only validation above but
        // stops before the re-encrypt/install step.
        if cli.dry_run {
            return print_resolve_dry_run(
                cli,
                root,
                &id,
                "merged-file",
                &sides.path,
                ResolveDryRunDetail {
                    side: None,
                    merged_file: Some(&canonical),
                    from_inbox: None,
                    next: None,
                },
            );
        }
        let outcome = record_resolve::apply_merge(root, cli.no_input, &vault, &prepared)?;
        return print_merge_result(cli, root, &id, &outcome, rekeyed);
    }
    if edit {
        // #465: `--dry-run --edit` creates no scratch and installs nothing;
        // `load_sides` is the same decrypt check the real edit would do.
        if cli.dry_run {
            let sides = record_resolve::load_sides(root, &vault.config.vault_id, &id)?;
            return print_resolve_dry_run(
                cli,
                root,
                &id,
                "edit",
                &sides.path,
                ResolveDryRunDetail {
                    side: None,
                    merged_file: None,
                    from_inbox: None,
                    next: None,
                },
            );
        }
        return cmd_resolve_edit(cli, root, &vault, &id, id_raw);
    }
    // Unreachable: clap's ArgGroup requires exactly one resolve action.
    Err(anyhow::Error::new(DomainError::usage(
        "choose one of --show, --take, --merged-file, --edit",
    )))
}

/// Build the inbox-item decrypt closure (same key path the drain uses).
///
/// Used by `record resolve --from-inbox` to decrypt the named item.
fn inbox_decrypt_closure() -> anyhow::Result<impl Fn(&[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>>> {
    let keys = confidant_core::InboxKeys::load_opt()?;
    let inbox_keys: Option<std::sync::Arc<confidant_core::InboxKeys>> =
        keys.map(std::sync::Arc::new);
    Ok(move |ciphertext: &[u8]| match &inbox_keys {
        Some(k) => k.decrypt(ciphertext),
        None => Err(anyhow::Error::new(DomainError::inbox_crypto(
            "no inbox key enrolled".to_string(),
        ))),
    })
}

/// #457: `record resolve <id> --from-inbox <stem> <action>` — resolve a
/// record against a conflicting inbox item.
///
/// `ours` is the current record on main (decrypted with the operator key);
/// `theirs` is the inbox item's plaintext. The actions mirror the markers
/// source: `--show` prints both; `--take ours` keeps the file and prints
/// the `inbox --discard` hint; `--take theirs` encrypts the item's
/// plaintext through the `record edit` encryptor (#455's apply path — there
/// is no envelope to keep byte for byte); `--merged-file` / `--edit` run
/// the #455 hand-merge with the inbox sides.
#[allow(clippy::too_many_arguments)]
fn cmd_record_resolve_from_inbox(
    cli: &Cli,
    root: &Path,
    vault: &confidant_core::vault::Vault,
    user_config: Option<&UserConfig>,
    id: &RecordId,
    id_raw: &str,
    stem: &str,
    show: bool,
    take: Option<Side>,
    merged_file: Option<&Path>,
    edit: bool,
    allow_unsigned: bool,
) -> anyhow::Result<ExitCode> {
    let decrypt = inbox_decrypt_closure()?;
    let sides =
        record_resolve::load_sides_from_inbox(root, &vault.config.vault_id, id, stem, &decrypt)?;
    if show {
        let ours_text = String::from_utf8_lossy(&sides.ours_bytes);
        let theirs_text = String::from_utf8_lossy(&sides.theirs_bytes);
        if cli.json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "id": id.to_string(),
                    "path": sides.path,
                    "from_inbox": stem,
                    "ours": { "label": sides.ours_label, "text": ours_text },
                    "theirs": { "label": sides.theirs_label, "text": theirs_text },
                }),
            ))?;
        } else {
            println!("== ours ({}) ==", sides.ours_label);
            println!("{ours_text}");
            println!("== theirs ({}) ==", sides.theirs_label);
            println!("{theirs_text}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    // Write actions run the drain's signed-tip trust check (#457): the
    // inbox item's content is about to land in the encrypted record, and
    // these actions can run without `--show` first. `--show` stays
    // read-only above. Honors `--allow-unsigned` like the drain.
    //
    // The tip pinned by the read is what gets verified, and the branch must
    // still point there: verifying one commit while writing another's bytes
    // is exactly the gap the drain closes with `E_INBOX_RACE` (#457 review).
    let trusted_signers = user_config
        .map(|u| u.trust.signers.clone())
        .unwrap_or_default();
    let tip = sides.inbox_tip.as_deref().ok_or_else(|| {
        anyhow::Error::new(DomainError::internal(
            "inbox-sourced resolve is missing the tip it read the item at",
        ))
    })?;
    confidant_core::verify_inbox_trust(root, &trusted_signers, allow_unsigned, tip)?;
    if allow_unsigned {
        eprintln!("warning: {}", confidant_core::ALLOW_UNSIGNED_WARNING);
    }
    if let Some(side) = take {
        match side {
            Side::Ours => {
                // The file is already the ours side: nothing to write and
                // nothing to stage. Point at `inbox --discard` — otherwise
                // the item would conflict forever.
                if cli.dry_run {
                    // #465: even this no-write action reports `dry_run`
                    // rather than implying the item was consumed.
                    return print_resolve_dry_run(
                        cli,
                        root,
                        id,
                        "take",
                        &sides.path,
                        ResolveDryRunDetail {
                            side: Some("ours"),
                            merged_file: None,
                            from_inbox: Some(stem),
                            next: Some(&format!("confidant inbox --discard {stem}")),
                        },
                    );
                }
                if cli.json {
                    print_json(&ok_envelope(
                        Some(root),
                        serde_json::json!({
                            "command": "record-resolve",
                            "action": "take",
                            "side": "ours",
                            "id": id.to_string(),
                            "path": sides.path,
                            "staged": false,
                            "next": format!("confidant inbox --discard {stem}"),
                        }),
                    ))?;
                } else {
                    println!(
                        "Kept the current version of {} ({}); nothing staged.",
                        id,
                        sides.path.display()
                    );
                    println!("Next: confidant inbox --discard {stem}");
                }
                return Ok(ExitCode::SUCCESS);
            }
            Side::Theirs => {
                // No envelope to keep byte for byte: encrypt the item's
                // plaintext through the `record edit` path (#455).
                let text = String::from_utf8(sides.theirs_bytes.clone()).map_err(|_| {
                    anyhow::Error::new(DomainError::internal(format!(
                        "inbox item '{stem}' is not valid UTF-8"
                    )))
                })?;
                let prepared = prepare_record_write(
                    root,
                    vault,
                    PrepareSpec {
                        id,
                        id_raw,
                        text: &text,
                        provisional: &format!("{stem}.age"),
                        summary: format!("record-resolve {id}"),
                        canonical_prefix: "record-resolve/v1",
                        allow_conflict: false,
                    },
                )?;
                if prepared.rel != sides.path {
                    return Err(anyhow::Error::new(DomainError::invalid(format!(
                        "the inbox item belongs at {}, not {}",
                        prepared.rel.display(),
                        sides.path.display()
                    ))));
                }
                let rekeyed = record_resolve::rekeyed_for_merge(&sides, &prepared.rec);
                // #465: `--dry-run` runs the read-only validation above
                // (including the trust gate) but writes and stages nothing.
                if cli.dry_run {
                    return print_resolve_dry_run(
                        cli,
                        root,
                        id,
                        "take",
                        &sides.path,
                        ResolveDryRunDetail {
                            side: Some("theirs"),
                            merged_file: None,
                            from_inbox: Some(stem),
                            next: None,
                        },
                    );
                }
                let outcome = record_resolve::apply_merge(root, cli.no_input, vault, &prepared)?;
                return print_merge_result(cli, root, id, &outcome, rekeyed);
            }
        }
    }
    if let Some(merged_path) = merged_file {
        // Same hand-merge as #455, but the scratch sides come from the
        // inbox item rather than conflict markers.
        let canonical = record_resolve::refuse_vault_path(root, merged_path)?;
        let text = std::fs::read_to_string(&canonical).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read {}: {e}",
                canonical.display()
            )))
        })?;
        // #473: refuse an unfinished merge before it is re-encrypted.
        record_resolve::refuse_merged_conflict_markers(
            &text,
            &format!("the merged file {}", canonical.display()),
        )
        .map_err(anyhow::Error::new)?;
        let provisional = canonical
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "record.md".to_owned());
        let prepared = prepare_record_write(
            root,
            vault,
            PrepareSpec {
                id,
                id_raw,
                text: &text,
                provisional: &provisional,
                summary: format!("record-resolve {id}"),
                canonical_prefix: "record-resolve/v1",
                allow_conflict: false,
            },
        )?;
        if prepared.rel != sides.path {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "the merged record belongs at {}, not {}",
                prepared.rel.display(),
                sides.path.display()
            ))));
        }
        let rekeyed = record_resolve::rekeyed_for_merge(&sides, &prepared.rec);
        // #465: `--dry-run` stops before the re-encrypt/install step; the
        // validation above is read-only.
        if cli.dry_run {
            return print_resolve_dry_run(
                cli,
                root,
                id,
                "merged-file",
                &sides.path,
                ResolveDryRunDetail {
                    side: None,
                    merged_file: Some(&canonical),
                    from_inbox: Some(stem),
                    next: None,
                },
            );
        }
        let outcome = record_resolve::apply_merge(root, cli.no_input, vault, &prepared)?;
        return print_merge_result(cli, root, id, &outcome, rekeyed);
    }
    if edit {
        // #465: `--dry-run --edit` writes no scratch and installs nothing;
        // the editor path is the same otherwise (#457).
        if cli.dry_run {
            return print_resolve_dry_run(
                cli,
                root,
                id,
                "edit",
                &sides.path,
                ResolveDryRunDetail {
                    side: None,
                    merged_file: None,
                    from_inbox: Some(stem),
                    next: None,
                },
            );
        }
        return cmd_resolve_edit_from_inbox(cli, root, vault, id, id_raw, &sides);
    }
    // Unreachable: clap's ArgGroup requires exactly one resolve action.
    Err(anyhow::Error::new(DomainError::usage(
        "choose one of --show, --take, --merged-file, --edit",
    )))
}

/// #457: `record resolve <id> --from-inbox <stem> --edit` — hand-merge in
/// the operator's editor, with the inbox item as the theirs side.
///
/// Reuses #455's scratch/edit/apply machinery; only the sides differ.
fn cmd_resolve_edit_from_inbox(
    cli: &Cli,
    root: &Path,
    vault: &confidant_core::vault::Vault,
    id: &RecordId,
    id_raw: &str,
    sides: &record_resolve::LoadedSides,
) -> anyhow::Result<ExitCode> {
    record_resolve::resolve_editor()?;
    let (mut guard, merged_path) = record_resolve::setup_edit_scratch(root, id, sides)?;
    record_resolve::run_editor(&merged_path)?;
    let text = std::fs::read_to_string(&merged_path).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            merged_path.display()
        )))
    })?;
    // #473: refuse an unfinished merge before it is re-encrypted. The
    // guard is dropped by the `?`, cleaning the scratch up.
    record_resolve::refuse_merged_conflict_markers(
        &text,
        &format!("the merged record from {}", merged_path.display()),
    )
    .map_err(anyhow::Error::new)?;
    let prepared = prepare_record_write(
        root,
        vault,
        PrepareSpec {
            id,
            id_raw,
            text: &text,
            provisional: "merged.md",
            summary: format!("record-resolve {id}"),
            canonical_prefix: "record-resolve/v1",
            allow_conflict: false,
        },
    )?;
    if prepared.rel != sides.path {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "the merged record belongs at {}, not {}",
            prepared.rel.display(),
            sides.path.display()
        ))));
    }
    let rekeyed = record_resolve::rekeyed_for_merge(sides, &prepared.rec);
    let outcome = record_resolve::apply_merge(root, cli.no_input, vault, &prepared)?;
    guard.cleanup();
    print_merge_result(cli, root, id, &outcome, rekeyed)
}

fn print_merge_result(
    cli: &Cli,
    root: &Path,
    id: &RecordId,
    outcome: &record_resolve::MergeOutcome,
    rekeyed: Option<(String, String)>,
) -> anyhow::Result<ExitCode> {
    if cli.json {
        let mut obj = serde_json::json!({
            "command": "record-resolve",
            "action": "merge",
            "id": id.to_string(),
            "path": outcome.path,
            "staged": true,
            "next": outcome.next,
        });
        if let Some((from, to)) = &rekeyed {
            obj["rekeyed"] = serde_json::json!({ "from": from, "to": to });
        }
        print_json(&ok_envelope(Some(root), obj))?;
    } else {
        println!("Merged {} ({}); staged.", id, outcome.path.display());
        if let Some((from, to)) = &rekeyed {
            println!("rekeyed {id}: {from} -> {to}");
        }
        println!("Next: {}", outcome.next);
    }
    Ok(ExitCode::SUCCESS)
}

/// #465: report what a `record resolve` write action would do instead of
/// doing it, when the global `--dry-run` flag is set.
///
/// Callers reach this only after read-only validation (`load_sides`,
/// `refuse_vault_path`, reading `--merged-file`, `prepare_record_write`):
/// the dry run fails the same way the real run would, and by this point
/// nothing has been written — no vault file, no index entry, no scratch,
/// no inbox change (CD6: stage only, never commit — here not even that).
struct ResolveDryRunDetail<'a> {
    /// `--take <side>`: the side spelling as printed elsewhere.
    side: Option<&'a str>,
    /// `--merged-file`: the operator's local file (outside the vault).
    merged_file: Option<&'a Path>,
    /// `--from-inbox <stem>`: the item stem, for `inbox --discard` hints.
    from_inbox: Option<&'a str>,
    /// A follow-up command the real run would suggest.
    next: Option<&'a str>,
}

fn print_resolve_dry_run(
    cli: &Cli,
    root: &Path,
    id: &RecordId,
    action: &str,
    path: &Path,
    detail: ResolveDryRunDetail<'_>,
) -> anyhow::Result<ExitCode> {
    if cli.json {
        let mut obj = serde_json::json!({
            "command": "record-resolve",
            "dry_run": true,
            "action": action,
            "id": id.to_string(),
            "path": path,
            "staged": false,
        });
        let o = obj.as_object_mut().expect("json object literal");
        if let Some(side) = detail.side {
            o.insert("side".into(), serde_json::json!(side));
        }
        if let Some(merged_file) = detail.merged_file {
            o.insert(
                "merged_file".into(),
                serde_json::json!(merged_file.display().to_string()),
            );
        }
        if let Some(stem) = detail.from_inbox {
            o.insert("from_inbox".into(), serde_json::json!(stem));
        }
        if let Some(next) = detail.next {
            o.insert("next".into(), serde_json::json!(next));
        }
        print_json(&ok_envelope(Some(root), obj))?;
    } else {
        // Text mirrors the real action's wording; `nothing changed` is the
        // operator-visible gap versus a real run.
        if action == "take" && detail.side == Some("ours") {
            println!(
                "dry run — would keep the current version of {} ({}); nothing changed.",
                id,
                path.display()
            );
        } else if action == "take" {
            println!(
                "dry run — would keep the {} side of {} ({}); nothing changed.",
                detail.side.unwrap_or("?"),
                id,
                path.display()
            );
        } else if action == "merged-file" {
            println!(
                "dry run — would install {} into {} ({}); nothing changed.",
                detail
                    .merged_file
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                id,
                path.display()
            );
        } else {
            println!(
                "dry run — would open the merge for {} ({}) in an editor; nothing changed.",
                id,
                path.display()
            );
        }
        if let Some(next) = detail.next {
            println!("Next: {next}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// #455: `record resolve <id> --edit` — hand-merge in the operator's
/// editor with 0600 scratch files under `.confidant/conflicts/<id>/`.
///
/// Both sides are decrypted to scratch (CD7 already held by `load_sides`);
/// `merged.md` is pre-filled with the ours plaintext. After the editor
/// exits, the merged text goes through the shared validate → re-encrypt →
/// stage path. Scratch is zero-overwritten and removed on every exit path
/// via `ScratchGuard` (explicit on success, drop on error).
fn cmd_resolve_edit(
    cli: &Cli,
    root: &Path,
    vault: &confidant_core::vault::Vault,
    id: &RecordId,
    id_raw: &str,
) -> anyhow::Result<ExitCode> {
    let sides = record_resolve::load_sides(root, &vault.config.vault_id, id)?;
    // Fail fast if no editor is configured, before creating any scratch
    // files (which would hold plaintext).
    record_resolve::resolve_editor()?;
    let (mut guard, merged_path) = record_resolve::setup_edit_scratch(root, id, &sides)?;
    // An editor failure returns here; the guard drops and cleans up.
    record_resolve::run_editor(&merged_path)?;
    let text = std::fs::read_to_string(&merged_path).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            merged_path.display()
        )))
    })?;
    // #473: refuse an unfinished merge before it is re-encrypted. The
    // guard is dropped by the `?`, cleaning the scratch up.
    record_resolve::refuse_merged_conflict_markers(
        &text,
        &format!("the merged record from {}", merged_path.display()),
    )
    .map_err(anyhow::Error::new)?;
    let prepared = prepare_record_write(
        root,
        vault,
        PrepareSpec {
            id,
            id_raw,
            text: &text,
            provisional: "merged.md",
            summary: format!("record-resolve {id}"),
            canonical_prefix: "record-resolve/v1",
            allow_conflict: true,
        },
    )?;
    if prepared.rel != sides.path {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "the merged record belongs at {}, not {}",
            prepared.rel.display(),
            sides.path.display()
        ))));
    }
    let rekeyed = record_resolve::rekeyed_for_merge(&sides, &prepared.rec);
    let outcome = record_resolve::apply_merge(root, cli.no_input, vault, &prepared)?;
    // Explicit cleanup on the success path (drop after is a no-op).
    guard.cleanup();
    print_merge_result(cli, root, id, &outcome, rekeyed)
}

/// Parameters for [`prepare_record_write`], bundled to keep the
/// argument count within clippy's limit.
pub(crate) struct PrepareSpec<'a> {
    /// The parsed record id.
    pub id: &'a RecordId,
    /// The raw id string, for error messages (preserves user spelling).
    pub id_raw: &'a str,
    /// The new record text (merged plaintext).
    pub text: &'a str,
    /// Filename used in parse error messages.
    pub provisional: &'a str,
    /// Summary for the planned write (e.g. `"record {id}"`).
    pub summary: String,
    /// Prefix for the idempotency canonical request (e.g. `"record-edit/v1"`).
    pub canonical_prefix: &'a str,
    /// Whether the existing file may have conflict markers. `record edit`
    /// refuses them (they must be resolved first); the resolve path
    /// expects them. The check runs before the no-ai restamp planning,
    /// which cannot read a conflicted file (#412 Q6).
    pub allow_conflict: bool,
}

/// The validated record and its planned write, shared by `record edit` and
/// `record resolve --merged-file` / `--edit` (#455).
///
/// `pending` holds the `WriteFile` changes (the record itself, plus #410
/// child re-stamps for a person whose `no-ai` mode changed). The caller
/// applies it: `cmd_record_edit` via [`apply_record_write_inner`] (which
/// commits), the resolve path by encrypting and staging each change
/// without committing (CD6).
pub(crate) struct PreparedWrite {
    /// The write to apply.
    pub pending: PendingWrite,
    /// Vault-relative path of the record file.
    pub rel: PathBuf,
    /// The parsed record (for rekeyed detection and reporting).
    pub rec: Record,
    /// Mode overrides for the encryptor (#410 no-ai re-stamp).
    pub mode_overrides: HashMap<String, confidant_crypt::envelope::NoAi>,
}

/// Validate `text` as the new contents of record `id` and plan the write.
///
/// Shared by `record edit` and `record resolve --merged-file` / `--edit`
/// (#455): parses the record, checks the id, validates `with:` lists,
/// derives the record path (which must already exist), formats the
/// canonical contents, and plans the #410 no-ai re-stamp for persons.
///
/// Does not read the existing file and does not apply the write. The
/// caller does its own fail-closed checks on the stored bytes first:
/// `cmd_record_edit`'s ladder (conflict markers, envelope identity,
/// rekeyed detection, decrypt), or the resolve path's `load_sides`
/// (which already verified the conflict and decrypted both sides, CD7).
///
/// `provisional` is the filename used in parse error messages;
/// `summary` and `canonical_prefix` label the planned write (e.g.
/// `"record {id}"` / `"record-edit/v1"` for edit).
fn prepare_record_write(
    root: &Path,
    vault: &confidant_core::vault::Vault,
    spec: PrepareSpec<'_>,
) -> anyhow::Result<PreparedWrite> {
    let PrepareSpec {
        id,
        id_raw,
        text,
        provisional,
        summary,
        canonical_prefix,
        allow_conflict,
    } = spec;
    let rec = confidant_core::parse_record(text, provisional)
        .map_err(|e| anyhow::Error::new(DomainError::invalid(e.message).with_fix(e.fix)))?;
    if rec.id != *id {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!("the file's id is {}, not {id_raw}", rec.id))
                .with_fix("Edit the record the file names, or fix `id:` in the file"),
        ));
    }
    // `record add` validates `with:` shape before encrypting, and an edit
    // must too: in an encrypted vault the post-write `check` cannot see
    // inside the envelope, so a malformed list would be committed and later
    // block `keys shred` (which refuses when an interaction's `with:` will
    // not parse). Touchpoints are not mirrored on an edit — see the PR notes.
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
            }
        }
    }
    let rel = main_record_path(&rec)
        .map_err(|e| anyhow::Error::new(DomainError::invalid(e.message).with_fix(e.fix)))?;
    if !root.join(&rel).exists() {
        return Err(anyhow::Error::new(
            DomainError::not_found(format!("no record file at {}", rel.display()))
                .with_fix("Use `confidant record add --file` to create a new record"),
        ));
    }
    // The conflict-marker guard must run before the no-ai restamp planning
    // below, which cannot read a conflicted file (#412 Q6). `record edit`
    // refuses; the resolve path expects a conflict and skips this.
    if !allow_conflict {
        let existing = std::fs::read(root.join(&rel)).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read {}: {e}",
                rel.display()
            )))
        })?;
        if confidant_core::crypto_mode::is_envelope_bytes(&existing)
            && confidant_core::record::has_conflict_markers(&String::from_utf8_lossy(&existing))
        {
            return Err(anyhow::Error::new(
                DomainError::invalid(format!(
                    "{} has unresolved merge conflicts; resolve them before editing",
                    rel.display()
                ))
                .with_fix("Resolve the conflict markers (git mergetool), then re-run the edit"),
            ));
        }
    }
    let contents = confidant_core::format_record(&rec);
    let mut changes = vec![FileChange::WriteFile {
        path: rel.clone(),
        contents,
    }];
    // #410: a person edit whose effective `no-ai` mode changes re-stamps
    // that person's existing children in the same commit — the header the
    // write-time stamp left behind moves with the person, in both
    // directions. Refuses the whole edit (nothing committed) when a
    // child cannot be read. See [`plan_no_ai_restamp`].
    //
    // Skipped for the resolve path (`allow_conflict`): the existing file
    // is conflicted by definition, so its mode cannot be read. The
    // operator can re-run an edit afterwards if a re-stamp is needed.
    let id_str = rec.id.to_string();
    let mode_overrides = if rec.kind == RecordKind::Person && !allow_conflict {
        let (overrides, child_changes) =
            plan_no_ai_restamp(root, vault, &id_str, record_crypto::person_own_mode(&rec))?;
        changes.extend(child_changes);
        overrides
    } else {
        HashMap::new()
    };
    Ok(PreparedWrite {
        pending: PendingWrite {
            changes,
            summary,
            canonical_request: format!("{canonical_prefix}\npath={}\nbody={}", rel.display(), text),
        },
        rel,
        rec,
        mode_overrides,
    })
}

/// #216: replace an existing main record's file from a markdown file.
///
/// The write goes through [`apply_record_write`], so in an encrypted vault
/// it encrypts, runs `check` before the commit, and makes one commit —
/// exactly like `record add`. The target path is derived from the record's
/// id, never from the path the caller passed, and the file's own `id:` must
/// match the id argument so a wrong file cannot silently clobber a record.
fn cmd_record_edit(cli: &Cli, root: &Path, id_raw: &str, file: &Path) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    // Parse the id the same way every other positional record id is parsed:
    // a malformed argument is a usage error (exit 2, ADR-7), and parsing
    // canonicalises a lowercase ULID instead of rejecting it.
    let id = RecordId::parse(id_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a record id: {id_raw}"))).context(
            "`record edit` takes an opaque record id; use `confidant find <name>` to look one up",
        )
    })?;
    reject_unsupported_prefix(&id)?;
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
    // Shared validation + write planning (#455). The fail-closed ladder
    // below is edit-specific: the resolve path already verified the
    // conflict and decrypted both sides via `load_sides` (CD7).
    let prepared = prepare_record_write(
        root,
        &vault,
        PrepareSpec {
            id: &id,
            id_raw,
            text: &text,
            provisional: &provisional,
            summary: format!("record {id}"),
            canonical_prefix: "record-edit/v1",
            allow_conflict: false,
        },
    )?;
    let rec = &prepared.rec;
    let rel = &prepared.rel;
    let id_str = rec.id.to_string();
    // The path was checked above, so a read error here is a real failure and
    // must not be swallowed by a fail-closed guard.
    let existing = std::fs::read(root.join(rel)).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            rel.display()
        )))
    })?;
    // Fail closed before writing anything, naming the real cause. Each rung
    // is a state the write layer would otherwise refuse later with a less
    // specific error, or that the decrypt below would misreport as a key
    // problem (#412).
    let mut rekeyed: Option<(String, String)> = None;
    if confidant_core::crypto_mode::is_envelope_bytes(&existing) {
        // (Conflict markers were already refused by `prepare_record_write`
        // above when `allow_conflict` is false.)
        let env = confidant_crypt::envelope::parse(&existing).map_err(|e| {
            anyhow::Error::new(
                DomainError::invalid(format!("{} is not a readable envelope: {e}", rel.display()))
                    .with_fix("Restore the file from git history, then re-run the edit"),
            )
        })?;
        if env.id != id_str || env.record_type != rec.kind.as_str() {
            return Err(anyhow::Error::new(
                DomainError::invalid(format!(
                    "{} holds {} (type {}), not {id_str} (type {})",
                    rel.display(),
                    env.id,
                    env.record_type,
                    rec.kind.as_str()
                ))
                .with_fix(
                    "The stored record and its path disagree; move the file back to the path for the record it holds (or restore this path from git history), then re-run the edit",
                ),
            ));
        }
        // Report a re-key rather than doing it silently: which client owns a
        // record is a consequential difference, and `deal` edits move it.
        // `envelope::parse` already validated the key id shape; failure here
        // is unreachable, but fail closed rather than reporting a wrong client.
        let from_client = confidant_crypt::envelope::key_id_client(&env.key_id).ok();
        if let (Some(from), Ok(to)) = (from_client, record_client_id(rec)) {
            if from != to {
                rekeyed = Some((from, to));
            }
        }
        // The only rung that needs the device key.
        if let Some(enc) = record_crypto::RecordEncryptor::for_vault(root, &vault)? {
            enc.decrypt_existing(rel, &existing).map_err(|_| {
                anyhow::Error::new(
                    DomainError::invalid(format!(
                        "cannot edit {}: this device cannot decrypt the record",
                        rel.display()
                    ))
                    .with_fix(
                        "Run `confidant recover` on this device, or ask an enrolled device to add it via `confidant keys device-add`",
                    ),
                )
            })?;
        }
    }
    let (outcome, _created) = apply_record_write_inner(
        root,
        &vault,
        prepared.pending,
        &write_options(cli),
        prepared.mode_overrides,
    )?;
    let mut extra = serde_json::json!({
        "id": id_str,
        "path": rel.display().to_string(),
    });
    if let Some((from, to)) = &rekeyed {
        extra["rekeyed"] = serde_json::json!({ "from": from, "to": to });
    }
    let applied = matches!(&outcome, WriteOutcome::Applied { .. });
    let result = finish_write(cli, root, "record-edit", outcome, extra);
    if let (true, false, Some((from, to))) = (applied, cli.json, &rekeyed) {
        println!("rekeyed {id_str}: {from} -> {to}");
    }
    result
}

/// #410: when a person's effective `no-ai` mode changes, plan the
/// re-stamp of that person's existing children in the same commit as the
/// person edit — the same shape as `keys shred`'s
/// `delete_edges_naming` / `strip_participant_from_interactions`,
/// including their fail-closed refusals.
///
/// Returns the encryptor mode overrides (this person's new mode) and one
/// `WriteFile` change per referencing child. The child changes carry each
/// child's *inner plaintext unchanged*; the write layer's encryptor
/// re-derives the outer header — from the override, so it sees the new
/// mode — and re-encrypts only where the header actually changed
/// (`stability_decision` keeps an unchanged child's ciphertext
/// byte-for-byte, so the commit diff names exactly the records that
/// moved).
///
/// Fail-closed discovery: finding a person's children in an encrypted
/// vault means decrypting records to read their references, through the
/// operator read path (#216) so `no-ai`-hidden children decrypt too. Any
/// record this device cannot decrypt — or refuses as tampered, or cannot
/// parse — refuses the whole edit, naming every unreadable file, and
/// nothing is committed; the operator fixes or shreds those records and
/// retries. A plaintext child in an encrypted vault has no outer header
/// to move (its visibility follows the person at read time) and `check`
/// reports the mixed mode, so it is left alone. On a plaintext vault
/// there are no headers at all and this returns empty.
fn plan_no_ai_restamp(
    root: &Path,
    vault: &confidant_core::vault::Vault,
    person_id: &str,
    new_mode: confidant_crypt::envelope::NoAi,
) -> anyhow::Result<(
    HashMap<String, confidant_crypt::envelope::NoAi>,
    Vec<FileChange>,
)> {
    let old_mode = record_crypto::person_no_ai_mode(root, person_id, None);
    if old_mode == new_mode {
        return Ok((HashMap::new(), Vec::new()));
    }
    // Plaintext vault: nothing carries an outer header, so nothing is
    // stale. The read path re-derives visibility live.
    let mode = confidant_core::crypto_mode::resolve_write_mode(root, &vault.config)
        .map_err(anyhow::Error::new)?;
    if !matches!(mode, confidant_core::crypto_mode::WriteMode::Encrypted) {
        return Ok((HashMap::new(), Vec::new()));
    }

    // DISCOVER: decrypt every record through the operator read path and
    // collect the ones this device cannot read. Any unreadable record
    // could reference this person, so an unreadable one refuses the whole
    // edit rather than leaving exactly those records with the stale
    // header this re-stamp exists to remove.
    let probe = load_vault(root)?;
    let decryptor = std::sync::Arc::new(record_decrypt::RecordDecryptor::for_edit(
        root,
        &probe.config.vault_id,
    ));
    let unreadable = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let inner = decryptor.hook();
    let hook: ContentHook = std::sync::Arc::new({
        let unreadable = std::sync::Arc::clone(&unreadable);
        move |path: &str, bytes: &[u8]| {
            let outcome = inner(path, bytes);
            // Operator mode never returns the keyless `no-ai` shell, so
            // anything that is not decrypted content is unreadable here:
            // skipped (this device cannot decrypt it) or refused (tampered
            // or corrupt).
            if !matches!(outcome, ContentOutcome::Content(_)) {
                unreadable.lock().unwrap().push(path.to_string());
            }
            outcome
        }
    });
    let scanned =
        confidant_core::load_vault_with_hook(root, Some(hook)).map_err(anyhow::Error::new)?;
    let mut unreadable = unreadable.lock().unwrap().clone();
    // A load finding on a record file means it could not be parsed — its
    // references are unknown, same as an undecryptable envelope. Findings
    // on other files (ledger, `confidant.toml`, stray top-level entries)
    // say nothing about who references this person, so they stay out of
    // the refusal list (#424): naming them under "record file(s)" would
    // be misleading, and the write path's own pre-check still fails
    // closed on any error-severity finding. `check` reports them all.
    for finding in &scanned.load_findings {
        if let Some(path) = &finding.file {
            if confidant_core::crypto_mode::is_record_path(std::path::Path::new(path)) {
                unreadable.push(path.clone());
            }
        }
    }
    if !unreadable.is_empty() {
        unreadable.sort();
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "cannot edit {person_id}: {} record file(s) could not be read to determine whether they reference this person: {}",
            unreadable.len(),
            unreadable.join(", ")
        ))
        .with_fix(
            "Re-stamping must reach every child or the stale header survives on the records it skipped. Resolve the unreadable files on a device that can decrypt them (check reports them), or shred them, then re-run the edit",
        )));
    }

    // PLAN: one change per referencing child, in the same reference set
    // the write-time stamp uses.
    let changes: Vec<FileChange> = scanned
        .records
        .values()
        .filter(|rec| rec.id.to_string() != person_id)
        .filter(|rec| references_person(&rec.fields, person_id))
        .filter(|rec| {
            // Only an envelope child has an outer header to re-stamp.
            std::fs::read(root.join(&rec.path))
                .map(|bytes| confidant_core::crypto_mode::is_envelope_bytes(&bytes))
                .unwrap_or(false)
        })
        .map(|rec| FileChange::WriteFile {
            path: std::path::PathBuf::from(&rec.path),
            contents: rec.source.clone(),
        })
        .collect();
    Ok((HashMap::from([(person_id.to_owned(), new_mode)]), changes))
}

/// #410: whether a record's front matter references `person`, using the
/// same field scan `record_crypto::inherited_no_ai_mode` applies at stamp
/// time — the `person:` field plus every other ID-valued or ID-list
/// field. If the two scans ever drift apart, a stale header comes back
/// through whichever side the scan no longer covers.
fn references_person(fields: &BTreeMap<String, String>, person: &str) -> bool {
    use confidant_core::record::{parse_ref_id, parse_with_list, FrontmatterRef};
    fields.iter().any(|(key, value)| {
        if key == "no-ai" {
            return false;
        }
        match parse_ref_id(value) {
            FrontmatterRef::Id(id) => id.to_string() == person,
            _ => parse_with_list(value)
                .is_some_and(|ids| ids.iter().any(|id| id.to_string() == person)),
        }
    })
}

/// The client whose data key encrypts `rec`: its own id for a person, the
/// `person` field otherwise. Mirrors the routing in
/// `record_crypto::encrypt_file`; used to report a re-key on edit.
pub(crate) fn record_client_id(rec: &Record) -> anyhow::Result<String> {
    let routing_person = match rec.kind {
        RecordKind::Person => Some(rec.id.to_string()),
        _ => rec.field("person").map(str::to_owned),
    };
    confidant_crypt::client_id_for_record(rec.kind.as_str(), routing_person.as_deref())
        .map_err(|e| anyhow::anyhow!("cannot route record to a client key: {e}"))
}

// ---------------------------------------------------------------------------
// context
// ---------------------------------------------------------------------------

fn cmd_context(
    cli: &Cli,
    root: &Path,
    person_raw: &str,
    include_private: bool,
    for_operator: bool,
) -> anyhow::Result<ExitCode> {
    // Operator mode (#572) loads through the operator decrypt path (the
    // same mechanism as `record show --for-edit`); the default stays the
    // agent read path.
    let vault = match load_vault_for_reads(root, cli.json, for_operator) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    // #537: a `p-<ULID>` keeps its exact previous behaviour (unsupported id
    // shapes still fall through to the ⚠2b / not-found branches below); a
    // non-id argument is an exact display name resolved against the cleared
    // set and canonicalized. Id args are not canonicalized here — `context`
    // already folds merge groups when it builds the bundle.
    let person = match RecordId::parse(person_raw) {
        Ok(id) => id,
        Err(_) => match confidant_core::resolve::resolve_person(&vault, person_raw) {
            Ok(m) => m.id,
            Err(err) => return Err(person_resolve_error(person_raw, err)),
        },
    };
    let (scope, _scope_names) = match resolve_cli_scope(&vault, cli.packs.as_deref()) {
        Ok(pair) => pair,
        Err(err) => {
            print_error(cli.json, Some(&vault.root.display().to_string()), &err)?;
            return Ok(ExitCode::from(err.exit_code() as u8));
        }
    };
    let bundle = match build_context(&vault, &person, include_private, &scope, for_operator) {
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
        if for_operator {
            println!("{OPERATOR_MODE_BANNER}");
        }
        let p = &bundle.person;
        // Operator mode carries the tri-state; the agent path still only
        // knows the boolean.
        let badge = match p.no_ai_mode {
            Some("notes") => " [no-ai: notes]",
            Some(_) => " [no-ai]",
            None if p.no_ai => " [no-ai]",
            None => "",
        };
        println!(
            "{} {}{badge}",
            p.id,
            p.name.as_deref().unwrap_or("(name withheld)"),
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

/// `confidant resolve <query>` (#537, phase 3a): resolve a `p-<ULID>` or an
/// exact display name to the canonical person. Read-only.
///
/// Uses the `for_reads` (`operator: false`) cleared set, so a `no-ai: notes`
/// person resolves by name and a `no-ai: true` person resolves by id only.
/// An ambiguous name fails closed with `E_AMBIGUOUS_PERSON` (candidate ids
/// are opaque, never names).
fn cmd_resolve(cli: &Cli, root: &Path, query: &str) -> anyhow::Result<ExitCode> {
    let vault = match load_vault_for_reads(root, cli.json, false) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let matched = match confidant_core::resolve::resolve_person(&vault, query) {
        Ok(m) => m,
        Err(err) => return Err(person_resolve_error(query, err)),
    };
    let id = matched.id.clone();
    let record = vault.records.get(&id);
    // Rule 3: an id-resolved `no-ai: true` person is outside the cleared set,
    // so withhold its name (a name-resolved person is cleared by
    // construction). The mode itself is not content and stays visible.
    let cleared = confidant_core::cleared_record_ids(&vault);
    let name = record
        .and_then(|r| r.name.clone())
        .filter(|_| cleared.contains(&id));
    let no_ai = record.map(Record::no_ai).unwrap_or(false);
    let matched_by = if matched.matched_by_name {
        "name"
    } else {
        "id"
    };
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "command": "resolve",
                "query": query,
                "matched_by": matched_by,
                "person": {
                    "id": id.to_string(),
                    "name": name,
                    "no_ai": no_ai,
                },
            }),
        ))?;
    } else if let Some(name) = &name {
        println!("{id} {name}");
    } else {
        println!("{id}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Read an alias value (email/phone/handle) from `--value-file` or stdin.
///
/// B7/#547: the raw value is PII and never arrives as an argument or leaves
/// this process in output, errors, or `Debug`. Wrapped in [`Zeroizing`] so
/// the plaintext copy is wiped on drop. An empty (or whitespace-only) value
/// is refused: it normalizes to the empty string, which would alias every
/// such value together.
fn read_alias_value(value_file: Option<&Path>) -> anyhow::Result<Zeroizing<String>> {
    let value = if let Some(path) = value_file {
        Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
            anyhow::Error::new(DomainError::usage(format!(
                "--value-file {} unreadable: {e}",
                path.display()
            )))
        })?)
    } else {
        let mut buf = String::new();
        use std::io::Read;
        io::stdin().read_to_string(&mut buf).map_err(|e| {
            anyhow::Error::new(DomainError::usage(format!(
                "cannot read alias value from stdin: {e}"
            )))
        })?;
        Zeroizing::new(buf)
    };
    if value.trim().is_empty() {
        return Err(anyhow::Error::new(DomainError::usage(
            "alias value is required via stdin or --value-file",
        )));
    }
    Ok(value)
}

/// Alias kinds are fixed by spec §6. A bad kind is a usage error (exit 2),
/// refused before any key is touched or anything is read from stdin.
fn validate_alias_kind(kind: &str) -> anyhow::Result<()> {
    if matches!(kind, "email" | "phone" | "handle") {
        Ok(())
    } else {
        Err(anyhow::Error::new(DomainError::usage(format!(
            "bad alias kind '{kind}'; use one of: email, phone, handle"
        ))))
    }
}

/// Read the vault lookup key through the verified `KeyStore::read_lookup_key`
/// path (#547): the `vault:lookup` manifest is verified against the anchor and
/// the key commitment checked before the key is returned. No new crypt API.
///
/// Needs an enrolled device key, a `keys/` tree, and the trust anchor; any of
/// those missing fails closed (no key is returned).
fn read_vault_lookup_key(
    root: &Path,
    vault_id: &str,
) -> anyhow::Result<confidant_crypt::keys::LookupKey> {
    use confidant_crypt::{anchor, lifecycle::KeyStore};
    let config_dir = confidant_config_dir().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    let (anchor, _warnings) = anchor::load(&config_dir, root).map_err(anyhow::Error::new)?;
    let identity = keys_device_identity()?;
    let keys_dir = root.join("keys");
    if !keys_dir.exists() {
        return Err(anyhow::Error::new(DomainError::invalid(
            "this vault has no keys/ tree, so alias HMACs cannot be computed; run `confidant init` first",
        )));
    }
    let mut store =
        KeyStore::with_config_dir(keys_dir, vault_id, &config_dir).map_err(anyhow::Error::new)?;
    let (key, _commitments, _seq) =
        store
            .read_lookup_key(identity.as_ref(), &anchor)
            .map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot read the vault lookup key: {e}"
                )))
            })?;
    Ok(key)
}

/// Map a failed alias resolution to the command-error layer. The not-found
/// fix is generic (no existence oracle): it must not confirm that a hidden
/// `no-ai: true` person exists, and it never carries the alias value.
fn alias_resolve_error(
    kind: &str,
    err: confidant_core::resolve::PersonResolveError,
) -> anyhow::Error {
    use confidant_core::resolve::PersonResolveError;
    match err {
        PersonResolveError::NotFound => anyhow::Error::new(
            DomainError::not_found("no person matches this alias").with_fix(
                "Check the alias kind and value; if this person is `no-ai: true`, pass their \
                 p-<ULID>",
            ),
        ),
        PersonResolveError::Ambiguous { candidates } => {
            let ids: Vec<String> = candidates.iter().map(RecordId::to_string).collect();
            anyhow::Error::new(DomainError::ambiguous_alias(kind, &ids))
        }
    }
}

/// `confidant alias add <person> <kind>` (#537 phase 3b): append
/// `DATE alias <p-ULID> KIND hmac:HEX` using the vault lookup key.
///
/// The value arrives via stdin or `--value-file` only. The line carries the
/// HMAC, never the value; the same is true of `--json` output, errors, and
/// `--dry-run` previews.
fn cmd_alias_add(
    cli: &Cli,
    root: &Path,
    person_raw: &str,
    kind: &str,
    value_file: Option<&Path>,
    date_raw: Option<String>,
) -> anyhow::Result<ExitCode> {
    validate_alias_kind(kind)?;
    let vault = vault_or!(root, cli.json);
    // Refinement B: a by-name person echoes the resolved p-<ULID> (and name).
    let person = resolve_person_arg(root, &vault, person_raw)?;
    announce_resolved_person(cli, &person);
    let date = parse_date_arg(&date_raw)?;

    let value = read_alias_value(value_file)?;
    let key = read_vault_lookup_key(root, &vault.config.vault_id)?;
    let hmac = confidant_crypt::alias::alias_hmac(&key, &value);

    let line = format!("{date} alias {} {kind} hmac:{hmac}", person.id);
    let canonical = format!(
        "alias-add/v1\nperson={}\ndate={date}\nkind={kind}\nhmac={hmac}\n",
        person.id
    );
    let summary = format!("alias {} {kind}", person.id);
    let changes = vec![FileChange::AppendLines {
        path: month_path(&date),
        lines: vec![line.clone()],
    }];
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
    let mut extra = serde_json::json!({
        "kind": kind,
        "hmac": format!("hmac:{hmac}"),
        "lines": [line],
    });
    if let Some(echo) = person.echo_json() {
        extra["person"] = echo;
    }
    finish_write(cli, root, "alias-add", outcome, extra)
}

/// `confidant alias resolve <kind>` (#537 phase 3b): resolve a `kind` + value
/// alias to the canonical person. Read-only.
///
/// Uses the `for_reads` cleared set, so an alias on a `no-ai: true` person is
/// not surfaced (the same generic not-found as an unmatched alias). Two
/// cleared people sharing an alias fail closed with `E_AMBIGUOUS_PERSON`.
fn cmd_alias_resolve(
    cli: &Cli,
    root: &Path,
    kind: &str,
    value_file: Option<&Path>,
) -> anyhow::Result<ExitCode> {
    validate_alias_kind(kind)?;
    let vault = match load_vault_for_reads(root, cli.json, false) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let value = read_alias_value(value_file)?;
    let key = read_vault_lookup_key(root, &vault.config.vault_id)?;
    let hmac = confidant_crypt::alias::alias_hmac(&key, &value);
    let id = match confidant_core::resolve::resolve_alias(&vault, kind, &hmac) {
        Ok(m) => m.id,
        Err(err) => return Err(alias_resolve_error(kind, err)),
    };
    // `resolve_alias` returns only cleared people, so the name is safe. The
    // mode is not content and stays visible (mirrors `cmd_resolve`).
    let record = vault.records.get(&id);
    let name = record.and_then(|r| r.name.clone());
    let no_ai = record.map(Record::no_ai).unwrap_or(false);
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "command": "alias-resolve",
                "kind": kind,
                "matched_by": "alias",
                "person": {
                    "id": id.to_string(),
                    "name": name,
                    "no_ai": no_ai,
                },
            }),
        ))?;
    } else if let Some(name) = &name {
        println!("{id} {name}");
    } else {
        println!("{id}");
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
    /// Actionable next step for a non-ok check, serialized as `fix` (the
    /// ADR-7 error-envelope field name). `None` when nothing needs doing.
    fix: Option<String>,
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
        fix: None,
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
            fix: None,
        },
        Some(v) => DoctorCheck {
            id: "git-version",
            status: if has_signers { "error" } else { "warning" },
            message: format!(
                "git {}.{}.{} is below the minimum {floor}; upgrade git to >= {floor} for SSH-signed inbox commits",
                v.0, v.1, v.2
            ),
            fix: None,
        },
        None => DoctorCheck {
            id: "git-version",
            status: "warning",
            message: format!(
                "could not determine git version; SSH-signed inbox commits need git >= {floor}"
            ),
            fix: None,
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
            fix: None,
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
            fix: None,
        }
    } else {
        DoctorCheck {
            id: "keys-staging",
            status: "error",
            message: format!(
                "keys/ is missing with leftover staging state ({detail}); re-run the interrupted keys command — it repairs staging leftovers before starting"
            ),
            fix: None,
        }
    }
}

/// #541: device key / keychain state for headless hosts and agents.
///
/// Probes the same resolution order a real load uses (env, then the OS
/// keychain) and reports the source plus the exact fix. Never returns or
/// logs key material. Warning-only for a missing key: an unenrolled device
/// is normal for a plaintext vault, and `doctor` must not fail on a host
/// that simply has no keychain yet — the hint is the point.
fn device_key_check() -> DoctorCheck {
    use confidant_crypt::keychain::{self, DeviceKeyState, DEVICE_KEY_ENV, INBOX_KEY_ENV};

    const ID: &str = "device-key";
    let headless_fix = format!(
        "On a host with no D-Bus Secret Service, set {DEVICE_KEY_ENV} to the device key \
         (AGE-SECRET-KEY-1…) and {OPERATOR_KEY_ENV} to a 64-character hex Ed25519 seed \
         before running `confidant init`, e.g. `export {OPERATOR_KEY_ENV}=<64 hex characters>`. \
         {INBOX_KEY_ENV} is only needed later, for inbox commands after the vault exists. \
         To put an existing vault on another device, clone it and run \
         `confidant keys device-add` (not `init`; `recover` only if every enrolled device \
         is lost). Keys never live in files."
    );
    let check = |status: &'static str, message: String, fix: Option<String>| DoctorCheck {
        id: ID,
        status,
        message,
        fix,
    };
    match keychain::device_key_state() {
        Ok(DeviceKeyState::Env) => check(
            "ok",
            format!("device key comes from {DEVICE_KEY_ENV} (headless/agent host)"),
            None,
        ),
        Ok(DeviceKeyState::Keychain) => check(
            "ok",
            "device key is in the OS keychain (keychain reachable)".to_owned(),
            None,
        ),
        Ok(DeviceKeyState::NotEnrolled) => check(
            "warning",
            "device key: not enrolled (the OS keychain holds no device key)".to_owned(),
            Some(headless_fix),
        ),
        Ok(DeviceKeyState::KeychainUnreachable(detail)) => check(
            "warning",
            format!(
                "device key: the OS keychain is unreachable ({detail}); this device cannot \
                 unwrap client keys"
            ),
            Some(headless_fix),
        ),
        Err(e) => check(
            "error",
            format!("device key: {e}"),
            Some(format!(
                "Fix the device key source (the OS keychain, or {DEVICE_KEY_ENV} on a headless host), \
                 then re-run `confidant doctor`"
            )),
        ),
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
                fix: None,
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
            fix: None,
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
            fix: None,
        }
    } else {
        let mut parts = Vec::new();
        for h in targeted {
            parts.push(format!(
                "{} {}/{} ({})",
                h.name,
                h.linked,
                h.total,
                h.dir.display()
            ));
        }
        DoctorCheck {
            id: "skills-links",
            status: "warning",
            message: format!(
                "skills missing (linked {total_linked}/{total_expected}: {}); run `confidant setup --agent auto`",
                parts.join(", ")
            ),
            fix: None,
        }
    }
}

/// #386: informational `qmd` search-availability check. qmd is optional,
/// so a missing qmd is `ok` — the same rule as the offline staleness check:
/// it just means search falls back to `confidant find` (see
/// `qmd-query.py`). A qmd that is installed but has no corpus is a
/// `warning` (#657): the fallback still works, but the operator asked for
/// semantic search and an initial `confidant reindex` is needed to enable
/// it, so an `ok` badge on that message is easy to miss.
///
/// Reports, in order: qmd on PATH? corpus built? embeddings present?
/// (BM25 keyword search is ready without embeddings; semantic/hybrid
/// ranking needs the skill wrapper's `--embed`, not a bare `qmd embed`,
/// because QMD's store is relocated under the vault. #666)
fn qmd_search_check(root: &Path) -> DoctorCheck {
    const ID: &str = "qmd-search";
    const INSTALL_HINT: &str = "npm install -g @tobilu/qmd";
    let ok = |message: String| DoctorCheck {
        id: ID,
        status: "ok",
        message,
        fix: None,
    };

    let Some(qmd) = find_on_path("qmd") else {
        return ok(format!(
            "qmd not found on PATH; search falls back to `confidant find` \
             (install with `{INSTALL_HINT}` to enable semantic search)"
        ));
    };
    if !root.join(QMD_CORPUS_REL).is_dir() {
        return DoctorCheck {
            id: ID,
            status: "warning",
            message: "qmd is on PATH but the search corpus is missing; \
                 run `confidant reindex` to rebuild it \
                 (search falls back to `confidant find`)"
                .to_owned(),
            fix: Some("Run `confidant reindex` to build the search corpus".to_owned()),
        };
    }
    match qmd_embedded_vectors(root, &qmd) {
        Some(n) if n > 0 => ok(format!(
            "hybrid/vector search available ({n} embedded vectors); \
             keyword (BM25) search is also ready"
        )),
        Some(_) => DoctorCheck {
            id: ID,
            status: "ok",
            message: "keyword (BM25) search ready; semantic/hybrid ranking is optional \
                      and not enabled (no embeddings)"
                .to_owned(),
            // #666: a bare `qmd embed` would target QMD's default store.
            // This project relocates QMD under the vault via
            // INDEX_PATH/QMD_CONFIG_DIR, so use the skill wrapper.
            fix: Some(format!(
                "Run \"$(confidant which --skills-dir)\"/qmd-search/bin/qmd-index.py \
                 --vault \"{}\" --embed to enable semantic/hybrid ranking \
                 (the first run downloads multi-GB GGUF models, needs network, \
                 and the disk must be encrypted)",
                root.display()
            )),
        },
        // The probe itself could not report (status failed or timed out):
        // do not point at `qmd embed`, which would not fix a broken status.
        None => ok(
            "qmd status did not report embedded vectors; run `qmd status` \
             with INDEX_PATH=<vault>/.confidant/qmd/index.sqlite to diagnose \
             (search falls back to `confidant find`)"
                .to_owned(),
        ),
    }
}

/// Probe the vault-local qmd store for embedded vectors, mirroring
/// `qmd-query.py`'s `vectors_available` (same env, same `status` parse).
/// Returns `None` when qmd cannot report (missing store, failing status,
/// timeout). Never creates the store: when `index.sqlite` is absent the
/// probe is skipped, because some `qmd` versions create an empty index
/// file as a side effect of `status`.
fn qmd_embedded_vectors(root: &Path, qmd: &Path) -> Option<u64> {
    let store = root.join(QMD_STORE_REL);
    if !store.join("index.sqlite").is_file() {
        return Some(0);
    }
    let mut child = std::process::Command::new(qmd)
        .arg("status")
        .env("INDEX_PATH", store.join("index.sqlite"))
        .env("QMD_CONFIG_DIR", store.join("config"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    // Drain stdout on a helper thread while we poll: if qmd ever prints
    // more than the pipe buffer, it would block on write and never exit,
    // and we would only ever see the timeout below. Cap what we keep —
    // we only need the `Vectors:` line. (#416 nit 1)
    const MAX_STDOUT: u64 = 1 << 20; // 1 MiB
    let stdout_thread = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = (&mut out).take(MAX_STDOUT).read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        })
    });
    // `qmd status` has no built-in timeout (unlike `qmd-query.py`, which
    // uses timeout=30); a hung qmd must not hang `doctor` or the TUI
    // Doctor tab. Poll with try_wait and kill after the grace period.
    const QMD_STATUS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait().ok()? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= QMD_STATUS_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    };
    // The pipe's write end is closed now (child exited or was killed), so
    // the drain thread always terminates.
    let stdout = stdout_thread
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();
    if !status.success() {
        return None;
    }
    parse_embedded_vectors(&stdout)
}

/// Parse `qmd status` output for a `Vectors: <n> embedded` line.
fn parse_embedded_vectors(output: &str) -> Option<u64> {
    for line in output.lines() {
        if let Some(rest) = line.trim().strip_prefix("Vectors:") {
            let digits: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(n) = digits.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

/// Parse the version out of `confidant-tui --version` output. Accepts
/// `confidant-tui 1.2.3`, `confidant-tui v1.2.3`, and a bare `1.2.3`;
/// scans tokens so a build suffix (`1.2.3 (abc)`) or a leading banner
/// line still resolves. Returns the normalized `major.minor.patch`, or
/// `None` when no version token is present.
fn parse_tui_version(output: &str) -> Option<String> {
    for token in output.split_whitespace() {
        let token = token.trim_start_matches('v');
        let mut parts = token.split('.');
        let major = parts.next()?;
        if major.is_empty() || !major.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(minor) = parts.next() else {
            continue;
        };
        if minor.is_empty() || !minor.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(patch) = parts.next() else {
            continue;
        };
        let patch: String = patch.chars().take_while(|c| c.is_ascii_digit()).collect();
        if patch.is_empty() {
            continue;
        }
        return Some(format!("{major}.{minor}.{patch}"));
    }
    None
}

/// Run `<bin> --version` and return its normalized version. `None` when
/// the probe fails, times out, or prints no recognizable version; the
/// caller treats that as "unknown", never as an error.
///
/// A broken TUI must not hang `doctor` or `confidant tui`, so this mirrors
/// the qmd probe: spawn, poll `try_wait`, and kill after the grace period
/// (a `--version` that takes two seconds is already pathological).
fn tui_binary_version(bin: &Path) -> Option<String> {
    use std::io::Read as _;
    const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
    const MAX_OUTPUT: u64 = 64 * 1024;

    let mut child = std::process::Command::new(bin)
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    // Drain both pipes on helper threads: a chatty binary that fills a
    // pipe would otherwise block on write and never exit, leaving only
    // the timeout to fire.
    let mut stdout_thread = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = (&mut out).take(MAX_OUTPUT).read_to_end(&mut buf);
            buf
        })
    });
    let mut stderr_thread = child.stderr.take().map(|mut err| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = (&mut err).take(MAX_OUTPUT).read_to_end(&mut buf);
            buf
        })
    });
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait().ok()? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= PROBE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    // Do not join the drain threads: a wrapper script can
                    // leave a grandchild (e.g. `sleep`) holding the pipes
                    // after the direct child is killed, and joining would
                    // wait for it. They end when the pipes close, and
                    // process exit detaches them either way. (#659)
                    let _ = stdout_thread.take();
                    let _ = stderr_thread.take();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    };
    // Both pipes are closed now, so the drain threads always terminate.
    let stdout = stdout_thread
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = stderr_thread
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    if !status.success() {
        return None;
    }
    parse_tui_version(&String::from_utf8_lossy(&stdout))
        .or_else(|| parse_tui_version(&String::from_utf8_lossy(&stderr)))
}

/// #659: `tui-version` doctor check. `confidant-tui` is optional and
/// installed separately, so a missing TUI is `ok`. An installed TUI whose
/// version differs from this CLI is a `warning`: the TUI speaks the same
/// ADR-7 contract, and a stale one can render unknown finding codes.
fn tui_version_check() -> DoctorCheck {
    const ID: &str = "tui-version";
    const INSTALL: &str = "cargo install confidant-tui";
    let cli_version = env!("CARGO_PKG_VERSION");
    let Some(bin) = find_on_path("confidant-tui") else {
        return DoctorCheck {
            id: ID,
            status: "ok",
            message: format!("optional TUI not installed; install it with `{INSTALL}`"),
            fix: None,
        };
    };
    let Some(tui_version) = tui_binary_version(&bin) else {
        // A broken or unusual `--version` must not make doctor noisy; the
        // TUI is optional and may still work.
        return DoctorCheck {
            id: ID,
            status: "ok",
            message: "confidant-tui is installed but did not report a version".to_owned(),
            fix: None,
        };
    };
    if tui_version == cli_version {
        DoctorCheck {
            id: ID,
            status: "ok",
            message: format!("confidant-tui {tui_version} matches confidant-cli {cli_version}"),
            fix: None,
        }
    } else {
        DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "confidant-tui {tui_version} does not match confidant-cli {cli_version}; \
                 the TUI may render stale or unknown state"
            ),
            fix: Some(format!("Run `{INSTALL}` to install the matching version")),
        }
    }
}

/// Parse `git remote -v` output into unique remote names, in first-seen
/// order. URLs are deliberately discarded: they may carry credentials.
fn parse_git_remotes(output: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in output.lines() {
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        if name.is_empty() || names.iter().any(|n| n == name) {
            continue;
        }
        names.push(name.to_owned());
    }
    names
}

/// #660: `git-remote` doctor check. Read-only and offline: it never
/// fetches, pushes, or contacts a remote. A remote is safe only because
/// the vault is encrypted, so a plaintext vault with a remote warns.
///
/// `root` is the resolved vault. When it is not a directory (doctor never
/// reaches this today), the check stays `ok`: a missing vault is not a
/// remote problem.
fn git_remote_check(root: &Path, no_input: bool) -> DoctorCheck {
    const ID: &str = "git-remote";
    if !root.is_dir() {
        return DoctorCheck {
            id: ID,
            status: "ok",
            message: "no vault to inspect for git remotes".to_owned(),
            fix: None,
        };
    }
    let output = match confidant_core::write::git(root, &["remote", "-v"], no_input) {
        Ok(out) => out,
        Err(e) => {
            // Never a panic or an error: `git-repo` already reports a
            // missing repository, and this check is advisory.
            return DoctorCheck {
                id: ID,
                status: "warning",
                message: format!("could not read git remotes: {e}"),
                fix: None,
            };
        }
    };
    let remotes = parse_git_remotes(&output);
    if remotes.is_empty() {
        return DoctorCheck {
            id: ID,
            status: "ok",
            message: "local-only; add a remote for backup and second-device enrollment".to_owned(),
            fix: Some(
                "Run `git remote add origin <url>` (or `confidant init --create --remote <url>` \
                 on a new vault). Clone on another device, then `confidant keys device-add`; \
                 `recover` only if every enrolled device is lost"
                    .to_owned(),
            ),
        };
    }
    let named = remotes.join(", ");
    if confidant_core::crypto_mode::is_structurally_encrypted(root) {
        DoctorCheck {
            id: ID,
            status: "ok",
            message: format!("git remote configured ({named}); vault is encrypted"),
            fix: None,
        }
    } else {
        DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "git remote configured ({named}) but this vault is plaintext; record bodies \
                 are readable by anyone with repo access"
            ),
            fix: Some(
                "Do not push plaintext vaults; encrypt the vault first or remove the remote"
                    .to_owned(),
            ),
        }
    }
}

/// Parse `findmnt -no SOURCE /` output into a device path. `findmnt` can
/// append a subvolume suffix (`/dev/sda2[/@root]`); strip it. Returns
/// `None` for a non-device source (overlay, tmpfs, `UUID=…`), where the
/// `lsblk` ancestry cannot be resolved.
#[cfg(target_os = "linux")]
fn parse_findmnt_source(output: &str) -> Option<String> {
    let line = output.lines().map(str::trim).find(|l| !l.is_empty())?;
    let source = line.split('[').next().unwrap_or(line).trim();
    if source.starts_with("/dev/") {
        Some(source.to_owned())
    } else {
        None
    }
}

/// True when `lsblk -s -no TYPE` output lists a `crypt` device in the
/// root device's ancestry (LUKS/dm-crypt).
#[cfg(target_os = "linux")]
fn lsblk_types_include_crypt(output: &str) -> bool {
    output
        .lines()
        .map(str::trim)
        .any(|line| line.eq_ignore_ascii_case("crypt"))
}

/// #653(d): best-effort `disk-encryption` check. Linux-only and purely
/// advisory: a missing tool, an unparseable source, or a non-block root
/// all report `ok` "could not determine", so this can never fail doctor.
/// It never prompts and never leaves the machine.
#[cfg(target_os = "linux")]
fn disk_encryption_check() -> DoctorCheck {
    const ID: &str = "disk-encryption";
    let unknown = |detail: &str| DoctorCheck {
        id: ID,
        status: "ok",
        message: format!("could not determine disk encryption ({detail})"),
        fix: None,
    };
    let findmnt = match std::process::Command::new("findmnt")
        .args(["-no", "SOURCE", "/"])
        .output()
    {
        Ok(out) if out.status.success() => out,
        Ok(_) => return unknown("findmnt could not resolve the root filesystem"),
        Err(_) => return unknown("findmnt is not available"),
    };
    let Some(source) = parse_findmnt_source(&String::from_utf8_lossy(&findmnt.stdout)) else {
        return unknown("root filesystem is not on a block device");
    };
    let lsblk = match std::process::Command::new("lsblk")
        .args(["-sno", "TYPE", &source])
        .output()
    {
        Ok(out) if out.status.success() => out,
        Ok(_) => return unknown("lsblk could not read the root device"),
        Err(_) => return unknown("lsblk is not available"),
    };
    let types = String::from_utf8_lossy(&lsblk.stdout);
    if lsblk_types_include_crypt(&types) {
        DoctorCheck {
            id: ID,
            status: "ok",
            message: "root filesystem is on an encrypted device".to_owned(),
            fix: None,
        }
    } else if types.lines().any(|l| !l.trim().is_empty()) {
        DoctorCheck {
            id: ID,
            status: "warning",
            message: "root filesystem is not on an encrypted disk; keep real client data on an \
                      encrypted disk"
                .to_owned(),
            fix: Some(
                "Move the vault to a full-disk-encrypted volume before storing real client data"
                    .to_owned(),
            ),
        }
    } else {
        unknown("lsblk returned no device types")
    }
}

/// Non-Linux platforms have no `findmnt`/`lsblk`; macOS FileVault is not
/// probed here. Report `ok` "could not determine" so doctor still passes.
#[cfg(not(target_os = "linux"))]
fn disk_encryption_check() -> DoctorCheck {
    DoctorCheck {
        id: "disk-encryption",
        status: "ok",
        message: "could not determine disk encryption (unsupported platform)".to_owned(),
        fix: None,
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
        fix: None,
    });

    match require_git_repo(root, cli.no_input) {
        Ok(()) => checks.push(DoctorCheck {
            id: "git-repo",
            status: "ok",
            message: "vault is a git repository".to_owned(),
            fix: None,
        }),
        Err(_) => checks.push(DoctorCheck {
            id: "git-repo",
            status: "error",
            message: "vault is not a git repository; writes need git".to_owned(),
            fix: None,
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
            fix: None,
        });
    } else {
        checks.push(DoctorCheck {
            id: "git-identity",
            status: "error",
            message: "git user.name / user.email are not configured; commits will fail".to_owned(),
            fix: None,
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

    // #660: remote visibility. Read-only and offline; warns when a
    // plaintext vault has a remote, because that leaks record bodies.
    checks.push(git_remote_check(root, cli.no_input));

    // #175: leftover keys/ staging state from an interrupted swap.
    checks.push(keys_staging_check(root));

    match load_vault(root) {
        Ok(vault) => {
            if vault.config.spec == confidant_core::SPEC_VERSION {
                checks.push(DoctorCheck {
                    id: "spec",
                    status: "ok",
                    message: "vault spec 0.1 supported".to_owned(),
                    fix: None,
                });
            } else {
                checks.push(DoctorCheck {
                    id: "spec",
                    status: "error",
                    message: format!("unsupported vault spec: {}", vault.config.spec),
                    fix: None,
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
                    fix: None,
                });
            } else if report.summary.warnings > 0 {
                checks.push(DoctorCheck {
                    id: "check",
                    status: "warning",
                    message: format!("check reports {} warning(s)", report.summary.warnings),
                    fix: None,
                });
            } else {
                checks.push(DoctorCheck {
                    id: "check",
                    status: "ok",
                    message: "check is clean".to_owned(),
                    fix: None,
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
                        fix: None,
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
                                fix: None,
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
                                        fix: None,
                                    });
                                } else {
                                    checks.push(DoctorCheck {
                                        id: "crypto-manifests",
                                        status: "error",
                                        message: format!(
                                            "corrupt key manifest(s); fix or re-init before crypto operations: {}",
                                            corrupt.join("; ")
                                        ),
                                        fix: None,
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
                                        fix: None,
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
            fix: None,
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
            fix: None,
        });
    } else if confidant_crypt::is_available() {
        checks.push(DoctorCheck {
            id: "crypto",
            status: "warning",
            message:
                "crypto library present, CLI not wired yet, vault content is stored as plaintext"
                    .to_owned(),
            fix: None,
        });
    } else {
        checks.push(DoctorCheck {
            id: "crypto",
            status: "warning",
            message: "encryption not available in this build; vault content is stored as plaintext"
                .to_owned(),
            fix: None,
        });
    }

    // #653(d): best-effort encrypted-disk check. Advisory only: a missing
    // tool or an unknown platform is `ok`, so doctor never fails on it.
    checks.push(disk_encryption_check());

    // #541: keychain reachability and device enrollment. Headless hosts
    // have no Secret Service, so the failure an agent hits is otherwise an
    // opaque NoKey; this names the source and the env-var fix.
    checks.push(device_key_check());

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
                    fix: None,
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
            fix: None,
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
        // #659: the optional TUI must match the CLI's agent contract.
        checks.push(tui_version_check());
        // #386/#657: qmd search availability. Missing qmd is `ok`; an
        // installed qmd without a corpus warns and points at `reindex`.
        checks.push(qmd_search_check(root));
    }

    let ok = !checks.iter().any(|c| c.status == "error");
    if cli.json {
        let items: Vec<serde_json::Value> = checks
            .iter()
            .map(|c| {
                let mut item = serde_json::json!({
                    "id": c.id,
                    "status": c.status,
                    "message": c.message,
                });
                // `fix` only when there is one: the field stays absent on
                // healthy checks, matching the ADR-7 error envelope.
                if let Some(fix) = &c.fix {
                    item["fix"] = serde_json::Value::String(fix.clone());
                }
                item
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
            if let Some(fix) = &c.fix {
                println!("        fix: {fix}");
            }
        }
    }
    if ok {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

// ---------------------------------------------------------------------------
// reset --machine-state (#638)
// ---------------------------------------------------------------------------

/// One keychain slot `reset --machine-state` clears. The service/account
/// pairs come from the public `confidant-crypt` constants; this command
/// only orchestrates, it does not introduce a new key path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MachineKeySlot {
    Device,
    Operator,
    Inbox,
    InboxPrevious,
}

impl MachineKeySlot {
    const ALL: [Self; 4] = [
        Self::Device,
        Self::Operator,
        Self::Inbox,
        Self::InboxPrevious,
    ];

    fn service(self) -> &'static str {
        match self {
            Self::Device | Self::Operator => confidant_crypt::keychain::DEVICE_SERVICE,
            Self::Inbox | Self::InboxPrevious => confidant_crypt::keychain::INBOX_SERVICE,
        }
    }

    fn account(self) -> &'static str {
        match self {
            Self::Device => confidant_crypt::keychain::DEVICE_ACCOUNT,
            Self::Operator => confidant_crypt::keychain::OPERATOR_ACCOUNT,
            Self::Inbox => confidant_crypt::keychain::INBOX_ACCOUNT,
            Self::InboxPrevious => confidant_crypt::keychain::INBOX_PREVIOUS_ACCOUNT,
        }
    }
}

/// One thing `reset --machine-state` can remove. `present` is `None` when
/// the keychain could not be checked (for example on a headless host with
/// no Secret Service); JSON reports `null` rather than guessing.
struct ResetItem {
    kind: &'static str,
    /// File path, or `service/account` for a keychain item.
    location: String,
    key: Option<&'static str>,
    slot: Option<MachineKeySlot>,
    present: Option<bool>,
}

impl ResetItem {
    fn file(path: PathBuf, present: bool) -> Self {
        Self {
            kind: "file",
            location: path.display().to_string(),
            key: None,
            slot: None,
            present: Some(present),
        }
    }

    fn config_key(path: &Path, key: &'static str, present: bool) -> Self {
        Self {
            kind: "config-key",
            location: path.display().to_string(),
            key: Some(key),
            slot: None,
            present: Some(present),
        }
    }

    fn keychain(slot: MachineKeySlot, present: Option<bool>) -> Self {
        Self {
            kind: "keychain",
            location: format!("{}/{}", slot.service(), slot.account()),
            key: None,
            slot: Some(slot),
            present,
        }
    }

    fn to_json(&self) -> Value {
        let mut item = serde_json::json!({
            "kind": self.kind,
            "present": self.present,
        });
        match self.kind {
            "config-key" => {
                item["path"] = Value::String(self.location.clone());
                item["key"] = Value::String(self.key.unwrap_or_default().to_owned());
            }
            "keychain" => {
                let slot = self.slot.expect("keychain item has a slot");
                item["service"] = Value::String(slot.service().to_owned());
                item["account"] = Value::String(slot.account().to_owned());
            }
            _ => item["path"] = Value::String(self.location.clone()),
        }
        item
    }

    fn label(&self) -> String {
        match self.kind {
            "config-key" => format!("{}: {}", self.location, self.key.unwrap_or_default()),
            _ => self.location.clone(),
        }
    }
}

/// Read `config.toml` for a rewrite. A missing file is an empty document;
/// any other read error fails instead of replacing a file we could not
/// read (matching `inbox rotate`'s pin rewrite).
fn read_user_config_document(path: &Path) -> anyhow::Result<toml_edit::DocumentMut> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "could not read {}: {e} — refusing to rewrite it",
                path.display()
            ))))
        }
    };
    text.parse().map_err(|e| {
        anyhow::Error::new(DomainError::config(format!(
            "{} is not valid TOML: {e}",
            path.display()
        )))
    })
}

/// Whether one of the four machine-state config entries is present. A
/// `[vaults]`/`[trust]`/`[inbox]` value of the wrong shape fails closed:
/// rewriting a file whose structure we do not understand could drop keys.
fn config_key_present(
    doc: &toml_edit::DocumentMut,
    path: &Path,
    key: &str,
) -> anyhow::Result<bool> {
    match key {
        "default_vault" => Ok(doc.get("default_vault").is_some()),
        "vaults" => Ok(match doc.get("vaults") {
            None => false,
            // `as_table_like` covers both `[vaults]` and the inline
            // `vaults = { … }` form.
            Some(item) if item.as_table_like().is_some() => true,
            Some(_) => return Err(not_a_table(path, "vaults")),
        }),
        "trust.signers" => nested_config_key_present(doc, path, "trust", "signers"),
        "inbox.pubkey" => nested_config_key_present(doc, path, "inbox", "pubkey"),
        other => Err(anyhow::anyhow!("unknown machine-state config key {other}")),
    }
}

fn nested_config_key_present(
    doc: &toml_edit::DocumentMut,
    path: &Path,
    table: &str,
    key: &str,
) -> anyhow::Result<bool> {
    match doc.get(table) {
        None => Ok(false),
        Some(item) if item.as_table_like().is_some() => {
            Ok(item.as_table_like().and_then(|t| t.get(key)).is_some())
        }
        Some(_) => Err(not_a_table(path, table)),
    }
}

fn not_a_table(path: &Path, table: &str) -> anyhow::Error {
    anyhow::Error::new(DomainError::config(format!(
        "{}: [{table}] is not a table — refusing to rewrite it",
        path.display()
    )))
}

/// Remove the four machine-state entries, preserving every unrelated key,
/// comment and table. Returns whether the document changed. Empty
/// `[trust]`/`[inbox]` tables left by the removal are dropped too.
fn remove_config_entries(doc: &mut toml_edit::DocumentMut) -> bool {
    let mut changed = false;
    for key in ["default_vault", "vaults"] {
        if doc.remove(key).is_some() {
            changed = true;
        }
    }
    for (table, key) in [("trust", "signers"), ("inbox", "pubkey")] {
        let emptied = match doc.get_mut(table) {
            Some(item) => match item.as_table_like_mut() {
                Some(table_item) => {
                    let removed = table_item.remove(key).is_some();
                    changed |= removed;
                    removed && table_item.is_empty()
                }
                None => false,
            },
            None => false,
        };
        if emptied {
            doc.remove(table);
        }
    }
    changed
}

/// Replace the config atomically, keeping the original permissions. A
/// crash mid-write can never leave a truncated config.
fn write_user_config_atomically(
    path: &Path,
    doc: &toml_edit::DocumentMut,
    mode: Option<std::fs::Permissions>,
) -> anyhow::Result<()> {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{file_name}.reset-{}", std::process::id()));
    std::fs::write(&tmp, doc.to_string()).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "could not write {}: {e}",
            tmp.display()
        )))
    })?;
    if let Some(mode) = mode {
        let _ = std::fs::set_permissions(&tmp, mode);
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::Error::new(DomainError::invalid(format!(
            "could not replace {}: {e}",
            path.display()
        )))
    })
}

/// Whether a keychain slot holds a key. `None` means "could not tell"
/// (headless host, or the test-only `CONFIDANT_KEYCHAIN=off` switch):
/// never reported as absent. Deletion still refuses under the kill switch.
fn machine_key_present(slot: MachineKeySlot) -> anyhow::Result<Option<bool>> {
    #[cfg(feature = "test-overrides")]
    if let Some(dir) = test_keychain_dir() {
        use confidant_crypt::keychain::KeychainBackend as _;
        let present = if slot == MachineKeySlot::Device {
            dir.join("device.key").is_file()
        } else {
            FileKeychain::new(dir)
                .get_password(slot.service(), slot.account())
                .ok()
                .flatten()
                .is_some()
        };
        return Ok(Some(present));
    }
    if confidant_crypt::keychain::keychain_switch().map_err(anyhow::Error::new)?
        == confidant_crypt::keychain::KeychainSwitch::Off
    {
        return Ok(None);
    }
    use confidant_crypt::keychain::KeychainBackend as _;
    Ok(confidant_crypt::keychain::OsKeychain
        .get_password(slot.service(), slot.account())
        .ok()
        .map(|value| value.is_some()))
}

/// Delete one slot through the existing `confidant-crypt` entry points.
/// Test builds with `CONFIDANT_TEST_KEYCHAIN_DIR` use the same file-backed
/// backend the inbox-rotation tests use, so CI never touches a real
/// keychain (and the device key keeps its `device.key` test path).
fn delete_machine_key(slot: MachineKeySlot) -> anyhow::Result<()> {
    #[cfg(feature = "test-overrides")]
    if let Some(dir) = test_keychain_dir() {
        use confidant_crypt::keychain::KeychainBackend as _;
        if slot == MachineKeySlot::Device {
            let path = dir.join("device.key");
            return match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(anyhow::Error::new(DomainError::invalid(format!(
                    "cannot delete test keychain entry {}: {e}",
                    path.display()
                )))),
            };
        }
        return FileKeychain::new(dir)
            .delete_credential(slot.service(), slot.account())
            .map_err(|e| anyhow::anyhow!("{e}"));
    }
    let result = match slot {
        MachineKeySlot::Device => confidant_crypt::keychain::delete_device_key(),
        MachineKeySlot::Operator => confidant_crypt::keychain::delete_operator_key(),
        MachineKeySlot::Inbox => confidant_crypt::keychain::delete_inbox_key(),
        MachineKeySlot::InboxPrevious => confidant_crypt::keychain::delete_inbox_key_previous(),
    };
    result.map_err(anyhow::Error::new)
}

/// A keychain failure is a dead end without a pointer to the manual path;
/// the docs page keeps the platform commands as the fallback.
fn keychain_delete_error(slot: MachineKeySlot, err: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(
        DomainError::invalid(format!(
            "could not remove keychain entry {}/{}: {err:#}",
            slot.service(),
            slot.account()
        ))
        .with_fix(
            "If this host has no reachable keychain, remove the entry with `secret-tool` (Linux) or `security` (macOS); see docs/starting-fresh.md, \"Clearing keychain entries\", then re-run",
        ),
    )
}

/// One vault path the reset guard checked. `sources` records every input
/// that named it (`--vault`, `CONFIDANT_VAULT`, a walk-up, `default_vault`,
/// or a `[vaults]` entry); `initialized` means the directory exists and has
/// a `keys/` tree.
struct VaultCandidate {
    path: PathBuf,
    sources: Vec<String>,
    initialized: bool,
}

/// Expand the `~/` form used by `config.toml` values, matching
/// `confidant_core::discover`'s `default_vault`/`[vaults]` handling.
fn expand_config_path(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let mut path = PathBuf::from(home);
            path.push(rest);
            return path;
        }
    }
    PathBuf::from(raw)
}

/// A display/dedupe path for a candidate: a `confidant.toml` argument
/// becomes its parent (as discovery does), and an existing path is
/// canonicalized (macOS `/var` → `/private/var`).
fn normalize_vault_candidate(path: &Path) -> PathBuf {
    let path = if path.is_file()
        && path
            .file_name()
            .is_some_and(|name| name == "confidant.toml")
    {
        path.parent().unwrap_or(path)
    } else {
        path
    };
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn push_vault_candidate(
    candidates: &mut Vec<VaultCandidate>,
    source: impl Into<String>,
    path: PathBuf,
) {
    let path = normalize_vault_candidate(&path);
    let source = source.into();
    if let Some(existing) = candidates.iter_mut().find(|c| c.path == path) {
        if !existing.sources.contains(&source) {
            existing.sources.push(source);
        }
        return;
    }
    let initialized = path.join("keys").is_dir();
    candidates.push(VaultCandidate {
        path,
        sources: vec![source],
        initialized,
    });
}

/// The nearest ancestor of `start` holding `confidant.toml`, matching
/// discovery's walk-up. Never fails the guard when the directory cannot be
/// canonicalized.
fn walk_up_vault(start: &Path) -> Option<PathBuf> {
    let mut dir = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
    loop {
        if dir.join("confidant.toml").is_file() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn config_string_value(
    doc: &toml_edit::DocumentMut,
    path: &Path,
    key: &str,
) -> anyhow::Result<Option<String>> {
    match doc.get(key) {
        None => Ok(None),
        Some(item) => match item.as_str() {
            Some(value) => Ok(Some(value.to_owned())),
            None => Err(anyhow::Error::new(DomainError::config(format!(
                "{}: {key} is not a string — refusing to rewrite it",
                path.display()
            )))),
        },
    }
}

fn config_vault_entries(
    doc: &toml_edit::DocumentMut,
    path: &Path,
) -> anyhow::Result<Vec<(String, String)>> {
    let Some(item) = doc.get("vaults") else {
        return Ok(Vec::new());
    };
    let Some(table) = item.as_table_like() else {
        return Err(not_a_table(path, "vaults"));
    };
    let mut entries = Vec::new();
    for (name, item) in table.iter() {
        let Some(value) = item.as_str() else {
            return Err(anyhow::Error::new(DomainError::config(format!(
                "{}: [vaults].{name} is not a string — refusing to rewrite it",
                path.display()
            ))));
        };
        entries.push((name.to_owned(), value.to_owned()));
    }
    Ok(entries)
}

/// Build the guard's candidate set from every way a vault can resolve. It
/// deliberately does not use `discover()`: discovery stops at the first
/// answer, and a bad `--vault` makes it fail, which would leave a live
/// `default_vault` or `[vaults]` entry unchecked. Read-only.
fn vault_guard_candidates(
    cli: &Cli,
    doc: &toml_edit::DocumentMut,
    config_path: &Path,
) -> anyhow::Result<Vec<VaultCandidate>> {
    let mut candidates = Vec::new();

    if let Some(flag) = &cli.vault {
        push_vault_candidate(&mut candidates, "--vault", flag.clone());
    }

    let vault_entries = config_vault_entries(doc, config_path)?;
    if let Some(env) = std::env::var("CONFIDANT_VAULT")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    {
        // `CONFIDANT_VAULT` is a path unless it names a `[vaults]` entry,
        // exactly as discovery treats it.
        let path = vault_entries
            .iter()
            .find(|(name, _)| name == &env)
            .map(|(_, raw)| expand_config_path(raw))
            .unwrap_or_else(|| expand_config_path(&env));
        push_vault_candidate(&mut candidates, "CONFIDANT_VAULT", path);
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if let Some(found) = walk_up_vault(&cwd) {
        push_vault_candidate(&mut candidates, "walk-up", found);
    }

    if let Some(default) = config_string_value(doc, config_path, "default_vault")? {
        push_vault_candidate(
            &mut candidates,
            "default_vault",
            expand_config_path(&default),
        );
    }

    for (name, raw) in vault_entries {
        push_vault_candidate(
            &mut candidates,
            format!("[vaults] {name}"),
            expand_config_path(&raw),
        );
    }

    Ok(candidates)
}

fn vault_candidates_json(candidates: &[VaultCandidate], force: bool) -> Value {
    let items: Vec<Value> = candidates
        .iter()
        .map(|candidate| {
            serde_json::json!({
                "path": candidate.path.display().to_string(),
                "sources": candidate.sources,
                "initialized": candidate.initialized,
            })
        })
        .collect();
    let initialized: Vec<Value> = candidates
        .iter()
        .filter(|candidate| candidate.initialized)
        .map(|candidate| Value::String(candidate.path.display().to_string()))
        .collect();
    serde_json::json!({
        "candidates": items,
        "initialized": initialized,
        "forced": force,
    })
}

/// `confidant reset --machine-state` (#638): clear the state the machine
/// keeps *outside* the vault so `init --create` starts clean. The vault is
/// never opened for writing; a resolvable initialized vault only triggers
/// the guard.
fn cmd_reset_machine_state(cli: &Cli, yes: bool, force: bool) -> anyhow::Result<ExitCode> {
    let dry_run = cli.dry_run;

    if dry_run && yes {
        return Err(anyhow::Error::new(DomainError::usage(
            "--dry-run changes nothing; drop --yes to preview, or drop --dry-run to remove",
        )));
    }
    if !dry_run && !yes && (cli.no_input || cli.json) {
        return Err(anyhow::Error::new(DomainError::usage(
            "`reset --machine-state` needs --yes with --no-input or --json (or --dry-run to preview)",
        )));
    }

    let config_dir = confidant_config_dir().ok_or_else(|| {
        anyhow::Error::new(DomainError::usage(
            "`reset --machine-state` needs $HOME to locate ~/.config/confidant",
        ))
    })?;
    let config_path = config_dir.join("config.toml");

    // Read the config once so presence, guard, and removal agree on one
    // document.
    let mut doc = read_user_config_document(&config_path)?;

    // Guard: only an initialized vault (keys/ exists) can be broken by
    // removing the anchor and keys. Check every way a vault can resolve,
    // not just the one discovery would pick. Read-only.
    let candidates = vault_guard_candidates(cli, &doc, &config_path)?;
    let initialized: Vec<&VaultCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.initialized)
        .collect();
    if !initialized.is_empty() {
        let listed = initialized
            .iter()
            .map(|candidate| candidate.path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let (subject, verb, object, possessive) = if initialized.len() == 1 {
            ("vault", "looks", "it", "its")
        } else {
            ("vaults", "look", "them", "their")
        };
        if !force {
            return Err(anyhow::Error::new(
                DomainError::invalid(format!(
                    "refusing to clear machine state: {subject} {listed} {verb} initialized (keys/ exists), and removing the trust anchor and keys would break {object}"
                ))
                .with_fix(
                    "Pass --force only after retiring every listed vault; otherwise run from outside them or unset CONFIDANT_VAULT",
                ),
            ));
        }
        if !cli.json {
            eprintln!(
                "warning: --force set; initialized {subject} {listed} will be left without {possessive} anchor or keys"
            );
        }
    }

    let mut items: Vec<ResetItem> = Vec::new();
    for name in [
        "trust.toml",
        "manifest-seq.toml",
        "inbox-rotation-pending.toml",
    ] {
        let path = config_dir.join(name);
        let present = path.exists();
        items.push(ResetItem::file(path, present));
    }
    for key in ["default_vault", "vaults", "trust.signers", "inbox.pubkey"] {
        let present = config_key_present(&doc, &config_path, key)?;
        items.push(ResetItem::config_key(&config_path, key, present));
    }
    for slot in MachineKeySlot::ALL {
        items.push(ResetItem::keychain(slot, machine_key_present(slot)?));
    }

    let changed = items.iter().any(|item| item.present != Some(false));

    // Nothing present: report the no-op without asking (there is nothing
    // to confirm).
    if !dry_run
        && changed
        && !yes
        && !confirm_yn(
            "Remove this machine's Confidant state? This never touches a vault.",
            cli.no_input,
            cli.json,
        )?
    {
        println!("nothing removed");
        return Ok(ExitCode::SUCCESS);
    }

    if !dry_run {
        // Keychain first: a keychain failure (unreachable, or the
        // CONFIDANT_KEYCHAIN=off test switch) must leave the files in
        // place so a retry can finish the job.
        for slot in MachineKeySlot::ALL {
            let present = items
                .iter()
                .find(|item| item.slot == Some(slot))
                .and_then(|item| item.present);
            if present != Some(false) {
                delete_machine_key(slot).map_err(|err| keychain_delete_error(slot, err))?;
            }
        }
        if remove_config_entries(&mut doc) {
            let mode = std::fs::metadata(&config_path)
                .ok()
                .map(|meta| meta.permissions());
            write_user_config_atomically(&config_path, &doc, mode)?;
        }
        for name in [
            "trust.toml",
            "manifest-seq.toml",
            "inbox-rotation-pending.toml",
        ] {
            let path = config_dir.join(name);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(anyhow::Error::new(DomainError::invalid(format!(
                        "could not remove {}: {e}",
                        path.display()
                    ))))
                }
            }
        }
    }

    if cli.json {
        let mut extra = serde_json::Map::new();
        extra.insert("command".to_owned(), Value::String("reset".to_owned()));
        extra.insert(
            "scope".to_owned(),
            Value::String("machine-state".to_owned()),
        );
        extra.insert("dry_run".to_owned(), Value::Bool(dry_run));
        extra.insert("changed".to_owned(), Value::Bool(changed));
        extra.insert(
            "items".to_owned(),
            Value::Array(items.iter().map(ResetItem::to_json).collect()),
        );
        extra.insert(
            "vault_guard".to_owned(),
            vault_candidates_json(&candidates, force),
        );
        print_json(&ok_envelope(None, Value::Object(extra)))?;
    } else if !changed {
        println!("nothing to remove: machine state is already clear");
    } else {
        println!("{}:", if dry_run { "would remove" } else { "removed" });
        for item in items.iter().filter(|item| item.present != Some(false)) {
            println!("  {:<10} {}", item.kind, item.label());
        }
        if dry_run {
            println!("dry run: nothing was changed");
        } else {
            println!(
                "machine state cleared; `confidant init --create` in a new directory starts with no inherited anchor, config entries, or keys"
            );
        }
    }
    Ok(ExitCode::SUCCESS)
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

/// #662: create the recovery phrase file, mode 0600, refusing to overwrite
/// and never following a symlink (`create_new` uses `O_EXCL`). Split from
/// the write so a refusal leaves any existing file untouched and the caller
/// marks the file as its own only after creation succeeds.
fn create_phrase_file(path: &Path) -> anyhow::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(path).map_err(|e| {
        let fix = if e.kind() == io::ErrorKind::AlreadyExists {
            "Choose a new path, or remove the existing file first"
        } else {
            "Choose a writable path in an existing directory"
        };
        anyhow::Error::new(DomainError::usage(format!(
            "cannot create --phrase-out {}: {e}",
            path.display()
        )))
        .with_fix(fix)
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot set mode 0600 on --phrase-out {}: {e}",
                    path.display()
                )))
            })?;
    }
    Ok(file)
}

fn write_phrase_file(file: &mut std::fs::File, path: &Path, phrase: &str) -> anyhow::Result<()> {
    file.write_all(phrase.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot write --phrase-out {}: {e}",
                path.display()
            )))
        })?;
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

/// The B1 trust-anchor refusal, shared by the `--create` bootstrap preflight
/// and [`cmd_init`] so the two paths can never drift. `init` never silently
/// replaces an existing anchor: a re-initialization needs `--force`.
fn refuse_existing_anchor(trust_path: &Path, force: bool) -> anyhow::Result<()> {
    if trust_path.exists() && !force {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "trust anchor already exists at {}; refusing to overwrite (clone an existing \
                 vault and run `confidant keys device-add`, or `confidant recover` only if \
                 every enrolled device is lost, or pass --force)",
                trust_path.display()
            ))
            .with_fix(
                "To enroll this device on an existing vault, clone it and run `confidant keys \
                 device-add`. `confidant recover` is only for when every enrolled device is \
                 lost. Pass --force to replace this machine's trust anchor for a new vault",
            ),
        ));
    }
    Ok(())
}

/// The directory `init --create` should scaffold: resolved like discovery
/// (`--vault`, then `CONFIDANT_VAULT`, then cwd), except that the path need
/// not exist yet and a `confidant.toml` argument is reduced to its parent.
fn bootstrap_target(cli: &Cli) -> PathBuf {
    fn lenient(p: &Path) -> PathBuf {
        if !p.is_dir() && p.file_name().is_some_and(|n| n == "confidant.toml") {
            p.parent().unwrap_or(p).to_path_buf()
        } else {
            p.to_path_buf()
        }
    }
    if let Some(flag) = &cli.vault {
        return lenient(flag);
    }
    if let Ok(env) = std::env::var("CONFIDANT_VAULT") {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if let Some(cfg) = load_user_config(home.as_deref()) {
            if let Some(named) = cfg.named(&env) {
                return lenient(&named);
            }
        }
        return lenient(Path::new(&env));
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// True when `root` is the top level of its own git repository. A
/// subdirectory of someone else's repo is not the vault's repo root, so
/// `--create` must not commit the skeleton into the parent.
fn is_git_repo_root(root: &Path, no_input: bool) -> bool {
    let Ok(top) = confidant_core::write::git(root, &["rev-parse", "--show-toplevel"], no_input)
    else {
        return false;
    };
    let top = Path::new(top.trim());
    let top = top.canonicalize().unwrap_or_else(|_| top.to_path_buf());
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    top == root
}

fn dir_entry_names(root: &Path) -> anyhow::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(root)? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    Ok(names)
}

/// Validate `init --create --packs` before the skeleton is written (#639).
///
/// `init` can only seed packs the binary already implements: compiled packs
/// or the implicit built-ins (today `personal@0.2`). An external pack is
/// vendored into an existing vault by `confidant pack add`, so naming one
/// here is a usage error with the install-after-init fix, not the opaque
/// "unknown pack" it used to be.
fn validate_init_packs(packs: &[String]) -> anyhow::Result<()> {
    for name in packs {
        if confidant_core::packs::is_known_pack_id(name) {
            continue;
        }
        let fix = "Run `confidant init --create` without `--packs`, then \
                   install the pack with `confidant pack add <source> --yes`";
        let (message, fix) = match name.split_once('@') {
            Some((pack, version)) if !pack.is_empty() && !version.is_empty() => (
                format!(
                    "`--packs {name}` names an external pack, which init cannot vendor; \
                     init only seeds packs built into this binary (today the implicit \
                     personal@0.2)"
                ),
                fix,
            ),
            _ => (
                format!(
                    "`--packs {name}` is not a pack this binary implements; init only \
                     seeds built-in packs written as name@version (today personal@0.2)"
                ),
                fix,
            ),
        };
        return Err(anyhow::Error::new(DomainError::usage(message)).with_fix(fix));
    }
    Ok(())
}

/// What `init --create` scaffolded for real, kept until the key steps and
/// the anchor save succeed so a failure can remove only what this command
/// created (#651). Every field records a path this run wrote; rollback never
/// touches a pre-existing user file.
struct Scaffold {
    root: PathBuf,
    created_root: bool,
    git_initialized: bool,
    gitignore_original: Option<Vec<u8>>,
    wrote_gitignore: bool,
    wrote_config: bool,
    commit_created: bool,
    previous_head: Option<String>,
    /// True when this run added `origin` via `--remote` on a pre-existing
    /// repo (a repo this run created is removed entirely on rollback).
    added_remote: bool,
    armed: bool,
}

impl Scaffold {
    /// Best-effort rollback. A repo this run created is removed entirely; a
    /// pre-existing repo is rewound to its previous HEAD (or its unborn
    /// state) and only this run's files are removed.
    fn rollback(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        if self.git_initialized {
            let _ = std::fs::remove_dir_all(self.root.join(".git"));
        } else if self.added_remote {
            let _ = confidant_core::write::git(&self.root, &["remote", "remove", "origin"], true);
        }
        if self.commit_created && !self.git_initialized {
            match &self.previous_head {
                Some(prev) => {
                    let _ =
                        confidant_core::write::git(&self.root, &["reset", "--mixed", prev], true);
                }
                None => {
                    let _ =
                        confidant_core::write::git(&self.root, &["update-ref", "-d", "HEAD"], true);
                }
            }
        }
        if self.wrote_gitignore {
            let path = self.root.join(".gitignore");
            match &self.gitignore_original {
                Some(bytes) => {
                    let _ = std::fs::write(path, bytes);
                }
                None => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        if self.wrote_config {
            let _ = std::fs::remove_file(self.root.join("confidant.toml"));
        }
        if self.created_root {
            // Only removes an empty directory: any user file leaves it alone.
            let _ = std::fs::remove_dir(&self.root);
        }
    }
}

impl Drop for Scaffold {
    fn drop(&mut self) {
        self.rollback();
    }
}

/// Result of the `init --create` bootstrap step.
enum BootstrapPlan {
    /// Continue to discovery and `cmd_init`; `Some` when a skeleton was
    /// written for real and must be rolled back if `cmd_init` fails.
    Continue(Option<Scaffold>),
    /// #649: `--dry-run` printed the plan and wrote nothing; stop here.
    DryRun,
}

/// Rollback for the key steps of `init` (#651): removes a `keys/` tree this
/// run created (never a pre-existing one), a `--phrase-out` file this run
/// created, and the `init: trust anchor and vault keys` commit when the run
/// fails after committing but before the anchor save. Then it lets an armed
/// [`Scaffold`] roll the skeleton back on drop.
struct InitRollback {
    root: PathBuf,
    scaffold: Option<Scaffold>,
    keys_dir_preexisting: bool,
    keys_started: bool,
    /// HEAD immediately before the keys commit; `None` on an unborn branch.
    head_before_keys: Option<String>,
    /// True once `init: trust anchor and vault keys` succeeded.
    keys_committed: bool,
    phrase_out: Option<PathBuf>,
    phrase_out_created: bool,
    armed: bool,
}

impl InitRollback {
    fn new(root: &Path, scaffold: Option<Scaffold>, phrase_out: Option<&Path>) -> Self {
        InitRollback {
            root: root.to_path_buf(),
            scaffold,
            keys_dir_preexisting: root.join("keys").exists(),
            keys_started: false,
            head_before_keys: None,
            keys_committed: false,
            phrase_out: phrase_out.map(Path::to_path_buf),
            phrase_out_created: false,
            armed: true,
        }
    }

    /// Keep everything written so far (the run is about to succeed).
    fn disarm(&mut self) {
        self.armed = false;
        if let Some(scaffold) = self.scaffold.as_mut() {
            scaffold.armed = false;
        }
    }

    /// Rewind the `init: trust anchor and vault keys` commit so the working
    /// tree can be cleaned up. Returns false when git refuses.
    fn rewind_keys_commit(&self) -> bool {
        match &self.head_before_keys {
            Some(prev) => {
                confidant_core::write::git(&self.root, &["reset", "--mixed", prev], true).is_ok()
            }
            None => {
                confidant_core::write::git(&self.root, &["update-ref", "-d", "HEAD"], true).is_ok()
            }
        }
    }
}

impl Drop for InitRollback {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.keys_committed && !self.rewind_keys_commit() {
            // Keep the keys tree, the phrase file, and the scaffold: the
            // commit still references keys/, and deleting either side would
            // lose data silently. Say exactly what is left and why.
            if let Some(scaffold) = self.scaffold.as_mut() {
                scaffold.armed = false;
            }
            let keys_path = self.root.join("keys");
            eprintln!(
                "warning: init failed after committing keys/ but could not rewind the commit; \
                 keeping {} so the phrase still matches the committed keys",
                keys_path.display()
            );
            if self.phrase_out_created {
                if let Some(path) = &self.phrase_out {
                    eprintln!(
                        "warning: keeping the recovery phrase file at {}; write it down before \
                         retrying",
                        path.display()
                    );
                }
            }
            return;
        }
        if self.keys_started && !self.keys_dir_preexisting {
            let _ = std::fs::remove_dir_all(self.root.join("keys"));
        }
        if self.phrase_out_created {
            if let Some(path) = &self.phrase_out {
                let _ = std::fs::remove_file(path);
            }
        }
        // `scaffold` (if still armed) rolls back when it drops next.
    }
}

/// Env-var override for the operator Ed25519 signing seed at `init`
/// (64 hex characters = a 32-byte seed). The load path
/// (`confidant_crypt::keychain::operator_key`) already honors this variable;
/// `init` accepts it so a host with no OS Secret Service can create an
/// encrypted vault (#650).
const OPERATOR_KEY_ENV: &str = "CONFIDANT_OPERATOR_KEY";

/// Read and validate [`OPERATOR_KEY_ENV`] for `init` (#650). Returns `None`
/// when unset. Never echoes the value: errors name the variable and the
/// expected shape only.
fn operator_key_from_env() -> anyhow::Result<Option<ed25519_dalek::SigningKey>> {
    let raw = match std::env::var(OPERATOR_KEY_ENV) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(invalid_operator_key("it is not valid UTF-8"));
        }
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(invalid_operator_key("it is empty"));
    }
    if trimmed.len() != 64 {
        return Err(invalid_operator_key(&format!(
            "it is {} characters, not 64",
            trimmed.len()
        )));
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid_operator_key("it contains non-hex characters"));
    }
    let decoded = Zeroizing::new(
        hex::decode(trimmed).map_err(|_| invalid_operator_key("it is not valid hex"))?,
    );
    let seed: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| invalid_operator_key("it is not a 32-byte seed"))?;
    Ok(Some(ed25519_dalek::SigningKey::from_bytes(&seed)))
}

fn invalid_operator_key(reason: &str) -> anyhow::Error {
    anyhow::Error::new(DomainError::usage(format!(
        "{OPERATOR_KEY_ENV} is invalid: {reason}; expected 64 hex characters \
         (a 32-byte Ed25519 seed)"
    )))
    .with_fix(&format!(
        "Set {OPERATOR_KEY_ENV} to 64 hex characters, or unset it to generate a key \
         (the OS keychain must then be reachable)"
    ))
}

/// True when this process already has a device identity that
/// [`provision_device_key`] will use without writing the OS keychain:
/// `CONFIDANT_DEVICE_KEY`, or (test-overrides only) a
/// `CONFIDANT_TEST_KEYCHAIN_DIR` file / `CONFIDANT_TEST_DEVICE_KEY`.
fn device_key_supplied_from_env() -> anyhow::Result<bool> {
    use std::str::FromStr;
    #[cfg(feature = "test-overrides")]
    if test_keychain_dir().is_some_and(|dir| dir.join("device.key").is_file()) {
        return Ok(true);
    }
    #[cfg(feature = "test-overrides")]
    if let Ok(test_key) = std::env::var("CONFIDANT_TEST_DEVICE_KEY") {
        let trimmed = test_key.trim();
        if !trimmed.is_empty() {
            age::x25519::Identity::from_str(trimmed).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "CONFIDANT_TEST_DEVICE_KEY is not a valid age identity: {e}"
                )))
            })?;
            return Ok(true);
        }
    }
    match std::env::var(confidant_crypt::keychain::DEVICE_KEY_ENV) {
        Err(_) => Ok(false),
        Ok(value) if value.trim().is_empty() => Ok(false),
        Ok(value) => {
            age::x25519::Identity::from_str(value.trim()).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "{} is not a valid age identity: {e}",
                    confidant_crypt::keychain::DEVICE_KEY_ENV
                )))
            })?;
            Ok(true)
        }
    }
}

fn init_key_sources_error(detail: &str) -> anyhow::Error {
    use confidant_crypt::keychain::DEVICE_KEY_ENV;
    anyhow::Error::new(DomainError::invalid(format!(
        "cannot init on this host: {detail}"
    )))
    .with_fix(&format!(
        "On a host with no OS keychain, set {DEVICE_KEY_ENV} to an AGE-SECRET-KEY-1… identity \
         and {OPERATOR_KEY_ENV} to a 64-character hex Ed25519 seed before `confidant init` \
         (see docs/agent-setup.md, Headless hosts and agents)"
    ))
}

/// Refuse `init` — including `--dry-run` — when this host cannot persist
/// the device or operator key the same way a real run would (#682).
///
/// A reachable OS keychain is enough to generate both. A headless host
/// (keychain unreachable, or the test-only `CONFIDANT_KEYCHAIN=off`
/// switch) needs `CONFIDANT_DEVICE_KEY` (or, in test builds, a
/// `CONFIDANT_TEST_KEYCHAIN_DIR` / `CONFIDANT_TEST_DEVICE_KEY` that
/// [`provision_device_key`] would honor); it also needs
/// `CONFIDANT_OPERATOR_KEY` unless the kill switch is on, matching the
/// real init path that skips the operator keychain write in tests.
fn require_init_key_sources() -> anyhow::Result<()> {
    use confidant_crypt::keychain::{
        self, DeviceKeyState, KeychainBackend, DEVICE_ACCOUNT, DEVICE_KEY_ENV, DEVICE_SERVICE,
    };

    // Same stand-in #688 uses in `device_key_store_available`: a test
    // keychain dir is the file-backed store `provision_device_key` writes
    // to under `--all-features`. Dir presence is enough; do not wait for
    // `device.key` (shred-rotation fixtures set the dir and then init).
    #[cfg(feature = "test-overrides")]
    if test_keychain_dir().is_some() {
        return Ok(());
    }

    let operator_from_env = operator_key_from_env()?.is_some();
    let device_from_env = device_key_supplied_from_env()?;
    if device_from_env && operator_from_env {
        return Ok(());
    }

    if keychain::keychain_switch().map_err(anyhow::Error::new)? == keychain::KeychainSwitch::Off {
        if !device_from_env {
            return Err(init_key_sources_error(
                "the OS keychain is not available to store a generated device key",
            ));
        }
        // Real init skips the operator keychain write under the kill switch.
        return Ok(());
    }

    let keychain_reachable = match keychain::device_key_state() {
        Ok(DeviceKeyState::Keychain | DeviceKeyState::NotEnrolled) => true,
        Ok(DeviceKeyState::Env) => {
            if operator_from_env {
                return Ok(());
            }
            // `DeviceKeyState::Env` means CONFIDANT_DEVICE_KEY is set, so
            // `device_key_state` never opened the OS keychain. Probe it so
            // a headless host still needs CONFIDANT_OPERATOR_KEY unless
            // the keychain can persist one. `Error::Keychain` is
            // "unreachable" (no Secret Service / no entry); any other
            // error is a real backend failure and must not be treated as
            // "no store".
            match keychain::OsKeychain.get_password(DEVICE_SERVICE, DEVICE_ACCOUNT) {
                Ok(_) => true,
                Err(confidant_crypt::error::Error::Keychain(_)) => false,
                Err(e) => return Err(anyhow::Error::new(e)),
            }
        }
        Ok(DeviceKeyState::KeychainUnreachable(_)) => false,
        Err(e) => return Err(anyhow::Error::new(e)),
    };
    if keychain_reachable {
        return Ok(());
    }

    let mut missing = Vec::new();
    if !device_from_env {
        missing.push(DEVICE_KEY_ENV);
    }
    if !operator_from_env {
        missing.push(OPERATOR_KEY_ENV);
    }
    Err(init_key_sources_error(&format!(
        "the OS keychain is unreachable and {} is unset",
        missing.join(" and ")
    )))
}

/// Branch `--create` will use, plus a note when an existing repo is left
/// on a name other than `main` (#682, #661).
fn planned_create_branch(root: &Path, no_input: bool) -> (String, Option<String>) {
    if !root.is_dir() || !is_git_repo_root(root, no_input) {
        return ("main".to_owned(), None);
    }
    if confidant_core::write::git(root, &["rev-parse", "--verify", "HEAD"], no_input).is_err() {
        return (
            "main".to_owned(),
            Some("would move unborn HEAD to main".to_owned()),
        );
    }
    let current = current_branch(root, no_input).unwrap_or_else(|| "main".to_owned());
    if current == "main" {
        (current, None)
    } else {
        (
            current.clone(),
            Some(format!(
                "would leave existing branch {current} (init only moves an unborn HEAD to main)"
            )),
        )
    }
}

/// True when git can resolve a commit identity for the repo at `root`.
/// Runs `git var` before `init --create` writes anything (#651), and avoids
/// reading the *current* directory's repo config: a fresh target has no local
/// config, so only global/system/env identity applies. `GIT_DIR` works even
/// when that path does not exist yet.
fn require_git_identity(root: &Path, no_input: bool) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new("git");
    if is_git_repo_root(root, no_input) {
        cmd.arg("-C").arg(root);
    } else {
        cmd.env("GIT_DIR", root.join(".git"));
    }
    cmd.args(["var", "GIT_AUTHOR_IDENT"]);
    if no_input {
        cmd.env("GIT_TERMINAL_PROMPT", "0");
    }
    let ok = cmd
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if ok {
        return Ok(());
    }
    Err(anyhow::Error::new(DomainError::invalid(
        "git has no author identity, so init cannot commit the vault",
    ))
    .with_fix(
        "Set a git identity, e.g. `git config --global user.name \"Your Name\"` and `git config --global user.email you@example.com`",
    ))
}

/// The current branch name (works on an unborn branch), or `None` when git
/// cannot report one.
fn current_branch(root: &Path, no_input: bool) -> Option<String> {
    confidant_core::write::git(root, &["branch", "--show-current"], no_input)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// #685/#686: second devices clone + `keys device-add`; `recover` burns the
/// phrase. Shown after `init` (human and JSON) so a new-device operator is
/// not sent to `init` or `recover`.
const SECOND_DEVICE_HINT: &str = "to put this vault on another device, clone it and run `confidant keys device-add` (not `init`; `recover` only if every enrolled device is lost)";

/// `--remote` on `init --create`, if present.
fn init_remote_url(cli: &Cli) -> Option<&str> {
    match &cli.command {
        Command::Init { remote, .. } => remote.as_deref(),
        _ => None,
    }
}

/// Additive `next_steps` for `init` JSON (#658, #686): `pack add` when the
/// scaffolded list is empty, `git push` when `--remote` set origin, and
/// always the second-device enrollment path.
fn init_next_steps(packs_empty: bool, remote: Option<&str>, branch: &str) -> Value {
    let mut steps = Vec::new();
    if packs_empty {
        steps.push("confidant pack add <https-url> --yes".to_string());
    }
    if remote.is_some() {
        steps.push(format!("git push -u origin {branch}"));
    }
    steps.push(SECOND_DEVICE_HINT.to_string());
    serde_json::json!(steps)
}

/// Human follow-up after a real or dry-run `init`. The pack-add line must
/// appear at most once (#658).
fn print_init_followup(packs_empty: bool, remote: Option<&str>, branch: &str) {
    if packs_empty {
        println!("optional: install a pack with `confidant pack add <https-url> --yes`");
    }
    if let Some(url) = remote {
        println!("git remote origin {} (not pushed)", display_remote_url(url));
        println!("push when ready: git push -u origin {branch}");
    } else {
        println!(
            "optional: `git remote add origin <url>` for backup (or `--remote <url>` with `--create`); this command does not push"
        );
    }
    println!("{SECOND_DEVICE_HINT}");
}

/// Refuse `--remote` when the URL is empty or `origin` already exists, so
/// `--create --dry-run` reports the same error a real run would.
fn refuse_init_remote(
    root: &Path,
    url: &str,
    existing_repo: bool,
    no_input: bool,
) -> anyhow::Result<()> {
    let url = url.trim();
    if url.is_empty() {
        return Err(anyhow::Error::new(
            DomainError::usage("--remote needs a git URL").with_fix(
                "Pass `--remote <url>` with a real remote, or omit it and add origin later",
            ),
        ));
    }
    // `git remote add` would otherwise parse a leading `-` as an option.
    if url.starts_with('-') {
        return Err(anyhow::Error::new(
            DomainError::usage("refusing --remote: URL must not start with '-'")
                .with_fix("Pass a git URL (https://… or git@…), not a flag"),
        ));
    }
    if !existing_repo {
        return Ok(());
    }
    let remotes = confidant_core::write::git(root, &["remote"], no_input)?;
    if remotes.lines().any(|line| line.trim() == "origin") {
        return Err(anyhow::Error::new(
            DomainError::usage(format!(
                "refusing --remote: origin already exists on {}",
                root.display()
            ))
            .with_fix("Use the existing origin, or `git remote remove origin` first"),
        ));
    }
    Ok(())
}

/// `git remote add origin URL`. `Scaffold::added_remote` is set only after
/// this succeeds so a failed `git remote add` is not rolled back as if it
/// created origin.
fn add_init_remote(
    root: &Path,
    url: &str,
    no_input: bool,
    scaffold: &mut Scaffold,
) -> anyhow::Result<()> {
    confidant_core::write::git(
        root,
        &["remote", "add", "--", "origin", url.trim()],
        no_input,
    )?;
    scaffold.added_remote = true;
    Ok(())
}

/// #649: report the `init --create` plan without writing anything.
fn print_init_scaffold_dry_run(cli: &Cli, root: &Path, packs: &[String]) -> anyhow::Result<()> {
    let packs_empty = packs.is_empty();
    let (branch, branch_note) = planned_create_branch(root, cli.no_input);
    let remote = init_remote_url(cli);
    if cli.json {
        let mut extra = serde_json::json!({
            "command": "init",
            "dry_run": true,
            "branch": branch,
            "scaffold": true,
            "packs": packs,
            "remote": remote.map(display_remote_url),
            "next_steps": init_next_steps(packs_empty, remote, &branch),
        });
        if let Some(note) = &branch_note {
            extra["branch_note"] = Value::String(note.clone());
        }
        print_json(&ok_envelope(Some(root), extra))?;
    } else {
        println!("dry run — no changes:");
        println!("  vault    {}", root.display());
        println!("  branch   {branch}");
        if let Some(note) = &branch_note {
            println!("  note     {note}");
        }
        println!("  would    create the vault directory (when absent)");
        println!("  would    run git init and commit .gitignore + confidant.toml");
        match remote {
            Some(url) => println!(
                "  would    add git remote origin {} (not pushed)",
                display_remote_url(url)
            ),
            None => println!("  would    not add a git remote"),
        }
        if std::env::var_os(OPERATOR_KEY_ENV).is_some() {
            println!("  would    use {OPERATOR_KEY_ENV} as the operator key");
        } else {
            println!("  would    generate the operator key");
        }
        println!("  would    generate the recovery phrase and device key");
        println!("  would    commit keys/ and write the trust anchor");
        print_init_followup(packs_empty, remote, &branch);
    }
    Ok(())
}

/// `init --create`: scaffold a vault before the key steps so one
/// non-interactive command produces a working vault (#539).
///
/// Creates the directory, runs `git init` when the target is not its own
/// repo, ensures `.confidant/` is git-ignored, writes a minimal
/// `confidant.toml` (`packs` from the global `--packs`, default `[]`), and
/// commits just those files. An existing vault is left to today's path; any
/// other non-empty directory is refused with nothing written.
fn bootstrap_vault(cli: &Cli, create: bool, force: bool) -> anyhow::Result<BootstrapPlan> {
    if !create {
        return Ok(BootstrapPlan::Continue(None));
    }
    let no_input = cli.no_input;
    let root = bootstrap_target(cli);

    // An existing vault takes today's path unchanged (anchor check, clean
    // tree, key steps). `--remote` is a scaffold-only flag: refuse rather
    // than silently skip it on a directory that already has a vault.
    if root.join("confidant.toml").is_file() {
        if init_remote_url(cli).is_some() {
            return Err(anyhow::Error::new(
                DomainError::usage(format!(
                    "refusing --remote: {} already has a vault; --remote only applies while scaffolding",
                    root.display()
                ))
                .with_fix("Add a remote with `git remote add origin <url>` (this command does not push)"),
            ));
        }
        return Ok(BootstrapPlan::Continue(None));
    }

    // B1 preflight: the very refusal `cmd_init` would produce, but before any
    // file is written, so a refused init leaves no half-built skeleton.
    let config_dir = confidant_config_dir().ok_or_else(|| {
        anyhow::Error::new(DomainError::invalid(
            "HOME is not set; cannot locate the operator config dir",
        ))
    })?;
    refuse_existing_anchor(&config_dir.join(confidant_crypt::anchor::TRUST_FILE), force)?;

    // #539: only an absent, empty, or skeleton-only directory is scaffolded.
    // A non-empty target — including a clean git repo — is refused so that
    // running `--create` from the wrong cwd cannot turn a project checkout
    // into a vault. Vault-inside-an-existing-repo, if ever wanted, is its own
    // explicit flag and decision.
    let exists = root.is_dir();
    let entries = if exists {
        dir_entry_names(&root)?
    } else {
        Vec::new()
    };
    let only_our_files = entries.iter().all(|n| n == ".git" || n == ".gitignore");
    if exists && !entries.is_empty() && !only_our_files {
        return Err(anyhow::Error::new(
            DomainError::usage(format!(
                "refusing to scaffold a vault in {}: the directory is not empty (--create only scaffolds an absent or empty directory)",
                root.display()
            ))
            .with_fix(
                "Use an empty directory, or create the vault by hand (`git init`, write `confidant.toml`, commit) and run `confidant init`",
            ),
        ));
    }

    // Validate `--packs` before writing: an unknown pack would leave the new
    // vault failing `check`, and an external pack cannot be vendored before
    // the vault exists (#639).
    let packs: Vec<String> = cli
        .packs
        .as_deref()
        .map(parse_pack_list)
        .unwrap_or_default();
    validate_init_packs(&packs)?;

    // #650: validate the operator-key override before the dry-run branch and
    // before any write, so `--create --dry-run` reports a bad value too.
    let _ = operator_key_from_env()?;

    // #651: require a commit identity before creating the directory or
    // running `git init`. `git var` works outside a repo, so a refused run
    // leaves an absent target absent instead of an empty `.git` that blocks
    // the retry. This also covers the dry run so it reports the same refusal.
    require_git_identity(&root, no_input)?;

    // #682: `--dry-run` "runs every preflight check" — including whether
    // this host can persist keys. A keyless headless box must fail here
    // the same way a real init would at `store_device_key`.
    require_init_key_sources()?;

    let existing_repo = exists && is_git_repo_root(&root, no_input);
    if let Some(url) = init_remote_url(cli) {
        refuse_init_remote(&root, url, existing_repo, no_input)?;
    }

    // #649: dry run stops before the first write.
    if cli.dry_run {
        print_init_scaffold_dry_run(cli, &root, &packs)?;
        return Ok(BootstrapPlan::DryRun);
    }
    let previous_head = if existing_repo {
        confidant_core::write::git(&root, &["rev-parse", "HEAD"], no_input)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    let mut scaffold = Scaffold {
        root: root.clone(),
        created_root: !exists,
        git_initialized: !existing_repo,
        gitignore_original: std::fs::read(root.join(".gitignore")).ok(),
        wrote_gitignore: false,
        wrote_config: false,
        commit_created: false,
        previous_head,
        added_remote: false,
        armed: true,
    };

    std::fs::create_dir_all(&root).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot create vault directory {}: {e}",
            root.display()
        )))
    })?;

    if scaffold.git_initialized {
        confidant_core::write::git(&root, &["init"], no_input)?;
        // #661: create `main` explicitly, independent of init.defaultBranch.
        // `symbolic-ref` is portable and works before the first commit.
        confidant_core::write::git(
            &root,
            &["symbolic-ref", "HEAD", "refs/heads/main"],
            no_input,
        )?;
    } else if existing_repo
        && confidant_core::write::git(&root, &["rev-parse", "--verify", "HEAD"], no_input).is_err()
    {
        // #661 edge: a pre-existing repo with an unborn HEAD has no commits
        // to rename, so create `main` explicitly here too. A repo with
        // commits is never renamed (the `rev-parse --verify HEAD` above).
        confidant_core::write::git(
            &root,
            &["symbolic-ref", "HEAD", "refs/heads/main"],
            no_input,
        )?;
    }

    // `.confidant/` holds the plaintext search corpus and must never be
    // committed (ADR-6); `reindex` refuses without this entry.
    let gitignore = root.join(".gitignore");
    let mut text = std::fs::read_to_string(&gitignore).unwrap_or_default();
    let already_ignored = text
        .lines()
        .any(|line| matches!(line.trim(), ".confidant/" | ".confidant"));
    if !already_ignored {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(".confidant/\n");
        scaffold.wrote_gitignore = true;
        std::fs::write(&gitignore, text)?;
    }

    let packs_toml = if packs.is_empty() {
        "[]".to_string()
    } else {
        let quoted: Vec<String> = packs.iter().map(|p| format!("{p:?}")).collect();
        format!("[{}]", quoted.join(", "))
    };
    scaffold.wrote_config = true;
    std::fs::write(
        root.join("confidant.toml"),
        format!(
            "spec = {:?}\npacks = {packs_toml}\nvault_id = {:?}\n",
            confidant_core::SPEC_VERSION,
            confidant_core::write::new_ulid(),
        ),
    )?;

    // Commit only the skeleton files this command wrote, never `git add -A`.
    // The commit carries a pathspec too, so any changes an existing repo
    // already had staged are never swept into the skeleton commit.
    confidant_core::write::git(
        &root,
        &["add", "--", ".gitignore", "confidant.toml"],
        no_input,
    )?;
    let staged = confidant_core::write::git(
        &root,
        &[
            "status",
            "--porcelain",
            "--",
            ".gitignore",
            "confidant.toml",
        ],
        no_input,
    )?;
    if !staged.trim().is_empty() {
        confidant_core::write::git(
            &root,
            &[
                "commit",
                "-m",
                "init: vault skeleton",
                "--",
                ".gitignore",
                "confidant.toml",
            ],
            no_input,
        )?;
        scaffold.commit_created = true;
    }

    if let Some(url) = init_remote_url(cli) {
        add_init_remote(&root, url, no_input, &mut scaffold)?;
    }

    if !cli.json {
        let branch = current_branch(&root, no_input).unwrap_or_else(|| "main".to_owned());
        eprintln!("scaffolded vault at {} (branch {branch})", root.display());
    }
    Ok(BootstrapPlan::Continue(Some(scaffold)))
}

fn cmd_init(
    cli: &Cli,
    root: &Path,
    force: bool,
    scaffold: Option<Scaffold>,
    phrase_out: Option<&Path>,
) -> anyhow::Result<ExitCode> {
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
    refuse_existing_anchor(&trust_path, force)?;

    // Git repo + clean tree required.
    require_git_repo(root, no_input)?;
    let status = confidant_core::write::git(root, &["status", "--porcelain"], no_input)?;
    if !status.trim().is_empty() {
        return Err(anyhow::Error::new(
            DomainError::invalid("vault tree is not clean; commit or stash changes first")
                .with_fix("Run `git status` in the vault and clean the tree"),
        ));
    }

    // #640: `init` creates a first-device key tree; it never re-initializes
    // one. `init_client` refuses once `keys/shared/epoch` exists, but only
    // after `init_lookup_key` has already rewritten `keys/vault`. Check the
    // same condition before any key material is generated, stored, or
    // written, so a refused `--force` leaves the working tree
    // byte-identical (and does not replace the keychain entries either).
    let keys_dir = root.join("keys");
    if keys_dir.join("shared").join("epoch").exists() {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "vault keys already exist at {}; init creates a new key tree and never \
                 re-initializes an existing one (--force only replaces a trust anchor)",
                keys_dir.display()
            ))
            .with_fix(
                "Start in a fresh directory for a new vault. To put this vault on another \
                 device, clone it and run `confidant keys device-add` (not `init`; `recover` \
                 only if every enrolled device is lost). Use `confidant keys rotate` to \
                 rotate existing keys",
            ),
        ));
    }

    // #651: the key commit needs an identity too. Check before generating
    // any key material (works inside an existing repo).
    require_git_identity(root, no_input)?;

    // #650: validate the operator-key override in the preflight so a bad
    // value fails (including under --dry-run) before anything is generated
    // or written. The same env var is already honored by the load path.
    let env_operator_sk = operator_key_from_env()?;

    // #682: same key-source preflight as `--create`, so `--dry-run` on a
    // prepared vault also refuses a keyless headless host.
    require_init_key_sources()?;

    let vault = load_vault(root)?;
    // Spec 3 (§2.2): keys must never coexist with a plaintext declaration.
    // `init` on a vault declaring `[crypto] mode = "plaintext"` is a hard
    // error — the opt-out is a pre-`init` declaration only. Checked here so
    // `--dry-run` reports the same refusal without generating keys.
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

    let branch = current_branch(root, no_input);
    let packs_empty = vault.config.packs.is_empty();

    // #649: every preflight above passed; report the plan and stop before
    // key generation, keychain writes, keys/ commits, or the anchor save.
    let remote = init_remote_url(cli);
    let branch_name = branch.as_deref().unwrap_or("main");
    if cli.dry_run {
        if json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "command": "init",
                    "dry_run": true,
                    "branch": branch,
                    "remote": remote.map(display_remote_url),
                    "next_steps": init_next_steps(packs_empty, remote, branch_name),
                }),
            ))?;
        } else {
            println!("dry run — no changes:");
            println!("  vault    {}", root.display());
            if let Some(branch) = &branch {
                println!("  branch   {branch}");
            }
            if env_operator_sk.is_some() {
                println!("  would    use {OPERATOR_KEY_ENV} as the operator key");
            } else {
                println!("  would    generate the operator key");
            }
            println!("  would    generate the recovery phrase and device key");
            println!(
                "  would    commit keys/ and write the trust anchor at {}",
                trust_path.display()
            );
            print_init_followup(packs_empty, remote, branch_name);
        }
        return Ok(ExitCode::SUCCESS);
    }

    // Everything from here on can write. The guard removes only what this
    // run created: a `keys/` tree that did not exist, a `--phrase-out` file,
    // and (with `--create`) the skeleton.
    let mut rollback = InitRollback::new(root, scaffold, phrase_out);

    // B2: generate operator key, recovery phrase, and device keypair.
    // None of this material is ever written into the vault.
    // Test override (test-overrides feature only): CONFIDANT_TEST_OPERATOR_KEY
    // provides the hex seed and keeps precedence. Otherwise #650's
    // CONFIDANT_OPERATOR_KEY (validated above) supplies the seed for
    // headless hosts; with neither, generate a fresh key.
    #[cfg(feature = "test-overrides")]
    let test_operator_sk = test_operator_key();
    #[cfg(not(feature = "test-overrides"))]
    let test_operator_sk: Option<SigningKey> = None;
    let operator_from_env = env_operator_sk.is_some();
    let operator_sk = test_operator_sk
        .or(env_operator_sk)
        .unwrap_or_else(|| SigningKey::generate(&mut OsRng));
    let recovery = Recovery::generate();
    let phrase = recovery.phrase();

    // #662: write the phrase file before any key persistence. If the file
    // cannot be created, abort with nothing persisted; the guard removes a
    // partial file if the write itself fails, but never a pre-existing one.
    if let Some(path) = phrase_out {
        let mut file = create_phrase_file(path)?;
        rollback.phrase_out_created = true;
        write_phrase_file(&mut file, path, &phrase)?;
    }

    let (_device_bech32, device_recipient) = provision_device_key()?;

    // Persist the operator signing key to the OS keychain (needed for
    // `keys` commands to sign manifests). #650: when CONFIDANT_OPERATOR_KEY
    // is set, the operator key is externally managed for this run — do not
    // write it to the keychain, which would fail on a headless host or
    // duplicate the secret. The test-override path is otherwise unchanged:
    // in tests (CONFIDANT_KEYCHAIN=off) the keychain write is refused and
    // the harness provides the key via CONFIDANT_TEST_OPERATOR_KEY instead.
    if !operator_from_env {
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
    rollback.keys_started = true;
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

    // #651: the phrase must be visible BEFORE the irreversible keys/ commit
    // and anchor save, so a failed run can never leave keys whose phrase was
    // never seen. With --phrase-out the file was written above; without it,
    // display now. A display failure aborts before anything is committed.
    if phrase_out.is_none() {
        display_phrase_once(no_input, &phrase)?;
    }

    // #651 review: record the pre-keys HEAD so a failure after the keys
    // commit (e.g. the anchor save) can rewind it before removing keys/.
    rollback.head_before_keys = confidant_core::write::git(root, &["rev-parse", "HEAD"], no_input)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());

    stage_keys(root, no_input)?;
    confidant_core::write::git(
        root,
        &["commit", "-m", "init: trust anchor and vault keys"],
        no_input,
    )?;
    rollback.keys_committed = true;
    let commit = confidant_core::write::git(root, &["rev-parse", "HEAD"], no_input)?
        .trim()
        .to_owned();

    // Test-only failpoint (never in release builds): a failure after the
    // irreversible keys/ commit and before the anchor save exercises the
    // rewind path. Not part of the agent contract.
    #[cfg(feature = "test-overrides")]
    if std::env::var("CONFIDANT_TEST_FAIL_AFTER_KEYS_COMMIT").as_deref() == Ok("1") {
        return Err(anyhow::Error::new(DomainError::internal(
            "test-only failpoint: failing after the keys/ commit",
        )));
    }

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

    // The run succeeded: keep the skeleton, keys/, and phrase file.
    rollback.disarm();

    // B5: phrase exactly once on stderr (or only its path when
    // --phrase-out was used); stdout JSON carries ok, vault, and opaque
    // paths — no phrase, no key material.
    if let Some(path) = phrase_out {
        eprintln!("recovery phrase written to {}", path.display());
        eprintln!("Move this file offline, then delete it.");
    }

    if json {
        let mut extra = serde_json::json!({
            "anchor": trust_path.display().to_string(),
            "keys_dir": keys_dir.display().to_string(),
            "commit": commit,
            "branch": branch,
            "remote": remote.map(display_remote_url),
            "next_steps": init_next_steps(packs_empty, remote, branch_name),
        });
        if let Some(path) = phrase_out {
            extra["phrase_out"] = Value::String(path.display().to_string());
        }
        print_json(&ok_envelope(Some(root), extra))?;
    } else {
        println!("initialized trust anchor at {}", trust_path.display());
        if let Some(branch) = &branch {
            println!("branch {branch}");
        }
        println!("committed keys/ tree ({})", &commit[..8.min(commit.len())]);
        print_init_followup(packs_empty, remote, branch_name);
    }
    Ok(ExitCode::SUCCESS)
}

/// Read a recovery phrase from stdin or `--phrase-file` (B7: never argv).
///
/// Both channels read straight into a [`Zeroizing<String>`]; the trimmed
/// copy is zeroizing too, so neither the raw nor the trimmed buffer is ever
/// dropped as a plain `String`. Empty input is a usage error.
fn read_phrase(phrase_file: Option<&Path>) -> anyhow::Result<Zeroizing<String>> {
    use std::io::Read;

    let mut buf: Zeroizing<String> = Zeroizing::new(String::new());
    if let Some(path) = phrase_file {
        let text = std::fs::read_to_string(path).map_err(|e| {
            anyhow::Error::new(DomainError::usage(format!(
                "--phrase-file {} unreadable: {e}",
                path.display()
            )))
        })?;
        *buf = text;
    } else {
        io::stdin().read_to_string(&mut buf).map_err(|e| {
            anyhow::Error::new(DomainError::usage(format!(
                "cannot read phrase from stdin: {e}"
            )))
        })?;
    }

    let trimmed = buf.trim();
    if trimmed.is_empty() {
        return Err(anyhow::Error::new(DomainError::usage(
            "recovery phrase is required via stdin or --phrase-file",
        )));
    }
    if trimmed.len() == buf.len() {
        return Ok(buf);
    }
    // A separate zeroizing buffer, so dropping the untrimmed original does
    // not leave the phrase bytes in a plain `String` (#663).
    Ok(Zeroizing::new(trimmed.to_owned()))
}

/// Compare a phrase-derived recovery identity with a trust anchor: **both**
/// halves must match (Ed25519 pubkey and X25519 age recipient). The two
/// comparisons live here so `recover` and `keys verify-recovery` cannot
/// drift apart (#663).
fn recovery_matches_anchor(
    anchor: &confidant_crypt::anchor::Anchor,
    recovery: &confidant_crypt::recovery::Recovery,
) -> (bool, bool) {
    (
        anchor.recovery == recovery.verifying_key(),
        anchor.recovery_age == recovery.age_identity().to_recipient_string(),
    )
}

/// Fail closed unless the phrase-derived recovery identity matches the
/// anchor's Ed25519 pubkey and X25519 age recipient. Shared by `recover`
/// and `keys verify-recovery`.
fn check_recovery(
    anchor: &confidant_crypt::anchor::Anchor,
    recovery: &confidant_crypt::recovery::Recovery,
) -> anyhow::Result<()> {
    let (pubkey_matches, recipient_matches) = recovery_matches_anchor(anchor, recovery);
    if !pubkey_matches {
        return Err(anyhow::Error::new(DomainError::invalid(
            "recovery phrase does not match this vault's trust anchor",
        )));
    }
    // The X25519 recovery recipient is a separate HKDF branch of the
    // phrase; it must match too, or a tampered anchor file could get a
    // forged recipient recorded in the denylist and the real retired
    // recipient missed (#154 must-fix 1).
    if !recipient_matches {
        return Err(anyhow::Error::new(DomainError::invalid(
            "recovery phrase does not match this vault's trust anchor (recovery recipient)",
        )));
    }
    Ok(())
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

    // B7: phrase via stdin or --phrase-file only — never argv. Both
    // channels read into zeroizing buffers (shared `read_phrase`).
    let phrase = read_phrase(phrase_file)?;

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
    let anchor = if let Some(path) = anchor_file {
        let a = anchor::load_from(path, root).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "--anchor-file {} rejected: {e}",
                path.display()
            )))
        })?;
        check_recovery(&a, &old_recovery)?;
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
                check_recovery(&a, &old_recovery)?;
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
        println!(
            "next: confirm the copy you just saved with `confidant keys verify-recovery --phrase-file <path>`"
        );
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
        "removed_stale": result
            .removed_stale
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "dry_run": result.dry_run,
    })
}

fn cmd_setup(
    cli: &Cli,
    agent: &str,
    force: bool,
    copy: bool,
    verbose: bool,
) -> anyhow::Result<ExitCode> {
    match setup::run_setup(agent, force, copy, cli.dry_run) {
        Ok(result) => {
            // #653c: `--agent auto` falls back to claude-code when nothing is
            // detected; say so instead of creating ~/.claude silently.
            if let Some(note) = &result.fallback_note {
                eprintln!("warning: {note}");
            }
            if cli.json {
                let mut value = setup_result_json(&result);
                if let Value::Object(ref mut obj) = value {
                    obj.insert("next_steps".to_owned(), setup_next_steps_json(cli));
                }
                print_json(&ok_envelope(None, value))?;
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
                if result.dry_run {
                    println!("Confidant skills (dry run; nothing written)");
                } else {
                    println!("Confidant skills installed");
                }
                println!("  skills   {} → {labels}", result.skills_dir.display());
                println!("  version  {}", result.version);
                println!(
                    "  {:<9} {} ({} skipped)",
                    if result.dry_run {
                        "would link"
                    } else {
                        "linked"
                    },
                    result.linked_count(),
                    result.skipped_count()
                );
                if result.skipped_count() > 0 {
                    println!("  replace existing dirs with: confidant setup --force");
                }
                if !result.removed_stale.is_empty() {
                    println!(
                        "  {:<9} {} stale skill link(s)",
                        if result.dry_run {
                            "would drop"
                        } else {
                            "removed"
                        },
                        result.removed_stale.len()
                    );
                }
                if result.dry_run {
                    println!("  re-run without --dry-run to apply");
                } else {
                    println!();
                    setup_next_steps(cli, verbose)?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => Err(err),
    }
}

/// True when the operator has pointed at a vault via `CONFIDANT_VAULT`
/// (non-empty). Unset or empty means the next-steps block prints the
/// export line instead.
fn vault_env_set() -> bool {
    std::env::var("CONFIDANT_VAULT")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// The exact line to paste when `CONFIDANT_VAULT` is unset (#376): the real
/// path only when one was given explicitly (e.g. `--vault`), otherwise the
/// `<path>` placeholder. The vault itself is never read or probed.
fn vault_export_line(cli: &Cli) -> String {
    match &cli.vault {
        Some(p) => format!("export CONFIDANT_VAULT={}", p.display()),
        None => "export CONFIDANT_VAULT=<path>".to_owned(),
    }
}

/// Additive `next_steps` entry for the `setup` JSON envelope (#376): the
/// check command to run, whether `CONFIDANT_VAULT` is set, and the exact
/// export line when it is not. Never probes the vault. #386 adds the
/// informational qmd availability (`qmd_available`, plus `qmd_note` only
/// when qmd is missing): qmd is optional and never changes exit status.
fn setup_next_steps_json(cli: &Cli) -> Value {
    let set = vault_env_set();
    let qmd_note = qmd_setup_note();
    serde_json::json!({
        "check_command": "confidant check",
        "vault_set": set,
        "vault_export": if set {
            Value::Null
        } else {
            Value::String(vault_export_line(cli))
        },
        "qmd_available": qmd_note.is_none(),
        "qmd_note": qmd_note.map(Value::String).unwrap_or(Value::Null),
    })
}

/// Human-readable next steps after `setup` (#376). When `CONFIDANT_VAULT`
/// is set, an interactive terminal is offered `run `confidant check` now?`
/// (default No, never automatic); non-interactive output only prints the
/// check command. When unset, the exact export line replaces the old
/// generic wording. The vault is never read or probed here — the check
/// runs only after an explicit `y`, inheriting the environment.
///
/// #653e: the optional qmd npm note is only printed with `-v/--verbose`;
/// JSON keeps `qmd_available`/`qmd_note` for agents either way.
fn setup_next_steps(cli: &Cli, verbose: bool) -> anyhow::Result<()> {
    println!("Next:");
    if vault_env_set() {
        println!("  Run `confidant check` against your vault.");
        if confirm_yn("run `confidant check` now?", cli.no_input, cli.json)? {
            let exe = offer_exe_path();
            match run_offered_command("confidant check", exe.as_os_str(), &["check"]) {
                Ok(()) => println!("`confidant check` passed."),
                Err(err) => eprintln!("`confidant check` failed: {err:#}"),
            }
        }
    } else {
        println!("  {}", vault_export_line(cli));
        println!("  Then run `confidant check`.");
    }
    // #386: informational qmd note. Optional, never prompts, never fails,
    // never changes exit status.
    if verbose {
        if let Some(note) = qmd_setup_note() {
            println!("  {note}");
        }
    }
    Ok(())
}

fn cmd_update(cli: &Cli, agent: &str, force: bool, verbose: bool) -> anyhow::Result<ExitCode> {
    // Self-update via the cargo-dist updater is not yet wired: `update`
    // reports the latest release, offers to run the matching upgrade
    // command (#376), and re-links skills from this binary.
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
    let method = detect_install_method(&offer_exe_path());
    let upgrade_cmd =
        "update the binary first (re-run the installer or `cargo install confidant-cli`), then re-run `confidant setup`.";
    if cli.json {
        // The JSON path never prompts and never runs anything (#376); the
        // new fields are additive.
        let mut update_info = match &latest {
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
        if let Value::Object(ref mut obj) = update_info {
            obj.insert(
                "install_method".to_owned(),
                Value::String(method.as_str().to_owned()),
            );
            obj.insert(
                "update_command".to_owned(),
                method
                    .update_command()
                    .map(|c| Value::String(c.to_owned()))
                    .unwrap_or(Value::Null),
            );
        }
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
        let result = setup::run_setup(agent, force, false, cli.dry_run)?;
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
                    // Never re-link from a behind binary: the installed
                    // skills would be stale on arrival. Print the single
                    // command that fits this install; in an interactive
                    // terminal, offer to run it (default No). `--dry-run`
                    // prints the command and never offers or runs it (#668).
                    if let (Some(cmd), Some((program, args))) =
                        (method.update_command(), method.run_spec())
                    {
                        if cli.dry_run {
                            println!("confidant {local} is behind the latest release {tag}; would run `{cmd}`, then re-run `confidant setup`.");
                        } else {
                            println!("confidant {local} is behind the latest release {tag}; run `{cmd}`, then re-run `confidant setup`.");
                            if offerable_update(method, true)
                                && confirm_yn(&format!("run `{cmd}` now?"), cli.no_input, cli.json)?
                            {
                                match run_offered_command(cmd, program, args) {
                                    Ok(()) => {
                                        println!("updated via `{cmd}`.");
                                        if confirm_yn(
                                            "run `confidant setup` now?",
                                            cli.no_input,
                                            cli.json,
                                        )? {
                                            return relink_after_update(
                                                agent,
                                                force,
                                                verbose,
                                                cli.dry_run,
                                            );
                                        }
                                    }
                                    Err(err) => eprintln!("update failed: {err:#}"),
                                }
                            }
                        }
                    } else {
                        println!(
                            "confidant {local} is behind the latest release {tag}; {upgrade_cmd}"
                        );
                    }
                    return Ok(ExitCode::SUCCESS);
                }
                if cli.dry_run {
                    println!("confidant {local} is current (latest: {tag}). Would re-link skills…");
                } else {
                    println!("confidant {local} is current (latest: {tag}). Re-linking skills…");
                }
            }
        }
    }
    relink_after_update(agent, force, verbose, cli.dry_run)
}

/// Shared tail of `update`: re-link skills from this binary and report.
/// `force` is the operator's own flag: owned entries are re-pointed
/// regardless, unowned entries need it. `dry_run` (#668) plans the relink
/// and writes nothing.
fn relink_after_update(
    agent: &str,
    force: bool,
    verbose: bool,
    dry_run: bool,
) -> anyhow::Result<ExitCode> {
    let result = setup::run_setup(agent, force, false, dry_run)?;
    if verbose {
        for line in &result.verbose_lines {
            println!("{line}");
        }
    }
    for unknown in &result.unknown_agents {
        eprintln!("warning: unknown agent '{unknown}' — skipped");
    }
    if dry_run {
        println!(
            "would re-link {} skills → {}",
            result.linked_count(),
            result.agent_labels().join(", ")
        );
    } else {
        println!(
            "re-linked {} skills → {}",
            result.linked_count(),
            result.agent_labels().join(", ")
        );
    }
    if !result.removed_stale.is_empty() {
        println!(
            "{} {} stale skill link(s)",
            if dry_run { "would remove" } else { "removed" },
            result.removed_stale.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_agents(cli: &Cli, _verbose: bool) -> anyhow::Result<ExitCode> {
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
        // #652: always show the full table, including before `setup` has run.
        println!("{:<14} {:<9} {:<7} PATH", "AGENT", "DETECTED", "LINKED");
        let mut any_linked = false;
        for h in &health {
            any_linked |= h.linked > 0;
            println!(
                "{:<14} {:<9} {:<7} {}",
                h.name,
                if h.detected { "yes" } else { "no" },
                format!("{}/{}", h.linked, h.total),
                h.dir.display()
            );
        }
        if !any_linked {
            println!();
            println!(
                "No skills linked yet. Run `confidant setup --agent <name>` or `confidant setup --agent auto`."
            );
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

/// Find `name` on `PATH`, returning the full path of the first match.
fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn cmd_tui(cli: &Cli, args: &[String]) -> anyhow::Result<ExitCode> {
    const HINT: &str =
        "confidant-tui not found on PATH; install it with: cargo install confidant-tui";
    let bin = match find_on_path("confidant-tui") {
        Some(path) => path,
        None => {
            if cli.json {
                print_json(&serde_json::json!({
                    "ok": false,
                    "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
                    "vault": vault_json(None),
                    "error": {"code": "E_TUI_NOT_FOUND", "message": HINT},
                }))?;
            } else {
                eprintln!("{HINT}");
            }
            return Ok(ExitCode::from(1));
        }
    };
    // #659: a CLI-only upgrade leaves `confidant-tui` on the old release,
    // and the TUI then speaks an older ADR-7 contract. Warn but keep
    // launching: mixing versions is sometimes intentional, and refusing
    // would break working installs.
    let cli_version = env!("CARGO_PKG_VERSION");
    let tui_version = tui_binary_version(&bin);
    let version_mismatch = tui_version
        .as_deref()
        .map(|v| v != cli_version)
        .unwrap_or(false);
    if cli.json {
        // Probe-only: the TUI owns stdout and would corrupt the ADR-7
        // envelope. Report what would launch and leave launching to a
        // human-mode invocation.
        print_json(&ok_envelope(
            cli.vault.as_deref(),
            serde_json::json!({
                "tui_version": tui_version,
                "version_mismatch": version_mismatch,
                "would_launch": true,
            }),
        ))?;
        return Ok(ExitCode::SUCCESS);
    }
    if version_mismatch {
        eprintln!(
            "warning: confidant-tui {} does not match confidant-cli {cli_version}; \
             the TUI may render stale or unknown state. Install the matching version with \
             `cargo install confidant-tui`",
            tui_version.as_deref().unwrap_or("unknown")
        );
    }
    // The child inherits this process's environment, so CONFIDANT_VAULT and
    // CONFIDANT_BIN pass through untouched. An explicit `--vault` on this
    // command is forwarded the same way the TUI already reads it.
    let mut cmd = std::process::Command::new(&bin);
    cmd.args(args);
    if let Some(vault) = cli.vault.as_deref() {
        cmd.env("CONFIDANT_VAULT", vault);
    }
    let status = cmd.status()?;
    Ok(match status.code() {
        Some(code) => ExitCode::from(code as u8),
        // Killed by a signal: no exit code to propagate.
        None => ExitCode::FAILURE,
    })
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
                    "empty pack name: use `help pack:<name>`, e.g. `help pack:personal@0.2`",
                )));
            }
            if !names.iter().any(|n| n == name) {
                let known = v.pack_registry().all().iter().any(|p| p.name() == name);
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
            let mut text = embedded::pack_skill_text_from_registry(v.pack_registry(), name)
                .ok_or_else(|| {
                    anyhow::Error::new(DomainError::internal(format!(
                        "pack `{name}` is enabled but ships no SKILL.md"
                    )))
                })?
                .to_owned();
            // PD10 (#445): external pack text shown to agents is labelled
            // with where it came from. Compiled packs are shipped with the
            // binary and print exactly as before.
            if let Some(label) = external_pack_label(v.pack_registry(), root, name) {
                text = format!("{label}\n{text}");
            }
            (vec![name.to_owned()], text)
        }
        None => {
            debug_assert_eq!(topic, "pack");
            // #523: build the combined text from the vault's registry, so a
            // loaded external pack contributes its vendored skill text and
            // the #445 external label instead of failing as "no SKILL.md".
            // A compiled-only vault resolves every pack to its embedded copy
            // and gets no label, so its output is byte for byte unchanged.
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            let text = embedded::combined_pack_skill(v.pack_registry(), &refs, |name| {
                external_pack_label(v.pack_registry(), root, name)
            })
            .ok_or_else(|| {
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

/// The PD10 (#445) first-line label for an external pack's skill text:
/// `[external pack: not shipped with confidant; text is from <source> at
/// <rev first 12>]`. `None` for a compiled pack (embedded, shipped with
/// the binary).
///
/// The decision is the pack's `origin` in the vault's registry (#535),
/// never whether embedded text with the same base name exists: an external
/// pack whose base name matches a built-in pack (`personal@0.9` next to the
/// built-in `personal@0.2`) is still external and must be labelled.
///
/// The lockfile is the authority for source and rev; a loaded external
/// pack always has a pin (the loader fails closed without one). A `dir`
/// source has no commit (PD3), so its empty rev prints `unknown`; a
/// missing pin prints `unknown` too rather than inventing a source.
fn external_pack_label(
    registry: &confidant_core::packs::PackRegistry,
    vault_root: &Path,
    name: &str,
) -> Option<String> {
    if !registry.is_external(name) {
        return None; // compiled: ships with confidant
    }
    let entry = read_lockfile(vault_root).ok().flatten().and_then(|lock| {
        name.split_once('@')
            .and_then(|(pack, version)| lock.find(pack, version).cloned())
    });
    let (source, rev) = entry
        .map(|e| (e.source, e.rev))
        .unwrap_or_else(|| ("unknown".to_owned(), String::new()));
    Some(external_pack_label_line(&source, &rev))
}

/// The label line for a lockfile `source`/`rev` pair (#445, #527). The
/// source is operator-supplied text from `confidant.lock`, which can be
/// hand-edited or synced from another machine, so it is sanitized before it
/// reaches agent-facing output: URL userinfo is stripped (a credential must
/// not leak) and control/format characters are escaped so the source cannot
/// hide or reorder the line. The rev is a pinned bare commit (40 lower-hex,
/// checked at lockfile parse) or empty, so it needs no escaping.
fn external_pack_label_line(source: &str, rev: &str) -> String {
    let rev = if rev.is_empty() {
        "unknown".to_owned()
    } else {
        rev.chars().take(12).collect()
    };
    format!(
        "[external pack: not shipped with confidant; text is from {} at {rev}]",
        sanitize_pack_source(source)
    )
}

/// Sanitize a lockfile `source` for the label (#527): drop URL userinfo,
/// then escape it with `pack add`'s `escape_line` rules (#499) so a control
/// or bidi character cannot survive into agent-facing text. A `dir` source
/// (no URL) has nothing to strip and passes through escaping unchanged.
fn sanitize_pack_source(source: &str) -> String {
    pack_fetch::escape_line(&strip_source_userinfo(source))
}

/// Strip the userinfo component (`user:token@`) from an `https://` source's
/// authority, keeping scheme, host and path (`https://user:token@host/p` ->
/// `https://host/p`). A source that is not `https://`, or whose authority
/// carries no `@`, is returned unchanged. Matches the authority rule the
/// lockfile reader uses when it refuses credentials (PD3).
fn strip_source_userinfo(source: &str) -> String {
    let Some(rest) = source.strip_prefix("https://") else {
        return source.to_owned();
    };
    let (authority, path) = match rest.find('/') {
        Some(end) => (&rest[..end], &rest[end..]),
        None => (rest, ""),
    };
    let Some((_, host)) = authority.rsplit_once('@') else {
        return source.to_owned();
    };
    format!("https://{host}{path}")
}

/// Redact credentials in a `--remote` URL before printing it or putting it
/// in JSON. `https://user:token@host/path` becomes `https://host/path`.
/// The real URL is still passed to `git remote add`.
fn display_remote_url(url: &str) -> String {
    let url = url.trim();
    for scheme in ["https://", "http://", "ssh://", "git://"] {
        let Some(rest) = url.strip_prefix(scheme) else {
            continue;
        };
        let (authority, path) = match rest.find('/') {
            Some(end) => (&rest[..end], &rest[end..]),
            None => (rest, ""),
        };
        if let Some((_, host)) = authority.rsplit_once('@') {
            return format!("{scheme}{host}{path}");
        }
        return url.to_owned();
    }
    url.to_owned()
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

/// True when `CONFIDANT_DEVICE_KEY` is set to a non-empty value. Headless
/// `--initiate` uses this as the new device's identity (#684) and does not
/// treat it as "already enrolled" in a keychain.
fn device_key_env_set() -> bool {
    std::env::var(confidant_crypt::keychain::DEVICE_KEY_ENV)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// Whether `--initiate` can persist a newly generated device key. The env
/// identity path does not need this: it never writes the keychain.
/// `CONFIDANT_KEYCHAIN=off` (tests) and an unreachable OS keychain both
/// mean "no": generate-and-store would fail, so fail closed with the
/// headless hint instead.
fn device_key_store_available() -> anyhow::Result<bool> {
    #[cfg(feature = "test-overrides")]
    if test_keychain_dir().is_some() {
        return Ok(true);
    }
    use confidant_crypt::keychain::{self, DeviceKeyState, KeychainSwitch};
    match keychain::keychain_switch() {
        Err(e) => Err(anyhow::Error::new(DomainError::invalid(format!(
            "cannot check device key: {e}"
        )))),
        Ok(KeychainSwitch::Off) => Ok(false),
        Ok(KeychainSwitch::On) => match keychain::device_key_state() {
            Ok(DeviceKeyState::KeychainUnreachable(_)) => Ok(false),
            Ok(_) => Ok(true),
            Err(e) => Err(anyhow::Error::new(DomainError::invalid(format!(
                "cannot check device key: {e}"
            )))),
        },
    }
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
            "no device key enrolled; run `confidant init` (new vault), clone this vault and `confidant keys device-add`, or `confidant recover` only if every enrolled device is lost".to_string(),
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
    use confidant_crypt::keychain::DEVICE_KEY_ENV;

    // Item 6: validate the label BEFORE any key-source probe or
    // provisioning. A bad label must not store a key and then error —
    // the retry would need --force to clean up the mess. (Shared
    // validator with --from-request: a hand-edited request can inject
    // controls into the commit message/manifest/stderr.)
    let label = validate_device_label(label.unwrap_or("device"))?;

    // #684: `CONFIDANT_DEVICE_KEY` is this new device's identity, the same
    // way `init` uses it (#650). Do not generate a different key, do not
    // write a keychain, and do not require --force: the env value is not
    // "already enrolled in a keychain". `--from-request` still refuses a
    // previously-seen pubkey, so re-using an already-enrolled identity
    // fails on the approve side.
    let using_env = device_key_env_set();
    if !using_env {
        // Probe persistence before enrollment: an unreachable keychain
        // makes `device_key()` error, and generate-and-store would fail
        // the same way. Fail closed with the headless hint instead.
        if !device_key_store_available()? {
            return Err(anyhow::Error::new(
                DomainError::invalid(format!(
                    "cannot generate a device key: the OS keychain is unavailable and \
                     {DEVICE_KEY_ENV} is not set"
                ))
                .with_fix(format!(
                    "Generate this device's identity with `age-keygen`, export only the \
                     AGE-SECRET-KEY-1… line as {DEVICE_KEY_ENV}, then retry \
                     `confidant keys device-add --initiate`. Keys never live in files."
                )),
            ));
        }
        // Refuse to overwrite an already-enrolled keychain entry (same
        // check as recover's B13). --force overrides the refusal, but not
        // the confirmation below.
        let already_enrolled = device_key_enrolled()?;
        if already_enrolled && !force {
            return Err(anyhow::Error::new(DomainError::invalid(
                "a device key is already enrolled; refusing to overwrite (use --force to replace it)",
            )));
        }
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
    }

    let (_bech32, recipient) = provision_device_key()?;
    let fingerprint = confidant_crypt::keychain::pubkey_fingerprint(&recipient);
    let key_id = device_key_id(&recipient);
    let key_source = if using_env { "env" } else { "keychain" };

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
    if using_env {
        eprintln!("using {DEVICE_KEY_ENV} as this device's identity (not stored in a keychain)");
    }

    if cli.json {
        print_json(&serde_json::json!({
            "ok": true,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": null,
            "fingerprint": fingerprint,
            "label": label,
            "key_id": key_id,
            "key_source": key_source,
            "pubkey": recipient,
            "request": document,
        }))?;
    } else if let Some(path) = output {
        // 0644 explicit: the request carries only the public key + label,
        // safe to transfer. Deliberate, not a default.
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
/// Written to git-ignored `.confidant/shred.marker` after `check` passes
/// (it stays there across the swap — the swap only renames `keys/` and the
/// stage). Presence means "roll forward, never back": the swap and the
/// out-of-tree promotions (anchor re-pin, device key) must complete before
/// any other key operation runs.
///
/// The marker carries the new anchor material and the new device private key
/// so `repair_keys_staging` can finish the promotions after a crash. It is
/// written with 0600 permissions, fsynced before the swap, lives outside
/// git-tracked `keys/`, and is removed before the shred commit, so the
/// private key is never committed. Rolling back after a crash would restore
/// the destroyed keys and undo the shred — hence roll-forward.
const SHRED_MARKER_FILE: &str = "shred.marker";
const SHRED_MARKER_VERSION: u32 = 1;

/// Path of the shred marker: git-ignored `.confidant/` (never inside
/// git-tracked `keys/`). Repair keys off its contents to decide whether
/// the swap happened yet (via `keys.old`).
fn shred_marker_path(root: &Path) -> PathBuf {
    root.join(".confidant").join(SHRED_MARKER_FILE)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ShredStageMarker {
    version: u32,
    /// New recovery verifying key (hex) for the anchor re-pin.
    recovery_verifying_key_hex: String,
    /// New recovery age recipient for the anchor re-pin.
    recovery_age_recipient: String,
    /// Fresh device private key (bech32) to promote to the keychain.
    /// Sensitive: 0600 file, git-ignored, removed before commit.
    /// Zeroized on drop (see `Drop` impl below).
    device_key_bech32: String,
}

impl Drop for ShredStageMarker {
    fn drop(&mut self) {
        // The device private key must not linger in memory.
        use zeroize::Zeroize;
        self.device_key_bech32.zeroize();
    }
}

/// Write the shred marker with 0600 permissions (it holds a private key),
/// fsynced for crash durability: a torn write would block every key op
/// until hand-fixed. Uses write-to-temp + rename + fsync so the marker
/// is never observed partial.
fn write_shred_marker(path: &Path, marker: &ShredStageMarker) -> anyhow::Result<()> {
    let text = toml::to_string(marker).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot serialize shred marker: {e}"
        )))
    })?;
    let dir = path.parent().ok_or_else(|| {
        anyhow::Error::new(DomainError::invalid(format!(
            "shred marker path has no parent: {}",
            path.display()
        )))
    })?;
    std::fs::create_dir_all(dir).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot create shred marker dir at {}: {e}",
            dir.display()
        )))
    })?;
    // Write to a temp file in the same directory, fsync, then rename.
    let tmp = dir.join(".shred.marker.tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        let mut f = opts.open(&tmp).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot write shred marker at {}: {e}",
                tmp.display()
            )))
        })?;
        f.write_all(text.as_bytes()).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot write shred marker: {e}"
            )))
        })?;
        // Fsync the file before the rename so the content is durable.
        f.sync_all().map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot fsync shred marker: {e}"
            )))
        })?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot install shred marker at {}: {e}",
            path.display()
        )))
    })?;
    // Fsync the directory so the rename itself is durable (best-effort
    // on non-unix; the file fsync above is the critical part).
    #[cfg(unix)]
    {
        if let Ok(dir_f) = std::fs::File::open(dir) {
            let _ = dir_f.sync_all();
        }
    }
    Ok(())
}

fn read_shred_marker(path: &Path) -> anyhow::Result<ShredStageMarker> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read shred marker at {}: {e}",
            path.display()
        )))
    })?;
    // NOTE: the toml parse error is deliberately NOT included: it can
    // quote the offending line, which may be the device private key.
    let marker: ShredStageMarker = toml::from_str(&text).map_err(|_| {
        anyhow::Error::new(DomainError::invalid(
            "bad shred marker: refusing to parse (fail closed; inspect .confidant/shred.marker by hand)",
        ))
    })?;
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
    if shred_marker_path(root).exists() {
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
/// The marker lives at git-ignored `.confidant/shred.marker` (never inside
/// git-tracked `keys/`). Every step is idempotent, so a second crash
/// mid-repair is safe to retry.
///
/// Crash-point behavior (Frank's decision on #290), inferred from `keys.old`:
/// - No `keys.old`, stage present: pre-swap crash. Do the swap now.
/// - `keys.old` present, `keys/` missing: mid-swap crash. Complete the swap.
/// - `keys.old` present, `keys/` present: post-swap crash. Finish the
///   re-pin and device-key promotion from the marker's material.
///   Then clear the marker. Any other combination fails closed.
fn repair_shred_marker(root: &Path, config_dir: &Path) -> anyhow::Result<()> {
    use confidant_crypt::anchor;
    let keys_dir = root.join("keys");
    let old = keys_old_dir(root);
    let stage = keys_stage_dir(root);
    let staged_tracker = keys_staged_tracker_path(config_dir);
    let real_tracker = confidant_crypt::manifest::seq_tracker_path(config_dir);
    let marker_path = shred_marker_path(root);

    // Fail closed on a corrupt marker: never print key material (the toml
    // error text is already stripped by read_shred_marker).
    let marker = read_shred_marker(&marker_path)?;

    // Ensure the swap is complete, inferring the crash point.
    if !old.exists() {
        // No backup: the swap never started (pre-swap crash). The stage
        // holds the new tree; keys/ holds the old tree.
        if !stage.exists() || !keys_dir.exists() {
            return Err(anyhow::Error::new(DomainError::invalid(
                "shred marker exists but the swap never started and the stage or keys/ is missing; refusing to guess — inspect .confidant/ and restore by hand",
            )));
        }
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
    } else if !keys_dir.exists() {
        // Mid-swap: keys/ -> keys.old happened, stage -> keys/ did not.
        if !stage.exists() {
            return Err(anyhow::Error::new(DomainError::invalid(
                "shred marker exists, keys/ is missing, but the stage is gone too; refusing to guess — inspect .confidant/ and restore by hand",
            )));
        }
        std::fs::rename(&stage, &keys_dir).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot complete interrupted keys/ swap during shred repair: {e}"
            )))
        })?;
    }
    // keys/ now holds the new tree. The old tree is shred's destroy
    // target; remove it best-effort.
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

    // All promotions done: clear the marker.
    std::fs::remove_file(&marker_path).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot clear shred marker at {}: {e}",
            marker_path.display()
        )))
    })?;
    // Tell the operator what to commit: the working-tree deletions from
    // the shred were left uncommitted by the crash. Also remind them the
    // phrase was already shown: a Ctrl-C at the phrase prompt lands here
    // via the next key op, and the shred is complete either way.
    eprintln!(
        "shred repair complete: a shred you started was completed; use the recovery phrase it showed. Review and commit the working-tree changes (deleted edges, re-encrypted interactions) in a separate commit"
    );
    Ok(())
}

/// Run a `keys shred` through the staged path with roll-forward (#220,
/// Frank's decision on #290). Operation order:
/// 1. Stage `keys/` and mutate the copy (re-wrap remaining clients to
///    fresh recipients, rotate recovery wrapping, re-sign operator cert
///    into the stage).
/// 2. Reload the vault and run `check` on the post-mutation state.
/// 3. Record a durable marker at `.confidant/shred.marker` (complete +
///    checked, with the new anchor material and the new device key).
/// 4. Atomically swap the staged `keys/` into place, then disarm the
///    working-tree guard: post-swap failures roll forward, never back.
/// 5. Re-pin the trust anchor and promote the device key from the marker.
/// 6. Remove the marker.
///
/// Why roll forward: shred exists to destroy the old keys; rolling back
/// after a crash would restore them and undo the shred. The marker makes
/// every crash point recoverable via `repair_keys_staging`.
///
/// The recovery phrase is displayed BEFORE the swap (step 3.5): once the
/// swap lands, the tree is wrapped to that phrase, so a crash before
/// display would lose it. If the swap then fails before anything moves
/// (the first rename), the error says to ignore the shown phrase — the
/// old phrase is still current. Once `keys/` has moved, the shown phrase
/// is the new recovery phrase, and the error says so.
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
    guard: &mut ShredTreeGuard,
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

    // Step 2: check before the swap. The caller reloads the vault after
    // the working-tree changes (edge deletions, interaction strips) and
    // passes it in, so the check sees the post-shred record state. (See
    // the #209 note in staged_keys_mutation: check reads keys/ only for
    // crypto-mode detection.)
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
    // Lives at git-ignored .confidant/shred.marker (never in keys/).
    let hex = |k: &[u8]| k.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let marker = ShredStageMarker {
        version: SHRED_MARKER_VERSION,
        recovery_verifying_key_hex: hex(new_recovery.verifying_key().as_bytes()),
        recovery_age_recipient: new_recovery.age_identity().to_recipient_string(),
        device_key_bech32: fresh_device_key.as_str().to_owned(),
    };
    let marker_path = shred_marker_path(root);
    if let Err(e) = write_shred_marker(&marker_path, &marker) {
        remove_path_best_effort(&stage);
        remove_path_best_effort(&staged_tracker);
        return Err(e);
    }

    // Step 3.5: show the phrase BEFORE the swap. Once the swap lands the
    // tree is wrapped to this phrase; a crash before display would lose it.
    // If the first rename fails (before anything moved), the error tells
    // the operator to ignore the shown phrase — the old phrase is still
    // current. After it succeeds, the shown phrase is the new recovery
    // phrase.
    let phrase = outcome.recovery_phrase_for_display();
    if let Err(e) = display_phrase_once(no_input, &phrase) {
        remove_path_best_effort(&stage);
        remove_path_best_effort(&staged_tracker);
        remove_path_best_effort(&marker_path);
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "cannot display recovery phrase: {e}"
        ))));
    }

    // Step 4: swap (keys/ -> keys.old, stage -> keys/).
    // NOTE: the recovery phrase was already shown at step 3.5. If the
    // first rename fails (before anything moved), the shown phrase
    // matches nothing — the old phrase is still current. Once keys/
    // has moved, the shown phrase is the new recovery phrase.
    if keys_dir.exists() {
        if let Err(e) = std::fs::rename(&keys_dir, &old) {
            remove_path_best_effort(&stage);
            remove_path_best_effort(&staged_tracker);
            remove_path_best_effort(&marker_path);
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "keys/ swap failed before anything moved ({e}); keys/ was not modified — ignore the phrase shown above; your old phrase is still current"
            ))));
        }
        // Point of no return: keys/ has moved to keys.old and the marker
        // exists, so repair will roll forward from here (finish the swap,
        // re-pin, promote, clear). Disarm the working-tree guard NOW,
        // before stage -> keys/ — a failure from this point on must NOT
        // restore the deleted edges / stripped interactions (the privacy
        // leak #320 closed, and the roll-back-after-roll-forward mix #290
        // rules out).
        guard.disarm();
    } else {
        // Safety net: disarm() is idempotent. If keys/ did not exist, the
        // point-of-no-return disarm above was skipped — but the swap is
        // about to land, so disarm NOW, before stage -> keys/. If the
        // rename fails, the error branch below returns early, so a disarm
        // after it would never run. Unreachable today (shred stages from
        // keys/), but safe even if that ever changes.
        guard.disarm();
    }
    if let Err(e) = std::fs::rename(&stage, &keys_dir) {
        let _ = repair_keys_staging(root, config_dir);
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "keys/ swap failed mid-swap ({e}); shred is finishing, re-run to complete; the phrase shown above is your new recovery phrase"
        ))));
    }

    // Promote the staged seq tracker (same-directory rename, atomic).
    // Post-swap: on failure, repair rolls forward; report re-run.
    if staged_tracker.exists() {
        if let Err(e) = std::fs::rename(&staged_tracker, &real_tracker) {
            let _ = repair_keys_staging(root, config_dir);
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "seq tracker promotion failed ({e}); shred is finishing, re-run to complete"
            ))));
        }
    }

    // Step 5: re-pin the anchor and promote the device key from the marker.
    // Both are idempotent, so a crash here is safe to retry via repair.
    // Post-swap: on failure, repair rolls forward; report re-run.
    if let Err(e) = anchor::replace(
        config_dir,
        root,
        &anchor.operator,
        &new_recovery.verifying_key(),
        &new_recovery.age_identity().to_recipient_string(),
    ) {
        let _ = repair_keys_staging(root, config_dir);
        return Err(anyhow::Error::new(e).context("shred is finishing, re-run to complete"));
    }
    if let Err(e) = store_rotated_device_key(fresh_device_key) {
        let _ = repair_keys_staging(root, config_dir);
        return Err(e.context("shred is finishing, re-run to complete"));
    }

    // Step 6: remove the marker. Post-swap: on failure, repair clears it;
    // report re-run.
    if marker_path.exists() {
        if let Err(e) = std::fs::remove_file(&marker_path) {
            let _ = repair_keys_staging(root, config_dir);
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "cannot clear shred marker at {} ({e}); shred is finishing, re-run to complete",
                marker_path.display()
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
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?
        .write_all(content.as_bytes())?;
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

    /// Whether the guard is still armed. After the keys/ swap lands,
    /// `staged_shred_mutation` disarms it: post-swap failures roll forward
    /// via the shred marker, never back via restore.
    fn is_armed(&self) -> bool {
        self.armed
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
        let client =
            confidant_crypt::envelope::key_id_client(&env.key_id).map_err(|_| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot determine every interaction naming {client_id}: skipped envelope {path} has an undeterminable client"
                )))
            })?;
        if live_clients.contains(client.as_str()) {
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
    //
    // #339: reload the vault AFTER the working-tree mutations above so
    // the pre-swap check sees the post-shred record state (deleted edges,
    // stripped interactions), as the old reload-and-check did.
    let vault = load_vault(root)?;
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
        &mut guard,
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            // If the swap landed, staged_shred_mutation disarmed the guard:
            // the shred is committed to rolling forward via the marker.
            // Do NOT restore the working tree (that would be the privacy
            // leak #320 closed); repair already ran inside.
            if guard.is_armed() {
                return Err(shred_restore(&mut guard, e));
            }
            return Err(e);
        }
    };
    // The staged swap landed and the out-of-tree promotions completed
    // (or the guard would still be armed): the working-tree mutations
    // above are now intentional. The guard was disarmed on swap; this
    // is a no-op safeguard.
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
        println!(
            "next: confirm the copy you just saved with `confidant keys verify-recovery --phrase-file <path>`"
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Print the structured failure for `keys verify-recovery`.
///
/// The error envelope is the ordinary ADR-7 shape (`ok:false`, stable
/// `code`); `outcome` and `checks` are additive so `--json` still reports
/// which checks passed. Never include words, positions, derived keys, or
/// recipient fingerprints.
fn verify_recovery_failure(
    cli: &Cli,
    root: &Path,
    outcome: &str,
    checks: Option<Value>,
    err: DomainError,
) -> anyhow::Result<ExitCode> {
    let code = err.exit_code() as u8;
    if cli.json {
        let mut body = serde_json::json!({
            "ok": false,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": vault_json(Some(root)),
            "outcome": outcome,
            "error": err.to_json(),
        });
        if let Some(checks) = checks {
            body["checks"] = checks;
        }
        print_json(&body)?;
    } else {
        print_error(false, None, &err)?;
    }
    Ok(ExitCode::from(code))
}

/// `confidant keys verify-recovery` (#663): check a saved phrase without
/// changing anything.
///
/// Match requires all of:
/// 1. when `~/.config/confidant/trust.toml` exists, both its Ed25519
///    `recovery_pubkey` and X25519 `recovery_age_recipient` match the
///    phrase (and a disagreement never falls back to `keys/`);
/// 2. when `keys/operator.toml` exists, its certificate verifies against
///    the phrase-derived recovery pubkey;
/// 3. the phrase identity trial-unwraps the current-epoch
///    `wrapped/recovery.age` for every initialized client except the
///    device-only `vault:lookup` key.
fn cmd_keys_verify_recovery(
    cli: &Cli,
    root: &Path,
    phrase_file: Option<&Path>,
) -> anyhow::Result<ExitCode> {
    use confidant_crypt::{
        anchor,
        lifecycle::KeyStore,
        manifest::{RECOVERY_KEY_ID, VAULT_CLIENT_ID},
        recovery::Recovery,
    };

    // B7: stdin or --phrase-file only, never argv; zeroizing buffers.
    let phrase = read_phrase(phrase_file)?;
    let recovery = match Recovery::from_phrase(&phrase) {
        Ok(recovery) => recovery,
        Err(e) => {
            drop(phrase);
            // The position hint is stderr-only. The JSON error message is
            // deliberately generic so no word position reaches --json.
            eprintln!("hint: {e}");
            return verify_recovery_failure(
                cli,
                root,
                "malformed",
                None,
                DomainError::new(
                    ErrorKind::RecoveryMalformed,
                    "recovery phrase is malformed (expected 24 BIP39 words)",
                )
                .with_fix("Check the saved copy and re-enter the 24 words from it"),
            );
        }
    };
    drop(phrase);

    let vault = load_vault(root)?;
    let config_dir = confidant_config_dir().ok_or_else(|| {
        anyhow::Error::new(DomainError::invalid(
            "HOME is not set; cannot locate the operator config dir",
        ))
    })?;
    let keys_dir = root.join("keys");
    let trust_path = config_dir.join(anchor::TRUST_FILE);
    let trust_exists = trust_path.is_file();

    let derived_pubkey = recovery.verifying_key();
    let derived_recipient = recovery.age_identity().to_recipient_string();

    let mut anchor_pin: Option<anchor::Anchor> = None;
    let mut anchor_state = "absent";
    let mut recipient_state = "absent";
    if trust_exists {
        match anchor::load(&config_dir, root) {
            Ok((loaded, _warnings)) => {
                let (pubkey_matches, recipient_matches) =
                    recovery_matches_anchor(&loaded, &recovery);
                anchor_state = if pubkey_matches { "pass" } else { "fail" };
                recipient_state = if recipient_matches { "pass" } else { "fail" };
                anchor_pin = Some(loaded);
            }
            Err(e) => {
                // The anchor exists but cannot be used: fail closed. Never
                // fall back to the keys/ tree in this case.
                let checks = serde_json::json!({
                    "anchor": "fail",
                    "recipient": "fail",
                    "cert": "absent",
                    "unwrap": {},
                });
                let err = DomainError::new(
                    ErrorKind::RecoveryMismatch,
                    format!(
                        "trust anchor exists at {} but cannot be used: {e}",
                        trust_path.display()
                    ),
                )
                .with_fix(
                    "Restore a valid trust.toml from backup; verify-recovery never falls back \
                     to the vault's keys/ tree when an anchor exists",
                );
                return verify_recovery_failure(cli, root, "mismatch", Some(checks), err);
            }
        }
    }

    let store = KeyStore::with_config_dir(keys_dir.clone(), &vault.config.vault_id, &config_dir)
        .map_err(anyhow::Error::new)?;

    // A retired phrase is only knowable against a current anchor: the
    // append-only history also records the current recipient, so membership
    // alone would flag a healthy phrase after any rotation.
    let retired = trust_exists
        && recipient_state == "fail"
        && store.recovery_history().contains(&derived_recipient);

    // The operator certificate is what a fresh-device `recover` relies on.
    let mut cert_state = "absent";
    let mut cert_error: Option<String> = None;
    if keys_dir.join(anchor::OPERATOR_CERT_FILE).is_file() {
        match anchor::verify_operator_cert(&keys_dir, &vault.config.vault_id, &derived_pubkey) {
            Ok(operator) => {
                cert_state = "pass";
                if anchor_pin.is_none() {
                    // Fresh device: rebuild the anchor from the verified
                    // certificate, exactly as `recover` does.
                    anchor_pin = Some(anchor::Anchor {
                        operator,
                        recovery: derived_pubkey,
                        recovery_age: derived_recipient.clone(),
                        source: trust_path.clone(),
                    });
                }
            }
            Err(e) => {
                cert_state = "fail";
                cert_error = Some(e.to_string());
            }
        }
    }

    let identity = recovery.age_identity().to_age_identity().map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!("bad recovery identity: {e}")))
    })?;

    let mut clients: Vec<String> = store
        .manifest_clients()
        .into_iter()
        .filter(|c| c != VAULT_CLIENT_ID)
        .collect();
    clients.sort();

    let mut unwrap = serde_json::Map::new();
    let mut unwrap_failed = false;
    let mut unwrap_error: Option<(String, String)> = None;
    if let Some(anchor) = &anchor_pin {
        for client_id in &clients {
            let result = (|| -> Result<(), String> {
                let epoch = store.current_epoch(client_id).map_err(|e| e.to_string())?;
                // The trial key is a DataKey (zeroizing). Drop it right
                // here: it is never returned, logged, or cached.
                let key = store
                    .trial_unwrap_data_key(client_id, RECOVERY_KEY_ID, epoch, &identity, anchor)
                    .map_err(|e| e.to_string())?;
                drop(key);
                Ok(())
            })();
            match result {
                Ok(()) => {
                    unwrap.insert(client_id.clone(), Value::String("pass".to_owned()));
                }
                Err(e) => {
                    unwrap_failed = true;
                    unwrap_error.get_or_insert_with(|| (client_id.clone(), e));
                    unwrap.insert(client_id.clone(), Value::String("fail".to_owned()));
                }
            }
        }
    }

    let checks = serde_json::json!({
        "anchor": anchor_state,
        "recipient": recipient_state,
        "cert": cert_state,
        "unwrap": Value::Object(unwrap),
    });

    let outcome = if retired {
        "retired"
    } else if anchor_state == "fail" || recipient_state == "fail" || cert_state == "fail" {
        "mismatch"
    } else if unwrap_failed {
        "unwrap_failed"
    } else if anchor_pin.is_none() {
        // Nothing to verify against: no anchor, no operator certificate.
        "mismatch"
    } else {
        "match"
    };

    if outcome != "match" {
        let err = match outcome {
            "retired" => DomainError::new(
                ErrorKind::RecoveryRetired,
                "this is a retired recovery phrase (a later `recover` or `keys shred` replaced it)",
            )
            .with_fix(
                "Destroy that copy: it still opens the vault's history, but it cannot recover \
                 the current device. Use the current phrase.",
            ),
            "unwrap_failed" => {
                let (client_id, detail) = unwrap_error
                    .unwrap_or_else(|| ("unknown".to_owned(), "unwrap failed".to_owned()));
                DomainError::new(
                    ErrorKind::RecoveryUnwrap,
                    format!(
                        "the phrase matches the pinned keys but cannot unwrap the current data \
                         key for {client_id}: {detail}"
                    ),
                )
                .with_fix(
                    "Re-check the saved copy; if trust.toml was restored from an old backup, \
                     restore the current one",
                )
            }
            _ => {
                if anchor_state == "fail" {
                    DomainError::new(
                        ErrorKind::RecoveryMismatch,
                        "recovery phrase does not match this vault's trust anchor",
                    )
                    .with_fix("Use the current phrase; do not run `recover` with this copy")
                } else if recipient_state == "fail" {
                    DomainError::new(
                        ErrorKind::RecoveryMismatch,
                        "recovery phrase does not match this vault's trust anchor (recovery recipient)",
                    )
                    .with_fix("Use the current phrase; do not run `recover` with this copy")
                } else if cert_state == "fail" {
                    DomainError::new(
                        ErrorKind::RecoveryMismatch,
                        format!(
                            "operator certificate does not verify against this recovery phrase: {}",
                            cert_error.as_deref().unwrap_or("signature check failed")
                        ),
                    )
                    .with_fix(
                        "Use the current phrase; a fresh-device `recover` with this copy would \
                         fail the same way",
                    )
                } else {
                    DomainError::new(
                        ErrorKind::RecoveryMismatch,
                        "cannot verify this phrase: the vault has neither a trust anchor nor an \
                         operator certificate",
                    )
                    .with_fix(
                        "Restore ~/.config/confidant/trust.toml from a backup; pre-certificate \
                         vaults cannot verify a phrase without one",
                    )
                }
            }
        };
        return verify_recovery_failure(cli, root, outcome, Some(checks), err);
    }

    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "outcome": "match",
                "checks": checks,
                "clients_checked": clients.len(),
            }),
        ))?;
    } else {
        println!("recovery phrase matches this vault");
        match anchor_state {
            "pass" => println!("  trust anchor  both recovery halves match"),
            _ => println!("  trust anchor  not on this device (verified from keys/)"),
        }
        match cert_state {
            "pass" => println!("  certificate   verified against the phrase"),
            _ => println!("  certificate   not present in keys/"),
        }
        println!(
            "  data keys     {} client(s) opened with the phrase",
            clients.len()
        );
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
    use super::{
        confirm_yn, detect_install_method, git_version_check_from, offerable_update,
        parse_git_remotes, parse_git_version, parse_tui_version, reject_unsupported_prefix,
        InstallMethod, MIN_GIT_VERSION,
    };
    use std::path::Path;

    /// #659: the TUI `--version` probe accepts a prefixed, `v`-prefixed,
    /// bare, and suffix-bearing version, and refuses garbage.
    #[test]
    fn tui_version_parser_accepts_real_shapes() {
        assert_eq!(
            parse_tui_version("confidant-tui 0.6.0"),
            Some("0.6.0".into())
        );
        assert_eq!(
            parse_tui_version("confidant-tui v0.6.1\n"),
            Some("0.6.1".into())
        );
        assert_eq!(parse_tui_version("0.6.0"), Some("0.6.0".into()));
        assert_eq!(
            parse_tui_version("confidant-tui 0.7.0 (abc123)"),
            Some("0.7.0".into())
        );
        // A numeric non-version token must not abort the scan.
        assert_eq!(
            parse_tui_version("confidant-tui build 1 0.6.2"),
            Some("0.6.2".into())
        );
        assert_eq!(parse_tui_version("confidant-tui unknown"), None);
        assert_eq!(parse_tui_version(""), None);
    }

    /// #660: remote URLs may carry credentials, so only names survive.
    #[test]
    fn git_remote_parser_keeps_names_only() {
        let out = "\
origin\thttps://user:token@host.example/org/repo.git (fetch)
origin\thttps://user:token@host.example/org/repo.git (push)
backup\tgit@host.example:org/repo.git (fetch)
backup\tgit@host.example:org/repo.git (push)
";
        assert_eq!(parse_git_remotes(out), vec!["origin", "backup"]);
        assert!(parse_git_remotes("").is_empty());
    }

    /// #653(d): `findmnt` output is a device path with an optional btrfs
    /// subvolume suffix; non-block sources cannot be traced through
    /// `lsblk` and must report "unknown", never a warning.
    #[cfg(target_os = "linux")]
    #[test]
    fn findmnt_source_parser() {
        use super::parse_findmnt_source;
        assert_eq!(
            parse_findmnt_source("/dev/nvme0n1p2\n"),
            Some("/dev/nvme0n1p2".to_owned())
        );
        assert_eq!(
            parse_findmnt_source("/dev/sda2[/@root]\n"),
            Some("/dev/sda2".to_owned())
        );
        assert_eq!(parse_findmnt_source("overlay\n"), None);
        assert_eq!(parse_findmnt_source("UUID=abcd-1234\n"), None);
        assert_eq!(parse_findmnt_source("\n"), None);
    }

    /// #653(d): only a `crypt` ancestor means the root disk is encrypted.
    #[cfg(target_os = "linux")]
    #[test]
    fn lsblk_types_detect_crypt() {
        use super::lsblk_types_include_crypt;
        assert!(lsblk_types_include_crypt("lvm\ncrypt\npart\ndisk\n"));
        assert!(lsblk_types_include_crypt("crypt\n"));
        assert!(!lsblk_types_include_crypt("lvm\npart\ndisk\n"));
        assert!(!lsblk_types_include_crypt(""));
    }

    /// #542: a `confidant <command>` hint in `reject_unsupported_prefix`
    /// must name a subcommand clap actually has. The old package hint said
    /// `confidant balance`, which does not exist, so following it produced
    /// a clap error instead of a fix.
    #[test]
    fn prefix_hint_names_an_existing_subcommand() {
        use clap::CommandFactory as _;

        let pkg = confidant_core::id::RecordId::parse("pkg-01J9Z3K4QF0000000000000000")
            .expect("fake package id");
        let err = reject_unsupported_prefix(&pkg).expect_err("packages are refused");

        let domain = confidant_core::error::DomainError::of(&err).expect("usage error");
        assert_eq!(domain.kind(), confidant_core::error::ErrorKind::Usage);
        assert_eq!(domain.exit_code(), 2, "ADR-7: usage errors exit 2");

        // Extract the backticked hint and its first two words:
        // `confidant <subcommand> …`.
        let hint = domain
            .message()
            .split('`')
            .nth(1)
            .expect("the message carries a backticked command hint");
        let mut words = hint.split_whitespace();
        assert_eq!(words.next(), Some("confidant"), "hint: {hint}");
        let subcommand = words.next().expect("the hint names a subcommand");

        let known: Vec<String> = crate::Cli::command()
            .get_subcommands()
            .map(|c| c.get_name().to_owned())
            .collect();
        assert!(
            known.iter().any(|name| name == subcommand),
            "hint `{hint}` names `{subcommand}`, which is not a subcommand; known: {known:?}"
        );
        assert!(
            hint.contains("<person>"),
            "the hint should say what to pass: {hint}"
        );
    }

    #[test]
    fn install_method_detection_from_exe_path() {
        // `cargo install` (and the cargo-dist shell installer, which
        // targets CARGO_HOME) lands in `<cargo-home>/bin`.
        assert_eq!(
            detect_install_method(Path::new("/home/ada/.cargo/bin/confidant")),
            InstallMethod::CargoInstall
        );
        // Windows separators stay detectable on every platform.
        assert_eq!(
            detect_install_method(Path::new("C:\\Users\\ada\\.cargo\\bin\\confidant.exe")),
            InstallMethod::CargoInstall
        );
        // Homebrew and anything else: unknown, so `update` falls back to
        // the generic wording and offers nothing to run.
        assert_eq!(
            detect_install_method(Path::new("/opt/homebrew/bin/confidant")),
            InstallMethod::Unknown
        );
        assert_eq!(
            detect_install_method(Path::new("/usr/local/bin/confidant")),
            InstallMethod::Unknown
        );
        assert_eq!(
            detect_install_method(Path::new("confidant")),
            InstallMethod::Unknown
        );
    }

    #[test]
    fn install_method_commands() {
        let cargo = InstallMethod::CargoInstall;
        assert_eq!(cargo.as_str(), "cargo-install");
        assert_eq!(cargo.update_command(), Some("cargo install confidant-cli"));
        let (program, args) = cargo.run_spec().unwrap();
        assert_eq!(program, "cargo");
        assert_eq!(args, &["install", "confidant-cli"]);

        let unknown = InstallMethod::Unknown;
        assert_eq!(unknown.as_str(), "unknown");
        assert_eq!(unknown.update_command(), None);
        assert_eq!(unknown.run_spec(), None);
    }

    #[test]
    fn offerable_update_needs_known_method_and_safe_replacement() {
        assert!(offerable_update(InstallMethod::CargoInstall, true));
        // Unsafe replacement: print only.
        assert!(!offerable_update(InstallMethod::CargoInstall, false));
        // Unknown method: nothing to run.
        assert!(!offerable_update(InstallMethod::Unknown, true));
        assert!(!offerable_update(InstallMethod::Unknown, false));
    }

    #[test]
    fn confirm_yn_never_prompts_when_non_interactive() {
        // --no-input and --json short-circuit to false without touching
        // stdin, on any terminal.
        assert!(!confirm_yn("run it?", true, false).unwrap());
        assert!(!confirm_yn("run it?", false, true).unwrap());
        assert!(!confirm_yn("run it?", true, true).unwrap());
    }

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
    /// Returns (tmp, root, config_dir, keychain_dir, env_guard) — the
    /// guard restores `CONFIDANT_TEST_KEYCHAIN_DIR` on drop.
    ///
    /// NOTE: the marker tests manipulate the process-global
    /// `CONFIDANT_TEST_KEYCHAIN_DIR`; they take `KEYCHAIN_ENV_LOCK` to
    /// serialize against each other.
    static KEYCHAIN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Restores `CONFIDANT_TEST_KEYCHAIN_DIR` to its previous value (or
    /// unsets it) on drop, so marker tests don't leak the process-global
    /// env var into other tests running in the same binary.
    struct KeychainEnvGuard {
        old: Option<std::ffi::OsString>,
    }

    impl KeychainEnvGuard {
        fn set_dir(dir: &std::path::Path) -> Self {
            let old = std::env::var_os("CONFIDANT_TEST_KEYCHAIN_DIR");
            std::env::set_var("CONFIDANT_TEST_KEYCHAIN_DIR", dir);
            Self { old }
        }
    }

    impl Drop for KeychainEnvGuard {
        fn drop(&mut self) {
            match self.old.take() {
                Some(v) => std::env::set_var("CONFIDANT_TEST_KEYCHAIN_DIR", v),
                None => std::env::remove_var("CONFIDANT_TEST_KEYCHAIN_DIR"),
            }
        }
    }

    fn shred_marker_fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        KeychainEnvGuard,
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
        // Point the test keychain at our dir (restored on drop by the guard).
        let env_guard = KeychainEnvGuard::set_dir(&keychain_dir);
        (tmp, root, config_dir, keychain_dir, env_guard)
    }

    fn write_test_marker(path: &std::path::Path, recovery_vk_hex: &str, device_key: &str) {
        use super::{write_shred_marker, ShredStageMarker, SHRED_MARKER_VERSION};
        let marker = ShredStageMarker {
            version: SHRED_MARKER_VERSION,
            recovery_verifying_key_hex: recovery_vk_hex.to_owned(),
            recovery_age_recipient: "age1ql5z7k2dpq6x9x8v4n3m2l1k0j9h8g7f6d5s4a3".to_string(),
            device_key_bech32: device_key.to_owned(),
        };
        write_shred_marker(path, &marker).unwrap();
    }

    #[test]
    fn shred_marker_pre_swap_rolls_forward() {
        let _lock = KEYCHAIN_ENV_LOCK.lock().unwrap();
        // #220: crash after check, before swap (marker in .confidant/).
        // Repair must finish the swap, re-pin the anchor, promote the
        // device key, and clear the marker — never discard the stage.
        use super::{keys_stage_dir, repair_keys_staging, shred_marker_path};
        let (_tmp, root, config_dir, _keychain, _env_guard) = shred_marker_fixture();
        let stage = keys_stage_dir(&root);
        std::fs::create_dir_all(&stage).unwrap();
        // New tree in the stage (sentinel).
        std::fs::write(stage.join("NEW_TREE"), b"new").unwrap();
        // Marker in .confidant/ with new anchor material and device key.
        let new_recovery_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let new_vk_hex: String = new_recovery_sk
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        write_test_marker(&shred_marker_path(&root), &new_vk_hex, "NEW_DEVICE_KEY");
        let old_anchor = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();

        repair_keys_staging(&root, &config_dir).unwrap();

        // Swap completed: keys/ holds the new tree, old tree gone.
        assert!(root.join("keys/NEW_TREE").is_file());
        assert!(!root.join("keys/OLD_TREE").exists());
        assert!(!root.join(".confidant/keys.old").exists());
        assert!(!stage.exists());
        // Marker cleared from .confidant/.
        assert!(!shred_marker_path(&root).exists());
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
        let _lock = KEYCHAIN_ENV_LOCK.lock().unwrap();
        // #220: crash after swap, before re-pin (marker in .confidant/,
        // keys.old present, keys/ is the new tree). Repair must finish
        // the re-pin and device-key promotion from the marker, then
        // clear it.
        use super::{keys_old_dir, repair_keys_staging, shred_marker_path};
        let (_tmp, root, config_dir, _keychain, _env_guard) = shred_marker_fixture();
        let keys_dir = root.join("keys");
        // Simulate post-swap: new tree in keys/, old tree in keys.old.
        std::fs::write(keys_dir.join("NEW_TREE"), b"new").unwrap();
        std::fs::remove_file(keys_dir.join("OLD_TREE")).unwrap();
        std::fs::create_dir_all(keys_old_dir(&root)).unwrap();
        std::fs::write(keys_old_dir(&root).join("OLD_TREE"), b"old").unwrap();
        let new_recovery_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let new_vk_hex: String = new_recovery_sk
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        write_test_marker(&shred_marker_path(&root), &new_vk_hex, "NEW_DEVICE_KEY");
        let old_anchor = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();

        repair_keys_staging(&root, &config_dir).unwrap();

        // Marker cleared, anchor re-pinned, device key promoted.
        assert!(!shred_marker_path(&root).exists());
        let new_anchor = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();
        assert_ne!(new_anchor, old_anchor);
        assert!(new_anchor.contains(&new_vk_hex));
        let device_key = std::fs::read_to_string(_keychain.join("device.key")).unwrap();
        assert_eq!(device_key, "NEW_DEVICE_KEY");
        // keys/ untouched apart from the swap; old tree cleaned up.
        assert!(keys_dir.join("NEW_TREE").is_file());
        assert!(!keys_old_dir(&root).exists());
    }

    #[test]
    fn shred_no_marker_discards_stage() {
        let _lock = KEYCHAIN_ENV_LOCK.lock().unwrap();
        // #220: crash during mutate/check (no marker). The stage is
        // discarded; keys/ and the anchor are untouched.
        use super::{keys_stage_dir, repair_keys_staging};
        let (_tmp, root, config_dir, _keychain, _env_guard) = shred_marker_fixture();
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

    #[test]
    fn shred_marker_post_repin_is_safe_noop() {
        let _lock = KEYCHAIN_ENV_LOCK.lock().unwrap();
        // #220/#339: crash after the re-pin, before marker removal.
        // Repair must be a safe no-op re-run (idempotent re-pin and
        // device-key promotion), then clear the marker. A second run
        // must also succeed.
        use super::{keys_old_dir, repair_keys_staging, shred_marker_path};
        let (_tmp, root, config_dir, _keychain, _env_guard) = shred_marker_fixture();
        let keys_dir = root.join("keys");
        // Simulate post-re-pin: new tree in keys/, old tree in keys.old,
        // anchor ALREADY re-pinned, device key ALREADY promoted.
        std::fs::write(keys_dir.join("NEW_TREE"), b"new").unwrap();
        std::fs::remove_file(keys_dir.join("OLD_TREE")).unwrap();
        std::fs::create_dir_all(keys_old_dir(&root)).unwrap();
        std::fs::write(keys_old_dir(&root).join("OLD_TREE"), b"old").unwrap();
        let new_recovery_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let new_vk_hex: String = new_recovery_sk
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        // Pre-pin the anchor and promote the device key (as a crash
        // after step 5 would have left them).
        write_test_marker(&shred_marker_path(&root), &new_vk_hex, "NEW_DEVICE_KEY");
        // Manually re-pin: rewrite trust.toml with the new recovery key
        // (keeping a valid operator pubkey).
        let operator_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let operator_hex: String = operator_sk
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let trust_toml = format!(
            "[trust]\noperator_pubkey = \"{}\"\nrecovery_pubkey = \"{}\"\nrecovery_age_recipient = \"age1ql5z7k2dpq6x9x8v4n3m2l1k0j9h8g7f6d5s4a3\"\n",
            operator_hex, new_vk_hex
        );
        std::fs::write(config_dir.join("trust.toml"), &trust_toml).unwrap();
        std::fs::write(_keychain.join("device.key"), b"NEW_DEVICE_KEY").unwrap();
        let anchor_before = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();

        // First repair: idempotent re-run, then clear marker.
        repair_keys_staging(&root, &config_dir).unwrap();
        assert!(!shred_marker_path(&root).exists());
        // Anchor still the new key (re-pin was a no-op).
        assert_eq!(
            std::fs::read_to_string(config_dir.join("trust.toml")).unwrap(),
            anchor_before
        );
        // Device key still promoted.
        assert_eq!(
            std::fs::read_to_string(_keychain.join("device.key")).unwrap(),
            "NEW_DEVICE_KEY"
        );
        // keys/ still the new tree.
        assert!(keys_dir.join("NEW_TREE").is_file());

        // Second repair: no marker, normal path, succeeds.
        repair_keys_staging(&root, &config_dir).unwrap();
        assert!(keys_dir.join("NEW_TREE").is_file());
    }

    #[test]
    fn shred_marker_mid_swap_completes_swap() {
        let _lock = KEYCHAIN_ENV_LOCK.lock().unwrap();
        // #220/#339: mid-swap crash. Marker in .confidant/, keys/
        // missing, keys.old present (old tree), stage present (new tree).
        // Repair must complete the swap, then finish promotions.
        use super::{keys_old_dir, keys_stage_dir, repair_keys_staging, shred_marker_path};
        let (_tmp, root, config_dir, _keychain, _env_guard) = shred_marker_fixture();
        let stage = keys_stage_dir(&root);
        // Simulate mid-swap: keys/ -> keys.old done, stage -> keys/ not.
        std::fs::create_dir_all(root.join(".confidant")).unwrap();
        std::fs::rename(root.join("keys"), keys_old_dir(&root)).unwrap();
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("NEW_TREE"), b"new").unwrap();
        let new_recovery_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let new_vk_hex: String = new_recovery_sk
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        write_test_marker(&shred_marker_path(&root), &new_vk_hex, "NEW_DEVICE_KEY");

        repair_keys_staging(&root, &config_dir).unwrap();

        // Swap completed, promotions done, marker cleared.
        assert!(root.join("keys/NEW_TREE").is_file());
        assert!(!root.join("keys/OLD_TREE").exists());
        assert!(!keys_old_dir(&root).exists());
        assert!(!stage.exists());
        assert!(!shred_marker_path(&root).exists());
        let new_anchor = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();
        assert!(new_anchor.contains(&new_vk_hex));
        assert_eq!(
            std::fs::read_to_string(_keychain.join("device.key")).unwrap(),
            "NEW_DEVICE_KEY"
        );
    }

    #[test]
    fn shred_marker_corrupt_fails_closed() {
        let _lock = KEYCHAIN_ENV_LOCK.lock().unwrap();
        // #339: a corrupt or empty marker must fail closed, and the error
        // must NOT quote the marker content (it may hold a private key).
        use super::{repair_keys_staging, shred_marker_path};
        for (name, content) in [
            (
                "corrupt",
                "version = 1\ndevice_key_bech32 = \"SECRET_KEY_MATERIAL_12345\"\n###garbage###",
            ),
            ("empty", ""),
            (
                "truncated",
                "version = 1\nrecovery_verifying_key_hex = \"ab",
            ),
        ] {
            let (_tmp, root, config_dir, _keychain, _env_guard) = shred_marker_fixture();
            let marker_path = shred_marker_path(&root);
            std::fs::create_dir_all(marker_path.parent().unwrap()).unwrap();
            std::fs::write(&marker_path, content).unwrap();
            let err = repair_keys_staging(&root, &config_dir).unwrap_err();
            let msg = err.to_string();
            assert!(
                !msg.contains("SECRET_KEY_MATERIAL_12345"),
                "{name}: error leaked marker content: {msg}"
            );
            assert!(
                !msg.contains("garbage"),
                "{name}: error leaked marker content: {msg}"
            );
            // keys/ untouched.
            assert!(root.join("keys/OLD_TREE").is_file());
        }
    }

    #[test]
    fn shred_marker_other_op_rolls_forward() {
        let _lock = KEYCHAIN_ENV_LOCK.lock().unwrap();
        // #220/#339, #99 rule: a different key operation (e.g. rotate)
        // starting while a shred marker exists must finish the shred
        // first via repair_keys_staging, not clobber it. The marker takes
        // precedence over the normal "discard the stage" path.
        use super::{keys_stage_dir, repair_keys_staging, shred_marker_path};
        let (_tmp, root, config_dir, _keychain, _env_guard) = shred_marker_fixture();
        let stage = keys_stage_dir(&root);
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("NEW_TREE"), b"new").unwrap();
        let new_recovery_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let new_vk_hex: String = new_recovery_sk
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        write_test_marker(&shred_marker_path(&root), &new_vk_hex, "NEW_DEVICE_KEY");
        let old_anchor = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();

        // This is what `keys rotate` / `keys init-client` call first.
        repair_keys_staging(&root, &config_dir).unwrap();

        // The shred rolled forward (not discarded): new tree swapped in,
        // anchor re-pinned to the marker's key, marker cleared.
        assert!(root.join("keys/NEW_TREE").is_file());
        assert!(!stage.exists());
        assert!(!shred_marker_path(&root).exists());
        let new_anchor = std::fs::read_to_string(config_dir.join("trust.toml")).unwrap();
        assert_ne!(new_anchor, old_anchor);
        assert!(new_anchor.contains(&new_vk_hex));
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

    /// #527: a lockfile `source` with URL userinfo must not leak the
    /// credential into the label. The lockfile reader refuses such a source,
    /// so the loader never serves that pack; the label is still sanitized
    /// defensively (a synced or hand-edited file is untrusted input), which
    /// this test pins directly.
    #[test]
    fn external_pack_label_strips_source_userinfo() {
        use super::{external_pack_label_line, sanitize_pack_source};
        assert_eq!(
            sanitize_pack_source("https://user:token@host.example/org/repo.git"),
            "https://host.example/org/repo.git"
        );
        assert_eq!(
            sanitize_pack_source("https://token@host.example/org/repo.git"),
            "https://host.example/org/repo.git"
        );
        // A `dir` source has no URL to strip.
        assert_eq!(sanitize_pack_source("dir"), "dir");
        // An `@` in the path is not userinfo and must survive.
        assert_eq!(
            sanitize_pack_source("https://host.example/org/user@host/repo.git"),
            "https://host.example/org/user@host/repo.git"
        );

        let label = external_pack_label_line(
            "https://user:token@host.example/org/repo.git",
            "0123456789ab",
        );
        assert!(!label.contains("user:token@"), "{label}");
        assert!(
            label.contains("https://host.example/org/repo.git"),
            "{label}"
        );
        assert_eq!(
            label,
            "[external pack: not shipped with confidant; text is from \
             https://host.example/org/repo.git at 0123456789ab]"
        );
    }

    #[test]
    fn display_remote_url_strips_userinfo() {
        use super::display_remote_url;
        assert_eq!(
            display_remote_url("https://user:token@example.invalid/vault.git"),
            "https://example.invalid/vault.git"
        );
        assert_eq!(
            display_remote_url("http://user:token@example.invalid/vault.git"),
            "http://example.invalid/vault.git"
        );
        assert_eq!(
            display_remote_url("https://example.invalid/vault.git"),
            "https://example.invalid/vault.git"
        );
        assert_eq!(
            display_remote_url("git@example.invalid:org/vault.git"),
            "git@example.invalid:org/vault.git"
        );
    }

    /// #527: a control or bidi character in a lockfile `source` is escaped,
    /// so no raw control/format character reaches the label line.
    #[test]
    fn external_pack_label_escapes_source_controls() {
        use super::external_pack_label_line;
        let label = external_pack_label_line(
            "https://host.example/org/\u{1b}[8m\u{202e}/repo.git",
            "0123456789abcdef",
        );
        for raw in ['\u{1b}', '\u{202e}'] {
            assert!(!label.contains(raw), "raw {raw:?} survived: {label:?}");
        }
        assert!(label.contains("\\u{1b}"), "{label:?}");
        assert!(label.contains("\\u{202e}"), "{label:?}");
        // An empty rev (a `--from-dir` install) still prints `unknown`.
        assert!(
            external_pack_label_line("dir", "").contains("at unknown]"),
            "missing rev must print unknown"
        );
    }
}
