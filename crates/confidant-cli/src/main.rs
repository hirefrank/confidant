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
mod setup;

use std::collections::{BTreeMap, BTreeSet};
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
use confidant_core::error::DomainError;
use confidant_core::id::{Prefix, RecordId};
use confidant_core::ledger::{parse_duration_minutes, parse_strict_date};
use confidant_core::packs::dir::read_pack_dir;
use confidant_core::packs::lock::read_lockfile;
use confidant_core::record::{main_record_path, Record, RecordKind};
use confidant_core::schema::contract_schema;
use confidant_core::scope::{owner_labels, parse_pack_list, resolve_scope, PackScope};
use confidant_core::write::{
    apply_write, apply_write_repairing, require_git_repo, FileChange, PendingWrite, WriteOptions,
    WriteOutcome,
};
use confidant_core::{check_vault, load_vault, search, search_for_operator, CheckOptions};
use serde_json::Value;

/// Attach a `DomainError` fix hint to an `anyhow::Error`.
///
/// `DomainError::with_fix` returns the domain error, so
/// `anyhow::Error::new(DomainError::…)` would lose it. This keeps the fix on
/// the common `Err(anyhow::Error::new(DomainError::…).with_fix(…))` shape.
/// A non-`DomainError` error is returned unchanged (it has no fix slot).
pub(crate) trait FixExt {
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
    /// Resolve a person by a contact value (email/phone/handle/name).
    ///
    /// Aliases are plain front-matter contact fields, matched
    /// case-insensitively as whole strings. Operator-only.
    Alias {
        #[command(subcommand)]
        action: AliasAction,
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
    /// Vault health checks.
    Doctor,
    /// Show how the vault compares with its git upstream (fetch, report).
    ///
    /// Read-only by default: fetch the upstream remote, report ahead/behind
    /// from the refreshed state, and exit non-zero when the branch diverged.
    /// `--pull` fast-forwards the local branch and `--push` pushes local
    /// commits; both are explicit, confirmed network writes and never run
    /// automatically. Refuses a vault with no remote or upstream
    /// (`E_NO_REMOTE`) and a diverged branch (`E_NOT_FAST_FORWARD`).
    ///
    /// The global `--dry-run` reports state from the last fetch without
    /// touching the network, so it is safe on metered or offline hosts.
    Sync {
        /// Fast-forward the local branch to the upstream after confirmation.
        #[arg(long, conflicts_with = "push")]
        pull: bool,
        /// Push local commits to the upstream after confirmation.
        #[arg(long)]
        push: bool,
        /// Confirm a `--pull` or `--push` without prompting. Required with
        /// --no-input or --json; interactive sessions are asked instead.
        #[arg(long)]
        yes: bool,
    },
    /// Create or scaffold a plaintext vault.
    ///
    /// With `--create`, an empty or absent vault directory is scaffolded:
    /// the directory is created, `git init` runs when needed and the branch
    /// is set to `main`, `.gitignore` gains `.confidant/`, and a minimal
    /// `confidant.toml` is written (its `packs` list comes from the global
    /// `--packs` flag, defaulting to `[]`) and committed. `--remote <url>`
    /// then adds `origin` (it does not push). Only packs built into this
    /// binary (today the implicit `personal@0.2`) may be listed: an external
    /// pack is vendored into an existing vault by `confidant pack add`, so
    /// install it after `init`.
    ///
    /// `--dry-run` runs every preflight check and reports the plan without
    /// creating a directory, writing a file, making a commit, or adding a
    /// remote.
    Init {
        /// Scaffold the vault directory (create, `git init`, `.gitignore`,
        /// `confidant.toml`, committed skeleton).
        #[arg(long)]
        create: bool,
        /// Add `git remote origin URL` after scaffolding. Does not push
        /// (credentials and host keys stay yours). Requires `--create`.
        #[arg(long, value_name = "URL", requires = "create")]
        remote: Option<String>,
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
        /// Log even when an identical session (same person, date,
        /// duration, tag) is already in the ledger (#747).
        #[arg(long)]
        force: bool,
    },
    /// Append a personal touchpoint ledger line, e.g. `log touch p-… meal`.
    Touch {
        /// Opaque person id (p-…) or an exact display name (cleared people
        /// only; see `confidant resolve`).
        person: String,
        /// Touchpoint kind: call, text, email, meet, meal, event, gift, video, or other.
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
        /// Log even when an identical touch (same person, date, kind)
        /// is already in the ledger (#747).
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand, Debug)]
enum AliasAction {
    /// Resolve a `kind` + value alias to the canonical person (read-only).
    ///
    /// `kind` is email, phone, handle, or name; the value is matched
    /// case-insensitively against the person's `personal@0.2` front-matter
    /// `emails`/`phones`/`handles` (or the value half of a `links` entry),
    /// or their display name for `name`. Honors `no-ai` like other reads:
    /// a `no-ai: true` person is not surfaced.
    Resolve {
        /// Alias kind: email, phone, handle, or name.
        kind: String,
        /// The value to look up.
        value: String,
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
        /// Skip the pre-check for data/checks this pack will resolve; the
        /// post-check still gates. Applies with --yes.
        #[arg(long)]
        allow_unresolved: bool,
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
    #[command(group(
        clap::ArgGroup::new("resolve_action").required(true).multiple(false)
    ))]
    Resolve {
        /// Opaque record id (p-…, o-…, d-…, e-…).
        id: String,
        /// Print both versions to stdout.
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
        Command::Init { create, .. } => match bootstrap_vault(&cli, *create)? {
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
            | Command::Pack { .. }
    );
    let vault_root: Option<PathBuf> = match discover(cli.vault.as_deref()) {
        Ok((root, _user)) => Some(root),
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
            touch,
        } => {
            let (unique, common) = confidant_core::bench::generate_realistic_vault(
                dir, *people, *notes, *cjk, *touch,
            )?;
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
            let report = check_vault(
                &vault,
                &CheckOptions {
                    as_of,
                    fail_on: Some(fail_on),
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
                AliasAction::Resolve { kind, value } => cmd_alias_resolve(&cli, &root, kind, value),
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
                    force,
                } => cmd_log_session(
                    &cli,
                    &root,
                    person,
                    duration,
                    tag.clone(),
                    date.clone(),
                    note.clone(),
                    src.clone(),
                    *force,
                ),
                LogAction::Touch {
                    person,
                    kind,
                    date,
                    note,
                    src,
                    force,
                } => cmd_log_touch(
                    &cli,
                    &root,
                    person,
                    kind,
                    date.clone(),
                    note.clone(),
                    src.clone(),
                    *force,
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
                allow_unresolved,
            } => cmd_pack_add(
                &cli,
                vault_root.as_deref(),
                url.as_deref(),
                from_dir.as_deref(),
                subdir.as_deref(),
                *yes,
                *allow_unresolved,
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
                    show,
                    take,
                    merged_file,
                    edit,
                } => {
                    cmd_record_resolve(&cli, &root, id, *show, *take, merged_file.as_deref(), *edit)
                }
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
        Command::Doctor => {
            let root = vault_root.unwrap();
            cmd_doctor(&cli, &root)
        }
        Command::Sync { pull, push, yes } => {
            let root = vault_root.unwrap();
            cmd_sync(&cli, &root, *pull, *push, *yes)
        }
        Command::Init { .. } => {
            let root = vault_root.unwrap();
            cmd_init(&cli, &root, scaffold.take())
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

/// Load the vault for a read command (`find`/`context`).
///
/// Records are plaintext on disk, so every read parses the same bytes; the
/// `no-ai` gate is applied on the parsed front matter by the search
/// allowlist. `operator` is accepted for call-site symmetry with the
/// operator-only reads and has no effect on loading.
fn load_vault_for_reads(
    root: &Path,
    json: bool,
    _operator: bool,
) -> Result<confidant_core::Vault, ExitCode> {
    match load_vault(root) {
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
    allow_unresolved: bool,
) -> anyhow::Result<ExitCode> {
    // The pack reader, manifest parser and git all quote untrusted
    // repository text; escape it before any error reaches the terminal or
    // the JSON error envelope (#499).
    cmd_pack_add_inner(
        cli,
        vault_root,
        url,
        from_dir,
        subdir,
        yes,
        allow_unresolved,
    )
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
    // An unreadable `packs/` entry is an error, not evidence of a vendored
    // copy: surface it instead of claiming the pack is already there.
    let vendored = confidant_core::paths::exists(root, Path::new(&rel))?;
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
            // Exact match or a prefix under the pack's namespace. A pack
            // name cannot collide with a built-in `[checks]` namespace: the
            // manifest name rules reject the reserved built-in names (PD14).
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

/// #694 review: whether a blocked-check finding can be blamed on the pack
/// being added or removed.
///
/// A finding counts when its message names the pack — an unknown `[checks]`
/// key renders as `unknown [checks] key 'name.key'` — or when the file:line
/// it points at contains one of the pack's declared verbs, metrics, or edge
/// kinds. Findings with no readable location do not count: the hint must
/// never blame this pack for another pack's data.
fn finding_names_pack(
    root: &Path,
    finding: &confidant_core::check::Finding,
    name: &str,
    owned: &[String],
) -> bool {
    let quoted = format!("'{name}.");
    let bare = format!("'{name}'");
    if finding.message.contains(&quoted) || finding.message.contains(&bare) {
        return true;
    }
    let Some(file) = finding.file.as_deref() else {
        return false;
    };
    let Some(line) = finding.line.and_then(|line| line.checked_sub(1)) else {
        return false;
    };
    let Ok(text) = confidant_core::paths::read_to_string(root, Path::new(file)) else {
        return false;
    };
    text.lines()
        .nth(line as usize)
        .is_some_and(|text| line_mentions_any(text, owned))
}

/// Whether `line` carries one of `owned` as a whole token, so a short verb
/// like `use` does not match `user`.
fn line_mentions_any(line: &str, owned: &[String]) -> bool {
    line.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'))
        .filter(|token| !token.is_empty())
        .any(|token| owned.iter().any(|owned| owned.eq_ignore_ascii_case(token)))
}

/// The finding codes a pack's own data can produce once it is missing or
/// unlisted: an unknown `[checks]` key and an unresolved verb/metric/edge
/// kind.
fn is_pack_data_finding(finding: &confidant_core::check::Finding) -> bool {
    matches!(
        finding.code.as_str(),
        "E_CONFIG" | "E_UNKNOWN_VERB" | "E_UNKNOWN_METRIC" | "E_UNKNOWN_EDGE_KIND"
    )
}

/// The names a manifest declares: verbs, balance metrics, and edge kinds.
fn manifest_tokens(manifest: &confidant_core::packs::manifest::PackManifest) -> Vec<String> {
    manifest
        .verbs
        .iter()
        .map(|verb| verb.name.clone())
        .chain(manifest.balance_metrics.iter().cloned())
        .chain(manifest.edge_kinds.iter().map(|kind| kind.name.clone()))
        .collect()
}

/// The names the vault's loaded copy of `name` declares. Empty when the
/// pack is not loadable (a missing or unreadable copy), so the hint stays
/// silent rather than guessing.
fn installed_pack_tokens(root: &Path, name: &str) -> Vec<String> {
    let Ok(vault) = confidant_core::load_vault(root) else {
        return Vec::new();
    };
    vault
        .pack_registry()
        .all()
        .iter()
        .find(|pack| pack.name() == name)
        .map(|pack| {
            pack.verbs()
                .iter()
                .map(|verb| (*verb).to_owned())
                .chain(
                    pack.balance_metrics()
                        .iter()
                        .map(|metric| (*metric).to_owned()),
                )
                .chain(pack.edge_kinds().iter().map(|kind| kind.name.to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

/// #694: a stderr hint after `pack add --yes` is blocked, tailored to the
/// findings that name this pack's data. Returns `None` when the block is
/// unrelated (for example a pack conflict), so the hint never misdiagnoses.
///
/// #696: with `--allow-unresolved` the pre-check was already skipped, so the
/// hint must not suggest listing the pack again or claim the flag fixes
/// unrelated findings; it only says the post-check is what rolled back.
fn pack_add_blocked_hint(
    root: &Path,
    report: &confidant_core::check::CheckReport,
    name: &str,
    version: &str,
    manifest: &confidant_core::packs::manifest::PackManifest,
    allow_unresolved: bool,
) -> Option<String> {
    let owned = manifest_tokens(manifest);
    let scoped: Vec<&confidant_core::check::Finding> = report
        .findings
        .iter()
        .filter(|finding| is_pack_data_finding(finding))
        .filter(|finding| finding_names_pack(root, finding, name, &owned))
        .collect();
    let listed = format!(
        "{}@{}",
        pack_fetch::escape_line(name),
        pack_fetch::escape_line(version)
    );
    let sets_checks = scoped
        .iter()
        .any(|finding| finding.code.as_str() == "E_CONFIG");
    let uses_ledger = scoped
        .iter()
        .any(|finding| finding.code.as_str() != "E_CONFIG");
    if allow_unresolved {
        if scoped.is_empty() {
            return None;
        }
        return Some(format!(
            "hint: --allow-unresolved skipped the pre-check, but the post-check still failed, so nothing was committed. The findings above name data {listed} resolves or `[checks]` keys the vault already sets; fix them, then re-run `confidant pack add`."
        ));
    }
    let mut lines = Vec::new();
    if sets_checks {
        lines.push(format!(
            "hint: the findings above name [checks] keys the vault already carries for {listed}; add \"{listed}\" to `packs` in confidant.toml first (or remove those keys), then re-run `confidant pack add`"
        ));
    }
    if uses_ledger {
        lines.push(format!(
            "hint: the findings above name ledger entries or edges that use {listed}'s verbs, metrics, or edge kinds; add \"{listed}\" to `packs` in confidant.toml first so the write lists it (or migrate/remove those lines if the pack is going away), then re-run `confidant pack add`"
        ));
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// #696: additive JSON field for `pack add`, present only when the flag was
/// passed so existing envelopes keep their shape.
fn with_allow_unresolved(
    mut payload: serde_json::Value,
    allow_unresolved: bool,
) -> serde_json::Value {
    if allow_unresolved {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("allow_unresolved".to_owned(), serde_json::Value::Bool(true));
        }
    }
    payload
}

/// #694: a stderr hint after `pack remove --yes` is blocked. The report
/// still prints unchanged and the exit stays 1; this only names the
/// workaround. Returns `None` when no finding names this pack, so a
/// pre-check failure on an unrelated vault does not blame the removal.
fn pack_remove_blocked_hint(
    root: &Path,
    report: &confidant_core::check::CheckReport,
    name: &str,
    owned: &[String],
) -> Option<String> {
    let blocked = report
        .findings
        .iter()
        .filter(|finding| is_pack_data_finding(finding))
        .any(|finding| finding_names_pack(root, finding, name, owned));
    if !blocked {
        return None;
    }
    let name = pack_fetch::escape_line(name);
    Some(format!(
        "hint: the vault still uses {name}'s verbs, metrics, [checks] keys, or edge kinds, so removing the pack would leave orphan data. Remove or migrate those entries (and drop the [checks] keys) first, or keep the pack installed. An explicit remove-side flag is tracked in #699 and is not available yet."
    ))
}

fn cmd_pack_add_inner(
    cli: &Cli,
    vault_root: Option<&Path>,
    url: Option<&str>,
    from_dir: Option<&Path>,
    subdir: Option<&str>,
    yes: bool,
    allow_unresolved: bool,
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
            // #696: the explicit install-over-existing-data path skips this
            // preflight. The post-check still gates the commit, so an
            // unrelated error rolls the whole write back.
            if !allow_unresolved {
                preflight_unlisted_pack(root, &cfg, &report)?;
            }
        }
        let lock = read_lockfile_or_empty(root)?;
        if let Some(entry) = lock.find(&report.name, &report.version) {
            if entry.hash == report.hash && listed_name {
                // Same pin, same bytes, already listed: nothing to write
                // (PD10 idempotence).
                if cli.json {
                    print_json(&ok_envelope(
                        Some(root),
                        with_allow_unresolved(
                            serde_json::json!({
                                "command": "pack-add",
                                "unchanged": true,
                                "pack": {"name": report.name, "version": report.version, "hash": report.hash},
                            }),
                            allow_unresolved,
                        ),
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
            if entry.hash != report.hash {
                return Err(anyhow::Error::new(DomainError::invalid(format!(
                    "{}@{} is already installed with a different hash",
                    report.name, report.version
                )))
                .with_fix("Use `confidant pack update <name> --rev <ref>` to move it"));
            }
            // #696 review: pinned at this hash but missing from `packs`. The
            // vendored copy is already the right bytes, so the only repair is
            // adding the listing; fall through to the write instead of
            // claiming "nothing to do" while `check` still fails.
        }
        // One version at a time: installing a second version of the same name
        // side by side leaves `pack update` unable to tell which to move, so
        // refuse up front and point at `update` (which replaces in place). The
        // same name and version as the pin already handled above is not a
        // second version.
        if let Some(other) = lock
            .packs
            .iter()
            .find(|e| e.name == report.name && e.version != report.version)
        {
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
        //
        // #696: `--allow-unresolved` opts into the same repairing path for a
        // vault that already carries this pack's checks/verbs/metrics/edge
        // kinds but does not list it. The pre-check is skipped; the
        // post-check still refuses to commit an unclean vault, so unrelated
        // errors roll back.
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
        let outcome = if unpinned_listing || allow_unresolved {
            apply_write_repairing(root, pending, &write_options(cli))?
        } else {
            apply_write(root, pending, &write_options(cli))?
        };
        // #694: the check report still prints unchanged (exit 1); this only
        // adds a stderr hint, so `--json` stdout stays valid.
        let hint = match &outcome {
            WriteOutcome::CheckBlocked {
                report: check_report,
            } => pack_add_blocked_hint(
                root,
                check_report,
                &report.name,
                &report.version,
                &report.manifest,
                allow_unresolved,
            ),
            _ => None,
        };
        let code = finish_write(
            cli,
            root,
            "pack-add",
            outcome,
            with_allow_unresolved(
                serde_json::json!({
                    "pack": {"name": report.name, "version": report.version, "hash": report.hash},
                }),
                allow_unresolved,
            ),
        )?;
        if let Some(hint) = hint {
            writeln!(io::stderr(), "{hint}")?;
        }
        return Ok(code);
    }
    if cli.json {
        let payload = report.to_json(&fetched.source, &fetched.rev, &fetched.subdir);
        print_json(&ok_envelope(
            vault_root,
            with_allow_unresolved(payload, allow_unresolved),
        ))?;
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
    // #694: the report still prints unchanged (exit 1); this only adds a
    // stderr hint, so `--json` stdout stays valid. Only findings that name
    // this pack produce one, so an unrelated pre-check failure stays quiet.
    let hint = match &outcome {
        WriteOutcome::CheckBlocked { report } => {
            let owned = installed_pack_tokens(root, &name);
            pack_remove_blocked_hint(root, report, &name, &owned)
        }
        _ => None,
    };
    let code = finish_write(
        cli,
        root,
        "pack-remove",
        outcome,
        serde_json::json!({ "removed": listed }),
    )?;
    if let Some(hint) = hint {
        writeln!(io::stderr(), "{hint}")?;
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
    let findings = result.findings;
    // #386: optional ranked-search hint. Present only when qmd is on PATH
    // and the corpus exists; never changes matches, ordering, or exit status.
    let qmd_hint = qmd_hint_for_find(&vault.root);
    if json {
        let mut data = serde_json::json!({
                "query": query,
                "matches": hits,
                "findings": findings,
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
        for f in &findings {
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
const QMD_STORE_REL: &str = ".confidant/qmd";

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

/// Apply a record write through the plaintext write pipeline.
///
/// Records are written as YAML front matter plus a Markdown body, atomically
/// (`temp file + rename` via `confidant_core::paths::write_replace`), and
/// gated by the pre/post `check` exactly as before.
fn apply_record_write(
    root: &Path,
    _vault: &confidant_core::vault::Vault,
    pending: PendingWrite,
    opts: &WriteOptions,
) -> anyhow::Result<WriteOutcome> {
    apply_write(root, pending, opts)
}

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

/// The vault loaded for name resolution in a write command. Unlike
/// [`load_vault_for_reads`] this returns the classified error instead of
/// printing it: the write commands resolve names *in addition to* loading
/// their own vault, and the error must reach the top-level handler once.
fn load_read_vault(root: &Path) -> anyhow::Result<confidant_core::Vault> {
    confidant_core::load_vault(root).map_err(anyhow::Error::new)
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
        // #717: the vault was not fully searched, so this is not a
        // not-found: the person may be in an unread record.
        PersonResolveError::CannotSearch { skipped, refused } => {
            anyhow::Error::new(DomainError::cannot_search(skipped, refused))
        }
    }
}

/// Resolve a `--person` / positional person argument: a `p-<ULID>` against
/// the already-loaded write vault (its id and type sit in the plaintext
/// envelope header, so a `no-ai: true` person stays addressable by id without
/// decrypting), or an exact display name against the `for_reads` cleared set.
///
/// An id miss in the write vault is not a confident not-found: the id
/// could belong to a record the read path could not search, so the miss
/// is resolved again against the `for_reads` vault, whose unread person
/// records gate it to `E_CANNOT_SEARCH` exactly like a name miss (#717).
/// Id arguments never echo a name, so the read-vault hit path cannot leak
/// a hidden person's name.
fn resolve_person_arg(
    root: &Path,
    vault: &confidant_core::Vault,
    raw: &str,
) -> anyhow::Result<ResolvedPersonArg> {
    if let Ok(id) = RecordId::parse(raw) {
        if let Some(r) = vault.records.get(&id) {
            if r.kind == RecordKind::Person {
                return Ok(ResolvedPersonArg {
                    id,
                    matched_name: None,
                });
            }
        }
        // Miss (or a non-person record) in the write vault: fall through
        // to the read vault, where `resolve_person` applies the same
        // cannot-search gate a name lookup gets. A non-person id stays
        // NotFound there too (positive knowledge), and a hit — e.g. a
        // `no-ai` shell the un-hooked write load could not surface —
        // still resolves by id.
        let read_vault = load_read_vault(root)?;
        return match confidant_core::resolve::resolve_person(&read_vault, raw) {
            Ok(m) => Ok(ResolvedPersonArg {
                id: m.id,
                matched_name: None,
            }),
            Err(err) => Err(person_resolve_error(raw, err)),
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

fn refuse_unknown_verb(verb: &str) -> anyhow::Error {
    // Deliberate echo, unlike `check_verbs_and_refs`' bare "unknown
    // verb": a verb is a command name the operator typed, not vault
    // content, so naming it cannot leak record text.
    anyhow::Error::new(DomainError::invalid(format!(
        "verb '{verb}' is not enabled in this vault"
    )))
    .with_fix("Use a core verb or enable the pack that defines it")
}

fn require_log_verb(vault: &confidant_core::vault::Vault, verb: &str) -> anyhow::Result<()> {
    if confidant_core::check::verb_passes_check(vault, verb) {
        return Ok(());
    }
    Err(refuse_unknown_verb(verb))
}

/// #747: semantic idempotency for `log touch` / `log session`. Returns
/// the existing line's vault-relative file and line number when an
/// identical line is already in the ledger, so the refusal can point at
/// it. The caller runs this after building the canonical request but
/// before applying or queueing anything, so a refusal writes nothing and
/// queues nothing. `note:` and `src:` never make a line distinct — a
/// backfill that re-adds the same contact with a fresh note or
/// provenance is still the same touchpoint. Lines already queued to the
/// inbox are not visible here (they are encrypted to the inbox key);
/// the drain skips them instead (see `plan_item`'s semantic check).
fn find_duplicate_touch(
    vault: &confidant_core::Vault,
    person: &RecordId,
    date: &chrono::NaiveDate,
    kind: &str,
) -> Option<(String, u32)> {
    vault.entries.iter().find_map(|sourced| {
        let (id, d, k) = confidant_core::touch::touch_identity(&sourced.entry)?;
        (id == *person && d == *date && k == kind).then_some((sourced.file.clone(), sourced.line))
    })
}

fn find_duplicate_session(
    vault: &confidant_core::Vault,
    person: &RecordId,
    date: &chrono::NaiveDate,
    duration: &str,
    tag: Option<&str>,
) -> Option<(String, u32)> {
    let minutes = parse_duration_minutes(duration)?;
    // Tags compare lowercased, matching `session_identity`, so a
    // historical `Paid` line matches a `paid` re-log.
    let tag = tag.unwrap_or("").to_ascii_lowercase();
    vault.entries.iter().find_map(|sourced| {
        let (id, d, m, t) = confidant_core::ledger::session_identity(&sourced.entry)?;
        (id == *person && d == *date && m == minutes && t == tag)
            .then_some((sourced.file.clone(), sourced.line))
    })
}

/// #747: whether `apply_record_write` should decide this write instead of
/// the duplicate refusal. True when `--request-id` is present and either
/// invalid (so the write path reports the usage error) or already
/// committed (so it replays an exact retry or reports an idempotency
/// conflict). Without this, a retry after a timeout would be refused as
/// a duplicate instead of replaying.
fn defer_to_write_path(root: &Path, cli: &Cli, canonical: &str) -> anyhow::Result<bool> {
    let Some(rid) = cli.request_id.as_deref() else {
        return Ok(false);
    };
    if rid.trim().is_empty() || rid.chars().count() < 22 {
        return Ok(true);
    }
    let (id_hash, _) = confidant_core::write::idempotency_digests(rid, canonical);
    Ok(confidant_core::write::find_request_commit(root, &id_hash, cli.no_input)?.is_some())
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
    force: bool,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    require_log_verb(&vault, "session")?;
    let person = resolve_person_arg(root, &vault, person_raw)?;
    announce_resolved_person(cli, &person);
    let Some(minutes) = parse_duration_minutes(duration) else {
        return Err(anyhow::Error::new(DomainError::usage(format!(
            "bad duration '{duration}'; use like 60m or 1h30m"
        ))));
    };
    // #747 review: the billing tag is a closed vocabulary — a
    // free-form token would silently count as untagged in balance
    // math, and `Paid` would be a distinct session from `paid`.
    // Validate before the refusal, like touch kinds are validated
    // before comparison, so the refusal never compares raw tags.
    // #747 round 3: the vocabulary is the union of the enabled packs'
    // `session-checks` billing tags for verb `session`, falling back
    // to the core default (`paid`, `pps`, `comp`) when no enabled pack
    // declares any — so a pack that bills under different tags is no
    // longer overruled at log time. Fail-closed enforcement is
    // unchanged: an unlisted tag still fails, in any case.
    if let Some(t) = &tag {
        let tags = confidant_core::packs::session_billing_tags_for_vault(&vault);
        if !tags.iter().any(|valid| valid == t) {
            return Err(anyhow::Error::new(DomainError::usage(format!(
                "bad session tag '{t}'; use one of: {}",
                tags.join(", ")
            ))));
        }
    }
    let date = parse_date_arg(&date_raw)?;

    // An inline --note becomes its own note record, referenced from the line.
    let mut changes = Vec::new();
    let mut note_arg: Option<String> = None;
    let mut note_body: Option<String> = None;
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
    // #747: refuse an identical session before applying or queueing
    // anything, unless --force or the write path owns the decision
    // (a known --request-id replays or conflicts there).
    if !force {
        if let Some((file, line)) =
            find_duplicate_session(&vault, &person.id, &date, duration, tag.as_deref())
        {
            if !defer_to_write_path(root, cli, &canonical)? {
                return Err(anyhow::Error::new(
                    DomainError::already_exists(format!(
                        // #747 review: name the normalized minutes, not
                        // the raw typed duration — re-logging `1h`
                        // against a stored `60m` line reports a `60m`
                        // session, so the message points at the line
                        // matched.
                        "a {minutes}m{} session for {} on {date} is already in the ledger ({file}:{line})",
                        tag.as_deref().map(|t| format!(" {t}")).unwrap_or_default(),
                        person.id,
                    ))
                    .with_file(file)
                    .with_line(line)
                    .with_fix("Pass --force to log a genuinely separate session anyway"),
                ));
            }
        }
    }
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
    person_raw: &str,
    kind: &str,
    date_raw: Option<String>,
    note: Option<String>,
    src: Option<String>,
    force: bool,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    // #551: the built-in personal pack is implicit, so `touch` is always
    // owned by an enabled pack; the #510 enable gate is gone. The #732
    // gate below is still applied so both log verbs share the same
    // dry-run/apply parity rule (it never fires for a core verb).
    require_log_verb(&vault, "touch")?;
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
    // #747: refuse an identical touch before applying or queueing
    // anything, unless --force or the write path owns the decision
    // (a known --request-id replays or conflicts there).
    if !force {
        if let Some((file, line)) = find_duplicate_touch(&vault, &person.id, &date, kind) {
            if !defer_to_write_path(root, cli, &canonical)? {
                return Err(anyhow::Error::new(
                    DomainError::already_exists(format!(
                        "a {kind} touch for {} on {date} is already in the ledger ({file}:{line})",
                        person.id,
                    ))
                    .with_file(file)
                    .with_line(line)
                    .with_fix("Pass --force to log a genuinely separate touch anyway"),
                ));
            }
        }
    }
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
    let mut extra = serde_json::json!({"lines": [line]});
    if let Some(echo) = person.echo_json() {
        extra["person"] = echo;
    }
    finish_write(cli, root, "log-touch", outcome, extra)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    // #732 fix wave: `import` appends arbitrary verbs, so it gets the
    // same up-front verb gate as `log` — in dry-run and apply alike,
    // and for MCP `import_ledger`, which routes through this command.
    // Without it, a dry-run preview would report `ok:true` for lines
    // apply's post-check blocks with `E_UNKNOWN_VERB`.
    {
        let vault = vault_or!(root, cli.json);
        for entry in &entries {
            if !confidant_core::check::verb_passes_check(&vault, &entry.verb) {
                return Err(refuse_unknown_verb(&entry.verb));
            }
        }
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
    let outcome = apply_record_write(
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
/// load. Mirrors `record show`'s ladder; never names the body.
fn note_unreadable_error(id_raw: &str, rel: &Path, _bytes: &[u8]) -> anyhow::Error {
    anyhow::Error::new(
        DomainError::invalid(format!(
            "cannot read {id_raw}: {} is not a readable note",
            rel.display()
        ))
        .with_fix("Run `confidant check` for the finding on that file"),
    )
}

fn note_plaintext(root: &Path, _vault_id: &str, rel: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            rel.display()
        )))
    })
}

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
    sweep_stale_note_scratch(root);
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
        resolve_editor()?;
        let (mut guard, scratch) = setup_note_edit_scratch(root, &id, &current)?;
        let result = run_note_editor(&scratch).and_then(|()| {
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
    // Fail closed before writing (#412-style): a note whose `person:` no
    // longer matches its directory must not be committed.
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
    let outcome = apply_record_write(
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
    let outcome = apply_record_write(
        root,
        &vault,
        PendingWrite {
            changes,
            summary: format!("record {id}"),
            canonical_request: format!("record-add/v1\npath={}\nbody={}", rel.display(), text),
        },
        &write_options(cli),
    )?;
    let mut extra = serde_json::json!({
        "id": id,
        "path": rel.display().to_string(),
    });
    // #179/#505: the mirrored touchpoints (primary first, then `with:`
    // participants), only when any were written.
    if !touch_lines.is_empty() {
        extra["touchpoints"] = serde_json::json!(touch_lines);
    }
    finish_write(cli, root, "record-add", outcome, extra)
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
        // A scoped call names the scope that applied (like `context`).
        if matches!(scope, PackScope::Only(_)) && !scope_names.is_empty() {
            writeln!(io::stdout(), "scope: {}", scope_names.join(", "))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// record show (operator-only) / record edit (#216)
// ---------------------------------------------------------------------------

/// #216: print one record's text so the operator can edit it.
///
/// Operator-only by construction: `mcp.rs` maps a fixed tool whitelist to
/// argv and this command is not in it, so no agent connection can reach it.
/// `--for-edit` is required rather than optional so that a bare invocation
/// can never print a record body — the flag is the operator stating the
/// intent to edit.
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
        // file; `check` already reports it.
        if let Some(rel) = main_path_for(&id) {
            if std::fs::read(root.join(&rel)).is_ok() {
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

fn cmd_record_resolve(
    cli: &Cli,
    root: &Path,
    id_raw: &str,
    show: bool,
    take: Option<Side>,
    merged_file: Option<&Path>,
    edit: bool,
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
    sweep_stale_scratch(root);
    if show {
        let sides = load_sides(root, &id)?;
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
        let sides = load_sides(root, &id)?;
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
                    next: None,
                },
            );
        }
        let outcome = take_side(root, cli.no_input, &sides, side)?;
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
        let sides = load_sides(root, &id)?;
        // CD5: refuse ANY path inside the vault tree, no `.confidant/`
        // exception, so a plaintext merge file cannot be committed by
        // accident.
        let canonical = refuse_vault_path(root, merged_path)?;
        let text = std::fs::read_to_string(&canonical).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read {}: {e}",
                canonical.display()
            )))
        })?;
        // #473: refuse an unfinished merge before it is re-encrypted.
        refuse_merged_conflict_markers(&text, &format!("the merged file {}", canonical.display()))
            .map_err(anyhow::Error::new)?;
        let provisional = canonical
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "record.md".to_owned());
        let prepared = prepare_record_write(
            root,
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
        let rekeyed: Option<(String, String)> = None;
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
                    next: None,
                },
            );
        }
        let outcome = apply_merge(root, cli.no_input, &prepared)?;
        return print_merge_result(cli, root, &id, &outcome, rekeyed);
    }
    if edit {
        // #465: `--dry-run --edit` creates no scratch and installs nothing;
        // `load_sides` is the same decrypt check the real edit would do.
        if cli.dry_run {
            let sides = load_sides(root, &id)?;
            return print_resolve_dry_run(
                cli,
                root,
                &id,
                "edit",
                &sides.path,
                ResolveDryRunDetail {
                    side: None,
                    merged_file: None,
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

fn print_merge_result(
    cli: &Cli,
    root: &Path,
    id: &RecordId,
    outcome: &MergeOutcome,
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
    _vault: &confidant_core::vault::Vault,
    id: &RecordId,
    id_raw: &str,
) -> anyhow::Result<ExitCode> {
    let sides = load_sides(root, id)?;
    // Fail fast if no editor is configured, before creating any scratch
    // files (which would hold plaintext).
    resolve_editor()?;
    let (mut guard, merged_path) = setup_edit_scratch(root, id, &sides)?;
    // An editor failure returns here; the guard drops and cleans up.
    run_editor(&merged_path)?;
    let text = std::fs::read_to_string(&merged_path).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            merged_path.display()
        )))
    })?;
    // #473: refuse an unfinished merge before it is re-encrypted. The
    // guard is dropped by the `?`, cleaning the scratch up.
    refuse_merged_conflict_markers(
        &text,
        &format!("the merged record from {}", merged_path.display()),
    )
    .map_err(anyhow::Error::new)?;
    let prepared = prepare_record_write(
        root,
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
    let rekeyed: Option<(String, String)> = None;
    let outcome = apply_merge(root, cli.no_input, &prepared)?;
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
    /// The parsed record.
    pub rec: Record,
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
fn prepare_record_write(root: &Path, spec: PrepareSpec<'_>) -> anyhow::Result<PreparedWrite> {
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
    // `record edit` refuses a conflicted file (it must be resolved first);
    // the resolve path expects a conflict and skips this.
    if !allow_conflict {
        let existing = std::fs::read_to_string(root.join(&rel)).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read {}: {e}",
                rel.display()
            )))
        })?;
        if confidant_core::record::has_conflict_markers(&existing) {
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
    Ok(PreparedWrite {
        pending: PendingWrite {
            changes: vec![FileChange::WriteFile {
                path: rel.clone(),
                contents,
            }],
            summary,
            canonical_request: format!("{canonical_prefix}\npath={}\nbody={}", rel.display(), text),
        },
        rel,
        rec,
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
    let outcome = apply_record_write(root, &vault, prepared.pending, &write_options(cli))?;
    let extra = serde_json::json!({
        "id": id_str,
        "path": rel.display().to_string(),
    });
    finish_write(cli, root, "record-edit", outcome, extra)
}

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
    // shapes still fall through to the cannot-search / ⚠2b / not-found
    // branches below); a non-id argument is an exact display name resolved
    // against the cleared set and canonicalized. Id args are not
    // canonicalized here — `context` already folds merge groups when it
    // builds the bundle.
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

fn validate_alias_kind(kind: &str) -> anyhow::Result<()> {
    if matches!(kind, "email" | "phone" | "handle" | "name") {
        Ok(())
    } else {
        Err(anyhow::Error::new(DomainError::usage(format!(
            "bad alias kind '{kind}'; use one of: email, phone, handle, name"
        ))))
    }
}

/// `confidant alias resolve <kind> <value>` (#537 phase 3b): resolve a
/// `kind` + value alias to the canonical person. Read-only.
///
/// Aliases are plain `personal@0.2` front-matter contact values, matched
/// case-insensitively as whole strings against the cleared set. A
/// `no-ai: true` person is indistinguishable from an unmatched alias. Two
/// cleared people sharing a value fail closed with `E_AMBIGUOUS_PERSON`.
fn cmd_alias_resolve(cli: &Cli, root: &Path, kind: &str, value: &str) -> anyhow::Result<ExitCode> {
    validate_alias_kind(kind)?;
    let vault = match load_vault_for_reads(root, cli.json, false) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let id = match confidant_core::resolve::resolve_alias(&vault, kind, value) {
        Ok(m) => m.id,
        Err(err) => return Err(person_resolve_error(value, err)),
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

/// Message whenever staleness cannot be determined: offline, DNS
/// failure, timeout, non-200, or malformed JSON. The check reports
/// status `unknown` for it (#709): an undetermined check never renders
/// `ok`. `unknown` is warning-tier — it never fails `doctor` — so an
/// offline user still passes, just not with a green line.
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
/// when it could not be fetched). Never an error: behind is `warning`,
/// ahead and equal are `ok`, and undetermined (no tag, or an unparseable
/// tag) is `unknown` (#709). With `offline`, the fetch was skipped by
/// operator choice — a determined state, not an undetermined one — so
/// the check reports `ok` "disabled".
fn cli_staleness_check(latest: Option<String>, offline: bool) -> DoctorCheck {
    let local = env!("CARGO_PKG_VERSION");
    let (status, message) = if offline {
        ("ok", STALENESS_DISABLED.to_owned())
    } else {
        match latest {
            None => (DOCTOR_STATUS_UNKNOWN, STALENESS_UNKNOWN.to_owned()),
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
                _ => (DOCTOR_STATUS_UNKNOWN, STALENESS_UNKNOWN.to_owned()),
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

/// Minimum git version Confidant relies on. Confidant shells out to git
/// for every write, commit, and sync; older clients miss behavior the
/// agent contract assumes.
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
/// missing or unparseable output) is `unknown` (#709, following the
/// #174 precedent it generalizes): the `git-repo` check already errors
/// when the vault is not a git repository, and an unparseable version
/// string is an odd environment, not a known-bad git. `unknown` is
/// warning-tier, so it never fails `doctor`.
fn git_version_check_from(version: Option<(u64, u64, u64)>, has_signers: bool) -> DoctorCheck {
    let floor = format!(
        "{}.{}.{}",
        MIN_GIT_VERSION.0, MIN_GIT_VERSION.1, MIN_GIT_VERSION.2
    );
    match version {
        Some(v) if v >= MIN_GIT_VERSION => DoctorCheck {
            id: "git-version",
            status: "ok",
            message: format!("git {}.{}.{} (>= {floor})", v.0, v.1, v.2),
            fix: None,
        },
        Some(v) => DoctorCheck {
            id: "git-version",
            status: if has_signers { "error" } else { "warning" },
            message: format!(
                "git {}.{}.{} is below the minimum {floor}; upgrade git to >= {floor}",
                v.0, v.1, v.2
            ),
            fix: None,
        },
        None => DoctorCheck {
            id: "git-version",
            status: DOCTOR_STATUS_UNKNOWN,
            message: format!("could not determine git version; Confidant needs git >= {floor}"),
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

/// #723: the persisted encrypted-disk election, as `doctor` reports it.
///
/// The `[qmd] assume_encrypted_disk` key is skill-side device policy, so
/// `UserConfig` drops the table — read the raw TOML instead. `Some` only
/// when the file itself asserts: the message names it an assertion, never
/// a detection result (#709's rule — an assumption never masquerades as
/// detection). A detected disk needs no report; there is no assumption
/// to disclose. Anything unreadable or unparsable is not an assertion.
/// A truthy value is a bool true, the integer 1, or a string in
/// 1/true/yes/on — the same set the Python gate's TRUTHY accepts, so a
/// hand-edited integer key is not silently invisible to `doctor`.
fn qmd_disk_assertion_check() -> Option<DoctorCheck> {
    let home = setup::home_dir().ok()?;
    let text = std::fs::read_to_string(home.join(".config/confidant/config.toml")).ok()?;
    let value: toml::Value = toml::from_str(&text).ok()?;
    let asserted = value
        .get("qmd")
        .and_then(|q| q.get("assume_encrypted_disk"))
        .is_some_and(|v| {
            v.as_bool().unwrap_or(false)
                || v.as_integer().is_some_and(|n| n == 1)
                || v.as_str().is_some_and(|s| {
                    matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
                })
        });
    if !asserted {
        return None;
    }
    Some(DoctorCheck {
        id: "qmd-disk",
        status: "ok",
        message: "disk encryption: asserted by operator (persisted [qmd] \
                  assume_encrypted_disk; an assertion, not a detection)"
            .to_owned(),
        fix: None,
    })
}

/// #386: informational `qmd` search-availability check. qmd is optional,
/// so a missing qmd is `ok` — the same rule as the offline staleness check:
/// it just means search falls back to `confidant find` (see
/// `qmd-query.py`). A qmd that is installed but has no corpus is a
/// `warning` (#657): the fallback still works, but the operator asked for
/// semantic search and a corpus built by the `qmd-search` skill is needed
/// to enable it, so an `ok` badge on that message is easy to miss.
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
                 build it with the qmd-search skill \
                 (search falls back to `confidant find`)"
                .to_owned(),
            fix: Some(
                "Run `confidant setup` to install the qmd-search skill, then build the corpus"
                    .to_owned(),
            ),
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
/// fetches, pushes, or contacts a remote. It reports the configured
/// remotes by name; transport safety is the operator's choice of host.
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
            message: "local-only; add a remote for backup".to_owned(),
            fix: Some(
                "Run `git remote add origin <url>` (or `confidant init --create --remote <url>` \
                 on a new vault)"
                    .to_owned(),
            ),
        };
    }
    let named = remotes.join(", ");
    DoctorCheck {
        id: ID,
        status: "ok",
        message: format!("git remote configured ({named})"),
        fix: None,
    }
}

/// Ahead/behind counts from `git rev-list --left-right --count @{u}...HEAD`.
/// `ahead` counts commits only on HEAD; `behind` counts commits only on the
/// upstream. Both are from the last fetch (or push) — this helper never
/// touches the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AheadBehind {
    ahead: u64,
    behind: u64,
}

/// Refspec for `sync --push`: `HEAD:<upstream-branch>` on the remote that
/// was fetched. `upstream` is `rev-parse --abbrev-ref @{u}` (`origin/main`).
fn sync_push_refspec(remote: &str, upstream: &str) -> Option<String> {
    let prefix = format!("{remote}/");
    let branch = upstream.strip_prefix(&prefix)?;
    if branch.is_empty() {
        return None;
    }
    Some(format!("HEAD:{branch}"))
}

/// Parse `git rev-list --left-right --count @{u}...HEAD` output
/// (`<behind>\t<ahead>`). Returns `None` for anything unexpected.
fn parse_ahead_behind(output: &str) -> Option<AheadBehind> {
    let mut parts = output.split_whitespace();
    let behind = parts.next()?.parse().ok()?;
    let ahead = parts.next()?.parse().ok()?;
    Some(AheadBehind { ahead, behind })
}

/// Run the offline ahead/behind comparison. Callers resolve the upstream
/// first; a failure here is surfaced as a command error, never as a silent
/// zero.
fn git_ahead_behind(root: &Path, no_input: bool) -> anyhow::Result<AheadBehind> {
    let out = confidant_core::write::git(
        root,
        &["rev-list", "--left-right", "--count", "@{u}...HEAD"],
        no_input,
    )?;
    parse_ahead_behind(&out).ok_or_else(|| {
        anyhow::Error::new(DomainError::invalid(
            "could not parse the ahead/behind counts from git",
        ))
    })
}

/// Resolve the current branch and its upstream (e.g. `main` and
/// `origin/main`) without contacting a remote. `None` means "no upstream",
/// which is a valid local-only setup rather than a failure.
fn git_upstream(root: &Path, no_input: bool) -> Option<(String, String)> {
    let branch = confidant_core::write::git(root, &["rev-parse", "--abbrev-ref", "HEAD"], no_input)
        .ok()?
        .trim()
        .to_owned();
    let upstream = confidant_core::write::git(
        root,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        no_input,
    )
    .ok()?
    .trim()
    .to_owned();
    if branch.is_empty() || upstream.is_empty() || branch == "HEAD" {
        return None;
    }
    Some((branch, upstream))
}

/// #665: `local-commits` doctor check. Offline and advisory: it reports
/// ahead/behind from the **last fetch** and never calls fetch, pull, or
/// push. No remote, no upstream, or an unreadable comparison is `ok`; only
/// a real difference warns (a warning, never an error).
fn local_commits_check(root: &Path, no_input: bool) -> DoctorCheck {
    const ID: &str = "local-commits";
    let ok = |message: String, fix: Option<String>| DoctorCheck {
        id: ID,
        status: "ok",
        message,
        fix,
    };
    if !root.is_dir() {
        return ok("no vault to inspect for local commits".to_owned(), None);
    }
    let Some((_, upstream)) = git_upstream(root, no_input) else {
        // Distinguish "no remote at all" from "remote, no upstream branch":
        // the first is a valid local-only setup, the second needs one git
        // command. Neither is an error, and `git-remote` already carries the
        // add-a-remote instructions.
        let remotes = confidant_core::write::git(root, &["remote"], no_input)
            .map(|out| parse_git_remotes(&out))
            .unwrap_or_default();
        let branch =
            confidant_core::write::git(root, &["rev-parse", "--abbrev-ref", "HEAD"], no_input)
                .map(|out| out.trim().to_owned())
                .unwrap_or_else(|_| "HEAD".to_owned());
        if remotes.is_empty() {
            return ok(
                "local-only; no remote to compare local commits with".to_owned(),
                None,
            );
        }
        return ok(
            format!(
                "no upstream branch for '{branch}'; cannot compare local commits with {}",
                remotes.join(", ")
            ),
            Some(format!(
                "Set an upstream with `git push -u {} {branch}`",
                remotes[0]
            )),
        );
    };
    let state = match git_ahead_behind(root, no_input) {
        Ok(state) => state,
        Err(e) => {
            return ok(
                format!("could not compare with {upstream}: {e}"),
                Some("Run `git status` to check the repository".to_owned()),
            )
        }
    };
    match (state.ahead, state.behind) {
        (0, 0) => ok(
            format!("up to date with {upstream} (as of the last fetch)"),
            None,
        ),
        (ahead, 0) => DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "{ahead} local commit(s) not pushed to {upstream} (as of the last fetch)"
            ),
            fix: Some("Run `confidant sync --push`".to_owned()),
        },
        (0, behind) => DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "{upstream} has {behind} new commit(s) not local (as of the last fetch)"
            ),
            fix: Some("Run `confidant sync --pull`".to_owned()),
        },
        (ahead, behind) => DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "diverged from {upstream}: {ahead} local commit(s) not pushed, \
                 {behind} remote commit(s) not local (as of the last fetch)"
            ),
            fix: Some(
                "Merge or rebase the branch explicitly, then run `confidant sync`".to_owned(),
            ),
        },
    }
}

/// #665: `confidant sync`. Read-only by default (fetch, report ahead/behind);
/// `--pull` and `--push` are explicit, confirmed network writes. Refuses no
/// remote/upstream or a diverged branch with stable codes. `--dry-run` never touches the network and reports the state from
/// the last fetch.
///
/// #736: the default report names its own remedy. A report of "N commits
/// behind" that names no next step left the product's author reaching for
/// a bare `git pull` when `confidant sync --pull` already existed, so when
/// `action == "none"` and the branch is ahead or behind, the report prints
/// (and the JSON carries) the exact command that applies the state it just
/// reported. Up-to-date reports, applied writes, and declined confirms
/// carry no remedy; a `--dry-run` report does, qualified as last-fetched.
/// A diverged branch errors with a `fix` naming the explicit reconcile
/// steps instead of a success-envelope remedy.
fn cmd_sync(cli: &Cli, root: &Path, pull: bool, push: bool, yes: bool) -> anyhow::Result<ExitCode> {
    let no_input = cli.no_input;
    let git = |args: &[&str]| confidant_core::write::git(root, args, no_input);

    // Fail closed on a missing repository or an empty remote list before
    // any git command that could reach the network.
    confidant_core::write::require_git_repo(root, no_input)?;
    let remotes = git(&["remote", "-v"])
        .map(|out| parse_git_remotes(&out))
        .unwrap_or_default();
    if remotes.is_empty() {
        return Err(anyhow::Error::new(DomainError::no_remote(
            "no git remote is configured for this vault",
        )));
    }
    let Some((branch, upstream)) = git_upstream(root, no_input) else {
        return Err(anyhow::Error::new(DomainError::no_remote(
            "the current branch has no upstream branch",
        )));
    };
    // The upstream's first path segment is the remote name
    // (`origin/main` → `origin`); verify it is one of the configured
    // remotes rather than trusting the string.
    let remote = upstream.split('/').next().unwrap_or_default().to_owned();
    if !remotes.iter().any(|name| name == &remote) {
        return Err(anyhow::Error::new(DomainError::no_remote(format!(
            "upstream '{upstream}' does not name a configured remote"
        ))));
    }

    // `--dry-run` reports the last-fetched state and never contacts the
    // remote, so it works offline and on a metered connection.
    let mut fetched = false;
    if !cli.dry_run {
        git(&["fetch", "--quiet", &remote]).map_err(|_| {
            anyhow::Error::new(DomainError::invalid(format!(
                "git fetch {remote} failed; check the remote URL and credentials"
            )))
        })?;
        fetched = true;
    }

    let mut state = git_ahead_behind(root, no_input)?;
    if state.ahead > 0 && state.behind > 0 {
        // #736: a diverged branch gets a remedy too, not just a refusal.
        // The generic `not_fast_forward` fix names no branch, upstream, or
        // command, so override it here where both are known: the exact
        // reconcile steps, ending in the sync command that finishes the job.
        // Confidant still never auto-merges and never force-pushes.
        return Err(anyhow::Error::new(DomainError::not_fast_forward(
            state.ahead,
            state.behind,
        ))
        .with_fix(&format!(
            "Reconcile {branch} with {upstream} explicitly, then run `confidant sync --push`: `git fetch {remote}`; `git log --oneline --left-right @{{u}}...HEAD` to see both sides; `git merge {upstream}` (or `git rebase {upstream}`)"
        )));
    }

    let mut action = "none";
    let mut applied = false;
    if pull && state.behind > 0 && !cli.dry_run {
        action = "pull";
        if confirm_sync_write(
            cli,
            yes,
            &format!(
                "Fast-forward {branch} to {upstream} ({} commit(s))?",
                state.behind
            ),
        )? {
            git(&["pull", "--ff-only", "--quiet"]).map_err(|e| {
                let detail = format!("{e:#}");
                if detail.contains("Not possible to fast-forward")
                    || detail.contains("non-fast-forward")
                {
                    anyhow::Error::new(DomainError::not_fast_forward(state.ahead, state.behind))
                } else if detail.contains("would be overwritten")
                    || detail.contains("commit or stash")
                    || detail.contains("commit your changes or stash")
                {
                    // A dirty tree is the common fast-forward refusal; a
                    // credentials message here would send the operator to
                    // the wrong place.
                    anyhow::Error::new(
                        DomainError::conflict(
                            "git pull --ff-only refused: local changes would be overwritten",
                        )
                        .with_fix("Commit or stash your changes, then run `confidant sync --pull`"),
                    )
                } else {
                    anyhow::Error::new(DomainError::invalid(
                        "git pull --ff-only failed; check the remote URL and credentials",
                    ))
                }
            })?;
            state = git_ahead_behind(root, no_input)?;
            applied = true;
        }
    } else if push && state.ahead > 0 && !cli.dry_run {
        action = "push";
        if confirm_sync_write(
            cli,
            yes,
            &format!("Push {} commit(s) to {upstream}?", state.ahead),
        )? {
            // Push HEAD to the upstream branch on the same remote that
            // was fetched and counted. A bare `git push` follows
            // `push.default=simple` (refuses a differently named
            // upstream) and can honour `remote.pushDefault` /
            // `branch.<b>.pushRemote` (a different remote).
            let Some(refspec) = sync_push_refspec(&remote, &upstream) else {
                return Err(anyhow::Error::new(DomainError::no_remote(format!(
                    "upstream '{upstream}' does not name a branch on remote '{remote}'"
                ))));
            };
            git(&["push", "--quiet", &remote, &refspec]).map_err(|e| {
                let detail = format!("{e:#}");
                if detail.contains("non-fast-forward")
                    || detail.contains("fetch first")
                    || detail.contains("stale info")
                {
                    anyhow::Error::new(DomainError::not_fast_forward(state.ahead, state.behind))
                } else {
                    anyhow::Error::new(DomainError::invalid(format!(
                        "git push {remote} failed; check the remote URL and credentials"
                    )))
                }
            })?;
            // `push` updates the remote-tracking ref, so the comparison is
            // current without a second fetch.
            state = git_ahead_behind(root, no_input)?;
            applied = true;
        }
    }

    // #736: the remedy for the state just reported, printed only when the
    // report itself changed nothing. The gate is exactly `action == "none"`
    // with ahead/behind non-zero: an applied write has nothing left to
    // point at, and a requested-but-declined write already names its own
    // command ("pull not confirmed"), so both get no second pointer.
    // `--dry-run` never takes a write branch, so a dry-run report of a
    // behind/ahead state does carry a remedy — qualified below as
    // last-fetched, since dry-run never contacts the remote. A `--pull`
    // request on an ahead-only branch (or `--push` on a behind-only one)
    // likewise falls through with `action == "none"` and names the other
    // direction's command. Diverged never reaches here: it errors above.
    // At most one remedy can exist here — ahead > 0 and behind > 0 is the
    // diverged early return — so this is a single `Option`, not a list.
    let mut remedy: Option<String> = None;
    if action == "none" {
        if state.behind > 0 {
            // A dirty tree qualifies the pull remedy: `--pull` refuses a
            // tree it would overwrite, so the plain fast-forward pointer
            // would send the operator into a refusal. Commit-or-stash
            // first is the path that actually fast-forwards.
            let dirty = git(&["status", "--porcelain"])
                .map(|out| !out.trim().is_empty())
                .unwrap_or(false);
            remedy = Some(if dirty {
                format!(
                    "Commit or stash your changes, then run `confidant sync --pull` to fast-forward {branch} to {upstream} ({} commit(s))",
                    state.behind
                )
            } else {
                format!(
                    "Run `confidant sync --pull` to fast-forward {branch} to {upstream} ({} commit(s))",
                    state.behind
                )
            });
        } else if state.ahead > 0 {
            remedy = Some(format!(
                "Run `confidant sync --push` to push {} commit(s) to {upstream}",
                state.ahead
            ));
        }
    }
    // A dry-run count is last-fetched, not fresh: say so in the remedy
    // itself, so a script branching on `remedy` alone can tell it is stale
    // without also checking `dry_run`/`fetched`.
    if cli.dry_run {
        if let Some(text) = remedy.as_mut() {
            text.push_str(" (as of the last fetch)");
        }
    }

    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "remote": remote,
                "branch": branch,
                "upstream": upstream,
                "ahead": state.ahead,
                "behind": state.behind,
                "crypto_mode": "plaintext",
                "fetched": fetched,
                "dry_run": cli.dry_run,
                "action": action,
                "applied": applied,
                "remedy": remedy,
            }),
        ))?;
    } else {
        println!("{branch} -> {upstream} ({remote})");
        println!(
            "{ahead} ahead, {behind} behind ({})",
            if fetched {
                "after fetch"
            } else {
                "last fetched state; --dry-run did not contact the remote"
            },
            ahead = state.ahead,
            behind = state.behind
        );
        if action != "none" {
            if applied {
                println!("{action} complete");
            } else {
                println!("{action} not confirmed; nothing changed");
            }
        }
        if let Some(line) = &remedy {
            println!("{line}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Confirmation for a `sync --pull` / `--push` network write. Unlike the
/// read-only report, these need an explicit yes: interactive sessions are
/// prompted, and non-interactive sessions must pass `--yes` (a usage error,
/// exit 2). Never returns `true` without confirmation.
fn confirm_sync_write(cli: &Cli, yes: bool, question: &str) -> anyhow::Result<bool> {
    if yes {
        return Ok(true);
    }
    if cli.no_input || cli.json {
        return Err(anyhow::Error::new(DomainError::usage(
            "--pull and --push are network writes; pass --yes with --no-input or --json",
        )));
    }
    confirm_yn(question, false, false)
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
/// root device's ancestry (LUKS/dm-crypt). Pure string logic, so it is
/// shared by the Linux probe and the platform-independent decision below
/// (and its unit tests) rather than gated on Linux.
fn lsblk_types_include_crypt(output: &str) -> bool {
    output
        .lines()
        .map(str::trim)
        .any(|line| line.eq_ignore_ascii_case("crypt"))
}

/// Doctor status vocabulary (#709): `ok` means the check ran and passed,
/// `warning` means it ran and found something to act on, `error` means
/// it ran and found something blocking, and `unknown` means it could
/// not run to a determination at all. `unknown` is warning-tier: it
/// never fails `doctor` (only `error` does, in `cmd_doctor`), but it
/// never renders `ok` either — an undetermined check is not a pass.
/// Callers branch on this status string, never on message text (ADR-7):
/// `unknown` is a stable fourth value, alongside the existing three.
const DOCTOR_STATUS_UNKNOWN: &str = "unknown";

/// Pure decision for the `disk-encryption` check (#653(d), #709).
/// `source` is the parsed `findmnt` root source, or `None` when
/// `findmnt` failed, is missing, or the root is not on a block device;
/// `types` is the `lsblk` TYPE output, or `None` when `lsblk` failed or
/// is missing. `unknown_detail` names the probe failure for the
/// undetermined cases, and is only consulted when `source` or `types`
/// is `None`; an empty TYPE list is its own undetermined case.
/// Determined outcomes are unchanged: encrypted is `ok`, a readable
/// non-encrypted ancestry is `warning`.
fn disk_encryption_check_from(
    source: Option<&str>,
    types: Option<&str>,
    unknown_detail: &str,
) -> DoctorCheck {
    const ID: &str = "disk-encryption";
    let unknown = |detail: &str| DoctorCheck {
        id: ID,
        status: DOCTOR_STATUS_UNKNOWN,
        message: format!("could not determine disk encryption ({detail})"),
        fix: None,
    };
    let Some(_source) = source else {
        return unknown(unknown_detail);
    };
    let Some(types) = types else {
        return unknown(unknown_detail);
    };
    if lsblk_types_include_crypt(types) {
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

/// #653(d): best-effort `disk-encryption` check. Linux-only and purely
/// advisory: a missing tool, an unparseable source, or a non-block root
/// all report `unknown` "could not determine" (#709), so this can never
/// fail doctor — but also never passes it. It never prompts and never
/// leaves the machine.
#[cfg(target_os = "linux")]
fn disk_encryption_check() -> DoctorCheck {
    let findmnt = match std::process::Command::new("findmnt")
        .args(["-no", "SOURCE", "/"])
        .output()
    {
        Ok(out) if out.status.success() => out,
        Ok(_) => {
            return disk_encryption_check_from(
                None,
                None,
                "findmnt could not resolve the root filesystem",
            );
        }
        Err(_) => {
            return disk_encryption_check_from(None, None, "findmnt is not available");
        }
    };
    let source = parse_findmnt_source(&String::from_utf8_lossy(&findmnt.stdout));
    let Some(source) = source else {
        return disk_encryption_check_from(None, None, "root filesystem is not on a block device");
    };
    let lsblk = match std::process::Command::new("lsblk")
        .args(["-sno", "TYPE", &source])
        .output()
    {
        Ok(out) if out.status.success() => out,
        Ok(_) => {
            return disk_encryption_check_from(
                Some(&source),
                None,
                "lsblk could not read the root device",
            );
        }
        Err(_) => {
            return disk_encryption_check_from(Some(&source), None, "lsblk is not available");
        }
    };
    let types = String::from_utf8_lossy(&lsblk.stdout);
    disk_encryption_check_from(Some(&source), Some(&types), "lsblk is not available")
}

/// Non-Linux platforms have no `findmnt`/`lsblk`; macOS FileVault is not
/// probed here. Report `unknown` "could not determine" (#709) so doctor
/// still passes, without claiming a pass.
#[cfg(not(target_os = "linux"))]
fn disk_encryption_check() -> DoctorCheck {
    disk_encryption_check_from(None, None, "unsupported platform")
}

fn cmd_doctor(cli: &Cli, root: &Path) -> anyhow::Result<ExitCode> {
    let mut checks: Vec<DoctorCheck> = Vec::new();

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

    // #174: minimum git version. Confidant shells out to git, so a very
    // old client is reported.
    checks.push(git_version_check(false));

    // #660: remote visibility. Read-only and offline.
    checks.push(git_remote_check(root, cli.no_input));

    // #665: ahead/behind visibility from the last fetch. Offline and
    // advisory: no remote/upstream stays `ok`, and a real difference warns.
    checks.push(local_commits_check(root, cli.no_input));

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
        }
        Err(e) => checks.push(DoctorCheck {
            id: "vault-load",
            status: "error",
            message: format!("cannot load vault: {e}"),
            fix: None,
        }),
    }

    // #653(d): best-effort encrypted-disk check. Advisory only: a missing
    // tool or an unknown platform is `unknown` (#709), so doctor never
    // fails on it — and never passes on it either.
    checks.push(disk_encryption_check());

    // #165: staleness vs the latest GitHub Release. Warning-only: a stale
    // install is never an error, so exit-code semantics are unchanged. Any
    // network failure degrades to `unknown` "unknown" (#709, offline-first):
    // staleness is informational, so `doctor` must not punish offline users
    // — but an undetermined check is not a pass either.
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
        // #723: the persisted disk election, reported honestly forever
        // after — present only when the operator asserted it.
        if let Some(check) = qmd_disk_assertion_check() {
            checks.push(check);
        }
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
    /// Keep the scaffold: the run is about to succeed.
    fn disarm(&mut self) {
        self.armed = false;
    }

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
const SECOND_DEVICE_HINT: &str = "to put this vault on another device, clone it with git";

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
fn bootstrap_vault(cli: &Cli, create: bool) -> anyhow::Result<BootstrapPlan> {
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

    // #651: require a commit identity before creating the directory or
    // running `git init`. `git var` works outside a repo, so a refused run
    // leaves an absent target absent instead of an empty `.git` that blocks
    // the retry. This also covers the dry run so it reports the same refusal.
    require_git_identity(&root, no_input)?;

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

/// `confidant init`: validate a vault, or scaffold one with `--create`.
///
/// Records are plaintext, so there is no key, keychain, anchor, or recovery
/// step. With `--create` the skeleton is already written and committed by
/// [`bootstrap_vault`]; this validates the result and reports the plan.
fn cmd_init(cli: &Cli, root: &Path, scaffold: Option<Scaffold>) -> anyhow::Result<ExitCode> {
    let json = cli.json;
    let no_input = cli.no_input;

    require_git_repo(root, no_input)?;
    let vault = load_vault(root)?;
    if vault.config.spec != confidant_core::SPEC_VERSION {
        return Err(anyhow::Error::new(DomainError::spec_unsupported(
            &vault.config.spec,
        )));
    }
    let branch = current_branch(root, no_input);
    let packs_empty = vault.config.packs.is_empty();
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
            print_init_followup(packs_empty, remote, branch_name);
        }
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(mut scaffold) = scaffold {
        scaffold.disarm();
    }
    if json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "command": "init",
                "branch": branch,
                "remote": remote.map(display_remote_url),
                "next_steps": init_next_steps(packs_empty, remote, branch_name),
            }),
        ))?;
    } else {
        println!("vault ready at {}", root.display());
        if let Some(branch) = &branch {
            println!("branch {branch}");
        }
        print_init_followup(packs_empty, remote, branch_name);
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

// ---------------------------------------------------------------------------
// merge-conflict resolution plumbing (plaintext)
// ---------------------------------------------------------------------------

/// Both sides of a conflicted record, reconstructed from the file's git
/// conflict markers (#451).
pub(crate) struct LoadedSides {
    /// Vault-relative path of the conflicted file.
    pub path: PathBuf,
    /// The `<<<<<<<` side, byte-exact.
    pub ours_bytes: Vec<u8>,
    /// The `>>>>>>>` side, byte-exact.
    pub theirs_bytes: Vec<u8>,
    /// The conflicted file's bytes as read (for rollback).
    pub raw: Vec<u8>,
    /// Label from the first hunk's `<<<<<<<` line (e.g. `HEAD`).
    pub ours_label: String,
    /// Label from the first hunk's `>>>>>>>` line (e.g. `feature/x`).
    pub theirs_label: String,
}

/// Load both sides of the conflicted record `id`.
///
/// The file path is derived from the id (never trusting a caller-supplied
/// path). Both sides must parse as records naming `id` with equal `type`.
fn load_sides(root: &Path, id: &RecordId) -> anyhow::Result<LoadedSides> {
    reject_unsupported_prefix(id)?;
    let rel = main_path_for(id).ok_or_else(|| {
        anyhow::Error::new(DomainError::usage(format!(
            "record resolve does not handle ids like {id}"
        )))
    })?;
    let bytes = std::fs::read(root.join(&rel)).map_err(|_| {
        anyhow::Error::new(DomainError::not_found(format!("no record with id {id}")))
            .context("use `confidant find <name>` to look up the id")
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        anyhow::Error::new(DomainError::invalid(format!(
            "{} is not valid UTF-8",
            rel.display()
        )))
    })?;
    if !confidant_core::record::has_conflict_markers(text) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!("{} has no merge conflict", rel.display()))
                .with_fix("Use `confidant record show --for-edit` to read it"),
        ));
    }
    let sides = confidant_core::conflict::split_conflict_sides(text).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot split the conflict in {}: {e}",
            rel.display()
        )))
    })?;
    let ours = parse_side("ours", &sides.ours, &rel, id)?;
    let theirs = parse_side("theirs", &sides.theirs, &rel, id)?;
    if ours.kind != theirs.kind {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "the two sides of {} have different record types",
            rel.display()
        ))));
    }
    Ok(LoadedSides {
        path: rel,
        ours_bytes: sides.ours.into_bytes(),
        theirs_bytes: sides.theirs.into_bytes(),
        raw: bytes,
        ours_label: sides.ours_label,
        theirs_label: sides.theirs_label,
    })
}

/// Parse one reconstructed side as a record naming `id`.
fn parse_side(side: &str, text: &str, rel: &Path, id: &RecordId) -> anyhow::Result<Record> {
    let rec = confidant_core::parse_record(text, &rel.display().to_string()).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "the {side} side of {} is not a readable record: {}",
            rel.display(),
            e.message
        )))
    })?;
    if rec.id != *id {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "the {side} side of {} holds a different record ({})",
            rel.display(),
            rec.id
        ))));
    }
    Ok(rec)
}

/// Outcome of `record resolve --take`.
#[derive(Debug)]
pub(crate) struct TakeOutcome {
    /// The next git step for the operator, e.g. `git merge --continue`.
    pub next: String,
}

/// Install one side byte for byte, verify the vault still checks clean for
/// this path, stage the file, and return the next git step.
pub(crate) fn take_side(
    root: &Path,
    no_input: bool,
    sides: &LoadedSides,
    side: Side,
) -> anyhow::Result<TakeOutcome> {
    let chosen: &[u8] = match side {
        Side::Ours => &sides.ours_bytes,
        Side::Theirs => &sides.theirs_bytes,
    };
    let rel = &sides.path;
    confidant_core::paths::write_replace(root, rel, chosen).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "could not install the {} side of {}: {e}",
            side.name(),
            rel.display()
        )))
    })?;

    if let Err(failure) = check_path_clean(root, rel) {
        let _ = confidant_core::paths::write_replace(root, rel, &sides.raw);
        return Err(failure);
    }

    if let Err(e) =
        confidant_core::write::git(root, &["add", "--", &rel.to_string_lossy()], no_input)
    {
        let _ = confidant_core::paths::write_replace(root, rel, &sides.raw);
        return Err(anyhow::Error::new(DomainError::internal(format!(
            "could not stage {}: {e}",
            rel.display()
        ))));
    }

    Ok(TakeOutcome {
        next: next_git_step(root),
    })
}

/// Reload the vault and require no error finding on `rel`.
fn check_path_clean(root: &Path, rel: &Path) -> anyhow::Result<()> {
    let vault = confidant_core::load_vault(root).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "could not reload the vault after installing {}: {e}",
            rel.display()
        )))
    })?;
    let report = confidant_core::check_vault(&vault, &CheckOptions::default());
    let rel_str = rel.to_string_lossy();
    if let Some(finding) = report.findings.iter().find(|f| {
        f.severity == confidant_core::Severity::Error && f.file.as_deref() == Some(rel_str.as_ref())
    }) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "installing the chosen side left {} with an error: {}",
                rel.display(),
                finding.message
            ))
            .with_fix("The conflicted file was restored; fix the underlying problem and retry"),
        ));
    }
    Ok(())
}

/// The next git step for the operator: `git merge --continue` while a merge
/// is in progress, `git rebase --continue` while a rebase is.
fn next_git_step(root: &Path) -> String {
    let git_dir = confidant_core::write::git(root, &["rev-parse", "--git-dir"], true)
        .map(|s| root.join(s.trim()))
        .unwrap_or_else(|_| root.join(".git"));
    if git_dir.join("MERGE_HEAD").exists() {
        "git merge --continue".to_owned()
    } else if git_dir.join("rebase-merge").exists() || git_dir.join("rebase-apply").exists() {
        "git rebase --continue".to_owned()
    } else if git_dir.join("CHERRY_PICK_HEAD").exists() {
        "git cherry-pick --continue".to_owned()
    } else {
        "git commit".to_owned()
    }
}

/// Outcome of `record resolve --merged-file` / `--edit`.
#[derive(Debug)]
pub(crate) struct MergeOutcome {
    /// The next git step for the operator.
    pub next: String,
    /// Vault-relative path of the resolved record.
    pub path: PathBuf,
}

/// Guard for `--edit` scratch files (#455).
///
/// Zero-overwrites each file (same length), syncs, removes the files and
/// the directory on drop. [`ScratchGuard::cleanup`] can also be called
/// explicitly on the success path (after which drop is a no-op).
#[cfg(unix)]
pub(crate) struct ScratchGuard {
    dir: PathBuf,
    files: Vec<PathBuf>,
}

#[cfg(unix)]
impl ScratchGuard {
    pub(crate) fn new(dir: PathBuf, files: Vec<PathBuf>) -> Self {
        ScratchGuard { dir, files }
    }

    /// Zero-overwrite, sync, and remove every file, then remove the dir.
    pub(crate) fn cleanup(&mut self) {
        use std::io::Write;
        for file in &self.files {
            if let Ok(len) = std::fs::metadata(file).map(|m| m.len()) {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(file) {
                    let zeros = vec![0u8; len as usize];
                    let _ = f.write_all(&zeros);
                    let _ = f.sync_all();
                }
            }
            let _ = std::fs::remove_file(file);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
        if let Some(parent) = self.dir.parent() {
            let _ = std::fs::remove_dir(parent);
        }
        self.files.clear();
    }
}

#[cfg(unix)]
impl Drop for ScratchGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Refuse to install merged text that still contains conflict markers.
///
/// The error names the first offending marker and its line number, never
/// the line's content: the merged text is operator plaintext and must not
/// reach logs or error output (rule 4).
pub(crate) fn refuse_merged_conflict_markers(text: &str, source: &str) -> Result<(), DomainError> {
    for (n, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let marker = if trimmed.starts_with("<<<<<<<") {
            "<<<<<<<"
        } else if trimmed.starts_with(">>>>>>>") {
            ">>>>>>>"
        } else if trimmed == "=======" {
            "======="
        } else {
            continue;
        };
        return Err(DomainError::usage(format!(
            "{source} still contains a conflict marker ({marker} at line {})",
            n + 1
        ))
        .with_fix(
            "Remove the conflict markers — keep the text you merged — then re-run the command",
        ));
    }
    Ok(())
}

/// The operator's merged file must live outside the vault so a plaintext
/// merge file cannot be committed by accident.
pub(crate) fn refuse_vault_path(root: &Path, path: &Path) -> anyhow::Result<PathBuf> {
    let canonical = path.canonicalize().map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            path.display()
        )))
    })?;
    let canonical_root = root.canonicalize().map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot resolve vault root {}: {e}",
            root.display()
        )))
    })?;
    if canonical.starts_with(&canonical_root) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "refusing to read a merge file inside the vault: {}",
                path.display()
            ))
            .with_fix("Put the merged file outside the vault tree"),
        ));
    }
    Ok(canonical)
}

/// Remove a stale `.confidant/conflicts/` dir left by a crashed
/// `resolve --edit`.
pub(crate) fn sweep_stale_scratch(root: &Path) {
    sweep_stale_scratch_under(&root.join(".confidant").join("conflicts"));
}

/// Remove a stale `.confidant/notes/` dir left by a crashed
/// `note edit --edit`.
pub(crate) fn sweep_stale_note_scratch(root: &Path) {
    sweep_stale_scratch_under(&root.join(".confidant").join("notes"));
}

/// Zero-overwrite every file under `dir`, then remove the tree. Best-effort.
fn sweep_stale_scratch_under(dir: &Path) {
    use std::io::Write;
    if !dir.exists() {
        return;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(len) = std::fs::metadata(&p).map(|m| m.len()) {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&p) {
                    let zeros = vec![0u8; len as usize];
                    let _ = f.write_all(&zeros);
                    let _ = f.sync_all();
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Apply a merged record (#455): write each planned change atomically,
/// verify no error finding on any changed path (rolling everything back on
/// failure), then stage every changed path.
pub(crate) fn apply_merge(
    root: &Path,
    no_input: bool,
    prepared: &PreparedWrite,
) -> anyhow::Result<MergeOutcome> {
    let mut originals: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for change in &prepared.pending.changes {
        let FileChange::WriteFile { path, .. } = change else {
            continue;
        };
        let bytes = std::fs::read(root.join(path)).unwrap_or_default();
        originals.push((path.clone(), bytes));
    }

    for change in &prepared.pending.changes {
        let FileChange::WriteFile { path, contents } = change else {
            continue;
        };
        confidant_core::paths::write_replace(root, path, contents.as_bytes()).map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "could not write {}: {e}",
                path.display()
            )))
        })?;
    }

    let mut failed: Option<anyhow::Error> = None;
    for (path, _) in &originals {
        if let Err(e) = check_path_clean(root, path) {
            failed = Some(e);
            break;
        }
    }
    if let Some(e) = failed {
        for (path, bytes) in &originals {
            let _ = confidant_core::paths::write_replace(root, path, bytes);
        }
        return Err(e);
    }

    for (path, _) in &originals {
        if let Err(e) =
            confidant_core::write::git(root, &["add", "--", &path.to_string_lossy()], no_input)
        {
            for (p, b) in &originals {
                let _ = confidant_core::paths::write_replace(root, p, b);
            }
            return Err(anyhow::Error::new(DomainError::internal(format!(
                "could not stage {}: {e}",
                path.display()
            ))));
        }
    }

    Ok(MergeOutcome {
        next: next_git_step(root),
        path: prepared.rel.clone(),
    })
}

/// Set up `--edit` scratch files (unix only).
#[cfg(unix)]
pub(crate) fn setup_edit_scratch(
    root: &Path,
    id: &RecordId,
    sides: &LoadedSides,
) -> anyhow::Result<(ScratchGuard, PathBuf)> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    ensure_corpus_gitignored(root).map_err(anyhow::Error::new)?;

    let dir = root
        .join(".confidant")
        .join("conflicts")
        .join(id.to_string());
    std::fs::create_dir_all(&dir).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot create scratch dir {}: {e}",
            dir.display()
        )))
    })?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot set permissions on {}: {e}",
            dir.display()
        )))
    })?;

    let ours_path = dir.join("ours.md");
    let theirs_path = dir.join("theirs.md");
    let merged_path = dir.join("merged.md");
    for (path, bytes) in [
        (&ours_path, sides.ours_bytes.as_slice()),
        (&theirs_path, sides.theirs_bytes.as_slice()),
        (&merged_path, sides.ours_bytes.as_slice()),
    ] {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                anyhow::Error::new(DomainError::internal(format!(
                    "cannot write scratch file {}: {e}",
                    path.display()
                )))
            })?;
        f.write_all(bytes).map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "cannot write scratch file {}: {e}",
                path.display()
            )))
        })?;
        f.sync_all().map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "cannot sync scratch file {}: {e}",
                path.display()
            )))
        })?;
    }

    let guard = ScratchGuard::new(dir, vec![ours_path, theirs_path, merged_path.clone()]);
    Ok((guard, merged_path))
}

/// Resolve the operator's editor: `$VISUAL`, then `$EDITOR`.
#[cfg(unix)]
pub(crate) fn resolve_editor() -> anyhow::Result<String> {
    std::env::var("VISUAL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .ok_or_else(|| {
            anyhow::Error::new(
                DomainError::usage("no editor configured")
                    .with_fix("Set $EDITOR or use --merged-file"),
            )
        })
}

/// Run the operator's editor on `path`.
#[cfg(unix)]
pub(crate) fn run_editor(path: &Path) -> anyhow::Result<()> {
    let editor = resolve_editor()?;
    let status = std::process::Command::new(&editor)
        .arg(path)
        .status()
        .map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "could not run editor '{editor}': {e}"
            )))
        })?;
    if !status.success() {
        return Err(anyhow::Error::new(
            DomainError::invalid("editor exited with an error; the merge was not applied")
                .with_fix("Fix the merge and retry, or use --merged-file"),
        ));
    }
    Ok(())
}

/// Set up `note edit --edit` scratch (unix only).
#[cfg(unix)]
pub(crate) fn setup_note_edit_scratch(
    root: &Path,
    id: &RecordId,
    text: &str,
) -> anyhow::Result<(ScratchGuard, PathBuf)> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    ensure_corpus_gitignored(root).map_err(anyhow::Error::new)?;

    let dir = root.join(".confidant").join("notes").join(id.to_string());
    std::fs::create_dir_all(&dir).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot create scratch dir {}: {e}",
            dir.display()
        )))
    })?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot set permissions on {}: {e}",
            dir.display()
        )))
    })?;

    let note_path = dir.join("note.md");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&note_path)
        .map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "cannot write scratch file {}: {e}",
                note_path.display()
            )))
        })?;
    f.write_all(text.as_bytes()).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot write scratch file {}: {e}",
            note_path.display()
        )))
    })?;
    f.sync_all().map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot sync scratch file {}: {e}",
            note_path.display()
        )))
    })?;

    let guard = ScratchGuard::new(dir, vec![note_path.clone()]);
    Ok((guard, note_path))
}

/// Run the operator's editor on a note's scratch file.
#[cfg(unix)]
pub(crate) fn run_note_editor(path: &Path) -> anyhow::Result<()> {
    let editor = resolve_editor()?;
    let status = std::process::Command::new(&editor)
        .arg(path)
        .status()
        .map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "could not run editor '{editor}': {e}"
            )))
        })?;
    if !status.success() {
        return Err(anyhow::Error::new(
            DomainError::invalid("editor exited with an error; the note was not changed")
                .with_fix("Fix the note and retry, or use --file"),
        ));
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
        parse_ahead_behind, parse_git_remotes, parse_git_version, parse_tui_version,
        reject_unsupported_prefix, sync_push_refspec, AheadBehind, InstallMethod, MIN_GIT_VERSION,
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

    /// #665: `git rev-list --left-right --count @{u}...HEAD` prints
    /// `<behind>\t<ahead>`; the right column is ahead, not behind.
    #[test]
    fn ahead_behind_parser_maps_left_to_behind() {
        assert_eq!(
            parse_ahead_behind("0\t2\n"),
            Some(AheadBehind {
                ahead: 2,
                behind: 0
            })
        );
        assert_eq!(
            parse_ahead_behind("3\t1\n"),
            Some(AheadBehind {
                ahead: 1,
                behind: 3
            })
        );
        assert_eq!(parse_ahead_behind(""), None);
        assert_eq!(parse_ahead_behind("not numbers"), None);
    }

    /// #665: `sync --push` sends HEAD to the upstream branch on the
    /// fetched remote, even when that branch name differs from HEAD.
    #[test]
    fn sync_push_refspec_uses_upstream_branch_on_the_fetched_remote() {
        assert_eq!(
            sync_push_refspec("origin", "origin/main").as_deref(),
            Some("HEAD:main")
        );
        assert_eq!(
            sync_push_refspec("origin", "origin/trunk").as_deref(),
            Some("HEAD:trunk")
        );
        assert_eq!(
            sync_push_refspec("origin", "origin/feature/foo").as_deref(),
            Some("HEAD:feature/foo")
        );
        assert_eq!(sync_push_refspec("origin", "upstream/main"), None);
        assert_eq!(sync_push_refspec("origin", "origin"), None);
        assert_eq!(sync_push_refspec("origin", "origin/"), None);
    }

    /// #653(d): `findmnt` output is a device path with an optional btrfs
    /// subvolume suffix; non-block sources cannot be traced through
    /// `lsblk` and must report status "unknown" (#709), never `ok`.
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

    /// #709: the `disk-encryption` decision for every probe shape.
    /// Undetermined shapes (no source, no TYPE list, empty TYPE list)
    /// are `unknown`, never `ok`; only a readable ancestry decides
    /// between `ok` (crypt present) and `warning` (no crypt).
    #[test]
    fn disk_encryption_check_status_rules() {
        use super::disk_encryption_check_from;
        // No source: findmnt missing, failed, or a non-block root
        // (e.g. overlay on a VM/container) — the issue's shape.
        let c = disk_encryption_check_from(None, None, "root filesystem is not on a block device");
        assert_eq!(c.status, "unknown");
        assert!(c.message.contains("could not determine disk encryption"));
        assert!(c.message.contains("not on a block device"));
        assert!(c.fix.is_none());
        // A device but no TYPE list: lsblk missing or failed.
        let c = disk_encryption_check_from(Some("/dev/sda2"), None, "lsblk is not available");
        assert_eq!(c.status, "unknown");
        assert!(c.message.contains("lsblk is not available"));
        // A device with an empty TYPE list: lsblk ran, said nothing.
        let c = disk_encryption_check_from(Some("/dev/sda2"), Some(""), "lsblk is not available");
        assert_eq!(c.status, "unknown");
        assert!(c.message.contains("lsblk returned no device types"));
        // Determined outcomes are unchanged.
        let c = disk_encryption_check_from(Some("/dev/sda2"), Some("crypt\npart\ndisk\n"), "");
        assert_eq!(c.status, "ok");
        assert!(c.message.contains("encrypted device"));
        let c = disk_encryption_check_from(Some("/dev/sda2"), Some("part\ndisk\n"), "");
        assert_eq!(c.status, "warning");
        assert!(c.message.contains("not on an encrypted disk"));
        assert!(c.fix.is_some());
    }

    /// #709: staleness the fetch cannot determine is `unknown`, not
    /// `ok`; an operator opt-out is the only `ok` non-determination.
    #[test]
    fn cli_staleness_check_unknown_rules() {
        use super::cli_staleness_check;
        let c = cli_staleness_check(None, false);
        assert_eq!(c.status, "unknown");
        assert!(c.message.contains("staleness unknown"));
        // An unparseable tag is undetermined the same way a failed
        // fetch is: neither proves the install is current.
        let c = cli_staleness_check(Some("not-a-version".to_owned()), false);
        assert_eq!(c.status, "unknown");
        let c = cli_staleness_check(None, true);
        assert_eq!(c.status, "ok");
        assert!(c.message.contains("disabled"));
    }

    /// #653(d): only a `crypt` ancestor means the root disk is encrypted.
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
        assert!(c.message.contains("upgrade git to >="));
        let c = git_version_check_from(Some((2, 33, 0)), false);
        assert_eq!(c.status, "warning");
        assert!(c.message.contains("upgrade git to >= 2.34.0"));

        // Undetermined version is `unknown` (#709), warning-tier, never
        // an error and never `ok`.
        let c = git_version_check_from(None, true);
        assert_eq!(c.status, "unknown");
    }

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
