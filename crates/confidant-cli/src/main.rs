//! `confidant` — local-first, git-backed, plaintext relationship memory.
//!
//! Read commands (`check`, `find`, `context`, `doctor`, `schema`, `help`)
//! never mutate the vault. Write commands (`log touch`, `import`,
//! `note add`) funnel through the [`write`] pipeline: one commit per write,
//! `check` runs before every commit and a failing check blocks the write.
//! `mcp` is a thin stdio JSON-RPC wrapper around this binary — never a
//! second way in.
//!
//! [`write`]: confidant_core::write

/// Load the vault for a command, returning the command's exit code on error.
///
/// Defined before the `mod commands;` declaration below on purpose: a
/// `macro_rules!` macro is scoped textually, so the child modules declared
/// after it can use it without an import.
macro_rules! vault_or {
    ($root:expr, $json:expr) => {
        match crate::load_vault_or($root, $json) {
            Ok(v) => v,
            Err(code) => return Ok(code),
        }
    };
}

mod commands;
mod embedded;
mod mcp;
mod pack_fetch;
mod pack_init;
mod setup;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::help::grouped_help_command;
use clap::{FromArgMatches, Parser, Subcommand};
use confidant_core::config::UserConfig;
use confidant_core::discover::{load_user_config, resolve, Discovery};
use confidant_core::error::DomainError;
use confidant_core::load_vault;
use confidant_core::scope::{parse_pack_list, resolve_scope, PackScope};
use serde_json::Value;

use commands::agents::{cmd_agents, cmd_routing, cmd_tui, cmd_which};
use commands::context::{cmd_alias_resolve, cmd_context, cmd_resolve};
use commands::corrections::{cmd_correct, cmd_record_retire, cmd_retract};
use commands::doctor::cmd_doctor;
use commands::find::cmd_find;
use commands::help::cmd_help;
use commands::import::cmd_import;
use commands::init::{bootstrap_vault, cmd_init, BootstrapPlan};
use commands::log::cmd_log_touch;
use commands::note::{cmd_note_add, cmd_note_edit, cmd_note_show};
use commands::pack::{
    cmd_pack_add, cmd_pack_init, cmd_pack_list, cmd_pack_remove, cmd_pack_update, cmd_pack_verify,
};
use commands::record::{
    cmd_record_add, cmd_record_edit, cmd_record_list, cmd_record_resolve, cmd_record_show,
};
use commands::schema::cmd_schema;
use commands::setup::cmd_setup;
use commands::status::cmd_status;
use commands::sync::cmd_sync;
use commands::update::cmd_update;

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
        Start here:        confidant setup --agent auto\n  \
        Everyday:          confidant log touch p-01H… meal --json --no-input\n  \
        Repair:            confidant retract p-01H… --line line:<hex> --reason duplicate\n  \
        Integrations:      confidant mcp\n  \
        Advanced / rare:   confidant schema --json\n  \
        Demo vault:        confidant check --vault ./examples/demo-vault"
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
        /// Include `no-ai` records, read through the operator path (the same
        /// mechanism as `record show --for-edit`).
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
        /// Approve an agent-initiated batch above the retraction/retirement
        /// safety cap (15% of live records, minimum 3). Operator approval;
        /// ignored for a human write.
        #[arg(long)]
        force: bool,
    },
    /// Retract a ledger line without editing or deleting it (#746).
    ///
    /// Appends one attributed `DATE retract …` line. The original stays in
    /// the ledger and in git history; `check` and agent reads skip it.
    /// Operator-only; never exposed over MCP.
    Retract {
        /// The target line's subject id (p-…, o-…, d-…, …).
        subject: String,
        /// Target line reference: line:<64 hex>, a unique ≥12-hex prefix,
        /// optionally with #<occurrence>. Omit to use the bulk selector
        /// (`--verb` + `--match-date` + `--keep`).
        #[arg(long, value_name = "REF")]
        line: Option<String>,
        /// 1-based occurrence for byte-identical lines (default from the
        /// ref, else 1).
        #[arg(long)]
        occurrence: Option<u32>,
        /// Closed reason: duplicate, wrong-date, wrong-kind, wrong-person,
        /// wrong-amount, wrong-note, wrong-record, typo, or other.
        #[arg(long)]
        reason: String,
        /// Optional replacement line reference (a correction without
        /// `correct`'s inline replacement text).
        #[arg(long, value_name = "REF")]
        replace: Option<String>,
        /// Bulk selector: only lines dated this YYYY-MM-DD.
        #[arg(long, value_name = "DATE")]
        match_date: Option<String>,
        /// Bulk selector: only this ledger verb (e.g. touch, session).
        #[arg(long)]
        verb: Option<String>,
        /// Bulk selector: only touch lines of this kind.
        #[arg(long)]
        kind: Option<String>,
        /// Bulk selector: keep the first N lines per identity group and
        /// retract the rest (default 1; 0 retracts the whole group).
        #[arg(long)]
        keep: Option<usize>,
        /// Retraction date YYYY-MM-DD (default today).
        #[arg(long)]
        date: Option<String>,
        /// Approve an agent-initiated batch above the retraction/retirement
        /// safety cap (15% of live records, minimum 3). Operator approval;
        /// ignored for a human write.
        #[arg(long)]
        force: bool,
    },
    /// Correct a ledger line: append a replacement and retract the original.
    ///
    /// Writes both lines in one commit. The original stays in the ledger and
    /// in git history. Operator-only; never exposed over MCP.
    Correct {
        /// The target line's subject id (p-…, o-…, d-…, …).
        subject: String,
        /// Target line reference (see `retract --line`).
        #[arg(long, value_name = "REF")]
        line: String,
        /// 1-based occurrence for byte-identical lines.
        #[arg(long)]
        occurrence: Option<u32>,
        /// The full replacement ledger line, e.g.
        /// `2026-10-08 touch p-… call`.
        #[arg(long, value_name = "LEDGER-LINE")]
        replacement: String,
        /// Closed reason token (see `retract --reason`).
        #[arg(long)]
        reason: String,
        /// Correction date YYYY-MM-DD (default today).
        #[arg(long)]
        date: Option<String>,
    },
    /// Manage notes (one commit per write).
    Note {
        #[command(subcommand)]
        action: NoteAction,
    },
    /// Create or manage records (one commit per write).
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
    /// Context bundle for one entity: a person, org, or declared entity type
    /// (honors no-ai).
    ///
    /// Operator-only flag: `--for-operator` includes `no-ai` records the
    /// default (agent) allowlist hides. It is never passed by MCP.
    Context {
        /// Opaque entity id (p-…, o-…, or a declared pack type id) or an
        /// exact person display name (cleared people only; see `confidant
        /// resolve`). Non-person names are not resolved by name; use `find`
        /// for the id.
        #[arg(value_name = "ENTITY")]
        person: String,
        /// Strip private data: name, profile, bodies, edge endpoint names,
        /// and the personal pack's PII fields (`birthday`, `dates`,
        /// `relationship`, `location`, `emails`, `phones`, `links`, `tags`).
        #[arg(long)]
        exclude_private: bool,
        /// Include `no-ai` records, read through the operator path (the same
        /// mechanism as `record show --for-edit`).
        #[arg(long)]
        for_operator: bool,
    },
    /// Vault health checks.
    Doctor,
    /// One-screen readiness rollup and the completion brief for this install.
    ///
    /// Reports CLI/TUI versions, vault discovery and writability, skill
    /// links, system-of-record instructions, git sync state, QMD corpus
    /// state, and binary staleness. Optional layers report `absent`, never
    /// a false `ok` (#709, #716, #733). Exits 1 when a required check is
    /// not `ok`; warnings on optional layers do not fail it.
    Status,
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
    /// the directory is created, `git init -b main` runs when needed,
    /// `.gitignore` gains `.confidant/`, the collection directories
    /// (`people/`, `orgs/`, `deals/`, `interactions/`, `notes/`, `edges/`,
    /// `ledger/`) are created, and a minimal `confidant.toml` is written
    /// (its `packs` list comes from the global `--packs` flag, defaulting
    /// to `[]`) and committed. A neutral repo-local git identity is set
    /// (even when a global one exists, so it never leaks into the vault's
    /// history); a per-vault identity already in `.git/config` is kept.
    /// `--remote <url>` then adds `origin` (it does not push). Only packs
    /// built into this binary (today the implicit `personal@0.2`) may be
    /// listed: an external pack is vendored into an existing vault by
    /// `confidant pack add`, so install it after `init`.
    ///
    /// `--dry-run` runs every preflight check and reports the plan without
    /// creating a directory, writing a file, making a commit, or adding a
    /// remote.
    Init {
        /// Scaffold the vault directory (create, `git init -b main`,
        /// `.gitignore`, `confidant.toml`, collection directories,
        /// committed skeleton).
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
        /// Do not write the system-of-record rule into agent instruction files.
        #[arg(long, default_value_t = false)]
        no_instructions: bool,
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
        /// How long the touch lasted (for example 60m, 1h, 1h30m), stored
        /// as duration:<minutes>m (#741).
        #[arg(long)]
        duration: Option<String>,
        /// Social mode: one-on-one or group (#741).
        #[arg(long)]
        mode: Option<String>,
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
    /// case-insensitively against the person's `emails`/`phones`/`handles`
    /// (or the value half of a `links` entry), or their display name for
    /// `name`, plus the typed `alias_history` entries of that kind (#739).
    /// Current values are preferred over historical ones. Honors `no-ai`
    /// like other reads: a `no-ai: true` person is not surfaced.
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
        /// Unlist the pack but keep its vendored files and lock entry, so
        /// its data and `[checks]` keys warn `W_PACK_ORPHAN` until migrated.
        /// A later `pack remove` (no flag) deletes them once the data is gone.
        #[arg(long)]
        allow_unresolved: bool,
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
    /// Retire a record: keep its file and history, remove it from agent reads.
    ///
    /// Writes canonical `retired: true` in one commit. Operator-only; never
    /// exposed over MCP. Refuses a merged-away id.
    Retire {
        /// Opaque record id (p-…, o-…, d-…, i-…, e-…).
        id: String,
    },
    /// Undo a retirement: remove `retired: true` in one commit.
    Unretire {
        /// Opaque record id (p-…, o-…, d-…, i-…, e-…).
        id: String,
    },
    /// List the vault's records, one entry each.
    ///
    /// Defaults to every identity kind (`person`, `org`, `deal`), so orgs
    /// are visible without already knowing to ask for them. Operator-only:
    /// this command is never exposed over MCP (`mcp.rs` maps a fixed tool
    /// whitelist), and without `--for-operator` it lists only the §12
    /// cleared set, so `no-ai: true` records are absent. With
    /// `--for-operator` an operator may see them, with a tri-state
    /// `no_ai` (`"true"`, `"notes"`, `"false"`). The resolved vault path
    /// stays in the JSON envelope (ADR-7).
    List {
        /// Include `no-ai` records and orphaned pack-type records, read
        /// through the operator path (the same mechanism as `record show
        /// --for-edit`).
        #[arg(long)]
        for_operator: bool,
        /// Record kind to list: all (default), person, org, deal, or a
        /// declared pack type name.
        #[arg(long, default_value = "all")]
        kind: String,
    },
    /// Print one record's text, to prepare an edit.
    ///
    /// Operator-only. This command is never exposed over MCP (`mcp.rs` maps
    /// a fixed tool whitelist), and `--for-edit` is required so a bare
    /// invocation cannot print a record body.
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

#[derive(Subcommand, Debug)]
enum NoteAction {
    /// Create a note record under people/<person>/notes/ or notes/<id>/note.md.
    #[command(group(
        clap::ArgGroup::new("note_subject").required(true).multiple(false)
    ))]
    Add {
        /// Opaque person id (p-…) or an exact display name (cleared people
        /// only; see `confidant resolve`).
        #[arg(long, group = "note_subject")]
        person: Option<String>,
        /// Opaque entity id (p-…, o-…, or a declared entity). Writes a
        /// top-level note with `entity:` so it can attach to any entity.
        #[arg(long, group = "note_subject")]
        entity: Option<String>,
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
    /// Print one note's text, to prepare an edit.
    ///
    /// Operator-only. This command is never exposed over MCP (`mcp.rs` maps
    /// a fixed tool whitelist), and `--for-edit` is required so a bare
    /// invocation cannot print a note body. Notes are where
    /// `no-ai` prose lives, so `no-ai` notes are printed in full here
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
    /// convention). The write goes through the normal pipeline, so it runs
    /// `check` before the commit and makes one commit; identical bytes report
    /// `unchanged` and commit nothing.
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

/// Parse argv with the journey-grouped top-level help attached (#721).
///
/// `Cli::try_parse()` builds the derive command directly; this keeps the
/// same parse path but swaps in the human help template. `help --json` and
/// `help <command>` still read `Cli::command()` and are unchanged.
fn parse_cli() -> Result<Cli, clap::Error> {
    let mut matches = grouped_help_command().try_get_matches()?;
    Cli::from_arg_matches_mut(&mut matches)
}

fn main() -> ExitCode {
    let json_hint = std::env::args_os().any(|a| a == "--json");
    let cli = match parse_cli() {
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
            | Command::Status
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
        } => commands::bench::cmd_bench_gen(json, dir, *people, *notes, *cjk, *touch),
        Command::Check { fail_on, as_of } => {
            let root = vault_root.unwrap();
            commands::check::cmd_check(json, &root, fail_on, as_of.as_deref())
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
            commands::check::cmd_allowlist(&cli, json, &root)
        }
        Command::Log { action } => {
            let root = vault_root.unwrap();
            match action {
                LogAction::Touch {
                    person,
                    kind,
                    date,
                    note,
                    src,
                    duration,
                    mode,
                    force,
                } => cmd_log_touch(
                    &cli,
                    &root,
                    person,
                    kind,
                    date.clone(),
                    note.clone(),
                    src.clone(),
                    duration.clone(),
                    mode.clone(),
                    *force,
                ),
            }
        }
        Command::Import { file, force } => {
            let root = vault_root.unwrap();
            cmd_import(&cli, &root, file, *force)
        }
        Command::Note { action } => {
            let root = vault_root.unwrap();
            match action {
                NoteAction::Add {
                    person,
                    entity,
                    date,
                    no_ai,
                    id,
                    body_file,
                } => cmd_note_add(
                    &cli,
                    &root,
                    person.as_deref(),
                    entity.as_deref(),
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
            PackAction::Remove {
                name,
                yes,
                allow_unresolved,
            } => cmd_pack_remove(
                &cli,
                vault_root.as_deref(),
                name.clone(),
                *yes,
                *allow_unresolved,
            )
            .map_err(pack_fetch::escape_domain_error),
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
        Command::Retract {
            subject,
            line,
            occurrence,
            reason,
            replace,
            match_date,
            verb,
            kind,
            keep,
            date,
            force,
        } => {
            let root = vault_root.unwrap();
            cmd_retract(
                &cli,
                &root,
                subject,
                line.as_deref(),
                *occurrence,
                reason.to_string(),
                replace.as_deref(),
                match_date.as_deref(),
                verb.as_deref(),
                kind.as_deref(),
                *keep,
                date.as_deref(),
                *force,
            )
        }
        Command::Correct {
            subject,
            line,
            occurrence,
            replacement,
            reason,
            date,
        } => {
            let root = vault_root.unwrap();
            cmd_correct(
                &cli,
                &root,
                subject,
                line,
                *occurrence,
                replacement.to_string(),
                reason.to_string(),
                date.as_deref(),
            )
        }
        Command::Record { action } => {
            let root = vault_root.unwrap();
            match action {
                RecordAction::Add { file } => cmd_record_add(&cli, &root, file),
                RecordAction::Edit { id, file } => cmd_record_edit(&cli, &root, id, file),
                RecordAction::Retire { id } => cmd_record_retire(&cli, &root, id, true),
                RecordAction::Unretire { id } => cmd_record_retire(&cli, &root, id, false),
                RecordAction::List { for_operator, kind } => {
                    cmd_record_list(&cli, &root, kind, *for_operator)
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
        Command::Status => cmd_status(&cli, vault_root.as_deref()),
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
            no_instructions,
            verbose,
        } => cmd_setup(
            &cli,
            agent,
            *force,
            *copy,
            *no_instructions,
            *verbose,
            vault_root.as_deref(),
        ),
        Command::Update {
            agent,
            force,
            verbose,
        } => cmd_update(&cli, agent, *force, *verbose),
        Command::Agents { verbose } => cmd_agents(&cli, *verbose),
        Command::Which { skills_dir } => cmd_which(&cli, *skills_dir),
        Command::Routing => cmd_routing(&cli, vault_root.as_deref()),
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

/// Refuse a vault written by the encrypted Confidant (≤0.7) (#821).
///
/// The sniff is read-only and returns only a boolean; the command error
/// carries the same message as the `check` finding and the `doctor` check.
/// Every agent-facing read calls this after loading and before reading
/// content, so a legacy vault fails closed instead of returning an empty or
/// partial result.
fn legacy_vault_gate(root: &Path) -> Result<(), DomainError> {
    if confidant_core::vault::is_legacy_encrypted_vault(root) {
        Err(DomainError::vault_legacy_encrypted())
    } else {
        Ok(())
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
    use crate::commands::doctor::{
        git_version_check_from, looks_like_version_or_usage, parse_ahead_behind, parse_git_remotes,
        parse_git_version, parse_tui_version, sync_push_refspec, AheadBehind, MIN_GIT_VERSION,
    };
    use crate::commands::help::JOURNEYS;
    use crate::commands::install::{confirm_yn, offerable_update, InstallMethod};
    use crate::commands::record::reject_unsupported_prefix;
    use crate::commands::update::{parse_sha256_sum, sha256_hex, verify_installer};
    use crate::Cli;
    use clap::CommandFactory;
    use std::path::{Path, PathBuf};

    /// #854: only the first non-empty probe line is judged. A canned hit list
    /// can carry a version-shaped score like `0.87` (or the tool name) on a
    /// later line, and that must not make a shim look like an installed qmd.
    #[test]
    fn qmd_probe_trusts_only_the_first_nonempty_line() {
        assert!(looks_like_version_or_usage("qmd 1.0.0"));
        assert!(looks_like_version_or_usage("\n\n  qmd 1.0.0\nusage..."));
        assert!(looks_like_version_or_usage("1.2.3"));
        assert!(looks_like_version_or_usage("Usage: qmd [options]"));
        assert!(!looks_like_version_or_usage(""));
        assert!(!looks_like_version_or_usage("  \n\t\n"));
        assert!(
            !looks_like_version_or_usage(
                "Robin Example — canned search hit\nscore 0.87\nqmd 1.0.0"
            ),
            "a later score or tool name must not rescue canned hits"
        );
        assert!(!looks_like_version_or_usage("search results:\nqmd 1.0.0\n"));
    }

    /// #721: every visible command sits in exactly one journey, so the
    /// grouped human help can never silently drop a command (hidden
    /// `bench-gen` stays out, as it does from clap's own help).
    #[test]
    fn journey_groups_cover_every_visible_command() {
        let command = Cli::command();
        let mut visible: Vec<&str> = command
            .get_subcommands()
            .filter(|sc| !sc.is_hide_set())
            .map(|sc| sc.get_name())
            .collect();
        let mut grouped: Vec<&str> = JOURNEYS
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        visible.sort_unstable();
        grouped.sort_unstable();
        assert_eq!(grouped, visible);
    }

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

    /// #660: transport classification decides whether a vault's content
    /// crosses the network readable. Encrypted and local transports are
    /// safe; `http://` and `git://` are cleartext; an unknown scheme is
    /// left unverified.
    #[test]
    fn git_remote_transport_classification() {
        use crate::commands::doctor::{remote_transport, RemoteTransport};
        for url in [
            "https://host.example/org/repo.git",
            "HTTPS://host.example/org/repo.git",
            "ssh://git@host.example/org/repo.git",
            "git@host.example:org/repo.git",
            "host.example:org/repo.git",
            "file:///srv/remote.git",
            "/srv/remote.git",
            "../remote.git",
            "remote.git",
        ] {
            assert_eq!(remote_transport(url), RemoteTransport::Safe, "{url}");
        }
        assert_eq!(
            remote_transport("http://host.example/org/repo.git"),
            RemoteTransport::Cleartext("http")
        );
        assert_eq!(
            remote_transport("git://host.example/org/repo.git"),
            RemoteTransport::Cleartext("git")
        );
        assert_eq!(
            remote_transport("ftp://host.example/org/repo.git"),
            RemoteTransport::Unverified
        );
    }

    /// `git remote -v` can list distinct fetch and push URLs; both survive
    /// parsing under the remote's name.
    #[test]
    fn git_remote_urls_keep_fetch_and_push() {
        use crate::commands::doctor::parse_git_remote_urls;
        let out = "\
origin\thttps://host.example/org/repo.git (fetch)
origin\tssh://git@host.example/org/repo.git (push)
";
        assert_eq!(
            parse_git_remote_urls(out),
            vec![
                (
                    "origin".to_owned(),
                    "https://host.example/org/repo.git".to_owned()
                ),
                (
                    "origin".to_owned(),
                    "ssh://git@host.example/org/repo.git".to_owned()
                ),
            ]
        );
        assert!(parse_git_remote_urls("").is_empty());
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

    /// #709: staleness the fetch cannot determine is `unknown`, not
    /// `ok`; an operator opt-out is the only `ok` non-determination.
    #[test]
    fn cli_staleness_check_unknown_rules() {
        use crate::commands::doctor::cli_staleness_check;
        let c = cli_staleness_check(None, false, None);
        assert_eq!(c.status, "unknown");
        assert!(c.message.contains("staleness unknown"));
        // An unparseable tag is undetermined the same way a failed
        // fetch is: neither proves the install is current.
        let c = cli_staleness_check(Some("not-a-version".to_owned()), false, None);
        assert_eq!(c.status, "unknown");
        let c = cli_staleness_check(None, true, None);
        assert_eq!(c.status, "ok");
        assert!(c.message.contains("disabled"));
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
        use crate::commands::install::detect_install_method_from_path;
        // `cargo install` lands in `<cargo-home>/bin`.
        assert_eq!(
            detect_install_method_from_path(Path::new("/home/ada/.cargo/bin/confidant")),
            InstallMethod::CargoInstall
        );
        // Windows separators stay detectable on every platform.
        assert_eq!(
            detect_install_method_from_path(Path::new(
                "C:\\Users\\ada\\.cargo\\bin\\confidant.exe"
            )),
            InstallMethod::CargoInstall
        );
        // Homebrew: a versioned keg in the Cellar or a plain prefix bin.
        assert_eq!(
            detect_install_method_from_path(Path::new("/opt/homebrew/bin/confidant")),
            InstallMethod::Brew
        );
        assert_eq!(
            detect_install_method_from_path(Path::new(
                "/usr/local/Cellar/confidant/0.8.0/bin/confidant"
            )),
            InstallMethod::Brew
        );
        // Anything else is unknown, so `update` falls back to the generic
        // wording and offers nothing to run.
        assert_eq!(
            detect_install_method_from_path(Path::new("/usr/local/bin/confidant")),
            InstallMethod::Unknown
        );
        assert_eq!(
            detect_install_method_from_path(Path::new("confidant")),
            InstallMethod::Unknown
        );
    }

    fn receipt(path: &str, prefix: &str) -> crate::commands::install::InstallReceipt {
        crate::commands::install::InstallReceipt {
            path: PathBuf::from(path),
            install_prefix: PathBuf::from(prefix),
        }
    }

    #[test]
    fn installer_root_uses_the_running_binarys_bin_directory() {
        use crate::commands::update::cargo_dist_install_root;

        let exe = Path::new("/home/ada/.cargo/bin/confidant");
        let root = PathBuf::from("/home/ada/.cargo");
        assert_eq!(cargo_dist_install_root(&root, exe), Some(root.clone()));
        assert_eq!(cargo_dist_install_root(&root.join("bin"), exe), Some(root));
        assert_eq!(
            cargo_dist_install_root(
                Path::new("/home/ada/.cargo"),
                Path::new("/home/ada/.cargo/other/confidant")
            ),
            None,
        );
    }

    #[test]
    fn install_receipt_detection_covers_the_running_copy() {
        use crate::commands::install::detect_install_with_receipt;
        // The receipt names the `bin` dir (cargo-dist's CARGO_HOME shape).
        let detection = detect_install_with_receipt(
            Path::new("/home/ada/.cargo/bin/confidant"),
            Some(receipt(
                "/home/ada/.config/confidant-cli/confidant-cli-receipt.json",
                "/home/ada/.cargo/bin",
            )),
        );
        assert_eq!(
            detection.method,
            InstallMethod::CargoDist {
                install_prefix: PathBuf::from("/home/ada/.cargo/bin")
            }
        );
        assert!(detection.stray_receipt.is_none());

        // Or the prefix root (`~/.cargo`); both contain the binary.
        let detection = detect_install_with_receipt(
            Path::new("/home/ada/.cargo/bin/confidant"),
            Some(receipt("/receipt.json", "/home/ada/.cargo")),
        );
        assert_eq!(
            detection.method,
            InstallMethod::CargoDist {
                install_prefix: PathBuf::from("/home/ada/.cargo")
            }
        );

        // A one-liner install into ~/.local/bin, with Windows separators in
        // the receipt, stays detectable on any platform.
        let detection = detect_install_with_receipt(
            Path::new("C:\\Users\\ada\\.local\\bin\\confidant.exe"),
            Some(receipt("C:\\receipt.json", "C:\\Users\\ada\\.local\\bin")),
        );
        assert!(matches!(detection.method, InstallMethod::CargoDist { .. }));
    }

    #[test]
    fn install_receipt_for_a_different_copy_is_never_trusted() {
        use crate::commands::install::detect_install_with_receipt;
        // The receipt names ~/.local/bin, but this binary runs from
        // ~/.cargo/bin: two copies, so the receipt is not CargoDist and
        // `update` can refuse loudly instead of replacing the wrong one.
        let detection = detect_install_with_receipt(
            Path::new("/home/ada/.cargo/bin/confidant"),
            Some(receipt("/receipt.json", "/home/ada/.local/bin")),
        );
        assert_eq!(detection.method, InstallMethod::Unknown);
        assert_eq!(
            detection.stray_receipt,
            Some(receipt("/receipt.json", "/home/ada/.local/bin"))
        );

        // A prefix that is only a string prefix (not a path boundary) does
        // not count either.
        let detection = detect_install_with_receipt(
            Path::new("/home/ada/.local/bin/confidant"),
            Some(receipt("/receipt.json", "/home/ada/.local/b")),
        );
        assert_eq!(detection.method, InstallMethod::Unknown);
        assert!(detection.stray_receipt.is_some());
    }

    #[test]
    fn install_receipt_parsing_is_fail_closed() {
        use crate::commands::install::read_install_receipt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt.json");

        // Absent: no receipt, no CargoDist guess.
        assert!(read_install_receipt(&path).is_none());

        // Malformed JSON: same.
        std::fs::write(&path, "{not json").unwrap();
        assert!(read_install_receipt(&path).is_none());

        // Well-formed JSON without an install_prefix: same.
        std::fs::write(&path, r#"{"version":"0.8.0"}"#).unwrap();
        assert!(read_install_receipt(&path).is_none());

        // Empty install_prefix: same.
        std::fs::write(&path, r#"{"install_prefix":""}"#).unwrap();
        assert!(read_install_receipt(&path).is_none());

        // The shape cargo-dist writes.
        std::fs::write(
            &path,
            r#"{"install_prefix":"/home/ada/.cargo/bin","binaries":["confidant"],"source":{"release_type":"github","owner":"hirefrank","name":"confidant","app_name":"confidant-cli"},"version":"0.8.0","provider":{"source":"cargo-dist","version":"0.32.0"}}"#,
        )
        .unwrap();
        let receipt = read_install_receipt(&path).expect("receipt parses");
        assert_eq!(
            receipt.install_prefix,
            PathBuf::from("/home/ada/.cargo/bin")
        );
        assert_eq!(receipt.path, path);
    }

    #[test]
    fn receipt_roots_follow_the_installer_search_order() {
        use crate::commands::install::receipt_config_roots;
        // Unix: XDG first, then ~/.config; LOCALAPPDATA is ignored.
        let roots = receipt_config_roots(
            Some(PathBuf::from("/xdg")),
            Some(PathBuf::from("/local-app-data")),
            Some(PathBuf::from("/home/ada")),
            false,
        );
        assert_eq!(
            roots,
            vec![
                PathBuf::from("/xdg/confidant-cli"),
                PathBuf::from("/home/ada/.config/confidant-cli"),
            ]
        );
        // No XDG: only the home fallback.
        let roots = receipt_config_roots(None, None, Some(PathBuf::from("/home/ada")), false);
        assert_eq!(
            roots,
            vec![PathBuf::from("/home/ada/.config/confidant-cli")]
        );
        // Windows (unsupported as a target, but parity with the installer):
        // LOCALAPPDATA replaces ~/.config.
        let roots = receipt_config_roots(
            None,
            Some(PathBuf::from("C:\\Users\\ada\\AppData\\Local")),
            Some(PathBuf::from("C:\\Users\\ada")),
            true,
        );
        assert_eq!(
            roots,
            vec![PathBuf::from("C:\\Users\\ada\\AppData\\Local").join("confidant-cli")]
        );
        // An empty variable is treated as unset.
        assert!(receipt_config_roots(None, None, None, false).is_empty());
    }

    #[test]
    fn install_method_commands() {
        let cargo = InstallMethod::CargoInstall;
        assert_eq!(cargo.as_str(), "cargo-install");
        assert_eq!(cargo.update_command(), Some("cargo install confidant-cli"));
        let (program, args) = cargo.run_spec().unwrap();
        assert_eq!(program, "cargo");
        assert_eq!(args, &["install", "confidant-cli"]);
        assert!(!cargo.self_updates());

        let brew = InstallMethod::Brew;
        assert_eq!(brew.as_str(), "brew");
        assert_eq!(brew.update_command(), Some("brew upgrade confidant-cli"));
        assert_eq!(brew.run_spec(), None);
        assert!(!brew.self_updates());

        let dist = InstallMethod::CargoDist {
            install_prefix: PathBuf::from("/home/ada/.cargo/bin"),
        };
        assert_eq!(dist.as_str(), "cargo-dist");
        let cmd = dist.update_command().unwrap();
        assert!(cmd.contains("confidant-cli-installer.sh"), "{cmd}");
        assert!(
            cmd.contains("curl --proto '=https' --tlsv1.2 -LsSf"),
            "{cmd}"
        );
        assert!(cmd.ends_with("| sh"), "{cmd}");
        assert_eq!(dist.run_spec(), None);
        assert!(dist.self_updates());

        let unknown = InstallMethod::Unknown;
        assert_eq!(unknown.as_str(), "unknown");
        assert_eq!(unknown.update_command(), None);
        assert_eq!(unknown.run_spec(), None);
        assert!(!unknown.self_updates());
    }

    #[test]
    fn sha256_hex_matches_a_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn release_checksums_parse_both_sum_styles() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let text = format!(
            "{a} *confidant-cli-x86_64-unknown-linux-gnu.tar.xz\n\
             {b}  source.tar.gz\n\
             not a checksum line\n"
        );
        assert_eq!(
            parse_sha256_sum(&text),
            vec![
                (
                    "confidant-cli-x86_64-unknown-linux-gnu.tar.xz".to_owned(),
                    a.clone()
                ),
                ("source.tar.gz".to_owned(), b),
            ]
        );
        assert!(parse_sha256_sum("").is_empty());
        assert!(parse_sha256_sum("zz *short").is_empty());
    }

    #[test]
    fn installer_verification_prefers_a_published_installer_checksum() {
        let installer = b"#!/bin/sh\n_checksum_value=\"not-hex\"\n";
        let sums = vec![(
            "confidant-cli-installer.sh".to_owned(),
            sha256_hex(installer),
        )];
        assert!(verify_installer(
            "v9.9.9",
            installer,
            &sums,
            "confidant-cli-x86_64-unknown-linux-gnu.tar.xz"
        )
        .is_ok());
        // A future release that publishes an installer line gets the
        // strongest check: a mismatch refuses before the fallback.
        let wrong = vec![("confidant-cli-installer.sh".to_owned(), "0".repeat(64))];
        let err = verify_installer("v9.9.9", installer, &wrong, "x").unwrap_err();
        assert!(
            format!("{err:#}").contains("does not match sha256.sum"),
            "{err:#}"
        );
    }

    #[test]
    fn installer_verification_cross_checks_embedded_archive_checksums() {
        let archive = "confidant-cli-x86_64-unknown-linux-gnu.tar.xz";
        let ours = "a".repeat(64);
        let other = "b".repeat(64);
        let sums = vec![
            (archive.to_owned(), ours.clone()),
            ("source.tar.gz".to_owned(), other.clone()),
        ];
        // Every embedded hash is published, and ours is covered: run.
        let good = format!("_checksum_value=\"{ours}\"\n_checksum_value=\"{other}\"\n");
        assert!(verify_installer("v9.9.9", good.as_bytes(), &sums, archive).is_ok());
        // An embedded hash absent from sha256.sum: refuse.
        let tampered = format!("_checksum_value=\"{}\"\n", "c".repeat(64));
        let err = verify_installer("v9.9.9", tampered.as_bytes(), &sums, archive).unwrap_err();
        assert!(format!("{err:#}").contains("not in sha256.sum"), "{err:#}");
        // No embedded checksums at all: refuse.
        let err = verify_installer("v9.9.9", b"#!/bin/sh\n", &sums, archive).unwrap_err();
        assert!(
            format!("{err:#}").contains("embeds no archive checksums"),
            "{err:#}"
        );
        // The platform archive is not listed: refuse.
        let err = verify_installer(
            "v9.9.9",
            good.as_bytes(),
            &sums,
            "confidant-cli-other.tar.xz",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("do not cover"), "{err:#}");
    }

    #[test]
    fn offerable_update_needs_known_method_and_safe_replacement() {
        assert!(offerable_update(&InstallMethod::CargoInstall, true));
        // Unsafe replacement: print only.
        assert!(!offerable_update(&InstallMethod::CargoInstall, false));
        // Unknown method: nothing to run.
        assert!(!offerable_update(&InstallMethod::Unknown, true));
        assert!(!offerable_update(&InstallMethod::Unknown, false));
        // Brew and cargo-dist are never offered as a shell command: brew is
        // guidance only, cargo-dist self-replaces.
        assert!(!offerable_update(&InstallMethod::Brew, true));
        assert!(!offerable_update(
            &InstallMethod::CargoDist {
                install_prefix: PathBuf::from("/home/ada/.cargo/bin")
            },
            true
        ));
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
        let c = git_version_check_from(Some(MIN_GIT_VERSION));
        assert_eq!(c.status, "ok");
        assert!(c.message.contains("2.34.0"));
        let c = git_version_check_from(Some((2, 50, 0)));
        assert_eq!(c.status, "ok");

        // Below the floor: a warning, never an error (nothing here verifies
        // signatures).
        let c = git_version_check_from(Some((2, 33, 0)));
        assert_eq!(c.status, "warning");
        assert!(c.message.contains("upgrade git to >= 2.34.0"));
        assert!(c.message.contains("upgrade git to >="));

        // Undetermined version is `unknown` (#709), warning-tier, never
        // an error and never `ok`.
        let c = git_version_check_from(None);
        assert_eq!(c.status, "unknown");
    }

    #[test]
    fn external_pack_label_strips_source_userinfo() {
        use crate::commands::help::{external_pack_label_line, sanitize_pack_source};
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
        use crate::commands::shared::display_remote_url;
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
        use crate::commands::help::external_pack_label_line;
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
