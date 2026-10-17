//! Application state machine for `confidant-tui`.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::theme;

use crate::apply::{ApplyFlow, FlowPhase, StepApplyOutcome, StepStatus};
use crate::contract::{
    parse_raw_output, CheckReport, Context, ContractOutcome, DoctorReport, FindResult, InboxReport,
    ResolveApplied, ResolveShow, SearchResult,
};
use crate::proposals::{discover_proposals, resolve_vault_root, DiscoveredProposal};
use crate::runner::{RawOutput, Runner};
use crate::search::{filter_search_result, find_result_to_search, SearchViewState};
use crate::views::alert::{self, AlertState};
use crate::views::check::{self, CheckViewState};
use crate::views::confirm::{self, ConfirmState};
use crate::views::conflict::{self, ConflictAction, ConflictListEntry, ConflictViewState};
use crate::views::context::{self, ContextViewState};
use crate::views::diff::{self, DiffState};
use crate::views::doctor::{self, DoctorViewState};
use crate::views::inbox::{self, InboxViewState};
use crate::views::proposals::{
    self, ProposalDetailState, ProposalListEntry, ProposalsListState, StepRow,
};
use crate::views::search;

/// The seven views: Check, Context, Doctor, Proposals, unified
/// Search (qmd-ranked with an exact `find` toggle), Inbox, Conflicts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ActiveView {
    #[default]
    Check,
    Context,
    Doctor,
    Proposals,
    Search,
    Inbox,
    Conflicts,
}

impl ActiveView {
    pub fn next(self) -> Self {
        match self {
            Self::Check => Self::Context,
            Self::Context => Self::Doctor,
            Self::Doctor => Self::Proposals,
            Self::Proposals => Self::Search,
            Self::Search => Self::Inbox,
            Self::Inbox => Self::Conflicts,
            Self::Conflicts => Self::Check,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Check => Self::Conflicts,
            Self::Context => Self::Check,
            Self::Doctor => Self::Context,
            Self::Proposals => Self::Doctor,
            Self::Inbox => Self::Search,
            Self::Search => Self::Proposals,
            Self::Conflicts => Self::Inbox,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Check => "1:Check",
            Self::Context => "2:Context",
            Self::Doctor => "3:Doctor",
            Self::Proposals => "4:Proposals",
            Self::Search => "5:Search",
            Self::Inbox => "6:Inbox",
            Self::Conflicts => "7:Conflicts",
        }
    }
}

/// State for the proposals tab: the discovered manifests and the open flow.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProposalsTab {
    pub vault_root: Option<std::path::PathBuf>,
    pub entries: Vec<ProposalListEntry>,
    pub selected: usize,
    pub opened: Option<ApplyFlow>,
    pub load_error: Option<String>,
    loaded: bool,
}

/// Keyboard input mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InputMode {
    #[default]
    Normal,
    EditingSearch,
}

/// An interactive `confidant` invocation the TUI must run outside its
/// alternate screen (#456 hand-merge): the host suspends the terminal,
/// runs the argv, then resumes and refreshes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SuspendedCommand {
    pub args: Vec<String>,
}

/// Top-level TUI state machine generic over a [`Runner`].
pub struct App<R: Runner> {
    pub runner: R,
    pub active_view: ActiveView,
    pub input_mode: InputMode,
    pub vault: Option<String>,
    pub check: CheckViewState,
    pub context: ContextViewState,
    pub doctor: DoctorViewState,
    pub search: SearchViewState,
    pub alert: Option<AlertState>,
    pub blocking_alert: Option<AlertState>,
    pub should_quit: bool,
    pub proposals: ProposalsTab,
    pub inbox: InboxViewState,
    pub conflict: ConflictViewState,
    /// Pending interactive command (set by hand-merge confirm); the host
    /// takes it, suspends the terminal, runs it, and resumes.
    pub suspended: Option<SuspendedCommand>,
    vault_root_override: Option<std::path::PathBuf>,
}

impl<R: Runner> App<R> {
    /// Construct a new `App` on the `Check` view without running a command yet.
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            active_view: ActiveView::Check,
            input_mode: InputMode::Normal,
            vault: None,
            check: CheckViewState::default(),
            context: ContextViewState::default(),
            doctor: DoctorViewState::default(),
            search: SearchViewState::default(),
            alert: None,
            blocking_alert: None,
            should_quit: false,
            proposals: ProposalsTab::default(),
            inbox: InboxViewState::default(),
            conflict: ConflictViewState::default(),
            suspended: None,
            vault_root_override: None,
        }
    }

    /// Set an explicit vault root (from `--vault`) for proposal discovery.
    pub fn set_vault_root(&mut self, root: std::path::PathBuf) {
        self.vault_root_override = Some(root);
    }

    /// Run `confidant check --json --no-input` and update the Check view state.
    pub fn load_check(&mut self) {
        let raw = match self.runner.run(&["check"]) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        if let Some((_ok, report)) = self.apply_outcome::<CheckReport>(&raw) {
            self.check.report = Some(report);
            self.check.selected = 0;
        }
    }

    /// Run the unified Search tab (#387): exact literal scan via
    /// `confidant find` when `exact` is set, otherwise qmd-ranked search
    /// via the `qmd-search` skill's `qmd-query.py` (which already falls
    /// back to `confidant find` with a banner when qmd or its corpus is
    /// missing, so the `via` label always shows which engine answered).
    pub fn run_search(&mut self, query: &str) {
        let trimmed = query.trim().to_owned();
        self.search.query = trimmed.clone();
        self.search.input = trimmed.clone();
        self.search.editing = false;
        self.input_mode = InputMode::Normal;
        if trimmed.is_empty() {
            return;
        }
        if self.search.exact {
            self.run_search_exact(&trimmed);
            return;
        }

        let vault_root = match resolve_vault_root(self.vault_root_override.as_deref()) {
            Some(root) => root,
            None => {
                self.alert = Some(AlertState {
                    title: "No Vault".to_owned(),
                    code: Some("no_vault".to_owned()),
                    message:
                        "no vault found: pass --vault, set CONFIDANT_VAULT, or run inside a vault"
                            .to_owned(),
                    fix: None,
                    blocking: false,
                });
                return;
            }
        };

        let skills_dir = match self.skills_dir() {
            Some(dir) => dir,
            None => return, // skills_dir() sets the alert
        };
        let script = std::path::Path::new(&skills_dir)
            .join("qmd-search")
            .join("bin")
            .join("qmd-query.py");
        if !script.is_file() {
            self.alert = Some(AlertState {
                title: "Search Unavailable".to_owned(),
                code: Some("qmd_skill_missing".to_owned()),
                message: format!("qmd-search skill not found at {}", script.display()),
                fix: Some(
                    "Run `confidant setup` to install skills, or press e for exact search"
                        .to_owned(),
                ),
                blocking: false,
            });
            return;
        }

        let script_str = script.display().to_string();
        let vault_str = vault_root.display().to_string();
        let raw = match self
            .runner
            .run_program("python3", &[&script_str, "--vault", &vault_str, &trimmed])
        {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState {
                    title: "Search Unavailable".to_owned(),
                    code: Some("python3_missing".to_owned()),
                    message: format!("could not run python3: {e:#}"),
                    fix: Some("Install python3, or press e for exact search".to_owned()),
                    blocking: false,
                });
                return;
            }
        };
        if let Some((_ok, result)) = self.apply_outcome::<SearchResult>(&raw) {
            self.search.result = Some(filter_search_result(result));
            self.search.selected = 0;
        }
    }

    /// Exact literal scan for the unified Search tab: runs
    /// `confidant find --json --no-input -- <query>` and renders the hits
    /// through the same fail-closed Search path (`via == "find"`).
    fn run_search_exact(&mut self, trimmed: &str) {
        let raw = match self.runner.run(&["find", "--", trimmed]) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        if let Some((_ok, result)) = self.apply_outcome::<FindResult>(&raw) {
            self.search.result = Some(filter_search_result(find_result_to_search(result)));
            self.search.selected = 0;
        }
    }

    /// Toggle the Search exact mode (#387) and re-run the current query
    /// when one is present.
    pub fn toggle_search_exact(&mut self) {
        self.search.exact = !self.search.exact;
        self.alert = None;
        if !self.search.query.trim().is_empty() {
            let q = self.search.query.clone();
            self.run_search(&q);
        }
    }

    /// Whether qmd-ranked search is available for the `/` default (#416
    /// nit 4, Frank's call): `qmd` on PATH and the vault's search corpus
    /// built. Mirrors the `doctor` qmd-search check's first two probes;
    /// the embeddings probe is skipped here because bm25 keyword search
    /// works without embeddings.
    fn qmd_available(&self) -> bool {
        let paths = std::env::var_os("PATH");
        let root = resolve_vault_root(self.vault_root_override.as_deref());
        qmd_available_on(paths.as_deref(), root.as_deref())
    }

    /// Enter the Search tab for a new query (`/`), defaulting the mode
    /// per Frank's call on #416 nit 4: qmd-ranked search when qmd is
    /// available, exact literal scan otherwise.
    fn enter_search(&mut self) {
        self.active_view = ActiveView::Search;
        self.input_mode = InputMode::EditingSearch;
        self.search.editing = true;
        self.search.exact = !self.qmd_available();
        self.alert = None;
    }

    /// Resolve the installed skills directory via `confidant which --skills-dir`.
    fn skills_dir(&mut self) -> Option<String> {
        let raw = match self.runner.run(&["which", "--skills-dir"]) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return None;
            }
        };
        let value: serde_json::Value = match serde_json::from_slice(&raw.stdout) {
            Ok(v) => v,
            Err(_) => {
                self.alert = Some(AlertState::invalid_json(raw.status));
                return None;
            }
        };
        match value.get("skills_dir").and_then(|s| s.as_str()) {
            Some(dir) if !dir.is_empty() => Some(dir.to_owned()),
            _ => {
                self.alert = Some(AlertState {
                    title: "Search Unavailable".to_owned(),
                    code: Some("skills_dir_missing".to_owned()),
                    message: "`confidant which --skills-dir` did not report a skills directory"
                        .to_owned(),
                    fix: Some("Run `confidant setup` to install skills".to_owned()),
                    blocking: false,
                });
                None
            }
        }
    }

    /// Run `confidant context --json --no-input -- <person_id>` and update the Context view state.
    pub fn load_context(&mut self, person_id: &str) {
        let pid = person_id.to_owned();
        self.context.person_id = Some(pid.clone());
        let raw = match self.runner.run(&["context", "--", &pid]) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        if let Some((_ok, ctx)) = self.apply_outcome::<Context>(&raw) {
            self.context.context = Some(ctx);
            self.context.scroll = 0;
        }
    }

    /// Run `confidant doctor --json --no-input` and update the Doctor view state.
    pub fn load_doctor(&mut self) {
        let raw = match self.runner.run(&["doctor"]) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        if let Some((ok, report)) = self.apply_outcome::<DoctorReport>(&raw) {
            self.doctor.report = Some(report);
            self.doctor.ok = Some(ok);
            self.doctor.selected = 0;
        }
    }

    /// Run `confidant inbox --dry-run --json --no-input` and update the
    /// Inbox view state. Read-only: decrypts and plans, commits nothing.
    pub fn load_inbox(&mut self) {
        let raw = match self.runner.run(&["inbox", "--dry-run"]) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        if let Some((_, report)) = self.apply_outcome::<InboxReport>(&raw) {
            self.inbox.report = Some(report);
            self.inbox.confirming = false;
            self.inbox.last_apply = None;
        }
    }

    /// Open the apply confirm modal, if there is anything to apply.
    pub fn inbox_begin_apply(&mut self) {
        let can_apply = self
            .inbox
            .report
            .as_ref()
            .map(|r| !r.empty && !r.items.is_empty())
            .unwrap_or(false);
        if can_apply {
            self.inbox.confirming = true;
        }
    }

    /// Run the real `confidant inbox` (all-or-nothing merge + clear), then
    /// reload the dry run so the view shows the new state.
    pub fn inbox_run_apply(&mut self) {
        self.inbox.confirming = false;
        let raw = match self.runner.run(&["inbox"]) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        if let Some((_, report)) = self.apply_outcome::<InboxReport>(&raw) {
            let msg = format!(
                "merged {} item(s), cleared {}",
                report.merged, report.cleared
            );
            self.load_inbox();
            self.inbox.last_apply = Some(msg);
        }
    }

    /// Run `confidant check --json --no-input` and list the
    /// `E_MERGE_CONFLICT` findings that carry a record id (#456).
    pub fn load_conflicts(&mut self) {
        let raw = match self.runner.run(&["check"]) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        if let Some((_, report)) = self.apply_outcome::<CheckReport>(&raw) {
            self.conflict.entries = report
                .findings
                .iter()
                .filter(|f| f.code == "E_MERGE_CONFLICT" && f.id.is_some())
                .map(|f| ConflictListEntry {
                    id: f.id.clone().unwrap_or_default(),
                    message: f.message.clone(),
                })
                .collect();
            self.conflict.selected = 0;
            self.conflict.detail = None;
            self.conflict.detail_id = None;
            self.conflict.confirming = None;
            self.conflict.last_result = None;
            self.conflict.loaded = true;
        }
    }

    /// Alert shown when the CLI does not support `record resolve`
    /// (unknown subcommand on an older binary): the operator needs to
    /// upgrade confidant.
    fn resolve_unsupported_alert() -> AlertState {
        AlertState {
            title: "Resolve Not Available".to_owned(),
            code: Some("old_cli".to_owned()),
            message: "this confidant binary does not support `record resolve`".to_owned(),
            fix: Some("upgrade confidant to resolve merge conflicts".to_owned()),
            blocking: false,
        }
    }

    /// Open the detail view for the selected conflict: run
    /// `record resolve <id> --show` and keep both decrypted sides in
    /// memory only.
    pub fn open_conflict_detail(&mut self) {
        let Some(entry) = self.conflict.entries.get(self.conflict.selected) else {
            return;
        };
        let id = entry.id.clone();
        let raw = match self.runner.run(&["record", "resolve", "--show", &id]) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        match parse_raw_output::<ResolveShow>(&raw) {
            ContractOutcome::Ok { vault, data, .. } => {
                if vault.is_some() {
                    self.vault = vault;
                }
                self.alert = None;
                self.conflict.detail_id = Some(id);
                self.conflict.detail = Some(data);
            }
            ContractOutcome::CliError {
                usage_error: true, ..
            } => {
                self.alert = Some(Self::resolve_unsupported_alert());
            }
            ContractOutcome::CliError {
                status,
                usage_error,
                error,
            } => {
                self.alert = Some(AlertState::from_cli_error(status, usage_error, &error));
            }
            ContractOutcome::VersionMismatch { reported_version } => {
                self.blocking_alert = Some(AlertState::version_mismatch(&reported_version));
            }
            ContractOutcome::InvalidJson { status } => {
                self.alert = Some(AlertState::invalid_json(status));
            }
        }
    }

    /// Open the `y`/`n` confirm modal for taking one side.
    pub fn conflict_begin_take(&mut self, side: ConflictAction) {
        if self.conflict.detail.is_some() {
            self.conflict.confirming = Some(side);
        }
    }

    /// Open the `y`/`n` confirm modal for the editor hand-merge.
    pub fn conflict_begin_hand_merge(&mut self) {
        if self.conflict.detail.is_some() {
            self.conflict.confirming = Some(ConflictAction::HandMerge);
        }
    }

    /// Run `record resolve <id> --take ours|theirs` after confirm: the
    /// chosen side is installed byte for byte and staged, never committed.
    /// Shows the CLI's `next` line, then refreshes the list.
    pub fn conflict_run_take(&mut self, side: ConflictAction) {
        self.conflict.confirming = None;
        let (id, side_name) = match (&self.conflict.detail_id, side) {
            (Some(id), ConflictAction::TakeOurs) => (id.clone(), "ours"),
            (Some(id), ConflictAction::TakeTheirs) => (id.clone(), "theirs"),
            _ => return,
        };
        let raw = match self
            .runner
            .run(&["record", "resolve", &id, "--take", side_name])
        {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        match parse_raw_output::<ResolveApplied>(&raw) {
            ContractOutcome::Ok { vault, data, .. } => {
                if vault.is_some() {
                    self.vault = vault;
                }
                self.alert = None;
                let msg = format!(
                    "kept the {side_name} side of {id}; staged. Next: {}",
                    data.next
                );
                self.load_conflicts();
                self.conflict.last_result = Some(msg);
            }
            ContractOutcome::CliError {
                usage_error: true, ..
            } => {
                self.alert = Some(Self::resolve_unsupported_alert());
            }
            ContractOutcome::CliError {
                status,
                usage_error,
                error,
            } => {
                self.alert = Some(AlertState::from_cli_error(status, usage_error, &error));
            }
            ContractOutcome::VersionMismatch { reported_version } => {
                self.blocking_alert = Some(AlertState::version_mismatch(&reported_version));
            }
            ContractOutcome::InvalidJson { status } => {
                self.alert = Some(AlertState::invalid_json(status));
            }
        }
    }

    /// Queue the interactive hand-merge: the host suspends the TUI and
    /// runs `confidant record resolve <id> --edit` in the terminal.
    pub fn conflict_run_hand_merge(&mut self) {
        self.conflict.confirming = None;
        let Some(id) = self.conflict.detail_id.clone() else {
            return;
        };
        self.suspended = Some(SuspendedCommand {
            args: vec![
                "record".to_owned(),
                "resolve".to_owned(),
                id,
                "--edit".to_owned(),
            ],
        });
    }

    /// Take the pending interactive command for the host to run while the
    /// alternate screen is suspended.
    pub fn take_suspended_command(&mut self) -> Option<SuspendedCommand> {
        self.suspended.take()
    }

    /// Run a suspended command through the runner with an inherited
    /// terminal. Called by the host while the TUI is suspended.
    pub fn run_suspended_command(&self, cmd: &SuspendedCommand) -> anyhow::Result<i32> {
        self.runner
            .run_confidant_interactive(&cmd.args.iter().map(String::as_str).collect::<Vec<_>>())
    }

    /// Refresh after an interactive command completes: the hand-merge may
    /// have resolved the record, so reload the list and close the detail.
    pub fn after_suspended_command(&mut self) {
        self.suspended = None;
        self.load_conflicts();
    }

    /// Refresh the currently active view.
    pub fn refresh_current(&mut self) {
        self.alert = None;
        match self.active_view {
            ActiveView::Check => self.load_check(),
            ActiveView::Context => {
                if let Some(pid) = self.context.person_id.clone() {
                    self.load_context(&pid);
                }
            }
            ActiveView::Doctor => self.load_doctor(),
            ActiveView::Proposals => self.load_proposals(),
            ActiveView::Search => {
                let q = self.search.query.clone();
                if !q.is_empty() {
                    self.run_search(&q);
                }
            }
            ActiveView::Inbox => self.load_inbox(),
            ActiveView::Conflicts => self.load_conflicts(),
        }
    }

    /// Discover proposal manifests under `.confidant/proposals/` and rebuild
    /// the list entries.
    pub fn load_proposals(&mut self) {
        let root = resolve_vault_root(self.vault_root_override.as_deref());
        self.proposals.vault_root = root.clone();
        self.proposals.load_error = None;
        let Some(root) = root else {
            self.proposals.load_error = Some(
                "no vault found: pass --vault, set CONFIDANT_VAULT, or run inside a vault"
                    .to_owned(),
            );
            self.proposals.entries.clear();
            return;
        };
        let discovered = discover_proposals(&root);
        let mut entries = Vec::with_capacity(discovered.len());
        for d in discovered {
            entries.push(self.proposal_entry(&d, &root));
        }
        if self.proposals.selected >= entries.len() {
            self.proposals.selected = 0;
        }
        self.proposals.entries = entries;
        self.proposals.loaded = true;
        // If a proposal is open, re-open it: progress may have changed on
        // disk, and any in-flight step returns to Browsing.
        if self.proposals.opened.is_some() {
            let path = self
                .proposals
                .opened
                .as_ref()
                .map(|f| f.manifest_path.clone());
            match path.map(|p| ApplyFlow::open(&p, &root)) {
                Some(Ok(flow)) => self.proposals.opened = Some(flow),
                _ => self.proposals.opened = None,
            }
        }
    }

    fn proposal_entry(
        &self,
        discovered: &DiscoveredProposal,
        root: &std::path::Path,
    ) -> ProposalListEntry {
        match &discovered.manifest {
            Err(e) => ProposalListEntry {
                name: discovered.name.clone(),
                skill: "-".to_owned(),
                detail: "invalid manifest".to_owned(),
                progress: String::new(),
                error: Some(e.clone()),
            },
            Ok(manifest) => {
                let notes = manifest
                    .records
                    .iter()
                    .filter(|r| r.note_id.is_some())
                    .count();
                let records = manifest.records.len() - notes;
                let ledger_lines = manifest
                    .lines_file
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .and_then(|lf| std::fs::read_to_string(lf).ok())
                    .map(|t| t.lines().count())
                    .unwrap_or(0);
                let detail =
                    format!("{notes} notes, {records} records, {ledger_lines} ledger lines");
                // Count planned steps for progress.
                let planned = crate::apply::plan_manifest(manifest, &discovered.path, root);
                let (total, done) = match planned {
                    Ok(steps) => {
                        let progress = crate::proposals::read_progress(&discovered.path);
                        let total = steps.iter().filter(|s| s.blocked.is_none()).count();
                        let done = steps
                            .iter()
                            .filter(|s| s.blocked.is_none() && progress.is_done(&s.key))
                            .count();
                        (total, done)
                    }
                    Err(_) => (0, 0),
                };
                ProposalListEntry {
                    name: discovered.name.clone(),
                    skill: manifest.skill.clone(),
                    detail,
                    progress: format!("{done}/{total} steps done"),
                    error: None,
                }
            }
        }
    }

    /// Open the selected proposal's detail view.
    pub fn open_selected_proposal(&mut self) {
        let (Some(root), Some(entry)) = (
            self.proposals.vault_root.clone(),
            self.proposals.entries.get(self.proposals.selected).cloned(),
        ) else {
            return;
        };
        if let Some(err) = entry.error {
            self.alert = Some(AlertState {
                title: "Invalid Proposal Manifest".to_owned(),
                code: Some("invalid_manifest".to_owned()),
                message: format!("{}: {err}", entry.name),
                fix: Some("Re-run the proposer to regenerate the manifest".to_owned()),
                blocking: false,
            });
            return;
        }
        let path = root.join(".confidant").join("proposals").join(&entry.name);
        match ApplyFlow::open(&path, &root) {
            Ok(flow) => self.proposals.opened = Some(flow),
            Err(e) => {
                self.alert = Some(AlertState {
                    title: "Cannot Open Proposal".to_owned(),
                    code: Some("proposal_open_failed".to_owned()),
                    message: e,
                    fix: Some("Re-run the proposer to regenerate the manifest".to_owned()),
                    blocking: false,
                });
            }
        }
    }

    /// Start (or resume) the apply flow for the open proposal: dry-run the
    /// first pending step.
    pub fn proposals_start_apply(&mut self) {
        let Some(flow) = self.proposals.opened.as_mut() else {
            return;
        };
        if flow.appliable_done() {
            self.proposals_final_check();
            return;
        }
        let Some(step) = flow.first_pending() else {
            return;
        };
        if let Err(e) = flow.dry_run_step(&self.runner, step) {
            self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
            flow.phase = FlowPhase::Browsing;
        }
    }

    /// Run the final `check` once every runnable step is done.
    fn proposals_final_check(&mut self) {
        let Some(flow) = self.proposals.opened.as_mut() else {
            return;
        };
        match flow.final_check(&self.runner) {
            Ok(None) => {
                flow.phase = FlowPhase::CleanupPrompt;
            }
            Ok(Some(report)) => {
                self.check.report = Some(report);
                self.check.selected = 0;
                self.active_view = ActiveView::Check;
                self.alert = Some(AlertState {
                    title: "Proposal Applied, Check Not Clean".to_owned(),
                    code: Some("final_check_failed".to_owned()),
                    message: "every step applied, but the final check has findings; fix them before cleaning up".to_owned(),
                    fix: Some("Resolve the findings above, then re-run the apply to reach cleanup".to_owned()),
                    blocking: false,
                });
            }
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
            }
        }
    }

    fn apply_outcome<T: serde::de::DeserializeOwned + Default>(
        &mut self,
        raw: &RawOutput,
    ) -> Option<(bool, T)> {
        match parse_raw_output::<T>(raw) {
            ContractOutcome::Ok { ok, vault, data } => {
                if vault.is_some() {
                    self.vault = vault;
                }
                self.alert = None;
                Some((ok, data))
            }
            ContractOutcome::VersionMismatch { reported_version } => {
                self.blocking_alert = Some(AlertState::version_mismatch(&reported_version));
                None
            }
            ContractOutcome::CliError {
                status,
                usage_error,
                error,
            } => {
                self.alert = Some(AlertState::from_cli_error(status, usage_error, &error));
                None
            }
            ContractOutcome::InvalidJson { status } => {
                self.alert = Some(AlertState::invalid_json(status));
                None
            }
        }
    }

    fn switch_to(&mut self, view: ActiveView) {
        self.active_view = view;
        self.input_mode = InputMode::Normal;
        self.search.editing = false;
        self.alert = None;
        match view {
            ActiveView::Check if self.check.report.is_none() => self.load_check(),
            ActiveView::Doctor if self.doctor.report.is_none() => self.load_doctor(),
            ActiveView::Proposals if !self.proposals.loaded => self.load_proposals(),
            ActiveView::Inbox if self.inbox.report.is_none() => self.load_inbox(),
            ActiveView::Conflicts if !self.conflict.loaded => self.load_conflicts(),
            _ => {}
        }
    }

    /// Handle a key event while the proposals tab is active.
    fn handle_proposals_key(&mut self, key: KeyEvent) {
        let in_export_input = matches!(
            self.proposals.opened.as_ref().map(|f| &f.phase),
            Some(FlowPhase::CleanupExportInput { .. })
        );
        if !in_export_input {
            match key.code {
                KeyCode::Tab => {
                    let next = self.active_view.next();
                    self.switch_to(next);
                    return;
                }
                KeyCode::BackTab => {
                    let prev = self.active_view.prev();
                    self.switch_to(prev);
                    return;
                }
                KeyCode::Char('1') => {
                    self.switch_to(ActiveView::Check);
                    return;
                }
                KeyCode::Char('2') => {
                    self.switch_to(ActiveView::Context);
                    return;
                }
                KeyCode::Char('3') => {
                    self.switch_to(ActiveView::Doctor);
                    return;
                }
                KeyCode::Char('4') => {
                    self.switch_to(ActiveView::Proposals);
                    return;
                }
                KeyCode::Char('5') => {
                    self.switch_to(ActiveView::Search);
                    return;
                }
                KeyCode::Char('6') => {
                    self.switch_to(ActiveView::Inbox);
                    return;
                }
                KeyCode::Char('7') => {
                    self.switch_to(ActiveView::Conflicts);
                    return;
                }
                KeyCode::Char('/') => {
                    self.enter_search();
                    return;
                }
                _ => {}
            }
        }
        if in_export_input {
            self.handle_export_input_key(key);
        } else if self.proposals.opened.is_some() {
            self.handle_open_proposal_key(key);
        } else {
            self.handle_proposal_list_key(key);
        }
    }

    /// Text input for the lightfield cleanup export path.
    fn handle_export_input_key(&mut self, key: KeyEvent) {
        let run_with: Option<String> = {
            let Some(flow) = self.proposals.opened.as_mut() else {
                return;
            };
            let FlowPhase::CleanupExportInput { input } = &mut flow.phase else {
                return;
            };
            match key.code {
                KeyCode::Esc => {
                    flow.phase = FlowPhase::CleanupPrompt;
                    None
                }
                KeyCode::Enter => Some(input.clone()),
                KeyCode::Backspace => {
                    input.pop();
                    None
                }
                KeyCode::Char(c)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && !key.modifiers.contains(KeyModifiers::ALT) =>
                {
                    input.push(c);
                    None
                }
                _ => None,
            }
        };
        if let Some(path) = run_with {
            self.proposals_run_cleanup(Some(path.as_str()));
        }
    }

    fn handle_proposal_list_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc => {
                if self.alert.is_some() {
                    self.alert = None;
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.proposals.entries.is_empty()
                    && self.proposals.selected + 1 < self.proposals.entries.len()
                {
                    self.proposals.selected += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.proposals.selected = self.proposals.selected.saturating_sub(1);
            }
            KeyCode::Enter => self.open_selected_proposal(),
            KeyCode::Char('a') => {
                self.open_selected_proposal();
                self.proposals_start_apply();
            }
            KeyCode::Char('r') => self.load_proposals(),
            _ => {}
        }
    }

    /// Handle a key event while the inbox tab is active.
    ///
    /// Returns true when the key was consumed. The confirm modal swallows
    /// every key: `y` applies, anything else just cancels. Outside the
    /// modal, `r` re-runs the dry run and `a` opens the all-or-nothing
    /// apply confirm; everything else falls through to the shared
    /// navigation and quit handling in `handle_key`.
    fn handle_inbox_key(&mut self, key: KeyEvent) -> bool {
        // Esc dismisses an alert first, before any view action.
        if self.alert.is_some() && matches!(key.code, KeyCode::Esc) {
            self.alert = None;
            return true;
        }
        if self.inbox.confirming {
            match key.code {
                KeyCode::Char('y') => self.inbox_run_apply(),
                _ => self.inbox.confirming = false,
            }
            return true;
        }
        match key.code {
            KeyCode::Char('r') => {
                self.load_inbox();
                true
            }
            KeyCode::Char('a') => {
                self.inbox_begin_apply();
                true
            }
            _ => false,
        }
    }

    /// Handle a key event while the conflicts tab is active.
    ///
    /// Returns true when the key was consumed. The confirm modal swallows
    /// every key: `y` runs the pending action, anything else cancels.
    /// In the detail view, `o`/`t` take a side and `m` hand-merges (each
    /// behind a confirm); `q`/Esc goes back to the list. In the list,
    /// `Enter` opens the detail and `r` reloads. Everything else falls
    /// through to the shared navigation and quit handling in `handle_key`.
    fn handle_conflict_key(&mut self, key: KeyEvent) -> bool {
        // Esc dismisses an alert first, before any view action.
        if self.alert.is_some() && matches!(key.code, KeyCode::Esc) {
            self.alert = None;
            return true;
        }
        if let Some(action) = self.conflict.confirming {
            match key.code {
                KeyCode::Char('y') => match action {
                    ConflictAction::TakeOurs | ConflictAction::TakeTheirs => {
                        self.conflict_run_take(action)
                    }
                    ConflictAction::HandMerge => self.conflict_run_hand_merge(),
                },
                _ => self.conflict.confirming = None,
            }
            return true;
        }
        if self.conflict.detail.is_some() {
            match key.code {
                KeyCode::Char('o') => {
                    self.conflict_begin_take(ConflictAction::TakeOurs);
                    true
                }
                KeyCode::Char('t') => {
                    self.conflict_begin_take(ConflictAction::TakeTheirs);
                    true
                }
                KeyCode::Char('m') => {
                    self.conflict_begin_hand_merge();
                    true
                }
                KeyCode::Char('q') | KeyCode::Esc => {
                    self.conflict.detail = None;
                    self.conflict.detail_id = None;
                    true
                }
                _ => false,
            }
        } else {
            match key.code {
                KeyCode::Char('r') => {
                    self.load_conflicts();
                    true
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if !self.conflict.entries.is_empty()
                        && self.conflict.selected + 1 < self.conflict.entries.len()
                    {
                        self.conflict.selected += 1;
                    }
                    true
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.conflict.selected = self.conflict.selected.saturating_sub(1);
                    true
                }
                KeyCode::Enter => {
                    self.open_conflict_detail();
                    true
                }
                _ => false,
            }
        }
    }

    fn handle_open_proposal_key(&mut self, key: KeyEvent) {
        // Esc dismisses an alert first, before any view action.
        if self.alert.is_some() && matches!(key.code, KeyCode::Esc) {
            self.alert = None;
            return;
        }
        let phase = self.proposals.opened.as_ref().map(|f| f.phase.clone());
        let Some(phase) = phase else { return };
        match phase {
            FlowPhase::Browsing => match key.code {
                KeyCode::Esc => self.proposals.opened = None,
                KeyCode::Char('a') => self.proposals_start_apply(),
                KeyCode::Char('q') => self.should_quit = true,
                _ => {}
            },
            FlowPhase::Diff { step, outcome } => match key.code {
                KeyCode::Char('y') => {
                    if let Some(flow) = self.proposals.opened.as_mut() {
                        flow.phase = FlowPhase::Confirm { step, outcome };
                    }
                }
                KeyCode::Esc => {
                    if let Some(flow) = self.proposals.opened.as_mut() {
                        flow.phase = FlowPhase::Browsing;
                    }
                }
                KeyCode::Char('q') => self.should_quit = true,
                _ => {}
            },
            // Any key other than `y` cancels back to the diff. Confirm is
            // `y` typed into the modal, never Enter.
            FlowPhase::Confirm { step, .. } => match key.code {
                KeyCode::Char('y') => self.proposals_confirm_apply(step),
                _ => {
                    if let Some(flow) = self.proposals.opened.as_mut() {
                        if let FlowPhase::Confirm { step, outcome } = flow.phase.clone() {
                            flow.phase = FlowPhase::Diff { step, outcome };
                        }
                    }
                }
            },
            FlowPhase::StepFailed { .. } => match key.code {
                KeyCode::Esc => {
                    if let Some(flow) = self.proposals.opened.as_mut() {
                        flow.phase = FlowPhase::Browsing;
                    }
                }
                KeyCode::Char('r') => self.proposals_start_apply(),
                KeyCode::Char('q') => self.should_quit = true,
                _ => {}
            },
            FlowPhase::CleanupPrompt => match key.code {
                KeyCode::Char('y') => {
                    let is_lightfield = self
                        .proposals
                        .opened
                        .as_ref()
                        .is_some_and(|f| f.manifest.skill == "lightfield-import");
                    if is_lightfield {
                        if let Some(flow) = self.proposals.opened.as_mut() {
                            flow.phase = FlowPhase::CleanupExportInput {
                                input: String::new(),
                            };
                        }
                    } else {
                        self.proposals_run_cleanup(None);
                    }
                }
                _ => {
                    if let Some(flow) = self.proposals.opened.as_mut() {
                        flow.phase = FlowPhase::Browsing;
                    }
                }
            },
            FlowPhase::CleanupFailed { .. } => match key.code {
                KeyCode::Esc => {
                    if let Some(flow) = self.proposals.opened.as_mut() {
                        flow.phase = FlowPhase::CleanupPrompt;
                    }
                }
                KeyCode::Char('q') => self.should_quit = true,
                _ => {}
            },
            // The progress file was corrupt: `y` treats the proposal as fresh
            // (re-apply is safe — the CLI's idempotence checks skip done
            // steps), any other key closes the proposal.
            FlowPhase::CorruptProgress => match key.code {
                KeyCode::Char('y') => {
                    if let Some(flow) = self.proposals.opened.as_mut() {
                        flow.phase = FlowPhase::Browsing;
                    }
                }
                _ => {
                    self.proposals.opened = None;
                }
            },
            // Terminal phases are exited immediately by the action that
            // produced them; any stray key just closes the detail.
            FlowPhase::Finished | FlowPhase::CheckFailed | FlowPhase::CleanupExportInput { .. } => {
                self.proposals.opened = None;
            }
        }
    }

    /// The operator confirmed in the modal: run the real apply for `step`,
    /// then continue with the next pending step or the final check.
    fn proposals_confirm_apply(&mut self, step: usize) {
        let outcome = {
            let Some(flow) = self.proposals.opened.as_mut() else {
                return;
            };
            match flow.apply_step(&self.runner, step) {
                Ok(outcome) => outcome,
                Err(e) => {
                    self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                    return;
                }
            }
        };
        match outcome {
            StepApplyOutcome::Done { more } => {
                if more {
                    self.proposals_start_apply();
                } else {
                    let done = self
                        .proposals
                        .opened
                        .as_ref()
                        .is_some_and(|f| f.appliable_done());
                    if done {
                        self.proposals_final_check();
                    }
                    // Otherwise a step failed; the detail view shows it.
                }
            }
            StepApplyOutcome::Failed => {
                // The detail view shows the failure; the operator retries
                // with `r` or goes back with Esc.
            }
            StepApplyOutcome::CheckBlocked { report } => {
                // The report renders in the Check view itself; the step is
                // not marked done.
                self.check.report = Some(report);
                self.check.selected = 0;
                self.active_view = ActiveView::Check;
            }
        }
    }

    /// Run cleanup (delete the proposal set) for the open proposal.
    fn proposals_run_cleanup(&mut self, export: Option<&str>) {
        let result = {
            let Some(flow) = self.proposals.opened.as_mut() else {
                return;
            };
            flow.cleanup(&self.runner, export)
        };
        match result {
            Ok(()) => {
                let finished = self
                    .proposals
                    .opened
                    .as_ref()
                    .is_some_and(|f| f.phase == FlowPhase::Finished);
                if finished {
                    self.proposals.opened = None;
                    self.load_proposals();
                }
            }
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                if let Some(flow) = self.proposals.opened.as_mut() {
                    flow.phase = FlowPhase::Browsing;
                }
            }
        }
    }

    /// Handle a single key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            self.should_quit = true;
            return;
        }

        if self.blocking_alert.is_some() {
            if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                self.should_quit = true;
            }
            return;
        }

        if self.active_view == ActiveView::Proposals {
            self.handle_proposals_key(key);
            return;
        }

        if self.active_view == ActiveView::Inbox && self.handle_inbox_key(key) {
            return;
        }

        if self.active_view == ActiveView::Conflicts && self.handle_conflict_key(key) {
            return;
        }

        if self.input_mode == InputMode::EditingSearch {
            match key.code {
                KeyCode::Esc => {
                    self.input_mode = InputMode::Normal;
                    self.search.editing = false;
                    self.search.input = self.search.query.clone();
                }
                KeyCode::Enter => {
                    let q = self.search.input.clone();
                    self.run_search(&q);
                }
                KeyCode::Backspace => {
                    self.search.input.pop();
                }
                KeyCode::Char(c)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && !key.modifiers.contains(KeyModifiers::ALT) =>
                {
                    self.search.input.push(c);
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Esc => {
                if self.alert.is_some() {
                    self.alert = None;
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Tab => {
                let next = self.active_view.next();
                self.switch_to(next);
            }
            KeyCode::BackTab => {
                let prev = self.active_view.prev();
                self.switch_to(prev);
            }
            KeyCode::Char('1') => self.switch_to(ActiveView::Check),
            KeyCode::Char('2') => self.switch_to(ActiveView::Context),
            KeyCode::Char('3') => self.switch_to(ActiveView::Doctor),
            KeyCode::Char('4') => self.switch_to(ActiveView::Proposals),
            KeyCode::Char('5') => self.switch_to(ActiveView::Search),
            KeyCode::Char('6') => self.switch_to(ActiveView::Inbox),
            KeyCode::Char('7') => self.switch_to(ActiveView::Conflicts),
            KeyCode::Char('/') => {
                self.enter_search();
            }
            // #387: exact literal scan toggle for the unified Search tab.
            KeyCode::Char('e') if self.active_view == ActiveView::Search => {
                self.toggle_search_exact();
            }
            KeyCode::Char('r') => {
                self.refresh_current();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.select_next();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.select_prev();
            }
            KeyCode::Enter => {
                self.activate_selected();
            }
            _ => {}
        }
    }

    fn select_next(&mut self) {
        match self.active_view {
            ActiveView::Check => {
                if let Some(r) = &self.check.report {
                    if !r.findings.is_empty() && self.check.selected + 1 < r.findings.len() {
                        self.check.selected += 1;
                    }
                }
            }
            ActiveView::Context => {
                self.context.scroll = self.context.scroll.saturating_add(1);
            }
            ActiveView::Doctor => {
                if let Some(r) = &self.doctor.report {
                    if !r.checks.is_empty() && self.doctor.selected + 1 < r.checks.len() {
                        self.doctor.selected += 1;
                    }
                }
            }
            ActiveView::Search => {
                if let Some(r) = &self.search.result {
                    if !r.kept.is_empty() && self.search.selected + 1 < r.kept.len() {
                        self.search.selected += 1;
                    }
                }
            }
            // The proposals, inbox, and conflicts tabs handle their own keys.
            ActiveView::Proposals | ActiveView::Inbox | ActiveView::Conflicts => {}
        }
    }

    fn select_prev(&mut self) {
        match self.active_view {
            ActiveView::Check => {
                self.check.selected = self.check.selected.saturating_sub(1);
            }
            ActiveView::Context => {
                self.context.scroll = self.context.scroll.saturating_sub(1);
            }
            ActiveView::Doctor => {
                self.doctor.selected = self.doctor.selected.saturating_sub(1);
            }
            ActiveView::Search => {
                self.search.selected = self.search.selected.saturating_sub(1);
            }
            // The proposals, inbox, and conflicts tabs handle their own keys.
            ActiveView::Proposals | ActiveView::Inbox | ActiveView::Conflicts => {}
        }
    }

    fn activate_selected(&mut self) {
        let person_id = match self.active_view {
            ActiveView::Search => self
                .search
                .result
                .as_ref()
                .and_then(|r| r.kept.get(self.search.selected))
                .and_then(|h| h.id.as_deref())
                .filter(|id| id.starts_with("p-"))
                .map(str::to_owned),
            ActiveView::Check => self
                .check
                .report
                .as_ref()
                .and_then(|r| r.findings.get(self.check.selected))
                .and_then(|f| f.id.as_deref())
                .filter(|id| id.starts_with("p-"))
                .map(str::to_owned),
            ActiveView::Context
            | ActiveView::Doctor
            | ActiveView::Proposals
            | ActiveView::Inbox
            | ActiveView::Conflicts => None,
        };

        if let Some(pid) = person_id {
            self.active_view = ActiveView::Context;
            self.load_context(&pid);
        }
    }

    /// Render the current state to a ratatui [`Frame`].
    pub fn render(&self, frame: &mut Frame<'_>) {
        let area = frame.area();
        if let Some(blocking) = &self.blocking_alert {
            alert::render(blocking, frame, area);
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(10),
                Constraint::Length(1),
            ])
            .split(area);

        self.render_header(frame, chunks[0]);

        if let Some(active_alert) = &self.alert {
            alert::render(active_alert, frame, chunks[1]);
        } else {
            match self.active_view {
                ActiveView::Check => check::render(&self.check, frame, chunks[1]),
                ActiveView::Context => context::render(&self.context, frame, chunks[1]),
                ActiveView::Doctor => doctor::render(&self.doctor, frame, chunks[1]),
                ActiveView::Proposals => self.render_proposals(frame, chunks[1]),
                ActiveView::Search => search::render(&self.search, frame, chunks[1]),
                ActiveView::Inbox => self.render_inbox(frame, chunks[1]),
                ActiveView::Conflicts => self.render_conflict(frame, chunks[1]),
            }
        }

        Self::render_footer(frame, chunks[2]);
    }

    /// Borderless header: tab pills on the left, app title right-aligned.
    fn render_header(&self, frame: &mut Frame<'_>, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(18)])
            .split(area);

        let mut spans = Vec::new();
        for v in [
            ActiveView::Check,
            ActiveView::Context,
            ActiveView::Doctor,
            ActiveView::Proposals,
            ActiveView::Search,
            ActiveView::Inbox,
            ActiveView::Conflicts,
        ] {
            if !spans.is_empty() {
                spans.push(Span::raw(" "));
            }
            spans.push(theme::tab_pill(v.label(), v == self.active_view));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), chunks[0]);

        let title = Paragraph::new(Line::from(Span::styled(
            "confidant-tui v1",
            Style::default().fg(theme::palette::MUTED),
        )))
        .alignment(Alignment::Right);
        frame.render_widget(title, chunks[1]);
    }

    /// Borderless one-line footer with key badges and action labels.
    fn render_footer(frame: &mut Frame<'_>, area: Rect) {
        let mut spans = Vec::new();
        for (key, label) in [
            ("Tab/1-7", "view"),
            ("/", "search"),
            ("e", "exact"),
            ("j/k", "move"),
            ("Enter", "context"),
            ("r", "refresh"),
            ("q/Esc", "quit"),
        ] {
            spans.push(theme::key_badge(key));
            spans.push(theme::key_hint(label));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    /// Render the inbox tab: dry-run report, or the apply confirm modal.
    fn render_inbox(&self, frame: &mut Frame<'_>, area: Rect) {
        inbox::render(&self.inbox, frame, area);
        if self.inbox.confirming {
            if let Some(report) = &self.inbox.report {
                inbox::render_confirm(frame, area, report.merged, report.cleared);
            }
        }
    }

    /// Render the conflicts tab: list, open detail, or the take/hand-merge
    /// confirm modal.
    fn render_conflict(&self, frame: &mut Frame<'_>, area: Rect) {
        if self.conflict.detail.is_some() {
            conflict::render_detail(&self.conflict, frame, area);
        } else {
            conflict::render(&self.conflict, frame, area);
        }
        if let Some(action) = self.conflict.confirming {
            let id = self.conflict.detail_id.clone().unwrap_or_default();
            confirm::render(
                &ConfirmState::new(
                    action.title().to_owned(),
                    conflict::confirm_lines(action, &id, None),
                ),
                frame,
                area,
            );
        }
    }

    /// Render the proposals tab: list, open detail, or an in-flight step.
    fn render_proposals(&self, frame: &mut Frame<'_>, area: Rect) {
        if let Some(err) = &self.proposals.load_error {
            frame.render_widget(
                Paragraph::new(err.clone()).block(theme::block(" Proposals ")),
                area,
            );
            return;
        }
        let Some(flow) = &self.proposals.opened else {
            let state = ProposalsListState {
                entries: self.proposals.entries.clone(),
                selected: self.proposals.selected,
                vault_note: self
                    .proposals
                    .vault_root
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
            };
            proposals::render_list(&state, frame, area);
            return;
        };
        match &flow.phase {
            FlowPhase::Diff { step, outcome } => {
                let label = Self::flow_step_label(flow, *step);
                diff::render(
                    &DiffState::new(label, outcome.command.clone(), outcome.changes.clone()),
                    frame,
                    area,
                );
            }
            FlowPhase::Confirm { step, outcome } => {
                let label = Self::flow_step_label(flow, *step);
                diff::render(
                    &DiffState::new(
                        label.clone(),
                        outcome.command.clone(),
                        outcome.changes.clone(),
                    ),
                    frame,
                    area,
                );
                let argv = flow
                    .steps
                    .get(*step)
                    .map(|s| format!("confidant {}", s.plan.argv.join(" ")))
                    .unwrap_or_default();
                confirm::render(
                    &ConfirmState::new(
                        format!("Apply: {label}"),
                        vec![
                            argv,
                            String::new(),
                            "This writes to the vault and creates one commit.".to_owned(),
                        ],
                    ),
                    frame,
                    area,
                );
            }
            FlowPhase::CleanupPrompt => {
                proposals::render_detail(&self.proposal_detail(flow), frame, area);
                confirm::render(
                    &ConfirmState::new(
                        "Delete proposal set?".to_owned(),
                        vec![
                            "Delete proposal set (manifest, lines file, staged notes, progress file)?"
                                .to_owned(),
                        ],
                    ),
                    frame,
                    area,
                );
            }
            FlowPhase::CorruptProgress => {
                proposals::render_detail(&self.proposal_detail(flow), frame, area);
                confirm::render(
                    &ConfirmState::new(
                        "Corrupt progress file".to_owned(),
                        vec![
                            "The progress file for this proposal is corrupt, so every".to_owned(),
                            "step looks pending — an already-applied step may be among".to_owned(),
                            "them.".to_owned(),
                            String::new(),
                            "Re-applying is safe: the CLI's idempotence checks skip".to_owned(),
                            "steps that are already done.".to_owned(),
                        ],
                    ),
                    frame,
                    area,
                );
            }
            _ => {
                proposals::render_detail(&self.proposal_detail(flow), frame, area);
            }
        }
    }

    fn flow_step_label(flow: &ApplyFlow, step: usize) -> String {
        flow.steps
            .get(step)
            .map(|s| s.plan.label.clone())
            .unwrap_or_default()
    }

    /// Build the detail view state for an open proposal.
    fn proposal_detail(&self, flow: &ApplyFlow) -> ProposalDetailState {
        let steps = flow
            .steps
            .iter()
            .map(|s| {
                let (icon, extra) = match &s.status {
                    StepStatus::Pending => ("[ ]", String::new()),
                    StepStatus::Done { commit } => (
                        "[x]",
                        format!(" (commit {})", &commit[..8.min(commit.len())]),
                    ),
                    StepStatus::Blocked { message } => ("[!]", format!(" — blocked: {message}")),
                    StepStatus::Failed { message } => ("[E]", format!(" — failed: {message}")),
                };
                StepRow {
                    label: format!("{}{}", s.plan.label, extra),
                    status: icon.to_owned(),
                }
            })
            .collect();
        let hint = match &flow.phase {
            FlowPhase::Browsing => {
                if flow.first_pending().is_some() {
                    "a: apply next step (dry-run, then explicit confirm) | Esc: back to list"
                        .to_owned()
                } else if flow.appliable_done() {
                    "a: run final check and clean up | Esc: back to list".to_owned()
                } else {
                    "Esc: back to list".to_owned()
                }
            }
            FlowPhase::StepFailed {
                code, message, fix, ..
            } => {
                let mut h = format!("step failed [{code}]: {message}");
                if let Some(fix) = fix {
                    h.push_str(&format!(" Fix: {fix}"));
                }
                h.push_str(" | r: retry step | Esc: back");
                h
            }
            FlowPhase::CleanupExportInput { input } => {
                format!(
                    "Lightfield cleanup deletes the plaintext export. Type the export file path.\nExport file: {input}_\nEnter: delete export and proposal set | Esc: cancel"
                )
            }
            FlowPhase::CleanupFailed { message } => {
                format!("cleanup failed: {message} | Esc: back to cleanup prompt")
            }
            _ => String::new(),
        };
        ProposalDetailState {
            name: flow
                .manifest_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            skill: flow.manifest.skill.clone(),
            summary: flow.manifest.summary.clone().unwrap_or_default(),
            warnings: flow.manifest.warnings.clone(),
            steps,
            hint,
        }
    }
}

/// Pure check behind [`App::qmd_available`], taking its inputs explicitly
/// so tests can control them without touching the process environment.
fn qmd_available_on(
    path_var: Option<&std::ffi::OsStr>,
    vault_root: Option<&std::path::Path>,
) -> bool {
    let on_path = path_var.is_some_and(|paths| {
        std::env::split_paths(paths).any(|dir| {
            dir.join(if cfg!(windows) { "qmd.exe" } else { "qmd" })
                .is_file()
        })
    });
    if !on_path {
        return false;
    }
    let Some(root) = vault_root else {
        return false;
    };
    root.join(".confidant/qmd-corpus").is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qmd_available_needs_qmd_on_path_and_corpus() {
        let tmp = tempfile::tempdir().unwrap();
        let bin_dir = tmp.path().join("bin");
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(vault.join(".confidant/qmd-corpus")).unwrap();
        let qmd_name = if cfg!(windows) { "qmd.exe" } else { "qmd" };
        let path_var = std::ffi::OsString::from(bin_dir.as_os_str());

        // qmd file missing -> not available.
        assert!(!qmd_available_on(Some(&path_var), Some(&vault)));
        // qmd present but no corpus -> not available.
        std::fs::write(bin_dir.join(qmd_name), b"").unwrap();
        let bare = tmp.path().join("bare");
        std::fs::create_dir_all(&bare).unwrap();
        assert!(!qmd_available_on(Some(&path_var), Some(&bare)));
        // qmd present + corpus -> available.
        assert!(qmd_available_on(Some(&path_var), Some(&vault)));
        // No PATH / no vault -> not available.
        assert!(!qmd_available_on(None, Some(&vault)));
        assert!(!qmd_available_on(Some(&path_var), None));
    }
}
