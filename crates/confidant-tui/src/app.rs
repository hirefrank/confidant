//! Application state machine for `confidant-tui`.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::theme;
use crate::theme::palette;

use crate::apply::{ApplyFlow, FlowPhase, StepApplyOutcome, StepStatus, WriteOutcome};
use crate::capture::{self, Capture, CaptureKind, CapturePhase, FieldId};
use crate::contract::{
    parse_raw_output, CheckReport, Context, ContractOutcome, DoctorReport, EditSource, ErrorBody,
    FindResult, InboxReport, ResolveApplied, ResolveShow, Roster, SearchResult,
};
use crate::edit::{self, EditFlow, EditPhase};
use crate::ids;
use crate::proposals::{discover_proposals, resolve_vault_root, DiscoveredProposal};
use crate::runner::{RawOutput, Runner};
use crate::search::{filter_search_result, find_result_to_search, SearchViewState};
use crate::views::alert::{self, AlertState};
use crate::views::capture as capture_view;
use crate::views::check::{self, CheckViewState};
use crate::views::confirm::{self, ConfirmState};
use crate::views::conflict::{self, ConflictAction, ConflictViewState};
use crate::views::context::{self, ContextViewState};
use crate::views::diff::{self, DiffState};
use crate::views::doctor::{self, DoctorViewState};
use crate::views::help;
use crate::views::inbox::{self, InboxViewState};
use crate::views::info::{self, InfoState};
use crate::views::palette::{render as render_palette, PaletteState};
use crate::views::people::{self, PeopleViewState};
use crate::views::proposals::{
    self, ProposalDetailState, ProposalListEntry, ProposalsListState, StepRow,
};
use crate::views::search;

/// The three workspaces of the operator layout (#556 phase 1).
///
/// The underlying [`ActiveView`] still exists per view; a workspace is the
/// coarse job the operator is doing. `Search` and `Context` live under
/// People; Proposals/Inbox/Conflicts share the Review workspace and carry a
/// pending-count badge so a queued item is visible from any workspace
/// (#556 phase 3); Check and Doctor are the third workspace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Workspace {
    #[default]
    People,
    Review,
    Check,
}

impl Workspace {
    pub fn label(self) -> &'static str {
        match self {
            Self::People => "1 People & Search",
            Self::Review => "2 Review Queue",
            Self::Check => "3 Check",
        }
    }

    /// Views in tab order inside this workspace.
    fn views(self) -> &'static [ActiveView] {
        match self {
            Self::People => &[ActiveView::People, ActiveView::Search],
            Self::Review => &[
                ActiveView::Proposals,
                ActiveView::Inbox,
                ActiveView::Conflicts,
            ],
            Self::Check => &[ActiveView::Check, ActiveView::Doctor],
        }
    }
}

/// The underlying views: People & Search (master–detail), Check, full-screen
/// Context, Doctor, Proposals, unified Search (qmd-ranked with an exact
/// `find` toggle), Inbox, and Conflicts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ActiveView {
    #[default]
    People,
    Check,
    Context,
    Doctor,
    Proposals,
    Search,
    Inbox,
    Conflicts,
}

impl ActiveView {
    /// The workspace this view belongs to.
    pub fn workspace(self) -> Workspace {
        match self {
            Self::People | Self::Search | Self::Context => Workspace::People,
            Self::Proposals | Self::Inbox | Self::Conflicts => Workspace::Review,
            Self::Check | Self::Doctor => Workspace::Check,
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
    EditingFilter,
}

/// An interactive `confidant` invocation the TUI must run outside its
/// alternate screen (#456 hand-merge): the host suspends the terminal,
/// runs the argv, then resumes and refreshes.
///
/// `program: None` runs the resolved `confidant` binary; `Some(program)`
/// runs an external program (the operator's `$EDITOR` on a scratch file,
/// #556 phase 2). Both inherit the terminal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SuspendedCommand {
    pub program: Option<String>,
    pub args: Vec<String>,
}

impl SuspendedCommand {
    /// Run the `confidant` binary with `args`.
    pub fn confidant(args: Vec<String>) -> Self {
        Self {
            program: None,
            args,
        }
    }

    /// Run `program` with `args` (the operator's editor).
    pub fn program(program: String, args: Vec<String>) -> Self {
        Self {
            program: Some(program),
            args,
        }
    }
}

/// The operator-mode banner. Byte-identical to the CLI's
/// (`crates/confidant-cli/src/main.rs` `OPERATOR_MODE_BANNER`) so a screen
/// share shows the same warning whichever front end is on screen.
pub const OPERATOR_MODE_BANNER: &str = "OPERATOR MODE: no-ai records included (--for-operator)";

/// Top-level TUI state machine generic over a [`Runner`].
pub struct App<R: Runner> {
    pub runner: R,
    pub active_view: ActiveView,
    pub input_mode: InputMode,
    pub vault: Option<String>,
    pub check: CheckViewState,
    pub context: ContextViewState,
    pub people: PeopleViewState,
    pub doctor: DoctorViewState,
    pub search: SearchViewState,
    pub alert: Option<AlertState>,
    pub blocking_alert: Option<AlertState>,
    /// Scope names resolved by the last scoped read (`record list`).
    pub scope: Option<Vec<String>>,
    /// `p` Scope / `?` Help modal; any key dismisses it.
    pub info_modal: Option<InfoState>,
    /// The `:` / `Ctrl-P` command palette (#556 phase 5). While `Some`, the
    /// palette owns the keyboard; `Enter` runs the highlighted entry through
    /// the same function its key binding calls, so a write still previews
    /// with `--dry-run` and waits for `y`.
    pub palette: Option<PaletteState>,
    pub should_quit: bool,
    pub proposals: ProposalsTab,
    pub inbox: InboxViewState,
    pub conflict: ConflictViewState,
    /// Pending interactive command (set by hand-merge confirm); the host
    /// takes it, suspends the terminal, runs it, and resumes.
    pub suspended: Option<SuspendedCommand>,
    /// Operator mode (#556 phase 2): when on, the roster and context are
    /// loaded with `--for-operator`, so `no-ai` people and notes appear with
    /// a tri-state badge and the footer carries the operator banner.
    /// Off by default: the flags are only ever passed after the human presses
    /// `!`, never on the TUI's own initiative.
    pub operator_mode: bool,
    /// The in-flight record/note edit (`e`). While `Some`, the confirm modal
    /// owns the keyboard and the scratch file is live on disk.
    pub edit_flow: Option<EditFlow>,
    /// The in-flight quick capture (`s`/`t`/`n`) (#556 phase 3). While `Some`,
    /// the capture modal owns the keyboard; nothing is written until the
    /// operator confirms the `--dry-run` preview.
    pub capture: Option<Capture>,
    vault_root_override: Option<std::path::PathBuf>,
}

impl<R: Runner> App<R> {
    /// Construct a new `App` on the `Check` view without running a command yet.
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            active_view: ActiveView::People,
            input_mode: InputMode::Normal,
            vault: None,
            check: CheckViewState::default(),
            context: ContextViewState::default(),
            people: PeopleViewState::default(),
            doctor: DoctorViewState::default(),
            search: SearchViewState::default(),
            alert: None,
            blocking_alert: None,
            scope: None,
            info_modal: None,
            palette: None,
            should_quit: false,
            proposals: ProposalsTab::default(),
            inbox: InboxViewState::default(),
            conflict: ConflictViewState::default(),
            suspended: None,
            operator_mode: false,
            edit_flow: None,
            capture: None,
            vault_root_override: None,
        }
    }

    /// Best-effort overwrite-with-zeros and removal of any stale edit scratch
    /// left by a crashed run (#455/#557 convention). This is hygiene, not
    /// secure deletion; called once at startup.
    pub fn sweep_stale_edit_scratch(&self) {
        if let Some(root) = resolve_vault_root(self.vault_root_override.as_deref()) {
            edit::sweep_stale_edit_scratch(&root);
        }
    }

    /// Set an explicit vault root (from `--vault`) for proposal discovery.
    pub fn set_vault_root(&mut self, root: std::path::PathBuf) {
        self.vault_root_override = Some(root);
    }

    /// Run `confidant check --json --no-input` and update the Check view
    /// state. The People workspace reuses the same cached report for its
    /// `Needs Attention` list; it never runs check per keystroke.
    ///
    /// A failed refresh clears the cached report: a stale report would keep
    /// rendering old nudges (or a false "Nothing needs attention") after
    /// check stopped answering.
    pub fn load_check(&mut self) {
        let raw = match self.runner.run(&["check"]) {
            Ok(r) => r,
            Err(e) => {
                self.check.report = None;
                self.check.selected = 0;
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                self.people.clamp(self.check.report.as_ref());
                return;
            }
        };
        match self.apply_outcome::<CheckReport>(&raw) {
            Some((_ok, report)) => self.check.report = Some(report),
            None => self.check.report = None,
        }
        self.check.selected = 0;
        self.people.clamp(self.check.report.as_ref());
    }

    /// Run `confidant record list --json --no-input --kind person` and
    /// update the People roster (#558). Without operator mode this is the
    /// cleared set: `no-ai: true` people are absent. With operator mode the
    /// call carries `--for-operator`, so `no-ai` people appear badged. On
    /// first load it selects the first person and loads their live context;
    /// refreshing preserves the current selection when that person is still
    /// in the roster.
    pub fn load_roster(&mut self) {
        let mut args: Vec<&str> = vec!["record", "list", "--kind", "person"];
        if self.operator_mode {
            args.push("--for-operator");
        }
        let raw = match self.runner.run(&args) {
            Ok(r) => r,
            Err(e) => {
                self.people.loaded = true;
                self.people.load_error = Some(format!("{e:#}"));
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        match parse_raw_output::<Roster>(&raw) {
            ContractOutcome::Ok { vault, data, .. } => {
                if vault.is_some() {
                    self.vault = vault;
                }
                self.alert = None;
                self.scope = Some(data.scope.clone());
                self.people.roster = Some(data);
                self.people.load_error = None;
                self.people.loaded = true;
                let prefer_first = self.people.selected_person.is_none();
                self.sync_people_selection(prefer_first);
            }
            ContractOutcome::VersionMismatch { reported_version } => {
                self.people.loaded = true;
                self.people.load_error = Some("unsupported agent contract version".to_owned());
                self.blocking_alert = Some(AlertState::version_mismatch(&reported_version));
            }
            ContractOutcome::CliError {
                status,
                usage_error,
                error,
            } => {
                self.people.loaded = true;
                self.people.load_error = Some(error.message.clone());
                let cli_alert = self.cli_error_alert(status, usage_error, &error);
                self.alert = Some(cli_alert);
            }
            ContractOutcome::InvalidJson { status } => {
                self.people.loaded = true;
                self.people.load_error = Some("invalid roster JSON".to_owned());
                self.alert = Some(AlertState::invalid_json(status));
            }
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
                self.alert = Some(no_vault_alert());
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
                raw: None,
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
                    raw: None,
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
                    raw: None,
                });
                None
            }
        }
    }

    /// Run `confidant context --json --no-input -- <person_id>` and update
    /// the Context view state. With operator mode the call carries
    /// `--for-operator`, so `no-ai` people, notes, and interactions come
    /// back with the tri-state `no_ai`. The People workspace's right pane and
    /// the full-screen Context view share this state.
    pub fn load_context(&mut self, person_id: &str) {
        let pid = person_id.to_owned();
        let changed = self.context.person_id.as_deref() != Some(pid.as_str());
        if changed {
            self.context.context = None;
            self.context.scroll = 0;
            self.context.edit_index = 0;
        }
        self.context.person_id = Some(pid.clone());
        let mut args: Vec<&str> = vec!["context"];
        if self.operator_mode {
            args.push("--for-operator");
        }
        args.push("--");
        args.push(&pid);
        let raw = match self.runner.run(&args) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        if let Some((_ok, ctx)) = self.apply_outcome::<Context>(&raw) {
            if self.scope.is_none() && !ctx.scope.is_empty() {
                self.scope = Some(ctx.scope.clone());
            }
            self.context.context = Some(ctx);
            self.context.scroll = 0;
            // The bundle changed under the cursor: keep the edit target in
            // range rather than pointing at a record that no longer renders.
            let count = self
                .context
                .context
                .as_ref()
                .map(|ctx| context::edit_targets(ctx).len())
                .unwrap_or(0);
            if count == 0 {
                self.context.edit_index = 0;
            } else if self.context.edit_index >= count {
                self.context.edit_index = count - 1;
            }
        }
    }

    /// Toggle operator mode (#556 phase 2): the explicit human action that
    /// lets the TUI pass `--for-operator`. Reloads the check report, the
    /// roster, and the selected person's context through the new path.
    ///
    /// Turning **off** fails closed: everything the operator path may have
    /// surfaced is dropped *before* the agent-path reload. If that reload
    /// fails, the panes show "not loaded" rather than leaving hidden people
    /// or notes on screen without the operator banner.
    pub fn toggle_operator_mode(&mut self) {
        self.operator_mode = !self.operator_mode;
        if !self.operator_mode {
            // Clear the operator-derived views first. `load_roster` and
            // `load_context` keep their previous value on failure, so without
            // this a failed reload would leave `no-ai` content visible while
            // the banner is gone.
            self.people.roster = None;
            self.people.selected = 0;
            self.context.context = None;
            self.context.scroll = 0;
            self.context.edit_index = 0;
            // An edit started in operator mode cannot be pending here (the
            // confirm modal swallows every key, including `!`), but cancelling
            // is harmless and keeps the removal of hidden state exhaustive.
            self.cancel_edit();
        }
        self.load_check();
        self.load_roster();
        if let Some(pid) = self.context.person_id.clone() {
            self.load_context(&pid);
        }
    }

    /// Move the context pane's edit target by `delta`, wrapping. No CLI call.
    fn move_edit_target(&mut self, delta: i32) {
        let count = self
            .context
            .context
            .as_ref()
            .map(|ctx| context::edit_targets(ctx).len())
            .unwrap_or(0);
        if count == 0 {
            self.context.edit_index = 0;
            return;
        }
        let current = self.context.edit_index.min(count - 1);
        self.context.edit_index = (current as i32 + delta).rem_euclid(count as i32) as usize;
    }

    /// Reconcile the left-pane selection with the current roster, filter,
    /// and nudge list. `prefer_first` forces the first person to be
    /// selected (used when the roster is first loaded); otherwise the
    /// current person is kept when still visible.
    fn sync_people_selection(&mut self, prefer_first: bool) {
        let nudge_count =
            people::attention(self.check.report.as_ref(), self.people.roster.as_ref()).len();
        let ids: Vec<String> =
            people::filtered_entries(self.people.roster.as_ref(), &self.people.filter)
                .iter()
                .map(|entry| entry.id.clone())
                .collect();
        let total = nudge_count + ids.len();
        if total == 0 {
            self.people.selected = 0;
            self.people.selected_person = None;
            self.context.person_id = None;
            self.context.context = None;
            return;
        }

        if prefer_first {
            self.people.selected_person = None;
            self.people.selected = nudge_count;
        } else if let Some(id) = self.people.selected_person.as_deref() {
            if let Some(index) = ids.iter().position(|candidate| candidate == id) {
                self.people.selected = nudge_count + index;
            } else {
                // The selected person left the roster (or the filter hid
                // them): fall through to the first visible row.
                self.people.selected_person = None;
            }
        }
        self.people.selected = self.people.selected.min(total - 1);

        if self.people.selected >= nudge_count && !ids.is_empty() {
            let index = self.people.selected - nudge_count;
            let id = ids[index].clone();
            if self.people.selected_person.as_deref() != Some(id.as_str()) {
                self.people.selected_person = Some(id.clone());
                self.load_context(&id);
            }
        } else if self.people.selected_person.is_none() && !ids.is_empty() {
            self.people.selected = nudge_count;
            let id = ids[0].clone();
            self.people.selected_person = Some(id.clone());
            self.load_context(&id);
        }
    }

    /// Move the People selection by one row. Landing on a person loads
    /// their live context; nudges leave the right pane on the last person.
    fn move_people_selection(&mut self, delta: i32) {
        let nudge_count =
            people::attention(self.check.report.as_ref(), self.people.roster.as_ref()).len();
        let ids: Vec<String> =
            people::filtered_entries(self.people.roster.as_ref(), &self.people.filter)
                .iter()
                .map(|entry| entry.id.clone())
                .collect();
        let total = nudge_count + ids.len();
        if total == 0 {
            return;
        }
        let next = (self.people.selected as i32 + delta).clamp(0, total as i32 - 1) as usize;
        self.select_people_row(next);
    }

    /// Select a row in the combined nudge + roster list and load the
    /// person's context when the row is a person.
    fn select_people_row(&mut self, next: usize) {
        let nudge_count =
            people::attention(self.check.report.as_ref(), self.people.roster.as_ref()).len();
        let ids: Vec<String> =
            people::filtered_entries(self.people.roster.as_ref(), &self.people.filter)
                .iter()
                .map(|entry| entry.id.clone())
                .collect();
        let total = nudge_count + ids.len();
        if total == 0 {
            return;
        }
        let next = next.min(total - 1);
        self.people.selected = next;
        if next >= nudge_count {
            let id = ids[next - nudge_count].clone();
            if self.people.selected_person.as_deref() != Some(id.as_str()) {
                self.people.selected_person = Some(id.clone());
                self.load_context(&id);
            }
        }
    }

    /// `Enter`: on a nudge, focus the person it names (clearing a filter
    /// that hides them); on a person row, load that row's context.
    fn activate_people_selection(&mut self) {
        let nudge_count =
            people::attention(self.check.report.as_ref(), self.people.roster.as_ref()).len();
        if self.people.selected < nudge_count {
            let nudge = people::attention(self.check.report.as_ref(), self.people.roster.as_ref())
                .into_iter()
                .nth(self.people.selected);
            if let Some(nudge) = nudge {
                self.focus_person(&nudge.person_id);
            }
            return;
        }
        let ids: Vec<String> =
            people::filtered_entries(self.people.roster.as_ref(), &self.people.filter)
                .iter()
                .map(|entry| entry.id.clone())
                .collect();
        if let Some(id) = ids.get(self.people.selected - nudge_count).cloned() {
            self.people.selected_person = Some(id.clone());
            self.load_context(&id);
        }
    }

    /// Select a person by id, clearing the local filter if needed, and load
    /// their live context.
    fn focus_person(&mut self, id: &str) {
        let visible = people::filtered_entries(self.people.roster.as_ref(), &self.people.filter)
            .iter()
            .any(|entry| entry.id == id);
        if !visible {
            self.people.filter.clear();
            self.people.editing_filter = false;
            self.input_mode = InputMode::Normal;
        }
        let nudge_count =
            people::attention(self.check.report.as_ref(), self.people.roster.as_ref()).len();
        let ids: Vec<String> =
            people::filtered_entries(self.people.roster.as_ref(), &self.people.filter)
                .iter()
                .map(|entry| entry.id.clone())
                .collect();
        if let Some(index) = ids.iter().position(|candidate| candidate == id) {
            self.people.selected = nudge_count + index;
            self.people.selected_person = Some(id.to_owned());
            self.load_context(id);
        }
    }

    /// `/` in People: edit the local roster filter. No CLI call is made
    /// while typing.
    fn enter_filter(&mut self) {
        self.active_view = ActiveView::People;
        self.input_mode = InputMode::EditingFilter;
        self.people.editing_filter = true;
        self.search.editing = false;
        self.alert = None;
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
    ///
    /// Returns `false` when the dry run failed (runner error, CLI error,
    /// invalid JSON, or a version mismatch); in that case any report already
    /// on the state is left untouched, and the caller must not treat it as a
    /// fresh preview. The palette's apply entry gates its confirm on this.
    pub fn load_inbox(&mut self) -> bool {
        let raw = match self.runner.run(&["inbox", "--dry-run"]) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return false;
            }
        };
        if let Some((_, report)) = self.apply_outcome::<InboxReport>(&raw) {
            self.inbox.report = Some(report);
            self.inbox.confirming = false;
            self.inbox.last_apply = None;
            true
        } else {
            false
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
            self.conflict.entries = conflict::entries_from_report(Some(&report));
            // Keep the cached check report in step: the Review Queue badge
            // reads conflicts from it, so a resolve must move the count too.
            // Reset the Check list cursor too, or it can open on a stale row.
            self.check.report = Some(report);
            self.check.selected = 0;
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
            raw: None,
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
        let raw = match self.runner.run(&["record", "resolve", &id, "--show"]) {
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
                let cli_alert = self.cli_error_alert(status, usage_error, &error);
                self.alert = Some(cli_alert);
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
                let cli_alert = self.cli_error_alert(status, usage_error, &error);
                self.alert = Some(cli_alert);
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
        self.suspended = Some(SuspendedCommand::confidant(vec![
            "record".to_owned(),
            "resolve".to_owned(),
            id,
            "--edit".to_owned(),
        ]));
    }

    /// Take the pending interactive command for the host to run while the
    /// alternate screen is suspended.
    pub fn take_suspended_command(&mut self) -> Option<SuspendedCommand> {
        self.suspended.take()
    }

    /// Run a suspended command through the runner with an inherited
    /// terminal. Called by the host while the TUI is suspended.
    pub fn run_suspended_command(&self, cmd: &SuspendedCommand) -> anyhow::Result<i32> {
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        match &cmd.program {
            None => self.runner.run_confidant_interactive(&args),
            Some(program) => self.runner.run_program_interactive(program, &args),
        }
    }

    /// Refresh after an interactive command completes.
    ///
    /// For the conflict hand-merge (#456) the merge may have resolved the
    /// record, so reload the list and close the detail. For an edit
    /// (#556 phase 2) the editor has changed the scratch file: read it back
    /// and either confirm the write or report a no-op. A failed or nonzero
    /// run raises the alert view instead of silently refreshing.
    pub fn after_suspended_command(&mut self, result: anyhow::Result<i32>) {
        self.suspended = None;
        if self.edit_flow.is_some() {
            self.after_edit_editor(result);
            return;
        }
        // Reload first: the loaders clear the alert on success, so the
        // failure alert below must be raised after.
        self.load_conflicts();
        match result {
            Ok(0) => {}
            Ok(status) => {
                self.alert = Some(AlertState {
                    title: "Hand-merge failed".to_owned(),
                    code: None,
                    message: format!("`record resolve --edit` exited with status {status}"),
                    fix: Some("re-run the hand-merge from the conflict detail view".to_owned()),
                    blocking: false,
                    raw: None,
                });
            }
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!(
                    "hand-merge command failed: {e:#}"
                )));
            }
        }
    }

    /// `e`: edit the context pane's selected item (person, note, or
    /// interaction) through the operator scratch/editor flow. Operator-only
    /// by construction: `record show --for-edit` / `note show --for-edit`
    /// are the same reads the CLI reserves for the human.
    pub fn begin_edit(&mut self) {
        if self.edit_flow.is_some() {
            return;
        }
        let Some(root) = resolve_vault_root(self.vault_root_override.as_deref()) else {
            self.alert = Some(no_vault_alert());
            return;
        };
        let Some(ctx) = self.context.context.clone() else {
            self.alert = Some(AlertState {
                title: "Nothing to Edit".to_owned(),
                code: Some("no_context".to_owned()),
                message: "no context is loaded for the selected person".to_owned(),
                fix: Some("select a person in People, then press e".to_owned()),
                blocking: false,
                raw: None,
            });
            return;
        };
        let targets = context::edit_targets(&ctx);
        if targets.is_empty() {
            return;
        }
        let target = targets[self.context.edit_index.min(targets.len() - 1)].clone();

        // Pre-flight: the plaintext scratch must not be committable. Mirrors
        // the CLI's `git check-ignore` gate before it writes plaintext.
        if !self.scratch_is_gitignored(&root) {
            self.alert = Some(AlertState {
                title: "Edit Refused".to_owned(),
                code: Some("scratch_not_ignored".to_owned()),
                message: "`.confidant/` is not git-ignored in this vault, so the edit scratch could be committed".to_owned(),
                fix: Some("Add `.confidant/` to .gitignore, then retry".to_owned()),
                blocking: false,
                raw: None,
            });
            return;
        }

        // Fail fast: no editor means no plaintext scratch is written.
        let Some(editor) = edit::resolve_editor() else {
            self.alert = Some(AlertState {
                title: "No Editor Configured".to_owned(),
                code: Some("no_editor".to_owned()),
                message: "neither $VISUAL nor $EDITOR is set".to_owned(),
                fix: Some("Set $EDITOR (or $VISUAL), then press e again".to_owned()),
                blocking: false,
                raw: None,
            });
            return;
        };

        // The operator-only read that prints the current text as JSON.
        let argv = target.kind.show_argv(&target.id);
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let raw = match self.runner.run(&refs) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        let source = match parse_raw_output::<EditSource>(&raw) {
            ContractOutcome::Ok { vault, data, .. } => {
                if vault.is_some() {
                    self.vault = vault;
                }
                self.alert = None;
                data
            }
            ContractOutcome::VersionMismatch { reported_version } => {
                self.blocking_alert = Some(AlertState::version_mismatch(&reported_version));
                return;
            }
            ContractOutcome::CliError {
                status,
                usage_error,
                error,
            } => {
                let cli_alert = self.cli_error_alert(status, usage_error, &error);
                self.alert = Some(cli_alert);
                return;
            }
            ContractOutcome::InvalidJson { status } => {
                self.alert = Some(AlertState::invalid_json(status));
                return;
            }
        };

        let Some(scratch) = edit::scratch_path(&root, &target.id) else {
            self.alert = Some(AlertState {
                title: "Edit Refused".to_owned(),
                code: Some("unsafe_id".to_owned()),
                message: format!("{} is not a usable record id", target.id),
                fix: None,
                blocking: false,
                raw: None,
            });
            return;
        };
        // Clear any stale scratch from a crashed run before writing ours.
        edit::sweep_stale_edit_scratch(&root);
        if let Err(e) = edit::write_scratch(&scratch, &source.text) {
            self.alert = Some(AlertState {
                title: "Cannot Stage Scratch".to_owned(),
                code: Some("scratch_write_failed".to_owned()),
                message: format!("{e:#}"),
                fix: Some(format!("Check permissions on {}", root.display())),
                blocking: false,
                raw: None,
            });
            return;
        }
        self.edit_flow = Some(EditFlow {
            target,
            scratch: scratch.clone(),
            original: source.text,
            edited: None,
            phase: EditPhase::Editing,
        });
        self.suspended = Some(SuspendedCommand::program(
            editor,
            vec![scratch.display().to_string()],
        ));
    }

    /// After the editor exits: a failed run or an unchanged file writes
    /// nothing; otherwise arm the confirm modal.
    fn after_edit_editor(&mut self, result: anyhow::Result<i32>) {
        let Some(flow) = self.edit_flow.take() else {
            return;
        };
        match result {
            Ok(0) => {}
            Ok(status) => {
                edit::remove_scratch(&flow.scratch);
                self.alert = Some(AlertState {
                    title: "Editor Exited with an Error".to_owned(),
                    code: Some("editor_failed".to_owned()),
                    message: format!("the editor exited with status {status}; nothing was written"),
                    fix: Some("Retry the edit with e".to_owned()),
                    blocking: false,
                    raw: None,
                });
                return;
            }
            Err(e) => {
                edit::remove_scratch(&flow.scratch);
                self.alert = Some(AlertState::runner_error(&format!(
                    "could not run the editor: {e:#}"
                )));
                return;
            }
        }
        match edit::read_scratch(&flow.scratch) {
            // A no-op edit never reaches the CLI, so nothing can be committed.
            Ok(text) if text == flow.original => {
                edit::remove_scratch(&flow.scratch);
                self.alert = Some(AlertState {
                    title: "No Changes".to_owned(),
                    code: Some("unchanged".to_owned()),
                    message: format!("{} was not changed; nothing was written", flow.target.id),
                    fix: None,
                    blocking: false,
                    raw: None,
                });
            }
            Ok(text) => {
                self.edit_flow = Some(EditFlow {
                    edited: Some(text),
                    phase: EditPhase::Confirm,
                    ..flow
                });
            }
            Err(e) => {
                edit::remove_scratch(&flow.scratch);
                self.alert = Some(AlertState {
                    title: "Cannot Read the Edited File".to_owned(),
                    code: Some("scratch_read_failed".to_owned()),
                    message: format!("{e:#}"),
                    fix: Some("Retry the edit with e".to_owned()),
                    blocking: false,
                    raw: None,
                });
            }
        }
    }

    /// The confirm modal owns every key once the editor returns: `y` writes
    /// through the CLI, anything else cancels and removes the scratch.
    /// Returns true when the key was consumed.
    fn handle_edit_confirm_key(&mut self, key: KeyEvent) -> bool {
        let Some(flow) = self.edit_flow.as_ref() else {
            return false;
        };
        if flow.phase != EditPhase::Confirm {
            return false;
        }
        if matches!(key.code, KeyCode::Char('y')) {
            self.apply_edit();
        } else {
            self.cancel_edit();
        }
        true
    }

    /// Cancel the pending edit: remove the scratch, write nothing.
    fn cancel_edit(&mut self) {
        if let Some(flow) = self.edit_flow.take() {
            edit::remove_scratch(&flow.scratch);
        }
    }

    /// Run the confirmed write (`record edit --file` / `note edit --file`),
    /// then remove the scratch and surface the outcome. Always cleans up:
    /// the CLI has already read the file by the time it returns.
    fn apply_edit(&mut self) {
        let Some(flow) = self.edit_flow.take() else {
            return;
        };
        let Some(file) = flow.scratch.to_str().map(str::to_owned) else {
            edit::remove_scratch(&flow.scratch);
            return;
        };
        let argv = flow.target.kind.edit_argv(&flow.target.id, &file);
        let outcome = crate::apply::run_write_step(&self.runner, &argv, false);
        edit::remove_scratch(&flow.scratch);
        let id = flow.target.id.clone();
        let noun = flow.target.kind.noun();
        match outcome {
            Ok(WriteOutcome::Applied { commit, .. }) => {
                self.reload_after_write();
                self.alert = Some(AlertState {
                    title: "Edit Committed".to_owned(),
                    code: Some("committed".to_owned()),
                    message: format!("{noun} {id} edited (commit {})", short_commit(&commit)),
                    fix: None,
                    blocking: false,
                    raw: None,
                });
            }
            Ok(WriteOutcome::Idempotent { .. }) => {
                self.reload_after_write();
                self.alert = Some(AlertState {
                    title: "No Changes".to_owned(),
                    code: Some("unchanged".to_owned()),
                    message: format!("{noun} {id} was unchanged; nothing was committed"),
                    fix: None,
                    blocking: false,
                    raw: None,
                });
            }
            Ok(WriteOutcome::CheckBlocked { report }) => {
                // The report renders in the Check view itself.
                self.check.report = Some(report);
                self.check.selected = 0;
                self.active_view = ActiveView::Check;
            }
            Ok(WriteOutcome::CliError { code, message, fix }) => {
                self.alert = Some(AlertState {
                    title: format!("Edit Failed ({code})"),
                    code: Some(code),
                    message,
                    fix,
                    blocking: false,
                    raw: None,
                });
            }
            Ok(WriteOutcome::DryRun { .. }) => {
                self.alert = Some(AlertState {
                    title: "Edit Failed".to_owned(),
                    code: Some("unexpected_outcome".to_owned()),
                    message: "the edit command returned a dry-run preview; nothing was applied"
                        .to_owned(),
                    fix: None,
                    blocking: false,
                    raw: None,
                });
            }
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
            }
        }
    }

    /// Reload the views a write can change: the check report (a write can add
    /// findings), the roster (a name or `no-ai` mode may differ), and the
    /// selected person's context (the body/notes/interactions changed).
    /// Shared by the `e` edit and the `s`/`t`/`n` captures.
    fn reload_after_write(&mut self) {
        self.load_check();
        self.load_roster();
        if let Some(pid) = self.context.person_id.clone() {
            self.load_context(&pid);
        }
    }

    /// The selected person's opaque id and, when known, display name. The
    /// capture modals pre-fill this so the operator never types a ULID.
    ///
    /// The full-screen Context view can show a person reached from a Search
    /// hit or a Check finding without moving the People cursor
    /// ([`Self::activate_selected`] calls `load_context` but not
    /// `sync_people_selection`). When Context is the visible view, the person
    /// on screen is the capture target — never a stale People row — so the
    /// form and the write can't disagree with what the operator is reading.
    fn selected_person(&self) -> Option<(String, Option<String>)> {
        let id = if self.active_view == ActiveView::Context {
            self.context
                .person_id
                .clone()
                .or_else(|| self.people.selected_person.clone())
        } else {
            self.people
                .selected_person
                .clone()
                .or_else(|| self.context.person_id.clone())
        }?;
        let name = self
            .context
            .context
            .as_ref()
            .filter(|ctx| ctx.person.id == id)
            .and_then(|ctx| ctx.person.name.clone())
            .or_else(|| people::person_name(self.people.roster.as_ref(), &id).map(str::to_owned));
        Some((id, name))
    }

    /// `s`/`t`/`n`: open a quick-capture form pre-filled with the selected
    /// person. Writes nothing; the operator confirms the CLI's dry run first.
    pub fn begin_capture(&mut self, kind: CaptureKind) {
        if self.capture.is_some() {
            return;
        }
        let Some((id, name)) = self.selected_person() else {
            self.alert = Some(AlertState {
                title: "No Person Selected".to_owned(),
                code: Some("no_person".to_owned()),
                message: format!(
                    "{} capture needs a person: no roster row is selected",
                    kind.noun()
                ),
                fix: Some("Select a person in People, then retry".to_owned()),
                blocking: false,
                raw: None,
            });
            return;
        };
        self.alert = None;
        self.capture = Some(Capture::new(kind, id, name));
    }

    /// `a` (#621): open the new-person form, minting the `p-<ULID>` the CLI
    /// requires in the record's front matter. Nothing is written and no
    /// person is selected: this is the one capture that starts from an empty
    /// form. A pending write (another capture, an edit confirm, or a proposal
    /// modal) keeps the keyboard, so this is only reachable at browse level;
    /// the guard below also makes a programmatic call a safe no-op.
    pub fn begin_new_person(&mut self) {
        if self.capture.is_some() {
            return;
        }
        let id = match ids::new_person_id() {
            Ok(id) => id,
            Err(e) => {
                self.alert = Some(AlertState {
                    title: "Cannot Mint a Person ID".to_owned(),
                    code: Some("id_mint_failed".to_owned()),
                    message: format!("could not mint a ULID for the new person: {e:#}"),
                    fix: Some(
                        "Retry; if it persists, check the system clock and available entropy"
                            .to_owned(),
                    ),
                    blocking: false,
                    raw: None,
                });
                return;
            }
        };
        self.alert = None;
        self.capture = Some(Capture::new(CaptureKind::NewPerson, id, None));
    }

    /// Run each capture source that is cheap to know up front so the Review
    /// Queue badge is populated from launch: the proposal manifests from disk,
    /// and the inbox dry run. Conflicts are derived from the check report
    /// `load_check` already fetched.
    ///
    /// The inbox read must not mask an earlier startup failure: a successful
    /// `load_inbox` clears the alert (the usual "a good reload clears the
    /// alert" rule), and a failed one replaces it. Either way an alert raised
    /// by the startup `check`/roster load is the one the operator should see,
    /// so it is restored when there was one.
    pub fn prime_review_queue(&mut self) {
        self.load_proposals();
        let prior_alert = self.alert.take();
        self.load_inbox();
        if prior_alert.is_some() {
            self.alert = prior_alert;
        }
    }

    /// Pending items across the Review Queue sources: proposal manifests,
    /// inbox items to merge, and conflicted records. Derived from cached
    /// state only; nothing here runs the CLI.
    pub fn review_pending(&self) -> usize {
        let proposals = self.proposals.entries.len();
        let inbox = self
            .inbox
            .report
            .as_ref()
            .filter(|report| !report.empty)
            .map(|report| report.items.len())
            .unwrap_or(0);
        let conflicts = conflict::entries_from_report(self.check.report.as_ref()).len();
        proposals + inbox + conflicts
    }

    /// The workspace tab label, with a pending-count badge on Review Queue.
    fn workspace_label(&self, workspace: Workspace) -> String {
        if workspace == Workspace::Review {
            let pending = self.review_pending();
            if pending > 0 {
                return format!("{} ({pending})", workspace.label());
            }
        }
        workspace.label().to_owned()
    }

    /// Handle a key event while a capture modal is open. Returns true when the
    /// key was consumed. The modal owns every key: while editing, `Enter` runs
    /// the dry run, `Esc` cancels, `Tab` moves the field, and everything else
    /// edits a field. In the preview, `y` writes and any other key cancels.
    fn handle_capture_key(&mut self, key: KeyEvent) -> bool {
        let Some(phase) = self.capture.as_ref().map(|capture| capture.phase) else {
            return false;
        };
        match phase {
            CapturePhase::Editing => {
                match key.code {
                    KeyCode::Esc => self.cancel_capture(),
                    KeyCode::Enter => self.capture_begin_preview(),
                    KeyCode::Tab => {
                        if let Some(capture) = self.capture.as_mut() {
                            capture.focus_next(true);
                        }
                    }
                    KeyCode::BackTab => {
                        if let Some(capture) = self.capture.as_mut() {
                            capture.focus_next(false);
                        }
                    }
                    KeyCode::Backspace => {
                        if let Some(capture) = self.capture.as_mut() {
                            capture.backspace();
                        }
                    }
                    KeyCode::Char(' ') => {
                        if let Some(capture) = self.capture.as_mut() {
                            capture.space();
                        }
                    }
                    KeyCode::Char(c)
                        if !key.modifiers.contains(KeyModifiers::CONTROL)
                            && !key.modifiers.contains(KeyModifiers::ALT) =>
                    {
                        if let Some(capture) = self.capture.as_mut() {
                            capture.push_char(c);
                        }
                    }
                    _ => {}
                }
                true
            }
            CapturePhase::Preview => {
                if matches!(key.code, KeyCode::Char('y')) {
                    self.capture_confirm();
                } else {
                    self.cancel_capture();
                }
                true
            }
        }
    }

    /// Stage the input a file-backed write needs (a note body for
    /// `note add --body-file`, or a composed record for `record add --file`),
    /// then run the CLI's `--dry-run` preview. Nothing is written to the
    /// vault.
    fn capture_begin_preview(&mut self) {
        let Some(kind) = self.capture.as_ref().map(|capture| capture.kind) else {
            return;
        };
        let missing = self
            .capture
            .as_ref()
            .and_then(|capture| capture.first_missing());
        if let Some(label) = missing {
            self.set_capture_error(format!("{label} is required"));
            return;
        }
        // A new preview invalidates any earlier pin: if staging or the CLI
        // fails from here, a confirm must not be able to reuse a stale hash.
        if let Some(capture) = self.capture.as_mut() {
            capture.reviewed_hash = None;
        }

        // Only the file-backed surfaces need a scratch; the inline surfaces
        // (session/touch) pass their note as an argument.
        let mut scratch_arg: Option<String> = None;
        if kind.stages_scratch() {
            let (person_id, staged) = {
                let Some(capture) = self.capture.as_ref() else {
                    return;
                };
                let staged = match kind {
                    CaptureKind::Note => capture.value(FieldId::Body).to_owned(),
                    CaptureKind::NewPerson => capture.compose_record(),
                    _ => unreachable!("stages_scratch covers only the file surfaces"),
                };
                (capture.person_id.clone(), staged)
            };
            let Some(root) = resolve_vault_root(self.vault_root_override.as_deref()) else {
                self.set_capture_error(
                    "no vault found: pass --vault or set CONFIDANT_VAULT".to_owned(),
                );
                return;
            };
            if !self.scratch_is_gitignored(&root) {
                self.set_capture_error(
                    "`.confidant/` is not git-ignored in this vault, so the scratch could be committed"
                        .to_owned(),
                );
                return;
            }
            let Some(path) = capture::scratch_path(&root, &person_id) else {
                self.set_capture_error(format!("{person_id} is not a usable person id"));
                return;
            };
            if let Err(e) = edit::write_scratch(&path, &staged) {
                self.set_capture_error(format!("cannot stage the scratch: {e:#}"));
                return;
            }
            if let Some(capture) = self.capture.as_mut() {
                capture.scratch = Some(path.clone());
                // Pin the bytes this preview reviews (#611/#618): a confirm
                // re-reads the scratch and refuses if it changed.
                capture.reviewed_hash = Some(crate::apply::sha256_hex(staged.as_bytes()));
            }
            scratch_arg = path.to_str().map(str::to_owned);
        }

        let Some(capture) = self.capture.as_ref() else {
            return;
        };
        let argv = capture.argv(scratch_arg.as_deref());
        match crate::apply::run_write_step(&self.runner, &argv, true) {
            Ok(WriteOutcome::DryRun { changes, .. }) => {
                if let Some(capture) = self.capture.as_mut() {
                    capture.preview = changes;
                    capture.phase = CapturePhase::Preview;
                    capture.error = None;
                }
            }
            Ok(WriteOutcome::CliError { code, message, fix }) => {
                self.clear_preview_scratch();
                self.set_capture_error(cli_error_message(&code, &message, fix.as_deref()));
            }
            Ok(WriteOutcome::CheckBlocked { .. }) => {
                self.clear_preview_scratch();
                self.set_capture_error(
                    "check blocked the preview; fix the findings, then retry".to_owned(),
                );
            }
            Ok(other) => {
                self.clear_preview_scratch();
                self.set_capture_error(format!("unexpected preview outcome: {other:?}"));
            }
            Err(e) => {
                self.clear_preview_scratch();
                self.set_capture_error(format!("could not run confidant: {e:#}"));
            }
        }
    }

    /// A failed preview wrote nothing: sweep any staged plaintext and clear
    /// the review pin so the form stays open with nothing left on disk.
    fn clear_preview_scratch(&mut self) {
        if let Some(capture) = self.capture.as_mut() {
            if let Some(path) = capture.scratch.take() {
                edit::remove_scratch(&path);
            }
            capture.reviewed_hash = None;
        }
    }

    /// The operator confirmed the preview: run the real write, then report the
    /// resulting commit. The scratch is removed on every path.
    fn capture_confirm(&mut self) {
        let Some(capture) = self.capture.take() else {
            return;
        };
        let kind = capture.kind;
        // #611/#618: the review is bound to what it showed. A file-backed
        // write (a note body, a composed person) staged plaintext for the
        // preview and the CLI re-reads that file now; if anything changed it
        // since the dry-run, refuse instead of committing bytes the operator
        // never saw. (The inline surfaces have no scratch and no pin.)
        if let (Some(expected), Some(path)) = (&capture.reviewed_hash, &capture.scratch) {
            let unchanged = std::fs::read(path)
                .map(|bytes| crate::apply::sha256_hex(&bytes) == *expected)
                .unwrap_or(false);
            if !unchanged {
                edit::remove_scratch(path);
                self.alert = Some(AlertState {
                    title: "Record Changed After Preview".to_owned(),
                    code: Some("source_changed".to_owned()),
                    message: "the staged record changed after the dry-run you reviewed; nothing was written"
                        .to_owned(),
                    fix: Some("Open the form again and review the new preview, then confirm".to_owned()),
                    blocking: false,
                    raw: None,
                });
                return;
            }
        }
        let scratch_arg = capture
            .scratch
            .as_ref()
            .and_then(|path| path.to_str())
            .map(str::to_owned);
        let argv = capture.argv(scratch_arg.as_deref());
        // Run first: the CLI reads `--body-file` / `--file` during the write.
        let outcome = crate::apply::run_write_step(&self.runner, &argv, false);
        if let Some(path) = &capture.scratch {
            edit::remove_scratch(path);
        }
        match outcome {
            Ok(WriteOutcome::Applied { commit, .. }) => {
                self.reload_after_write();
                self.alert = Some(AlertState {
                    title: "Capture Committed".to_owned(),
                    code: Some("committed".to_owned()),
                    message: format!(
                        "{} committed for {} (commit {})",
                        kind.noun(),
                        capture.person_id,
                        short_commit(&commit)
                    ),
                    fix: None,
                    blocking: false,
                    raw: None,
                });
            }
            Ok(WriteOutcome::Idempotent { .. }) => {
                self.reload_after_write();
                self.alert = Some(AlertState {
                    title: "No Changes".to_owned(),
                    code: Some("unchanged".to_owned()),
                    message: format!(
                        "{} for {} was unchanged; nothing was committed",
                        kind.noun(),
                        capture.person_id
                    ),
                    fix: None,
                    blocking: false,
                    raw: None,
                });
            }
            Ok(WriteOutcome::CheckBlocked { report }) => {
                self.check.report = Some(report);
                self.check.selected = 0;
                self.active_view = ActiveView::Check;
            }
            Ok(WriteOutcome::CliError { code, message, fix }) => {
                self.alert = Some(AlertState {
                    title: format!("Capture Failed ({code})"),
                    code: Some(code),
                    message,
                    fix,
                    blocking: false,
                    raw: None,
                });
            }
            Ok(WriteOutcome::DryRun { .. }) => {
                self.alert = Some(AlertState {
                    title: "Capture Failed".to_owned(),
                    code: Some("unexpected_outcome".to_owned()),
                    message: "the write command returned a dry-run preview; nothing was confirmed"
                        .to_owned(),
                    fix: None,
                    blocking: false,
                    raw: None,
                });
            }
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
            }
        }
    }

    /// Cancel the pending capture: remove the staged scratch (a note body or
    /// a composed new person), write nothing.
    fn cancel_capture(&mut self) {
        if let Some(capture) = self.capture.take() {
            if let Some(path) = &capture.scratch {
                edit::remove_scratch(path);
            }
        }
    }

    /// Show an inline capture error; the modal stays open so the field can be
    /// fixed. Nothing is written.
    fn set_capture_error(&mut self, message: String) {
        if let Some(capture) = self.capture.as_mut() {
            capture.error = Some(message);
        }
    }

    /// True when `.confidant/` is git-ignored in `root`, mirroring the CLI's
    /// pre-flight gate: git missing or the vault not a repo is allowed (there
    /// is nothing to commit into); a repo that does not ignore `.confidant/`
    /// is refused.
    fn scratch_is_gitignored(&self, root: &std::path::Path) -> bool {
        let root_str = root.display().to_string();
        match self
            .runner
            .run_program("git", &["-C", &root_str, "rev-parse", "--git-dir"])
        {
            Err(_) => return true,                     // git not found
            Ok(out) if out.status != 0 => return true, // not a git repo
            Ok(_) => {}
        }
        match self.runner.run_program(
            "git",
            &["-C", &root_str, "check-ignore", "-q", ".confidant/.probe"],
        ) {
            Ok(out) => out.status == 0,
            Err(_) => true,
        }
    }

    /// Refresh the currently active view. Read-only views reload their
    /// cached CLI result; People reloads check + roster (which preserves
    /// the selected person).
    pub fn refresh_current(&mut self) {
        self.alert = None;
        match self.active_view {
            ActiveView::People => {
                self.load_check();
                self.load_roster();
            }
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
            ActiveView::Inbox => {
                self.load_inbox();
            }
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
                _ => self.close_opened_proposal(),
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
                raw: None,
            });
            return;
        }
        let path = root.join(".confidant").join("proposals").join(&entry.name);
        // Defensive: if a flow was already open, sweep its staged reviewed
        // bytes before it is replaced (#618).
        self.close_opened_proposal();
        match ApplyFlow::open(&path, &root) {
            Ok(flow) => self.proposals.opened = Some(flow),
            Err(e) => {
                self.alert = Some(AlertState {
                    title: "Cannot Open Proposal".to_owned(),
                    code: Some("proposal_open_failed".to_owned()),
                    message: e,
                    fix: Some("Re-run the proposer to regenerate the manifest".to_owned()),
                    blocking: false,
                    raw: None,
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
                    raw: None,
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
                let cli_alert = self.cli_error_alert(status, usage_error, &error);
                self.alert = Some(cli_alert);
                None
            }
            ContractOutcome::InvalidJson { status } => {
                self.alert = Some(AlertState::invalid_json(status));
                None
            }
        }
    }

    fn switch_to(&mut self, view: ActiveView) {
        self.reset_for_navigation(view);
        match view {
            ActiveView::People => {
                if !self.people.loaded {
                    self.load_roster();
                } else if self.context.context.is_none() {
                    if let Some(id) = self.people.selected_person.clone() {
                        self.load_context(&id);
                    }
                }
            }
            ActiveView::Check if self.check.report.is_none() => self.load_check(),
            ActiveView::Doctor if self.doctor.report.is_none() => self.load_doctor(),
            ActiveView::Proposals if !self.proposals.loaded => self.load_proposals(),
            ActiveView::Inbox if self.inbox.report.is_none() => {
                self.load_inbox();
            }
            ActiveView::Conflicts if !self.conflict.loaded => self.load_conflicts(),
            _ => {}
        }
    }

    /// Move to `view` and leave any local text mode, without loading
    /// anything. The caller owns the refresh (the palette's inbox apply
    /// wants exactly one fresh dry run, not the lazy load plus another).
    fn reset_for_navigation(&mut self, view: ActiveView) {
        self.active_view = view;
        self.input_mode = InputMode::Normal;
        self.search.editing = false;
        self.people.editing_filter = false;
        self.alert = None;
    }

    /// Switch to a workspace, landing on its first view.
    fn switch_workspace(&mut self, workspace: Workspace) {
        match workspace {
            Workspace::People => {
                if self.active_view != ActiveView::People {
                    self.switch_to(ActiveView::People);
                }
            }
            Workspace::Review => {
                if !matches!(
                    self.active_view,
                    ActiveView::Proposals | ActiveView::Inbox | ActiveView::Conflicts
                ) {
                    self.switch_to(ActiveView::Proposals);
                }
            }
            Workspace::Check => {
                if !matches!(self.active_view, ActiveView::Check | ActiveView::Doctor) {
                    self.switch_to(ActiveView::Check);
                }
            }
        }
    }

    /// `Tab`/`BackTab`: cycle the views inside the current workspace.
    fn cycle_view(&mut self, forward: bool) {
        let views = self.active_view.workspace().views();
        let current = views
            .iter()
            .position(|view| *view == self.active_view)
            .unwrap_or(0);
        let next = if forward {
            (current + 1) % views.len()
        } else {
            (current + views.len() - 1) % views.len()
        };
        self.switch_to(views[next]);
    }

    /// `d`: Doctor is a pill, not a workspace. Toggling it returns to Check.
    fn toggle_doctor(&mut self) {
        if self.active_view == ActiveView::Doctor {
            self.switch_to(ActiveView::Check);
        } else {
            self.switch_to(ActiveView::Doctor);
        }
    }

    /// The vault path the status pill shows: the envelope value when a
    /// call has answered, else the explicit `--vault` root.
    fn vault_label(&self) -> String {
        self.vault
            .clone()
            .or_else(|| {
                self.vault_root_override
                    .as_ref()
                    .map(|path| path.display().to_string())
            })
            .unwrap_or_else(|| "unknown".to_owned())
    }

    /// The resolved scope, from the last scoped read (`record list`).
    fn scope_label(&self) -> String {
        match self.scope.as_deref() {
            Some([]) => "all enabled packs".to_owned(),
            Some(names) => names.join(", "),
            None => "not resolved yet".to_owned(),
        }
    }

    /// The alert for a CLI error envelope: a usage error that names an
    /// unknown subcommand becomes an actionable version-skew message (#591)
    /// rather than a wall of clap help. Everything else keeps its current
    /// rendering. The raw CLI text rides on the alert and is reachable with
    /// `x`.
    fn cli_error_alert(&self, status: i32, usage_error: bool, error: &ErrorBody) -> AlertState {
        if usage_error {
            if let Some(subcommand) = alert::unknown_subcommand(&error.message) {
                return AlertState::cli_version_skew(
                    &self.cli_display(),
                    &subcommand,
                    &error.message,
                );
            }
        }
        AlertState::from_cli_error(status, usage_error, error)
    }

    /// The resolved `confidant` path, for display in the Scope modal and the
    /// version-skew alert: an explicit path is shown as configured; a bare
    /// command name (`confidant` from `PATH`) is resolved against `PATH` so
    /// the user sees which binary actually ran. Best-effort.
    fn cli_display(&self) -> String {
        match self.runner.bin() {
            Some(bin) => resolved_bin_display(bin),
            None => "confidant".to_owned(),
        }
    }

    /// Doctor state from the cached report; never runs doctor itself.
    fn doctor_label(&self) -> String {
        let Some(report) = &self.doctor.report else {
            return "not run".to_owned();
        };
        let errors = report
            .checks
            .iter()
            .filter(|check| check.status == "error")
            .count();
        let warnings = report
            .checks
            .iter()
            .filter(|check| check.status == "warning")
            .count();
        if errors > 0 {
            format!("{errors} error(s)")
        } else if warnings > 0 {
            format!("{warnings} warning(s)")
        } else {
            "ok".to_owned()
        }
    }

    /// The tone of the cached doctor status pill: neutral until doctor has
    /// run, then red/amber/green by the worst cached check.
    fn doctor_tone(&self) -> theme::Tone {
        let Some(report) = &self.doctor.report else {
            return theme::Tone::Neutral;
        };
        if report.checks.iter().any(|check| check.status == "error") {
            theme::Tone::Error
        } else if report.checks.iter().any(|check| check.status == "warning") {
            theme::Tone::Warn
        } else {
            theme::Tone::Ok
        }
    }

    fn open_scope_modal(&mut self) {
        self.info_modal = Some(InfoState::new(
            "Scope",
            vec![
                format!("vault: {}", self.vault_label()),
                format!("cli: {}", self.cli_display()),
                format!("scope: {}", self.scope_label()),
                "source: `confidant record list --json` (cleared set)".to_owned(),
                String::new(),
                "Scope is resolved by the CLI. The TUI passes no --packs, so this".to_owned(),
                "is every enabled pack. Run the CLI with --packs to scope agent reads.".to_owned(),
            ],
        ));
    }

    fn open_help_modal(&mut self) {
        self.info_modal = Some(InfoState::new("Help", help::lines(self.operator_mode)));
    }

    /// `:` or `Ctrl-P`: the command palette's opening keys. `:` is vim's
    /// command line; `Ctrl-P` is the familiar launcher binding.
    fn palette_open_key(key: KeyEvent) -> bool {
        matches!(key.code, KeyCode::Char(':'))
            || (key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('p') | KeyCode::Char('P')))
    }

    /// The palette is a browser-level launcher: it refuses to open while a
    /// text field owns the keyboard or a write flow is waiting for an answer,
    /// so it can never be used to jump out of a confirm modal.
    fn palette_can_open(&self) -> bool {
        self.input_mode == InputMode::Normal
            && self.edit_flow.is_none()
            && self.capture.is_none()
            && !self.inbox.confirming
            && self.conflict.confirming.is_none()
            && self
                .proposals
                .opened
                .as_ref()
                .is_none_or(|flow| matches!(flow.phase, FlowPhase::Browsing))
    }

    fn open_palette(&mut self) {
        self.palette = Some(PaletteState::new());
    }

    /// Handle a key while the palette is open. Returns true: the palette
    /// owns the keyboard until it runs an entry or closes.
    ///
    /// `j`/`k` are *not* navigation here — they are ordinary query
    /// characters, so a query like `j` still filters. Use the arrows or
    /// `Ctrl-P`/`Ctrl-N`.
    fn handle_palette_key(&mut self, key: KeyEvent) {
        let Some(state) = self.palette.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.palette = None,
            KeyCode::Enter => {
                let chosen = state.selected_entry().map(|entry| entry.id);
                self.palette = None;
                if let Some(id) = chosen {
                    self.run_palette_action(id);
                }
            }
            KeyCode::Up => state.move_by(-1),
            KeyCode::Down => state.move_by(1),
            KeyCode::Backspace => state.backspace(),
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                state.move_by(-1);
            }
            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                state.move_by(1);
            }
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                state.insert(c);
            }
            _ => {}
        }
    }

    /// Run a palette entry through the same path as its key binding.
    ///
    /// Read-only entries switch views or open a modal. Write entries
    /// (`capture.*`, `record.edit`, `inbox.apply`) only *start* the usual
    /// flow: a `--dry-run` preview followed by an explicit `y`. Nothing here
    /// writes on `Enter` alone. `record.edit` is refused outside People and
    /// the Context view (where the operator can see the loaded context), and
    /// `inbox.apply` opens its confirm only when the fresh dry run it just
    /// issued succeeded, so `y` can never apply behind a stale preview.
    fn run_palette_action(&mut self, id: &str) {
        match id {
            "workspace.people" => self.switch_workspace(Workspace::People),
            "workspace.review" => self.switch_workspace(Workspace::Review),
            "workspace.check" => self.switch_workspace(Workspace::Check),
            "view.proposals" => self.switch_to(ActiveView::Proposals),
            "view.inbox" => self.switch_to(ActiveView::Inbox),
            "view.conflicts" => self.switch_to(ActiveView::Conflicts),
            "view.doctor" => self.switch_to(ActiveView::Doctor),
            "people.filter" => {
                self.switch_workspace(Workspace::People);
                self.enter_filter();
            }
            "search.query" => self.enter_search(),
            "search.open" => self.switch_to(ActiveView::Search),
            // #621: the same guard as the `a` key — composing a person is a
            // People/Context action, so the palette cannot start it from a
            // view where the operator cannot see the roster/context.
            "person.new" => {
                if matches!(self.active_view, ActiveView::People | ActiveView::Context) {
                    self.begin_new_person();
                } else {
                    self.alert = Some(AlertState {
                        title: "New Person Needs People".to_owned(),
                        code: Some("new_person_needs_people".to_owned()),
                        message: "composing a new person works from People or the Context view"
                            .to_owned(),
                        fix: Some("switch to People (1), then retry".to_owned()),
                        blocking: false,
                        raw: None,
                    });
                }
            }
            "capture.session" => self.begin_capture(CaptureKind::Session),
            "capture.touch" => self.begin_capture(CaptureKind::Touch),
            "capture.note" => self.begin_capture(CaptureKind::Note),
            // `e` edits the loaded context pane, which only People and the
            // full-screen Context view show. Refuse elsewhere rather than
            // silently editing a context the operator cannot see.
            "record.edit" => {
                if matches!(self.active_view, ActiveView::People | ActiveView::Context) {
                    self.begin_edit();
                } else {
                    self.alert = Some(AlertState {
                        title: "Editing Needs the Context".to_owned(),
                        code: Some("edit_needs_context".to_owned()),
                        message: "editing the selected record or note works from People or the Context view"
                            .to_owned(),
                        fix: Some(
                            "open the person (People, or Enter a p-… hit), then press e".to_owned(),
                        ),
                        blocking: false,
                        raw: None,
                    });
                }
            }
            // Re-run the dry run first, then open the normal apply confirm —
            // but only when that fresh dry run succeeded. If it failed, the
            // loaded report is stale (e.g. the one primed at launch); opening
            // the confirm on it would let `y` apply behind a preview the TUI
            // just failed to refresh.
            "inbox.apply" => {
                self.reset_for_navigation(ActiveView::Inbox);
                if self.load_inbox() {
                    self.inbox_begin_apply();
                }
            }
            "operator.toggle" => self.toggle_operator_mode(),
            "scope" => self.open_scope_modal(),
            "help" => self.open_help_modal(),
            "refresh" => self.refresh_current(),
            "quit" => self.should_quit = true,
            _ => {}
        }
    }

    /// Workspace bar, pills, and per-workspace shortcuts. Returns true when
    /// the key was consumed. Text input modes call this only after their
    /// own handlers, so typing `p`, `1`, or `?` stays literal.
    fn handle_workspace_shortcut(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('1') => {
                self.switch_workspace(Workspace::People);
                true
            }
            KeyCode::Char('2') => {
                self.switch_workspace(Workspace::Review);
                true
            }
            KeyCode::Char('3') => {
                self.switch_workspace(Workspace::Check);
                true
            }
            KeyCode::Char('f') => {
                self.switch_to(ActiveView::Search);
                true
            }
            // #556 phase 3: quick capture, pre-filled with the selected person.
            KeyCode::Char('s') => {
                self.begin_capture(CaptureKind::Session);
                true
            }
            KeyCode::Char('t') => {
                self.begin_capture(CaptureKind::Touch);
                true
            }
            KeyCode::Char('n') => {
                self.begin_capture(CaptureKind::Note);
                true
            }
            // #621: compose a new person from People or the full-screen
            // Context view. Unlike `s`/`t`/`n` it needs no selected row.
            KeyCode::Char('a')
                if matches!(self.active_view, ActiveView::People | ActiveView::Context) =>
            {
                self.begin_new_person();
                true
            }
            KeyCode::Char('d') => {
                self.toggle_doctor();
                true
            }
            KeyCode::Char('p') => {
                self.open_scope_modal();
                true
            }
            KeyCode::Char('?') => {
                self.open_help_modal();
                true
            }
            KeyCode::Char('o') => {
                self.switch_to(ActiveView::Proposals);
                true
            }
            KeyCode::Char('i') => {
                self.switch_to(ActiveView::Inbox);
                true
            }
            KeyCode::Char('c') => {
                self.switch_to(ActiveView::Conflicts);
                true
            }
            KeyCode::Tab => {
                self.cycle_view(true);
                true
            }
            KeyCode::BackTab => {
                self.cycle_view(false);
                true
            }
            KeyCode::Char('/')
                if !matches!(self.active_view, ActiveView::People | ActiveView::Search) =>
            {
                self.enter_search();
                true
            }
            _ => false,
        }
    }

    /// Handle a key event while the proposals tab is active.
    fn handle_proposals_key(&mut self, key: KeyEvent) {
        // Workspace shortcuts are only honoured while browsing (or with no
        // proposal open). In a phase modal they would escape to another
        // workspace and leave the flow armed: gate on `Browsing` so the
        // phase handler disarms/ignores the key instead.
        let browsing = self
            .proposals
            .opened
            .as_ref()
            .is_none_or(|flow| matches!(flow.phase, FlowPhase::Browsing));
        if browsing && self.handle_workspace_shortcut(key) {
            return;
        }
        if self.proposals.opened.is_some() {
            self.handle_open_proposal_key(key);
        } else {
            self.handle_proposal_list_key(key);
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
            KeyCode::Char('g') => self.proposals.selected = 0,
            KeyCode::Char('G') => {
                if !self.proposals.entries.is_empty() {
                    self.proposals.selected = self.proposals.entries.len() - 1;
                }
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
                KeyCode::Char('g') => {
                    self.conflict.selected = 0;
                    true
                }
                KeyCode::Char('G') => {
                    if !self.conflict.entries.is_empty() {
                        self.conflict.selected = self.conflict.entries.len() - 1;
                    }
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
                KeyCode::Esc => self.close_opened_proposal(),
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
                    // Cancel the review: drop the staged reviewed bytes (#618).
                    if let Some(flow) = self.proposals.opened.as_mut() {
                        flow.cancel_step(step);
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
            FlowPhase::StepFailed { step, .. } => match key.code {
                KeyCode::Esc => {
                    // The step must be re-reviewed; drop its staged bytes (#618).
                    if let Some(flow) = self.proposals.opened.as_mut() {
                        flow.cancel_step(step);
                    }
                }
                KeyCode::Char('r') => self.proposals_start_apply(),
                KeyCode::Char('q') => self.should_quit = true,
                _ => {}
            },
            FlowPhase::CleanupPrompt => match key.code {
                KeyCode::Char('y') => self.proposals_run_cleanup(),
                _ => {
                    if let Some(flow) = self.proposals.opened.as_mut() {
                        flow.phase = FlowPhase::Browsing;
                    }
                }
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
                    self.close_opened_proposal();
                }
            },
            // Terminal phases are exited immediately by the action that
            // produced them; any stray key just closes the detail.
            FlowPhase::Finished | FlowPhase::CheckFailed => {
                self.close_opened_proposal();
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

    /// Close the opened proposal, dropping any staged reviewed bytes first
    /// (#618: `Esc`/terminal phases must not leave plaintext scratch behind).
    fn close_opened_proposal(&mut self) {
        if let Some(mut flow) = self.proposals.opened.take() {
            flow.sweep_all_staged_sources();
        }
    }

    /// Run cleanup (delete the proposal set) for the open proposal.
    fn proposals_run_cleanup(&mut self) {
        let result = {
            let Some(flow) = self.proposals.opened.as_mut() else {
                return;
            };
            flow.cleanup(&self.runner)
        };
        match result {
            Ok(()) => {
                let finished = self
                    .proposals
                    .opened
                    .as_ref()
                    .is_some_and(|f| f.phase == FlowPhase::Finished);
                if finished {
                    self.close_opened_proposal();
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

        // Scope/Help modals are informational: any key closes them.
        if self.info_modal.is_some() {
            self.info_modal = None;
            return;
        }

        // The command palette owns the keyboard while open, and only opens at
        // browse level: never out of a text field or a pending write confirm.
        if self.palette.is_some() {
            self.handle_palette_key(key);
            return;
        }
        if Self::palette_open_key(key) && self.palette_can_open() {
            self.open_palette();
            return;
        }

        // A version-skew alert keeps the raw clap output behind `x` (#591):
        // the alert itself shows the one-line fix, and the full text opens in
        // the dismissable info modal only when asked for.
        if matches!(key.code, KeyCode::Char('x')) {
            if let Some(raw) = self.alert.as_ref().and_then(|a| a.raw.as_deref()) {
                let lines: Vec<String> = raw.lines().map(str::to_owned).collect();
                self.info_modal = Some(InfoState::new("Raw CLI Output", lines));
                return;
            }
        }

        // The edit confirm modal owns every key once the editor has returned:
        // `y` writes, anything else cancels. It sits above the workspace
        // shortcuts so a pending write cannot be escaped (same rule as a
        // proposal confirm).
        if self.handle_edit_confirm_key(key) {
            return;
        }

        // The capture modal owns every key while it is open (same rule as the
        // edit confirm): it sits above the workspace shortcuts so a pending
        // capture cannot be escaped.
        if self.handle_capture_key(key) {
            return;
        }

        // Proposals owns its open-flow keys and calls the workspace
        // shortcuts itself (so its phase modals keep swallowing input).
        if self.active_view == ActiveView::Proposals {
            self.handle_proposals_key(key);
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

        if self.input_mode == InputMode::EditingFilter {
            self.handle_filter_input(key);
            return;
        }

        if self.active_view == ActiveView::Inbox && self.handle_inbox_key(key) {
            return;
        }

        if self.active_view == ActiveView::Conflicts && self.handle_conflict_key(key) {
            return;
        }

        if self.handle_workspace_shortcut(key) {
            return;
        }

        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Esc => match self.active_view {
                ActiveView::People if !self.people.filter.trim().is_empty() => {
                    self.people.filter.clear();
                    self.people.clamp(self.check.report.as_ref());
                }
                ActiveView::People => {
                    // Esc is "back", and the People home is the top of the
                    // stack: it does not quit (#556 phase 5, Silas's phase-1
                    // nit). `q` is the explicit quit; an alert is dismissed
                    // first so Esc keeps its dismiss meaning.
                    if self.alert.is_some() {
                        self.alert = None;
                    }
                }
                ActiveView::Search | ActiveView::Context => self.switch_to(ActiveView::People),
                _ => {
                    if self.alert.is_some() {
                        self.alert = None;
                    } else {
                        self.should_quit = true;
                    }
                }
            },
            KeyCode::Char('/') => {
                if self.active_view == ActiveView::People {
                    self.enter_filter();
                } else {
                    self.enter_search();
                }
            }
            // #387: exact literal scan toggle for the unified Search tab.
            KeyCode::Char('e') if self.active_view == ActiveView::Search => {
                self.toggle_search_exact();
            }
            // #556 phase 2: edit the selected record/note through the operator
            // scratch + editor flow.
            KeyCode::Char('e')
                if matches!(self.active_view, ActiveView::People | ActiveView::Context) =>
            {
                self.begin_edit();
            }
            // #556 phase 2: the explicit human action that lets the roster and
            // context be read through `--for-operator`.
            KeyCode::Char('!') => {
                self.toggle_operator_mode();
            }
            // #556 phase 2: move the context pane's edit target.
            KeyCode::Char('[') => {
                self.move_edit_target(-1);
            }
            KeyCode::Char(']') => {
                self.move_edit_target(1);
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
            // Vim/lazygit ends: first/last row of the active list.
            KeyCode::Char('g') => {
                self.select_first();
            }
            KeyCode::Char('G') => {
                self.select_last();
            }
            KeyCode::Enter => {
                self.activate_selected();
            }
            _ => {}
        }
    }

    /// Text input for the local People filter. Filtering is pure; no CLI
    /// call runs per keystroke. Enter applies the filter and activates the
    /// row under the cursor (loading that person's context).
    fn handle_filter_input(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
                self.people.editing_filter = false;
                self.people.filter.clear();
                self.people.clamp(self.check.report.as_ref());
            }
            KeyCode::Enter => {
                self.input_mode = InputMode::Normal;
                self.people.editing_filter = false;
                self.people.clamp(self.check.report.as_ref());
                self.activate_people_selection();
            }
            KeyCode::Backspace => {
                self.people.filter.pop();
                self.people.clamp(self.check.report.as_ref());
            }
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                self.people.filter.push(c);
                self.people.clamp(self.check.report.as_ref());
            }
            _ => {}
        }
    }

    fn select_next(&mut self) {
        match self.active_view {
            ActiveView::People => self.move_people_selection(1),
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
            ActiveView::People => self.move_people_selection(-1),
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

    /// `g`: jump to the first row of the active list (the top of the context
    /// pane when the full-screen Context view is open).
    fn select_first(&mut self) {
        self.select_edge(false);
    }

    /// `G`: jump to the last row of the active list.
    fn select_last(&mut self) {
        self.select_edge(true);
    }

    fn select_edge(&mut self, last: bool) {
        match self.active_view {
            ActiveView::People => {
                let nudge_count =
                    people::attention(self.check.report.as_ref(), self.people.roster.as_ref())
                        .len();
                let people =
                    people::filtered_entries(self.people.roster.as_ref(), &self.people.filter)
                        .len();
                let total = nudge_count + people;
                if total > 0 {
                    self.select_people_row(if last { total - 1 } else { 0 });
                }
            }
            ActiveView::Check => {
                if let Some(report) = &self.check.report {
                    if !report.findings.is_empty() {
                        self.check.selected = if last { report.findings.len() - 1 } else { 0 };
                    }
                }
            }
            ActiveView::Context => {
                if !last {
                    self.context.scroll = 0;
                }
            }
            ActiveView::Doctor => {
                if let Some(report) = &self.doctor.report {
                    if !report.checks.is_empty() {
                        self.doctor.selected = if last { report.checks.len() - 1 } else { 0 };
                    }
                }
            }
            ActiveView::Search => {
                if let Some(result) = &self.search.result {
                    if !result.kept.is_empty() {
                        self.search.selected = if last { result.kept.len() - 1 } else { 0 };
                    }
                }
            }
            // The proposals and conflicts tabs handle `g`/`G` in their own
            // list handlers (they own Enter/selection); Inbox has no row
            // selection.
            ActiveView::Proposals | ActiveView::Inbox | ActiveView::Conflicts => {}
        }
    }

    fn activate_selected(&mut self) {
        if self.active_view == ActiveView::People {
            self.activate_people_selection();
            return;
        }
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
            ActiveView::People
            | ActiveView::Context
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
                Constraint::Length(2),
                Constraint::Min(10),
                Constraint::Length(1),
            ])
            .split(area);

        self.render_header(frame, chunks[0]);

        if let Some(active_alert) = &self.alert {
            alert::render(active_alert, frame, chunks[1]);
        } else {
            match self.active_view {
                ActiveView::People => people::render(
                    &self.people,
                    self.check.report.as_ref(),
                    &self.context,
                    frame,
                    chunks[1],
                ),
                ActiveView::Check => check::render(&self.check, frame, chunks[1]),
                ActiveView::Context => context::render(&self.context, frame, chunks[1]),
                ActiveView::Doctor => doctor::render(&self.doctor, frame, chunks[1]),
                ActiveView::Proposals => self.render_proposals(frame, chunks[1]),
                ActiveView::Search => search::render(&self.search, frame, chunks[1]),
                ActiveView::Inbox => self.render_inbox(frame, chunks[1]),
                ActiveView::Conflicts => self.render_conflict(frame, chunks[1]),
            }
        }

        self.render_footer(frame, chunks[2]);
        if let Some(modal) = &self.info_modal {
            info::render(modal, frame, area);
        }
        if let Some(palette_state) = &self.palette {
            render_palette(palette_state, frame, area);
        }
        if let Some(flow) = &self.edit_flow {
            if flow.phase == EditPhase::Confirm {
                let noun = flow.target.kind.noun();
                confirm::render(
                    &ConfirmState::new(
                        format!("Apply {noun} edit: {}", flow.target.id),
                        vec![
                            format!("{noun} {} ({})", flow.target.id, flow.target.label),
                            String::new(),
                            "This re-encrypts and creates one commit (if anything changed)."
                                .to_owned(),
                        ],
                    ),
                    frame,
                    area,
                );
            }
        }
        if let Some(capture) = &self.capture {
            match capture.phase {
                CapturePhase::Editing => capture_view::render_form(capture, frame, area),
                CapturePhase::Preview => {
                    let scratch = capture.scratch.as_ref().and_then(|path| path.to_str());
                    let command = format!("confidant {}", capture.argv(scratch).join(" "));
                    diff::render(
                        &DiffState::new(
                            format!("{} {}", capture.kind.title(), capture.person_id),
                            command,
                            capture.preview.clone(),
                        ),
                        frame,
                        area,
                    );
                    confirm::render(
                        &ConfirmState::new(
                            format!("Confirm: {}", capture.kind.title()),
                            vec![
                                format!("Writes one commit for {}.", capture.person_id),
                                String::new(),
                                "Type y to write to the vault; any other key cancels the capture."
                                    .to_owned(),
                            ],
                        ),
                        frame,
                        area,
                    );
                }
            }
        }
    }

    /// Two-line borderless header: workspace pills + action pills, then the
    /// cached status pills (vault, resolved scope, doctor state). Nothing
    /// here runs the CLI.
    fn render_header(&self, frame: &mut Frame<'_>, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(1)])
            .split(area);

        let nav = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(34)])
            .split(rows[0]);

        let active = self.active_view.workspace();
        let mut spans = Vec::new();
        for workspace in [Workspace::People, Workspace::Review, Workspace::Check] {
            if !spans.is_empty() {
                spans.push(Span::raw(" "));
            }
            spans.push(theme::tab_pill(
                &self.workspace_label(workspace),
                workspace == active,
            ));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), nav[0]);

        let modal_title = self.info_modal.as_ref().map(|modal| modal.title.as_str());
        let actions = Line::from(vec![
            theme::tab_pill("[d] Doctor", self.active_view == ActiveView::Doctor),
            Span::raw(" "),
            theme::tab_pill("[p] Scope", modal_title == Some("Scope")),
            Span::raw(" "),
            theme::tab_pill("[?] Help", modal_title == Some("Help")),
        ]);
        frame.render_widget(Paragraph::new(actions).alignment(Alignment::Right), nav[1]);

        let status = Line::from(vec![
            theme::label("vault "),
            theme::pill(&compact_path(&self.vault_label(), 36)),
            Span::raw("  "),
            theme::label("scope "),
            theme::pill(&self.scope_label()),
            Span::raw("  "),
            theme::label("doctor "),
            theme::tone_pill(&self.doctor_label(), self.doctor_tone()),
        ]);
        frame.render_widget(Paragraph::new(status), rows[1]);
    }

    /// Borderless one-line footer with key badges and action labels. In
    /// operator mode the mode banner leads the line (persistent, not a
    /// toast), so hidden data on screen is unmistakable on a screen share;
    /// the banner is long, so only the keys that turn it off or get help
    /// follow it. Otherwise the hints are context-aware for the active view,
    /// and always advertise the operator toggle, context-item selection, and
    /// the command palette (#556 phase 5).
    fn render_footer(&self, frame: &mut Frame<'_>, area: Rect) {
        let mut spans = Vec::new();
        let keys: Vec<(&'static str, &'static str)> = if self.operator_mode {
            spans.push(Span::styled(
                OPERATOR_MODE_BANNER,
                Style::default().fg(palette::ERROR).bold(),
            ));
            spans.push(Span::raw("  "));
            vec![("!", "op off"), ("?", "help"), ("q", "quit")]
        } else {
            self.footer_keys()
        };
        for (key, label) in keys {
            spans.push(theme::key_badge(key));
            spans.push(theme::key_hint(label));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    /// The footer hint set for the current view. Kept short enough for a
    /// 100-column terminal; the full reference lives behind `?`.
    fn footer_keys(&self) -> Vec<(&'static str, &'static str)> {
        match self.active_view {
            ActiveView::People => vec![
                ("1-3", "ws"),
                ("Tab", "view"),
                ("j/k", "move"),
                ("/", "filter"),
                ("[ ]", "item"),
                ("!", "op"),
                (":", "palette"),
                ("?", "help"),
                ("q", "quit"),
            ],
            ActiveView::Context => vec![
                ("1-3", "ws"),
                ("Tab", "view"),
                ("j/k", "scroll"),
                ("[ ]", "item"),
                ("e", "edit"),
                ("!", "op"),
                (":", "palette"),
                ("?", "help"),
                ("q", "quit"),
            ],
            ActiveView::Search => vec![
                ("1-3", "ws"),
                ("Tab", "view"),
                ("/", "query"),
                ("e", "exact"),
                ("j/k", "move"),
                (":", "palette"),
                ("?", "help"),
                ("q", "quit"),
            ],
            ActiveView::Proposals => vec![
                ("1-3", "ws"),
                ("Tab", "view"),
                ("j/k", "move"),
                ("Enter", "open"),
                ("a", "apply"),
                ("r", "reload"),
                (":", "palette"),
                ("?", "help"),
                ("q", "quit"),
            ],
            ActiveView::Inbox => vec![
                ("1-3", "ws"),
                ("Tab", "view"),
                ("a", "apply"),
                ("r", "reload"),
                (":", "palette"),
                ("?", "help"),
                ("q", "quit"),
            ],
            ActiveView::Conflicts => vec![
                ("1-3", "ws"),
                ("Tab", "view"),
                ("j/k", "move"),
                ("Enter", "open"),
                ("o/t", "take"),
                ("m", "merge"),
                (":", "palette"),
                ("?", "help"),
                ("q", "quit"),
            ],
            ActiveView::Check => vec![
                ("1-3", "ws"),
                ("Tab", "view"),
                ("j/k", "move"),
                ("g/G", "ends"),
                ("d", "doctor"),
                ("r", "refresh"),
                (":", "palette"),
                ("?", "help"),
                ("q", "quit"),
            ],
            ActiveView::Doctor => vec![
                ("1-3", "ws"),
                ("Tab", "view"),
                ("j/k", "move"),
                ("g/G", "ends"),
                ("d", "check"),
                ("r", "refresh"),
                (":", "palette"),
                ("?", "help"),
                ("q", "quit"),
            ],
        }
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

/// Resolve `bin` for display. An explicit path is shown as configured; a
/// bare command name is resolved against `PATH` so the message names the
/// binary that actually ran. Falls back to the bare name when it is not on
/// `PATH`.
fn resolved_bin_display(bin: &std::path::Path) -> String {
    if bin.is_absolute() || bin.components().count() > 1 {
        return bin.display().to_string();
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(bin);
            if candidate.is_file() {
                return candidate.display().to_string();
            }
        }
    }
    bin.display().to_string()
}

/// Shorten a status-pill path from the left, keeping the most specific
/// trailing components. The full path stays in the Scope modal.
fn compact_path(path: &str, max_chars: usize) -> String {
    let chars: Vec<char> = path.chars().collect();
    if chars.len() <= max_chars {
        return path.to_owned();
    }
    let tail: String = chars[chars.len() - (max_chars - 1)..].iter().collect();
    format!("…{tail}")
}

/// The alert for "no vault found", shared by the search and edit paths.
fn no_vault_alert() -> AlertState {
    AlertState {
        title: "No Vault".to_owned(),
        code: Some("no_vault".to_owned()),
        message: "no vault found: pass --vault, set CONFIDANT_VAULT, or run inside a vault"
            .to_owned(),
        fix: None,
        blocking: false,
        raw: None,
    }
}

/// The first 8 characters of a commit SHA, or the whole (short) value.
fn short_commit(commit: &str) -> &str {
    &commit[..8.min(commit.len())]
}

/// One line for an inline capture error from a CLI error envelope, folding in
/// the fix hint when the CLI offered one.
fn cli_error_message(code: &str, message: &str, fix: Option<&str>) -> String {
    match fix.filter(|fix| !fix.is_empty()) {
        Some(fix) => format!("{code}: {message} — {fix}"),
        None => format!("{code}: {message}"),
    }
}

/// Pure check behind [`App::qmd_available`], taking its inputs explicitly
/// so tests can control them without touching the process environment.
fn qmd_available_on(
    path_var: Option<&std::ffi::OsStr>,
    vault_root: Option<&std::path::Path>,
) -> bool {
    let on_path = path_var
        .is_some_and(|paths| std::env::split_paths(paths).any(|dir| dir.join("qmd").is_file()));
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
    fn compact_path_keeps_short_paths_and_tail_of_long_ones() {
        assert_eq!(compact_path("/fake/demo-vault", 36), "/fake/demo-vault");
        let long = "/home/operator/some/deeply/nested/worktree/examples/demo-vault";
        let compact = compact_path(long, 20);
        assert_eq!(compact.chars().count(), 20);
        assert!(compact.starts_with('…'));
        assert!(compact.ends_with("demo-vault"));
    }

    #[test]
    fn qmd_available_needs_qmd_on_path_and_corpus() {
        let tmp = tempfile::tempdir().unwrap();
        let bin_dir = tmp.path().join("bin");
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(vault.join(".confidant/qmd-corpus")).unwrap();
        let qmd_name = "qmd";
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

    /// The header's doctor status pill carries the cached report's worst
    /// tone, and stays neutral until doctor has run.
    #[test]
    fn doctor_tone_follows_the_cached_report() {
        use crate::contract::DoctorCheck;
        use crate::runner::FakeRunner;

        let mut app = App::new(FakeRunner::new());
        assert_eq!(app.doctor_tone(), theme::Tone::Neutral);

        app.doctor.report = Some(DoctorReport {
            checks: vec![DoctorCheck {
                id: "spec".to_owned(),
                status: "ok".to_owned(),
                message: String::new(),
            }],
        });
        assert_eq!(app.doctor_tone(), theme::Tone::Ok);

        app.doctor.report.as_mut().unwrap().checks[0].status = "warning".to_owned();
        assert_eq!(app.doctor_tone(), theme::Tone::Warn);

        app.doctor.report.as_mut().unwrap().checks[0].status = "error".to_owned();
        assert_eq!(app.doctor_tone(), theme::Tone::Error);
    }
}
