//! Application state machine for `confidant-tui`.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::apply::{ApplyFlow, FlowPhase, StepApplyOutcome, StepStatus};
use crate::contract::{
    parse_raw_output, CheckReport, Context, ContractOutcome, DoctorReport, FindResult, SearchResult,
};
use crate::proposals::{discover_proposals, resolve_vault_root, DiscoveredProposal};
use crate::runner::{RawOutput, Runner};
use crate::search::{filter_search_result, SearchViewState};
use crate::views::alert::{self, AlertState};
use crate::views::check::{self, CheckViewState};
use crate::views::confirm::{self, ConfirmState};
use crate::views::context::{self, ContextViewState};
use crate::views::diff::{self, DiffState};
use crate::views::doctor::{self, DoctorViewState};
use crate::views::find::{self, FindViewState};
use crate::views::proposals::{
    self, ProposalDetailState, ProposalListEntry, ProposalsListState, StepRow,
};
use crate::views::search;

/// The six views: four Phase 1 views plus proposal review (Phase 2) and
/// QMD search (Phase 3a).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ActiveView {
    #[default]
    Check,
    Find,
    Context,
    Doctor,
    Proposals,
    Search,
}

impl ActiveView {
    pub fn next(self) -> Self {
        match self {
            Self::Check => Self::Find,
            Self::Find => Self::Context,
            Self::Context => Self::Doctor,
            Self::Doctor => Self::Proposals,
            Self::Proposals => Self::Search,
            Self::Search => Self::Check,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Check => Self::Search,
            Self::Find => Self::Check,
            Self::Context => Self::Find,
            Self::Doctor => Self::Context,
            Self::Proposals => Self::Doctor,
            Self::Search => Self::Proposals,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Check => "1:Check",
            Self::Find => "2:Find",
            Self::Context => "3:Context",
            Self::Doctor => "4:Doctor",
            Self::Proposals => "5:Proposals",
            Self::Search => "6:Search",
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
    EditingFind,
    EditingSearch,
}

/// Top-level TUI state machine generic over a [`Runner`].
pub struct App<R: Runner> {
    pub runner: R,
    pub active_view: ActiveView,
    pub input_mode: InputMode,
    pub vault: Option<String>,
    pub check: CheckViewState,
    pub find: FindViewState,
    pub context: ContextViewState,
    pub doctor: DoctorViewState,
    pub search: SearchViewState,
    pub alert: Option<AlertState>,
    pub blocking_alert: Option<AlertState>,
    pub should_quit: bool,
    pub proposals: ProposalsTab,
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
            find: FindViewState::default(),
            context: ContextViewState::default(),
            doctor: DoctorViewState::default(),
            search: SearchViewState::default(),
            alert: None,
            blocking_alert: None,
            should_quit: false,
            proposals: ProposalsTab::default(),
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

    /// Run `confidant find --json --no-input -- <query>` and update the Find view state.
    pub fn run_find(&mut self, query: &str) {
        let trimmed = query.trim().to_owned();
        self.find.query = trimmed.clone();
        self.find.input = trimmed.clone();
        self.find.editing = false;
        self.input_mode = InputMode::Normal;
        if trimmed.is_empty() {
            return;
        }
        let raw = match self.runner.run(&["find", "--", &trimmed]) {
            Ok(r) => r,
            Err(e) => {
                self.alert = Some(AlertState::runner_error(&format!("{e:#}")));
                return;
            }
        };
        if let Some((_ok, result)) = self.apply_outcome::<FindResult>(&raw) {
            self.find.result = Some(result);
            self.find.selected = 0;
        }
    }

    /// Run the `qmd-search` skill's `qmd-query.py` and update the Search view.
    ///
    /// The skill path comes from `confidant which --skills-dir`; the script
    /// runs as `python3 <skills>/qmd-search/bin/qmd-query.py --vault V <q>`.
    /// A missing `python3` or a missing skill shows an alert — the TUI never
    /// falls back to plain `find` silently.
    pub fn run_search(&mut self, query: &str) {
        let trimmed = query.trim().to_owned();
        self.search.query = trimmed.clone();
        self.search.input = trimmed.clone();
        self.search.editing = false;
        self.input_mode = InputMode::Normal;
        if trimmed.is_empty() {
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
                    "Run `confidant setup` to install skills, or use the Find tab".to_owned(),
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
                    fix: Some("Install python3, or use the Find tab".to_owned()),
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

    /// Refresh the currently active view.
    pub fn refresh_current(&mut self) {
        self.alert = None;
        match self.active_view {
            ActiveView::Check => self.load_check(),
            ActiveView::Find => {
                let q = self.find.query.clone();
                if !q.is_empty() {
                    self.run_find(&q);
                }
            }
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
        self.find.editing = false;
        self.search.editing = false;
        self.alert = None;
        match view {
            ActiveView::Check if self.check.report.is_none() => self.load_check(),
            ActiveView::Doctor if self.doctor.report.is_none() => self.load_doctor(),
            ActiveView::Proposals if !self.proposals.loaded => self.load_proposals(),
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
                    self.switch_to(ActiveView::Find);
                    return;
                }
                KeyCode::Char('3') => {
                    self.switch_to(ActiveView::Context);
                    return;
                }
                KeyCode::Char('4') => {
                    self.switch_to(ActiveView::Doctor);
                    return;
                }
                KeyCode::Char('/') => {
                    self.active_view = ActiveView::Find;
                    self.input_mode = InputMode::EditingFind;
                    self.find.editing = true;
                    self.alert = None;
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

        if self.input_mode == InputMode::EditingFind {
            match key.code {
                KeyCode::Esc => {
                    self.input_mode = InputMode::Normal;
                    self.find.editing = false;
                    self.find.input = self.find.query.clone();
                }
                KeyCode::Enter => {
                    let q = self.find.input.clone();
                    self.run_find(&q);
                }
                KeyCode::Backspace => {
                    self.find.input.pop();
                }
                KeyCode::Char(c)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && !key.modifiers.contains(KeyModifiers::ALT) =>
                {
                    self.find.input.push(c);
                }
                _ => {}
            }
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
            KeyCode::Char('2') => self.switch_to(ActiveView::Find),
            KeyCode::Char('3') => self.switch_to(ActiveView::Context),
            KeyCode::Char('4') => self.switch_to(ActiveView::Doctor),
            KeyCode::Char('5') => self.switch_to(ActiveView::Proposals),
            KeyCode::Char('6') => self.switch_to(ActiveView::Search),
            KeyCode::Char('/') => {
                if self.active_view == ActiveView::Search {
                    self.input_mode = InputMode::EditingSearch;
                    self.search.editing = true;
                } else {
                    self.active_view = ActiveView::Find;
                    self.input_mode = InputMode::EditingFind;
                    self.find.editing = true;
                }
                self.alert = None;
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
            ActiveView::Find => {
                if let Some(r) = &self.find.result {
                    if !r.matches.is_empty() && self.find.selected + 1 < r.matches.len() {
                        self.find.selected += 1;
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
            // The proposals tab handles its own keys in handle_proposals_key.
            ActiveView::Proposals => {}
        }
    }

    fn select_prev(&mut self) {
        match self.active_view {
            ActiveView::Check => {
                self.check.selected = self.check.selected.saturating_sub(1);
            }
            ActiveView::Find => {
                self.find.selected = self.find.selected.saturating_sub(1);
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
            // The proposals tab handles its own keys in handle_proposals_key.
            ActiveView::Proposals => {}
        }
    }

    fn activate_selected(&mut self) {
        let person_id = match self.active_view {
            ActiveView::Find => self
                .find
                .result
                .as_ref()
                .and_then(|r| r.matches.get(self.find.selected))
                .and_then(|h| h.id.as_deref())
                .filter(|id| id.starts_with("p-"))
                .map(str::to_owned),
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
            ActiveView::Context | ActiveView::Doctor | ActiveView::Proposals => None,
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
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);

        let tabs: Vec<String> = [
            ActiveView::Check,
            ActiveView::Find,
            ActiveView::Context,
            ActiveView::Doctor,
            ActiveView::Proposals,
            ActiveView::Search,
        ]
        .into_iter()
        .map(|v| {
            if v == self.active_view {
                format!("[*{}*]", v.label())
            } else {
                format!("[ {} ]", v.label())
            }
        })
        .collect();
        let header_line = format!(
            "{} | Tab/1-6:view /:find j/k:move Enter:context r:refresh q/Esc:quit",
            tabs.join(" ")
        );
        let header_block = Block::bordered().title(" confidant-tui (contract v1) ");
        frame.render_widget(Paragraph::new(header_line).block(header_block), chunks[0]);

        if let Some(active_alert) = &self.alert {
            alert::render(active_alert, frame, chunks[1]);
            return;
        }

        match self.active_view {
            ActiveView::Check => check::render(&self.check, frame, chunks[1]),
            ActiveView::Find => find::render(&self.find, frame, chunks[1]),
            ActiveView::Context => context::render(&self.context, frame, chunks[1]),
            ActiveView::Doctor => doctor::render(&self.doctor, frame, chunks[1]),
            ActiveView::Proposals => self.render_proposals(frame, chunks[1]),
            ActiveView::Search => search::render(&self.search, frame, chunks[1]),
        }
    }

    /// Render the proposals tab: list, open detail, or an in-flight step.
    fn render_proposals(&self, frame: &mut Frame<'_>, area: Rect) {
        if let Some(err) = &self.proposals.load_error {
            frame.render_widget(
                Paragraph::new(err.clone()).block(Block::bordered().title(" Proposals ")),
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
