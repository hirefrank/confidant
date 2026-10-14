//! Application state machine for `confidant-tui`.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::contract::{
    parse_raw_output, CheckReport, Context, ContractOutcome, DoctorReport, FindResult,
};
use crate::runner::{RawOutput, Runner};
use crate::views::alert::{self, AlertState};
use crate::views::check::{self, CheckViewState};
use crate::views::context::{self, ContextViewState};
use crate::views::doctor::{self, DoctorViewState};
use crate::views::find::{self, FindViewState};

/// The four read-only views in Phase 1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ActiveView {
    #[default]
    Check,
    Find,
    Context,
    Doctor,
}

impl ActiveView {
    pub fn next(self) -> Self {
        match self {
            Self::Check => Self::Find,
            Self::Find => Self::Context,
            Self::Context => Self::Doctor,
            Self::Doctor => Self::Check,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Check => Self::Doctor,
            Self::Find => Self::Check,
            Self::Context => Self::Find,
            Self::Doctor => Self::Context,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Check => "1:Check",
            Self::Find => "2:Find",
            Self::Context => "3:Context",
            Self::Doctor => "4:Doctor",
        }
    }
}

/// Keyboard input mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InputMode {
    #[default]
    Normal,
    EditingFind,
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
    pub alert: Option<AlertState>,
    pub blocking_alert: Option<AlertState>,
    pub should_quit: bool,
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
            alert: None,
            blocking_alert: None,
            should_quit: false,
        }
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
        self.alert = None;
        match view {
            ActiveView::Check if self.check.report.is_none() => self.load_check(),
            ActiveView::Doctor if self.doctor.report.is_none() => self.load_doctor(),
            _ => {}
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
            KeyCode::Char('/') => {
                self.active_view = ActiveView::Find;
                self.input_mode = InputMode::EditingFind;
                self.find.editing = true;
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
            ActiveView::Check => self
                .check
                .report
                .as_ref()
                .and_then(|r| r.findings.get(self.check.selected))
                .and_then(|f| f.id.as_deref())
                .filter(|id| id.starts_with("p-"))
                .map(str::to_owned),
            ActiveView::Context | ActiveView::Doctor => None,
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
            "{} | Tab/1-4:view /:find j/k:move Enter:context r:refresh q/Esc:quit",
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
        }
    }
}
