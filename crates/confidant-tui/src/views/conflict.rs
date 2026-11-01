//! Merge-conflict resolution view (#456).
//!
//! Lists conflicted records (from `check --json`
//! `E_MERGE_CONFLICT` findings) and shows both sides on screen
//! so the operator can pick one side or hand the record to the CLI
//! hand-merge. Plaintext lives in memory only: this view never writes it
//! to disk, never logs it, and its `Debug` impl redacts it.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::{CheckReport, ResolveShow};
use crate::theme;
use crate::theme::palette;

/// One row in the conflicts list: the opaque record id and the finding
/// message. Names never appear here; ids are the only identity shown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConflictListEntry {
    pub id: String,
    pub message: String,
}

/// The `E_MERGE_CONFLICT` findings that carry a record id, in check order.
///
/// Pure, so both [`crate::app::App::load_conflicts`] and the Review Queue
/// badge derive the same conflict set from a cached `check` report without a
/// second CLI call.
pub fn entries_from_report(report: Option<&CheckReport>) -> Vec<ConflictListEntry> {
    let Some(report) = report else {
        return Vec::new();
    };
    report
        .findings
        .iter()
        .filter(|finding| finding.code == "E_MERGE_CONFLICT" && finding.id.is_some())
        .map(|finding| ConflictListEntry {
            id: finding.id.clone().unwrap_or_default(),
            message: finding.message.clone(),
        })
        .collect()
}

/// The action awaiting explicit `y`/`n` confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictAction {
    TakeOurs,
    TakeTheirs,
    HandMerge,
}

impl ConflictAction {
    pub fn title(self) -> &'static str {
        match self {
            Self::TakeOurs => "Take ours",
            Self::TakeTheirs => "Take theirs",
            Self::HandMerge => "Hand-merge in editor",
        }
    }
}

/// State for the conflicts tab. `detail` holds record text in
/// memory only; the manual `Debug` impl redacts it.
#[derive(Clone, Default, PartialEq)]
pub struct ConflictViewState {
    /// Conflicted records from the latest `check`.
    pub entries: Vec<ConflictListEntry>,
    /// Selected row in the list.
    pub selected: usize,
    /// Both sides of the open record, if a detail is loaded.
    pub detail: Option<ResolveShow>,
    /// The record id the loaded detail belongs to.
    pub detail_id: Option<String>,
    /// Action awaiting `y`/`n` confirmation, if the modal is open.
    pub confirming: Option<ConflictAction>,
    /// Result line shown after a take (cleared on next load).
    pub last_result: Option<String>,
    /// Whether the list has been loaded at least once.
    pub loaded: bool,
}

impl std::fmt::Debug for ConflictViewState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConflictViewState")
            .field("entries", &self.entries)
            .field("selected", &self.selected)
            .field("detail", &self.detail.as_ref().map(|_| "<redacted>"))
            .field("detail_id", &self.detail_id)
            .field("confirming", &self.confirming)
            .field("last_result", &self.last_result)
            .field("loaded", &self.loaded)
            .finish()
    }
}

/// Pure renderer for the conflicts list screen.
pub fn render(state: &ConflictViewState, frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let header = match (state.loaded, state.entries.len()) {
        (false, _) => Line::from(Span::styled(
            "Press r to load conflicted records",
            theme::muted(),
        )),
        (true, 0) => Line::from(vec![
            theme::label("Conflicts "),
            Span::styled("none", Style::default().fg(palette::SUCCESS).bold()),
        ]),
        (true, n) => Line::from(vec![
            theme::label("Conflicts "),
            Span::styled(
                format!("{n} record(s)"),
                Style::default().fg(palette::WARNING).bold(),
            ),
        ]),
    };
    frame.render_widget(
        Paragraph::new(header).block(theme::block(" Conflicts ")),
        chunks[0],
    );

    let mut list_items: Vec<ListItem<'_>> = Vec::new();
    if state.loaded {
        if state.entries.is_empty() {
            list_items.push(ListItem::new(Line::from(
                "No conflicted records — the vault is clean.".fg(palette::MUTED),
            )));
        } else {
            for e in &state.entries {
                list_items.push(ListItem::new(Line::from(vec![
                    Span::styled(e.id.clone(), Style::default().fg(palette::ACCENT)),
                    Span::raw(" "),
                    Span::styled(e.message.clone(), palette::TEXT),
                ])));
            }
        }
    }

    if let Some(result) = &state.last_result {
        list_items.push(ListItem::new(Line::from("")));
        list_items.push(ListItem::new(Line::from(vec![
            theme::label("Last resolve: "),
            Span::styled(result.clone(), Style::default().fg(palette::SUCCESS)),
        ])));
    }

    if state.loaded && !state.entries.is_empty() {
        list_items.push(ListItem::new(Line::from("")));
        list_items.push(ListItem::new(Line::from(Span::styled(
            "Enter: show both sides   r: refresh",
            theme::muted(),
        ))));
    }

    let mut list_state = ListState::default();
    list_state.select(Some(state.selected));
    frame.render_stateful_widget(
        List::new(list_items)
            .block(theme::block(""))
            .highlight_style(Style::default().fg(palette::ACCENT).bold())
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always),
        chunks[1],
        &mut list_state,
    );
}

/// Pure renderer for the conflict detail screen: both sides,
/// ours on top and theirs below, with the record id (opaque) in the
/// header. Side labels come from git and are shown as-is; they are never
/// treated as record names.
pub fn render_detail(state: &ConflictViewState, frame: &mut Frame<'_>, area: Rect) {
    let Some(detail) = &state.detail else {
        frame.render_widget(
            Paragraph::new(Line::from("Loading…".fg(palette::MUTED)))
                .block(theme::block(" Conflicts ")),
            area,
        );
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(area);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            theme::label("record "),
            Span::styled(detail.id.clone(), Style::default().fg(palette::ACCENT)),
        ]))
        .block(theme::block(" Conflict ")),
        chunks[0],
    );

    render_side(
        frame,
        chunks[1],
        " ours ",
        &detail.ours.label,
        &detail.ours.text,
    );
    render_side(
        frame,
        chunks[2],
        " theirs ",
        &detail.theirs.label,
        &detail.theirs.text,
    );
}

/// One side pane.
fn render_side(frame: &mut Frame<'_>, area: Rect, title: &str, label: &str, text: &str) {
    let title = if label.is_empty() {
        title.to_string()
    } else {
        format!("{title}({label}) ")
    };
    let paragraph = Paragraph::new(text)
        .block(theme::block(&title))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

/// Lines for the `y`/`n` confirm modal for a pending conflict action.
pub fn confirm_lines(action: ConflictAction, id: &str, next: Option<&str>) -> Vec<String> {
    let mut lines = Vec::new();
    match action {
        ConflictAction::TakeOurs => {
            lines.push(format!("Keep the ours side of {id}, byte for byte."));
            lines.push("The theirs side is discarded. The result is staged,".to_owned());
            lines.push("never committed.".to_owned());
        }
        ConflictAction::TakeTheirs => {
            lines.push(format!("Keep the theirs side of {id}, byte for byte."));
            lines.push("The ours side is discarded. The result is staged,".to_owned());
            lines.push("never committed.".to_owned());
        }
        ConflictAction::HandMerge => {
            lines.push(format!("Hand-merge {id} in your editor.",));
            lines.push("The TUI suspends and runs `confidant record resolve --edit`".to_owned());
            lines.push("in the terminal. Scratch files are 0600 and removed after.".to_owned());
        }
    }
    if let Some(next) = next {
        lines.push(String::new());
        lines.push(format!("CLI next step: {next}"));
    }
    lines
}
