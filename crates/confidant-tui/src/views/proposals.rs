//! Proposals list and detail views.
//!
//! The list shows discovered `*.json` manifests in `.confidant/proposals/`;
//! the detail shows one manifest's planned steps and their status. All
//! rendering is pure: the apply flow lives in [`crate::apply`].

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

/// One row in the proposals list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposalListEntry {
    pub name: String,
    pub skill: String,
    pub detail: String,
    pub progress: String,
    pub error: Option<String>,
}

/// State for the proposals list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposalsListState {
    pub entries: Vec<ProposalListEntry>,
    pub selected: usize,
    pub vault_note: String,
}

/// One planned step row in the detail view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StepRow {
    pub label: String,
    pub status: String,
}

/// State for the open-proposal detail view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposalDetailState {
    pub name: String,
    pub skill: String,
    pub summary: String,
    pub warnings: Vec<String>,
    pub steps: Vec<StepRow>,
    pub hint: String,
}

/// Pure renderer for the proposals list.
pub fn render_list(state: &ProposalsListState, frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let header = if state.vault_note.is_empty() {
        "Proposal manifests awaiting review".to_owned()
    } else {
        format!("Proposal manifests ({})", state.vault_note)
    };
    frame.render_widget(
        Paragraph::new(header).block(Block::bordered().title(" Proposals ")),
        chunks[0],
    );

    if state.entries.is_empty() {
        frame.render_widget(
            Paragraph::new("No proposal manifests in .confidant/proposals/.")
                .block(Block::bordered()),
            chunks[1],
        );
        return;
    }

    let items: Vec<ListItem<'_>> = state
        .entries
        .iter()
        .enumerate()
        .map(|(idx, e)| {
            let marker = if idx == state.selected { ">" } else { " " };
            let status = e.error.as_deref().unwrap_or(&e.progress);
            ListItem::new(Line::from(format!(
                "{marker} {:<28} {:<18} {} | {}",
                e.name, e.skill, e.detail, status
            )))
        })
        .collect();
    frame.render_widget(
        List::new(items).block(Block::bordered().title(" Enter: open | a: apply | r: refresh ")),
        chunks[1],
    );
}

/// Pure renderer for the open-proposal detail view.
pub fn render_detail(state: &ProposalDetailState, frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    let mut header_lines = vec![
        Line::from(format!("manifest: {}", state.name)),
        Line::from(format!("skill:    {}", state.skill)),
    ];
    if !state.summary.is_empty() {
        header_lines.push(Line::from(format!("summary:  {}", state.summary)));
    }
    for warning in &state.warnings {
        header_lines.push(Line::from(format!("warning:  {warning}")));
    }
    frame.render_widget(
        Paragraph::new(header_lines).block(Block::bordered().title(" Proposal ")),
        chunks[0],
    );

    let items: Vec<ListItem<'_>> = state
        .steps
        .iter()
        .map(|s| ListItem::new(Line::from(format!("{}  {}", s.status, s.label))))
        .collect();
    let list_block = if items.is_empty() {
        Block::bordered().title(" Steps (nothing to apply) ")
    } else {
        Block::bordered().title(" Steps ")
    };
    frame.render_widget(List::new(items).block(list_block), chunks[1]);

    frame.render_widget(
        Paragraph::new(state.hint.clone())
            .block(Block::bordered())
            .wrap(Wrap { trim: false }),
        chunks[2],
    );
}
