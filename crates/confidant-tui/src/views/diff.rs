//! Dry-run diff view: renders a `--dry-run` preview (path, action, content).
//!
//! Content is plaintext PII from the proposal: it is rendered on screen only,
//! never logged or written anywhere.

use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::apply::DryRunChange;

/// State for the dry-run diff view.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DiffState {
    pub title: String,
    pub command: String,
    pub changes: Vec<DryRunChange>,
    pub scroll: usize,
}

impl DiffState {
    pub fn new(title: String, command: String, changes: Vec<DryRunChange>) -> Self {
        Self {
            title,
            command,
            changes,
            scroll: 0,
        }
    }
}

/// Pure renderer for the diff view.
pub fn render(state: &DiffState, frame: &mut Frame<'_>, area: Rect) {
    let mut lines = vec![
        Line::from(format!("command: {}", state.command)),
        Line::from(""),
    ];
    if state.changes.is_empty() {
        lines.push(Line::from("Dry run produced no changes."));
    }
    for change in &state.changes {
        lines.push(Line::from(format!(
            "--- {} ({})",
            change.path, change.action
        )));
        for content_line in change.content.lines() {
            lines.push(Line::from(content_line.to_owned()));
        }
        lines.push(Line::from(""));
    }
    lines.push(Line::from(
        "y: confirm and apply | Esc: back (nothing is written until you confirm)",
    ));

    let block = Block::bordered().title(format!(" Dry run: {} ", state.title));
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((state.scroll as u16, 0));
    frame.render_widget(paragraph, area);
}
