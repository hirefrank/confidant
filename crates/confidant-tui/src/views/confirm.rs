//! Explicit-confirm modal: `y` confirms, any other key cancels.
//!
//! Confirm is `y` typed into this modal, never Enter — matching the skill
//! workflow's "explicit approval" step.

use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

/// State for the confirm modal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfirmState {
    pub title: String,
    pub lines: Vec<String>,
}

impl ConfirmState {
    pub fn new(title: String, lines: Vec<String>) -> Self {
        Self { title, lines }
    }
}

/// Pure renderer: a centered modal over the current view.
pub fn render(state: &ConfirmState, frame: &mut Frame<'_>, area: Rect) {
    let width = area.width.saturating_sub(10).clamp(20, 76);
    let height = (state.lines.len() as u16 + 8)
        .min(area.height.saturating_sub(4))
        .max(8);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let modal = Rect::new(x, y, width, height);

    frame.render_widget(ratatui::widgets::Clear, modal);

    let mut lines: Vec<Line> = state.lines.iter().map(|l| Line::from(l.clone())).collect();
    lines.push(Line::from(""));
    lines.push(Line::from("Type y to confirm. Any other key cancels."));

    let block = Block::bordered().title(format!(" Confirm: {} ", state.title));
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, modal);
}
