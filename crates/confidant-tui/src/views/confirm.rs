//! Explicit-confirm modal: `y` confirms, any other key cancels.
//!
//! Confirm is `y` typed into this modal, never Enter — matching the skill
//! workflow's "explicit approval" step.

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::theme;
use crate::theme::palette;

/// State for the confirm modal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfirmState {
    pub title: String,
    pub lines: Vec<String>,
    /// Optional footer replacing the default "Type y to confirm" hint, for
    /// prompts where another key has its own meaning (the TUI quit prompt's
    /// `n` quits and `Esc` stays, #665).
    pub hint: Option<String>,
}

impl ConfirmState {
    pub fn new(title: String, lines: Vec<String>) -> Self {
        Self {
            title,
            lines,
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
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
    match &state.hint {
        Some(hint) => lines.push(Line::from(Span::styled(
            hint.clone(),
            Style::default().fg(palette::MUTED),
        ))),
        None => lines.push(Line::from(vec![
            Span::styled("Type y", Style::default().fg(palette::ACCENT).bold()),
            Span::raw(" to confirm. Any other key cancels."),
        ])),
    }

    let block = theme::block("").title(Span::styled(
        format!(" Confirm: {} ", state.title),
        Style::default().fg(palette::WARNING).bold(),
    ));
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, modal);
}
