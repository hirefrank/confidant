//! Read-only informational modal (`p` Scope, `?` Help).
//!
//! Unlike [`crate::views::confirm`], any key dismisses it: nothing here
//! writes or applies.

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::theme;
use crate::theme::palette;

/// State for the modal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InfoState {
    pub title: String,
    pub lines: Vec<String>,
}

impl InfoState {
    pub fn new(title: impl Into<String>, lines: Vec<String>) -> Self {
        Self {
            title: title.into(),
            lines,
        }
    }
}

/// Pure renderer: a centered modal over the current view.
pub fn render(state: &InfoState, frame: &mut Frame<'_>, area: Rect) {
    let width = area.width.saturating_sub(10).clamp(30, 80);
    let height = (state.lines.len() as u16 + 6)
        .min(area.height.saturating_sub(4))
        .max(7);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let modal = Rect::new(x, y, width, height);

    frame.render_widget(ratatui::widgets::Clear, modal);

    let mut lines: Vec<Line> = state.lines.iter().map(|l| Line::from(l.clone())).collect();
    lines.push(Line::from(""));
    lines.push(Line::from(ratatui::text::Span::styled(
        "Press any key to close.",
        theme::muted(),
    )));

    let block = theme::block("").title(ratatui::text::Span::styled(
        format!(" {} ", state.title),
        Style::default().fg(palette::TEXT).bold(),
    ));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        modal,
    );
}
