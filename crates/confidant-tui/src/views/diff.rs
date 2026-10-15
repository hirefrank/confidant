//! Dry-run diff view: renders a `--dry-run` preview (path, action, content).
//!
//! Content is plaintext PII from the proposal: it is rendered on screen only,
//! never logged or written anywhere.

use ratatui::layout::Rect;
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::apply::DryRunChange;
use crate::theme;
use crate::theme::palette;

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
        Line::from(vec![
            theme::label("command "),
            Span::styled(state.command.clone(), Color::White),
        ]),
        Line::from(""),
    ];
    if state.changes.is_empty() {
        lines.push(Line::from("Dry run produced no changes.".dark_gray()));
    }
    for change in &state.changes {
        lines.push(Line::from(vec![
            Span::styled("─── ", Style::default().fg(palette::MUTED)),
            Span::styled(change.path.clone(), Color::White),
            Span::raw(" "),
            Span::styled(
                format!("({})", change.action),
                Style::default().fg(palette::ACCENT),
            ),
        ]));
        for content_line in change.content.lines() {
            lines.push(Line::from(content_line.to_owned()));
        }
        lines.push(Line::from(""));
    }
    lines.push(Line::from(vec![
        Span::styled("y", Style::default().fg(palette::ACCENT).bold()),
        Span::raw(": confirm and apply   "),
        Span::styled("Esc", Style::default().fg(palette::ACCENT).bold()),
        Span::styled(
            ": back (nothing is written until you confirm)",
            Style::default().fg(palette::MUTED),
        ),
    ]));

    let block = theme::block("").title(Span::styled(
        format!(" Dry run: {} ", state.title),
        Style::default().fg(palette::MUTED),
    ));
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((state.scroll as u16, 0));
    frame.render_widget(paragraph, area);
}
