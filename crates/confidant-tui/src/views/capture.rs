//! Quick-capture form (`#556` phase 3).
//!
//! Pure renderer for the [`Capture`] form: the fields, the focused field
//! cursor, and the inline validation/CLI error. The dry-run preview renders
//! through [`crate::views::diff`] plus the shared confirm modal instead.
//!
//! Field values are operator plaintext (a note body): they are rendered on
//! screen only, never logged.

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::capture::{Capture, FieldKind};
use crate::theme;
use crate::theme::palette;

/// Pure renderer: a centered form over the active view.
pub fn render_form(capture: &Capture, frame: &mut Frame<'_>, area: Rect) {
    let width = area.width.saturating_sub(8).clamp(40, 100);
    // Person + blank + fields + blank + hint/error, clamped to the screen.
    let height = (capture.fields.len() as u16 + 8)
        .min(area.height.saturating_sub(2))
        .max(8);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let modal = Rect::new(x, y, width, height);

    frame.render_widget(ratatui::widgets::Clear, modal);

    let mut lines = Vec::new();
    let name = capture.person_name.clone().unwrap_or_default();
    lines.push(Line::from(vec![
        theme::label("person "),
        theme::pill(&capture.person_id),
        Span::raw(" "),
        Span::styled(name, Style::default().fg(palette::MUTED)),
    ]));
    lines.push(Line::from(""));

    for (index, field) in capture.fields.iter().enumerate() {
        let focused = index == capture.focus;
        let marker = if focused {
            Span::styled("▶ ", Style::default().fg(palette::ACCENT).bold())
        } else {
            Span::raw("  ")
        };
        let label = Span::styled(
            format!("{:<9}", field.label),
            Style::default().fg(palette::MUTED),
        );
        let value = match field.kind {
            FieldKind::Text => {
                let mut text = field.value.clone();
                if focused {
                    text.push('_');
                }
                Span::styled(text, Style::default().fg(Color::White))
            }
            FieldKind::Toggle => Span::styled(
                if field.enabled { "[x]" } else { "[ ]" },
                Style::default().fg(if field.enabled {
                    palette::WARNING
                } else {
                    palette::MUTED
                }),
            ),
        };
        lines.push(Line::from(vec![marker, label, value]));
        if focused {
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(
                    format!("({})", field.hint),
                    Style::default().fg(palette::MUTED),
                ),
            ]));
        }
    }

    if let Some(error) = &capture.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("⚠ {error}"),
            Style::default().fg(palette::ERROR).bold(),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Tab/Shift-Tab", Style::default().fg(palette::ACCENT).bold()),
        Span::raw(" field   "),
        Span::styled("Enter", Style::default().fg(palette::ACCENT).bold()),
        Span::raw(" preview (nothing is written yet)   "),
        Span::styled("Esc", Style::default().fg(palette::ACCENT).bold()),
        Span::raw(" cancel"),
    ]));

    let block = theme::block("").title(Span::styled(
        format!(" Capture: {} ", capture.kind.title()),
        Style::default().fg(palette::WARNING).bold(),
    ));
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, modal);
}
