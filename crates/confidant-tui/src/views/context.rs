//! Read-only Context view (`confidant context <p-id> --json --no-input`).

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::Context;
use crate::theme;
use crate::theme::palette;

/// State for the Context view.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ContextViewState {
    pub person_id: Option<String>,
    pub context: Option<Context>,
    pub scroll: u16,
}

fn first_line(text: Option<&str>) -> &str {
    match text {
        None => "(withheld)",
        Some(s) => s
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("(empty)"),
    }
}

/// A `label value` line with a dim label.
fn row<'a>(label_text: &'a str, value: Span<'a>) -> Line<'a> {
    Line::from(vec![theme::label(label_text), value])
}

/// Pure renderer for the Context view.
pub fn render(state: &ContextViewState, frame: &mut Frame<'_>, area: Rect) {
    let block = theme::block(" Person Context ");
    let Some(ctx) = &state.context else {
        let msg = match &state.person_id {
            Some(id) => Line::from(vec![
                Span::raw(format!("No context loaded for {id} ")),
                Span::styled("(press r to reload)", Style::default().fg(palette::MUTED)),
            ]),
            None => Line::from(Span::styled(
                "No person selected. Press Enter on a p-… item in Search or Check.",
                Style::default().fg(palette::MUTED),
            )),
        };
        frame.render_widget(Paragraph::new(msg).block(block), area);
        return;
    };

    let mut lines = Vec::new();
    let p = &ctx.person;
    let mut person_spans = vec![
        theme::label("person "),
        Span::styled(p.id.clone(), Style::default().fg(palette::ACCENT)),
        theme::label("  name "),
        Span::styled(
            p.name
                .clone()
                .unwrap_or_else(|| "(name withheld)".to_owned()),
            Color::White,
        ),
    ];
    if p.no_ai {
        person_spans.push(Span::styled(
            "  [no-ai]",
            Style::default().fg(palette::WARNING).bold(),
        ));
    }
    lines.push(Line::from(person_spans));
    if !ctx.scope.is_empty() {
        lines.push(row(
            "scope ",
            Span::styled(ctx.scope.join(", "), Style::default().fg(palette::MUTED)),
        ));
    }
    if ctx.skipped_encrypted > 0 || ctx.refused_envelopes > 0 {
        lines.push(Line::from(vec![
            theme::label("skipped_encrypted "),
            Span::raw(ctx.skipped_encrypted.to_string()),
            theme::label("  refused_envelopes "),
            Span::raw(ctx.refused_envelopes.to_string()),
        ]));
    }
    lines.push(row(
        "profile ",
        Span::raw(first_line(p.profile.as_deref()).to_owned()),
    ));

    if let Some(c) = &ctx.coaching {
        lines.push(Line::from(vec![
            theme::label("coaching: "),
            theme::label("sessions_remaining: "),
            Span::styled(
                c.sessions_remaining.to_string(),
                Style::default().fg(Color::White).bold(),
            ),
            theme::label(" | icf_hours: "),
            Span::styled(
                format!("{:.2}", c.icf_hours),
                Style::default().fg(Color::White).bold(),
            ),
        ]));
        for s in &c.recent_sessions {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(s.date.clone(), Style::default().fg(palette::MUTED)),
                Span::raw(format!(
                    " ({}m, {})",
                    s.duration_minutes.unwrap_or(0),
                    s.tag.as_deref().unwrap_or("untagged")
                )),
            ]));
        }
    }

    lines.push(Line::from(Span::styled(
        format!("notes ({})", ctx.notes.len()),
        Style::default().fg(palette::MUTED),
    )));
    for n in &ctx.notes {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(n.id.clone(), Style::default().fg(palette::ACCENT)),
            Span::styled(
                format!(" [{}]", n.date.as_deref().unwrap_or("-")),
                Style::default().fg(palette::MUTED),
            ),
            Span::raw(format!(": {}", first_line(n.body.as_deref()))),
        ]));
    }

    lines.push(Line::from(Span::styled(
        format!("interactions ({})", ctx.interactions.len()),
        Style::default().fg(palette::MUTED),
    )));
    for ixn in &ctx.interactions {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(ixn.id.clone(), Style::default().fg(palette::ACCENT)),
            Span::styled(
                format!(" [{}]", ixn.date.as_deref().unwrap_or("-")),
                Style::default().fg(palette::MUTED),
            ),
            Span::raw(format!(
                " {}: {}",
                ixn.title.as_deref().unwrap_or("-"),
                first_line(ixn.body.as_deref())
            )),
        ]));
    }

    lines.push(Line::from(Span::styled(
        format!("touchpoints ({})", ctx.touchpoints.len()),
        Style::default().fg(palette::MUTED),
    )));
    for tp in &ctx.touchpoints {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(tp.date.clone(), Style::default().fg(palette::MUTED)),
            Span::raw(format!(" (kind: {})", tp.kind.as_deref().unwrap_or("-"))),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled(
            format!("aliases ({}) ", ctx.aliases.len()),
            Style::default().fg(palette::MUTED),
        ),
        Span::styled(
            if ctx.aliases.is_empty() {
                "-".to_owned()
            } else {
                ctx.aliases.join(", ")
            },
            Style::default().fg(palette::MUTED),
        ),
    ]));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((state.scroll, 0));
    frame.render_widget(paragraph, area);
}
