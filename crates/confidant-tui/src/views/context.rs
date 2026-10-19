//! Read-only Context view (`confidant context <p-id> --json --no-input`).
//!
//! Used two ways: the full-screen Context view reached from Search/Check,
//! and the right pane of the People master–detail workspace. The renderer
//! is shared so both show the same live bundle.

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::{Context, NoteView};
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

/// The maximum body lines rendered per note/interaction. Longer bodies are
/// truncated with an ellipsis; the full text stays in the CLI's vault.
const MAX_BODY_LINES: usize = 12;

fn body_lines(body: Option<&str>, indent: &'static str) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let Some(body) = body else {
        return lines;
    };
    let paragraphs: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    for line in paragraphs.iter().take(MAX_BODY_LINES) {
        lines.push(Line::from(vec![
            Span::raw(indent),
            Span::raw((*line).to_owned()),
        ]));
    }
    if paragraphs.len() > MAX_BODY_LINES {
        lines.push(Line::from(vec![
            Span::raw(indent),
            Span::styled("…", Style::default().fg(palette::MUTED)),
        ]));
    }
    lines
}

fn note_block(note: &NoteView) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        Span::raw("  "),
        theme::pill(note.date.as_deref().unwrap_or("-")),
        Span::raw(" "),
        Span::styled(note.id.clone(), Style::default().fg(palette::MUTED)),
    ])];
    lines.extend(body_lines(note.body.as_deref(), "    "));
    lines
}

/// Pure renderer for the full-screen Context view.
pub fn render(state: &ContextViewState, frame: &mut Frame<'_>, area: Rect) {
    render_with_title(state, " Person Context ", frame, area);
}

/// Pure renderer for the right pane of the People workspace.
pub fn render_pane(
    state: &ContextViewState,
    selected_id: Option<&str>,
    frame: &mut Frame<'_>,
    area: Rect,
) {
    let title = state
        .context
        .as_ref()
        .and_then(|ctx| ctx.person.name.clone())
        .or_else(|| state.person_id.clone())
        .or_else(|| selected_id.map(str::to_owned))
        .map(|name| format!(" Context — {name} "))
        .unwrap_or_else(|| " Context ".to_owned());
    render_with_title(state, &title, frame, area);
}

fn render_with_title(state: &ContextViewState, title: &str, frame: &mut Frame<'_>, area: Rect) {
    let block = theme::block(title);
    let Some(ctx) = &state.context else {
        let id = state.person_id.as_deref();
        let line = match id {
            Some(id) => Line::from(vec![
                Span::raw(format!("No context loaded for {id} ")),
                Span::styled("(press r to reload)", Style::default().fg(palette::MUTED)),
            ]),
            None => Line::from(Span::styled(
                "No person selected. Choose someone in People or press Enter on a p-… item.",
                Style::default().fg(palette::MUTED),
            )),
        };
        frame.render_widget(Paragraph::new(line).block(block), area);
        return;
    };

    let paragraph = Paragraph::new(context_lines(ctx))
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((state.scroll, 0));
    frame.render_widget(paragraph, area);
}

/// Front matter as pills, then the profile, coaching numbers, notes,
/// interactions, touchpoints, and aliases. Bodies are plain text (the TUI
/// does not link a Markdown renderer).
fn context_lines(ctx: &Context) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let p = &ctx.person;
    let mut identity = vec![
        theme::label("id "),
        theme::pill(&p.id),
        Span::raw(" "),
        theme::label("name "),
        theme::pill(p.name.as_deref().unwrap_or("(name withheld)")),
    ];
    if p.no_ai {
        identity.push(Span::styled(
            " [no-ai]",
            Style::default().fg(palette::WARNING).bold(),
        ));
    }
    lines.push(Line::from(identity));
    if !ctx.scope.is_empty() {
        lines.push(Line::from(vec![
            theme::label("scope "),
            theme::pill(&ctx.scope.join(", ")),
        ]));
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
            theme::label("coaching "),
            theme::pill(&format!("sessions_remaining {}", c.sessions_remaining)),
            Span::raw(" "),
            theme::pill(&format!("icf_hours {:.2}", c.icf_hours)),
        ]));
        for s in &c.recent_sessions {
            lines.push(Line::from(vec![
                Span::raw("  "),
                theme::pill(&s.date),
                Span::raw(format!(
                    " {}m, {}",
                    s.duration_minutes.unwrap_or(0),
                    s.tag.as_deref().unwrap_or("untagged")
                )),
            ]));
        }
    }

    lines.push(Line::from(Span::styled(
        format!("notes ({})", ctx.notes.len()),
        Style::default().fg(palette::MUTED).bold(),
    )));
    for n in &ctx.notes {
        lines.extend(note_block(n));
    }

    lines.push(Line::from(Span::styled(
        format!("interactions ({})", ctx.interactions.len()),
        Style::default().fg(palette::MUTED).bold(),
    )));
    for ixn in &ctx.interactions {
        let mut title = vec![Span::raw("  ")];
        if let Some(date) = &ixn.date {
            title.push(theme::pill(date));
            title.push(Span::raw(" "));
        }
        title.push(Span::styled(
            ixn.title.clone().unwrap_or_else(|| "-".to_owned()),
            Style::default().fg(Color::White).bold(),
        ));
        title.push(Span::raw(" "));
        title.push(Span::styled(
            ixn.id.clone(),
            Style::default().fg(palette::MUTED),
        ));
        lines.push(Line::from(title));
        lines.extend(body_lines(ixn.body.as_deref(), "    "));
    }

    lines.push(Line::from(Span::styled(
        format!("touchpoints ({})", ctx.touchpoints.len()),
        Style::default().fg(palette::MUTED).bold(),
    )));
    for tp in &ctx.touchpoints {
        lines.push(Line::from(vec![
            Span::raw("  "),
            theme::pill(&tp.date),
            Span::raw(format!(" {}", tp.kind.as_deref().unwrap_or("-"))),
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

    lines
}
