//! Context view (`confidant context <p-id> --json --no-input`).
//!
//! Used two ways: the full-screen Context view reached from Search/Check,
//! and the right pane of the People master–detail workspace. The renderer
//! is shared so both show the same live bundle. Rendering performs no I/O:
//! the `▶` edit cursor is a pure marker over [`edit_targets`], which the app
//! resolves to a `record`/`note` edit on `e`.

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::{Context, NoteView};
use crate::edit::{EditKind, EditTarget};
use crate::theme;
use crate::theme::palette;

/// State for the Context view.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ContextViewState {
    pub person_id: Option<String>,
    pub context: Option<Context>,
    pub scroll: u16,
    /// Index into [`edit_targets`] of the item `e` would edit.
    pub edit_index: usize,
}

/// The editable items in render order: the person, then each note, then each
/// interaction. Shared by the app (to resolve `e` and `[`/`]`) and the
/// renderer (to mark the current target), so the two can never disagree.
pub fn edit_targets(ctx: &Context) -> Vec<EditTarget> {
    let mut targets = Vec::new();
    if !ctx.person.id.is_empty() {
        targets.push(EditTarget {
            id: ctx.person.id.clone(),
            kind: EditKind::Record,
            label: ctx
                .person
                .name
                .clone()
                .unwrap_or_else(|| ctx.person.id.clone()),
        });
    }
    for note in &ctx.notes {
        targets.push(EditTarget {
            id: note.id.clone(),
            kind: EditKind::Note,
            label: format!("note {}", note.date.as_deref().unwrap_or("-")),
        });
    }
    for ixn in &ctx.interactions {
        targets.push(EditTarget {
            id: ixn.id.clone(),
            kind: EditKind::Record,
            label: ixn
                .title
                .clone()
                .unwrap_or_else(|| format!("interaction {}", ixn.id)),
        });
    }
    targets
}

/// The `▶` prefix marking the item `e` would edit.
fn target_marker<'a>() -> Span<'a> {
    Span::styled("▶ ", Style::default().fg(palette::ACCENT).bold())
}

/// The tri-state `no-ai` badge for an operator-path view, or nothing when
/// the mode is `false`/absent (the agent path renders as it always did).
fn no_ai_badge<'a>(mode: Option<crate::contract::NoAiMode>) -> Option<Span<'a>> {
    mode.and_then(|mode| mode.badge())
        .map(|text| Span::styled(text, Style::default().fg(palette::WARNING).bold()))
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
            Span::styled("…", theme::muted()),
        ]));
    }
    lines
}

fn note_block(note: &NoteView, marker: bool) -> Vec<Line<'static>> {
    let mut lead = vec![
        Span::raw("  "),
        theme::pill(note.date.as_deref().unwrap_or("-")),
        Span::raw(" "),
    ];
    if marker {
        lead.insert(0, target_marker());
    }
    if let Some(badge) = no_ai_badge(note.no_ai) {
        lead.push(badge);
        lead.push(Span::raw(" "));
    }
    lead.push(Span::styled(note.id.clone(), theme::muted()));
    let mut lines = vec![Line::from(lead)];
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
                Span::styled("(press r to reload)", theme::muted()),
            ]),
            None => Line::from(Span::styled(
                "No person selected. Choose someone in People or press Enter on a p-… item.",
                theme::muted(),
            )),
        };
        frame.render_widget(Paragraph::new(line).block(block), area);
        return;
    };

    let paragraph = Paragraph::new(context_lines(ctx, state.edit_index))
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((state.scroll, 0));
    frame.render_widget(paragraph, area);
}

/// Front matter as pills, then the profile, notes, interactions,
/// touchpoints, and aliases. Bodies are plain text (the TUI
/// does not link a Markdown renderer). `edit_index` marks the item `e` would
/// edit and badges the tri-state `no-ai` mode the operator path reports.
fn context_lines(ctx: &Context, edit_index: usize) -> Vec<Line<'static>> {
    let targets = edit_targets(ctx);
    // Fail safe: an out-of-range index marks nothing rather than panicking.
    let selected = (edit_index < targets.len()).then_some(edit_index);
    let mut lines = Vec::new();
    let p = &ctx.person;
    let mut identity = Vec::new();
    if selected == Some(0) {
        identity.push(target_marker());
    }
    identity.push(theme::label("id "));
    identity.push(theme::pill(&p.id));
    identity.push(Span::raw(" "));
    identity.push(theme::label("name "));
    identity.push(theme::pill(p.name.as_deref().unwrap_or("(name withheld)")));
    if let Some(badge) = no_ai_badge(Some(p.no_ai)) {
        identity.push(Span::raw(" "));
        identity.push(badge);
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

    lines.push(Line::from(Span::styled(
        format!("notes ({})", ctx.notes.len()),
        theme::muted().bold(),
    )));
    for (index, n) in ctx.notes.iter().enumerate() {
        // Target 0 is the person; notes start at 1.
        lines.extend(note_block(n, selected == Some(1 + index)));
    }

    lines.push(Line::from(Span::styled(
        format!("interactions ({})", ctx.interactions.len()),
        theme::muted().bold(),
    )));
    let interactions_start = 1 + ctx.notes.len();
    for (index, ixn) in ctx.interactions.iter().enumerate() {
        let mut title = Vec::new();
        if selected == Some(interactions_start + index) {
            title.push(target_marker());
        }
        title.push(Span::raw("  "));
        if let Some(date) = &ixn.date {
            title.push(theme::pill(date));
            title.push(Span::raw(" "));
        }
        title.push(Span::styled(
            ixn.title.clone().unwrap_or_else(|| "-".to_owned()),
            Style::default().fg(palette::TEXT).bold(),
        ));
        if let Some(badge) = no_ai_badge(ixn.no_ai) {
            title.push(Span::raw(" "));
            title.push(badge);
        }
        title.push(Span::raw(" "));
        title.push(Span::styled(ixn.id.clone(), theme::muted()));
        lines.push(Line::from(title));
        lines.extend(body_lines(ixn.body.as_deref(), "    "));
    }

    lines.push(Line::from(Span::styled(
        format!("touchpoints ({})", ctx.touchpoints.len()),
        theme::muted().bold(),
    )));
    for tp in &ctx.touchpoints {
        lines.push(Line::from(vec![
            Span::raw("  "),
            theme::pill(&tp.date),
            Span::raw(format!(" {}", tp.kind.as_deref().unwrap_or("-"))),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled(format!("aliases ({}) ", ctx.aliases.len()), theme::muted()),
        Span::styled(
            if ctx.aliases.is_empty() {
                "-".to_owned()
            } else {
                ctx.aliases.join(", ")
            },
            theme::muted(),
        ),
    ]));

    lines
}
