//! Read-only Context view (`confidant context <p-id> --json --no-input`).

use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::Context;

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

/// Pure renderer for the Context view.
pub fn render(state: &ContextViewState, frame: &mut Frame<'_>, area: Rect) {
    let block = Block::bordered().title(" Person Context ");
    let Some(ctx) = &state.context else {
        let msg = match &state.person_id {
            Some(id) => format!("No context loaded for {id} (press r to reload)."),
            None => "No person selected. Press Enter on a p-… item in Find or Check.".to_owned(),
        };
        frame.render_widget(Paragraph::new(msg).block(block), area);
        return;
    };

    let mut lines = Vec::new();
    let p = &ctx.person;
    lines.push(Line::from(format!(
        "person: {} | name: {}{}",
        p.id,
        p.name.as_deref().unwrap_or("(name withheld)"),
        if p.no_ai { " [no-ai]" } else { "" }
    )));
    if !ctx.scope.is_empty() {
        lines.push(Line::from(format!("scope: {}", ctx.scope.join(", "))));
    }
    if ctx.skipped_encrypted > 0 || ctx.refused_envelopes > 0 {
        lines.push(Line::from(format!(
            "skipped_encrypted: {} | refused_envelopes: {}",
            ctx.skipped_encrypted, ctx.refused_envelopes
        )));
    }
    lines.push(Line::from(format!(
        "profile: {}",
        first_line(p.profile.as_deref())
    )));

    if let Some(c) = &ctx.coaching {
        lines.push(Line::from(format!(
            "coaching: sessions_remaining: {} | icf_hours: {:.2}",
            c.sessions_remaining, c.icf_hours
        )));
        for s in &c.recent_sessions {
            lines.push(Line::from(format!(
                "  session {} ({}m, {})",
                s.date,
                s.duration_minutes.unwrap_or(0),
                s.tag.as_deref().unwrap_or("untagged")
            )));
        }
    }

    lines.push(Line::from(format!("notes ({}):", ctx.notes.len())));
    for n in &ctx.notes {
        lines.push(Line::from(format!(
            "  {} [{}]: {}",
            n.id,
            n.date.as_deref().unwrap_or("-"),
            first_line(n.body.as_deref())
        )));
    }

    lines.push(Line::from(format!(
        "interactions ({}):",
        ctx.interactions.len()
    )));
    for ixn in &ctx.interactions {
        lines.push(Line::from(format!(
            "  {} [{}] {}: {}",
            ixn.id,
            ixn.date.as_deref().unwrap_or("-"),
            ixn.title.as_deref().unwrap_or("-"),
            first_line(ixn.body.as_deref())
        )));
    }

    lines.push(Line::from(format!(
        "touchpoints ({}):",
        ctx.touchpoints.len()
    )));
    for tp in &ctx.touchpoints {
        lines.push(Line::from(format!(
            "  {} (kind: {})",
            tp.date,
            tp.kind.as_deref().unwrap_or("-")
        )));
    }

    lines.push(Line::from(format!(
        "aliases ({}): {}",
        ctx.aliases.len(),
        if ctx.aliases.is_empty() {
            "-".to_owned()
        } else {
            ctx.aliases.join(", ")
        }
    )));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((state.scroll, 0));
    frame.render_widget(paragraph, area);
}
