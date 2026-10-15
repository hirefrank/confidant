//! Read-only inbox review view.
//!
//! Shows the `inbox --dry-run` plan: items with their actions, skipped
//! items, and warnings. Applying is all-or-nothing through the existing
//! `inbox` command with an explicit `y` confirm; there is no per-item
//! selection here (deferred to #217).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::InboxReport;
use crate::theme;
use crate::theme::palette;

/// State for the inbox tab.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct InboxViewState {
    /// The latest dry-run report, if one has loaded.
    pub report: Option<InboxReport>,
    /// True while the apply confirm modal is open.
    pub confirming: bool,
    /// Result line shown after an apply run (cleared on next load).
    pub last_apply: Option<String>,
}

/// One row in the items list: styled name, kind tag, target, and action.
fn item_line<'a>(name: &'a str, kind: &'a str, target: &'a str, action: Span<'a>) -> Line<'a> {
    Line::from(vec![
        Span::styled(name, Style::default().fg(palette::ACCENT)),
        Span::raw(" "),
        Span::styled(format!("[{kind}]"), Style::default().fg(palette::MUTED)),
        Span::raw(" "),
        Span::styled(target, Color::White),
        Span::raw(" "),
        action,
    ])
}

fn action_span(action: &str) -> Span<'static> {
    let style = match action {
        "merge" => Style::default().fg(palette::SUCCESS).bold(),
        "skip" => Style::default().fg(palette::MUTED),
        "deferred" => Style::default().fg(palette::WARNING),
        _ => Style::default().fg(palette::MUTED),
    };
    Span::styled(format!("({action})"), style)
}

/// Section header: dim, with the count.
fn section_header(title: &str) -> ListItem<'static> {
    ListItem::new(Line::from(Span::styled(
        format!("── {title} ──"),
        Style::default().fg(palette::MUTED),
    )))
}

/// Pure renderer for the inbox tab.
pub fn render(state: &InboxViewState, frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let header = match &state.report {
        Some(r) if r.empty => Line::from(Span::styled(
            "Inbox: nothing to do (no inbox branch)",
            Style::default().fg(palette::MUTED),
        )),
        Some(r) => Line::from(vec![
            theme::label("dry run "),
            Span::styled(r.branch.clone(), Color::White),
            theme::label("  •  to merge "),
            Span::styled(
                r.merged.to_string(),
                Style::default().fg(palette::SUCCESS).bold(),
            ),
            theme::label("  •  to clear "),
            Span::styled(
                r.cleared.to_string(),
                Style::default().fg(palette::WARNING).bold(),
            ),
        ]),
        None => Line::from(Span::styled(
            "Press r to load the dry run",
            Style::default().fg(palette::MUTED),
        )),
    };
    frame.render_widget(
        Paragraph::new(header).block(theme::block(" Inbox ")),
        chunks[0],
    );

    let Some(report) = &state.report else {
        frame.render_widget(
            Paragraph::new(Line::from("No dry-run report loaded yet.".dark_gray()))
                .block(theme::block("")),
            chunks[1],
        );
        return;
    };

    if report.empty {
        frame.render_widget(
            Paragraph::new(Line::from(
                "No inbox branch in this vault — nothing to merge.".dark_gray(),
            ))
            .block(theme::block("")),
            chunks[1],
        );
        return;
    }

    let mut list_items: Vec<ListItem<'_>> = Vec::new();

    list_items.push(section_header(&format!("Items ({})", report.items.len())));
    if report.items.is_empty() {
        list_items.push(ListItem::new(Line::from("(none)".dark_gray())));
    } else {
        for i in &report.items {
            list_items.push(ListItem::new(item_line(
                &i.name,
                &i.kind,
                &i.target,
                action_span(&i.action),
            )));
        }
    }

    if !report.skipped.is_empty() {
        list_items.push(section_header(&format!(
            "Deferred ({})",
            report.skipped.len()
        )));
        for s in &report.skipped {
            list_items.push(ListItem::new(item_line(
                &s.name,
                &s.kind,
                &s.target,
                action_span("deferred"),
            )));
        }
    }

    if !report.warnings.is_empty() {
        list_items.push(section_header(&format!(
            "Warnings ({})",
            report.warnings.len()
        )));
        for w in &report.warnings {
            list_items.push(ListItem::new(Line::from(vec![
                Span::styled("⚠ ", Style::default().fg(palette::WARNING)),
                Span::raw(w.clone()),
            ])));
        }
    }

    if let Some(apply) = &state.last_apply {
        list_items.push(ListItem::new(Line::from("")));
        list_items.push(ListItem::new(Line::from(vec![
            theme::label("Last apply: "),
            Span::styled(apply.clone(), Style::default().fg(palette::SUCCESS)),
        ])));
    }

    let hint = if state.confirming {
        None
    } else if report.items.is_empty() {
        Some("r: refresh dry run")
    } else {
        Some("r: refresh dry run   a: apply all (merge + clear)")
    };
    if let Some(hint) = hint {
        list_items.push(ListItem::new(Line::from("")));
        list_items.push(ListItem::new(Line::from(Span::styled(
            hint,
            Style::default().fg(palette::MUTED),
        ))));
    }

    frame.render_widget(List::new(list_items).block(theme::block("")), chunks[1]);
}

/// Render the apply confirm modal over the inbox view.
pub fn render_confirm(frame: &mut Frame<'_>, area: Rect, merged: usize, cleared: usize) {
    let width = area.width.saturating_sub(10).clamp(20, 76);
    let height = 12.min(area.height.saturating_sub(4)).max(8);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let modal = Rect::new(x, y, width, height);

    frame.render_widget(ratatui::widgets::Clear, modal);

    let lines = vec![
        Line::from(vec![
            Span::raw("This merges "),
            Span::styled(
                format!("{merged} item(s)"),
                Style::default().fg(palette::SUCCESS).bold(),
            ),
            Span::raw(" into the vault and clears the inbox "),
            Span::styled(
                format!("({cleared} cleared)"),
                Style::default().fg(palette::WARNING),
            ),
            Span::raw("."),
        ]),
        Line::from(""),
        Line::from("All-or-nothing: every item is merged, then the inbox branch is cleared."),
        Line::from(""),
        Line::from(vec![
            Span::styled("Type y", Style::default().fg(palette::ACCENT).bold()),
            Span::raw(" to confirm. Any other key cancels."),
        ]),
    ];
    let block = theme::block(" Confirm: apply inbox ");
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, modal);
}
