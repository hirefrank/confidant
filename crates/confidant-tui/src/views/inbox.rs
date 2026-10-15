//! Read-only inbox review view.
//!
//! Shows the `inbox --dry-run` plan: items with their actions, skipped
//! items, and warnings. Applying is all-or-nothing through the existing
//! `inbox` command with an explicit `y` confirm; there is no per-item
//! selection here (deferred to #217).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::{InboxReport, InboxSkipped};

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

/// One row in the items list: name, kind, target, action.
fn item_line(name: &str, kind: &str, target: &str, action: &str) -> String {
    format!("{name} [{kind}] -> {target} ({action})")
}

/// Pure renderer for the inbox tab.
pub fn render(state: &InboxViewState, frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let header = match &state.report {
        Some(r) if r.empty => "Inbox — nothing to do (no inbox branch)".to_owned(),
        Some(r) => format!(
            "Inbox — dry run on branch '{}': {} to merge, {} to clear",
            r.branch, r.merged, r.cleared
        ),
        None => "Inbox — press r to load the dry run".to_owned(),
    };
    frame.render_widget(
        Paragraph::new(header).block(Block::bordered().title(" Inbox ")),
        chunks[0],
    );

    let Some(report) = &state.report else {
        frame.render_widget(
            Paragraph::new("No dry-run report loaded yet.").block(Block::bordered()),
            chunks[1],
        );
        return;
    };

    if report.empty {
        frame.render_widget(
            Paragraph::new("No inbox branch in this vault — nothing to merge.")
                .block(Block::bordered()),
            chunks[1],
        );
        return;
    }

    let mut sections: Vec<(String, Vec<String>)> = Vec::new();

    let item_lines: Vec<String> = report
        .items
        .iter()
        .map(|i| item_line(&i.name, &i.kind, &i.target, &i.action))
        .collect();
    sections.push((
        format!("Items ({})", report.items.len()),
        if item_lines.is_empty() {
            vec!["(none)".to_owned()]
        } else {
            item_lines
        },
    ));

    if !report.skipped.is_empty() {
        let skipped_lines: Vec<String> = report
            .skipped
            .iter()
            .map(|s: &InboxSkipped| item_line(&s.name, &s.kind, &s.target, "deferred"))
            .collect();
        sections.push((
            format!("Deferred ({})", report.skipped.len()),
            skipped_lines,
        ));
    }

    if !report.warnings.is_empty() {
        sections.push((
            format!("Warnings ({})", report.warnings.len()),
            report.warnings.clone(),
        ));
    }

    let mut list_items: Vec<ListItem<'_>> = Vec::new();
    for (title, lines) in &sections {
        list_items.push(ListItem::new(format!("== {title} ==")));
        for line in lines {
            list_items.push(ListItem::new(format!("  {line}")));
        }
    }
    if let Some(apply) = &state.last_apply {
        list_items.push(ListItem::new(""));
        list_items.push(ListItem::new(format!("Last apply: {apply}")));
    }

    let hint = if state.confirming {
        ""
    } else if report.items.is_empty() {
        "r: refresh dry run"
    } else {
        "r: refresh dry run | a: apply all (merge + clear)"
    };
    if !hint.is_empty() {
        list_items.push(ListItem::new(""));
        list_items.push(ListItem::new(hint.to_owned()));
    }

    frame.render_widget(List::new(list_items).block(Block::bordered()), chunks[1]);
}

/// Render the apply confirm modal over the inbox view.
pub fn render_confirm(frame: &mut Frame<'_>, area: Rect, merged: usize, cleared: usize) {
    let width = area.width.saturating_sub(10).clamp(20, 76);
    let height = 12.min(area.height.saturating_sub(4)).max(8);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let modal = Rect::new(x, y, width, height);

    frame.render_widget(ratatui::widgets::Clear, modal);

    let lines = [
        format!(
            "This merges {merged} item(s) into the vault and clears the inbox ({cleared} cleared)."
        ),
        String::new(),
        "All-or-nothing: every item is merged, then the inbox branch is cleared.".to_owned(),
        String::new(),
        "Type y to confirm. Any other key cancels.".to_owned(),
    ];
    let block = Block::bordered().title(" Confirm: apply inbox ");
    let text: Vec<Line> = lines.iter().map(|l| Line::from(l.clone())).collect();
    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, modal);
}
