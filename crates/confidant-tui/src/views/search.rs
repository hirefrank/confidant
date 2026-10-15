//! Search view: QMD-backed search via the `qmd-search` skill (`#212` 3a).
//!
//! Renders the fail-closed [`FilteredSearchResult`]: only `via == "qmd"` or
//! `via == "find"` matches are shown, the fallback banner appears when the
//! skill fell back to `confidant find`, and drop counts are always visible.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::search::{FilteredSearchResult, SearchViewState};

/// Pure renderer for the Search view.
pub fn render(state: &SearchViewState, frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Min(5),
            Constraint::Length(5),
        ])
        .split(area);

    let query_title = if state.editing {
        " Search (typing query — Enter to search, Esc to cancel) "
    } else {
        " Search (press / to enter query, Enter on p-… hit opens Context) "
    };
    let query_display = if state.editing {
        format!("query: {}_", state.input)
    } else if state.query.is_empty() {
        "query: (empty — press / to search)".to_owned()
    } else {
        format!("query: {}", state.query)
    };
    frame.render_widget(
        Paragraph::new(query_display).block(Block::bordered().title(query_title)),
        chunks[0],
    );

    render_status(state.result.as_ref(), frame, chunks[1]);
    render_matches(state, frame, chunks[2]);
    render_detail(state, frame, chunks[3]);
}

/// Fallback banner, drop counts, and mode line.
fn render_status(result: Option<&FilteredSearchResult>, frame: &mut Frame<'_>, area: Rect) {
    let block = Block::bordered().title(" Status ");
    let Some(res) = result else {
        frame.render_widget(
            Paragraph::new("No search run yet. Press / to enter a query.").block(block),
            area,
        );
        return;
    };

    let mut lines = Vec::new();
    if res.result.mode == "find-fallback" {
        let reason = res.result.fallback.as_deref().unwrap_or("unknown reason");
        lines.push(Line::from(format!("fallback: {reason}")));
    } else if !res.result.mode.is_empty() {
        lines.push(Line::from(format!("mode: {}", res.result.mode)));
    }
    let mut counts = Vec::new();
    if res.result.dropped_uncleared > 0 {
        counts.push(format!(
            "dropped_uncleared: {}",
            res.result.dropped_uncleared
        ));
    }
    if res.dropped_unknown_via > 0 {
        counts.push(format!("dropped_unknown_via: {}", res.dropped_unknown_via));
    }
    if counts.is_empty() {
        lines.push(Line::from(format!("{} matches shown", res.kept.len())));
    } else {
        lines.push(Line::from(format!(
            "{} matches shown ({})",
            res.kept.len(),
            counts.join(", ")
        )));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_matches(state: &SearchViewState, frame: &mut Frame<'_>, area: Rect) {
    let block = Block::bordered().title(" Matches ");
    let Some(res) = state.result.as_ref() else {
        frame.render_widget(Paragraph::new("No search run yet.").block(block), area);
        return;
    };
    if res.kept.is_empty() {
        frame.render_widget(Paragraph::new("0 matches").block(block), area);
        return;
    }
    let items: Vec<ListItem<'_>> = res
        .kept
        .iter()
        .enumerate()
        .map(|(idx, hit)| {
            let marker = if idx == state.selected { ">" } else { " " };
            let id = hit.id.as_deref().unwrap_or("-");
            ListItem::new(Line::from(format!(
                "{marker} {:<28} {}:{}  [{} {:.2}] {}",
                id, hit.path, hit.line, hit.via, hit.score, hit.excerpt
            )))
        })
        .collect();
    frame.render_widget(List::new(items).block(block), area);
}

fn render_detail(state: &SearchViewState, frame: &mut Frame<'_>, area: Rect) {
    let detail_block = Block::bordered().title(" Match Detail ");
    let detail_lines = match state
        .result
        .as_ref()
        .and_then(|r| r.kept.get(state.selected))
    {
        None => vec![Line::from("No match selected.")],
        Some(hit) => vec![
            Line::from(format!(
                "id: {} | location: {}:{} | via: {} | score: {:.4}",
                hit.id.as_deref().unwrap_or("-"),
                hit.path,
                hit.line,
                hit.via,
                hit.score
            )),
            Line::from(format!("excerpt: {}", hit.excerpt)),
        ],
    };
    frame.render_widget(
        Paragraph::new(detail_lines)
            .block(detail_block)
            .wrap(Wrap { trim: false }),
        area,
    );
}
