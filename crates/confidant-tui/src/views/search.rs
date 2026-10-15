//! Search view: QMD-backed search via the `qmd-search` skill (`#212` 3a).
//!
//! Renders the fail-closed [`FilteredSearchResult`]: only `via == "qmd"` or
//! `via == "find"` matches are shown, the fallback banner appears when the
//! skill fell back to `confidant find`, and drop counts are always visible.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::search::{FilteredSearchResult, SearchViewState};
use crate::theme;
use crate::theme::palette;

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
    let query_line = if state.editing {
        Line::from(vec![
            theme::label("query "),
            Span::styled(format!("{}_", state.input), Color::White),
        ])
    } else if state.query.is_empty() {
        Line::from(vec![
            theme::label("query "),
            Span::styled(
                "(empty — press / to search)",
                Style::default().fg(palette::MUTED),
            ),
        ])
    } else {
        Line::from(vec![
            theme::label("query "),
            Span::styled(state.query.clone(), Color::White),
        ])
    };
    frame.render_widget(
        Paragraph::new(query_line).block(theme::block(query_title)),
        chunks[0],
    );

    render_status(state.result.as_ref(), frame, chunks[1]);
    render_matches(state, frame, chunks[2]);
    render_detail(state, frame, chunks[3]);
}

/// Fallback banner, drop counts, and mode line.
fn render_status(result: Option<&FilteredSearchResult>, frame: &mut Frame<'_>, area: Rect) {
    let block = theme::block(" Status ");
    let Some(res) = result else {
        frame.render_widget(
            Paragraph::new(Line::from(
                "No search run yet. Press / to enter a query.".dark_gray(),
            ))
            .block(block),
            area,
        );
        return;
    };

    let mut lines = Vec::new();
    if res.result.mode == "find-fallback" {
        let reason = res.result.fallback.as_deref().unwrap_or("unknown reason");
        lines.push(Line::from(vec![
            Span::styled("fallback: ", Style::default().fg(palette::WARNING).bold()),
            Span::raw(reason.to_owned()),
        ]));
    } else if !res.result.mode.is_empty() {
        lines.push(Line::from(vec![
            theme::label("mode: "),
            Span::styled(res.result.mode.clone(), Color::White),
        ]));
    }
    let mut count_spans: Vec<Span<'static>> = vec![
        theme::label("matches shown: "),
        Span::styled(
            res.kept.len().to_string(),
            Style::default().fg(Color::White).bold(),
        ),
    ];
    if res.result.dropped_uncleared > 0 {
        count_spans.push(theme::label("  (dropped_uncleared: "));
        count_spans.push(Span::styled(
            res.result.dropped_uncleared.to_string(),
            Style::default().fg(palette::WARNING).bold(),
        ));
        count_spans.push(theme::label(")"));
    }
    if res.dropped_unknown_via > 0 {
        count_spans.push(theme::label("  (dropped_unknown_via: "));
        count_spans.push(Span::styled(
            res.dropped_unknown_via.to_string(),
            Style::default().fg(palette::WARNING).bold(),
        ));
        count_spans.push(theme::label(")"));
    }
    lines.push(Line::from(count_spans));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_matches(state: &SearchViewState, frame: &mut Frame<'_>, area: Rect) {
    let block = theme::block(" Matches ");
    let Some(res) = state.result.as_ref() else {
        frame.render_widget(
            Paragraph::new(Line::from("No search run yet.".dark_gray())).block(block),
            area,
        );
        return;
    };
    if res.kept.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from("0 matches".dark_gray())).block(block),
            area,
        );
        return;
    }
    let items: Vec<ListItem<'_>> = res
        .kept
        .iter()
        .map(|hit| {
            let id = hit.id.clone().unwrap_or_else(|| "-".to_owned());
            ListItem::new(Line::from(vec![
                Span::styled(id, Style::default().fg(palette::ACCENT)),
                Span::raw(" "),
                Span::styled(
                    format!("{}:{}", hit.path, hit.line),
                    Style::default().fg(palette::MUTED),
                ),
                Span::raw(" "),
                Span::styled(
                    format!("[{} {:.2}]", hit.via, hit.score),
                    Style::default().fg(palette::MUTED),
                ),
                Span::raw("  "),
                Span::raw(hit.excerpt.clone()),
            ]))
        })
        .collect();
    let mut list_state = ListState::default();
    list_state.select(Some(state.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(Style::default().fg(palette::ACCENT).bold())
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always),
        area,
        &mut list_state,
    );
}

fn render_detail(state: &SearchViewState, frame: &mut Frame<'_>, area: Rect) {
    let detail_lines: Vec<Line<'_>> = match state
        .result
        .as_ref()
        .and_then(|r| r.kept.get(state.selected))
    {
        None => vec![Line::from("No match selected.".dark_gray())],
        Some(hit) => vec![
            Line::from(vec![
                theme::label("id        "),
                Span::styled(
                    hit.id.clone().unwrap_or_else(|| "-".to_owned()),
                    Style::default().fg(palette::ACCENT),
                ),
            ]),
            Line::from(vec![
                theme::label("location  "),
                Span::styled(
                    format!(
                        "{}:{}  via {}  score {:.4}",
                        hit.path, hit.line, hit.via, hit.score
                    ),
                    Style::default().fg(palette::MUTED),
                ),
            ]),
            Line::from(vec![
                theme::label("excerpt   "),
                Span::raw(hit.excerpt.clone()),
            ]),
        ],
    };
    frame.render_widget(
        Paragraph::new(detail_lines)
            .block(theme::block(" Match Detail "))
            .wrap(Wrap { trim: false }),
        area,
    );
}
