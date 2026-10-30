//! Search view: QMD-backed search via the `qmd-search` skill (`#212` 3a).
//!
//! Renders the fail-closed [`FilteredSearchResult`]: only `via == "qmd"` or
//! `via == "find"` matches are shown, the fallback banner appears when the
//! skill fell back to `confidant find`, and drop counts are always visible.
//! A `W_SKIPPED_ENCRYPTED` warning finding (#718) renders in the status
//! block, so a zero-match exact search over skipped records does not read
//! as absence in the TUI either, and a `W_PARTIAL_RESULTS` finding (#769)
//! renders the same way, so a non-empty exact search over skipped records
//! does not read as the complete answer.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::search::{FilteredSearchResult, SearchViewState};
use crate::theme;
use crate::theme::palette;

/// Pure renderer for the Search view.
pub fn render(state: &SearchViewState, frame: &mut Frame<'_>, area: Rect) {
    // #790: size the status block from the wrapped line count at the
    // actual width, so a wrapped warning is never clipped. The count
    // includes the block borders; the inner width subtracts the borders
    // and the block's horizontal padding (1 each side).
    let lines = status_lines(state.result.as_ref());
    let inner_width = area.width.saturating_sub(4).max(1);
    let status_len: u16 = 2 + lines
        .iter()
        .map(|line| wrapped_line_count(line, inner_width))
        .sum::<u16>();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(status_len),
            Constraint::Min(5),
            Constraint::Length(5),
        ])
        .split(area);

    let mode_tag = if state.exact { " [exact]" } else { "" };
    let query_title = if state.editing {
        format!(" Search{mode_tag} (typing query — Enter to search, Esc to cancel) ")
    } else {
        format!(
            " Search{mode_tag} (press / to enter query — qmd-ranked when available, \
             exact scan otherwise; e toggles exact, Enter on p-… hit opens Context) "
        )
    };
    let query_line = if state.editing {
        Line::from(vec![
            theme::label("query "),
            Span::styled(format!("{}_", state.input), palette::TEXT),
        ])
    } else if state.query.is_empty() {
        Line::from(vec![
            theme::label("query "),
            Span::styled("(empty — press / to search)", theme::muted()),
        ])
    } else {
        Line::from(vec![
            theme::label("query "),
            Span::styled(state.query.clone(), palette::TEXT),
        ])
    };
    frame.render_widget(
        Paragraph::new(query_line).block(theme::block(&query_title)),
        chunks[0],
    );

    render_status(state.result.as_ref(), frame, chunks[1]);
    render_matches(state, frame, chunks[2]);
    render_detail(state, frame, chunks[3]);
}

/// Number of visual rows a status line occupies once wrapped at
/// `inner_width` with `Wrap { trim: true }`.
///
/// Greedy word wrap over the line's plain text. The `line_count` API
/// would compute this exactly, but it needs ratatui's unstable
/// `rendered-line-info` feature, which this crate does not enable; the
/// greedy count matches it for the short, single-spaced prose these
/// status lines carry, and the 80x24 tests prove the full warning
/// renders. Overlong words spill onto further rows rather than
/// overflowing the block.
fn wrapped_line_count(line: &Line<'_>, inner_width: u16) -> u16 {
    let width = inner_width.max(1) as usize;
    let text: String = line
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect();
    let mut rows = 1usize;
    let mut current = 0usize;
    for word in text.split_whitespace() {
        let word_width = Line::from(word.to_owned()).width();
        if word_width == 0 {
            continue;
        }
        if current == 0 {
            rows += word_width.saturating_sub(1) / width;
            current = word_width % width;
            if current == 0 {
                current = width;
            }
        } else if current + 1 + word_width <= width {
            current += 1 + word_width;
        } else {
            rows += 1;
            rows += word_width.saturating_sub(1) / width;
            current = word_width % width;
            if current == 0 {
                current = width;
            }
        }
    }
    rows as u16
}

/// The status block's lines: fallback banner, drop counts, mode line,
/// and any in-band coverage warning. Shared by `render` (for sizing)
/// and `render_status` (for drawing) so the height always matches the
/// wrapped content.
fn status_lines(result: Option<&FilteredSearchResult>) -> Vec<Line<'static>> {
    let Some(res) = result else {
        return vec![Line::from(
            "No search run yet. Press / to enter a query.".fg(palette::MUTED),
        )];
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
            Span::styled(res.result.mode.clone(), palette::TEXT),
        ]));
    }
    let mut count_spans: Vec<Span<'static>> = vec![
        theme::label("matches shown: "),
        Span::styled(
            res.kept.len().to_string(),
            Style::default().fg(palette::TEXT).bold(),
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
    // #718/#769: the in-band warning from `confidant find` (carried
    // through `find_result_to_search`) renders here, not just in the
    // counts: a bare "0 matches" over skipped records must not read as
    // absence, and a non-empty match list over skipped records must not
    // read as the complete answer. Only the two warning codes render —
    // other findings keep their existing (non-)rendering, and the
    // message itself carries only the count.
    for finding in &res.result.findings {
        if finding.code == "W_SKIPPED_ENCRYPTED" || finding.code == "W_PARTIAL_RESULTS" {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{}: ", finding.code),
                    Style::default().fg(palette::WARNING).bold(),
                ),
                Span::styled(finding.message.clone(), palette::TEXT),
            ]));
        }
    }
    lines
}

/// Fallback banner, drop counts, and mode line.
fn render_status(result: Option<&FilteredSearchResult>, frame: &mut Frame<'_>, area: Rect) {
    let block = theme::block(" Status ");
    let lines = status_lines(result);
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(block),
        area,
    );
}

fn render_matches(state: &SearchViewState, frame: &mut Frame<'_>, area: Rect) {
    let block = theme::block(" Matches ");
    let Some(res) = state.result.as_ref() else {
        frame.render_widget(
            Paragraph::new(Line::from("No search run yet.".fg(palette::MUTED))).block(block),
            area,
        );
        return;
    };
    if res.kept.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from("0 matches".fg(palette::MUTED))).block(block),
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
                Span::styled(format!("{}:{}", hit.path, hit.line), theme::muted()),
                Span::raw(" "),
                Span::styled(format!("[{} {:.2}]", hit.via, hit.score), theme::muted()),
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
        None => vec![Line::from("No match selected.".fg(palette::MUTED))],
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
                    theme::muted(),
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
