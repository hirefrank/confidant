//! Read-only Find view (`confidant find <query> --json --no-input`).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::FindResult;
use crate::theme;
use crate::theme::palette;

/// State for the Find view.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FindViewState {
    pub query: String,
    pub input: String,
    pub editing: bool,
    pub result: Option<FindResult>,
    pub selected: usize,
}

/// Pure renderer for the Find view.
pub fn render(state: &FindViewState, frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(5),
        ])
        .split(area);

    let query_title = if state.editing {
        " Find (typing query — Enter to search, Esc to cancel) "
    } else {
        " Find (press / to enter query, Enter on p-… hit opens Context) "
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

    match &state.result {
        None => {
            frame.render_widget(
                Paragraph::new(Line::from(
                    "No search run yet. Press / to enter a query.".dark_gray(),
                ))
                .block(theme::block(" Matches ")),
                chunks[1],
            );
        }
        Some(res) => {
            let mut title = format!(" Matches ({} matches", res.matches.len());
            if res.skipped_encrypted > 0 {
                title.push_str(&format!(", skipped_encrypted: {}", res.skipped_encrypted));
            }
            if res.refused_envelopes > 0 {
                title.push_str(&format!(", refused_envelopes: {}", res.refused_envelopes));
            }
            if !res.findings.is_empty() {
                title.push_str(&format!(", {} load findings", res.findings.len()));
            }
            title.push_str(") ");

            if res.matches.is_empty() {
                frame.render_widget(
                    Paragraph::new(Line::from("0 matches".dark_gray())).block(theme::block(&title)),
                    chunks[1],
                );
            } else {
                let items: Vec<ListItem<'_>> = res
                    .matches
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
                            Span::raw("  "),
                            Span::raw(hit.excerpt.clone()),
                        ]))
                    })
                    .collect();
                let mut list_state = ListState::default();
                list_state.select(Some(state.selected));
                frame.render_stateful_widget(
                    List::new(items)
                        .block(theme::block(&title))
                        .highlight_style(Style::default().fg(palette::ACCENT).bold())
                        .highlight_symbol("› ")
                        .highlight_spacing(HighlightSpacing::Always),
                    chunks[1],
                    &mut list_state,
                );
            }
        }
    }

    let detail_lines: Vec<Line<'_>> = match state
        .result
        .as_ref()
        .and_then(|r| r.matches.get(state.selected))
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
                    format!("{}:{}", hit.path, hit.line),
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
        chunks[2],
    );
}
