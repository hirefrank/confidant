//! Read-only Find view (`confidant find <query> --json --no-input`).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::FindResult;

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

    match &state.result {
        None => {
            let block = Block::bordered().title(" Matches ");
            frame.render_widget(
                Paragraph::new("No search run yet. Press / to enter a query.").block(block),
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
            let block = Block::bordered().title(title);

            if res.matches.is_empty() {
                frame.render_widget(Paragraph::new("0 matches").block(block), chunks[1]);
            } else {
                let items: Vec<ListItem<'_>> = res
                    .matches
                    .iter()
                    .enumerate()
                    .map(|(idx, hit)| {
                        let marker = if idx == state.selected { ">" } else { " " };
                        let id = hit.id.as_deref().unwrap_or("-");
                        ListItem::new(Line::from(format!(
                            "{marker} {:<28} {}:{}  {}",
                            id, hit.path, hit.line, hit.excerpt
                        )))
                    })
                    .collect();
                frame.render_widget(List::new(items).block(block), chunks[1]);
            }
        }
    }

    let detail_block = Block::bordered().title(" Match Detail ");
    let detail_lines = match state
        .result
        .as_ref()
        .and_then(|r| r.matches.get(state.selected))
    {
        None => vec![Line::from("No match selected.")],
        Some(hit) => vec![
            Line::from(format!(
                "id: {} | location: {}:{}",
                hit.id.as_deref().unwrap_or("-"),
                hit.path,
                hit.line
            )),
            Line::from(format!("excerpt: {}", hit.excerpt)),
        ],
    };
    frame.render_widget(
        Paragraph::new(detail_lines)
            .block(detail_block)
            .wrap(Wrap { trim: false }),
        chunks[2],
    );
}
