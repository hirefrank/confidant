//! Read-only Doctor view (`confidant doctor --json --no-input`).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::DoctorReport;

/// State for the Doctor view.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DoctorViewState {
    pub report: Option<DoctorReport>,
    pub ok: Option<bool>,
    pub selected: usize,
}

/// Pure renderer for the Doctor view.
pub fn render(state: &DoctorViewState, frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(5),
        ])
        .split(area);

    let summary_text = match &state.report {
        None => "No doctor report loaded (press r to run doctor)".to_owned(),
        Some(r) => {
            let overall = if state
                .ok
                .unwrap_or_else(|| !r.checks.iter().any(|c| c.status == "error"))
            {
                "OK"
            } else {
                "FAILED"
            };
            format!("status: {overall} | checks: {}", r.checks.len())
        }
    };
    frame.render_widget(
        Paragraph::new(summary_text).block(Block::bordered().title(" Doctor Summary ")),
        chunks[0],
    );

    let checks_block = Block::bordered().title(" Checks ");
    match &state.report {
        None => {
            frame.render_widget(
                Paragraph::new("Press r to run doctor.").block(checks_block),
                chunks[1],
            );
        }
        Some(r) if r.checks.is_empty() => {
            frame.render_widget(Paragraph::new("0 checks").block(checks_block), chunks[1]);
        }
        Some(r) => {
            let items: Vec<ListItem<'_>> = r
                .checks
                .iter()
                .enumerate()
                .map(|(idx, c)| {
                    let marker = if idx == state.selected { ">" } else { " " };
                    ListItem::new(Line::from(format!(
                        "{marker} [{:<7}] {:<24} {}",
                        c.status, c.id, c.message
                    )))
                })
                .collect();
            frame.render_widget(List::new(items).block(checks_block), chunks[1]);
        }
    }

    let detail_block = Block::bordered().title(" Check Detail ");
    let detail_lines = match state
        .report
        .as_ref()
        .and_then(|r| r.checks.get(state.selected))
    {
        None => vec![Line::from("No check selected.")],
        Some(c) => vec![
            Line::from(format!("id: {} | status: {}", c.id, c.status)),
            Line::from(format!("message: {}", c.message)),
        ],
    };
    frame.render_widget(
        Paragraph::new(detail_lines)
            .block(detail_block)
            .wrap(Wrap { trim: false }),
        chunks[2],
    );
}
