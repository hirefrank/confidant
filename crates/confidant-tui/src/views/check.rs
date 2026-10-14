//! Read-only Check view (`confidant check --json --no-input`).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::CheckReport;

/// State for the Check view.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CheckViewState {
    pub report: Option<CheckReport>,
    pub selected: usize,
}

impl CheckViewState {
    pub fn from_report(report: CheckReport) -> Self {
        Self {
            report: Some(report),
            selected: 0,
        }
    }
}

/// Pure renderer for the Check view.
pub fn render(state: &CheckViewState, frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(7),
        ])
        .split(area);

    let summary_text = match &state.report {
        None => "No check report loaded (press r to run check)".to_owned(),
        Some(r) => {
            let status = if r.ok { "OK" } else { "FAILED" };
            format!(
                "status: {status} | spec: {} | records: {} | ledger: {} | errors: {} | warnings: {} | {} findings",
                r.spec,
                r.summary.records,
                r.summary.ledger_entries,
                r.summary.errors,
                r.summary.warnings,
                r.findings.len()
            )
        }
    };
    let summary_block = Block::bordered().title(" Check Summary ");
    frame.render_widget(Paragraph::new(summary_text).block(summary_block), chunks[0]);

    let findings_block = Block::bordered().title(" Findings ");
    match &state.report {
        None => {
            frame.render_widget(
                Paragraph::new("Press r to run check.").block(findings_block),
                chunks[1],
            );
        }
        Some(r) if r.findings.is_empty() => {
            frame.render_widget(
                Paragraph::new("0 findings — vault is coherent.").block(findings_block),
                chunks[1],
            );
        }
        Some(r) => {
            let items: Vec<ListItem<'_>> = r
                .findings
                .iter()
                .enumerate()
                .map(|(idx, f)| {
                    let marker = if idx == state.selected { ">" } else { " " };
                    let id = f.id.as_deref().unwrap_or("-");
                    ListItem::new(Line::from(format!(
                        "{marker} [{:<7}] {:<25} {:<28} {}",
                        f.severity, f.code, id, f.message
                    )))
                })
                .collect();
            frame.render_widget(List::new(items).block(findings_block), chunks[1]);
        }
    }

    let detail_block = Block::bordered().title(" Finding Detail (Enter on p-… opens Context) ");
    let detail_lines = match state
        .report
        .as_ref()
        .and_then(|r| r.findings.get(state.selected))
    {
        None => vec![Line::from("No finding selected.")],
        Some(f) => {
            let loc = match (&f.file, f.line) {
                (Some(file), Some(line)) => format!("{file}:{line}"),
                (Some(file), None) => file.clone(),
                _ => "-".to_owned(),
            };
            vec![
                Line::from(format!(
                    "code: {} | severity: {} | id: {} | location: {}",
                    f.code,
                    f.severity,
                    f.id.as_deref().unwrap_or("-"),
                    loc
                )),
                Line::from(format!("message: {}", f.message)),
                Line::from(format!("fix: {}", f.fix.as_deref().unwrap_or("-"))),
            ]
        }
    };
    frame.render_widget(
        Paragraph::new(detail_lines)
            .block(detail_block)
            .wrap(Wrap { trim: false }),
        chunks[2],
    );
}
