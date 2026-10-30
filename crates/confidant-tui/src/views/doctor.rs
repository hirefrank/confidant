//! Read-only Doctor view (`confidant doctor --json --no-input`).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::DoctorReport;
use crate::theme;
use crate::theme::palette;

/// State for the Doctor view.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DoctorViewState {
    pub report: Option<DoctorReport>,
    pub ok: Option<bool>,
    pub selected: usize,
}

/// Status tag for a doctor check: red for errors, yellow for warnings
/// and for `unknown` checks (#709: undetermined is warning-tier, never
/// a green pass), green otherwise.
fn status_tag(status: &str) -> Span<'_> {
    let style = match status {
        "error" => Style::default().fg(palette::ERROR).bold(),
        "warning" | "unknown" => Style::default().fg(palette::WARNING).bold(),
        _ => Style::default().fg(palette::SUCCESS),
    };
    Span::styled(format!("[{status}]"), style)
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

    let summary_line = match &state.report {
        None => Line::from(vec![
            Span::raw("No doctor report loaded "),
            Span::styled("(press r to run doctor)", theme::muted()),
        ]),
        Some(r) => {
            let overall = state
                .ok
                .unwrap_or_else(|| !r.checks.iter().any(|c| c.status == "error"));
            let mut spans = vec![theme::status_badge(overall), Span::raw("  ")];
            spans.extend(theme::count(
                "checks ",
                r.checks.len(),
                Style::default().fg(palette::TEXT).bold(),
            ));
            Line::from(spans)
        }
    };
    frame.render_widget(
        Paragraph::new(summary_line).block(theme::block(" Doctor Summary ")),
        chunks[0],
    );

    match &state.report {
        None => {
            frame.render_widget(
                Paragraph::new(Line::from("Press r to run doctor.".fg(palette::MUTED)))
                    .block(theme::block(" Checks ")),
                chunks[1],
            );
        }
        Some(r) if r.checks.is_empty() => {
            frame.render_widget(
                Paragraph::new(Line::from("0 checks".fg(palette::MUTED)))
                    .block(theme::block(" Checks ")),
                chunks[1],
            );
        }
        Some(r) => {
            let items: Vec<ListItem<'_>> = r
                .checks
                .iter()
                .map(|c| {
                    ListItem::new(Line::from(vec![
                        status_tag(&c.status),
                        Span::raw(" "),
                        Span::styled(c.id.clone(), palette::TEXT),
                        Span::raw(" "),
                        Span::raw(c.message.clone()),
                    ]))
                })
                .collect();
            let mut list_state = ListState::default();
            list_state.select(Some(state.selected));
            frame.render_stateful_widget(
                List::new(items)
                    .block(theme::block(" Checks "))
                    .highlight_style(Style::default().fg(palette::ACCENT).bold())
                    .highlight_symbol("› ")
                    .highlight_spacing(HighlightSpacing::Always),
                chunks[1],
                &mut list_state,
            );
        }
    }

    let detail_lines: Vec<Line<'_>> = match state
        .report
        .as_ref()
        .and_then(|r| r.checks.get(state.selected))
    {
        None => vec![Line::from("No check selected.".fg(palette::MUTED))],
        Some(c) => vec![
            Line::from(vec![
                theme::label("id      "),
                Span::styled(c.id.clone(), palette::TEXT),
            ]),
            Line::from(vec![theme::label("status  "), status_tag(&c.status)]),
            Line::from(vec![theme::label("message "), Span::raw(c.message.clone())]),
        ],
    };
    frame.render_widget(
        Paragraph::new(detail_lines)
            .block(theme::block(" Check Detail "))
            .wrap(Wrap { trim: false }),
        chunks[2],
    );
}
