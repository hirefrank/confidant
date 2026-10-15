//! Read-only Check view (`confidant check --json --no-input`).

use ratatui::layout::{Alignment, Constraint, Direction, Flex, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::CheckReport;
use crate::theme;
use crate::theme::palette;

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

/// Summary line: status badge, dim keys with bright values, and counts that
/// light up only when non-zero.
fn summary_line(r: &CheckReport) -> Line<'static> {
    let mut spans = vec![theme::status_badge(r.ok), Span::raw("  ")];
    spans.extend(theme::labeled(
        "spec ",
        Span::styled(r.spec.clone(), Color::White),
    ));
    spans.push(theme::label("  •  "));
    spans.extend(theme::labeled(
        "records ",
        Span::styled(
            r.summary.records.to_string(),
            Style::default().fg(Color::White).bold(),
        ),
    ));
    spans.push(theme::label("  •  "));
    spans.extend(theme::labeled(
        "ledger ",
        Span::styled(
            r.summary.ledger_entries.to_string(),
            Style::default().fg(Color::White).bold(),
        ),
    ));
    spans.push(theme::label("  •  "));
    spans.extend(theme::count(
        "errors ",
        r.summary.errors,
        Style::default().fg(palette::ERROR).bold(),
    ));
    spans.push(theme::label("  •  "));
    spans.extend(theme::count(
        "warnings ",
        r.summary.warnings,
        Style::default().fg(palette::WARNING).bold(),
    ));
    spans.push(theme::label("  •  "));
    spans.extend(theme::count(
        "findings ",
        r.findings.len(),
        Style::default().fg(palette::WARNING).bold(),
    ));
    Line::from(spans)
}

/// One finding row: colored severity tag, code, dim id, message.
fn finding_row(f: &crate::contract::Finding) -> ListItem<'_> {
    let id = f.id.clone().unwrap_or_else(|| "-".to_owned());
    ListItem::new(Line::from(vec![
        theme::severity_tag(&f.severity),
        Span::raw(" "),
        Span::styled(f.code.clone(), Style::default().fg(Color::White)),
        Span::raw(" "),
        Span::styled(id, Style::default().fg(palette::MUTED)),
        Span::raw(" "),
        Span::raw(f.message.clone()),
    ]))
}

/// Label/value detail row for the finding detail pane.
fn detail_row<'a>(label_text: &'a str, value: Span<'a>) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("{label_text:<10}"),
            Style::default().fg(palette::MUTED),
        ),
        value,
    ])
}

/// Pure renderer for the Check view.
pub fn render(state: &CheckViewState, frame: &mut Frame<'_>, area: Rect) {
    let Some(r) = &state.report else {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);
        frame.render_widget(
            Paragraph::new(summary_line_placeholder()).block(theme::block(" Check Summary ")),
            chunks[0],
        );
        frame.render_widget(
            Paragraph::new(Line::from("Press r to run check.".dark_gray()))
                .block(theme::block(" Findings ")),
            chunks[1],
        );
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);
    frame.render_widget(
        Paragraph::new(summary_line(r)).block(theme::block(" Check Summary ")),
        chunks[0],
    );

    if r.findings.is_empty() {
        render_empty_state(r, frame, chunks[1]);
        return;
    }

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);

    let items: Vec<ListItem<'_>> = r.findings.iter().map(finding_row).collect();
    let mut list_state = ListState::default();
    list_state.select(Some(state.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(theme::block(" Findings "))
            .highlight_style(Style::default().fg(palette::ACCENT).bold())
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always),
        panes[0],
        &mut list_state,
    );

    render_detail(r, state.selected, frame, panes[1]);
}

fn summary_line_placeholder() -> Line<'static> {
    Line::from(vec![
        Span::raw("No check report loaded "),
        Span::styled(
            "(press r to run check)",
            Style::default().fg(palette::MUTED),
        ),
    ])
}

/// Centered empty state: no detail pane, just a coherent-vault message.
fn render_empty_state(r: &CheckReport, frame: &mut Frame<'_>, area: Rect) {
    let block = theme::block(" Findings ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let centered = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2)])
        .flex(Flex::Center)
        .split(inner);

    let lines = vec![
        Line::from("✓ Vault is coherent".green().bold()),
        Line::from(
            format!(
                "0 findings across {} records and {} ledger entries",
                r.summary.records, r.summary.ledger_entries
            )
            .dark_gray(),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center),
        centered[0],
    );
}

/// Finding detail pane: label/value rows with a colored severity.
fn render_detail(r: &CheckReport, selected: usize, frame: &mut Frame<'_>, area: Rect) {
    let block = theme::block(" Detail ");
    let lines: Vec<Line<'_>> = match r.findings.get(selected) {
        None => vec![Line::from("No finding selected.".dark_gray())],
        Some(f) => {
            let loc = match (&f.file, f.line) {
                (Some(file), Some(line)) => format!("{file}:{line}"),
                (Some(file), None) => file.clone(),
                _ => "-".to_owned(),
            };
            let id = f.id.clone().unwrap_or_else(|| "-".to_owned());
            vec![
                detail_row("code", Span::styled(f.code.clone(), Color::White)),
                detail_row("severity", theme::severity_tag(&f.severity)),
                detail_row("id", Span::styled(id, Style::default().fg(palette::MUTED))),
                detail_row("location", Span::raw(loc)),
                detail_row("message", Span::raw(f.message.clone())),
                detail_row(
                    "fix",
                    Span::styled(
                        f.fix.clone().unwrap_or_else(|| "-".to_owned()),
                        Style::default().fg(palette::MUTED),
                    ),
                ),
            ]
        }
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}
