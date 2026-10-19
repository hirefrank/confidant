//! Proposals list and detail views.
//!
//! The list shows discovered `*.json` manifests in `.confidant/proposals/`;
//! the detail shows one manifest's planned steps and their status. All
//! rendering is pure: the apply flow lives in [`crate::apply`].

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::theme;
use crate::theme::palette;

/// One row in the proposals list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposalListEntry {
    pub name: String,
    pub skill: String,
    pub detail: String,
    pub progress: String,
    pub error: Option<String>,
}

/// State for the proposals list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposalsListState {
    pub entries: Vec<ProposalListEntry>,
    pub selected: usize,
    pub vault_note: String,
}

/// One planned step row in the detail view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StepRow {
    pub label: String,
    pub status: String,
}

/// State for the open-proposal detail view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposalDetailState {
    pub name: String,
    pub skill: String,
    pub summary: String,
    pub warnings: Vec<String>,
    pub steps: Vec<StepRow>,
    pub hint: String,
}

/// Status icon for a step, colored by state. Text is unchanged from before;
/// only styling is added.
fn step_status_span(status: &str) -> Span<'_> {
    let style = match status {
        "[x]" => Style::default().fg(palette::SUCCESS).bold(),
        "[!]" => Style::default().fg(palette::WARNING).bold(),
        "[E]" => Style::default().fg(palette::ERROR).bold(),
        _ => theme::muted(),
    };
    Span::styled(status, style)
}

/// Pure renderer for the proposals list.
pub fn render_list(state: &ProposalsListState, frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let header = if state.vault_note.is_empty() {
        Line::from("Proposal manifests awaiting review".fg(palette::MUTED))
    } else {
        Line::from(vec![
            theme::label("Proposal manifests "),
            Span::styled(state.vault_note.clone(), palette::TEXT),
        ])
    };
    frame.render_widget(
        Paragraph::new(header).block(theme::block(" Proposals ")),
        chunks[0],
    );

    if state.entries.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(
                "No proposal manifests in .confidant/proposals/.".fg(palette::MUTED),
            ))
            .block(theme::block("")),
            chunks[1],
        );
        return;
    }

    let items: Vec<ListItem<'_>> = state
        .entries
        .iter()
        .map(|e| {
            let status = e.error.clone().unwrap_or_else(|| e.progress.clone());
            let status_style = if e.error.is_some() {
                Style::default().fg(palette::ERROR)
            } else {
                theme::muted()
            };
            ListItem::new(Line::from(vec![
                Span::styled(e.name.clone(), palette::TEXT),
                Span::raw("  "),
                Span::styled(e.skill.clone(), Style::default().fg(palette::ACCENT)),
                Span::raw("  "),
                Span::styled(e.detail.clone(), theme::muted()),
                Span::raw("  "),
                Span::styled(status, status_style),
            ]))
        })
        .collect();
    let mut list_state = ListState::default();
    list_state.select(Some(state.selected));
    frame.render_stateful_widget(
        List::new(items)
            .block(theme::block(" Enter: open   a: apply   r: refresh "))
            .highlight_style(Style::default().fg(palette::ACCENT).bold())
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always),
        chunks[1],
        &mut list_state,
    );
}

/// Pure renderer for the open-proposal detail view.
pub fn render_detail(state: &ProposalDetailState, frame: &mut Frame<'_>, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    let mut header_lines = vec![
        Line::from(vec![
            theme::label("manifest "),
            Span::styled(state.name.clone(), palette::TEXT),
        ]),
        Line::from(vec![
            theme::label("skill    "),
            Span::styled(state.skill.clone(), Style::default().fg(palette::ACCENT)),
        ]),
    ];
    if !state.summary.is_empty() {
        header_lines.push(Line::from(vec![
            theme::label("summary  "),
            Span::raw(state.summary.clone()),
        ]));
    }
    for warning in &state.warnings {
        header_lines.push(Line::from(vec![
            Span::styled("⚠ warning ", Style::default().fg(palette::WARNING).bold()),
            Span::raw(warning.clone()),
        ]));
    }
    frame.render_widget(
        Paragraph::new(header_lines).block(theme::block(" Proposal ")),
        chunks[0],
    );

    let items: Vec<ListItem<'_>> = state
        .steps
        .iter()
        .map(|s| {
            ListItem::new(Line::from(vec![
                step_status_span(&s.status),
                Span::raw("  "),
                Span::raw(s.label.clone()),
            ]))
        })
        .collect();
    let list_block = if items.is_empty() {
        theme::block(" Steps (nothing to apply) ")
    } else {
        theme::block(" Steps ")
    };
    frame.render_widget(List::new(items).block(list_block), chunks[1]);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(state.hint.clone(), theme::muted())))
            .block(theme::block(""))
            .wrap(Wrap { trim: false }),
        chunks[2],
    );
}
