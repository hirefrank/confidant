//! Workspace 1: People & Search — master–detail roster (`#556` phase 1).
//!
//! The left pane is a local filter plus two sections: `Needs Attention`
//! (derived from cached `check --json` findings) and the cleared roster
//! from `record list --json`. The right pane renders the selected person's
//! live `context --json` bundle.
//!
//! Everything here is pure: the app decides when to run the CLI and what
//! is selected. No view performs I/O.

use std::collections::HashSet;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::{CheckReport, Roster, RosterEntry};
use crate::theme;
use crate::theme::palette;
use crate::views::context::{self, ContextViewState};

/// Finding codes that read as an operator nudge about a person. Order is
/// the order findings are shown in; the CLI already emits deterministically.
pub const ATTENTION_CODES: &[&str] = &[
    "W_DATE_UPCOMING",
    "W_CADENCE_OVERDUE",
    "E_SESSION_WITHOUT_NOTES",
    "E_PAID_SESSION_GAP",
];

/// One `Needs Attention` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nudge {
    pub code: String,
    pub severity: String,
    pub person_id: String,
    pub message: String,
}

/// State for the People & Search workspace.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PeopleViewState {
    /// Cleared roster from `record list --json` (no `no-ai` people).
    pub roster: Option<Roster>,
    /// Last roster load error, shown in the left pane (the alert carries
    /// the structured CLI error).
    pub load_error: Option<String>,
    /// Local, case-insensitive filter over the roster name/id.
    pub filter: String,
    pub editing_filter: bool,
    /// Selection over the combined list: nudges first, then roster rows.
    pub selected: usize,
    pub selected_person: Option<String>,
    pub loaded: bool,
}

impl PeopleViewState {
    /// Number of rows before the roster section.
    pub fn attention_len(&self, report: Option<&CheckReport>) -> usize {
        attention(report, self.roster.as_ref()).len()
    }

    /// Clamp the selection to the current combined list. Does not load
    /// anything: safe to call while the operator types in the filter.
    pub fn clamp(&mut self, report: Option<&CheckReport>) {
        let nudges = attention(report, self.roster.as_ref());
        let people = filtered_entries(self.roster.as_ref(), &self.filter);
        let total = nudges.len() + people.len();
        self.selected = self.selected.min(total.saturating_sub(1));
    }
}

/// Derive nudges from cached check findings, fail-closed to the roster:
/// a finding whose id is not a cleared person in the roster is dropped, so
/// the nudge list can never name someone the roster hides.
pub fn attention(report: Option<&CheckReport>, roster: Option<&Roster>) -> Vec<Nudge> {
    let (Some(report), Some(roster)) = (report, roster) else {
        return Vec::new();
    };
    let ids: HashSet<&str> = roster.records.iter().map(|r| r.id.as_str()).collect();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut nudges = Vec::new();
    for finding in &report.findings {
        if !ATTENTION_CODES.contains(&finding.code.as_str()) {
            continue;
        }
        let Some(id) = finding.id.as_deref() else {
            continue;
        };
        if !id.starts_with("p-") || !ids.contains(id) {
            continue;
        }
        let key = (finding.code.clone(), id.to_owned());
        if !seen.insert(key) {
            continue;
        }
        nudges.push(Nudge {
            code: finding.code.clone(),
            severity: finding.severity.clone(),
            person_id: id.to_owned(),
            message: finding.message.clone(),
        });
    }
    nudges
}

/// Roster entries the filter matches, in roster order (already name-sorted
/// by the CLI). An empty filter keeps everything.
pub fn filtered_entries<'a>(roster: Option<&'a Roster>, filter: &str) -> Vec<&'a RosterEntry> {
    let Some(roster) = roster else {
        return Vec::new();
    };
    let needle = filter.trim().to_lowercase();
    roster
        .records
        .iter()
        .filter(|entry| {
            needle.is_empty()
                || entry.name.to_lowercase().contains(&needle)
                || entry.id.to_lowercase().contains(&needle)
        })
        .collect()
}

/// The roster entry a nudge names, if it is currently visible.
pub fn person_name<'a>(roster: Option<&'a Roster>, id: &str) -> Option<&'a str> {
    roster?
        .records
        .iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.name.as_str())
}

/// Pure renderer for the split People & Search workspace.
pub fn render(
    state: &PeopleViewState,
    report: Option<&CheckReport>,
    context: &ContextViewState,
    frame: &mut Frame<'_>,
    area: Rect,
) {
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    render_left(state, report, frame, panes[0]);
    context::render_pane(context, state.selected_person.as_deref(), frame, panes[1]);
}

fn render_left(
    state: &PeopleViewState,
    report: Option<&CheckReport>,
    frame: &mut Frame<'_>,
    area: Rect,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)])
        .split(area);

    let filter_line = if state.editing_filter {
        Line::from(vec![
            theme::label("filter "),
            Span::styled(format!("{}_", state.filter), Color::White),
        ])
    } else if state.filter.trim().is_empty() {
        Line::from(Span::styled(
            "press / to filter by name or id",
            Style::default().fg(palette::MUTED),
        ))
    } else {
        Line::from(vec![
            theme::label("filter "),
            Span::styled(state.filter.clone(), Color::White),
            Span::styled("  (Esc clears)", Style::default().fg(palette::MUTED)),
        ])
    };
    frame.render_widget(
        Paragraph::new(filter_line).block(theme::block(" Filter ")),
        chunks[0],
    );

    let nudges = attention(report, state.roster.as_ref());
    let people = filtered_entries(state.roster.as_ref(), &state.filter);
    let total = nudges.len() + people.len();
    let selected = if total == 0 {
        None
    } else {
        Some(state.selected.min(total - 1))
    };

    let mut items: Vec<ListItem<'_>> = Vec::new();
    let mut list_selected = None;

    let attention_header = if report.is_some() {
        format!("Needs Attention ({})", nudges.len())
    } else {
        "Needs Attention".to_owned()
    };
    items.push(ListItem::new(Line::from(Span::styled(
        attention_header,
        Style::default().fg(palette::MUTED).bold(),
    ))));
    if report.is_none() {
        // No cached check report: never render the empty-state all-clear.
        // An absent or failed report is unknown, not "nothing to do".
        items.push(ListItem::new(Line::from(Span::styled(
            "check not loaded (press r)",
            Style::default().fg(palette::WARNING),
        ))));
    } else if nudges.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            "Nothing needs attention.",
            Style::default().fg(palette::MUTED),
        ))));
    } else {
        for (index, nudge) in nudges.iter().enumerate() {
            if selected == Some(index) {
                list_selected = Some(items.len());
            }
            items.push(nudge_row(nudge, state.roster.as_ref()));
        }
    }

    items.push(ListItem::new(Line::from(Span::styled(
        format!("People ({})", people.len()),
        Style::default().fg(palette::MUTED).bold(),
    ))));
    if state.roster.is_none() {
        let text = state
            .load_error
            .as_deref()
            .unwrap_or("roster not loaded (press r)");
        items.push(ListItem::new(Line::from(Span::styled(
            text.to_owned(),
            Style::default().fg(palette::WARNING),
        ))));
    } else if people.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            "No people match the filter.",
            Style::default().fg(palette::MUTED),
        ))));
    } else {
        for (index, entry) in people.iter().enumerate() {
            if selected == Some(nudges.len() + index) {
                list_selected = Some(items.len());
            }
            items.push(person_row(entry));
        }
    }

    let mut list_state = ListState::default();
    list_state.select(list_selected);
    frame.render_stateful_widget(
        List::new(items)
            .block(theme::block(" Roster "))
            .highlight_style(Style::default().fg(palette::ACCENT).bold())
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always),
        chunks[1],
        &mut list_state,
    );
}

fn nudge_row<'a>(nudge: &'a Nudge, roster: Option<&Roster>) -> ListItem<'a> {
    let name = person_name(roster, &nudge.person_id).unwrap_or(&nudge.person_id);
    let style = match nudge.severity.as_str() {
        "error" => Style::default().fg(palette::ERROR).bold(),
        "warning" => Style::default().fg(palette::WARNING).bold(),
        _ => Style::default().fg(palette::MUTED),
    };
    ListItem::new(vec![
        Line::from(vec![
            Span::styled(nudge.code.clone(), style),
            Span::raw(" "),
            Span::styled(name.to_owned(), Color::White),
        ]),
        Line::from(Span::styled(
            format!("  {}", nudge.message),
            Style::default().fg(palette::MUTED),
        )),
    ])
}

fn person_row(entry: &RosterEntry) -> ListItem<'_> {
    let mut spans = vec![Span::styled(entry.name.clone(), Color::White)];
    if entry.name != entry.id {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            entry.id.clone(),
            Style::default().fg(palette::MUTED),
        ));
    }
    ListItem::new(Line::from(spans))
}

/// A dim placeholder used by the right pane before a roster is loaded.
pub fn render_empty(frame: &mut Frame<'_>, area: Rect) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "No person selected. Load a roster or choose someone on the left.",
            Style::default().fg(palette::MUTED),
        )))
        .block(theme::block(" Context "))
        .wrap(Wrap { trim: false }),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{Finding, RosterEntry};

    fn roster() -> Roster {
        Roster {
            records: vec![
                RosterEntry {
                    id: "p-01".to_owned(),
                    name: "Ada Example".to_owned(),
                    ..RosterEntry::default()
                },
                RosterEntry {
                    id: "p-02".to_owned(),
                    name: "Bea Demo".to_owned(),
                    ..RosterEntry::default()
                },
            ],
            ..Roster::default()
        }
    }

    #[test]
    fn attention_keeps_only_known_people_and_attention_codes() {
        let report = CheckReport {
            findings: vec![
                Finding {
                    code: "W_DATE_UPCOMING".to_owned(),
                    severity: "warning".to_owned(),
                    id: Some("p-01".to_owned()),
                    message: "birthday soon".to_owned(),
                    ..Finding::default()
                },
                Finding {
                    code: "W_CADENCE_OVERDUE".to_owned(),
                    severity: "warning".to_owned(),
                    id: Some("p-99".to_owned()),
                    message: "hidden person".to_owned(),
                    ..Finding::default()
                },
                Finding {
                    code: "E_MERGE_CONFLICT".to_owned(),
                    severity: "error".to_owned(),
                    id: Some("p-02".to_owned()),
                    message: "not a nudge".to_owned(),
                    ..Finding::default()
                },
            ],
            ..CheckReport::default()
        };
        let nudges = attention(Some(&report), Some(&roster()));
        assert_eq!(nudges.len(), 1);
        assert_eq!(nudges[0].person_id, "p-01");
    }

    #[test]
    fn filter_matches_name_and_id_case_insensitively() {
        let roster = roster();
        assert_eq!(filtered_entries(Some(&roster), "bea").len(), 1);
        assert_eq!(filtered_entries(Some(&roster), "P-01").len(), 1);
        assert_eq!(filtered_entries(Some(&roster), "").len(), 2);
        assert!(filtered_entries(Some(&roster), "zzz").is_empty());
    }
}
