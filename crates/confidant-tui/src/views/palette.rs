//! Command palette (`:` / `Ctrl-P`): fuzzy-filter the TUI's actions and run
//! the selected one with `Enter` (#556 phase 5).
//!
//! The palette is a launcher, not a second implementation of the actions: the
//! app maps an entry id back to the same function a key binding calls. A
//! write entry therefore opens the normal dry-run + `y` confirmation; the
//! palette never writes by itself.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, HighlightSpacing, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::theme;
use crate::theme::palette;

/// One launchable action. `id` is stable (tests and the app dispatch on it);
/// `label` is what the operator reads and filters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: &'static str,
    pub label: &'static str,
    pub group: &'static str,
}

/// The command catalog, in browse order (used verbatim for an empty query).
///
/// Every write-ish entry (`person.new`, `capture.*`, `record.edit`) routes
/// through a flow that previews with `--dry-run` and waits for an explicit
/// `y`. `record.edit` is refused outside People and the Context view, where
/// the operator can see the context it would edit.
pub const ENTRIES: &[Entry] = &[
    Entry {
        id: "workspace.people",
        label: "People & Search workspace",
        group: "Go",
    },
    Entry {
        id: "workspace.review",
        label: "Review Queue workspace",
        group: "Go",
    },
    Entry {
        id: "workspace.check",
        label: "Check workspace",
        group: "Go",
    },
    Entry {
        id: "view.proposals",
        label: "Proposals",
        group: "Go",
    },
    Entry {
        id: "view.conflicts",
        label: "Conflicts",
        group: "Go",
    },
    Entry {
        id: "view.doctor",
        label: "Doctor",
        group: "Go",
    },
    Entry {
        id: "people.filter",
        label: "Filter people",
        group: "People",
    },
    Entry {
        id: "search.query",
        label: "Search (type a query)",
        group: "People",
    },
    Entry {
        id: "search.open",
        label: "Search (open the tab)",
        group: "People",
    },
    Entry {
        id: "person.new",
        label: "New person",
        group: "Write",
    },
    Entry {
        id: "capture.session",
        label: "Log a session",
        group: "Write",
    },
    Entry {
        id: "capture.touch",
        label: "Log a touch",
        group: "Write",
    },
    Entry {
        id: "capture.note",
        label: "Add a note",
        group: "Write",
    },
    Entry {
        id: "record.edit",
        label: "Edit the selected record or note",
        group: "Write",
    },
    Entry {
        id: "operator.toggle",
        label: "Toggle operator mode (no-ai records)",
        group: "App",
    },
    Entry {
        id: "scope",
        label: "Scope",
        group: "App",
    },
    Entry {
        id: "help",
        label: "Help / keymap",
        group: "App",
    },
    Entry {
        id: "refresh",
        label: "Refresh the current view",
        group: "App",
    },
    Entry {
        id: "quit",
        label: "Quit",
        group: "App",
    },
];

/// The palette's input and cursor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PaletteState {
    pub query: String,
    pub selected: usize,
}

impl PaletteState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Entries matching the current query, best score first.
    pub fn matches(&self) -> Vec<&'static Entry> {
        filtered(&self.query)
    }

    /// Add a character and move the cursor to the first match.
    pub fn insert(&mut self, c: char) {
        self.query.push(c);
        self.selected = 0;
    }

    /// Delete the last character and move the cursor to the first match.
    pub fn backspace(&mut self) {
        self.query.pop();
        self.selected = 0;
    }

    /// Move the selection by `delta`, clamped to the current matches.
    pub fn move_by(&mut self, delta: i32) {
        let len = self.matches().len();
        if len == 0 {
            self.selected = 0;
            return;
        }
        self.selected = (self.selected as i32 + delta).clamp(0, len as i32 - 1) as usize;
    }

    /// The entry `Enter` would run, if any.
    pub fn selected_entry(&self) -> Option<&'static Entry> {
        self.matches().get(self.selected).copied()
    }
}

/// Fuzzy-match `query` against `text`: every query character must appear in
/// order (case-insensitively), not necessarily next to each other. Returns a
/// score that rewards contiguous runs; `None` means no match.
pub fn fuzzy_score(query: &str, text: &str) -> Option<i32> {
    let needle: Vec<char> = query
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    if needle.is_empty() {
        return Some(0);
    }
    let mut score = 0i32;
    let mut streak = 0i32;
    let mut next = 0usize;
    for c in text.chars().flat_map(char::to_lowercase) {
        if next < needle.len() && c == needle[next] {
            streak += 1;
            score += 1 + streak * 3;
            next += 1;
        } else {
            streak = 0;
        }
    }
    (next == needle.len()).then_some(score)
}

/// Filter the catalog. Ties stay in browse order so the list is stable for a
/// given query; the id, label, and group are all searchable.
pub fn filtered(query: &str) -> Vec<&'static Entry> {
    let q = query.trim();
    let mut scored: Vec<(i32, usize, &'static Entry)> = ENTRIES
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let score = [
                fuzzy_score(q, entry.label),
                fuzzy_score(q, entry.id),
                fuzzy_score(q, entry.group),
            ]
            .into_iter()
            .flatten()
            .max()?;
            Some((score, index, entry))
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, _, entry)| entry).collect()
}

/// Render the palette as a centered modal over the current view.
pub fn render(state: &PaletteState, frame: &mut Frame<'_>, area: Rect) {
    let matches = state.matches();
    let width = area.width.saturating_sub(8).clamp(40, 72);
    let height = (matches.len() as u16 + 4)
        .clamp(7, 14)
        .min(area.height.saturating_sub(2).max(7));
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let modal = Rect::new(x, y, width, height);

    frame.render_widget(Clear, modal);
    let block = theme::block(" Command Palette ").title_bottom(Line::from(Span::styled(
        " Enter run   Up/Down select   Esc close ",
        theme::muted(),
    )));
    let inner = block.inner(modal);
    frame.render_widget(block, modal);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);

    let input = Line::from(vec![
        Span::styled("> ", Style::default().fg(palette::ACCENT).bold()),
        Span::styled(state.query.clone(), palette::TEXT),
        Span::styled("_", theme::muted()),
    ]);
    frame.render_widget(Paragraph::new(input), rows[0]);

    let items: Vec<ListItem<'_>> = if matches.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "no matching command",
            theme::muted(),
        )))]
    } else {
        matches
            .iter()
            .map(|entry| {
                ListItem::new(Line::from(vec![
                    Span::styled(entry.label, palette::TEXT),
                    Span::raw("  "),
                    Span::styled(entry.group, theme::muted()),
                ]))
            })
            .collect()
    };
    let mut list_state = ListState::default();
    list_state.select((!matches.is_empty()).then_some(state.selected));
    frame.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default().fg(palette::ACCENT).bold())
            .highlight_symbol("› ")
            .highlight_spacing(HighlightSpacing::Always),
        rows[2],
        &mut list_state,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzzy_matches_subsequences_case_insensitively() {
        assert!(fuzzy_score("note", "Add a note").is_some());
        assert!(fuzzy_score("note", "Add a NOTE").is_some());
        assert!(fuzzy_score("tgop", "Toggle operator mode").is_some());
        assert!(fuzzy_score("xyz", "Add a note").is_none());
        assert_eq!(fuzzy_score("", "anything"), Some(0));
    }

    #[test]
    fn empty_query_keeps_catalog_order_and_ids_are_unique() {
        let all = filtered("");
        assert_eq!(all.len(), ENTRIES.len());
        assert_eq!(all[0].id, "workspace.people");
        let mut ids: Vec<&str> = ENTRIES.iter().map(|entry| entry.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), ENTRIES.len(), "catalog ids are unique");
    }

    #[test]
    fn filtering_finds_by_label_id_and_group() {
        let labels: Vec<&str> = filtered("session").iter().map(|entry| entry.id).collect();
        assert!(labels.contains(&"capture.session"));

        let ids: Vec<&str> = filtered("view.conflicts")
            .iter()
            .map(|entry| entry.id)
            .collect();
        assert_eq!(ids.first(), Some(&"view.conflicts"));

        let groups: Vec<&str> = filtered("write").iter().map(|entry| entry.id).collect();
        assert!(groups.contains(&"capture.note"));
        assert!(groups.contains(&"record.edit"));
    }

    #[test]
    fn selection_clamps_and_backspace_resets_it() {
        let mut state = PaletteState::new();
        state.insert('s');
        state.move_by(100);
        assert!(state.selected < state.matches().len());
        assert!(state.selected_entry().is_some());
        state.backspace();
        assert_eq!(state.query, "");
        assert_eq!(state.selected, 0);
    }
}
