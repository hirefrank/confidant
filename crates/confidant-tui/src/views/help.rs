//! The `?` help modal's content: a grouped keymap reference (#556 phase 5).
//!
//! Kept as plain lines so the read-only [`crate::views::info`] modal can
//! render it; the groups cover every workspace, the operator (`!`), the
//! context-item selection (`[`/`]`), the write confirmations (`y`), and the
//! command palette (`:` / `Ctrl-P`).

/// Maximum line width the info modal renders without wrapping at the
/// standard 100-column test size (80-column modal, borders + padding).
pub const MAX_LINE_WIDTH: usize = 74;

/// Build the keymap, including the current operator-mode state.
pub fn lines(operator_mode: bool) -> Vec<String> {
    let operator = if operator_mode {
        "  ! operator mode is ON: no-ai records are included (--for-operator)"
    } else {
        "  ! operator mode: off; press ! to include no-ai records"
    };
    let lines = vec![
        "Workspaces".to_owned(),
        "  1 People & Search   2 Review Queue   3 Check   Tab/Shift-Tab cycles".to_owned(),
        "People & Search".to_owned(),
        "  list: j/k move   g/G first/last   / filter   Enter open".to_owned(),
        "  f search   s/t/n session/touch/note   a new person".to_owned(),
        "  s/t/n pre-fill the selected person; a composes a fresh one".to_owned(),
        "  context: j/k scroll   g top   [ / ] select the context item   e edit it".to_owned(),
        "Review Queue".to_owned(),
        "  o Proposals   i Inbox   c Conflicts   r refresh   Enter open/detail".to_owned(),
        "  Inbox: a apply (dry run, then y)   Conflicts: o/t take a side, m merge".to_owned(),
        "Check".to_owned(),
        "  3 Check   d Doctor   r refresh   x raw CLI output (from an alert)".to_owned(),
        "Anywhere".to_owned(),
        "  : or Ctrl-P palette   p scope   ? help   q quit".to_owned(),
        "  palette: type to filter, Up/Down select, Enter runs, Esc closes".to_owned(),
        operator.to_owned(),
        "  Enter never writes; y confirms after a preview (--dry-run/both sides)".to_owned(),
        "  Esc clears a filter or goes back; at the People home it does not quit".to_owned(),
    ];
    debug_assert!(
        lines
            .iter()
            .all(|line| line.chars().count() <= MAX_LINE_WIDTH),
        "help lines must not wrap in the standard modal"
    );
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keymap_covers_every_group_and_the_phase_one_to_four_keys() {
        let help = lines(false).join("\n");
        for group in [
            "Workspaces",
            "People & Search",
            "Review Queue",
            "Check",
            "Anywhere",
        ] {
            assert!(help.contains(group), "missing group {group}");
        }
        for needle in [
            "1 People & Search",
            "j/k move",
            "g/G first/last",
            "Tab/Shift-Tab",
            "/ filter",
            "p scope",
            "? help",
            "s/t/n session",
            "a new person",
            "o Proposals",
            "i Inbox",
            "c Conflicts",
            "d Doctor",
            "[ / ]",
            "e edit",
            "! operator mode",
            "y confirms",
            ": or Ctrl-P palette",
            "Up/Down select",
        ] {
            assert!(help.contains(needle), "missing {needle:?} in:\n{help}");
        }
    }

    #[test]
    fn operator_mode_state_is_named_in_the_help() {
        assert!(lines(true).join("\n").contains("operator mode is ON"));
        assert!(lines(false).join("\n").contains("operator mode: off"));
    }
}
