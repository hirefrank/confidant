//! Alert view for CLI errors, usage errors, non-JSON output, and blocking
//! contract version mismatches.

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::ErrorBody;
use crate::theme;
use crate::theme::palette;

/// State for an alert modal or blocking screen.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AlertState {
    pub title: String,
    pub code: Option<String>,
    pub message: String,
    pub fix: Option<String>,
    pub blocking: bool,
    /// The raw CLI text behind a one-line alert, when the CLI produced
    /// something worth keeping but too noisy to show first (#591). Reachable
    /// with `x`: the app opens it in the info modal. `None` for alerts with
    /// nothing extra to show.
    pub raw: Option<String>,
}

/// Extract the subcommand name clap named as unrecognized/unknown in a usage
/// message, if any.
///
/// The TUI only ever invokes fixed subcommands, so an "unrecognized
/// subcommand" usage error means the `confidant` on `PATH` predates this TUI
/// (#591). Both clap v4 (`unrecognized subcommand 'list'`) and clap v3
/// (`The subcommand 'list' wasn't recognized`) spellings are matched.
pub fn unknown_subcommand(message: &str) -> Option<String> {
    for needle in [
        "unrecognized subcommand '",
        "unknown subcommand '",
        "subcommand '",
    ] {
        if let Some((_, rest)) = message.split_once(needle) {
            if let Some(end) = rest.find('\'') {
                let name = rest[..end].trim();
                if !name.is_empty() {
                    return Some(name.to_owned());
                }
            }
        }
    }
    None
}

impl AlertState {
    /// Blocking alert shown when `schema_version != "1"`.
    pub fn version_mismatch(reported_version: &str) -> Self {
        Self {
            title: "Contract Version Mismatch".to_owned(),
            code: Some("schema_version_mismatch".to_owned()),
            message: format!("TUI built for agent contract v1; CLI reports v{reported_version}"),
            fix: Some("Install matching versions of confidant and confidant-tui".to_owned()),
            blocking: true,
            raw: None,
        }
    }

    /// Alert built from a CLI error envelope or exit code 2 usage failure.
    pub fn from_cli_error(status: i32, usage_error: bool, err: &ErrorBody) -> Self {
        if usage_error {
            let code = if err.code.is_empty() {
                "usage_error".to_owned()
            } else {
                err.code.clone()
            };
            let message = if err.message.to_ascii_lowercase().contains("usage error") {
                err.message.clone()
            } else if err.message.is_empty() {
                "usage error".to_owned()
            } else {
                format!("usage error: {}", err.message)
            };
            Self {
                title: "Usage Error (exit 2)".to_owned(),
                code: Some(code),
                message,
                fix: err.fix.clone(),
                blocking: false,
                raw: None,
            }
        } else {
            Self {
                title: format!("CLI Error (exit {status})"),
                code: (!err.code.is_empty()).then(|| err.code.clone()),
                message: err.message.clone(),
                fix: err.fix.clone(),
                blocking: false,
                raw: None,
            }
        }
    }

    /// Alert shown when the resolved `confidant` rejects a subcommand this TUI
    /// knows about: the binary is older than the TUI (ADR-7 skew, #591). The
    /// raw clap output stays reachable with `x` rather than being the first
    /// thing on screen.
    pub fn cli_version_skew(bin: &str, subcommand: &str, raw: &str) -> Self {
        Self {
            title: "CLI Version Skew".to_owned(),
            code: Some("old_cli".to_owned()),
            message: format!(
                "the confidant at {bin} does not support `{subcommand}` — it is older than this TUI"
            ),
            fix: Some(
                "set CONFIDANT_BIN (or --confidant) to a newer binary, or reinstall the confidant CLI"
                    .to_owned(),
            ),
            blocking: false,
            raw: Some(raw.to_owned()),
        }
    }

    /// Alert shown when CLI stdout is not valid JSON.
    pub fn invalid_json(status: i32) -> Self {
        Self {
            title: format!("Invalid CLI Output (exit {status})"),
            code: Some("invalid_json".to_owned()),
            message: "CLI output on stdout was not valid JSON".to_owned(),
            fix: Some("Verify that the confidant binary supports --json --no-input".to_owned()),
            blocking: false,
            raw: None,
        }
    }

    /// Alert shown when spawning the CLI process fails.
    pub fn runner_error(detail: &str) -> Self {
        Self {
            title: "CLI Execution Failed".to_owned(),
            code: Some("runner_error".to_owned()),
            message: detail.to_owned(),
            fix: Some("Pass --confidant <path> or set CONFIDANT_BIN".to_owned()),
            blocking: false,
            raw: None,
        }
    }
}

/// Pure renderer for an alert screen/panel.
pub fn render(state: &AlertState, frame: &mut Frame<'_>, area: Rect) {
    let title_style = if state.blocking {
        Style::default().fg(palette::ERROR).bold()
    } else {
        Style::default().fg(palette::WARNING).bold()
    };

    let mut lines = Vec::new();
    if let Some(code) = &state.code {
        lines.push(Line::from(vec![
            theme::label("code    "),
            Span::styled(code.clone(), theme::muted()),
        ]));
    }
    lines.push(Line::from(vec![
        theme::label("message "),
        Span::styled(state.message.clone(), palette::TEXT),
    ]));
    if let Some(fix) = &state.fix {
        lines.push(Line::from(vec![
            theme::label("fix     "),
            Span::styled(fix.clone(), Style::default().fg(palette::SUCCESS)),
        ]));
    }
    lines.push(Line::from(""));
    if state.blocking {
        lines.push(Line::from(Span::styled(
            "Blocking alert: press q or Esc to exit.",
            Style::default().fg(palette::ERROR),
        )));
    } else {
        let hint = if state.raw.is_some() {
            "Press x for the raw CLI output, Esc to dismiss, r to retry, or q to quit."
        } else {
            "Press Esc to dismiss, r to retry, or q to quit."
        };
        lines.push(Line::from(Span::styled(hint, theme::muted())));
    }

    let block = theme::block("").title(Span::styled(format!(" {} ", state.title), title_style));
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_subcommand_extracts_both_clap_spellings() {
        // clap v4.
        assert_eq!(
            unknown_subcommand("error: unrecognized subcommand 'list'\n\nUsage: ..."),
            Some("list".to_owned())
        );
        // clap v3.
        assert_eq!(
            unknown_subcommand("error: The subcommand 'record list' wasn't recognized"),
            Some("record list".to_owned())
        );
        // A usage error that names no subcommand is not skew.
        assert_eq!(unknown_subcommand("find requires a non-empty query"), None);
        assert_eq!(
            unknown_subcommand("usage error (CLI exited with code 2)"),
            None
        );
    }

    #[test]
    fn cli_version_skew_names_path_and_subcommand_and_keeps_raw() {
        let alert = AlertState::cli_version_skew("/tmp/fake-confidant", "list", "raw help text");
        assert_eq!(alert.title, "CLI Version Skew");
        assert_eq!(alert.code.as_deref(), Some("old_cli"));
        assert!(alert.message.contains("/tmp/fake-confidant"));
        assert!(alert.message.contains("`list`"));
        assert_eq!(alert.raw.as_deref(), Some("raw help text"));
        assert!(!alert.blocking);
    }
}
