//! Alert view for CLI errors, usage errors, non-JSON output, and blocking
//! contract version mismatches.

use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

use crate::contract::ErrorBody;

/// State for an alert modal or blocking screen.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AlertState {
    pub title: String,
    pub code: Option<String>,
    pub message: String,
    pub fix: Option<String>,
    pub blocking: bool,
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
            }
        } else {
            Self {
                title: format!("CLI Error (exit {status})"),
                code: (!err.code.is_empty()).then(|| err.code.clone()),
                message: err.message.clone(),
                fix: err.fix.clone(),
                blocking: false,
            }
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
        }
    }
}

/// Pure renderer for an alert screen/panel.
pub fn render(state: &AlertState, frame: &mut Frame<'_>, area: Rect) {
    let mut lines = Vec::new();
    if let Some(code) = &state.code {
        lines.push(Line::from(format!("code: {code}")));
    }
    lines.push(Line::from(format!("message: {}", state.message)));
    if let Some(fix) = &state.fix {
        lines.push(Line::from(format!("fix: {fix}")));
    }
    lines.push(Line::from(""));
    if state.blocking {
        lines.push(Line::from("Blocking alert: press q or Esc to exit."));
    } else {
        lines.push(Line::from(
            "Press Esc to dismiss, r to retry, or q to quit.",
        ));
    }

    let block = Block::bordered().title(format!(" {} ", state.title));
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}
