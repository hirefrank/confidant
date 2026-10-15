//! Semantic theme for `confidant-tui`: palette, blocks, pills, and badges.
//!
//! Styling only — no business logic. Every view builds its text from these
//! helpers so labels, values, and statuses look consistent.

use ratatui::style::{Color, Style, Stylize};
use ratatui::text::Span;
use ratatui::widgets::{Block, BorderType, Padding};

/// Semantic palette: accent for the active tab, green/yellow/red for
/// success/warning/error, dark gray for muted labels and inactive borders.
pub mod palette {
    use ratatui::style::Color;

    pub const ACCENT: Color = Color::Cyan;
    pub const SUCCESS: Color = Color::Green;
    pub const WARNING: Color = Color::Yellow;
    pub const ERROR: Color = Color::Red;
    pub const MUTED: Color = Color::DarkGray;
}

fn muted() -> Style {
    Style::default().fg(palette::MUTED)
}

/// A bordered content block: rounded corners, horizontal padding so text
/// never touches the vertical borders, muted border color, dim title.
pub fn block(title: &str) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(muted())
        .padding(Padding::horizontal(1))
        .title(Span::styled(title, muted()))
}

/// A navigation tab pill. The active tab is a solid cyan badge; inactive
/// tabs are plain gray text.
pub fn tab_pill(label: &str, active: bool) -> Span<'static> {
    let text = format!(" {label} ");
    if active {
        Span::styled(
            text,
            Style::default().fg(Color::Black).bg(palette::ACCENT).bold(),
        )
    } else {
        text.gray()
    }
}

/// A key badge for the footer bar: dark badge, black key name.
pub fn key_badge(key: &str) -> Span<'_> {
    Span::styled(
        format!(" {key} "),
        Style::default().fg(Color::Black).bg(Color::DarkGray),
    )
}

/// The action label next to a [`key_badge`]: dim text.
pub fn key_hint(label: &str) -> Span<'_> {
    Span::styled(format!(" {label} "), muted())
}

/// A status badge: ` OK ` on green, ` FAILED ` on red.
pub fn status_badge(ok: bool) -> Span<'static> {
    if ok {
        Span::styled(
            " OK ",
            Style::default()
                .fg(Color::Black)
                .bg(palette::SUCCESS)
                .bold(),
        )
    } else {
        Span::styled(
            " FAILED ",
            Style::default().fg(Color::Black).bg(palette::ERROR).bold(),
        )
    }
}

/// A severity tag like `[warning]`, colored by severity.
pub fn severity_tag(severity: &str) -> Span<'_> {
    let style = match severity {
        "error" => Style::default().fg(palette::ERROR).bold(),
        "warning" => Style::default().fg(palette::WARNING).bold(),
        _ => muted(),
    };
    Span::styled(format!("[{severity}]"), style)
}

/// A dim label span, e.g. the `spec` in `spec 0.1`.
pub fn label(text: &str) -> Span<'_> {
    Span::styled(text, muted())
}

/// A `label value` pair: dim label, caller-styled value.
pub fn labeled<'a>(label_text: &'a str, value: Span<'a>) -> Vec<Span<'a>> {
    vec![label(label_text), value]
}

/// A count that is dim at zero and `nonzero_style` otherwise.
pub fn count<'a>(label_text: &'a str, n: usize, nonzero: Style) -> Vec<Span<'a>> {
    let value = if n == 0 {
        Span::styled(n.to_string(), muted())
    } else {
        Span::styled(n.to_string(), nonzero)
    };
    vec![label(label_text), value]
}
