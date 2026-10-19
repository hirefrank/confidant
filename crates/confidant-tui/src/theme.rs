//! Semantic theme for `confidant-tui`: palette, blocks, pills, and badges.
//!
//! Styling only — no business logic. Every view builds its text from these
//! helpers so labels, values, and statuses look consistent.
//!
//! # Contrast
//!
//! The palette is fixed in RGB rather than left to the terminal's ANSI
//! colours, because ANSI "bright black"/"bright white" are near-invisible on
//! one of the two background families (#556 phase 4). Primary text uses
//! [`palette::TEXT`] (`Color::Reset`), so it follows the terminal's own
//! foreground and is legible on both dark and light themes. Secondary text
//! ([`palette::MUTED`]) is a mid-gray with at least 3.5:1 against white, a
//! solarized-light background, and `#1e1e1e`; semantic colours stay above
//! 3:1 on all three. Tinted pills and badges put [`palette::INK`] on a fixed
//! background, all of which clear 4.5:1. The ratios are asserted in the
//! tests below so a future palette edit cannot silently regress them.

use ratatui::style::{Color, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, BorderType, Padding};

/// Semantic palette: accent for the active tab, green/amber/red for
/// success/warning/error, and a mid-gray for muted labels and metadata.
pub mod palette {
    use ratatui::style::Color;

    /// Primary body text: the terminal's default foreground. `Color::White`
    /// is *bright* white and disappears on a light theme; reset follows the
    /// user's theme instead.
    pub const TEXT: Color = Color::Reset;
    /// Secondary text: labels, metadata, footer hints, disabled rows. A
    /// fixed mid-gray (~4.0:1 on white, ~4.2:1 on `#1e1e1e`) that is clearly
    /// quieter than [`TEXT`] without vanishing.
    pub const MUTED: Color = Color::Rgb(0x7f, 0x7f, 0x7f);
    /// Accent for the active tab, cursors, and links. Teal reads as cyan on
    /// a dark theme and stays readable as a foreground on a light one.
    pub const ACCENT: Color = Color::Rgb(0x0f, 0x8b, 0x8b);
    pub const SUCCESS: Color = Color::Rgb(0x2e, 0x8b, 0x57);
    pub const WARNING: Color = Color::Rgb(0xa8, 0x7d, 0x00);
    pub const ERROR: Color = Color::Rgb(0xd0, 0x50, 0x50);
    /// Background of a neutral value pill (paired with [`INK`]).
    pub const PILL_BG: Color = Color::Rgb(0xc8, 0xc8, 0xc8);
    /// Text on a tinted pill/badge/key. Every tint in this module clears
    /// 4.5:1 against black.
    pub const INK: Color = Color::Black;
}

/// The severity/status tone of a pill. Neutral is the plain gray value pill;
/// the others carry a semantic tint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Ok,
    Warn,
    Error,
}

impl Tone {
    fn background(self) -> Color {
        match self {
            Tone::Neutral => palette::PILL_BG,
            Tone::Ok => palette::SUCCESS,
            Tone::Warn => palette::WARNING,
            Tone::Error => palette::ERROR,
        }
    }
}

/// Secondary text style: labels, metadata, hints.
pub fn muted() -> Style {
    Style::default().fg(palette::MUTED)
}

/// Primary text style: follows the terminal's foreground so it stays legible
/// on both dark and light themes.
pub fn text() -> Style {
    Style::default().fg(palette::TEXT)
}

/// A bordered content block: rounded corners, horizontal padding so text
/// never touches the vertical borders, muted border color, muted title.
pub fn block(title: &str) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(muted())
        .padding(Padding::horizontal(1))
        .title(Span::styled(title, muted()))
}

/// A navigation tab pill. The active tab is a solid accent badge; inactive
/// tabs are muted text (not ANSI light gray, which disappears on a light
/// theme).
pub fn tab_pill(label: &str, active: bool) -> Span<'static> {
    let text = format!(" {label} ");
    if active {
        Span::styled(
            text,
            Style::default().fg(palette::INK).bg(palette::ACCENT).bold(),
        )
    } else {
        Span::styled(text, muted())
    }
}

/// A key badge for the footer bar: mid-gray badge, black key name.
pub fn key_badge(key: &str) -> Span<'_> {
    Span::styled(
        format!(" {key} "),
        Style::default().fg(palette::INK).bg(palette::MUTED),
    )
}

/// A compact value pill, e.g. a front-matter value (`p-…`, a scope name).
/// Light-gray background, black text.
pub fn pill(text: &str) -> Span<'static> {
    Span::styled(
        format!(" {text} "),
        Style::default().fg(palette::INK).bg(palette::PILL_BG),
    )
}

/// A status pill: the same shape as [`pill`], tinted by [`Tone`] so
/// `doctor ok`, `2 warning(s)`, and an error count read differently at a
/// glance instead of all rendering as identical gray blocks.
pub fn tone_pill(text: &str, tone: Tone) -> Span<'static> {
    let style = Style::default().fg(palette::INK).bg(tone.background());
    let style = if tone == Tone::Neutral {
        style
    } else {
        style.bold()
    };
    Span::styled(format!(" {text} "), style)
}

/// The action label next to a [`key_badge`]: muted text.
pub fn key_hint(label: &str) -> Span<'_> {
    Span::styled(format!(" {label} "), muted())
}

/// A status badge: ` OK ` on green, ` FAILED ` on red.
pub fn status_badge(ok: bool) -> Span<'static> {
    if ok {
        Span::styled(
            " OK ",
            Style::default()
                .fg(palette::INK)
                .bg(palette::SUCCESS)
                .bold(),
        )
    } else {
        Span::styled(
            " FAILED ",
            Style::default().fg(palette::INK).bg(palette::ERROR).bold(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The light and dark terminal backgrounds the palette is tuned against:
    /// pure white, solarized light, and a common near-black dark theme.
    const LIGHT: [(u8, u8, u8); 2] = [(0xff, 0xff, 0xff), (0xfd, 0xf6, 0xe3)];
    const DARK: (u8, u8, u8) = (0x1e, 0x1e, 0x1e);

    fn rgb(color: Color) -> (u8, u8, u8) {
        match color {
            Color::Rgb(r, g, b) => (r, g, b),
            Color::Black => (0, 0, 0),
            other => panic!("palette test needs an RGB colour, got {other:?}"),
        }
    }

    fn channel_luminance(value: u8) -> f64 {
        let c = f64::from(value) / 255.0;
        if c <= 0.040_45 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    }

    fn luminance(color: (u8, u8, u8)) -> f64 {
        0.2126 * channel_luminance(color.0)
            + 0.7152 * channel_luminance(color.1)
            + 0.0722 * channel_luminance(color.2)
    }

    fn contrast(a: (u8, u8, u8), b: (u8, u8, u8)) -> f64 {
        let (la, lb) = (luminance(a), luminance(b));
        let (hi, lo) = (la.max(lb), la.min(lb));
        (hi + 0.05) / (lo + 0.05)
    }

    /// Muted text has to beat 3.5:1 on both background families; at the old
    /// `DarkGray` it was ~2:1 on dark themes, which is the epic's original
    /// "near-invisible" complaint.
    #[test]
    fn muted_text_is_legible_on_dark_and_light_backgrounds() {
        let muted = rgb(palette::MUTED);
        for light in LIGHT {
            assert!(
                contrast(muted, light) >= 3.5,
                "muted on {light:?}: {:.2}",
                contrast(muted, light)
            );
        }
        assert!(
            contrast(muted, DARK) >= 3.5,
            "muted on dark: {:.2}",
            contrast(muted, DARK)
        );
    }

    /// Accent and status foregrounds need at least AA-large contrast (3:1)
    /// on every supported background. ANSI yellow/green failed this on a
    /// light theme.
    #[test]
    fn semantic_foregrounds_are_legible_on_both_backgrounds() {
        for color in [
            palette::ACCENT,
            palette::SUCCESS,
            palette::WARNING,
            palette::ERROR,
            palette::MUTED,
        ] {
            let color = rgb(color);
            for background in LIGHT.into_iter().chain([DARK]) {
                assert!(
                    contrast(color, background) >= 3.0,
                    "{color:?} on {background:?}: {:.2}",
                    contrast(color, background)
                );
            }
        }
    }

    /// Pills and badges draw black ink on a tint; every tint must keep that
    /// text readable (AA normal).
    #[test]
    fn badge_ink_clears_aa_on_every_tint() {
        for tint in [
            palette::ACCENT,
            palette::SUCCESS,
            palette::WARNING,
            palette::ERROR,
        ] {
            let ratio = contrast(rgb(palette::INK), rgb(tint));
            assert!(ratio >= 4.5, "ink on {tint:?}: {ratio:.2}");
        }
        let neutral = contrast(rgb(palette::INK), rgb(palette::PILL_BG));
        assert!(neutral >= 4.5, "ink on pill: {neutral:.2}");
    }

    /// Primary text must stay theme-relative: bright white is invisible on a
    /// light terminal.
    #[test]
    fn primary_text_follows_the_terminal_foreground() {
        assert_eq!(palette::TEXT, Color::Reset);
        assert_ne!(palette::TEXT, Color::White);
    }

    #[test]
    fn tone_pills_use_semantic_backgrounds() {
        let bg = |text: &str| match tone_pill(text, Tone::Ok).style.bg {
            Some(color) => color,
            None => panic!("tone pill has a background"),
        };
        assert_eq!(bg(" ok "), palette::SUCCESS);
        assert_eq!(
            tone_pill("warn", Tone::Warn).style.bg,
            Some(palette::WARNING)
        );
        assert_eq!(
            tone_pill("error", Tone::Error).style.bg,
            Some(palette::ERROR)
        );
        assert_eq!(
            tone_pill("not run", Tone::Neutral).style.bg,
            Some(palette::PILL_BG)
        );
    }
}
