//! Read-only TUI for Confidant (`confidant-tui`), consuming the ADR-7 CLI
//! JSON contract (`confidant <subcommand> --json --no-input`).

#![forbid(unsafe_code)]

use std::io::{self, Write};

pub mod app;
pub mod contract;
pub mod runner;
pub mod views;

/// Write the terminal teardown escape sequence (clear alternate buffer, reset
/// cursor, show cursor, and leave alternate screen) to `writer`.
pub fn write_restore_sequence<W: Write>(writer: &mut W) -> io::Result<()> {
    crossterm::execute!(
        writer,
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        crossterm::cursor::MoveTo(0, 0),
        crossterm::cursor::Show,
        crossterm::terminal::LeaveAlternateScreen
    )
}

/// Clear the alternate screen buffer, leave the alternate screen, and disable
/// raw mode. Safe to call multiple times, including from a panic hook.
pub fn restore_terminal() {
    let mut stdout = io::stdout();
    let _ = write_restore_sequence(&mut stdout);
    let _ = stdout.flush();
    let _ = crossterm::terminal::disable_raw_mode();
}

/// Execute a terminal-restore callback inside a panic hook before delegating.
/// Exposed for unit testing the panic-hook restore behavior directly.
pub fn run_panic_restore_hook<F>(restore: F)
where
    F: FnOnce(),
{
    restore();
}

/// Install a panic hook that clears the buffer and leaves the alternate screen
/// before invoking the previous panic hook.
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        run_panic_restore_hook(restore_terminal);
        prev(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn restore_sequence_clears_and_leaves_alternate_screen() {
        let mut buf: Vec<u8> = Vec::new();
        write_restore_sequence(&mut buf).expect("write restore sequence");
        let text = String::from_utf8_lossy(&buf);
        // ANSI Clear All (\x1b[2J) and LeaveAlternateScreen (\x1b[?1049l).
        assert!(
            text.contains("\x1b[2J"),
            "expected screen clear in {text:?}"
        );
        assert!(
            text.contains("\x1b[?1049l"),
            "expected LeaveAlternateScreen in {text:?}"
        );
    }

    #[test]
    fn panic_restore_hook_invokes_restore_on_panic() {
        let restored = Arc::new(AtomicBool::new(false));
        let restored_clone = Arc::clone(&restored);
        let mut output: Vec<u8> = Vec::new();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_panic_restore_hook(|| {
                write_restore_sequence(&mut output).expect("write restore sequence");
                restored_clone.store(true, Ordering::SeqCst);
            });
            panic!("simulated TUI panic");
        }));

        assert!(result.is_err());
        assert!(restored.load(Ordering::SeqCst));
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("\x1b[2J"));
        assert!(text.contains("\x1b[?1049l"));
    }
}
