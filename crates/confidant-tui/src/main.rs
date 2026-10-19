//! Entry point for `confidant-tui`.

#![forbid(unsafe_code)]

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, Event};
use crossterm::terminal::{enable_raw_mode, EnterAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use confidant_tui::app::App;
use confidant_tui::runner::ProcessRunner;
use confidant_tui::{install_panic_hook, restore_terminal};

/// Terminal UI for Confidant (contract v1): read-only views plus
/// confirm-before-apply proposal review.
#[derive(Debug, Parser)]
#[command(name = "confidant-tui", version, about)]
struct Cli {
    /// Path to the vault directory (forwarded as `--vault` to `confidant`).
    /// Falls back to the `CONFIDANT_VAULT` environment variable.
    #[arg(long, env = "CONFIDANT_VAULT")]
    vault: Option<PathBuf>,

    /// Path to the `confidant` binary (defaults to `CONFIDANT_BIN` or `confidant` on PATH).
    #[arg(long = "confidant", visible_alias = "bin", env = "CONFIDANT_BIN")]
    confidant: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let bin = ProcessRunner::resolve_bin(cli.confidant);
    let runner = ProcessRunner::new(bin, cli.vault.clone());

    install_panic_hook();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(err) = crossterm::execute!(stdout, EnterAlternateScreen) {
        let _ = crossterm::terminal::disable_raw_mode();
        return Err(err.into());
    }

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(err) => {
            restore_terminal();
            return Err(err.into());
        }
    };

    let run_result = run_event_loop(&mut terminal, runner, cli.vault);
    let _ = terminal.clear();
    restore_terminal();
    run_result
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    runner: ProcessRunner,
    vault: Option<PathBuf>,
) -> Result<()> {
    let mut app = App::new(runner);
    if let Some(vault) = vault {
        app.set_vault_root(vault);
    }
    app.load_check();
    app.load_roster();

    loop {
        terminal.draw(|frame| app.render(frame))?;
        if app.should_quit {
            break;
        }
        // Hand-merge (#456): the operator confirmed `record resolve --edit`.
        // Suspend the alternate screen so the CLI gets a real terminal for
        // the editor, run it, then resume and refresh.
        if let Some(cmd) = app.take_suspended_command() {
            restore_terminal();
            let result = app.run_suspended_command(&cmd);
            enable_raw_mode()?;
            if let Err(err) = crossterm::execute!(io::stdout(), EnterAlternateScreen) {
                let _ = crossterm::terminal::disable_raw_mode();
                return Err(err.into());
            }
            terminal.clear()?;
            app.after_suspended_command(result);
            continue;
        }
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes env-var manipulation: `CONFIDANT_VAULT` is process-wide.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_vault_env(value: Option<&str>, f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = std::env::var_os("CONFIDANT_VAULT");
        match value {
            Some(v) => std::env::set_var("CONFIDANT_VAULT", v),
            None => std::env::remove_var("CONFIDANT_VAULT"),
        }
        f();
        match old {
            Some(v) => std::env::set_var("CONFIDANT_VAULT", v),
            None => std::env::remove_var("CONFIDANT_VAULT"),
        }
    }

    #[test]
    fn vault_falls_back_to_confidant_vault_env() {
        with_vault_env(Some("/tmp/fake-vault"), || {
            let cli = Cli::try_parse_from(["confidant-tui"]).expect("parse succeeds");
            assert_eq!(cli.vault, Some(PathBuf::from("/tmp/fake-vault")));
        });
    }

    #[test]
    fn vault_flag_beats_confidant_vault_env() {
        with_vault_env(Some("/tmp/env-vault"), || {
            let cli = Cli::try_parse_from(["confidant-tui", "--vault", "/tmp/flag-vault"])
                .expect("parse succeeds");
            assert_eq!(cli.vault, Some(PathBuf::from("/tmp/flag-vault")));
        });
    }

    #[test]
    fn vault_is_none_without_flag_or_env() {
        with_vault_env(None, || {
            let cli = Cli::try_parse_from(["confidant-tui"]).expect("parse succeeds");
            assert_eq!(cli.vault, None);
        });
    }
}
