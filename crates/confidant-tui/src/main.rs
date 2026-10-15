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
    #[arg(long)]
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

    loop {
        terminal.draw(|frame| app.render(frame))?;
        if app.should_quit {
            break;
        }
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }
    }
    Ok(())
}
