//! `agents`, `which`, `routing`, and `tui`.

use std::path::Path;
use std::process::ExitCode;

use crate::commands::doctor::tui_binary_version;
use crate::commands::shared::find_on_path;
use crate::{ok_envelope, print_json, setup, vault_json, Cli};
use serde_json::Value;

pub(crate) fn cmd_agents(cli: &Cli, _verbose: bool) -> anyhow::Result<ExitCode> {
    let home = setup::home_dir()?;
    let health = setup::agents_health(&home);
    if cli.json {
        let agents: Vec<Value> = health
            .iter()
            .map(|h| {
                serde_json::json!({
                    "name": h.name,
                    "path": h.dir.display().to_string(),
                    "detected": h.detected,
                    "linked": h.linked,
                    "total": h.total,
                })
            })
            .collect();
        print_json(&ok_envelope(None, serde_json::json!({"agents": agents})))?;
    } else {
        // #652: always show the full table, including before `setup` has run.
        println!("{:<14} {:<9} {:<7} PATH", "AGENT", "DETECTED", "LINKED");
        let mut any_linked = false;
        for h in &health {
            any_linked |= h.linked > 0;
            println!(
                "{:<14} {:<9} {:<7} {}",
                h.name,
                if h.detected { "yes" } else { "no" },
                format!("{}/{}", h.linked, h.total),
                h.dir.display()
            );
        }
        if !any_linked {
            println!();
            println!(
                "No skills linked yet. Run `confidant setup --agent <name>` or `confidant setup --agent auto`."
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_which(cli: &Cli, skills_dir_only: bool) -> anyhow::Result<ExitCode> {
    let home = setup::confidant_home()?;
    let skills_dir = setup::skills_version_dir()?;
    let version = env!("CARGO_PKG_VERSION").to_owned();
    if skills_dir_only && !cli.json {
        println!("{}", skills_dir.display());
        return Ok(ExitCode::SUCCESS);
    }
    if cli.json {
        print_json(&ok_envelope(
            None,
            serde_json::json!({
                "skills_dir": skills_dir.display().to_string(),
                "home": home.display().to_string(),
                "version": version,
            }),
        ))?;
    } else {
        println!("skills_dir={}", skills_dir.display());
        println!("home={}", home.display());
        println!("version={version}");
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_routing(cli: &Cli, vault: Option<&Path>) -> anyhow::Result<ExitCode> {
    let text = setup::system_of_record_text(vault.or(cli.vault.as_deref()));
    if cli.json {
        print_json(&ok_envelope(vault, serde_json::json!({"snippet": text})))?;
    } else {
        print!("{text}");
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_tui(cli: &Cli, args: &[String]) -> anyhow::Result<ExitCode> {
    const HINT: &str =
        "confidant-tui not found on PATH; install it with: cargo install confidant-tui";
    let bin = match find_on_path("confidant-tui") {
        Some(path) => path,
        None => {
            if cli.json {
                print_json(&serde_json::json!({
                    "ok": false,
                    "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
                    "vault": vault_json(None),
                    "error": {"code": "E_TUI_NOT_FOUND", "message": HINT},
                }))?;
            } else {
                eprintln!("{HINT}");
            }
            return Ok(ExitCode::from(1));
        }
    };
    // #659: a CLI-only upgrade leaves `confidant-tui` on the old release,
    // and the TUI then speaks an older ADR-7 contract. Warn but keep
    // launching: mixing versions is sometimes intentional, and refusing
    // would break working installs.
    let cli_version = env!("CARGO_PKG_VERSION");
    let tui_version = tui_binary_version(&bin);
    let version_mismatch = tui_version
        .as_deref()
        .map(|v| v != cli_version)
        .unwrap_or(false);
    if cli.json {
        // Probe-only: the TUI owns stdout and would corrupt the ADR-7
        // envelope. Report what would launch and leave launching to a
        // human-mode invocation.
        print_json(&ok_envelope(
            cli.vault.as_deref(),
            serde_json::json!({
                "tui_version": tui_version,
                "version_mismatch": version_mismatch,
                "would_launch": true,
            }),
        ))?;
        return Ok(ExitCode::SUCCESS);
    }
    if version_mismatch {
        eprintln!(
            "warning: confidant-tui {} does not match confidant-cli {cli_version}; \
             the TUI may render stale or unknown state. Install the matching version with \
             `cargo install confidant-tui`",
            tui_version.as_deref().unwrap_or("unknown")
        );
    }
    // The child inherits this process's environment, so CONFIDANT_VAULT and
    // CONFIDANT_BIN pass through untouched. An explicit `--vault` on this
    // command is forwarded the same way the TUI already reads it.
    let mut cmd = std::process::Command::new(&bin);
    cmd.args(args);
    if let Some(vault) = cli.vault.as_deref() {
        cmd.env("CONFIDANT_VAULT", vault);
    }
    let status = cmd.status()?;
    Ok(match status.code() {
        Some(code) => ExitCode::from(code as u8),
        // Killed by a signal: no exit code to propagate.
        None => ExitCode::FAILURE,
    })
}
