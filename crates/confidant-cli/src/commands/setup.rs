//! `setup`: install skills and the system-of-record rule.

use std::path::Path;
use std::process::ExitCode;

use crate::commands::find::qmd_setup_note;
use crate::commands::install::{confirm_yn, offer_exe_path, run_offered_command};
use crate::commands::status::{
    completion_brief_json, optional_layers_json, print_completion_brief, print_optional_layers,
};
use crate::{ok_envelope, print_json, setup, Cli};
use serde_json::Value;

pub(crate) fn setup_result_json(
    result: &setup::SetupResult,
    instructions: Option<&[setup::InstructionInstall]>,
    instruction_text: &str,
    instructions_skipped: bool,
) -> Value {
    let agents: Vec<Value> = result
        .agents
        .iter()
        .map(|a| {
            serde_json::json!({
                "name": a.name,
                "dir": a.dir.display().to_string(),
                "linked": a.links.iter().filter(|l| !matches!(l.outcome, setup::LinkOutcome::SkippedExists)).count(),
                "skipped": a.links.iter().filter(|l| matches!(l.outcome, setup::LinkOutcome::SkippedExists)).count(),
                "skills": a.links.iter().map(|l| serde_json::json!({
                    "skill": l.skill,
                    "dest": l.dest.display().to_string(),
                    "outcome": l.outcome.as_str(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut value = serde_json::json!({
        "skills_dir": result.skills_dir.display().to_string(),
        "home": result.home.display().to_string(),
        "version": result.version,
        "agents": agents,
        "unknown_agents": result.unknown_agents,
        "linked": result.linked_count(),
        "skipped": result.skipped_count(),
        "removed_stale": result
            .removed_stale
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "dry_run": result.dry_run,
    });
    if let Some(instructions) = instructions {
        value["instructions"] = serde_json::json!({
            "skipped": instructions_skipped,
            "text": instruction_text,
            "targets": instructions.iter().map(|i| serde_json::json!({
                "agent": i.agent,
                "path": i.path.display().to_string(),
                "outcome": i.outcome.as_str(),
            })).collect::<Vec<_>>(),
        });
    }
    // #720: name both agent-integration surfaces, whether or not this run
    // wrote anything. Additive to the ADR-7 envelope.
    value["integrations"] = serde_json::json!({
        "skills": {
            "dir": result.skills_dir.display().to_string(),
            "agents": result.agent_labels(),
        },
        "mcp": {
            "command": "confidant mcp",
            "transport": "stdio",
            "note": "direct tool access for MCP-native hosts",
        },
    });
    value
}

pub(crate) fn cmd_setup(
    cli: &Cli,
    agent: &str,
    force: bool,
    copy: bool,
    no_instructions: bool,
    verbose: bool,
    vault: Option<&Path>,
) -> anyhow::Result<ExitCode> {
    let vault = vault.or(cli.vault.as_deref());
    match setup::run_setup(agent, force, copy, cli.dry_run) {
        Ok(result) => {
            // #653c: `--agent auto` falls back to claude-code when nothing is
            // detected; say so instead of creating ~/.claude silently.
            if let Some(note) = &result.fallback_note {
                eprintln!("warning: {note}");
            }
            // #727: install the system-of-record rule in each agent's
            // always-on instruction file, not only in the skill dirs.
            let instruction_text = setup::system_of_record_text(vault);
            let instructions = if no_instructions {
                Vec::new()
            } else {
                setup::install_instructions(
                    &result.resolved_agents,
                    &result.home,
                    vault,
                    cli.dry_run,
                )?
            };
            if cli.json {
                let mut value = setup_result_json(
                    &result,
                    Some(&instructions),
                    &instruction_text,
                    no_instructions,
                );
                if let Value::Object(ref mut obj) = value {
                    obj.insert("next_steps".to_owned(), setup_next_steps_json(cli));
                    obj.insert("brief".to_owned(), completion_brief_json(cli, vault));
                    obj.insert("optional_layers".to_owned(), optional_layers_json(vault));
                }
                print_json(&ok_envelope(None, value))?;
            } else {
                if verbose {
                    for line in &result.verbose_lines {
                        println!("{line}");
                    }
                }
                for unknown in &result.unknown_agents {
                    eprintln!("warning: unknown agent '{unknown}' — skipped");
                }
                let labels = result.agent_labels().join(", ");
                if result.dry_run {
                    println!("Confidant skills (dry run; nothing written)");
                } else {
                    println!("Confidant skills installed");
                }
                println!("  skills   {} → {labels}", result.skills_dir.display());
                println!("  version  {}", result.version);
                println!(
                    "  {:<9} {} ({} skipped)",
                    if result.dry_run {
                        "would link"
                    } else {
                        "linked"
                    },
                    result.linked_count(),
                    result.skipped_count()
                );
                if result.skipped_count() > 0 {
                    println!("  replace existing dirs with: confidant setup --force");
                }
                if !result.removed_stale.is_empty() {
                    println!(
                        "  {:<9} {} stale skill link(s)",
                        if result.dry_run {
                            "would drop"
                        } else {
                            "removed"
                        },
                        result.removed_stale.len()
                    );
                }
                // #720: both agent-integration surfaces, named the same way
                // skill links are. Skills carry workflow text; `mcp` is the
                // direct-tool surface for MCP-native hosts.
                println!();
                println!("Agent integrations:");
                println!(
                    "  skills   {} → {labels} (workflow guidance; agents shell out to `confidant`)",
                    result.skills_dir.display()
                );
                println!(
                    "  mcp      confidant mcp (MCP over stdio; direct tool access for MCP-native hosts)"
                );
                if no_instructions {
                    println!();
                    println!("System-of-record rule skipped (--no-instructions).");
                } else if instructions.is_empty() {
                    println!();
                    println!(
                        "System-of-record rule not installed: no agent instruction file was selected."
                    );
                } else {
                    println!();
                    println!(
                        "System-of-record rule {}:",
                        if result.dry_run {
                            "planned (nothing written)"
                        } else {
                            "installed"
                        }
                    );
                    for install in &instructions {
                        println!(
                            "  {:<12} {}",
                            install.outcome.as_str(),
                            install.path.display()
                        );
                    }
                    println!();
                    println!(
                        "Text {}:",
                        if result.dry_run {
                            "that would be written"
                        } else {
                            "written"
                        }
                    );
                    for line in instruction_text.lines() {
                        println!("  {line}");
                    }
                }
                if result.dry_run {
                    println!("  re-run without --dry-run to apply");
                } else {
                    println!();
                    setup_next_steps(cli, verbose)?;
                    println!();
                    print_completion_brief(cli, vault);
                }
                // #715: setup ends with the optional-layers checklist, so
                // "done" does not silently mean "keyword search only".
                println!();
                print_optional_layers(vault);
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => Err(err),
    }
}

/// True when the operator has pointed at a vault via `CONFIDANT_VAULT`
/// (non-empty). Unset or empty means the next-steps block prints the
/// export line instead.
pub(crate) fn vault_env_set() -> bool {
    std::env::var("CONFIDANT_VAULT")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// The exact line to paste when `CONFIDANT_VAULT` is unset (#376): the real
/// path only when one was given explicitly (e.g. `--vault`), otherwise the
/// `<path>` placeholder. The vault itself is never read or probed.
pub(crate) fn vault_export_line(cli: &Cli) -> String {
    match &cli.vault {
        Some(p) => format!("export CONFIDANT_VAULT={}", p.display()),
        None => "export CONFIDANT_VAULT=<path>".to_owned(),
    }
}

/// Additive `next_steps` entry for the `setup` JSON envelope (#376): the
/// check command to run, whether `CONFIDANT_VAULT` is set, and the exact
/// export line when it is not. Never probes the vault. #386 adds the
/// informational qmd availability (`qmd_available`, plus `qmd_note` only
/// when qmd is missing): qmd is optional and never changes exit status.
pub(crate) fn setup_next_steps_json(cli: &Cli) -> Value {
    let set = vault_env_set();
    let qmd_note = qmd_setup_note();
    serde_json::json!({
        "check_command": "confidant check",
        "vault_set": set,
        "vault_export": if set {
            Value::Null
        } else {
            Value::String(vault_export_line(cli))
        },
        "qmd_available": qmd_note.is_none(),
        "qmd_note": qmd_note.map(Value::String).unwrap_or(Value::Null),
    })
}

/// Human-readable next steps after `setup` (#376). When `CONFIDANT_VAULT`
/// is set, an interactive terminal is offered `run `confidant check` now?`
/// (default No, never automatic); non-interactive output only prints the
/// check command. When unset, the exact export line replaces the old
/// generic wording. The vault is never read or probed here — the check
/// runs only after an explicit `y`, inheriting the environment.
///
/// #653e: the optional qmd npm note is only printed with `-v/--verbose`;
/// JSON keeps `qmd_available`/`qmd_note` for agents either way.
pub(crate) fn setup_next_steps(cli: &Cli, verbose: bool) -> anyhow::Result<()> {
    println!("Next:");
    if vault_env_set() {
        println!("  Run `confidant check` against your vault.");
        if confirm_yn("run `confidant check` now?", cli.no_input, cli.json)? {
            let exe = offer_exe_path();
            match run_offered_command("confidant check", exe.as_os_str(), &["check"]) {
                Ok(()) => println!("`confidant check` passed."),
                Err(err) => eprintln!("`confidant check` failed: {err:#}"),
            }
        }
    } else {
        println!("  {}", vault_export_line(cli));
        println!("  Then run `confidant check`.");
    }
    // #386: informational qmd note. Optional, never prompts, never fails,
    // never changes exit status.
    if verbose {
        if let Some(note) = qmd_setup_note() {
            println!("  {note}");
        }
    }
    Ok(())
}
