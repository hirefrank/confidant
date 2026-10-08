//! Confidant CLI. Agent contract flags (`--json`, `--no-input`) exist from
//! day one even though milestone 1 only implements `check` and `find`.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use confidant_core::check::parse_fail_on;
use confidant_core::config::parse_iso_date;
use confidant_core::discover::{load_user_config, resolve, Discovery};
use confidant_core::error::DomainError;
use confidant_core::{check_vault, load_vault, search, CheckOptions};

#[derive(Parser, Debug)]
#[command(
    name = "confidant",
    version,
    about = "Plain-text, git-native CRM for one operator and their agents.",
    after_help = "Examples:\n  \
        confidant check --vault ./examples/demo-vault\n  \
        confidant check --json --no-input\n  \
        CONFIDANT_VAULT=./examples/demo-vault confidant find goals --json\n  \
        confidant check --fail-on warning --as-of 2026-10-08"
)]
struct Cli {
    /// Vault directory (ADR-11, first).
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    /// Machine-readable JSON on stdout. Every object includes `vault`.
    #[arg(long, global = true)]
    json: bool,

    /// Never prompt; fail instead (ADR-7). Milestone 1 never prompts.
    #[arg(long, global = true)]
    no_input: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Validate the vault and print findings (read-only).
    Check {
        /// Fail when a finding reaches this severity (default: error).
        #[arg(long, default_value = "error")]
        fail_on: String,
        /// Date gap rules use (YYYY-MM-DD). Overrides [checks].as_of.
        #[arg(long)]
        as_of: Option<String>,
    },
    /// Scan plaintext records and ledger lines.
    Find {
        /// Case-insensitive substring.
        query: String,
    },
    /// Write a fake vault of N people for search benchmarks (hidden).
    #[command(hide = true)]
    BenchGen {
        dir: PathBuf,
        #[arg(long, default_value_t = 400)]
        people: usize,
        #[arg(long, default_value_t = 5)]
        notes: usize,
        /// Fill note bodies with no-space CJK prose (quadratic-scan guard).
        #[arg(long)]
        cjk: bool,
    },
}

fn main() -> ExitCode {
    let json_hint = std::env::args_os().any(|a| a == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            if json_hint && err.use_stderr() {
                let _ = print_error(
                    true,
                    None,
                    &DomainError::usage(err.to_string().trim().to_owned()),
                );
                return ExitCode::from(2);
            }
            err.exit();
        }
    };
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            let json = std::env::args_os().any(|a| a == "--json");
            let domain = DomainError::of(&error)
                .cloned()
                .unwrap_or_else(|| DomainError::internal(format!("{error:#}")));
            let _ = print_error(json, None, &domain);
            ExitCode::from(domain.exit_code() as u8)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let json = cli.json;
    let _no_input = cli.no_input;
    match cli.command {
        Command::BenchGen {
            dir,
            people,
            notes,
            cjk,
        } => {
            let (unique, common) =
                confidant_core::bench::generate_realistic_vault(&dir, people, notes, cjk)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
                        "vault": dir.canonicalize().unwrap_or(dir).display().to_string(),
                        "people": people,
                        "notes_per_person": notes,
                        "unique_token": unique,
                        "common_token": common,
                    })
                );
            } else {
                println!("wrote {people} people × {notes} notes at {}", dir.display());
                println!("unique token: {unique}");
                println!("common token: {common}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Check { fail_on, as_of } => {
            let fail_on = parse_fail_on(&fail_on)?;
            let as_of = match as_of.as_deref() {
                None => None,
                Some(s) => Some(parse_iso_date(s).map_err(|_| {
                    DomainError::usage(format!(
                        "--as-of '{s}' is not a zero-padded calendar date YYYY-MM-DD"
                    ))
                })?),
            };
            let root = match discover(cli.vault.as_deref()) {
                Ok(root) => root,
                Err(err) => {
                    print_error(json, None, &err)?;
                    return Ok(ExitCode::from(err.exit_code() as u8));
                }
            };
            let vault = match load_vault(&root) {
                Ok(v) => v,
                Err(err) => {
                    print_error(json, Some(&root.display().to_string()), &err)?;
                    return Ok(ExitCode::from(err.exit_code() as u8));
                }
            };
            let report = check_vault(
                &vault,
                &CheckOptions {
                    as_of,
                    fail_on: Some(fail_on),
                },
            );
            if json {
                serde_json::to_writer(io::stdout(), &report)?;
                println!();
            } else {
                print_check_human(&report)?;
            }
            if report.ok {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(1))
            }
        }
        Command::Find { query } => {
            if query.trim().is_empty() {
                return Err(anyhow::Error::new(DomainError::usage(
                    "find requires a non-empty query",
                )));
            }
            let root = match discover(cli.vault.as_deref()) {
                Ok(root) => root,
                Err(err) => {
                    print_error(json, None, &err)?;
                    return Ok(ExitCode::from(err.exit_code() as u8));
                }
            };
            let vault = match load_vault(&root) {
                Ok(v) => v,
                Err(err) => {
                    print_error(json, Some(&root.display().to_string()), &err)?;
                    return Ok(ExitCode::from(err.exit_code() as u8));
                }
            };
            if vault.config.spec != confidant_core::SPEC_VERSION {
                print_error(
                    json,
                    Some(&vault.root.display().to_string()),
                    &DomainError::spec_unsupported(&vault.config.spec),
                )?;
                return Ok(ExitCode::from(1));
            }
            let result = match search(&vault, &query) {
                Ok(result) => result,
                Err(err) => {
                    print_error(json, Some(&vault.root.display().to_string()), &err)?;
                    return Ok(ExitCode::from(err.exit_code() as u8));
                }
            };
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
                        "vault": vault.root.display().to_string(),
                        "query": query,
                        "matches": result.hits,
                        "findings": result.findings,
                    })
                );
            } else {
                for f in &result.findings {
                    writeln!(
                        io::stdout(),
                        "{:<7}  {}  {}",
                        f.severity.label(),
                        f.code.as_str(),
                        f.message
                    )?;
                }
                for hit in &result.hits {
                    let id = hit.id.as_deref().unwrap_or("-");
                    writeln!(
                        io::stdout(),
                        "{id}\t{}:{}\t{}",
                        hit.path,
                        hit.line,
                        hit.excerpt
                    )?;
                }
                writeln!(io::stdout(), "{} matches", result.hits.len())?;
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn discover(flag: Option<&std::path::Path>) -> Result<PathBuf, DomainError> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let discovery = Discovery {
        flag: flag.map(PathBuf::from),
        env: std::env::var("CONFIDANT_VAULT").ok(),
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        user_config: load_user_config(home.as_deref()),
    };
    resolve(&discovery)
}

fn print_check_human(report: &confidant_core::CheckReport) -> io::Result<()> {
    let mut out = io::stdout();
    for f in &report.findings {
        write!(out, "{:<7}  {}", f.severity.label(), f.code.as_str())?;
        if let Some(file) = &f.file {
            write!(out, "  {file}")?;
            if let Some(line) = f.line {
                write!(out, ":{line}")?;
            }
        }
        if let Some(id) = &f.id {
            write!(out, "  {id}")?;
        }
        writeln!(out)?;
        writeln!(out, "    {}", f.message)?;
        if let Some(fix) = &f.fix {
            writeln!(out, "    fix: {fix}")?;
        }
    }
    if report.findings.is_empty() {
        writeln!(
            out,
            "ok  {} records, {} ledger entries",
            report.summary.records, report.summary.ledger_entries
        )?;
    } else {
        writeln!(
            out,
            "{} error(s), {} warning(s)",
            report.summary.errors, report.summary.warnings
        )?;
    }
    Ok(())
}

fn print_error(json: bool, vault: Option<&str>, err: &DomainError) -> io::Result<()> {
    if json {
        let body = serde_json::json!({
            "ok": false,
            "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
            "vault": vault,
            "error": err.to_json(),
        });
        writeln!(io::stdout(), "{body}")?;
    } else {
        writeln!(io::stderr(), "error: {} ({})", err.message(), err.code())?;
        if let Some(fix) = err.fix() {
            writeln!(io::stderr(), "  fix: {fix}")?;
        }
    }
    Ok(())
}
