//! `check` and `allowlist`.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use confidant_core::check::parse_fail_on;
use confidant_core::config::parse_iso_date;
use confidant_core::error::DomainError;
use confidant_core::scope::owner_labels;
use confidant_core::{check_vault, CheckOptions};
use serde_json::Value;

pub(crate) fn print_check_human(report: &confidant_core::CheckReport) -> io::Result<()> {
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

pub(crate) fn cmd_check(
    json: bool,
    root: &Path,
    fail_on: &str,
    as_of: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let fail_on = parse_fail_on(fail_on)?;
    let as_of = match as_of {
        None => None,
        Some(s) => Some(parse_iso_date(s).map_err(|_| {
            DomainError::usage(format!(
                "--as-of '{s}' is not a zero-padded calendar date YYYY-MM-DD"
            ))
        })?),
    };
    let vault = vault_or!(root, json);
    let report = check_vault(
        &vault,
        &CheckOptions {
            as_of,
            fail_on: Some(fail_on),
        },
    );
    if json {
        crate::print_json(&report)?;
    } else {
        print_check_human(&report)?;
    }
    if report.ok {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

pub(crate) fn cmd_allowlist(cli: &crate::Cli, json: bool, root: &Path) -> anyhow::Result<ExitCode> {
    if let Err(err) = crate::legacy_vault_gate(root) {
        crate::print_error(json, Some(&root.display().to_string()), &err)?;
        return Ok(ExitCode::from(err.exit_code() as u8));
    }
    // Spec 4: the allowlist is a read path — records participate,
    // uncleared ones are excluded by omission.
    let vault = match crate::load_vault_for_reads(root, json, false) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    if !confidant_core::SpecVersion::is_supported(&vault.config.spec) {
        crate::print_error(
            json,
            Some(&vault.root.display().to_string()),
            &DomainError::spec_unsupported(&vault.config.spec),
        )?;
        return Ok(ExitCode::from(1));
    }
    if vault.ledger_unread_count > 0 {
        let err = DomainError::ledger_unreadable(vault.ledger_unread_count);
        crate::print_error(json, Some(&vault.root.display().to_string()), &err)?;
        return Ok(ExitCode::from(err.exit_code() as u8));
    }
    let (scope, scope_names) = match crate::resolve_cli_scope(&vault, cli.packs.as_deref()) {
        Ok(pair) => pair,
        Err(err) => {
            crate::print_error(json, Some(&vault.root.display().to_string()), &err)?;
            return Ok(ExitCode::from(err.exit_code() as u8));
        }
    };
    // #178: scope the cleared set, and annotate each entry with its
    // owning packs (for index-time consumers — the QMD index
    // carries ownership via this output; query-time filtering
    // stays in `find`). `owning_packs` is [] for unattributed
    // items, ["core"] for core-owned items.
    let mut owning_packs: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut files: Vec<String> = Vec::new();
    for (path, owners) in confidant_core::cleared_record_owners(&vault) {
        if !scope.allows(&owners) {
            continue;
        }
        owning_packs.insert(
            path.clone(),
            Value::Array(
                owner_labels(&owners)
                    .into_iter()
                    .map(|s| Value::String(s.to_owned()))
                    .collect(),
            ),
        );
        files.push(path);
    }
    let mut ledger: Vec<serde_json::Value> = Vec::new();
    for (file, line, owners) in confidant_core::cleared_ledger_line_owners(&vault) {
        if !scope.allows(&owners) {
            continue;
        }
        ledger.push(serde_json::json!({
            "file": file,
            "line": line,
            "owning_packs": owner_labels(&owners),
        }));
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "schema_version": confidant_core::check::JSON_SCHEMA_VERSION,
                "vault": vault.root.display().to_string(),
                "cleared_files": files,
                "cleared_ledger_lines": ledger,
                "owning_packs": owning_packs,
                "scope": scope_names,
            })
        );
    } else {
        for f in &files {
            writeln!(io::stdout(), "{f}")?;
        }
        for entry in &ledger {
            writeln!(
                io::stdout(),
                "{}:{}",
                entry["file"].as_str().unwrap_or(""),
                entry["line"].as_u64().unwrap_or(0)
            )?;
        }
        writeln!(
            io::stdout(),
            "{} file(s), {} ledger line(s) cleared",
            files.len(),
            ledger.len()
        )?;
    }
    Ok(ExitCode::SUCCESS)
}
