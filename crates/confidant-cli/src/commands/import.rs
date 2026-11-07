//! `import` (bulk ledger lines).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::shared::{finish_write, month_path, refuse_unknown_verb, write_options};
use crate::Cli;
use confidant_core::error::DomainError;
use confidant_core::write::{apply_write, FileChange, PendingWrite};

pub(crate) fn cmd_import(
    cli: &Cli,
    root: &Path,
    file: &Path,
    force: bool,
) -> anyhow::Result<ExitCode> {
    let text = std::fs::read_to_string(file).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            file.display()
        )))
    })?;
    // Validate every line before touching the vault.
    let mut entries = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        match confidant_core::parse_line(raw) {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) => {}
            Err(msg) => {
                return Err(anyhow::Error::new(
                    DomainError::invalid(format!("{}:{}: {msg}", file.display(), idx + 1))
                        .with_file(file.display().to_string())
                        .with_line(idx as u32 + 1)
                        .with_fix("Fix the line so it matches DATE VERB ID ARGS…"),
                ));
            }
        }
    }
    if entries.is_empty() {
        return Err(anyhow::Error::new(DomainError::usage(
            "import file has no ledger lines",
        )));
    }
    // #732 fix wave: `import` appends arbitrary verbs, so it gets the
    // same up-front verb gate as `log` — in dry-run and apply alike,
    // and for MCP `import_ledger`, which routes through this command.
    // Without it, a dry-run preview would report `ok:true` for lines
    // apply's post-check blocks with `E_UNKNOWN_VERB`.
    {
        let vault = vault_or!(root, cli.json);
        for entry in &entries {
            if !confidant_core::check::verb_passes_check(&vault, &entry.verb) {
                return Err(refuse_unknown_verb(&entry.verb));
            }
        }
    }

    let mut by_file: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    for entry in &entries {
        by_file
            .entry(month_path(&entry.date))
            .or_default()
            .push(confidant_core::format_entry(entry));
    }
    // #611: appending commits the whole month file (`git add`), so an
    // unrelated uncommitted line in it would be swept into this commit.
    // The write pipeline refuses that target for dry run and apply alike
    // (#770), so it is not repeated here.
    let total = entries.len();
    let lines: Vec<String> = by_file.values().flatten().cloned().collect();
    let changes: Vec<FileChange> = by_file
        .into_iter()
        .map(|(path, file_lines)| FileChange::AppendLines {
            path,
            lines: file_lines,
        })
        .collect();

    let mut opts = write_options(cli);
    opts.allow_destructive_batch = force;
    let outcome = apply_write(
        root,
        PendingWrite {
            changes,
            summary: format!("import {total} ledger lines"),
            canonical_request: format!("import/v1\n{text}"),
        },
        &opts,
    )?;
    finish_write(
        cli,
        root,
        "import",
        outcome,
        serde_json::json!({"lines": lines}),
    )
}
