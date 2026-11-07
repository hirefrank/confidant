//! Search command (`find`) and the QMD corpus hints it prints.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use crate::commands::doctor::{qmd_state, QmdState};
use crate::commands::shared::{find_on_path, OPERATOR_MODE_BANNER};
use crate::{
    legacy_vault_gate, load_vault_for_reads, ok_envelope, print_error, print_json,
    resolve_cli_scope,
};
use confidant_core::error::DomainError;
use confidant_core::{search, search_for_operator};

pub(crate) fn cmd_find(
    json: bool,
    root: &Path,
    query: &str,
    limit: usize,
    packs: Option<&str>,
    for_operator: bool,
) -> anyhow::Result<ExitCode> {
    if query.trim().is_empty() {
        return Err(anyhow::Error::new(DomainError::usage(
            "find requires a non-empty query",
        )));
    }
    if let Err(err) = legacy_vault_gate(root) {
        print_error(json, Some(&root.display().to_string()), &err)?;
        return Ok(ExitCode::from(err.exit_code() as u8));
    }
    // Operator mode (#572) loads through the operator read path (the same
    // mechanism as `record show --for-edit`); the default stays the agent
    // read path (`no-ai` records are then excluded by the §12 allowlist).
    let vault = match load_vault_for_reads(root, json, for_operator) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let vault_path = vault.root.display().to_string();
    if !confidant_core::SpecVersion::is_supported(&vault.config.spec) {
        print_error(
            json,
            Some(&vault_path),
            &DomainError::spec_unsupported(&vault.config.spec),
        )?;
        return Ok(ExitCode::from(1));
    }
    let (scope, scope_names) = match resolve_cli_scope(&vault, packs) {
        Ok(pair) => pair,
        Err(err) => {
            print_error(json, Some(&vault_path), &err)?;
            return Ok(ExitCode::from(err.exit_code() as u8));
        }
    };
    let result = match if for_operator {
        search_for_operator(&vault, query, &scope)
    } else {
        search(&vault, query, &scope)
    } {
        Ok(result) => result,
        Err(err) => {
            print_error(json, Some(&vault_path), &err)?;
            return Ok(ExitCode::from(err.exit_code() as u8));
        }
    };
    let hits: Vec<_> = result.hits.into_iter().take(limit).collect();
    let findings = result.findings;
    // #386: optional ranked-search hint. Present only when qmd is on PATH
    // and the corpus exists; never changes matches, ordering, or exit status.
    let qmd_hint = qmd_hint_for_find(&vault.root);
    if json {
        let mut data = serde_json::json!({
                "query": query,
                "matches": hits,
                "findings": findings,
                "scope": scope_names,
        });
        if let (Some(hint), Some(obj)) = (qmd_hint.as_deref(), data.as_object_mut()) {
            obj.insert(
                "hint".to_owned(),
                serde_json::Value::String(hint.to_owned()),
            );
        }
        // Operator mode (#572): present only with the flag, so an agent's
        // JSON is byte-for-byte unchanged.
        if for_operator {
            if let Some(obj) = data.as_object_mut() {
                obj.insert("for_operator".to_owned(), serde_json::Value::Bool(true));
            }
        }
        print_json(&ok_envelope(Some(&vault.root), data))?;
    } else {
        if for_operator {
            writeln!(io::stdout(), "{OPERATOR_MODE_BANNER}")?;
        }
        for f in &findings {
            writeln!(
                io::stdout(),
                "{:<7}  {}  {}",
                f.severity.label(),
                f.code.as_str(),
                f.message
            )?;
        }
        for hit in &hits {
            let id = hit.id.as_deref().unwrap_or("-");
            let ref_col = hit
                .line_ref
                .as_deref()
                .map(|line_ref| format!("\t{line_ref}"))
                .unwrap_or_default();
            writeln!(
                io::stdout(),
                "{id}\t{}:{}\t{}{ref_col}",
                hit.path,
                hit.line,
                hit.excerpt
            )?;
        }
        writeln!(io::stdout(), "{} matches", hits.len())?;
        if let Some(hint) = qmd_hint.as_deref() {
            eprintln!("{hint}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// #386: optional `find` ranked-search hint. `Some` only when `qmd` is on
/// PATH and `<vault>/.confidant/qmd-corpus/` exists; otherwise `None`
/// (the install suggestion stays in `doctor` and `setup`).
pub(crate) fn qmd_hint_for_find(root: &Path) -> Option<String> {
    find_on_path("qmd")?;
    if !root.join(QMD_CORPUS_REL).is_dir() {
        return None;
    }
    Some("qmd index available; use the qmd-search skill for ranked results".to_owned())
}

/// #386/#715: optional `setup` note when qmd is missing or not working.
/// Informational only: no prompt, no failure, no exit-status change.
/// Search falls back to `confidant find` without a working qmd.
pub(crate) fn qmd_setup_note() -> Option<String> {
    match qmd_state() {
        QmdState::Working { .. } => None,
        QmdState::Missing => Some(
            "Note: `qmd` not found on PATH — search falls back to `confidant find`. \
             For ranked search, install with `npm install -g @tobilu/qmd` (optional)."
                .to_owned(),
        ),
        // #715: a shim named `qmd` is not a working qmd. Say so instead of
        // silently treating semantic search as available.
        QmdState::NotWorking { path } => Some(format!(
            "Note: `qmd` at {} did not report a version — search falls back to \
             `confidant find`. Reinstall with `npm install -g @tobilu/qmd` (optional).",
            path.display()
        )),
    }
}

/// `<vault>/.confidant/qmd-corpus/` — the QMD search corpus (ADR-6).
pub(crate) const QMD_CORPUS_REL: &str = ".confidant/qmd-corpus";
pub(crate) const QMD_STORE_REL: &str = ".confidant/qmd";
/// #725: the vault HEAD `qmd-index.py` recorded when it built the corpus.
pub(crate) const QMD_BUILD_MARKER_REL: &str = ".confidant/qmd-build.json";

pub(crate) fn ensure_corpus_gitignored(root: &Path) -> Result<(), DomainError> {
    let git_dir = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--git-dir"])
        .output();
    match git_dir {
        Err(_) => {
            eprintln!(
                "warning: git not found; cannot check that `.confidant/` is \
                 git-ignored. The corpus is a plaintext mirror — add \
                 `.confidant/` to `.gitignore` before this vault is ever committed."
            );
            return Ok(());
        }
        Ok(out) if !out.status.success() => {
            eprintln!(
                "warning: this vault is not a git repo yet; the `.confidant/` \
                 gitignore check is skipped. Add `.confidant/` to `.gitignore` \
                 before initializing a repo and committing."
            );
            return Ok(());
        }
        Ok(_) => {}
    }
    // Probe `.confidant/` (which contains the corpus, the QMD store, and the
    // build temp dir) rather than each child separately. `check-ignore -q`
    // exits 0 when the path is ignored; the probe file need not exist.
    let ignored = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["check-ignore", "-q", ".confidant/.probe"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if ignored {
        Ok(())
    } else {
        Err(DomainError::config(
            "refusing to write under `.confidant/`: not git-ignored in this vault",
        )
        .with_fix(format!(
            "Add `.confidant/` to the vault's .gitignore, e.g.: (cd {} && echo '.confidant/' >> .gitignore), then retry",
            root.display()
        )))
    }
}
