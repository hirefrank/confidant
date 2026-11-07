//! `retract`, `correct`, and `record retire`/`unretire`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::shared::{
    apply_record_write, defer_to_write_path, finish_write, month_path, parse_date_arg,
    write_options,
};
use crate::{Cli, FixExt};
use confidant_core::error::DomainError;
use confidant_core::id::{Prefix, RecordId};
use confidant_core::ledger::{
    format_entry, line_fingerprint, parse_line, parse_strict_date, LineRef, RetractReason,
};
use confidant_core::write::{apply_write_repairing, FileChange, PendingWrite, WriteOutcome};
use confidant_core::SpecVersion;

pub(crate) fn parse_line_ref_parts(raw: &str) -> anyhow::Result<(String, Option<u32>)> {
    let raw = raw.trim();
    let raw = raw.strip_prefix("line:").unwrap_or(raw);
    let (hash, anchor) = match raw.split_once('#') {
        Some((hash, n)) => {
            let n: u32 = n.parse().map_err(|_| {
                anyhow::Error::new(DomainError::usage(format!(
                    "bad line occurrence '{n}'; use #<positive integer>"
                )))
            })?;
            if n == 0 {
                return Err(anyhow::Error::new(DomainError::usage(
                    "line occurrences are 1-based",
                )));
            }
            (hash, Some(n))
        }
        None => (raw, None),
    };
    if hash.len() < 12 || hash.len() > 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::Error::new(DomainError::usage(
            "not a line ref; use line:<64 lowercase hex>, a unique ≥12-hex prefix, or append #<occurrence>",
        )));
    }
    if hash.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(anyhow::Error::new(DomainError::usage(
            "line refs are lowercase hex; use the value `find --json` prints",
        )));
    }
    Ok((hash.to_owned(), anchor))
}

/// Resolve a CLI line ref (full hash or unique prefix) against parsed ledger
/// entries. Occurrence defaults to 1; `--occurrence` and `#<n>` must agree
/// when both are given.
pub(crate) fn lookup_line_ref<'a>(
    vault: &'a confidant_core::vault::Vault,
    raw: &str,
    occurrence: Option<u32>,
) -> anyhow::Result<&'a confidant_core::vault::SourcedEntry> {
    if occurrence == Some(0) {
        return Err(anyhow::Error::new(DomainError::usage(
            "line occurrences are 1-based",
        )));
    }
    let (hash, anchor) = parse_line_ref_parts(raw)?;
    let occurrence = match (occurrence, anchor) {
        (Some(flag), Some(anchor)) if flag != anchor => {
            return Err(anyhow::Error::new(DomainError::usage(format!(
                "--occurrence {flag} conflicts with the ref's #{anchor}"
            ))))
        }
        (Some(flag), _) => flag,
        (None, Some(anchor)) => anchor,
        (None, None) => 1,
    };
    let mut hashes: BTreeSet<String> = BTreeSet::new();
    let mut found = None;
    for sourced in &vault.entries {
        let candidate = sourced.line_ref.hash_hex();
        let hash_matches = if hash.len() == 64 {
            candidate == hash
        } else {
            candidate.starts_with(&hash)
        };
        if hash_matches {
            hashes.insert(candidate);
            if sourced.line_ref.occurrence() == occurrence {
                found = Some(sourced);
            }
        }
    }
    if hashes.len() > 1 {
        return Err(anyhow::Error::new(DomainError::invalid(
            "line ref prefix matches more than one line; use more hex characters",
        )));
    }
    found.ok_or_else(|| {
        anyhow::Error::new(DomainError::not_found(
            "no ledger line matches that ref and occurrence",
        ))
        .with_fix("Run `confidant find <text> --json` and copy the `ref` it prints")
    })
}

pub(crate) fn parse_retract_reason(raw: &str) -> anyhow::Result<RetractReason> {
    RetractReason::parse(raw).ok_or_else(|| {
        anyhow::Error::new(DomainError::usage(format!(
            "bad retract reason '{raw}'; use duplicate, wrong-date, wrong-kind, wrong-person, wrong-amount, wrong-note, wrong-record, typo, or other"
        )))
    })
}

pub(crate) fn require_spec_04(
    vault: &confidant_core::vault::Vault,
    command: &str,
) -> anyhow::Result<()> {
    if vault
        .spec_version()
        .is_some_and(|spec| spec >= SpecVersion::V04)
    {
        return Ok(());
    }
    Err(anyhow::Error::new(DomainError::invalid(format!(
        "{command} requires a spec 0.4 vault"
    )))
    .with_fix("Change `spec` in confidant.toml to \"0.4\" after updating every device"))
}

pub(crate) fn ledger_correction_line(
    date: chrono::NaiveDate,
    subject: &RecordId,
    target: LineRef,
    reason: RetractReason,
    replacement: Option<LineRef>,
) -> String {
    let mut line = format!("{date} retract {subject} line:{}", target.hash_hex());
    if target.occurrence() != 1 {
        line.push_str(&format!(" occurrence:{}", target.occurrence()));
    }
    line.push_str(&format!(" reason:{reason}"));
    if let Some(replacement) = replacement {
        line.push_str(&format!(" replace:{}", replacement.hash_hex()));
    }
    line
}

pub(crate) fn apply_ledger_correction(
    cli: &Cli,
    root: &Path,
    changes: BTreeMap<PathBuf, Vec<String>>,
    summary: String,
    canonical_request: String,
    extra: serde_json::Value,
    force: bool,
) -> anyhow::Result<ExitCode> {
    // #611/#770: an append commits the whole target file, so a target with
    // uncommitted changes is refused. `apply_write` runs that read-only gate
    // for dry run and apply alike; nothing is repeated here.
    let pending = PendingWrite {
        changes: changes
            .into_iter()
            .map(|(path, lines)| FileChange::AppendLines { path, lines })
            .collect(),
        summary,
        canonical_request,
    };
    let mut opts = write_options(cli);
    opts.allow_destructive_batch = force;
    let outcome = apply_write_repairing(root, pending, &opts)?;
    finish_write(
        cli,
        root,
        if extra["command"] == "correct" {
            "correct"
        } else {
            "retract"
        },
        outcome,
        extra,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_retract_bulk(
    cli: &Cli,
    root: &Path,
    vault: &confidant_core::vault::Vault,
    subject: &RecordId,
    reason_raw: &str,
    match_date: Option<&str>,
    verb: Option<&str>,
    kind: Option<&str>,
    keep: Option<usize>,
    date_raw: Option<&str>,
    force: bool,
) -> anyhow::Result<ExitCode> {
    let Some(match_date_raw) = match_date else {
        return Err(anyhow::Error::new(DomainError::usage(
            "bulk retract needs --match-date and --verb, or a single --line",
        )));
    };
    let match_date = parse_strict_date(match_date_raw).ok_or_else(|| {
        anyhow::Error::new(DomainError::usage(format!(
            "--match-date is not YYYY-MM-DD: {match_date_raw}"
        )))
    })?;
    let Some(verb) = verb else {
        return Err(anyhow::Error::new(DomainError::usage(
            "bulk retract needs --verb (for example touch)",
        )));
    };
    if kind.is_some() && verb != "touch" {
        return Err(anyhow::Error::new(DomainError::usage(
            "--kind only applies to touch lines",
        )));
    }
    let reason = parse_retract_reason(reason_raw)?;
    let date = parse_date_arg(&date_raw.map(str::to_owned))?;
    let keep = keep.unwrap_or(1);

    let mut groups: BTreeMap<String, Vec<&confidant_core::vault::SourcedEntry>> = BTreeMap::new();
    for sourced in vault.effective_entries() {
        if sourced.entry.id != *subject
            || sourced.entry.verb != verb
            || sourced.entry.date != match_date
        {
            continue;
        }
        if let Some(kind_filter) = kind {
            if confidant_core::touch::extract_touch_kind(&sourced.entry).as_deref()
                != Some(kind_filter)
            {
                continue;
            }
        }
        let identity = match verb {
            "touch" => {
                let kind =
                    confidant_core::touch::extract_touch_kind(&sourced.entry).unwrap_or_default();
                format!("touch|{}|{match_date}|{kind}", sourced.entry.id)
            }
            _ => format!("fp|{}", sourced.line_ref.hash_hex()),
        };
        groups.entry(identity).or_default().push(sourced);
    }
    let mut targets: Vec<&confidant_core::vault::SourcedEntry> = Vec::new();
    for mut group in groups.into_values() {
        group.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
        targets.extend(group.into_iter().skip(keep));
    }
    targets.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    if targets.iter().any(|s| s.entry.date > date) {
        return Err(anyhow::Error::new(DomainError::invalid(
            "a selected line is dated after the retraction date",
        ))
        .with_fix("Pass a later --date"));
    }
    let lines: Vec<String> = targets
        .iter()
        .map(|s| ledger_correction_line(date, subject, s.line_ref, reason, None))
        .collect();
    // Selector-only canonical request: a retry with the same selector and a
    // known --request-id can replay even though every target is now voided.
    let canonical = format!(
        "retract-bulk/v1\nsubject={subject}\nmatch_date={match_date}\nverb={verb}\nkind={}\nkeep={keep}\nreason={reason}\ndate={date}\n",
        kind.unwrap_or("")
    );
    if targets.is_empty() && !defer_to_write_path(root, cli, &canonical)? {
        return Err(anyhow::Error::new(DomainError::already_exists(
            "no effective lines match that bulk selector",
        ))
        .with_fix("Widen the selector, or check that the lines are not already retracted"));
    }
    let mut changes: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    if !lines.is_empty() {
        changes
            .entry(month_path(&date))
            .or_default()
            .extend(lines.clone());
    }
    let target_refs: Vec<String> = targets.iter().map(|s| s.line_ref.to_string()).collect();
    apply_ledger_correction(
        cli,
        root,
        changes,
        format!("retract {subject} batch"),
        canonical,
        serde_json::json!({
            "command": "retract",
            "subject": subject.to_string(),
            "reason": reason.as_str(),
            "targets": target_refs,
            "lines": lines,
            "date": date.to_string(),
            "bulk": true,
        }),
        force,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_retract(
    cli: &Cli,
    root: &Path,
    subject_raw: &str,
    line_raw: Option<&str>,
    occurrence: Option<u32>,
    reason_raw: String,
    replace_raw: Option<&str>,
    match_date: Option<&str>,
    verb: Option<&str>,
    kind: Option<&str>,
    keep: Option<usize>,
    date_raw: Option<&str>,
    force: bool,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    require_spec_04(&vault, "retract")?;
    let subject = RecordId::parse(subject_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!(
            "not a record id: {subject_raw}"
        )))
        .with_fix("Pass the target line's subject id, e.g. p-<ULID>")
    })?;
    let Some(line_raw) = line_raw else {
        return cmd_retract_bulk(
            cli,
            root,
            &vault,
            &subject,
            &reason_raw,
            match_date,
            verb,
            kind,
            keep,
            date_raw,
            force,
        );
    };
    if match_date.is_some() || verb.is_some() || kind.is_some() || keep.is_some() {
        return Err(anyhow::Error::new(DomainError::usage(
            "bulk selectors cannot be combined with --line",
        ))
        .with_fix("Pass either --line, or --verb with --match-date"));
    }
    let target = lookup_line_ref(&vault, line_raw, occurrence)?;
    if target.entry.id != subject {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "target line's subject is {}, not {subject_raw}",
            target.entry.id
        )))
        .with_fix("Use the target line's own subject id"));
    }
    if matches!(target.entry.verb.as_str(), "retract" | "merge") {
        return Err(anyhow::Error::new(DomainError::invalid(
            "merge and retract lines cannot be retracted",
        ))
        .with_fix("Only a fact line can be retracted"));
    }
    let date = parse_date_arg(&date_raw.map(str::to_owned))?;
    if target.entry.date > date {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "target line is dated {}, after the retraction date {date}",
            target.entry.date
        )))
        .with_fix("Pass a --date on or after the target line's date"));
    }
    let reason = parse_retract_reason(&reason_raw)?;
    let replacement = match replace_raw {
        Some(raw) => {
            let replacement = lookup_line_ref(&vault, raw, None)?;
            if replacement.line_ref.occurrence() != 1 {
                return Err(anyhow::Error::new(DomainError::invalid(
                    "a replacement must be a unique line (occurrence 1)",
                ))
                .with_fix("Use `correct` with an inline replacement line instead"));
            }
            if replacement.entry.id != subject {
                return Err(anyhow::Error::new(DomainError::invalid(
                    "replacement line's subject does not match the target",
                ))
                .with_fix("A replacement must keep the target line's subject id"));
            }
            if replacement.entry.date > date {
                return Err(anyhow::Error::new(DomainError::invalid(
                    "replacement line is dated after the retraction",
                ))
                .with_fix("Pass a later --date or choose an earlier replacement"));
            }
            if vault.corrections().is_voided(&replacement.line_ref) {
                return Err(anyhow::Error::new(DomainError::invalid(
                    "replacement line is already superseded",
                ))
                .with_fix("Choose a line that is effective at the retraction date"));
            }
            if matches!(replacement.entry.verb.as_str(), "retract" | "merge") {
                return Err(anyhow::Error::new(DomainError::invalid(
                    "a replacement cannot be a merge or retract line",
                ))
                .with_fix("Replace a fact with another fact line"));
            }
            if replacement.line_ref == target.line_ref {
                return Err(anyhow::Error::new(DomainError::invalid(
                    "a line cannot replace itself",
                ))
                .with_fix("Choose a different replacement line"));
            }
            Some(replacement.line_ref)
        }
        None => None,
    };
    let retraction = ledger_correction_line(date, &subject, target.line_ref, reason, replacement);
    let mut changes: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    changes
        .entry(month_path(&date))
        .or_default()
        .push(retraction.clone());
    let canonical = format!(
        "retract/v1\nsubject={subject}\ntarget={}\nreason={}\nreplace={}\ndate={date}\n",
        target.line_ref,
        reason,
        replacement.map(|r| r.to_string()).unwrap_or_default()
    );
    if vault.corrections().is_voided(&target.line_ref)
        && !defer_to_write_path(root, cli, &canonical)?
    {
        return Err(anyhow::Error::new(DomainError::already_exists(
            "that line is already retracted",
        ))
        .with_fix("Repeat with the original --request-id, or choose a different line"));
    }
    apply_ledger_correction(
        cli,
        root,
        changes,
        format!("retract {}", target.line_ref.short()),
        canonical,
        serde_json::json!({
            "command": "retract",
            "target": target.line_ref.to_string(),
            "subject": subject.to_string(),
            "reason": reason.as_str(),
            "lines": [retraction],
            "date": date.to_string(),
        }),
        force,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_correct(
    cli: &Cli,
    root: &Path,
    subject_raw: &str,
    line_raw: &str,
    occurrence: Option<u32>,
    replacement_raw: String,
    reason_raw: String,
    date_raw: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    require_spec_04(&vault, "correct")?;
    let subject = RecordId::parse(subject_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!(
            "not a record id: {subject_raw}"
        )))
    })?;
    let target = lookup_line_ref(&vault, line_raw, occurrence)?;
    if target.entry.id != subject {
        return Err(anyhow::Error::new(DomainError::invalid(
            "target line's subject does not match",
        ))
        .with_fix("Use the target line's own subject id"));
    }
    if matches!(target.entry.verb.as_str(), "retract" | "merge") {
        return Err(anyhow::Error::new(DomainError::invalid(
            "merge and retract lines cannot be corrected",
        ))
        .with_fix("Only a fact line can be corrected"));
    }
    let date = parse_date_arg(&date_raw.map(str::to_owned))?;
    if target.entry.date > date {
        return Err(anyhow::Error::new(DomainError::invalid(
            "target line is dated after the correction",
        ))
        .with_fix("Pass a --date on or after the target line's date"));
    }
    let reason = parse_retract_reason(&reason_raw)?;
    let replacement_entry = parse_line(&replacement_raw)
        .map_err(|err| {
            anyhow::Error::new(DomainError::invalid(format!(
                "replacement is not a valid ledger line: {err}"
            )))
            .with_fix("Use a line like `2026-10-08 touch p-<ULID> call`")
        })?
        .ok_or_else(|| {
            anyhow::Error::new(DomainError::invalid(
                "replacement is a blank or comment line, not a fact",
            ))
        })?;
    if replacement_entry.id != subject {
        return Err(anyhow::Error::new(DomainError::invalid(
            "replacement line's subject does not match the target",
        ))
        .with_fix("A correction cannot move a fact between people"));
    }
    if matches!(replacement_entry.verb.as_str(), "retract" | "merge") {
        return Err(anyhow::Error::new(DomainError::invalid(
            "a replacement cannot be a merge or retract line",
        ))
        .with_fix("Replace a fact with another fact line"));
    }
    if replacement_entry.date > date {
        return Err(anyhow::Error::new(DomainError::invalid(
            "replacement line is dated after the correction",
        ))
        .with_fix("Pass a later --date or change the replacement date"));
    }
    if replacement_entry == target.entry {
        return Err(anyhow::Error::new(DomainError::invalid(
            "replacement is identical to the original line",
        ))
        .with_fix("Change the fact, or use `retract` to void it without a replacement"));
    }
    let replacement_text = format_entry(&replacement_entry);
    let fingerprint = line_fingerprint(&replacement_entry);
    let canonical = format!(
        "correct/v1\nsubject={subject}\ntarget={}\nreason={}\nreplacement={replacement_text}\ndate={date}\n",
        target.line_ref,
        reason
    );
    if vault
        .effective_entries()
        .any(|s| line_fingerprint(&s.entry) == fingerprint)
        && !defer_to_write_path(root, cli, &canonical)?
    {
        return Err(anyhow::Error::new(DomainError::already_exists(
            "that replacement line already exists",
        ))
        .with_fix("Use `retract` without a replacement, or change the replacement"));
    }
    if vault.corrections().is_voided(&target.line_ref)
        && !defer_to_write_path(root, cli, &canonical)?
    {
        return Err(anyhow::Error::new(DomainError::already_exists(
            "that line is already retracted",
        ))
        .with_fix("Repeat with the original --request-id, or choose a different line"));
    }
    let occurrence = vault
        .entries
        .iter()
        .filter(|s| line_fingerprint(&s.entry) == fingerprint)
        .count() as u32
        + 1;
    let replacement_ref = LineRef::new(fingerprint, occurrence);
    let retraction = ledger_correction_line(
        date,
        &subject,
        target.line_ref,
        reason,
        Some(replacement_ref),
    );
    let mut changes: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    changes
        .entry(month_path(&replacement_entry.date))
        .or_default()
        .push(replacement_text.clone());
    changes
        .entry(month_path(&date))
        .or_default()
        .push(retraction.clone());
    apply_ledger_correction(
        cli,
        root,
        changes,
        format!("correct {}", target.line_ref.short()),
        canonical,
        serde_json::json!({
            "command": "correct",
            "target": target.line_ref.to_string(),
            "subject": subject.to_string(),
            "reason": reason.as_str(),
            "replacement": replacement_ref.to_string(),
            "lines": [replacement_text, retraction],
            "date": date.to_string(),
        }),
        false,
    )
}

pub(crate) fn cmd_record_retire(
    cli: &Cli,
    root: &Path,
    id_raw: &str,
    retire: bool,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    require_spec_04(
        &vault,
        if retire {
            "record retire"
        } else {
            "record unretire"
        },
    )?;
    let id = RecordId::parse(id_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a record id: {id_raw}")))
    })?;
    if id.prefix() == Prefix::Package {
        return Err(anyhow::Error::new(DomainError::usage(
            "a package is a ledger id, not a record",
        )));
    }
    let canonical = confidant_core::canonical_record_id(&vault, &id);
    if canonical != id {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "{id} is merged into {canonical}"
        )))
        .with_fix(&format!("Retire {canonical} instead")));
    }
    let Some(record) = vault.records.get(&id) else {
        return Err(anyhow::Error::new(DomainError::not_found(format!(
            "no record with id {id_raw}"
        ))));
    };
    if record.is_retired() == retire {
        return finish_write(
            cli,
            root,
            if retire {
                "record-retire"
            } else {
                "record-unretire"
            },
            WriteOutcome::Unchanged,
            serde_json::json!({
                "id": id.to_string(),
                "path": record.path,
                "retired": retire,
            }),
        );
    }
    let mut updated = record.clone();
    if retire {
        updated
            .fields
            .insert("retired".to_owned(), "true".to_owned());
    } else {
        updated.fields.remove("retired");
    }
    let text = confidant_core::format_record(&updated);
    let rel = PathBuf::from(&record.path);
    // The record already loaded and validated from this path; a note may
    // live under `people/<person>/notes/`, which the generic main-path
    // derivation does not know. Writing the existing path keeps every
    // record type (including notes) addressable without a parallel path
    // resolver.
    let pending = PendingWrite {
        changes: vec![FileChange::WriteFile {
            path: rel.clone(),
            contents: text.clone(),
        }],
        summary: if retire {
            format!("record {id} retire")
        } else {
            format!("record {id} unretire")
        },
        canonical_request: format!(
            "{}/v1\npath={}\nbody={text}",
            if retire {
                "record-retire"
            } else {
                "record-unretire"
            },
            rel.display()
        ),
    };
    let outcome = apply_record_write(root, &vault, pending, &write_options(cli))?;
    finish_write(
        cli,
        root,
        if retire {
            "record-retire"
        } else {
            "record-unretire"
        },
        outcome,
        serde_json::json!({
            "id": id.to_string(),
            "path": rel.display().to_string(),
            "retired": retire,
        }),
    )
}
