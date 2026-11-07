//! `record add`, `list`, `show`, `resolve`, `edit`, and merge helpers.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::scratch::{
    resolve_editor, run_editor, setup_edit_scratch, sweep_stale_scratch,
};
use crate::commands::shared::{
    apply_record_write, finish_write, month_path, write_options, OPERATOR_MODE_BANNER,
};
use crate::{
    load_vault_for_reads, ok_envelope, print_error, print_json, resolve_cli_scope, Cli, FixExt,
    Side,
};
use confidant_core::error::DomainError;
use confidant_core::id::{Prefix, RecordId};
use confidant_core::ledger::parse_strict_date;
use confidant_core::record::{main_record_path_with, Record, RecordKind};
use confidant_core::record_type::{RecordSchema, TypeRegistry};
use confidant_core::scope::PackScope;
use confidant_core::write::{FileChange, PendingWrite};
use confidant_core::{CheckOptions, SpecVersion};

/// Parse with the vault's spec and declared types. Writes use this so a 0.3
/// vault can author edge `no-ai` and pack-type records; `require_declared`
/// is true for `record add` and false for edits of an orphaned type.
pub(crate) fn record_schema(
    vault: &confidant_core::Vault,
    require_declared: bool,
) -> RecordSchema<'_> {
    RecordSchema {
        spec: vault.spec_version().unwrap_or(SpecVersion::V02),
        types: Some(vault.type_registry()),
        require_declared,
    }
}

/// #838: refuse a *new* front-matter reference to a retired record.
///
/// `record add` has no previous version, so every reference in the file is
/// new. `record edit` passes the stored record so a reference that was
/// already on disk is grandfathered: a record may have referenced the target
/// before it was retired, and an unrelated edit must not become impossible.
/// The check is therefore "new to this file", not "present in the file", and
/// removing or keeping an existing reference is always allowed.
///
/// Merge-canonicalizes the target first: a reference to a merged-away member
/// of a retired record is a reference to the retired record.
pub(crate) fn refuse_new_retired_references(
    vault: &confidant_core::vault::Vault,
    rec: &Record,
    existing: Option<&Record>,
) -> anyhow::Result<()> {
    let prior: Vec<RecordId> = existing.map(Record::reference_ids).unwrap_or_default();
    for id in rec.reference_ids() {
        if prior.contains(&id) {
            continue;
        }
        let canonical = confidant_core::canonical_record_id(vault, &id);
        if !vault.is_retired(&canonical) {
            continue;
        }
        let target = if canonical == id {
            id.to_string()
        } else {
            format!("{id} (merged into {canonical})")
        };
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "{target} is retired; a new reference to a retired record is refused"
        )))
        .with_fix(&format!(
            "Unretire it first (`confidant record unretire {canonical}`), or reference a live record"
        )));
    }
    Ok(())
}

pub(crate) fn cmd_record_add(cli: &Cli, root: &Path, file: &Path) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    let text = std::fs::read_to_string(file).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            file.display()
        )))
    })?;
    let provisional = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "record.md".to_owned());
    let schema = record_schema(&vault, true);
    let rec = confidant_core::record::parse_record_with_schema(&text, &provisional, &schema)
        .map_err(|e| anyhow::Error::new(DomainError::invalid(e.message).with_fix(e.fix)))?;
    if rec.kind == RecordKind::Note {
        return Err(anyhow::Error::new(DomainError::usage(
            "record add does not create notes; use `confidant note add --body-file`",
        )));
    }
    refuse_new_retired_references(&vault, &rec, None)?;
    if let Some(decl) = vault.type_registry().get(rec.kind.as_str()) {
        if !decl.enabled {
            return Err(anyhow::Error::new(
                DomainError::invalid(format!(
                    "type '{}' belongs to a disabled or removed pack",
                    rec.kind.as_str()
                ))
                .with_fix("Enable the pack that declares this type, or remove the record"),
            ));
        }
    }
    let rel = main_record_path_with(&rec, Some(vault.type_registry()))
        .map_err(|e| anyhow::Error::new(DomainError::invalid(e.message).with_fix(e.fix)))?;
    if root.join(&rel).exists() {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!("{} already exists", rel.display()))
                .with_fix("Pick a fresh id in the record file, or edit the existing record"),
        ));
    }
    let contents = confidant_core::format_record(&rec);
    let id = rec.id.to_string();
    // #179/#505: an interaction mirrors one minimal touchpoint per person
    // involved (date + own id, nothing else) so cadence updates: one for the
    // primary `person:` and one per `with:` participant. A logged interaction
    // therefore counts as contact for everyone on it, while the check rules
    // stay ledger-only. The touchpoints land in the same write (same commit)
    // as the interaction record. The writer validates shape (parse, person
    // prefix, not the primary, no duplicates); existence is `check`'s job
    // (keyed check), like every other front-matter reference.
    let mut touch_lines: Vec<String> = Vec::new();
    let mut touch_change: Option<FileChange> = None;
    if rec.kind == RecordKind::Interaction {
        let primary = rec.person();
        let mut with: Vec<RecordId> = Vec::new();
        if let Some(raw) = rec.field("with") {
            with = confidant_core::record::parse_with_list(raw).ok_or_else(|| {
                anyhow::Error::new(
                    DomainError::invalid(
                        "front matter key 'with' is not a bracketed list of person IDs",
                    )
                    .with_fix("Use with: [p-<ULID>, p-<ULID>]"),
                )
            })?;
            let mut seen: Vec<RecordId> = Vec::new();
            for participant in &with {
                if participant.prefix() != Prefix::Person {
                    return Err(anyhow::Error::new(
                        DomainError::invalid("with: entries must be person ids")
                            .with_fix("Use p-<ULID> ids in with:"),
                    ));
                }
                if Some(participant) == primary.as_ref() {
                    return Err(anyhow::Error::new(
                        DomainError::invalid("with: lists the interaction's own person")
                            .with_fix("Remove the primary person from with:"),
                    ));
                }
                if seen.contains(participant) {
                    return Err(anyhow::Error::new(
                        DomainError::invalid("with: lists the same participant twice")
                            .with_fix("List each participant once in with:"),
                    ));
                }
                seen.push(participant.clone());
            }
        }
        // A `with:` list keeps the hard date requirement (#179). A
        // primary-only interaction mirrors only when it carries a usable
        // date; a dateless one still writes, it just counts as no contact.
        let date = if with.is_empty() {
            rec.field("date").and_then(parse_strict_date)
        } else {
            let date_raw = rec.field("date").ok_or_else(|| {
                anyhow::Error::new(
                    DomainError::invalid(
                        "interaction with with: needs a date (touchpoints are dated)",
                    )
                    .with_fix("Add date: YYYY-MM-DD to the interaction"),
                )
            })?;
            Some(parse_strict_date(date_raw).ok_or_else(|| {
                anyhow::Error::new(DomainError::invalid("interaction date is not YYYY-MM-DD"))
            })?)
        };
        if let Some(date) = date {
            if let Some(primary) = &primary {
                touch_lines.push(format!("{date} touch {primary}"));
            }
            for participant in &with {
                touch_lines.push(format!("{date} touch {participant}"));
            }
            if !touch_lines.is_empty() {
                touch_change = Some(FileChange::AppendLines {
                    path: month_path(&date),
                    lines: touch_lines.clone(),
                });
            }
        }
    }
    let mut changes = vec![FileChange::WriteFile {
        path: rel.clone(),
        contents,
    }];
    if let Some(change) = touch_change {
        changes.push(change);
    }
    let outcome = apply_record_write(
        root,
        &vault,
        PendingWrite {
            changes,
            summary: format!("record {id}"),
            canonical_request: format!("record-add/v1\npath={}\nbody={}", rel.display(), text),
        },
        &write_options(cli),
    )?;
    let mut extra = serde_json::json!({
        "id": id,
        "path": rel.display().to_string(),
    });
    // #179/#505: the mirrored touchpoints (primary first, then `with:`
    // participants), only when any were written.
    if !touch_lines.is_empty() {
        extra["touchpoints"] = serde_json::json!(touch_lines);
    }
    finish_write(cli, root, "record-add", outcome, extra)
}

/// Vault-relative main file path for a record id, derived from its prefix.
///
/// `None` for the prefixes this pair of commands does not handle: a note's
/// file lives at `people/<person>/notes/<id>.md` (not the collection/main
/// layout), and a package has no record file at all.
pub(crate) fn main_path_for(id: &RecordId) -> Option<PathBuf> {
    let prefix = id.prefix();
    if matches!(prefix, Prefix::Note | Prefix::Package) {
        return None;
    }
    Some(PathBuf::from(format!(
        "{}/{}/{}",
        prefix.collection()?,
        id,
        prefix.main_filename()?
    )))
}

/// Ids `record show` / `record edit` / `record resolve` do not handle,
/// refused as usage errors (exit 2, ADR-7) rather than looked up and
/// reported as missing.
///
/// Any `confidant <command>` hint in these messages must name a real
/// subcommand; `prefix_hint_names_an_existing_subcommand` enforces it so a
/// deleted command cannot leave a dead-end hint behind (#542).
pub(crate) fn reject_unsupported_prefix(id: &RecordId) -> anyhow::Result<()> {
    match id.prefix() {
        Prefix::Note => Err(anyhow::Error::new(DomainError::usage(
            "notes are not read or edited by `record`; their files live under people/<person>/notes/",
        ))),
        Prefix::Package => Err(anyhow::Error::new(DomainError::usage(
            "a package is a ledger id, not a record; use `confidant context <person>` to see a person's package balance",
        ))),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// record list (operator-only roster, #558)
// ---------------------------------------------------------------------------

/// #558: list the vault's records of one kind, one entry each.
///
/// Operator-only by construction: `mcp.rs` maps a fixed tool whitelist to
/// argv and this command is not in it, so no agent connection can reach it.
/// Without `--for-operator` the vault loads through the agent read path and
/// the roster is the §12 cleared set, so `no-ai: true` records are absent
/// (never present with a nulled name). With `--for-operator` the operator
/// read path is used (the same mechanism as `record show --for-edit`) and
/// entries carry the tri-state `no_ai`
/// (`"true"` | `"notes"` | `"false"`) the #559 ruling specifies.
pub(crate) fn cmd_record_list(
    cli: &Cli,
    root: &Path,
    kind: &str,
    for_operator: bool,
) -> anyhow::Result<ExitCode> {
    let vault = match load_vault_for_reads(root, cli.json, for_operator) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let vault_path = vault.root.display().to_string();
    if !confidant_core::SpecVersion::is_supported(&vault.config.spec) {
        print_error(
            cli.json,
            Some(&vault_path),
            &DomainError::spec_unsupported(&vault.config.spec),
        )?;
        return Ok(ExitCode::from(1));
    }
    let (scope, scope_names) = match resolve_cli_scope(&vault, cli.packs.as_deref()) {
        Ok(pair) => pair,
        Err(err) => {
            print_error(cli.json, Some(&vault_path), &err)?;
            return Ok(ExitCode::from(err.exit_code() as u8));
        }
    };
    if !confidant_core::roster::is_roster_kind(&vault, kind) {
        let err = DomainError::usage(format!(
            "unknown record kind '{kind}'; use all, person, org, deal, or a declared type"
        ));
        print_error(cli.json, Some(&vault_path), &err)?;
        return Ok(ExitCode::from(err.exit_code() as u8));
    }
    let filter = (kind != "all").then_some(kind);
    let roster = confidant_core::build_roster(&vault, filter, &scope, for_operator);
    if cli.json {
        print_json(&ok_envelope(
            Some(&vault.root),
            serde_json::to_value(&roster)?,
        ))?;
    } else {
        // #572: make operator mode unmistakable on a screen share, like
        // `find` / `context`. Without the flag the output is unchanged.
        if for_operator {
            writeln!(io::stdout(), "{OPERATOR_MODE_BANNER}")?;
        }
        for entry in &roster.records {
            let badge = match entry.no_ai {
                "true" => "\t[no-ai]",
                "notes" => "\t[no-ai: notes]",
                _ => "",
            };
            let orphan = entry
                .orphan
                .as_deref()
                .map(|reason| format!("\t[orphan: {reason}]"))
                .unwrap_or_default();
            let retired = if entry.retired { "\t[retired]" } else { "" };
            // Escape the name so a tab, newline, or terminal escape in a
            // display name cannot break the one-entry-per-line layout
            // (`escape_line` also neutralizes bidi/format characters).
            // `--json` is untouched: there the name is a JSON string.
            writeln!(
                io::stdout(),
                "{}\t{}{badge}{orphan}{retired}",
                entry.id,
                confidant_core::packs::untrusted::escape_line(&entry.name)
            )?;
        }
        let noun = if kind == "person" {
            "people"
        } else {
            "records"
        };
        writeln!(
            io::stdout(),
            "{} {noun} ({})",
            roster.records.len(),
            roster.kind
        )?;
        // A scoped call names the scope that applied (like `context`).
        if matches!(scope, PackScope::Only(_)) && !scope_names.is_empty() {
            writeln!(io::stdout(), "scope: {}", scope_names.join(", "))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// record show (operator-only) / record edit (#216)
// ---------------------------------------------------------------------------

/// #216: print one record's text so the operator can edit it.
///
/// Operator-only by construction: `mcp.rs` maps a fixed tool whitelist to
/// argv and this command is not in it, so no agent connection can reach it.
/// `--for-edit` is required rather than optional so that a bare invocation
/// can never print a record body — the flag is the operator stating the
/// intent to edit.
pub(crate) fn cmd_record_show(
    cli: &Cli,
    root: &Path,
    id_raw: &str,
    for_edit: bool,
) -> anyhow::Result<ExitCode> {
    if !for_edit {
        return Err(anyhow::Error::new(DomainError::usage(
            "record show is operator-only and exists to prepare an edit; pass --for-edit",
        )));
    }
    let vault = match load_vault_for_reads(root, cli.json, true) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    if !confidant_core::SpecVersion::is_supported(&vault.config.spec) {
        return Err(anyhow::Error::new(DomainError::spec_unsupported(
            &vault.config.spec,
        )));
    }
    let id = RecordId::parse(id_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a record id: {id_raw}"))).context(
            "`record show` takes an opaque record id; use `confidant find <name>` to look one up",
        )
    })?;
    reject_unsupported_prefix(&id)?;
    let Some(rec) = vault.records.get(&id) else {
        // A file that is on disk but did not load is a problem with that
        // file; `check` already reports it.
        if let Some(rel) = main_path_for(&id) {
            if std::fs::read(root.join(&rel)).is_ok() {
                return Err(anyhow::Error::new(
                    DomainError::invalid(format!(
                        "cannot read {id_raw}: {} is not a readable record",
                        rel.display()
                    ))
                    .with_fix("Run `confidant check` for the finding on that file"),
                ));
            }
        }
        return Err(anyhow::Error::new(DomainError::not_found(format!(
            "no record with id {id_raw}"
        )))
        .context("use `confidant find <name>` to look up the id"));
    };
    let text = rec.source.clone();
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "id": id.to_string(),
                "type": rec.kind.as_str(),
                "path": rec.path,
                "no_ai": rec.no_ai(),
                "retired": rec.is_retired(),
                "for_edit": true,
                "text": text,
            }),
        ))?;
    } else {
        if rec.is_retired() {
            writeln!(
                io::stderr(),
                "note: this record is retired; it is hidden from agent reads. Use `confidant record unretire {id}` to restore it."
            )?;
        }
        // Byte-for-byte on stdout, so it can be redirected into an editor
        // or a file and edited in place.
        print!("{text}");
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_record_resolve(
    cli: &Cli,
    root: &Path,
    id_raw: &str,
    show: bool,
    take: Option<Side>,
    merged_file: Option<&Path>,
    edit: bool,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    if !confidant_core::SpecVersion::is_supported(&vault.config.spec) {
        return Err(anyhow::Error::new(DomainError::spec_unsupported(
            &vault.config.spec,
        )));
    }
    let id = RecordId::parse(id_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a record id: {id_raw}"))).context(
            "`record resolve` takes an opaque record id; use `confidant find <name>` to look one up",
        )
    })?;
    // Sweep stale `--edit` scratch from a crashed earlier run (CD5). This
    // runs for every resolve action, not just `--edit`. It also runs
    // under `--dry-run`, deliberately: cleaning up zeroed scratch left
    // behind by a previous crashed run is recovery of this command's own
    // local state, not a vault write, and `--dry-run` promises the vault
    // stays untouched, not the scratch dir. (#487 item 1.)
    sweep_stale_scratch(root);
    if show {
        let sides = load_sides(root, &vault, &id)?;
        let ours_text = String::from_utf8_lossy(&sides.ours_bytes);
        let theirs_text = String::from_utf8_lossy(&sides.theirs_bytes);
        if cli.json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "id": id.to_string(),
                    "path": sides.path,
                    "ours": { "label": sides.ours_label, "text": ours_text },
                    "theirs": { "label": sides.theirs_label, "text": theirs_text },
                }),
            ))?;
        } else {
            println!("== ours ({}) ==", sides.ours_label);
            println!("{ours_text}");
            println!("== theirs ({}) ==", sides.theirs_label);
            println!("{theirs_text}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(side) = take {
        // #454: install one side byte for byte, stage it, print the next
        // git step. Both sides were read by `load_sides`, so the
        // operator has seen what they discard (CD7).
        let sides = load_sides(root, &vault, &id)?;
        // #465: `--dry-run` verifies both sides are readable (same
        // CD7 read the real write needs) but writes nothing.
        if cli.dry_run {
            return print_resolve_dry_run(
                cli,
                root,
                &id,
                "take",
                &sides.path,
                ResolveDryRunDetail {
                    side: Some(side.name()),
                    merged_file: None,
                    next: None,
                },
            );
        }
        let outcome = take_side(root, cli.no_input, &sides, side)?;
        if cli.json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "command": "record-resolve",
                    "action": "take",
                    "side": side.name(),
                    "id": id.to_string(),
                    "path": sides.path,
                    "staged": true,
                    "next": outcome.next,
                }),
            ))?;
        } else {
            println!(
                "Kept the {} side of {} ({}); staged.",
                side.name(),
                id,
                sides.path.display()
            );
            println!("Next: {}", outcome.next);
        }
        return Ok(ExitCode::SUCCESS);
    }
    // Only --merged-file/--edit remain; the flags are accepted so the
    // interface does not change when they land.
    if let Some(merged_path) = merged_file {
        // #455: hand-merge from a file outside the vault. The operator's
        // file is validated like `record edit --file` and written
        // through the same path; it is staged, never committed (CD6).
        let sides = load_sides(root, &vault, &id)?;
        // CD5: refuse ANY path inside the vault tree, no `.confidant/`
        // exception, so a plaintext merge file cannot be committed by
        // accident.
        let canonical = refuse_vault_path(root, merged_path)?;
        let text = std::fs::read_to_string(&canonical).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read {}: {e}",
                canonical.display()
            )))
        })?;
        // #473: refuse an unfinished merge before it is written.
        refuse_merged_conflict_markers(&text, &format!("the merged file {}", canonical.display()))
            .map_err(anyhow::Error::new)?;
        let provisional = canonical
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "record.md".to_owned());
        let existing_path = vault
            .records
            .get(&id)
            .map(|record| PathBuf::from(&record.path));
        let prepared = prepare_record_write(
            root,
            PrepareSpec {
                id: &id,
                id_raw,
                text: &text,
                provisional: &provisional,
                summary: format!("record-resolve {id}"),
                canonical_prefix: "record-resolve/v1",
                allow_conflict: true,
                spec: vault.spec_version().unwrap_or(SpecVersion::V02),
                types: Some(vault.type_registry()),
                existing_path: existing_path.as_deref(),
            },
        )?;
        // Defense in depth: the merged record must name the conflicted
        // file's own path.
        if prepared.rel != sides.path {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "the merged record belongs at {}, not {}",
                prepared.rel.display(),
                sides.path.display()
            ))));
        }
        // #465: `--dry-run` runs the full read-only validation above but
        // stops before the install step.
        if cli.dry_run {
            return print_resolve_dry_run(
                cli,
                root,
                &id,
                "merged-file",
                &sides.path,
                ResolveDryRunDetail {
                    side: None,
                    merged_file: Some(&canonical),
                    next: None,
                },
            );
        }
        let outcome = apply_merge(root, cli.no_input, &prepared)?;
        return print_merge_result(cli, root, &id, &outcome);
    }
    if edit {
        // #465: `--dry-run --edit` creates no scratch and installs nothing;
        // `load_sides` is the same conflict read the real edit would do.
        if cli.dry_run {
            let sides = load_sides(root, &vault, &id)?;
            return print_resolve_dry_run(
                cli,
                root,
                &id,
                "edit",
                &sides.path,
                ResolveDryRunDetail {
                    side: None,
                    merged_file: None,
                    next: None,
                },
            );
        }
        return cmd_resolve_edit(cli, root, &vault, &id, id_raw);
    }
    // Unreachable: clap's ArgGroup requires exactly one resolve action.
    Err(anyhow::Error::new(DomainError::usage(
        "choose one of --show, --take, --merged-file, --edit",
    )))
}

pub(crate) fn print_merge_result(
    cli: &Cli,
    root: &Path,
    id: &RecordId,
    outcome: &MergeOutcome,
) -> anyhow::Result<ExitCode> {
    if cli.json {
        let obj = serde_json::json!({
            "command": "record-resolve",
            "action": "merge",
            "id": id.to_string(),
            "path": outcome.path,
            "staged": true,
            "next": outcome.next,
        });
        print_json(&ok_envelope(Some(root), obj))?;
    } else {
        println!("Merged {} ({}); staged.", id, outcome.path.display());
        println!("Next: {}", outcome.next);
    }
    Ok(ExitCode::SUCCESS)
}

/// #465: report what a `record resolve` write action would do instead of
/// doing it, when the global `--dry-run` flag is set.
///
/// Callers reach this only after read-only validation (`load_sides`,
/// `refuse_vault_path`, reading `--merged-file`, `prepare_record_write`):
/// the dry run fails the same way the real run would, and by this point
/// nothing has been written — no vault file, no index entry, no scratch
/// (CD6: stage only, never commit — here not even that).
pub(crate) struct ResolveDryRunDetail<'a> {
    /// `--take <side>`: the side spelling as printed elsewhere.
    side: Option<&'a str>,
    /// `--merged-file`: the operator's local file (outside the vault).
    merged_file: Option<&'a Path>,
    /// A follow-up command the real run would suggest.
    next: Option<&'a str>,
}

pub(crate) fn print_resolve_dry_run(
    cli: &Cli,
    root: &Path,
    id: &RecordId,
    action: &str,
    path: &Path,
    detail: ResolveDryRunDetail<'_>,
) -> anyhow::Result<ExitCode> {
    if cli.json {
        let mut obj = serde_json::json!({
            "command": "record-resolve",
            "dry_run": true,
            "action": action,
            "id": id.to_string(),
            "path": path,
            "staged": false,
        });
        let o = obj.as_object_mut().expect("json object literal");
        if let Some(side) = detail.side {
            o.insert("side".into(), serde_json::json!(side));
        }
        if let Some(merged_file) = detail.merged_file {
            o.insert(
                "merged_file".into(),
                serde_json::json!(merged_file.display().to_string()),
            );
        }
        if let Some(next) = detail.next {
            o.insert("next".into(), serde_json::json!(next));
        }
        print_json(&ok_envelope(Some(root), obj))?;
    } else {
        // Text mirrors the real action's wording; `nothing changed` is the
        // operator-visible gap versus a real run.
        if action == "take" && detail.side == Some("ours") {
            println!(
                "dry run — would keep the current version of {} ({}); nothing changed.",
                id,
                path.display()
            );
        } else if action == "take" {
            println!(
                "dry run — would keep the {} side of {} ({}); nothing changed.",
                detail.side.unwrap_or("?"),
                id,
                path.display()
            );
        } else if action == "merged-file" {
            println!(
                "dry run — would install {} into {} ({}); nothing changed.",
                detail
                    .merged_file
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                id,
                path.display()
            );
        } else {
            println!(
                "dry run — would open the merge for {} ({}) in an editor; nothing changed.",
                id,
                path.display()
            );
        }
        if let Some(next) = detail.next {
            println!("Next: {next}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// #455: `record resolve <id> --edit` — hand-merge in the operator's
/// editor with 0600 scratch files under `.confidant/conflicts/<id>/`.
///
/// Both sides are copied to scratch (CD7 already held by `load_sides`);
/// `merged.md` is pre-filled with the ours text. After the editor
/// exits, the merged text goes through the shared validate → stage path.
/// Scratch is zero-overwritten and removed on every exit path
/// via `ScratchGuard` (explicit on success, drop on error).
pub(crate) fn cmd_resolve_edit(
    cli: &Cli,
    root: &Path,
    _vault: &confidant_core::vault::Vault,
    id: &RecordId,
    id_raw: &str,
) -> anyhow::Result<ExitCode> {
    let sides = load_sides(root, _vault, id)?;
    // Fail fast if no editor is configured, before creating any scratch
    // files (which would hold plaintext).
    resolve_editor()?;
    let (mut guard, merged_path) = setup_edit_scratch(root, id, &sides)?;
    // An editor failure returns here; the guard drops and cleans up.
    run_editor(&merged_path)?;
    let text = std::fs::read_to_string(&merged_path).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            merged_path.display()
        )))
    })?;
    // #473: refuse an unfinished merge before it is installed. The
    // guard is dropped by the `?`, cleaning the scratch up.
    refuse_merged_conflict_markers(
        &text,
        &format!("the merged record from {}", merged_path.display()),
    )
    .map_err(anyhow::Error::new)?;
    let existing_path = _vault
        .records
        .get(id)
        .map(|record| PathBuf::from(&record.path));
    let prepared = prepare_record_write(
        root,
        PrepareSpec {
            id,
            id_raw,
            text: &text,
            provisional: "merged.md",
            summary: format!("record-resolve {id}"),
            canonical_prefix: "record-resolve/v1",
            allow_conflict: true,
            spec: _vault.spec_version().unwrap_or(SpecVersion::V02),
            types: Some(_vault.type_registry()),
            existing_path: existing_path.as_deref(),
        },
    )?;
    if prepared.rel != sides.path {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "the merged record belongs at {}, not {}",
            prepared.rel.display(),
            sides.path.display()
        ))));
    }
    let outcome = apply_merge(root, cli.no_input, &prepared)?;
    // Explicit cleanup on the success path (drop after is a no-op).
    guard.cleanup();
    print_merge_result(cli, root, id, &outcome)
}

/// Parameters for [`prepare_record_write`], bundled to keep the
/// argument count within clippy's limit.
pub(crate) struct PrepareSpec<'a> {
    /// The parsed record id.
    pub id: &'a RecordId,
    /// The raw id string, for error messages (preserves user spelling).
    pub id_raw: &'a str,
    /// The new record text (merged plaintext).
    pub text: &'a str,
    /// Filename used in parse error messages.
    pub provisional: &'a str,
    /// Summary for the planned write (e.g. `"record {id}"`).
    pub summary: String,
    /// Prefix for the idempotency canonical request (e.g. `"record-edit/v1"`).
    pub canonical_prefix: &'a str,
    /// Whether the existing file may have conflict markers. `record edit`
    /// refuses them (they must be resolved first); the resolve path
    /// expects them. The check runs before the no-ai restamp planning,
    /// which cannot read a conflicted file (#412 Q6).
    pub allow_conflict: bool,
    /// Vault spec for edge `no-ai` and other format-version rules.
    pub spec: SpecVersion,
    /// Declared types for pack-type records.
    pub types: Option<&'a TypeRegistry>,
    /// Existing path, used to edit an orphan/retired type whose declaration
    /// is no longer in the registry.
    pub existing_path: Option<&'a Path>,
}

/// The validated record and its planned write, shared by `record edit` and
/// `record resolve --merged-file` / `--edit` (#455).
///
/// `pending` holds the `WriteFile` changes (the record itself, plus #410
/// child re-stamps for a person whose `no-ai` mode changed). The caller
/// applies it: `cmd_record_edit` via [`apply_record_write_inner`] (which
/// commits), the resolve path by staging each change
/// without committing (CD6).
pub(crate) struct PreparedWrite {
    /// The write to apply.
    pub pending: PendingWrite,
    /// Vault-relative path of the record file.
    pub rel: PathBuf,
    /// The parsed record.
    pub rec: Record,
}

/// Validate `text` as the new contents of record `id` and plan the write.
///
/// Shared by `record edit` and `record resolve --merged-file` / `--edit`
/// (#455): parses the record, checks the id, validates `with:` lists,
/// derives the record path (which must already exist), formats the
/// canonical contents, and plans the #410 no-ai re-stamp for persons.
///
/// Does not read the existing file and does not apply the write. The
/// caller does its own fail-closed checks on the stored bytes first:
/// `cmd_record_edit`'s ladder (conflict markers, front-matter identity),
/// or the resolve path's `load_sides`
/// (which already verified the conflict and read both sides, CD7).
///
/// `provisional` is the filename used in parse error messages;
/// `summary` and `canonical_prefix` label the planned write (e.g.
/// `"record {id}"` / `"record-edit/v1"` for edit).
pub(crate) fn prepare_record_write(
    root: &Path,
    spec: PrepareSpec<'_>,
) -> anyhow::Result<PreparedWrite> {
    let PrepareSpec {
        id,
        id_raw,
        text,
        provisional,
        summary,
        canonical_prefix,
        allow_conflict,
        spec,
        types,
        existing_path,
    } = spec;
    let rec = confidant_core::record::parse_record_with_schema(
        text,
        provisional,
        &RecordSchema {
            spec,
            types,
            require_declared: false,
        },
    )
    .map_err(|e| anyhow::Error::new(DomainError::invalid(e.message).with_fix(e.fix)))?;
    if rec.id != *id {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!("the file's id is {}, not {id_raw}", rec.id))
                .with_fix("Edit the record the file names, or fix `id:` in the file"),
        ));
    }
    // `record add` validates `with:` shape before writing, and an edit
    // must too: a malformed list would be committed and later
    // block downstream reads. Touchpoints are not mirrored on an edit — see
    // the PR notes.
    if rec.kind == RecordKind::Interaction {
        if let Some(raw) = rec.field("with") {
            let with = confidant_core::record::parse_with_list(raw).ok_or_else(|| {
                anyhow::Error::new(
                    DomainError::invalid(
                        "front matter key 'with' is not a bracketed list of person IDs",
                    )
                    .with_fix("Use with: [p-<ULID>, p-<ULID>]"),
                )
            })?;
            let primary = rec.person();
            let mut seen: Vec<RecordId> = Vec::new();
            for participant in &with {
                if participant.prefix() != Prefix::Person {
                    return Err(anyhow::Error::new(
                        DomainError::invalid("with: entries must be person ids")
                            .with_fix("Use p-<ULID> ids in with:"),
                    ));
                }
                if Some(participant) == primary.as_ref() {
                    return Err(anyhow::Error::new(
                        DomainError::invalid("with: lists the interaction's own person")
                            .with_fix("Remove the primary person from with:"),
                    ));
                }
                if seen.contains(participant) {
                    return Err(anyhow::Error::new(
                        DomainError::invalid("with: lists the same participant twice")
                            .with_fix("List each participant once in with:"),
                    ));
                }
                seen.push(participant.clone());
            }
        }
    }
    let rel = match main_record_path_with(&rec, types) {
        Ok(path) => path,
        Err(err) => {
            if let Some(existing) = existing_path {
                existing.to_path_buf()
            } else {
                return Err(anyhow::Error::new(
                    DomainError::invalid(err.message).with_fix(err.fix),
                ));
            }
        }
    };
    if !root.join(&rel).exists() {
        return Err(anyhow::Error::new(
            DomainError::not_found(format!("no record file at {}", rel.display()))
                .with_fix("Use `confidant record add --file` to create a new record"),
        ));
    }
    // `record edit` refuses a conflicted file (it must be resolved first);
    // the resolve path expects a conflict and skips this.
    if !allow_conflict {
        let existing = std::fs::read_to_string(root.join(&rel)).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read {}: {e}",
                rel.display()
            )))
        })?;
        if confidant_core::record::has_conflict_markers(&existing) {
            return Err(anyhow::Error::new(
                DomainError::invalid(format!(
                    "{} has unresolved merge conflicts; resolve them before editing",
                    rel.display()
                ))
                .with_fix("Resolve the conflict markers (git mergetool), then re-run the edit"),
            ));
        }
    }
    let contents = confidant_core::format_record(&rec);
    Ok(PreparedWrite {
        pending: PendingWrite {
            changes: vec![FileChange::WriteFile {
                path: rel.clone(),
                contents,
            }],
            summary,
            canonical_request: format!("{canonical_prefix}\npath={}\nbody={}", rel.display(), text),
        },
        rel,
        rec,
    })
}

/// #216: replace an existing main record's file from a markdown file.
///
/// The write goes through [`apply_record_write`], so it runs `check` before
/// the commit and makes one commit — exactly like `record add`. The target
/// path is derived from the record's
/// id, never from the path the caller passed, and the file's own `id:` must
/// match the id argument so a wrong file cannot silently clobber a record.
pub(crate) fn cmd_record_edit(
    cli: &Cli,
    root: &Path,
    id_raw: &str,
    file: &Path,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    // Parse the id the same way every other positional record id is parsed:
    // a malformed argument is a usage error (exit 2, ADR-7), and parsing
    // canonicalises a lowercase ULID instead of rejecting it.
    let id = RecordId::parse(id_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a record id: {id_raw}"))).context(
            "`record edit` takes an opaque record id; use `confidant find <name>` to look one up",
        )
    })?;
    reject_unsupported_prefix(&id)?;
    let text = std::fs::read_to_string(file).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            file.display()
        )))
    })?;
    let provisional = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "record.md".to_owned());
    // Shared validation + write planning (#455). The fail-closed ladder
    // below is edit-specific: the resolve path already verified the
    // conflict and read both sides via `load_sides` (CD7).
    let existing_path = vault
        .records
        .get(&id)
        .map(|record| PathBuf::from(&record.path));
    let prepared = prepare_record_write(
        root,
        PrepareSpec {
            id: &id,
            id_raw,
            text: &text,
            provisional: &provisional,
            summary: format!("record {id}"),
            canonical_prefix: "record-edit/v1",
            allow_conflict: false,
            spec: vault.spec_version().unwrap_or(SpecVersion::V02),
            types: Some(vault.type_registry()),
            existing_path: existing_path.as_deref(),
        },
    )?;
    let rec = &prepared.rec;
    let rel = &prepared.rel;
    let id_str = rec.id.to_string();
    // #838: a *new* reference to a retired record is refused; references
    // already in the stored file are grandfathered so an unrelated edit
    // still works.
    refuse_new_retired_references(&vault, rec, vault.records.get(&id))?;
    let outcome = apply_record_write(root, &vault, prepared.pending, &write_options(cli))?;
    let extra = serde_json::json!({
        "id": id_str,
        "path": rel.display().to_string(),
    });
    finish_write(cli, root, "record-edit", outcome, extra)
}

// ---------------------------------------------------------------------------
// merge-conflict resolution plumbing (plaintext)
// ---------------------------------------------------------------------------

/// Both sides of a conflicted record, reconstructed from the file's git
/// conflict markers (#451).
pub(crate) struct LoadedSides {
    /// Vault-relative path of the conflicted file.
    pub path: PathBuf,
    /// The `<<<<<<<` side, byte-exact.
    pub ours_bytes: Vec<u8>,
    /// The `>>>>>>>` side, byte-exact.
    pub theirs_bytes: Vec<u8>,
    /// The conflicted file's bytes as read (for rollback).
    pub raw: Vec<u8>,
    /// Label from the first hunk's `<<<<<<<` line (e.g. `HEAD`).
    pub ours_label: String,
    /// Label from the first hunk's `>>>>>>>` line (e.g. `feature/x`).
    pub theirs_label: String,
}

/// Load both sides of the conflicted record `id`.
///
/// The file path is derived from the id (never trusting a caller-supplied
/// path). Both sides must parse as records naming `id` with equal `type`.
pub(crate) fn load_sides(
    root: &Path,
    vault: &confidant_core::Vault,
    id: &RecordId,
) -> anyhow::Result<LoadedSides> {
    reject_unsupported_prefix(id)?;
    let rel = vault
        .records
        .get(id)
        .map(|record| PathBuf::from(&record.path))
        .or_else(|| main_path_for(id))
        .ok_or_else(|| {
            anyhow::Error::new(DomainError::usage(format!(
                "record resolve does not handle ids like {id}"
            )))
        })?;
    let bytes = std::fs::read(root.join(&rel)).map_err(|_| {
        anyhow::Error::new(DomainError::not_found(format!("no record with id {id}")))
            .context("use `confidant find <name>` to look up the id")
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        anyhow::Error::new(DomainError::invalid(format!(
            "{} is not valid UTF-8",
            rel.display()
        )))
    })?;
    if !confidant_core::record::has_conflict_markers(text) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!("{} has no merge conflict", rel.display()))
                .with_fix("Use `confidant record show --for-edit` to read it"),
        ));
    }
    let sides = confidant_core::conflict::split_conflict_sides(text).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot split the conflict in {}: {e}",
            rel.display()
        )))
    })?;
    let schema = record_schema(vault, false);
    let ours = parse_side("ours", &sides.ours, &rel, id, &schema)?;
    let theirs = parse_side("theirs", &sides.theirs, &rel, id, &schema)?;
    if ours.kind != theirs.kind {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "the two sides of {} have different record types",
            rel.display()
        ))));
    }
    Ok(LoadedSides {
        path: rel,
        ours_bytes: sides.ours.into_bytes(),
        theirs_bytes: sides.theirs.into_bytes(),
        raw: bytes,
        ours_label: sides.ours_label,
        theirs_label: sides.theirs_label,
    })
}

/// Parse one reconstructed side as a record naming `id`.
pub(crate) fn parse_side(
    side: &str,
    text: &str,
    rel: &Path,
    id: &RecordId,
    schema: &RecordSchema<'_>,
) -> anyhow::Result<Record> {
    let rec =
        confidant_core::record::parse_record_with_schema(text, &rel.display().to_string(), schema)
            .map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "the {side} side of {} is not a readable record: {}",
                    rel.display(),
                    e.message
                )))
            })?;
    if rec.id != *id {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "the {side} side of {} holds a different record ({})",
            rel.display(),
            rec.id
        ))));
    }
    Ok(rec)
}

/// Outcome of `record resolve --take`.
#[derive(Debug)]
pub(crate) struct TakeOutcome {
    /// The next git step for the operator, e.g. `git merge --continue`.
    pub next: String,
}

/// Install one side byte for byte, verify the vault still checks clean for
/// this path, stage the file, and return the next git step.
pub(crate) fn take_side(
    root: &Path,
    no_input: bool,
    sides: &LoadedSides,
    side: Side,
) -> anyhow::Result<TakeOutcome> {
    let chosen: &[u8] = match side {
        Side::Ours => &sides.ours_bytes,
        Side::Theirs => &sides.theirs_bytes,
    };
    let rel = &sides.path;
    confidant_core::paths::write_replace(root, rel, chosen).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "could not install the {} side of {}: {e}",
            side.name(),
            rel.display()
        )))
    })?;

    if let Err(failure) = check_path_clean(root, rel) {
        let _ = confidant_core::paths::write_replace(root, rel, &sides.raw);
        return Err(failure);
    }

    if let Err(e) =
        confidant_core::write::git(root, &["add", "--", &rel.to_string_lossy()], no_input)
    {
        let _ = confidant_core::paths::write_replace(root, rel, &sides.raw);
        return Err(anyhow::Error::new(DomainError::internal(format!(
            "could not stage {}: {e}",
            rel.display()
        ))));
    }

    Ok(TakeOutcome {
        next: next_git_step(root),
    })
}

/// Reload the vault and require no error finding on `rel`.
pub(crate) fn check_path_clean(root: &Path, rel: &Path) -> anyhow::Result<()> {
    let vault = confidant_core::load_vault(root).map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "could not reload the vault after installing {}: {e}",
            rel.display()
        )))
    })?;
    let report = confidant_core::check_vault(&vault, &CheckOptions::default());
    let rel_str = rel.to_string_lossy();
    if let Some(finding) = report.findings.iter().find(|f| {
        f.severity == confidant_core::Severity::Error && f.file.as_deref() == Some(rel_str.as_ref())
    }) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "installing the chosen side left {} with an error: {}",
                rel.display(),
                finding.message
            ))
            .with_fix("The conflicted file was restored; fix the underlying problem and retry"),
        ));
    }
    Ok(())
}

/// The next git step for the operator: `git merge --continue` while a merge
/// is in progress, `git rebase --continue` while a rebase is.
pub(crate) fn next_git_step(root: &Path) -> String {
    let git_dir = confidant_core::write::git(root, &["rev-parse", "--git-dir"], true)
        .map(|s| root.join(s.trim()))
        .unwrap_or_else(|_| root.join(".git"));
    if git_dir.join("MERGE_HEAD").exists() {
        "git merge --continue".to_owned()
    } else if git_dir.join("rebase-merge").exists() || git_dir.join("rebase-apply").exists() {
        "git rebase --continue".to_owned()
    } else if git_dir.join("CHERRY_PICK_HEAD").exists() {
        "git cherry-pick --continue".to_owned()
    } else {
        "git commit".to_owned()
    }
}

/// Outcome of `record resolve --merged-file` / `--edit`.
#[derive(Debug)]
pub(crate) struct MergeOutcome {
    /// The next git step for the operator.
    pub next: String,
    /// Vault-relative path of the resolved record.
    pub path: PathBuf,
}

/// Refuse to install merged text that still contains conflict markers.
///
/// The error names the first offending marker and its line number, never
/// the line's content: the merged text is operator plaintext and must not
/// reach logs or error output (rule 4).
pub(crate) fn refuse_merged_conflict_markers(text: &str, source: &str) -> Result<(), DomainError> {
    for (n, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let marker = if trimmed.starts_with("<<<<<<<") {
            "<<<<<<<"
        } else if trimmed.starts_with(">>>>>>>") {
            ">>>>>>>"
        } else if trimmed == "=======" {
            "======="
        } else {
            continue;
        };
        return Err(DomainError::usage(format!(
            "{source} still contains a conflict marker ({marker} at line {})",
            n + 1
        ))
        .with_fix(
            "Remove the conflict markers — keep the text you merged — then re-run the command",
        ));
    }
    Ok(())
}

/// The operator's merged file must live outside the vault so a plaintext
/// merge file cannot be committed by accident.
pub(crate) fn refuse_vault_path(root: &Path, path: &Path) -> anyhow::Result<PathBuf> {
    let canonical = path.canonicalize().map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            path.display()
        )))
    })?;
    let canonical_root = root.canonicalize().map_err(|e| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot resolve vault root {}: {e}",
            root.display()
        )))
    })?;
    if canonical.starts_with(&canonical_root) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "refusing to read a merge file inside the vault: {}",
                path.display()
            ))
            .with_fix("Put the merged file outside the vault tree"),
        ));
    }
    Ok(canonical)
}

/// Apply a merged record (#455): write each planned change atomically,
/// verify no error finding on any changed path (rolling everything back on
/// failure), then stage every changed path.
pub(crate) fn apply_merge(
    root: &Path,
    no_input: bool,
    prepared: &PreparedWrite,
) -> anyhow::Result<MergeOutcome> {
    let mut originals: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for change in &prepared.pending.changes {
        let FileChange::WriteFile { path, .. } = change else {
            continue;
        };
        let bytes = std::fs::read(root.join(path)).unwrap_or_default();
        originals.push((path.clone(), bytes));
    }

    for change in &prepared.pending.changes {
        let FileChange::WriteFile { path, contents } = change else {
            continue;
        };
        confidant_core::paths::write_replace(root, path, contents.as_bytes()).map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "could not write {}: {e}",
                path.display()
            )))
        })?;
    }

    let mut failed: Option<anyhow::Error> = None;
    for (path, _) in &originals {
        if let Err(e) = check_path_clean(root, path) {
            failed = Some(e);
            break;
        }
    }
    if let Some(e) = failed {
        for (path, bytes) in &originals {
            let _ = confidant_core::paths::write_replace(root, path, bytes);
        }
        return Err(e);
    }

    for (path, _) in &originals {
        if let Err(e) =
            confidant_core::write::git(root, &["add", "--", &path.to_string_lossy()], no_input)
        {
            for (p, b) in &originals {
                let _ = confidant_core::paths::write_replace(root, p, b);
            }
            return Err(anyhow::Error::new(DomainError::internal(format!(
                "could not stage {}: {e}",
                path.display()
            ))));
        }
    }

    Ok(MergeOutcome {
        next: next_git_step(root),
        path: prepared.rel.clone(),
    })
}
