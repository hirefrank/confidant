//! `note add`, `note show`, `note edit`.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::scratch::{
    resolve_editor, run_note_editor, setup_note_edit_scratch, sweep_stale_note_scratch,
};
use crate::commands::shared::{
    announce_resolved_person, apply_record_write, finish_write, parse_date_arg, resolve_person_arg,
    write_options,
};
use crate::{load_vault_for_reads, ok_envelope, print_json, Cli, FixExt};
use confidant_core::error::DomainError;
use confidant_core::id::{Prefix, RecordId};
use confidant_core::record::{Record, RecordKind};
use confidant_core::write::{FileChange, PendingWrite};

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_note_add(
    cli: &Cli,
    root: &Path,
    person_raw: Option<&str>,
    entity_raw: Option<&str>,
    date_raw: Option<String>,
    no_ai: bool,
    forced_id: Option<&str>,
    body_file: &Path,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    let date = parse_date_arg(&date_raw)?;
    let body = std::fs::read_to_string(body_file).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            body_file.display()
        )))
    })?;
    let (subject_id, subject_kind, subject_name) = match (person_raw, entity_raw) {
        (Some(person_raw), None) => {
            let person = resolve_person_arg(root, &vault, person_raw)?;
            announce_resolved_person(cli, &person);
            (
                person.id.clone(),
                "person",
                Some(person.matched_name.clone()),
            )
        }
        (None, Some(entity_raw)) => {
            let id = RecordId::parse(entity_raw).map_err(|_| {
                anyhow::Error::new(DomainError::usage(format!(
                    "not an entity id: {entity_raw}"
                )))
            })?;
            let Some(decl) = vault.type_registry().get_by_prefix(id.prefix()) else {
                return Err(anyhow::Error::new(DomainError::invalid(format!(
                    "no entity with id {entity_raw}"
                ))));
            };
            if !decl.entity || !decl.enabled {
                return Err(anyhow::Error::new(DomainError::invalid(format!(
                    "type does not accept entity notes: {entity_raw}"
                ))));
            }
            if vault.is_retired(&id) {
                return Err(
                    anyhow::Error::new(DomainError::invalid(format!("{id} is retired")))
                        .with_fix("Run `confidant record unretire <id>` before adding notes"),
                );
            }
            if !vault.records.contains_key(&id) {
                return Err(anyhow::Error::new(DomainError::not_found(format!(
                    "no record with id {id}"
                ))));
            }
            (id, "entity", None)
        }
        _ => {
            return Err(anyhow::Error::new(DomainError::usage(
                "pass exactly one of --person or --entity",
            )))
        }
    };

    // #611: the TUI passes the manifest's own note id so the reviewed
    // dry-run and the commit name the same note. Without `--id` the id is
    // minted here, exactly as before.
    let nid = match forced_id {
        Some(raw) => parse_note_id(raw, "note add")?,
        None => RecordId::new(Prefix::Note, confidant_core::write::new_ulid())
            .map_err(|e| anyhow::anyhow!("generated bad note id: {e}"))?,
    };
    let rel = if subject_kind == "person" {
        PathBuf::from(format!("people/{subject_id}/notes/{nid}.md"))
    } else {
        PathBuf::from(format!("notes/{nid}/note.md"))
    };
    let subject_key = if subject_kind == "person" {
        "person"
    } else {
        "entity"
    };
    let mut fields = BTreeMap::from([
        (subject_key.to_owned(), subject_id.to_string()),
        ("date".to_owned(), date.to_string()),
    ]);
    if no_ai {
        fields.insert("no-ai".to_owned(), "true".to_owned());
    }
    let rec = Record {
        id: nid.clone(),
        kind: RecordKind::Note,
        path: rel.display().to_string(),
        name: None,
        fields,
        body: body.clone(),
        source: String::new(),
        body_start_line: 0,
        field_lines: BTreeMap::new(),
    };
    let canonical_request =
        format!("note-add/v1\n{subject_key}={subject_id}\ndate={date}\nno_ai={no_ai}\nbody={body}");
    // A forced id must not overwrite an existing note. A genuine retry
    // (progress file lost after the commit) is recognized by its
    // request-id trailer, and apply_write reports it idempotent; only an
    // id we cannot account for refuses. A minted id is unique by
    // construction, so this only runs for `--id`.
    if forced_id.is_some() {
        ensure_note_target_free(root, &rel, &nid, cli, &canonical_request)?;
    }
    let outcome = apply_record_write(
        root,
        &vault,
        PendingWrite {
            changes: vec![FileChange::WriteFile {
                path: rel.clone(),
                contents: confidant_core::format_record(&rec),
            }],
            summary: format!("note {subject_id} {nid}"),
            canonical_request,
        },
        &write_options(cli),
    )?;
    let mut extra = serde_json::json!({
        "id": nid.to_string(),
        "path": rel.display().to_string(),
    });
    if subject_kind == "person" {
        if let Some(name) = subject_name {
            extra["person"] = serde_json::json!({"id": subject_id.to_string(), "name": name});
        }
    } else {
        extra["entity"] = serde_json::json!(subject_id.to_string());
    }
    finish_write(cli, root, "note-add", outcome, extra)
}

/// Refuse a forced note id whose target already exists, unless this exact
/// request already committed it (then the write pipeline reports it
/// idempotent and never rewrites). `--id` exists for the TUI's #611
/// dry-run→apply binding; a collision means a stale or hand-edited
/// manifest, which must not silently overwrite a note.
pub(crate) fn ensure_note_target_free(
    root: &Path,
    rel: &Path,
    nid: &RecordId,
    cli: &Cli,
    canonical_request: &str,
) -> anyhow::Result<()> {
    if !confidant_core::paths::exists(root, rel)? {
        return Ok(());
    }
    let opts = write_options(cli);
    if let Some(rid) = opts.request_id.as_deref() {
        let (id_hash, _) = confidant_core::write::idempotency_digests(rid, canonical_request);
        if confidant_core::write::find_request_commit(root, &id_hash, opts.no_input)?.is_some() {
            return Ok(());
        }
    }
    Err(anyhow::Error::new(
        DomainError::already_exists(format!("note {nid} already exists at {}", rel.display()))
            .with_fix("Pick a fresh note id, or edit the existing note with `confidant note edit`"),
    ))
}

// ---------------------------------------------------------------------------
// note show (operator-only) / note edit (#557)
// ---------------------------------------------------------------------------

/// Parse a positional note id: a usage error (exit 2, ADR-7) for a
/// malformed id or a non-note prefix. `verb` labels the error context.
pub(crate) fn parse_note_id(id_raw: &str, verb: &str) -> anyhow::Result<RecordId> {
    let id = RecordId::parse(id_raw).map_err(|_| {
        anyhow::Error::new(DomainError::usage(format!("not a note id: {id_raw}"))).context(format!(
            "`{verb}` takes an opaque note id; use `confidant find <name>` to look one up"
        ))
    })?;
    if id.prefix() != Prefix::Note {
        return Err(anyhow::Error::new(DomainError::usage(format!(
            "not a note id: {id_raw}"
        ))));
    }
    Ok(id)
}

/// Vault-relative path of a note file under `people/<person>/notes/` when
/// the loaded vault has no record for it, located by scanning the owner
/// directories. `None` when no note file matches. Used to tell an
/// unreadable note apart from a missing one in the error, never to derive
/// a write target.
pub(crate) fn note_path_for(root: &Path, id: &RecordId) -> Option<PathBuf> {
    let file = format!("{id}.md");
    let people = std::fs::read_dir(root.join("people")).ok()?;
    for entry in people.flatten() {
        if entry.path().join("notes").join(&file).is_file() {
            return Some(PathBuf::from(format!(
                "people/{}/notes/{file}",
                entry.file_name().to_string_lossy()
            )));
        }
    }
    None
}

/// Fail-closed error for a note id whose file exists on disk but did not
/// load. Mirrors `record show`'s ladder; never names the body.
pub(crate) fn note_unreadable_error(id_raw: &str, rel: &Path, _bytes: &[u8]) -> anyhow::Error {
    anyhow::Error::new(
        DomainError::invalid(format!(
            "cannot read {id_raw}: {} is not a readable note",
            rel.display()
        ))
        .with_fix("Run `confidant check` for the finding on that file"),
    )
}

pub(crate) fn note_plaintext(root: &Path, _vault_id: &str, rel: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| {
        anyhow::Error::new(DomainError::invalid(format!(
            "cannot read {}: {e}",
            rel.display()
        )))
    })
}

pub(crate) fn cmd_note_show(
    cli: &Cli,
    root: &Path,
    id_raw: &str,
    for_edit: bool,
) -> anyhow::Result<ExitCode> {
    if !for_edit {
        return Err(anyhow::Error::new(DomainError::usage(
            "note show is operator-only and exists to prepare an edit; pass --for-edit",
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
    let id = parse_note_id(id_raw, "note show")?;
    let Some(rec) = vault.records.get(&id) else {
        // A file that is on disk but did not load is a problem with that
        // file (as `record show` treats it).
        if let Some(rel) = note_path_for(root, &id) {
            if let Ok(bytes) = std::fs::read(root.join(&rel)) {
                return Err(note_unreadable_error(id_raw, &rel, &bytes));
            }
        }
        return Err(anyhow::Error::new(DomainError::not_found(format!(
            "no note with id {id_raw}"
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

/// #557: replace an existing note's file from `--file` or the editor.
///
/// The write goes through [`apply_record_write`], so it runs `check` before
/// the commit and makes one commit — exactly like `record edit`; an
/// unchanged body reports `unchanged` with no commit. The
/// target path is the note's existing location, never a path the caller or
/// the edited text chose: a note's `person:` must keep matching its
/// directory (a change would silently re-home the note, so it is refused
/// before the write).
pub(crate) fn cmd_note_edit(
    cli: &Cli,
    root: &Path,
    id_raw: &str,
    file: Option<&Path>,
    edit: bool,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    if !confidant_core::SpecVersion::is_supported(&vault.config.spec) {
        return Err(anyhow::Error::new(DomainError::spec_unsupported(
            &vault.config.spec,
        )));
    }
    let id = parse_note_id(id_raw, "note edit")?;
    // Sweep stale `--edit` scratch from a crashed earlier run (#455
    // convention). Harmless for a `--file` edit and for a dry run: it only
    // zero-overwrites and removes `.confidant/notes/`.
    sweep_stale_note_scratch(root);
    // Pin the existing file first: the edit can never move the note. A note
    // that is on disk but did not load is reported for what it is rather
    // than as missing.
    let rel = match vault.records.get(&id) {
        Some(rec) if rec.kind == RecordKind::Note => PathBuf::from(&rec.path),
        Some(_) => {
            return Err(anyhow::Error::new(DomainError::not_found(format!(
                "no note with id {id_raw}"
            ))))
        }
        None => match note_path_for(root, &id) {
            Some(rel) => {
                if let Ok(bytes) = std::fs::read(root.join(&rel)) {
                    return Err(note_unreadable_error(id_raw, &rel, &bytes));
                }
                return Err(anyhow::Error::new(DomainError::not_found(format!(
                    "no note with id {id_raw}"
                ))));
            }
            None => {
                return Err(anyhow::Error::new(DomainError::not_found(format!(
                    "no note with id {id_raw}"
                )))
                .context("use `confidant find <name>` to look up the id"))
            }
        },
    };
    // The owner implied by the path, so the person check below never trusts
    // the edited text.
    let owner =
        confidant_core::id::person_id_from_path(&rel.to_string_lossy()).ok_or_else(|| {
            anyhow::Error::new(DomainError::internal(format!(
                "note {id_raw} does not live under people/<person>/notes/"
            )))
        })?;
    let (text, provisional) = if let Some(file) = file {
        let text = std::fs::read_to_string(file).map_err(|e| {
            anyhow::Error::new(DomainError::invalid(format!(
                "cannot read {}: {e}",
                file.display()
            )))
        })?;
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "note.md".to_owned());
        (text, name)
    } else {
        // `--edit`: open the operator's editor on 0600 scratch (#455
        // convention). Fail fast if no editor is configured, before any
        // plaintext scratch exists.
        debug_assert!(edit, "clap requires --file or --edit");
        let current = note_plaintext(root, &vault.config.vault_id, &rel)?;
        resolve_editor()?;
        let (mut guard, scratch) = setup_note_edit_scratch(root, &id, &current)?;
        let result = run_note_editor(&scratch).and_then(|()| {
            std::fs::read_to_string(&scratch).map_err(|e| {
                anyhow::Error::new(DomainError::invalid(format!(
                    "cannot read {}: {e}",
                    scratch.display()
                )))
            })
        });
        // Explicit cleanup on every path; drop after is a no-op.
        guard.cleanup();
        (result?, "note.md".to_owned())
    };
    let rec = confidant_core::parse_record(&text, &provisional)
        .map_err(|e| anyhow::Error::new(DomainError::invalid(e.message).with_fix(e.fix)))?;
    if rec.kind != RecordKind::Note {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "note edit takes a note; the file's type is {}",
            rec.kind.as_str()
        ))));
    }
    if rec.id != id {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!("the file's id is {}, not {id_raw}", rec.id))
                .with_fix("Edit the note the file names, or fix `id:` in the file"),
        ));
    }
    // Fail closed before writing (#412-style): a note whose `person:` no
    // longer matches its directory must not be committed.
    if rec.person().as_ref() != Some(&owner) {
        return Err(anyhow::Error::new(
            DomainError::invalid(format!(
                "the edited note's person does not match its location ({}); a note cannot move",
                rel.display()
            ))
            .with_fix("Keep `person:` as it is, or use `note add` for a note on another person"),
        ));
    }
    let contents = confidant_core::format_record(&rec);
    let outcome = apply_record_write(
        root,
        &vault,
        PendingWrite {
            changes: vec![FileChange::WriteFile {
                path: rel.clone(),
                contents,
            }],
            summary: format!("note {id}"),
            canonical_request: format!("note-edit/v1\npath={}\nbody={text}", rel.display()),
        },
        &write_options(cli),
    )?;
    finish_write(
        cli,
        root,
        "note-edit",
        outcome,
        serde_json::json!({ "id": id.to_string(), "path": rel.display().to_string() }),
    )
}
