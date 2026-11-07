//! `log touch`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::shared::{
    announce_resolved_person, apply_record_write, defer_to_write_path, find_duplicate_touch,
    finish_write, month_path, parse_date_arg, require_log_verb, resolve_person_arg, write_options,
};
use crate::Cli;
use confidant_core::error::DomainError;
use confidant_core::id::{Prefix, RecordId};
use confidant_core::record::{Record, RecordKind};
use confidant_core::write::{FileChange, PendingWrite};

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_log_touch(
    cli: &Cli,
    root: &Path,
    person_raw: &str,
    kind: &str,
    date_raw: Option<String>,
    note: Option<String>,
    src: Option<String>,
    duration: Option<String>,
    mode: Option<String>,
    force: bool,
) -> anyhow::Result<ExitCode> {
    let vault = vault_or!(root, cli.json);
    // #551: the built-in personal pack is implicit, so `touch` is always
    // owned by an enabled pack; the #510 enable gate is gone. The #732
    // gate below is still applied so both log verbs share the same
    // dry-run/apply parity rule (it never fires for a core verb).
    require_log_verb(&vault, "touch")?;
    let person = resolve_person_arg(root, &vault, person_raw)?;
    announce_resolved_person(cli, &person);
    // #510: the kind grammar is core-owned; validate against the core list
    // directly instead of probing the owning pack's trait.
    if !confidant_core::touch::is_valid_touch_kind(kind) {
        return Err(anyhow::Error::new(DomainError::usage(format!(
            "bad touch kind '{kind}'; use one of: {}",
            confidant_core::touch::TOUCH_KINDS.join(", ")
        ))));
    }
    // #741: the rich pairs are optional; validate before writing so a typo
    // is a usage error, not an E_TOUCH_MALFORMED line in the vault.
    let duration_minutes = match duration.as_deref() {
        Some(raw) => Some(
            confidant_core::ledger::parse_duration_minutes(raw)
                .filter(|minutes| *minutes > 0)
                .ok_or_else(|| {
                    anyhow::Error::new(DomainError::usage(format!(
                        "bad touch duration '{raw}'; use minutes like 60m, or 1h / 1h30m"
                    )))
                })?,
        ),
        None => None,
    };
    if let Some(mode) = mode.as_deref() {
        if !confidant_core::touch::is_valid_touch_mode(mode) {
            return Err(anyhow::Error::new(DomainError::usage(format!(
                "bad touch mode '{mode}'; use one of: {}",
                confidant_core::touch::TOUCH_MODES.join(", ")
            ))));
        }
    }
    let date = parse_date_arg(&date_raw)?;

    let mut changes = Vec::new();
    let mut note_arg: Option<String> = None;
    let mut note_body: Option<String> = None;
    if let Some(text) = note {
        let nid = RecordId::new(Prefix::Note, confidant_core::write::new_ulid())
            .map_err(|e| anyhow::anyhow!("generated bad note id: {e}"))?;
        let rel = PathBuf::from(format!("people/{}/notes/{nid}.md", person.id));
        let rec = Record {
            id: nid.clone(),
            kind: RecordKind::Note,
            path: rel.display().to_string(),
            name: None,
            fields: BTreeMap::from([
                ("person".to_owned(), person.id.to_string()),
                ("date".to_owned(), date.to_string()),
            ]),
            body: text.clone(),
            source: String::new(),
            body_start_line: 0,
            field_lines: BTreeMap::new(),
        };
        let contents = confidant_core::format_record(&rec);
        changes.push(FileChange::WriteFile {
            path: rel,
            contents,
        });
        note_arg = Some(format!("note:{nid}"));
        note_body = Some(text);
    }

    let mut parts = vec![
        date.to_string(),
        "touch".to_owned(),
        person.id.to_string(),
        kind.to_owned(),
    ];
    if let Some(n) = &note_arg {
        parts.push(n.clone());
    }
    if let Some(s) = &src {
        parts.push(format!("src:{s}"));
    }
    if let Some(minutes) = duration_minutes {
        parts.push(format!(
            "{}:{minutes}m",
            confidant_core::touch::TOUCH_DURATION_PAIR
        ));
    }
    if let Some(mode) = &mode {
        parts.push(format!("{}:{mode}", confidant_core::touch::TOUCH_MODE_PAIR));
    }
    let line = parts.join(" ");
    changes.push(FileChange::AppendLines {
        path: month_path(&date),
        lines: vec![line.clone()],
    });

    // The canonical-request digest keeps its historical shape for a plain
    // touch, so a retry of a request id written before #741 still replays.
    // The rich pairs are appended only when present, and then they DO
    // distinguish content (a reused id with a different duration conflicts).
    let mut canonical = format!(
        "log-touch/v1\nperson={}\ndate={date}\nkind={kind}\nnote={}\nsrc={}\n",
        person.id,
        note_body.as_deref().unwrap_or(""),
        src.as_deref().unwrap_or(""),
    );
    if let Some(minutes) = duration_minutes {
        canonical.push_str(&format!("duration={minutes}m\n"));
    }
    if let Some(mode) = &mode {
        canonical.push_str(&format!("mode={mode}\n"));
    }
    let summary = format!("touch {} {kind}", person.id);
    // #747: refuse an identical touch before applying or queueing
    // anything, unless --force or the write path owns the decision
    // (a known --request-id replays or conflicts there).
    if !force {
        if let Some((file, line)) = find_duplicate_touch(&vault, &person.id, &date, kind) {
            if !defer_to_write_path(root, cli, &canonical)? {
                return Err(anyhow::Error::new(
                    DomainError::already_exists(format!(
                        "a {kind} touch for {} on {date} is already in the ledger ({file}:{line})",
                        person.id,
                    ))
                    .with_file(file)
                    .with_line(line)
                    .with_fix("Pass --force to log a genuinely separate touch anyway"),
                ));
            }
        }
    }
    let outcome = apply_record_write(
        root,
        &vault,
        PendingWrite {
            changes,
            summary,
            canonical_request: canonical,
        },
        &write_options(cli),
    )?;
    let mut extra = serde_json::json!({"lines": [line]});
    if let Some(echo) = person.echo_json() {
        extra["person"] = echo;
    }
    finish_write(cli, root, "log-touch", outcome, extra)
}
