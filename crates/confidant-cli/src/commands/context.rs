//! `context`, `resolve`, and `alias resolve`.

use std::path::Path;
use std::process::ExitCode;

use crate::commands::shared::{person_resolve_error, OPERATOR_MODE_BANNER};
use crate::{
    legacy_vault_gate, load_vault_for_reads, ok_envelope, print_error, print_json,
    resolve_cli_scope, Cli,
};
use confidant_core::context::build_context;
use confidant_core::error::DomainError;
use confidant_core::id::RecordId;
use confidant_core::record::Record;
use confidant_core::scope::PackScope;

pub(crate) fn cmd_context(
    cli: &Cli,
    root: &Path,
    person_raw: &str,
    include_private: bool,
    for_operator: bool,
) -> anyhow::Result<ExitCode> {
    if let Err(err) = legacy_vault_gate(root) {
        print_error(cli.json, Some(&root.display().to_string()), &err)?;
        return Ok(ExitCode::from(err.exit_code() as u8));
    }
    // Operator mode (#572) loads through the operator read path (the same
    // mechanism as `record show --for-edit`); the default stays the agent
    // read path.
    let vault = match load_vault_for_reads(root, cli.json, for_operator) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    // The bundle now parses edges, whose kind list depends on the vault
    // spec. Fail closed on a spec this binary does not implement instead of
    // rendering a partial bundle.
    if !confidant_core::SpecVersion::is_supported(&vault.config.spec) {
        print_error(
            cli.json,
            Some(&vault.root.display().to_string()),
            &DomainError::spec_unsupported(&vault.config.spec),
        )?;
        return Ok(ExitCode::from(1));
    }
    // #537: a `p-<ULID>` keeps its exact previous behaviour (unsupported id
    // shapes still fall through to the cannot-search / ⚠2b / not-found
    // branches below); a non-id argument is an exact display name resolved
    // against the cleared set and canonicalized. Id args are not
    // canonicalized here — `context` already folds merge groups when it
    // builds the bundle. #813: an `o-<ULID>` is an org target; an org name
    // is not resolved by name in phase 1.
    let target = match RecordId::parse(person_raw) {
        Ok(id) => id,
        Err(_) => match confidant_core::resolve::resolve_person(&vault, person_raw) {
            Ok(m) => m.id,
            Err(err) => return Err(person_resolve_error(person_raw, err)),
        },
    };
    let (scope, _scope_names) = match resolve_cli_scope(&vault, cli.packs.as_deref()) {
        Ok(pair) => pair,
        Err(err) => {
            print_error(cli.json, Some(&vault.root.display().to_string()), &err)?;
            return Ok(ExitCode::from(err.exit_code() as u8));
        }
    };
    let bundle = match build_context(&vault, &target, include_private, &scope, for_operator) {
        Some(b) => b,
        None => {
            return Err(anyhow::Error::new(DomainError::not_found(format!(
                "no entity with id {person_raw}"
            )))
            .context("use `confidant find <name>` to look up the id"));
        }
    };
    if cli.json {
        let value = serde_json::to_value(&bundle)?;
        print_json(&ok_envelope(Some(root), value))?;
    } else {
        if for_operator {
            println!("{OPERATOR_MODE_BANNER}");
        }
        let e = &bundle.entity;
        // Operator mode carries the tri-state; the agent path still only
        // knows the boolean. `"false"` is an explicit visible record, not a
        // hidden one, so it gets no badge.
        let badge = match e.no_ai_mode {
            Some("notes") => " [no-ai: notes]",
            Some("true") => " [no-ai]",
            Some(_) => "",
            None if e.no_ai => " [no-ai]",
            None => "",
        };
        let name = e.name.as_deref().unwrap_or("(name withheld)");
        if e.kind == "person" {
            println!("{} {name}{badge}", e.id);
        } else {
            println!("{} {name} ({}){badge}", e.id, e.kind);
        }
        // #178: show the scope that applied, so a scoped bundle is never
        // mistaken for the whole record.
        if !bundle.scope.is_empty() && matches!(scope, PackScope::Only(_)) {
            println!("scope: {}", bundle.scope.join(", "));
        }
        println!(
            "notes: {}, interactions: {}, touchpoints: {}, edges: {}",
            bundle.notes.len(),
            bundle.interactions.len(),
            bundle.touchpoints.len(),
            bundle.edges.len()
        );
        if !bundle.aliases.is_empty() {
            println!("aliases: {}", bundle.aliases.join(", "));
        }
        // ⚠2: the bundle carries what was skipped, never silent.
    }
    Ok(ExitCode::SUCCESS)
}

/// `confidant resolve <query>` (#537, phase 3a): resolve a `p-<ULID>` or an
/// exact display name to the canonical person. Read-only.
///
/// Uses the `for_reads` (`operator: false`) cleared set, so a `no-ai: notes`
/// person resolves by name and a `no-ai: true` person resolves by id only.
/// An ambiguous name fails closed with `E_AMBIGUOUS_PERSON` (candidate ids
/// are opaque, never names).
pub(crate) fn cmd_resolve(cli: &Cli, root: &Path, query: &str) -> anyhow::Result<ExitCode> {
    legacy_vault_gate(root).map_err(anyhow::Error::new)?;
    let vault = match load_vault_for_reads(root, cli.json, false) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let matched = match confidant_core::resolve::resolve_person(&vault, query) {
        Ok(m) => m,
        Err(err) => return Err(person_resolve_error(query, err)),
    };
    let id = matched.id.clone();
    let record = vault.records.get(&id);
    // Rule 3: an id-resolved `no-ai: true` person is outside the cleared set,
    // so withhold its name (a name-resolved person is cleared by
    // construction). The mode itself is not content and stays visible.
    let cleared = confidant_core::cleared_record_ids(&vault);
    let name = record
        .and_then(|r| r.name.clone())
        .filter(|_| cleared.contains(&id));
    let no_ai = record.map(Record::no_ai).unwrap_or(false);
    let matched_by = if matched.matched_by_name {
        "name"
    } else {
        "id"
    };
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "command": "resolve",
                "query": query,
                "matched_by": matched_by,
                "person": {
                    "id": id.to_string(),
                    "name": name,
                    "no_ai": no_ai,
                },
            }),
        ))?;
    } else if let Some(name) = &name {
        println!("{id} {name}");
    } else {
        println!("{id}");
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn validate_alias_kind(kind: &str) -> anyhow::Result<()> {
    if matches!(kind, "email" | "phone" | "handle" | "name") {
        Ok(())
    } else {
        Err(anyhow::Error::new(DomainError::usage(format!(
            "bad alias kind '{kind}'; use one of: email, phone, handle, name"
        ))))
    }
}

/// `confidant alias resolve <kind> <value>` (#537 phase 3b): resolve a
/// `kind` + value alias to the canonical person. Read-only.
///
/// Aliases are plain front-matter contact values (plus the typed
/// `alias_history` entries, #739), matched case-insensitively as whole
/// strings against the cleared set. Current values win over historical
/// ones. A `no-ai: true` person is indistinguishable from an unmatched
/// alias. Two cleared people sharing a current value fail closed with
/// `E_AMBIGUOUS_PERSON`.
pub(crate) fn cmd_alias_resolve(
    cli: &Cli,
    root: &Path,
    kind: &str,
    value: &str,
) -> anyhow::Result<ExitCode> {
    validate_alias_kind(kind)?;
    legacy_vault_gate(root).map_err(anyhow::Error::new)?;
    let vault = match load_vault_for_reads(root, cli.json, false) {
        Ok(v) => v,
        Err(code) => return Ok(code),
    };
    let id = match confidant_core::resolve::resolve_alias(&vault, kind, value) {
        Ok(m) => m.id,
        Err(err) => return Err(person_resolve_error(value, err)),
    };
    // `resolve_alias` returns only cleared people, so the name is safe. The
    // mode is not content and stays visible (mirrors `cmd_resolve`).
    let record = vault.records.get(&id);
    let name = record.and_then(|r| r.name.clone());
    let no_ai = record.map(Record::no_ai).unwrap_or(false);
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "command": "alias-resolve",
                "kind": kind,
                "matched_by": "alias",
                "person": {
                    "id": id.to_string(),
                    "name": name,
                    "no_ai": no_ai,
                },
            }),
        ))?;
    } else if let Some(name) = &name {
        println!("{id} {name}");
    } else {
        println!("{id}");
    }
    Ok(ExitCode::SUCCESS)
}
