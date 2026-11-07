//! Helpers shared by more than one write command.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::check::print_check_human;
use crate::{ok_envelope, print_json, Cli, FixExt};
use confidant_core::error::DomainError;
use confidant_core::id::RecordId;
use confidant_core::ledger::parse_strict_date;
use confidant_core::record::RecordKind;
use confidant_core::write::{apply_write, DryRunCheck, PendingWrite, WriteOptions, WriteOutcome};
use serde_json::Value;

pub(crate) const OPERATOR_MODE_BANNER: &str =
    "OPERATOR MODE: no-ai records included (--for-operator)";

pub(crate) fn write_options(cli: &Cli) -> WriteOptions {
    WriteOptions {
        dry_run: cli.dry_run,
        no_input: cli.no_input,
        request_id: cli.request_id.clone(),
        agent_id: std::env::var("CONFIDANT_AGENT_ID")
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty()),
        // Per-command opt-in: only the batch-capable commands (`retract`,
        // `import`) carry an explicit `--force` for this (#883).
        allow_destructive_batch: false,
    }
}

/// Apply a record write through the plaintext write pipeline.
///
/// Records are written as YAML front matter plus a Markdown body, atomically
/// (`temp file + rename` via `confidant_core::paths::write_replace`), and
/// gated by the pre/post `check` exactly as before.
pub(crate) fn apply_record_write(
    root: &Path,
    _vault: &confidant_core::vault::Vault,
    pending: PendingWrite,
    opts: &WriteOptions,
) -> anyhow::Result<WriteOutcome> {
    apply_write(root, pending, opts)
}

pub(crate) fn finish_write(
    cli: &Cli,
    root: &Path,
    command: &str,
    outcome: WriteOutcome,
    extra: serde_json::Value,
) -> anyhow::Result<ExitCode> {
    match outcome {
        WriteOutcome::Applied { commit, files } => {
            if cli.json {
                let mut obj = serde_json::json!({
                    "command": command,
                    "commit": commit,
                    "files": files,
                });
                if let serde_json::Value::Object(e) = extra {
                    obj.as_object_mut().unwrap().extend(e);
                }
                print_json(&ok_envelope(Some(root), obj))?;
            } else {
                println!(
                    "committed {} ({} file(s))",
                    &commit[..8.min(commit.len())],
                    files.len()
                );
                for f in &files {
                    println!("  {f}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        WriteOutcome::DryRun { preview, checks } => {
            if cli.json {
                let changes: Vec<serde_json::Value> = preview
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "path": p.path,
                            "action": p.action,
                            "content": p.content,
                        })
                    })
                    .collect();
                let mut obj = serde_json::json!({
                    "command": command,
                    "dry_run": true,
                    "commit": serde_json::Value::Null,
                    "checks": {
                        "pre": checks.pre.as_str(),
                        "post": checks.post.as_str(),
                    },
                    "changes": changes,
                });
                if let serde_json::Value::Object(e) = extra {
                    obj.as_object_mut().unwrap().extend(e);
                }
                print_json(&ok_envelope(Some(root), obj))?;
            } else {
                let pre = match checks.pre {
                    DryRunCheck::Passed => "pre-check passed",
                    DryRunCheck::Skipped => "pre-check skipped (repairing write)",
                };
                println!(
                    "dry run — no files written, no commit; {pre}, post-check skipped (it needs the applied tree):"
                );
                for p in &preview {
                    println!("--- {} ({})", p.path, p.action);
                    println!("{}", p.content);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        WriteOutcome::Idempotent { commit } => {
            if cli.json {
                print_json(&ok_envelope(
                    Some(root),
                    serde_json::json!({
                        "command": command,
                        "idempotent": true,
                        "commit": commit,
                    }),
                ))?;
            } else {
                println!(
                    "already applied (commit {})",
                    &commit[..8.min(commit.len())]
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        WriteOutcome::Unchanged => {
            if cli.json {
                let mut obj = serde_json::json!({ "command": command, "unchanged": true });
                if let serde_json::Value::Object(e) = extra {
                    obj.as_object_mut().unwrap().extend(e);
                }
                print_json(&ok_envelope(Some(root), obj))?;
            } else {
                println!("no changes; nothing committed");
            }
            Ok(ExitCode::SUCCESS)
        }
        WriteOutcome::CheckBlocked { report } => {
            if cli.json {
                print_json(&report)?;
            } else {
                writeln!(io::stderr(), "write blocked: check failed")?;
                print_check_human(&report)?;
            }
            Ok(ExitCode::from(1))
        }
    }
}

/// A `--person` / positional person argument resolved to a canonical person
/// (#537). `matched_name` is `Some` only for an exact display-name argument,
/// so a write resolved by name can echo the pick (Refinement B) while a
/// write by `p-<ULID>` keeps its previous output.
pub(crate) struct ResolvedPersonArg {
    pub(crate) id: RecordId,
    pub(crate) matched_name: Option<String>,
}

impl ResolvedPersonArg {
    /// JSON object echoing the resolved person, or `None` for an id argument
    /// (so id writes produce byte-identical output).
    pub(crate) fn echo_json(&self) -> Option<Value> {
        self.matched_name
            .as_ref()
            .map(|name| serde_json::json!({ "id": self.id.to_string(), "name": name }))
    }
}

/// The vault loaded for name resolution in a write command. Unlike
/// [`load_vault_for_reads`] this returns the classified error instead of
/// printing it: the write commands resolve names *in addition to* loading
/// their own vault, and the error must reach the top-level handler once.
pub(crate) fn load_read_vault(root: &Path) -> anyhow::Result<confidant_core::Vault> {
    confidant_core::load_vault(root).map_err(anyhow::Error::new)
}

/// Map a failed name resolution to the command-error layer. The not-found
/// fix is deliberately generic (Refinement A): it must not confirm that a
/// hidden `no-ai: true` person exists.
pub(crate) fn person_resolve_error(
    query: &str,
    err: confidant_core::resolve::PersonResolveError,
) -> anyhow::Error {
    use confidant_core::resolve::PersonResolveError;
    match err {
        PersonResolveError::NotFound => anyhow::Error::new(
            DomainError::not_found(format!("no person matches '{query}'")).with_fix(
                "Use an exact display name (trimmed, case-insensitive) or the p-<ULID>; if this \
                 person is `no-ai: true`, pass their p-<ULID>",
            ),
        ),
        PersonResolveError::Ambiguous { candidates } => {
            let ids: Vec<String> = candidates.iter().map(RecordId::to_string).collect();
            anyhow::Error::new(DomainError::ambiguous_person(query, &ids))
        }
        // #717: the vault was not fully searched, so this is not a
        // not-found: the person may be in an unread record.
        PersonResolveError::CannotSearch { skipped, refused } => {
            anyhow::Error::new(DomainError::cannot_search(skipped, refused))
        }
    }
}

/// Resolve a `--person` / positional person argument: a `p-<ULID>` against
/// the already-loaded write vault (its id and type come from plaintext front
/// matter, so a `no-ai: true` person stays addressable by id), or an exact
/// display name against the `for_reads` cleared set.
///
/// An id miss in the write vault is not a confident not-found: the id
/// could belong to a record the read path could not search, so the miss
/// is resolved again against the `for_reads` vault, whose unread person
/// records gate it to `E_CANNOT_SEARCH` exactly like a name miss (#717).
/// Id arguments never echo a name, so the read-vault hit path cannot leak
/// a hidden person's name.
pub(crate) fn resolve_person_arg(
    root: &Path,
    vault: &confidant_core::Vault,
    raw: &str,
) -> anyhow::Result<ResolvedPersonArg> {
    if let Ok(id) = RecordId::parse(raw) {
        if let Some(r) = vault.records.get(&id) {
            if r.kind == RecordKind::Person {
                if vault.is_retired(&id) {
                    return Err(anyhow::Error::new(DomainError::invalid(format!(
                        "{id} is retired"
                    )))
                    .with_fix("Run `confidant record unretire <id>` before writing to it"));
                }
                return Ok(ResolvedPersonArg {
                    id,
                    matched_name: None,
                });
            }
        }
        // Miss (or a non-person record) in the write vault: fall through
        // to the read vault, where `resolve_person` applies the same
        // cannot-search gate a name lookup gets. A non-person id stays
        // NotFound there too (positive knowledge), and a hit — e.g. a
        // `no-ai` shell the un-hooked write load could not surface —
        // still resolves by id.
        let read_vault = load_read_vault(root)?;
        return match confidant_core::resolve::resolve_person(&read_vault, raw) {
            Ok(m) => Ok(ResolvedPersonArg {
                id: m.id,
                matched_name: None,
            }),
            Err(err) => Err(person_resolve_error(raw, err)),
        };
    }
    let read_vault = load_read_vault(root)?;
    match confidant_core::resolve::resolve_person(&read_vault, raw) {
        Ok(m) => {
            // Belt-and-braces (#537 review): never echo a canonical the §12
            // cleared set excludes, even if resolution ever regresses. A
            // cleared person merged into a `no-ai: true` person must not
            // print (or serialize) that hidden person's name; fall back to
            // the same generic not-found as a miss.
            if !confidant_core::cleared_record_ids(&read_vault).contains(&m.id) {
                return Err(person_resolve_error(
                    raw,
                    confidant_core::resolve::PersonResolveError::NotFound,
                ));
            }
            // Echo the canonical person's own name; fall back to the query
            // for the rare merged-away name whose canonical has none.
            let matched_name = read_vault
                .records
                .get(&m.id)
                .and_then(|r| r.name.clone())
                .or_else(|| Some(raw.trim().to_owned()));
            Ok(ResolvedPersonArg {
                id: m.id,
                matched_name,
            })
        }
        Err(err) => Err(person_resolve_error(raw, err)),
    }
}

/// Refinement B (#537): a write resolved by exact display name prints the
/// resolved `p-<ULID>` (and name) so a wrong pick is immediately visible.
/// Id writes print nothing extra; under `--json` the envelope carries it.
///
/// The line is printed before the remaining validation (bad duration, bad
/// touch kind), so it says "resolving to" rather
/// than claiming a completed write: the human may still see an error and no
/// commit after it (#537 review).
pub(crate) fn announce_resolved_person(cli: &Cli, person: &ResolvedPersonArg) {
    if cli.json {
        return;
    }
    if let Some(name) = &person.matched_name {
        println!("resolving to {} ({name})", person.id);
    }
}

pub(crate) fn parse_date_arg(raw: &Option<String>) -> anyhow::Result<chrono::NaiveDate> {
    match raw {
        Some(s) => parse_strict_date(s)
            .ok_or_else(|| anyhow::Error::new(DomainError::usage(format!("not YYYY-MM-DD: {s}")))),
        None => Ok(chrono::Utc::now().date_naive()),
    }
}

pub(crate) fn month_path(date: &chrono::NaiveDate) -> PathBuf {
    use chrono::Datelike;
    PathBuf::from(format!("ledger/{}/{:02}.cfd", date.year(), date.month()))
}

pub(crate) fn refuse_unknown_verb(verb: &str) -> anyhow::Error {
    // Deliberate echo, unlike `check_verbs_and_refs`' bare "unknown
    // verb": a verb is a command name the operator typed, not vault
    // content, so naming it cannot leak record text.
    anyhow::Error::new(DomainError::invalid(format!(
        "verb '{verb}' is not enabled in this vault"
    )))
    .with_fix("Use a core verb or enable the pack that defines it")
}

pub(crate) fn require_log_verb(
    vault: &confidant_core::vault::Vault,
    verb: &str,
) -> anyhow::Result<()> {
    if confidant_core::check::verb_passes_check(vault, verb) {
        return Ok(());
    }
    Err(refuse_unknown_verb(verb))
}

/// #747: semantic idempotency for `log touch`. Returns the existing
/// line's vault-relative file and line number when an identical line is
/// already in the ledger, so the refusal can point at it. The caller runs
/// this after building the canonical request but before applying anything,
/// so a refusal writes nothing.
/// `note:` and `src:` never make a line distinct — a
/// backfill that re-adds the same contact with a fresh note or
/// provenance is still the same touchpoint.
pub(crate) fn find_duplicate_touch(
    vault: &confidant_core::Vault,
    person: &RecordId,
    date: &chrono::NaiveDate,
    kind: &str,
) -> Option<(String, u32)> {
    vault.entries.iter().find_map(|sourced| {
        let (id, d, k) = confidant_core::touch::touch_identity(&sourced.entry)?;
        (id == *person && d == *date && k == kind).then_some((sourced.file.clone(), sourced.line))
    })
}

/// #747: whether `apply_record_write` should decide this write instead of
/// the duplicate refusal. True when `--request-id` is present and either
/// invalid (so the write path reports the usage error) or already
/// committed (so it replays an exact retry or reports an idempotency
/// conflict). Without this, a retry after a timeout would be refused as
/// a duplicate instead of replaying.
pub(crate) fn defer_to_write_path(root: &Path, cli: &Cli, canonical: &str) -> anyhow::Result<bool> {
    let Some(rid) = cli.request_id.as_deref() else {
        return Ok(false);
    };
    if rid.trim().is_empty() || rid.chars().count() < 22 {
        return Ok(true);
    }
    let (id_hash, _) = confidant_core::write::idempotency_digests(rid, canonical);
    Ok(confidant_core::write::find_request_commit(root, &id_hash, cli.no_input)?.is_some())
}

/// Find `name` on `PATH`, returning the full path of the first match.
pub(crate) fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Redact credentials in a `--remote` URL before printing it or putting it
/// in JSON. `https://user:token@host/path` becomes `https://host/path`.
/// The real URL is still passed to `git remote add`.
pub(crate) fn display_remote_url(url: &str) -> String {
    let url = url.trim();
    for scheme in ["https://", "http://", "ssh://", "git://"] {
        let Some(rest) = url.strip_prefix(scheme) else {
            continue;
        };
        let (authority, path) = match rest.find('/') {
            Some(end) => (&rest[..end], &rest[end..]),
            None => (rest, ""),
        };
        if let Some((_, host)) = authority.rsplit_once('@') {
            return format!("{scheme}{host}{path}");
        }
        return url.to_owned();
    }
    url.to_owned()
}
