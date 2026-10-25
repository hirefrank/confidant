use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use crate::error::DomainError;
use crate::ledger::parse_line;
use crate::paths;

use super::item::{ItemKind, ParsedItem};
use super::merge::PlannedWrite;
use super::ItemOutcome;

// ---------------------------------------------------------------------------
// merge planning
// ---------------------------------------------------------------------------

/// `src:` values on a ledger entry (token `src:x` or pair `src: x`).
fn entry_srcs(args: &[crate::ledger::Arg]) -> Vec<String> {
    args.iter()
        .filter_map(|a| {
            if let Some(t) = a.as_token() {
                t.strip_prefix("src:").map(str::to_string)
            } else if let Some(("src", v)) = a.pair() {
                Some(v.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// All `src:` values already present in the loaded vault ledger.
pub(crate) fn collect_vault_srcs(vault: &crate::vault::Vault) -> BTreeSet<String> {
    let mut srcs = BTreeSet::new();
    for sourced in &vault.entries {
        srcs.extend(entry_srcs(&sourced.entry.args));
    }
    srcs
}

/// Canonical key for one `touch`/`session` identity (#747), shared by
/// [`collect_semantic_identities`] and [`plan_item`]. `note:`/`src:`
/// never appear here, so a re-log with fresh provenance still matches.
fn semantic_identity_key(entry: &crate::ledger::LedgerEntry) -> Option<String> {
    if let Some((id, date, kind)) = crate::touch::touch_identity(entry) {
        return Some(format!("touch|{id}|{date}|{kind}"));
    }
    if let Some((id, date, minutes, tag)) = crate::ledger::session_identity(entry) {
        return Some(format!("session|{id}|{date}|{minutes}|{tag}"));
    }
    None
}

/// Every semantic identity already in the loaded vault ledger (#747
/// review: inbox-queued lines bypass the write-time refusal, because
/// the queued item is encrypted to the inbox key and the log command
/// cannot see it — so the drain is where the duplicate must be caught).
pub(crate) fn collect_semantic_identities(vault: &crate::vault::Vault) -> BTreeSet<String> {
    vault
        .entries
        .iter()
        .filter_map(|sourced| semantic_identity_key(&sourced.entry))
        .collect()
}

fn month_file(date: &chrono::NaiveDate) -> PathBuf {
    PathBuf::from(format!("ledger/{}.cfd", date.format("%Y/%m")))
}

/// Plan one item. Returns `None` when everything it carries is already
/// present (idempotent re-import adds nothing).
///
/// `decrypt_existing` decrypts an existing record envelope for the retry
/// idempotency check on structurally encrypted vaults (see
/// [`DecryptExistingFn`]); `None` keeps the fail-closed byte comparison.
///
/// Mutable drain-run state for [`plan_item`], owned by the caller
/// across items so two queued copies of the same line — e.g. a session
/// queued twice via `--fallback-inbox` — merge at most once (#747
/// review).
pub(crate) struct PlanState {
    /// Every `touch`/`session` identity already in the ledger plus
    /// every identity planned so far in this drain run.
    pub(crate) semantic_identities: BTreeSet<String>,
    /// `confidant inbox --force` for this drain run (#747 round 3).
    pub(crate) drain_force: bool,
    /// Lines dropped by the semantic skip for the item most recently
    /// planned (reset by the caller per item). Counts semantic drops
    /// only, so the drain report can name them as distinct from
    /// `src:`/exact-text re-imports.
    pub(crate) semantic_skipped: usize,
}

/// Plan one item. Returns `None` when everything it carries is already
/// present (idempotent re-import adds nothing).
///
/// A skipped line is not an error: the item reports `skip` (or `merge`
/// for its surviving lines) and is cleared like any idempotent item.
///
/// The semantic skip is bypassed for a forced line (#747 round 3): a
/// line from an item carrying `force: true` (queued by `log --force
/// --fallback-inbox`) or a drain run with `drain_force` (`confidant
/// inbox --force`). A forced line still inserts its identity, so a
/// later *unforced* copy in the same drain still skips, while a later
/// forced copy — a second genuinely separate repeat — still plans.
/// `src:`/exact-text idempotency is never bypassed: a forced repeat
/// carries a fresh `src:fallback/…` token and a fresh note id, so it is
/// not an exact re-import.
pub(crate) fn plan_item(
    vault_root: &Path,
    item: &ParsedItem,
    existing_srcs: &BTreeSet<String>,
    ledger_cache: &mut HashMap<PathBuf, String>,
    decrypt_existing: Option<&super::DecryptExistingFn>,
    state: &mut PlanState,
) -> anyhow::Result<Option<(ItemOutcome, Vec<PlannedWrite>)>> {
    match item.kind {
        ItemKind::Ledger => {
            // Group new lines per month file, preserving item order.
            let mut by_file: Vec<(PathBuf, Vec<String>)> = Vec::new();
            for (n, raw) in item.content.lines().enumerate() {
                let line_no = n + 1;
                if raw.trim().is_empty() || raw.trim_start().starts_with(';') {
                    continue;
                }
                let entry = parse_line(raw).map_err(|e| {
                    anyhow::Error::new(DomainError::inbox_item(format!(
                        "item '{}' line {line_no}: {e}",
                        item.name
                    )))
                })?;
                let Some(entry) = entry else { continue };
                // Intake limits: identity and balance changes come from the
                // operator, never from intake. One crafted `merge` item could
                // fold two clients together; one `balance` item could rewrite
                // a balance assertion.
                if entry.verb == "merge" || entry.verb == "balance" {
                    return Err(anyhow::Error::new(DomainError::inbox_item(format!(
                        "item '{}' line {line_no}: verb '{}' is not allowed from intake",
                        item.name, entry.verb
                    ))));
                }
                // Every inbox ledger line carries provenance: `src:` is how
                // re-imports stay idempotent and how the operator traces where
                // a line came from.
                if entry_srcs(&entry.args).is_empty() {
                    return Err(anyhow::Error::new(DomainError::inbox_item(format!(
                        "item '{}' line {line_no}: every inbox ledger line needs a `src:`",
                        item.name
                    ))));
                }
                // #747 review: skip lines that are semantic duplicates
                // of a line already in the ledger or already planned in
                // this drain run — the drain-time half of the write-time
                // refusal, for lines the log command could not see
                // because they were queued (encrypted) to the inbox.
                // `note:`/`src:` do not distinguish, so a re-queued line
                // with a fresh `src:fallback/…` token still matches.
                if let Some(key) = semantic_identity_key(&entry) {
                    if state.semantic_identities.contains(&key) && !item.force && !state.drain_force
                    {
                        state.semantic_skipped += 1;
                        continue;
                    }
                }
                let target = month_file(&entry.date);
                // Idempotency: skip lines already imported (by src: or exact text).
                let dominated = entry_srcs(&entry.args)
                    .iter()
                    .any(|s| existing_srcs.contains(s));
                if dominated {
                    continue;
                }
                let existing = ledger_cache.entry(target.clone()).or_insert_with(|| {
                    paths::read_to_string(vault_root, &target).unwrap_or_default()
                });
                if existing.lines().any(|l| l.trim_end() == raw.trim_end()) {
                    continue;
                }
                if let Some(key) = semantic_identity_key(&entry) {
                    state.semantic_identities.insert(key);
                }
                match by_file.iter_mut().find(|(f, _)| *f == target) {
                    Some((_, lines)) => lines.push(raw.to_string()),
                    None => by_file.push((target, vec![raw.to_string()])),
                }
            }
            if by_file.is_empty() {
                return Ok(None);
            }
            let target = by_file
                .iter()
                .map(|(f, _)| f.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let writes = by_file
                .into_iter()
                .map(|(file, lines)| PlannedWrite::LedgerAppend { file, lines })
                .collect();
            Ok(Some((
                ItemOutcome {
                    name: item.name.clone(),
                    kind: "ledger".to_string(),
                    target,
                    action: "merge".to_string(),
                    // The caller (run_inbox) fills in the per-item
                    // semantic-skip count from the out-param.
                    semantic_skipped: 0,
                },
                writes,
            )))
        }
        ItemKind::Record => {
            let rel = item.path.as_ref().expect("record items have a path");
            match paths::read_to_string(vault_root, rel) {
                Ok(current) if current == item.content => return Ok(None),
                Ok(current) => {
                    // Retry idempotency on structurally encrypted vaults
                    // (#213): the first run's merge wrote an envelope, so a
                    // byte comparison against the plaintext item always
                    // mismatches and a retry after a failed clear would
                    // wedge the inbox on `E_INBOX_CONFLICT` forever.
                    // Decrypt the existing envelope and compare plaintext
                    // instead: equal means the item already merged (skip).
                    // Anything else — a real difference, an undecryptable
                    // file, or no decryptor — fails closed as a conflict.
                    let already_merged = crate::crypto_mode::is_structurally_encrypted(vault_root)
                        && decrypt_existing
                            .map(|dec| {
                                dec(rel, current.as_bytes())
                                    .map(|pt| pt.as_slice() == item.content.as_bytes())
                                    .unwrap_or(false)
                            })
                            .unwrap_or(false);
                    if already_merged {
                        return Ok(None);
                    }
                    return Err(anyhow::Error::new(DomainError::inbox_conflict(
                        rel.display().to_string(),
                    )));
                }
                Err(e) if crate::error::is_missing(&e) => {}
                Err(e) => return Err(e),
            }
            let writes = vec![PlannedWrite::RecordWrite {
                path: rel.clone(),
                content: item.content.clone(),
            }];
            Ok(Some((
                ItemOutcome {
                    name: item.name.clone(),
                    kind: "record".to_string(),
                    target: rel.display().to_string(),
                    action: "merge".to_string(),
                    semantic_skipped: 0,
                },
                writes,
            )))
        }
    }
}
