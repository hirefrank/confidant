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

fn month_file(date: &chrono::NaiveDate) -> PathBuf {
    PathBuf::from(format!("ledger/{}.cfd", date.format("%Y/%m")))
}

/// Plan one item. Returns `None` when everything it carries is already
/// present (idempotent re-import adds nothing).
pub(crate) fn plan_item(
    vault_root: &Path,
    item: &ParsedItem,
    existing_srcs: &BTreeSet<String>,
    ledger_cache: &mut HashMap<PathBuf, String>,
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
                },
                writes,
            )))
        }
        ItemKind::Record => {
            let rel = item.path.as_ref().expect("record items have a path");
            match paths::read_to_string(vault_root, rel) {
                Ok(current) if current == item.content => return Ok(None),
                Ok(_) => {
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
                },
                writes,
            )))
        }
    }
}
