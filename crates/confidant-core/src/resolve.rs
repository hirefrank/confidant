//! Resolve a `--person` / `resolve` query to the canonical person (#537).
//!
//! [`resolve_person`] accepts two forms; [`resolve_alias`] takes a
//! precomputed `(kind, hmac)` alias and resolves it against the same cleared
//! set:
//!
//! - an opaque `p-<ULID>`, resolved directly against the loaded vault. The
//!   id and record type live in the outer envelope header on an encrypted
//!   record, so a `no-ai: true` person stays addressable by id without
//!   decrypting anything;
//! - an **exact display name** among the §12 cleared set
//!   ([`cleared_record_ids`]): trimmed, Unicode case-insensitive,
//!   whole-string equality. `find` remains the fuzzy path.
//!
//! Because resolution reads only cleared records, a `no-ai: true` person
//! never enters a name lookup: they are addressed by id only. Names are
//! merge-canonicalized, so a name belonging to a merged-away member
//! resolves to the canonical person — but only when that canonical is
//! itself cleared. A cleared member merged into a `no-ai: true` person
//! canonicalizes to a hidden id and does not resolve by name, or echoing
//! the pick would leak the hidden person. More than one cleared person
//! with the same name is [`PersonResolveError::Ambiguous`], never a guess.
//! And a miss against a vault whose person records did not all load
//! (skipped encrypted person records, refused person envelopes) is
//! [`PersonResolveError::CannotSearch`], never `NotFound` (#717): the
//! searched person set is incomplete, so absence cannot be established.
//! The gate is person-scoped: an unreadable org, deal, note, edge, or
//! interaction cannot hide a person, so it never flips a person miss.
//! Only the negative outcome is gated: a match found in the searched set
//! still succeeds, which deliberately accepts one residual — a skipped
//! envelope could hide a second person with the same display name,
//! turning a true ambiguity into a confident single match. Gating every
//! match instead would fail all lookups whenever any person record is
//! unreadable, which is worse than the residual.

use std::collections::{BTreeSet, HashSet};

use crate::check::{canonical_on, check_aliases_and_merges, parse_alias, resolve_as_of_date};
use crate::id::RecordId;
use crate::record::RecordKind;
use crate::search::{case_fold, cleared_record_ids};
use crate::vault::Vault;

/// A query that resolved to exactly one person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonMatch {
    /// The canonical person the query resolved to.
    pub id: RecordId,
    /// True when `query` was an exact display name (so callers can echo the
    /// pick); false when it was already an opaque `p-<ULID>`.
    pub matched_by_name: bool,
}

/// Why a query did not resolve to exactly one person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersonResolveError {
    /// No person matched, and the vault was fully searched: every record
    /// file loaded, so the miss genuinely establishes absence from the
    /// cleared set. Deliberately carries no detail: a `no-ai: true`
    /// person's existence must not be confirmed by the error.
    NotFound,
    /// More than one cleared person matched (after merge canonicalization).
    /// Candidates are the canonical person ids, sorted and deduped. They
    /// are opaque ids, never names.
    Ambiguous { candidates: Vec<RecordId> },
    /// The vault could not be fully searched, so a miss cannot establish
    /// absence (#717). `skipped` person-record files were skipped as
    /// encrypted-but-unreadable (no usable key material on this device)
    /// and `refused` person envelopes were refused as tampered or corrupt;
    /// a person in any of them would be missed. The counts are
    /// person-scoped (see `miss`): unreadable records of other kinds do
    /// not contribute. Callers must surface this as a cannot-search
    /// error, never as `NotFound`: a confident wrong negative ("no person
    /// matches") about a real person is the failure this variant exists
    /// to prevent. A match found in the searched set is still returned
    /// normally — only the negative outcome is gated, because only the
    /// negative asserts absence. That deliberately accepts the residual
    /// that a skipped envelope could hide a second same-name person and
    /// mask a true ambiguity as a single match (see the module docs).
    CannotSearch { skipped: u32, refused: u32 },
}

impl std::fmt::Display for PersonResolveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("no person matched"),
            Self::Ambiguous { candidates } => {
                write!(formatter, "{} people matched", candidates.len())
            }
            Self::CannotSearch { skipped, refused } => {
                let mut parts = Vec::new();
                if *skipped > 0 {
                    parts.push(format!("{skipped} encrypted record(s) unreadable"));
                }
                if *refused > 0 {
                    parts.push(format!("{refused} envelope(s) refused"));
                }
                if parts.is_empty() {
                    // The constructor is public, so a (0, 0) value can
                    // exist even though `miss()` never builds one; never
                    // render an empty cause list.
                    parts.push("the vault could not be fully searched".to_owned());
                }
                write!(formatter, "cannot search the vault: {}", parts.join(", "))
            }
        }
    }
}

/// The miss outcome for `vault`: `CannotSearch` when any person-record
/// file went unread (skipped or refused), so the searched person set is
/// incomplete and a miss proves nothing; `NotFound` only when the person
/// set loaded in full. Person-scoped by construction: the loader counts
/// only person-record jobs (`Vault::skipped_person_records` /
/// `refused_person_records`), so an unreadable org, deal, note, edge, or
/// interaction never flips a person miss.
fn miss(vault: &Vault) -> PersonResolveError {
    if vault.skipped_person_records > 0 || vault.refused_person_records > 0 {
        PersonResolveError::CannotSearch {
            skipped: vault.skipped_person_records,
            refused: vault.refused_person_records,
        }
    } else {
        PersonResolveError::NotFound
    }
}

impl std::error::Error for PersonResolveError {}

/// Resolve `query` to exactly one person (see the module docs for the rule).
///
/// An unknown `p-<ULID>` and an unmatched name return
/// [`PersonResolveError::NotFound`] when the person set loaded in full,
/// or [`PersonResolveError::CannotSearch`] when person records went unread
/// (see `miss`); the caller applies the same generic error to either
/// form so a hidden person cannot be probed. Two arms are positive
/// knowledge, not misses, and stay `NotFound` however unread the vault
/// is: an id that resolves to a non-person record (that id is known not
/// to be a person, and no unread record could change that), and an empty
/// query (an empty string can never match, so the failure is not an
/// unsearchable vault).
pub fn resolve_person(vault: &Vault, query: &str) -> Result<PersonMatch, PersonResolveError> {
    // Id form: resolve directly, no cleared-set gate and no
    // canonicalization. This keeps every `p-<ULID>` write — including to a
    // `no-ai: true` person — working exactly as before.
    if let Ok(id) = RecordId::parse(query) {
        return match vault.records.get(&id) {
            Some(record) if record.kind == RecordKind::Person => Ok(PersonMatch {
                id,
                matched_by_name: false,
            }),
            Some(_) => Err(PersonResolveError::NotFound),
            None => Err(miss(vault)),
        };
    }

    let needle = case_fold(query.trim());
    if needle.is_empty() {
        return Err(PersonResolveError::NotFound);
    }

    let cleared = cleared_record_ids(vault);
    let as_of = resolve_as_of_date(vault);
    let known_ids: HashSet<RecordId> = vault.records.keys().cloned().collect();
    let mut merge_findings = Vec::new();
    let merges = check_aliases_and_merges(vault, &known_ids, as_of, &mut merge_findings);
    drop(merge_findings);

    // Sorted set of canonical people: deterministic candidates, and
    // `canonical_on` dedupes two members of one merge group.
    let mut matches: BTreeSet<RecordId> = BTreeSet::new();
    for record in vault.records.values() {
        if record.kind != RecordKind::Person || !cleared.contains(&record.id) {
            continue;
        }
        let Some(name) = record.name.as_deref() else {
            continue;
        };
        if case_fold(name.trim()) != needle {
            continue;
        }
        // The *canonical* must itself be cleared. A cleared person merged
        // into a `no-ai: true` person canonicalizes to the hidden id;
        // resolving — and then echoing the canonical's name — would leak a
        // `no-ai: true` person's existence. Fall through to `NotFound`
        // instead, indistinguishable from a name that matches nobody.
        let canonical = canonical_on(&record.id, &merges, as_of);
        if !cleared.contains(&canonical) {
            continue;
        }
        matches.insert(canonical);
    }

    match matches.len() {
        0 => Err(miss(vault)),
        1 => Ok(PersonMatch {
            id: matches.into_iter().next().expect("one match"),
            matched_by_name: true,
        }),
        _ => Err(PersonResolveError::Ambiguous {
            candidates: matches.into_iter().collect(),
        }),
    }
}

/// Resolve a `(kind, hmac)` alias to exactly one cleared person (#537 phase 3b).
///
/// `hmac_hex` is the lowercase hex of `HMAC(vault_lookup_key, normalized
/// value)` (spec §6). The caller computes it — core never touches keys — so
/// the plaintext value never reaches this function or its errors.
///
/// The match is against the §12 cleared set, exactly like a display-name
/// lookup: an alias line whose canonical person is `no-ai: true` is
/// indistinguishable from an unmatched alias ([`PersonResolveError::NotFound`]),
/// so the error never confirms a hidden person exists. Ledger `alias` lines
/// for a merged-away member canonicalize to the canonical person; two
/// distinct cleared canonical people sharing one alias fail closed
/// ([`PersonResolveError::Ambiguous`]).
pub fn resolve_alias(
    vault: &Vault,
    kind: &str,
    hmac_hex: &str,
) -> Result<PersonMatch, PersonResolveError> {
    let needle = hmac_hex.to_ascii_lowercase();
    let cleared = cleared_record_ids(vault);
    let as_of = resolve_as_of_date(vault);
    let known_ids: HashSet<RecordId> = vault.records.keys().cloned().collect();
    let mut merge_findings = Vec::new();
    let merges = check_aliases_and_merges(vault, &known_ids, as_of, &mut merge_findings);
    drop(merge_findings);

    let mut matches: BTreeSet<RecordId> = BTreeSet::new();
    for sourced in &vault.entries {
        if sourced.entry.verb != "alias" {
            continue;
        }
        // Reuse the check engine's parser so the accepted `hmac:HEX` shapes
        // (token or pair) stay identical to what `check` validates.
        match parse_alias(&sourced.entry) {
            Ok((k, hex)) if k == kind && hex == needle => {}
            _ => continue,
        }
        let canonical = canonical_on(&sourced.entry.id, &merges, as_of);
        // Only cleared people resolve. A cleared member merged into a
        // `no-ai: true` canonical maps to a hidden id and is dropped, so a
        // hidden person is never surfaced by an alias either.
        match vault.records.get(&canonical) {
            Some(record) if record.kind == RecordKind::Person && cleared.contains(&canonical) => {}
            _ => continue,
        }
        matches.insert(canonical);
    }

    match matches.len() {
        0 => Err(miss(vault)),
        1 => Ok(PersonMatch {
            id: matches.into_iter().next().expect("one match"),
            matched_by_name: false,
        }),
        _ => Err(PersonResolveError::Ambiguous {
            candidates: matches.into_iter().collect(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{resolve_alias, resolve_person, PersonMatch, PersonResolveError};
    use crate::id::RecordId;
    use crate::vault::Vault;
    use std::path::{Path, PathBuf};

    fn git(root: &Path, args: &[&str]) {
        let st = std::process::Command::new("git")
            .current_dir(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?} failed");
    }

    fn person(dir: &Path, id: &str, name: Option<&str>, no_ai: Option<&str>) {
        let d = dir.join(format!("people/{id}"));
        std::fs::create_dir_all(&d).unwrap();
        let name_line = name.map(|n| format!("name: \"{n}\"\n")).unwrap_or_default();
        let no_ai_line = no_ai.map(|m| format!("no-ai: {m}\n")).unwrap_or_default();
        std::fs::write(
            d.join("profile.md"),
            format!("---\nid: {id}\ntype: person\n{name_line}{no_ai_line}---\n\nFake bio.\n"),
        )
        .unwrap();
    }

    /// A fake git vault.
    fn vault(name: &str, build: impl FnOnce(&Path)) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join(name);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"01TEST00000000000000000000\"\n",
        )
        .unwrap();
        build(&root);
        git(&root, &["init", "-q", "-b", "master"]);
        git(&root, &["config", "user.email", "test@example.com"]);
        git(&root, &["config", "user.name", "Test"]);
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "base"]);
        (tmp, root)
    }

    fn load(root: &Path) -> Vault {
        crate::load_vault(root).unwrap()
    }

    /// Load with a hook that refuses (or skips) only the record file whose
    /// vault-relative path contains `needle`, standing in for one
    /// unreadable record in an otherwise readable vault. Every other file
    /// passes through unchanged, so the rest of the vault loads normally.
    fn load_refusing_only(root: &Path, needle: &str, skipped: bool) -> Vault {
        use crate::vault::ContentOutcome;
        let needle = needle.to_owned();
        let hook = std::sync::Arc::new(move |file: &str, bytes: &[u8]| {
            if file.contains(&needle) {
                if skipped {
                    ContentOutcome::Skipped
                } else {
                    ContentOutcome::Refused
                }
            } else {
                ContentOutcome::Content(bytes.to_vec())
            }
        });
        crate::vault::load_vault_with_hook(root, Some(hook)).unwrap()
    }

    /// Load with a hook that refuses to read any record file, standing in
    /// for a device with no usable key material (`skipped`) or with
    /// tampered envelopes (`refused`): the vault loads, but the record
    /// set is incomplete and the skip/refuse counts are nonzero.
    fn load_unread(root: &Path, skipped: bool) -> Vault {
        use crate::vault::ContentOutcome;
        let hook = std::sync::Arc::new(move |_: &str, _: &[u8]| {
            if skipped {
                ContentOutcome::Skipped
            } else {
                ContentOutcome::Refused
            }
        });
        crate::vault::load_vault_with_hook(root, Some(hook)).unwrap()
    }

    fn org(dir: &Path, id: &str, name: &str) {
        let d = dir.join(format!("orgs/{id}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("org.md"),
            format!("---\nid: {id}\ntype: org\nname: \"{name}\"\n---\n"),
        )
        .unwrap();
    }

    const ADA: &str = "p-01J9Z3K4QF0000000000000000";
    const BEA: &str = "p-01J9Z3K4QF0000000000000002";

    #[test]
    fn resolves_by_exact_name_and_by_id() {
        let (_tmp, root) = vault("ok", |root| {
            person(root, ADA, Some("Ada Example"), None);
            person(root, BEA, Some("Bea Demo"), None);
        });
        let vault = load(&root);
        assert_eq!(
            resolve_person(&vault, "Ada Example"),
            Ok(PersonMatch {
                id: RecordId::parse(ADA).unwrap(),
                matched_by_name: true,
            })
        );
        // Trimmed and case-insensitive.
        assert_eq!(
            resolve_person(&vault, "  ada example  "),
            Ok(PersonMatch {
                id: RecordId::parse(ADA).unwrap(),
                matched_by_name: true,
            })
        );
        assert_eq!(
            resolve_person(&vault, ADA),
            Ok(PersonMatch {
                id: RecordId::parse(ADA).unwrap(),
                matched_by_name: false,
            })
        );
    }

    #[test]
    fn substring_and_prefix_do_not_match() {
        let (_tmp, root) = vault("partial", |root| {
            person(root, ADA, Some("Ada Example"), None);
        });
        let vault = load(&root);
        assert_eq!(
            resolve_person(&vault, "Ada"),
            Err(PersonResolveError::NotFound)
        );
        assert_eq!(
            resolve_person(&vault, "Ada Example Jr"),
            Err(PersonResolveError::NotFound)
        );
    }

    #[test]
    fn ambiguous_name_lists_candidates() {
        let (_tmp, root) = vault("dup", |root| {
            person(root, ADA, Some("Same Name"), None);
            person(root, BEA, Some("Same Name"), None);
        });
        let vault = load(&root);
        assert_eq!(
            resolve_person(&vault, "Same Name"),
            Err(PersonResolveError::Ambiguous {
                candidates: vec![RecordId::parse(ADA).unwrap(), RecordId::parse(BEA).unwrap()],
            })
        );
    }

    #[test]
    fn no_ai_true_person_is_not_resolvable_by_name() {
        let (_tmp, root) = vault("hidden", |root| {
            person(root, ADA, Some("Hidden Person"), Some("true"));
        });
        let vault = load(&root);
        assert_eq!(
            resolve_person(&vault, "Hidden Person"),
            Err(PersonResolveError::NotFound)
        );
        // The id still resolves (id indexes without decrypting).
        assert_eq!(
            resolve_person(&vault, ADA),
            Ok(PersonMatch {
                id: RecordId::parse(ADA).unwrap(),
                matched_by_name: false,
            })
        );
    }

    #[test]
    fn no_ai_notes_person_resolves_by_name() {
        let (_tmp, root) = vault("notes", |root| {
            person(root, ADA, Some("Notes Person"), Some("notes"));
        });
        let vault = load(&root);
        assert_eq!(
            resolve_person(&vault, "Notes Person"),
            Ok(PersonMatch {
                id: RecordId::parse(ADA).unwrap(),
                matched_by_name: true,
            })
        );
    }

    #[test]
    fn merged_away_name_resolves_to_canonical() {
        let (_tmp, root) = vault("merged", |root| {
            person(root, ADA, Some("Ada Old"), None);
            person(root, BEA, Some("Bea New"), None);
            std::fs::create_dir_all(root.join("ledger/2026")).unwrap();
            std::fs::write(
                root.join("ledger/2026/10.cfd"),
                format!("2026-10-01 merge {ADA} into {BEA}\n"),
            )
            .unwrap();
        });
        let vault = load(&root);
        assert_eq!(
            resolve_person(&vault, "Ada Old"),
            Ok(PersonMatch {
                id: RecordId::parse(BEA).unwrap(),
                matched_by_name: true,
            })
        );
        assert_eq!(
            resolve_person(&vault, "Bea New"),
            Ok(PersonMatch {
                id: RecordId::parse(BEA).unwrap(),
                matched_by_name: true,
            })
        );
    }

    #[test]
    fn cleared_name_merged_into_no_ai_person_does_not_resolve() {
        // A cleared person ("Ada Old") merged into a `no-ai: true` person
        // canonicalizes to the hidden id. Resolving by the cleared name must
        // not return it, or a by-name write would echo the hidden name; the
        // query falls through to the same `NotFound` as a miss.
        let (_tmp, root) = vault("merged-hidden", |root| {
            person(root, ADA, Some("Ada Old"), None);
            person(root, BEA, Some("Hidden Canonical"), Some("true"));
            std::fs::create_dir_all(root.join("ledger/2026")).unwrap();
            std::fs::write(
                root.join("ledger/2026/10.cfd"),
                format!("2026-10-01 merge {ADA} into {BEA}\n"),
            )
            .unwrap();
        });
        let vault = load(&root);
        assert_eq!(
            resolve_person(&vault, "Ada Old"),
            Err(PersonResolveError::NotFound)
        );
        // The hidden canonical's own name is not resolvable either.
        assert_eq!(
            resolve_person(&vault, "Hidden Canonical"),
            Err(PersonResolveError::NotFound)
        );
        // The id still resolves: `no-ai: true` stays addressable by id.
        assert_eq!(
            resolve_person(&vault, BEA),
            Ok(PersonMatch {
                id: RecordId::parse(BEA).unwrap(),
                matched_by_name: false,
            })
        );
    }

    #[test]
    fn unread_vault_miss_is_cannot_search_not_not_found() {
        // #717: the field case — the person exists, but this device
        // cannot read the record file, so the name set is incomplete and
        // a miss must not be reported as "not found".
        for skipped in [true, false] {
            let (_tmp, root) = vault("unread", |root| {
                person(root, ADA, Some("Ada Example"), None);
            });
            let vault = load_unread(&root, skipped);
            assert!(vault.skipped_encrypted + vault.refused_envelopes > 0);
            let expected = if skipped {
                PersonResolveError::CannotSearch {
                    skipped: 1,
                    refused: 0,
                }
            } else {
                PersonResolveError::CannotSearch {
                    skipped: 0,
                    refused: 1,
                }
            };
            // The existing person's own name is missed too: her file
            // went unread, so the lookup cannot establish anything.
            assert_eq!(resolve_person(&vault, "Ada Example"), Err(expected.clone()));
            assert_eq!(resolve_person(&vault, "Nobody Here"), Err(expected.clone()));
            assert_eq!(resolve_person(&vault, ADA), Err(expected.clone()));
            // Alias lookups consult the same incomplete cleared set.
            assert_eq!(resolve_alias(&vault, "email", H1), Err(expected));
        }
    }

    #[test]
    fn mixed_vault_readable_person_resolves_unreadable_is_cannot_search() {
        // #717 review: the partial-search case — one readable person plus
        // one unreadable record. The readable person still resolves, but
        // the unreadable person's name and any unknown name are
        // cannot-search, not not-found.
        for skipped in [true, false] {
            let (_tmp, root) = vault("mixed", |root| {
                person(root, ADA, Some("Ada Example"), None);
                person(root, BEA, Some("Bea Demo"), None);
            });
            let vault = load_refusing_only(&root, BEA, skipped);
            assert_eq!(vault.skipped_person_records, u32::from(skipped));
            assert_eq!(vault.refused_person_records, u32::from(!skipped));
            let expected = if skipped {
                PersonResolveError::CannotSearch {
                    skipped: 1,
                    refused: 0,
                }
            } else {
                PersonResolveError::CannotSearch {
                    skipped: 0,
                    refused: 1,
                }
            };
            assert_eq!(
                resolve_person(&vault, "Ada Example"),
                Ok(PersonMatch {
                    id: RecordId::parse(ADA).unwrap(),
                    matched_by_name: true,
                })
            );
            assert_eq!(resolve_person(&vault, "Bea Demo"), Err(expected.clone()));
            assert_eq!(resolve_person(&vault, "Nobody Here"), Err(expected.clone()));
            assert_eq!(resolve_person(&vault, BEA), Err(expected));
        }
    }

    #[test]
    fn unreadable_non_person_record_does_not_gate_person_miss() {
        // #717 review: the gate is person-scoped. An unreadable org file
        // counts vault-wide but cannot hide a person, so a person miss
        // against an otherwise fully readable person set stays NotFound.
        // (The org id's ULID differs from Ada's: sharing a ULID stem
        // across prefixes would taint the cleared set via `path_ulids`,
        // which is a different rule, not the gate.)
        const ORG: &str = "o-01J9Z3K4QF0000000000000001";
        let (_tmp, root) = vault("org-unread", |root| {
            person(root, ADA, Some("Ada Example"), None);
            org(root, ORG, "Acme");
        });
        let vault = load_refusing_only(&root, ORG, false);
        assert_eq!(vault.refused_envelopes, 1);
        assert_eq!(vault.refused_person_records, 0);
        assert_eq!(vault.skipped_person_records, 0);
        assert_eq!(
            resolve_person(&vault, "Ada Example"),
            Ok(PersonMatch {
                id: RecordId::parse(ADA).unwrap(),
                matched_by_name: true,
            })
        );
        assert_eq!(
            resolve_person(&vault, "Nobody Here"),
            Err(PersonResolveError::NotFound)
        );
        assert_eq!(
            resolve_person(&vault, "p-01J9Z3K4QF9999999999999999"),
            Err(PersonResolveError::NotFound)
        );
    }

    #[test]
    fn non_person_id_and_empty_query_are_not_found_on_unread_vault() {
        // #717 review: both arms are positive knowledge, not misses. An
        // id that resolves to a loaded non-person record is known not to
        // be a person, and an empty string can never match, so neither
        // may become CannotSearch just because person records went
        // unread. (Only the person file is refused here: refusing every
        // file would leave the org itself unread, which is a miss, not
        // positive knowledge.)
        const ORG: &str = "o-01J9Z3K4QF0000000000000001";
        let (_tmp, root) = vault("org", |root| {
            person(root, ADA, Some("Ada Example"), None);
            org(root, ORG, "Acme");
        });
        let vault = load_refusing_only(&root, ADA, false);
        assert_eq!(vault.refused_person_records, 1);
        assert_eq!(
            resolve_person(&vault, ORG),
            Err(PersonResolveError::NotFound)
        );
        assert_eq!(
            resolve_person(&vault, ""),
            Err(PersonResolveError::NotFound)
        );
        assert_eq!(
            resolve_person(&vault, "   "),
            Err(PersonResolveError::NotFound)
        );
    }

    #[test]
    fn cannot_search_display_with_zero_counts_names_a_cause() {
        // The constructor is public, so a (0, 0) value can exist even
        // though `miss()` never builds one; its rendering must still name
        // a cause instead of trailing off after an empty list.
        let rendered = format!(
            "{}",
            PersonResolveError::CannotSearch {
                skipped: 0,
                refused: 0,
            }
        );
        assert!(rendered.starts_with("cannot search the vault: "));
        assert!(!rendered.ends_with(": "));
        assert!(rendered.contains("could not be fully searched"));
    }

    #[test]
    fn unknown_id_and_unknown_name_are_not_found() {
        let (_tmp, root) = vault("none", |root| {
            person(root, ADA, Some("Ada Example"), None);
        });
        let vault = load(&root);
        assert_eq!(
            resolve_person(&vault, "p-01J9Z3K4QF9999999999999999"),
            Err(PersonResolveError::NotFound)
        );
        assert_eq!(
            resolve_person(&vault, "Nobody Here"),
            Err(PersonResolveError::NotFound)
        );
    }

    #[test]
    fn non_person_id_is_not_found() {
        let (_tmp, root) = vault("org", |root| {
            let d = root.join("orgs/o-01J9Z3K4QF0000000000000000");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("org.md"),
                "---\nid: o-01J9Z3K4QF0000000000000000\ntype: org\nname: \"Acme\"\n---\n",
            )
            .unwrap();
        });
        let vault = load(&root);
        assert_eq!(
            resolve_person(&vault, "o-01J9Z3K4QF0000000000000000"),
            Err(PersonResolveError::NotFound)
        );
    }

    // Fake 64-hex HMACs (the real ones come from the lookup key in the CLI).
    const H1: &str = "6f2c9a1d8b7e4f30112233445566778899aabbccddeeff0011223344556677";
    const H2: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddee";

    fn ledger_line(root: &Path, line: &str) {
        let dir = root.join("ledger/2026");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("10.cfd");
        let mut text = std::fs::read_to_string(&path).unwrap_or_default();
        text.push_str(line);
        text.push('\n');
        std::fs::write(path, text).unwrap();
    }

    fn alias(root: &Path, date: &str, id: &str, kind: &str, hmac: &str) {
        ledger_line(root, &format!("{date} alias {id} {kind} hmac:{hmac}"));
    }

    #[test]
    fn resolve_alias_matches_one_cleared_person() {
        let (_tmp, root) = vault("alias", |root| {
            person(root, ADA, Some("Ada Example"), None);
            alias(root, "2026-10-03", ADA, "email", H1);
        });
        let vault = load(&root);
        assert_eq!(
            resolve_alias(&vault, "email", H1),
            Ok(PersonMatch {
                id: RecordId::parse(ADA).unwrap(),
                matched_by_name: false,
            })
        );
        // HMAC hex comparison is case-insensitive.
        assert_eq!(
            resolve_alias(&vault, "email", &H1.to_ascii_uppercase()),
            Ok(PersonMatch {
                id: RecordId::parse(ADA).unwrap(),
                matched_by_name: false,
            })
        );
        // Wrong kind, wrong hmac, and unknown kinds never match.
        assert_eq!(
            resolve_alias(&vault, "phone", H1),
            Err(PersonResolveError::NotFound)
        );
        assert_eq!(
            resolve_alias(&vault, "email", H2),
            Err(PersonResolveError::NotFound)
        );
        assert_eq!(
            resolve_alias(&vault, "twitter", H1),
            Err(PersonResolveError::NotFound)
        );
    }

    #[test]
    fn resolve_alias_name_kind_matches_one_cleared_person() {
        // #748: a `name` alias resolves through the same HMAC path as the
        // other kinds, and is kind-scoped — the same HMAC under `email`
        // does not match it.
        let (_tmp, root) = vault("alias-name", |root| {
            person(root, ADA, Some("Ada Example"), None);
            alias(root, "2026-10-03", ADA, "name", H1);
        });
        let vault = load(&root);
        assert_eq!(
            resolve_alias(&vault, "name", H1),
            Ok(PersonMatch {
                id: RecordId::parse(ADA).unwrap(),
                matched_by_name: false,
            })
        );
        // Different case/whitespace-insensitive comparison is on the HMAC
        // hex, as for the other kinds.
        assert_eq!(
            resolve_alias(&vault, "name", &H1.to_ascii_uppercase()),
            Ok(PersonMatch {
                id: RecordId::parse(ADA).unwrap(),
                matched_by_name: false,
            })
        );
        assert_eq!(
            resolve_alias(&vault, "email", H1),
            Err(PersonResolveError::NotFound)
        );
        assert_eq!(
            resolve_alias(&vault, "twitter", H1),
            Err(PersonResolveError::NotFound)
        );
    }

    #[test]
    fn resolve_alias_name_kind_shared_by_two_cleared_people_is_ambiguous() {
        // #748: the shared-alias ambiguity rule applies to `name` exactly
        // as to the other kinds — two cleared people, fail closed.
        let (_tmp, root) = vault("alias-name-dup", |root| {
            person(root, ADA, Some("Ada Example"), None);
            person(root, BEA, Some("Bea Demo"), None);
            alias(root, "2026-10-03", ADA, "name", H1);
            alias(root, "2026-10-03", BEA, "name", H1);
        });
        let vault = load(&root);
        assert_eq!(
            resolve_alias(&vault, "name", H1),
            Err(PersonResolveError::Ambiguous {
                candidates: vec![RecordId::parse(ADA).unwrap(), RecordId::parse(BEA).unwrap()],
            })
        );
    }

    #[test]
    fn resolve_alias_canonicalizes_merged_away_member() {
        let (_tmp, root) = vault("alias-merged", |root| {
            person(root, ADA, Some("Ada Old"), None);
            person(root, BEA, Some("Bea New"), None);
            alias(root, "2026-10-03", ADA, "handle", H1);
            alias(root, "2026-10-04", BEA, "handle", H2);
            // The merge is dated after the alias lines; current-state
            // resolution folds both onto the canonical.
            ledger_line(root, &format!("2026-10-05 merge {ADA} into {BEA}"));
        });
        let vault = load(&root);
        assert_eq!(
            resolve_alias(&vault, "handle", H1),
            Ok(PersonMatch {
                id: RecordId::parse(BEA).unwrap(),
                matched_by_name: false,
            })
        );
        assert_eq!(
            resolve_alias(&vault, "handle", H2),
            Ok(PersonMatch {
                id: RecordId::parse(BEA).unwrap(),
                matched_by_name: false,
            })
        );
    }

    #[test]
    fn resolve_alias_no_ai_true_person_is_not_surfaced() {
        let (_tmp, root) = vault("alias-hidden", |root| {
            person(root, ADA, Some("Hidden Person"), Some("true"));
            alias(root, "2026-10-03", ADA, "email", H1);
        });
        let vault = load(&root);
        // Indistinguishable from an unmatched alias: no existence oracle.
        assert_eq!(
            resolve_alias(&vault, "email", H1),
            Err(PersonResolveError::NotFound)
        );
    }

    #[test]
    fn resolve_alias_shared_by_two_cleared_people_is_ambiguous() {
        let (_tmp, root) = vault("alias-dup", |root| {
            person(root, ADA, Some("Ada Example"), None);
            person(root, BEA, Some("Bea Demo"), None);
            alias(root, "2026-10-03", ADA, "email", H1);
            alias(root, "2026-10-03", BEA, "email", H1);
        });
        let vault = load(&root);
        assert_eq!(
            resolve_alias(&vault, "email", H1),
            Err(PersonResolveError::Ambiguous {
                candidates: vec![RecordId::parse(ADA).unwrap(), RecordId::parse(BEA).unwrap()],
            })
        );
    }

    #[test]
    fn resolve_alias_cleared_name_merged_into_no_ai_is_not_surfaced() {
        let (_tmp, root) = vault("alias-merged-hidden", |root| {
            person(root, ADA, Some("Ada Old"), None);
            person(root, BEA, Some("Hidden Canonical"), Some("true"));
            alias(root, "2026-10-03", ADA, "email", H1);
            ledger_line(root, &format!("2026-10-05 merge {ADA} into {BEA}"));
        });
        let vault = load(&root);
        assert_eq!(
            resolve_alias(&vault, "email", H1),
            Err(PersonResolveError::NotFound)
        );
    }
}
