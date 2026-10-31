//! Resolve a `--person` / `resolve` / `alias` query to the canonical person
//! (#537).
//!
//! [`resolve_person`] accepts two forms; [`resolve_alias`] takes a
//! `(kind, value)` alias and resolves it against the same cleared set:
//!
//! - an opaque `p-<ULID>`, resolved directly against the loaded vault, so a
//!   `no-ai: true` person stays addressable by id;
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
//!
//! Aliases are plain contact values, not secrets: [`resolve_alias`] matches
//! `email` against the person's `emails` front-matter list, `phone` against
//! `phones`, `handle` against `handles` (or the value half of a `links`
//! entry), and `name` against the display name. Matching is trimmed,
//! case-insensitive, whole-string, and goes through the same cleared set and
//! merge canonicalization as a name lookup.

use std::collections::{BTreeSet, HashSet};

use crate::check::{canonical_on, check_aliases_and_merges, resolve_as_of_date};
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
    /// absence (#717). Kept on the public error surface so callers can keep
    /// branching on it; with plaintext vaults every record file loads, so
    /// no lookup constructs it today.
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
                let unreadable = skipped.saturating_add(*refused);
                let cause = if unreadable > 0 {
                    format!("{unreadable} person record file(s) unreadable")
                } else {
                    // The constructor is public, so a (0, 0) value can
                    // exist even though `miss()` never builds one; never
                    // render an empty cause list.
                    "the vault could not be fully searched".to_owned()
                };
                write!(formatter, "cannot search the vault: {cause}")
            }
        }
    }
}

/// The miss outcome for `vault`. A plaintext vault loads every record file,
/// so a miss always establishes absence; `CannotSearch` is retained on the
/// public error surface for callers but never constructed.
fn miss(_vault: &Vault) -> PersonResolveError {
    PersonResolveError::NotFound
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

/// Resolve a `(kind, value)` alias to exactly one cleared person (#537
/// phase 3b).
///
/// Aliases are plain front-matter values, matched trimmed and
/// case-insensitively as whole strings:
///
/// - `email` → the `emails` list;
/// - `phone` → the `phones` list;
/// - `handle` → the `handles` list, or the value half of a `links` entry;
/// - `name` → the record's display name.
///
/// The match is against the §12 cleared set, exactly like a display-name
/// lookup: a person who is `no-ai: true` is indistinguishable from an
/// unmatched alias ([`PersonResolveError::NotFound`]), so the error never
/// confirms a hidden person exists. A merged-away member canonicalizes to
/// the canonical person; two distinct cleared canonical people sharing one
/// alias fail closed ([`PersonResolveError::Ambiguous`]).
pub fn resolve_alias(
    vault: &Vault,
    kind: &str,
    value: &str,
) -> Result<PersonMatch, PersonResolveError> {
    let needle = case_fold(value.trim());
    if needle.is_empty() {
        return Err(PersonResolveError::NotFound);
    }
    let cleared = cleared_record_ids(vault);
    let as_of = resolve_as_of_date(vault);
    let known_ids: HashSet<RecordId> = vault.records.keys().cloned().collect();
    let mut merge_findings = Vec::new();
    let merges = check_aliases_and_merges(vault, &known_ids, as_of, &mut merge_findings);
    drop(merge_findings);

    let mut matches: BTreeSet<RecordId> = BTreeSet::new();
    for record in vault.records.values() {
        if record.kind != RecordKind::Person || !cleared.contains(&record.id) {
            continue;
        }
        let hit = match kind {
            "email" => list_field_contains(record, "emails", &needle),
            "phone" => list_field_contains(record, "phones", &needle),
            "handle" => {
                list_field_contains(record, "handles", &needle)
                    || links_field_contains(record, &needle)
            }
            "name" => record
                .name
                .as_deref()
                .is_some_and(|name| case_fold(name.trim()) == needle),
            _ => false,
        };
        if !hit {
            continue;
        }
        let canonical = canonical_on(&record.id, &merges, as_of);
        // Only cleared people resolve. A cleared member merged into a
        // `no-ai: true` canonical maps to a hidden id and is dropped, so a
        // hidden person is never surfaced by an alias either.
        if cleared.contains(&canonical) {
            matches.insert(canonical);
        }
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

/// Whether a `list` front-matter field contains `needle` (already
/// case-folded). A value that does not parse as a list never matches.
fn list_field_contains(record: &crate::record::Record, field: &str, needle: &str) -> bool {
    record
        .field(field)
        .and_then(crate::packs::grammars::parse_list)
        .is_some_and(|entries| entries.iter().any(|e| case_fold(e.trim()) == needle))
}

/// Whether a `links` labeled-list field carries `needle` as its value half.
fn links_field_contains(record: &crate::record::Record, needle: &str) -> bool {
    record
        .field("links")
        .and_then(crate::packs::grammars::parse_labeled_list)
        .is_some_and(|entries| {
            entries
                .iter()
                .any(|(_, value)| case_fold(value.trim()) == needle)
        })
}

/// The merge-canonical person id for `id` as of the vault's resolution
/// date: the id itself when no `merge` line applies to it, otherwise
/// the canonical person its merge group resolves to (the same walk
/// [`resolve_alias`] uses, so the two can be compared canonical to
/// canonical). This is deliberately the only canonicalization query
/// exposed outside this module: callers that must tell "the same
/// canonical person" from "a different person" — the `alias add`
/// ambiguity probe — need the canonical id, and no other lookup
/// returns it (`resolve_person` by id deliberately does not
/// canonicalize, and a name lookup needs a unique display name).
/// It exposes no merge map and no canonicalization machinery.
pub fn canonical_person_id(vault: &Vault, id: &RecordId) -> RecordId {
    let as_of = resolve_as_of_date(vault);
    let known_ids: HashSet<RecordId> = vault.records.keys().cloned().collect();
    let mut merge_findings = Vec::new();
    let merges = check_aliases_and_merges(vault, &known_ids, as_of, &mut merge_findings);
    drop(merge_findings);
    canonical_on(id, &merges, as_of)
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
        // The id still resolves (an id lookup never consults the display
        // name or the cleared set).
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
    fn canonical_person_id_follows_merge() {
        // #767 fix round 3: the alias-add probe must compare canonical
        // to canonical, so it needs the target's canonical id.
        let (_tmp, root) = vault("merged-canonical", |root| {
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
            super::canonical_person_id(&vault, &RecordId::parse(ADA).unwrap()),
            RecordId::parse(BEA).unwrap()
        );
        assert_eq!(
            super::canonical_person_id(&vault, &RecordId::parse(BEA).unwrap()),
            RecordId::parse(BEA).unwrap()
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

    fn ledger_line(root: &Path, line: &str) {
        let dir = root.join("ledger/2026");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("10.cfd");
        let mut text = std::fs::read_to_string(&path).unwrap_or_default();
        text.push_str(line);
        text.push('\n');
        std::fs::write(path, text).unwrap();
    }

    /// A person with extra front-matter fields (contact lists).
    fn contact_person(dir: &Path, id: &str, name: &str, extra: &str) {
        let d = dir.join(format!("people/{id}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("profile.md"),
            format!("---\nid: {id}\ntype: person\nname: \"{name}\"\n{extra}---\n\nFake bio.\n"),
        )
        .unwrap();
    }

    #[test]
    fn resolve_alias_matches_front_matter_contact_lists() {
        let (_tmp, root) = vault("alias", |root| {
            contact_person(
                root,
                ADA,
                "Ada Example",
                "emails: [ada@example.com, ada@work.example]\nphones: +15550100\nhandles: @ada\nlinks: linkedin:https://example.test/in/ada\n",
            );
        });
        let vault = load(&root);
        let expected = PersonMatch {
            id: RecordId::parse(ADA).unwrap(),
            matched_by_name: false,
        };
        assert_eq!(
            resolve_alias(&vault, "email", "ada@example.com"),
            Ok(expected.clone())
        );
        // Trimmed and case-insensitive.
        assert_eq!(
            resolve_alias(&vault, "email", "  ADA@WORK.EXAMPLE "),
            Ok(expected.clone())
        );
        assert_eq!(
            resolve_alias(&vault, "phone", "+15550100"),
            Ok(expected.clone())
        );
        assert_eq!(
            resolve_alias(&vault, "handle", "@ada"),
            Ok(expected.clone())
        );
        assert_eq!(
            resolve_alias(&vault, "handle", "https://example.test/in/ada"),
            Ok(expected.clone())
        );
        assert_eq!(resolve_alias(&vault, "name", "Ada Example"), Ok(expected));
    }

    #[test]
    fn resolve_alias_is_kind_scoped_and_misses_cleanly() {
        let (_tmp, root) = vault("alias-kinds", |root| {
            contact_person(root, ADA, "Ada Example", "emails: ada@example.com\n");
        });
        let vault = load(&root);
        // The value exists, but under `email`, not `phone`/`handle`.
        assert_eq!(
            resolve_alias(&vault, "phone", "ada@example.com"),
            Err(PersonResolveError::NotFound)
        );
        assert_eq!(
            resolve_alias(&vault, "handle", "ada@example.com"),
            Err(PersonResolveError::NotFound)
        );
        assert_eq!(
            resolve_alias(&vault, "email", "nobody@example.com"),
            Err(PersonResolveError::NotFound)
        );
        // An unknown kind never matches.
        assert_eq!(
            resolve_alias(&vault, "twitter", "ada@example.com"),
            Err(PersonResolveError::NotFound)
        );
        assert_eq!(
            resolve_alias(&vault, "email", "   "),
            Err(PersonResolveError::NotFound)
        );
    }

    #[test]
    fn resolve_alias_shared_by_two_cleared_people_is_ambiguous() {
        let (_tmp, root) = vault("alias-dup", |root| {
            contact_person(root, ADA, "Ada Example", "emails: shared@example.com\n");
            contact_person(root, BEA, "Bea Demo", "emails: shared@example.com\n");
        });
        let vault = load(&root);
        assert_eq!(
            resolve_alias(&vault, "email", "shared@example.com"),
            Err(PersonResolveError::Ambiguous {
                candidates: vec![RecordId::parse(ADA).unwrap(), RecordId::parse(BEA).unwrap()],
            })
        );
    }

    #[test]
    fn resolve_alias_canonicalizes_merged_away_member() {
        let (_tmp, root) = vault("alias-merged", |root| {
            contact_person(root, ADA, "Ada Old", "emails: ada@example.com\n");
            contact_person(root, BEA, "Bea New", "emails: bea@example.com\n");
            ledger_line(root, &format!("2026-10-05 merge {ADA} into {BEA}"));
        });
        let vault = load(&root);
        for email in ["ada@example.com", "bea@example.com"] {
            assert_eq!(
                resolve_alias(&vault, "email", email),
                Ok(PersonMatch {
                    id: RecordId::parse(BEA).unwrap(),
                    matched_by_name: false,
                })
            );
        }
    }

    #[test]
    fn resolve_alias_no_ai_true_person_is_not_surfaced() {
        let (_tmp, root) = vault("alias-hidden", |root| {
            let d = root.join(format!("people/{ADA}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("profile.md"),
                format!(
                    "---\nid: {ADA}\ntype: person\nname: \"Hidden Person\"\nno-ai: true\nemails: hidden@example.com\n---\n\nFake bio.\n"
                ),
            )
            .unwrap();
        });
        let vault = load(&root);
        // Indistinguishable from an unmatched alias: no existence oracle.
        assert_eq!(
            resolve_alias(&vault, "email", "hidden@example.com"),
            Err(PersonResolveError::NotFound)
        );
    }

    #[test]
    fn resolve_alias_cleared_name_merged_into_no_ai_is_not_surfaced() {
        let (_tmp, root) = vault("alias-merged-hidden", |root| {
            contact_person(root, ADA, "Ada Old", "emails: ada@example.com\n");
            let d = root.join(format!("people/{BEA}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("profile.md"),
                format!(
                    "---\nid: {BEA}\ntype: person\nname: \"Hidden Canonical\"\nno-ai: true\n---\n\nFake bio.\n"
                ),
            )
            .unwrap();
            ledger_line(root, &format!("2026-10-05 merge {ADA} into {BEA}"));
        });
        let vault = load(&root);
        assert_eq!(
            resolve_alias(&vault, "email", "ada@example.com"),
            Err(PersonResolveError::NotFound)
        );
    }
}
