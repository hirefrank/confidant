//! Record-type declarations and the per-vault type registry (spec 0.3).
//!
//! Core types are static declarations. Pack types come from a v3 manifest's
//! `[[record_types]]` tables. The registry is the single lookup for a type's
//! name, ID prefix, collection directory, main file, and semantics; it also
//! records enabled/disabled/retired state for the allowlist, scope, and
//! `check`.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::config::SpecVersion;
use crate::id::Prefix;

/// `no-ai` capability of a record type (spec 0.3 §4).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum NoAiPolicy {
    /// No `no-ai` key is allowed (`E_FRONTMATTER`).
    None,
    /// `true` / `false`; `true` hides the record.
    Full,
    /// `true` / `false` / `notes`; `notes` keeps the record visible but hides
    /// its attached notes/interactions by default. Requires `person_like`.
    Notes,
}

impl NoAiPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "none" => Some(Self::None),
            "full" => Some(Self::Full),
            "notes" => Some(Self::Notes),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Full => "full",
            Self::Notes => "notes",
        }
    }
}

/// Who owns a record type for scoping and orphan reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TypeOwner {
    Core,
    Pack(&'static str),
    Retired(&'static str),
}

impl TypeOwner {
    pub fn label(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Pack(name) | Self::Retired(name) => name,
        }
    }
}

/// One record-type declaration.
///
/// `prefix` is the parsed form of `id_prefix`; both are kept because conflict
/// messages and manifests carry the string spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordTypeDecl {
    pub name: &'static str,
    pub id_prefix: &'static str,
    pub prefix: Prefix,
    pub collection: &'static str,
    pub main_file: &'static str,
    pub entity: bool,
    pub person_like: bool,
    pub no_ai: NoAiPolicy,
    pub roster: bool,
    pub required_fields: &'static [&'static str],
    pub optional_fields: &'static [&'static str],
    pub owner: TypeOwner,
    pub enabled: bool,
    pub retired: bool,
}

impl RecordTypeDecl {
    pub fn is_core(&self) -> bool {
        self.owner == TypeOwner::Core
    }
}

/// The six core types. `package` is a ledger ID prefix, not a record type.
pub const CORE_TYPES: &[RecordTypeDecl] = &[
    RecordTypeDecl {
        name: "person",
        id_prefix: "p",
        prefix: Prefix::Person,
        collection: "people",
        main_file: "profile.md",
        entity: true,
        person_like: true,
        no_ai: NoAiPolicy::Notes,
        roster: true,
        required_fields: &[],
        optional_fields: &[],
        owner: TypeOwner::Core,
        enabled: true,
        retired: false,
    },
    RecordTypeDecl {
        name: "org",
        id_prefix: "o",
        prefix: Prefix::Org,
        collection: "orgs",
        main_file: "org.md",
        entity: true,
        person_like: false,
        no_ai: NoAiPolicy::None,
        roster: true,
        required_fields: &[],
        optional_fields: &[],
        owner: TypeOwner::Core,
        enabled: true,
        retired: false,
    },
    RecordTypeDecl {
        name: "deal",
        id_prefix: "d",
        prefix: Prefix::Deal,
        collection: "deals",
        main_file: "deal.md",
        entity: false,
        person_like: false,
        no_ai: NoAiPolicy::Full,
        roster: true,
        required_fields: &[],
        optional_fields: &[],
        owner: TypeOwner::Core,
        enabled: true,
        retired: false,
    },
    RecordTypeDecl {
        name: "interaction",
        id_prefix: "i",
        prefix: Prefix::Interaction,
        collection: "interactions",
        main_file: "interaction.md",
        entity: false,
        person_like: false,
        no_ai: NoAiPolicy::Full,
        roster: false,
        required_fields: &[],
        optional_fields: &[],
        owner: TypeOwner::Core,
        enabled: true,
        retired: false,
    },
    RecordTypeDecl {
        name: "note",
        id_prefix: "n",
        prefix: Prefix::Note,
        collection: "notes",
        main_file: "note.md",
        entity: false,
        person_like: false,
        no_ai: NoAiPolicy::Full,
        roster: false,
        required_fields: &[],
        optional_fields: &[],
        owner: TypeOwner::Core,
        enabled: true,
        retired: false,
    },
    RecordTypeDecl {
        name: "edge",
        id_prefix: "e",
        prefix: Prefix::Edge,
        collection: "edges",
        main_file: "edge.md",
        entity: false,
        person_like: false,
        // Edge-level `no-ai` is PR 2; 0.3's record-type core keeps edges
        // `no-ai`-free until then.
        no_ai: NoAiPolicy::None,
        roster: false,
        required_fields: &[],
        optional_fields: &[],
        owner: TypeOwner::Core,
        enabled: true,
        retired: false,
    },
];

/// One source of declarations: core, a registered pack, or retired config.
#[derive(Clone, Copy, Debug)]
pub struct TypeSource {
    pub owner: TypeOwner,
    pub decls: &'static [RecordTypeDecl],
    pub enabled: bool,
}

/// A problem the registry found while combining declarations. Vault load
/// turns these into findings; the registry still resolves deterministically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypeProblem {
    /// Two registered packs claim the same name/prefix/collection.
    Conflict {
        claim_kind: &'static str,
        claim: String,
        first: &'static str,
        second: &'static str,
    },
    /// A pack claims a core name/prefix/collection.
    CoreCollision {
        claim_kind: &'static str,
        claim: String,
        pack: &'static str,
    },
    /// A retired declaration collides with a live type.
    RetiredCollision {
        claim_kind: &'static str,
        claim: String,
        live: &'static str,
    },
    /// A `[[retired_types]]` entry is malformed.
    InvalidRetired { message: String },
}

fn note_collision(
    all: &[RecordTypeDecl],
    first_idx: usize,
    idx: usize,
    claim_kind: &'static str,
    claim: String,
    conflicting: &mut BTreeSet<usize>,
    problems: &mut Vec<TypeProblem>,
) {
    conflicting.insert(first_idx);
    conflicting.insert(idx);
    let first_owner = all[first_idx].owner;
    let this_owner = all[idx].owner;
    match (first_owner, this_owner) {
        (TypeOwner::Core, TypeOwner::Pack(pack)) => {
            // Never disable a core type because a pack tried to shadow it.
            conflicting.remove(&first_idx);
            problems.push(TypeProblem::CoreCollision {
                claim_kind,
                claim,
                pack,
            });
        }
        (TypeOwner::Pack(pack), TypeOwner::Core) => {
            conflicting.remove(&idx);
            problems.push(TypeProblem::CoreCollision {
                claim_kind,
                claim,
                pack,
            });
        }
        (TypeOwner::Retired(live), _) => {
            // The retired declaration is first; the live one wins and stays
            // enabled.
            conflicting.remove(&idx);
            problems.push(TypeProblem::RetiredCollision {
                claim_kind,
                claim,
                live,
            });
        }
        (_, TypeOwner::Retired(live)) => {
            // The live declaration is first; only the tombstone is disabled.
            conflicting.remove(&idx);
            problems.push(TypeProblem::RetiredCollision {
                claim_kind,
                claim,
                live,
            });
        }
        (TypeOwner::Pack(first), TypeOwner::Pack(second)) => {
            // Two enabled packs are already reported by `find_conflict`
            // (which also skips folding); only report here when at least one
            // side is disabled so the operator is not told twice.
            if !all[first_idx].enabled || !all[idx].enabled {
                problems.push(TypeProblem::Conflict {
                    claim_kind,
                    claim,
                    first,
                    second,
                });
            }
        }
        (TypeOwner::Core, TypeOwner::Core) => {
            conflicting.remove(&first_idx);
            conflicting.remove(&idx);
        }
    }
}

/// The resolved type table for one vault.
#[derive(Clone, Debug, Default)]
pub struct TypeRegistry {
    by_name: BTreeMap<&'static str, RecordTypeDecl>,
    by_prefix: BTreeMap<Prefix, RecordTypeDecl>,
    by_collection: BTreeMap<&'static str, RecordTypeDecl>,
}

impl TypeRegistry {
    /// Build from core, every registered pack, and retired config. Pack
    /// declarations are included for 0.3 and newer; older specs see core
    /// types only.
    pub fn build(
        spec: SpecVersion,
        sources: &[TypeSource],
        retired: Vec<RecordTypeDecl>,
        retired_problems: Vec<TypeProblem>,
    ) -> (Self, Vec<TypeProblem>) {
        let mut problems = retired_problems;
        let mut all: Vec<RecordTypeDecl> = Vec::new();
        for decl in CORE_TYPES {
            all.push(*decl);
        }
        if spec >= SpecVersion::V03 {
            for source in sources {
                for decl in source.decls {
                    let mut decl = *decl;
                    decl.owner = source.owner;
                    decl.enabled = source.enabled;
                    decl.retired = false;
                    all.push(decl);
                }
            }
            all.extend(retired);
        }

        // Find every claim collision first; mark both declarations disabled
        // so a conflicting pack never contributes an enabled type.
        let mut conflicting: BTreeSet<usize> = BTreeSet::new();
        let mut name_seen: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut prefix_seen: BTreeMap<Prefix, usize> = BTreeMap::new();
        let mut collection_seen: BTreeMap<&'static str, usize> = BTreeMap::new();
        for (idx, decl) in all.iter().enumerate() {
            if let Some(&first_idx) = name_seen.get(decl.name) {
                note_collision(
                    &all,
                    first_idx,
                    idx,
                    "record type",
                    decl.name.to_owned(),
                    &mut conflicting,
                    &mut problems,
                );
            } else {
                name_seen.insert(decl.name, idx);
            }
            if let Some(&first_idx) = prefix_seen.get(&decl.prefix) {
                note_collision(
                    &all,
                    first_idx,
                    idx,
                    "record type prefix",
                    decl.id_prefix.to_owned(),
                    &mut conflicting,
                    &mut problems,
                );
            } else {
                prefix_seen.insert(decl.prefix, idx);
            }
            if let Some(&first_idx) = collection_seen.get(decl.collection) {
                note_collision(
                    &all,
                    first_idx,
                    idx,
                    "record type collection",
                    decl.collection.to_owned(),
                    &mut conflicting,
                    &mut problems,
                );
            } else {
                collection_seen.insert(decl.collection, idx);
            }
        }

        let mut registry = Self::default();
        for (idx, decl) in all.iter().enumerate() {
            let mut decl = *decl;
            if conflicting.contains(&idx) {
                decl.enabled = false;
            }
            registry.by_name.entry(decl.name).or_insert(decl);
            registry.by_prefix.entry(decl.prefix).or_insert(decl);
            registry
                .by_collection
                .entry(decl.collection)
                .or_insert(decl);
        }
        (registry, problems)
    }

    pub fn get(&self, name: &str) -> Option<&RecordTypeDecl> {
        self.by_name.get(name)
    }

    pub fn get_by_prefix(&self, prefix: Prefix) -> Option<&RecordTypeDecl> {
        self.by_prefix.get(&prefix)
    }

    pub fn get_by_collection(&self, collection: &str) -> Option<&RecordTypeDecl> {
        self.by_collection.get(collection)
    }

    pub fn is_enabled(&self, name: &str) -> bool {
        self.get(name).is_some_and(|decl| decl.enabled)
    }

    pub fn is_entity(&self, prefix: Prefix) -> bool {
        self.get_by_prefix(prefix).is_some_and(|decl| decl.entity)
    }

    pub fn is_person_like(&self, name: &str) -> bool {
        self.get(name).is_some_and(|decl| decl.person_like)
    }

    pub fn collections(&self) -> Vec<&'static str> {
        self.by_collection.keys().copied().collect()
    }

    pub fn main_files(&self) -> Vec<&'static str> {
        let mut files: Vec<&'static str> = self
            .by_collection
            .values()
            .map(|decl| decl.main_file)
            .collect();
        files.sort_unstable();
        files.dedup();
        files
    }

    pub fn all(&self) -> impl Iterator<Item = &RecordTypeDecl> {
        self.by_name.values()
    }
}

/// Schema context for parsing a record. `types` is absent for the standalone
/// parser (core types only); the vault path passes its registry.
#[derive(Clone, Copy, Debug)]
pub struct RecordSchema<'a> {
    pub spec: SpecVersion,
    pub types: Option<&'a TypeRegistry>,
    /// `true` refuses an undeclared non-core type (writes). `false` loads it
    /// so `check` can report an orphan/unknown type.
    pub require_declared: bool,
}

impl<'a> RecordSchema<'a> {
    pub fn core(spec: SpecVersion) -> Self {
        Self {
            spec,
            types: None,
            require_declared: true,
        }
    }
}

/// A `[[retired_types]]` entry in `confidant.toml` (spec 0.3 §2/§8).
/// Pack removal will write these later (#699); the format and read behavior
/// land here so orphaned records stay parseable.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetiredTypeConfig {
    pub name: String,
    pub id_prefix: String,
    pub collection: String,
    pub main_file: String,
    #[serde(default)]
    pub entity: bool,
    #[serde(default)]
    pub person_like: bool,
    #[serde(default)]
    pub no_ai: String,
    #[serde(default)]
    pub roster: Option<bool>,
    #[serde(default)]
    pub removed_pack: Option<String>,
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

pub fn valid_type_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

pub fn is_core_type_name(name: &str) -> bool {
    CORE_TYPES.iter().any(|decl| decl.name == name) || name == "package"
}

pub fn valid_pack_prefix(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    if bytes.len() != 2 || !bytes[0].is_ascii_lowercase() || !bytes[1].is_ascii_lowercase() {
        return false;
    }
    // The scanner must be able to tell a two-letter pack prefix from a
    // one-letter core prefix glued after a letter (`xp-<ULID>` is a person
    // ID, not a pack `xp`). Forbid a core prefix letter in the second
    // position so that ambiguity cannot arise.
    !matches!(bytes[1], b'p' | b'o' | b'd' | b'i' | b'n' | b'e')
}

pub fn valid_collection(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "ledger",
        "packs",
        "keys",
        ".confidant",
        "confidant.toml",
        "confidant.lock",
        "people",
        "orgs",
        "deals",
        "interactions",
        "notes",
        "edges",
        "README.md",
        "LICENSE",
    ];
    let bytes = name.as_bytes();
    if RESERVED.contains(&name) {
        return false;
    }
    if bytes.is_empty() || bytes.len() > 32 || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

pub fn valid_main_file(name: &str) -> bool {
    if name.is_empty() || name.starts_with('.') || name.eq_ignore_ascii_case("README.md") {
        return false;
    }
    if !name.ends_with(".md") || name.contains('/') {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
}

/// Turn configured tombstones into declarations, or report why not.
pub fn retired_decls(configs: &[RetiredTypeConfig]) -> (Vec<RecordTypeDecl>, Vec<TypeProblem>) {
    let mut decls = Vec::new();
    let mut problems = Vec::new();
    let mut names = BTreeSet::new();
    let mut prefixes = BTreeSet::new();
    let mut collections = BTreeSet::new();
    for cfg in configs {
        let mut bad = |message: String| problems.push(TypeProblem::InvalidRetired { message });
        if !valid_type_name(&cfg.name) || is_core_type_name(&cfg.name) {
            bad("retired type name is not valid or is a core type".to_owned());
            continue;
        }
        if !valid_pack_prefix(&cfg.id_prefix) {
            bad(
                "retired type id_prefix must be two lowercase letters (and not end in p/o/d/i/n/e)"
                    .to_owned(),
            );
            continue;
        }
        let prefix = match Prefix::parse(&cfg.id_prefix) {
            Some(prefix @ Prefix::Pack(_)) => prefix,
            _ => {
                bad("retired type id_prefix must be two lowercase letters".to_owned());
                continue;
            }
        };
        if !valid_collection(&cfg.collection) {
            bad("retired type collection is not valid or is reserved".to_owned());
            continue;
        }
        if !valid_main_file(&cfg.main_file) {
            bad("retired type main_file is not a plain .md file name".to_owned());
            continue;
        }
        let no_ai = match NoAiPolicy::parse(if cfg.no_ai.is_empty() {
            "none"
        } else {
            &cfg.no_ai
        }) {
            Some(policy) => policy,
            None => {
                bad("retired type no_ai must be none, full, or notes".to_owned());
                continue;
            }
        };
        if cfg.person_like && !cfg.entity {
            bad("retired person_like type must also be entity".to_owned());
            continue;
        }
        if no_ai == NoAiPolicy::Notes && !cfg.person_like {
            bad("retired no_ai = notes requires person_like".to_owned());
            continue;
        }
        if !names.insert(cfg.name.clone())
            || !prefixes.insert(prefix)
            || !collections.insert(cfg.collection.clone())
        {
            bad("duplicate retired type name, prefix, or collection".to_owned());
            continue;
        }
        let removed = cfg
            .removed_pack
            .clone()
            .unwrap_or_else(|| "removed".to_owned());
        decls.push(RecordTypeDecl {
            name: leak(cfg.name.clone()),
            id_prefix: leak(cfg.id_prefix.clone()),
            prefix,
            collection: leak(cfg.collection.clone()),
            main_file: leak(cfg.main_file.clone()),
            entity: cfg.entity,
            person_like: cfg.person_like,
            no_ai,
            roster: cfg.roster.unwrap_or(cfg.entity),
            required_fields: &[],
            optional_fields: &[],
            owner: TypeOwner::Retired(leak(removed)),
            enabled: false,
            retired: true,
        });
    }
    (decls, problems)
}
