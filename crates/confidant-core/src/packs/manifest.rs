//! Pack manifest types, parser, and validation (`spec/pack-manifest.md`).
//!
//! Step 2 of #295: the types and loader for `packs/<name>/manifest.toml`.
//! Nothing loads a manifest yet and no pack reads its claims from one, so
//! this changes no behaviour. Steps 4-5 wire the packs up; step 6
//! generalizes the drift test against these types.
//!
//! The loader is strict: unknown keys are an error (a typo fails loudly
//! rather than silently doing nothing), and every semantic rule in the
//! spec's schema section is checked.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::check::FindingCode;
use crate::error::DomainError;
use crate::id::Prefix;

/// Schema version this loader implements (`manifest_version` in the file).
/// A file declaring any other version is rejected rather than guessed at.
pub const MANIFEST_VERSION: u32 = 1;

/// Schema version for external pack manifests (`manifest_version = 2`).
/// Parsed by [`parse_manifest_external`]; `parse_manifest` (v1, compiled)
/// still rejects 2.
pub const MANIFEST_VERSION_V2: u32 = 2;

/// Schema version that can declare `[[record_types]]` (spec 0.3).
pub const MANIFEST_VERSION_V3: u32 = 3;

/// Where a manifest's bytes came from (#550).
///
/// This is the trust boundary for the stable-code allowance: a manifest
/// loaded from **compiled-in bytes** (a built-in pack shipped inside the
/// binary) is trusted as core (#504 decision 3) and may name the stable
/// finding codes and claim core verbs; an external pack's vendored bytes
/// keep the `E_FRONTMATTER`-only carve-out (#490/PD13). The allowance is
/// keyed on this origin, **never on the pack name**, so a vault directory
/// `packs/personal@…` still fails `E_PACK_INVALID` (`#504` R8).
///
/// `#[serde(skip)]` on [`PackManifest::origin`] means a manifest file can
/// never claim its own origin; only the loader sets it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PackOrigin {
    /// Bytes read from the vault: an external pack's vendored directory.
    #[default]
    External,
    /// Bytes compiled into the binary: a built-in declarative pack.
    CompiledIn,
}

/// Rule kinds an external pack may declare (`[[rules]]`). Derived from
/// the evaluator's registered kinds (#441) so the manifest's list and
/// what actually runs cannot drift. Starts empty; each kind's own issue
/// appends its kind to `rule_kinds()` (PD1). Until a kind lands, any
/// `[[rules]]` entry is rejected as an unknown kind.
pub fn known_rule_kinds() -> Vec<&'static str> {
    crate::packs::declarative::registered_rule_kinds()
        .iter()
        .map(|k| k.name())
        .collect()
}

/// Core ledger verbs no external pack may claim (PD8 rule 1).
const CORE_VERBS_V2: &[&str] = &["alias", "merge", "stage", "balance", "touch"];

/// Core record types no external pack may claim (PD8 rule 2).
const CORE_RECORD_TYPES: &[&str] = &["person", "org", "deal", "interaction", "note", "edge"];

/// Pack names reserved for compiled-in packs (PD14). `personal` is the
/// only built-in; every other pack is external (#449).
const RESERVED_PACK_NAMES: &[&str] = &["personal"];

/// Whether `name` is reserved for a compiled-in pack (PD14). An external
/// pack cannot be installed under a reserved name (#440).
pub fn is_reserved_pack_name(name: &str) -> bool {
    RESERVED_PACK_NAMES.contains(&name)
}

/// Check a pack name against the v2 grammar `^[a-z][a-z0-9-]{1,31}$`.
/// PD14: an external pack name matches `^[a-z][a-z0-9-]{1,31}$` (2..32
/// chars, lowercase start). Used by the manifest loader, the lockfile
/// (#437), and `pack init` (#674).
pub fn is_valid_pack_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    // 2..32 chars total: first is [a-z], rest are [a-z0-9-].
    if bytes.len() < 2 || bytes.len() > 32 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Check a rule id against `^[a-z][a-z0-9_]*$`.
fn is_valid_rule_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Field grammars a manifest may name (spec §6). Canonical list lives in
/// [`grammars`](crate::packs::grammars); re-exported here so the loader's
/// validation reads the same frozen list the parser registry dispatches.
pub use crate::packs::grammars::KNOWN_GRAMMARS;

/// Severity values a `[checks]` severity default may take.
const KNOWN_SEVERITIES: &[&str] = &["error", "warning", "off"];

fn manifest_err(message: impl Into<String>) -> DomainError {
    DomainError::config(message).with_file("manifest.toml")
}

/// The `[pack]` table: identity and skill-text reference.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackInfo {
    /// Short pack name, e.g. `"personal"`. The full name is
    /// `"{name}@{version}"`, matching today's `Pack::name()`.
    pub name: String,
    /// Pack version, e.g. `"0.1"`.
    pub version: String,
    /// Skill text path relative to the pack directory, today `"SKILL.md"`.
    /// Referenced, never duplicated.
    pub skill: String,
    /// Exact spec versions this pack supports (v2 only). Absent in v1
    /// files; v2 requires it non-empty with each entry non-empty.
    #[serde(default)]
    pub requires_spec: Vec<String>,
}

/// A `[[record_types]]` table in a v3 manifest.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecordTypeDeclToml {
    pub name: String,
    pub id_prefix: String,
    pub collection: String,
    pub main_file: String,
    #[serde(default)]
    pub entity: bool,
    #[serde(default)]
    pub person_like: bool,
    #[serde(default = "default_no_ai")]
    pub no_ai: String,
    #[serde(default)]
    pub roster: Option<bool>,
    #[serde(default)]
    pub required_fields: Vec<String>,
    #[serde(default)]
    pub optional_fields: Vec<String>,
}

fn default_no_ai() -> String {
    "none".to_owned()
}

/// The `record_types` field: v2 holds names, v3 holds declaration tables.
/// Keeping one wrapper lets the rest of the loader read `names` uniformly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordTypes {
    pub names: Vec<String>,
    pub decls: Vec<RecordTypeDeclToml>,
}

impl std::ops::Deref for RecordTypes {
    type Target = [String];
    fn deref(&self) -> &Self::Target {
        &self.names
    }
}

impl<'a> IntoIterator for &'a RecordTypes {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;
    fn into_iter(self) -> Self::IntoIter {
        self.names.iter()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawRecordTypes {
    Names(Vec<String>),
    Decls(Vec<RecordTypeDeclToml>),
}

impl<'de> Deserialize<'de> for RecordTypes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match RawRecordTypes::deserialize(deserializer)? {
            RawRecordTypes::Names(names) => Ok(Self {
                names,
                decls: Vec::new(),
            }),
            RawRecordTypes::Decls(decls) => {
                let names = decls.iter().map(|decl| decl.name.clone()).collect();
                Ok(Self { names, decls })
            }
        }
    }
}

/// One `[[verbs]]` entry: a ledger verb the pack owns.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerbDecl {
    pub name: String,
    /// The verb-to-ID-type claim (today's `verb_id_type`); `None` for
    /// verbs with no ID-type claim. Resolved against core + the manifest's
    /// own declared types in `validate`.
    #[serde(default)]
    pub id_type: Option<String>,
}

/// One `[[fields]]` entry: a front-matter field the pack owns.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FieldDecl {
    pub name: String,
    /// Names one of [`KNOWN_GRAMMARS`]; Rust supplies the parser.
    pub grammar: String,
}

/// One `[[edge_kinds]]` entry: an edge kind the pack introduces (#813).
///
/// `from`/`to` name the endpoint record types for `a`/`b`. Both are
/// optional; when absent the kind keeps the historical person↔person
/// rule. When present they must appear together, be non-empty, and (for a
/// symmetric kind) name the same set on both sides.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EdgeKindDecl {
    pub name: String,
    pub symmetric: bool,
    #[serde(default)]
    pub from: Option<Vec<String>>,
    #[serde(default)]
    pub to: Option<Vec<String>>,
}

/// The optional `[context]` table (v2, spec §13.9): an opt-in naming a
/// core-built `context` view. The manifest *names* the view and supplies
/// its parameters through the pack's `ledger-balance` rule (PD1); core
/// implements the view. `[context]` is scope-limited to derived ledger
/// metadata — no record fields, no PII, no record content — so it does
/// not widen the §12 allowlist and needs no `private_context_fields`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContextDecl {
    /// One of the known core view kinds; today only `"ledger-sessions"`.
    pub view: String,
    /// Optional cap on the view's `recent_sessions`; core's default when
    /// absent. A present value must be positive.
    #[serde(default)]
    pub recent_limit: Option<u64>,
}

/// One `[[checks.severity]]` entry.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeverityCheck {
    /// Namespaced `<pack-name>.<rule>`, e.g. `"personal.cadence_overdue"`.
    pub key: String,
    /// One of `error`, `warning`, `off`.
    pub default: String,
}

/// One `[[checks.int]]` entry.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IntCheck {
    /// Namespaced `<pack-name>.<rule>`.
    pub key: String,
    pub default: i64,
}

/// One `[[rules]]` entry (v2 only): a named invocation of a rule kind.
/// The kind-specific parameters are kept raw in `params`; each kind's
/// own issue validates them. No `deny_unknown_fields` here: `params`
/// flattens every key the named fields don't claim, so an unknown key —
/// a typo of a generic key included (`severity_kye`, `cod`) — lands in
/// `params` instead of failing to deserialize. A *missing* generic key
/// still fails, the manifest parser only checks the fixed generic keys,
/// and each rule kind must validate its own `params` strictly.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct RuleDecl {
    /// Unique within the pack; matches `^[a-z][a-z0-9_]*$`.
    pub id: String,
    /// One of [`KNOWN_RULE_KINDS`].
    pub kind: String,
    /// The finding code this rule emits; must be in `finding_codes`.
    pub code: String,
    /// Optional declared `[[checks.severity]]` key (full namespaced key).
    /// Kinds with a fixed severity omit it.
    #[serde(default)]
    pub severity_key: Option<String>,
    /// Kind-specific parameters, kept raw.
    #[serde(flatten)]
    pub params: toml::Table,
}

/// The `[checks]` table: keys this pack owns, with defaults.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChecksDecl {
    #[serde(default)]
    pub severity: Vec<SeverityCheck>,
    #[serde(default)]
    pub int: Vec<IntCheck>,
}

/// A parsed and validated pack manifest. All names are owned strings;
/// steps 4-5 compare these against the compiled `&'static` slices.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackManifest {
    /// Schema version of the file; 1/2/3 are supported by the appropriate
    /// loader.
    pub manifest_version: u32,
    /// Record types this pack owns. v2 carries names only; v3 carries
    /// declaration tables (spec 0.3 §8).
    pub record_types: RecordTypes,
    /// Balance metrics this pack's fold computes.
    pub balance_metrics: Vec<String>,
    /// Finding codes this pack's fold/findings can emit. Must match the
    /// `[messages]` keys exactly.
    pub finding_codes: Vec<String>,
    pub pack: PackInfo,
    /// Verbs this pack owns. Empty when the pack owns none.
    #[serde(default)]
    pub verbs: Vec<VerbDecl>,
    /// Front-matter fields this pack owns. Empty when the pack owns none.
    #[serde(default)]
    pub fields: Vec<FieldDecl>,
    /// Edge kinds this pack introduces. Empty when the pack owns none.
    #[serde(default)]
    pub edge_kinds: Vec<EdgeKindDecl>,
    #[serde(default)]
    pub checks: ChecksDecl,
    /// Declarative rules (v2 only). Empty for v1 and for v2 packs that
    /// declare none yet.
    #[serde(default)]
    pub rules: Vec<RuleDecl>,
    /// Optional `[context]` table (v2, spec §13.9): names a core-built
    /// `context` view for this pack. Absent means the pack serves no view.
    #[serde(default)]
    pub context: Option<ContextDecl>,
    /// Finding message and fix templates, one table per code:
    /// `messages[code][variant] = template`. Every code in
    /// `finding_codes` needs a table with at least one variant, and every
    /// table key must be in `finding_codes`.
    pub messages: BTreeMap<String, BTreeMap<String, String>>,
    /// Where these bytes came from (#550). Set by the loader, never read
    /// from the file (`#[serde(skip)]`, so `origin = "…"` in TOML is an
    /// unknown-key error): a manifest cannot claim to be compiled in.
    #[serde(skip)]
    pub origin: PackOrigin,
}

/// Check one message template: `{placeholder}` substitution only — no
/// conditionals, no expressions, no filters. Braces must balance and
/// placeholders must be non-empty plain identifiers.
fn check_template(template: &str) -> Result<(), String> {
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c == '{' {
            let mut name = String::new();
            let mut closed = false;
            for c in chars.by_ref() {
                if c == '}' {
                    closed = true;
                    break;
                }
                if c == '{' {
                    return Err("nested '{' inside a placeholder".to_string());
                }
                name.push(c);
            }
            if !closed {
                return Err("unclosed '{'".to_string());
            }
            if name.is_empty() {
                return Err("empty placeholder '{}'".to_string());
            }
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!(
                    "placeholder '{{{name}}}' is not a plain identifier"
                ));
            }
        } else if c == '}' {
            return Err("unmatched '}'".to_string());
        }
    }
    Ok(())
}

fn check_unique(names: &[String], what: &str) -> Result<(), DomainError> {
    let mut seen = BTreeSet::new();
    for name in names {
        if name.trim().is_empty() {
            return Err(manifest_err(format!("{what} names must be non-empty"))
                .with_fix("Remove the empty entry or give it a name"));
        }
        if !seen.insert(name) {
            return Err(manifest_err(format!("duplicate {what} name '{name}'"))
                .with_fix("Each name may be declared only once"));
        }
    }
    Ok(())
}

/// Validate one `[[edge_kinds]]` endpoint declaration (#813).
///
/// Absent `from`/`to` means the historical person↔person rule. Present
/// declarations must be symmetric with the pair (both or neither),
/// non-empty, duplicate-free, and name only declared entity types. A
/// symmetric kind must allow the same set on both ends.
fn validate_edge_endpoints(
    kind: &EdgeKindDecl,
    manifest: &PackManifest,
) -> Result<(), DomainError> {
    let (from, to) = match (&kind.from, &kind.to) {
        (None, None) => return Ok(()),
        (Some(from), Some(to)) => (from, to),
        _ => {
            return Err(manifest_err(format!(
                "edge kind '{}' must declare from and to together",
                kind.name
            ))
            .with_fix("Add both endpoint arrays, or neither for person↔person"));
        }
    };

    for (label, endpoints) in [("from", from), ("to", to)] {
        if endpoints.is_empty() {
            return Err(manifest_err(format!(
                "edge kind '{}' has an empty {label} endpoint list",
                kind.name
            ))
            .with_fix("Name at least one endpoint type, e.g. from = [\"person\"]"));
        }
        let mut seen = BTreeSet::new();
        for name in endpoints {
            if !seen.insert(name.as_str()) {
                return Err(manifest_err(format!(
                    "edge kind '{}' repeats endpoint type '{name}' in {label}",
                    kind.name
                ))
                .with_fix("List each endpoint type once"));
            }
            if !manifest.is_entity_type(name) {
                return Err(manifest_err(format!(
                    "edge kind '{}' names unknown {label} endpoint type '{name}'",
                    kind.name
                ))
                .with_fix(
                    "Use person, org, or an entity type declared by this pack (cross-pack references are not supported in 0.3)",
                ));
            }
        }
    }

    if kind.symmetric {
        let from_set: BTreeSet<&str> = from.iter().map(String::as_str).collect();
        let to_set: BTreeSet<&str> = to.iter().map(String::as_str).collect();
        if from_set != to_set {
            return Err(manifest_err(format!(
                "symmetric edge kind '{}' must allow the same endpoint types on both ends",
                kind.name
            ))
            .with_fix("Make from and to list the same types, or set symmetric = false"));
        }
    }

    Ok(())
}

impl PackManifest {
    fn validate(&self) -> Result<(), DomainError> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(manifest_err(format!(
                "manifest_version {} is not supported (this loader implements {})",
                self.manifest_version, MANIFEST_VERSION
            ))
            .with_fix("Set manifest_version = 1 or upgrade the CLI"));
        }
        // `[context]` is a v2 surface (spec §13.9). A v1 file that names it
        // would otherwise parse (the field is known) and silently do
        // nothing; refuse it instead.
        if self.context.is_some() {
            return Err(
                manifest_err("[context] requires manifest_version = 2 (spec §13.9)")
                    .with_fix("Set manifest_version = 2, or remove the [context] table"),
            );
        }

        self.validate_common()
    }

    /// Validate the optional `[context]` table (spec §13.9): an unknown
    /// view, a missing or duplicated `ledger-balance` rule, or a
    /// non-positive `recent_limit` is refused here. The resolution lives
    /// with the view builder so the loader and the runtime read the same
    /// rules.
    fn validate_context(&self) -> Result<(), DomainError> {
        crate::context::ledger_sessions::resolve_params(self).map(drop)
    }

    /// Whether this manifest may name core (builtin) finding codes as its
    /// rule codes (#550). Only trusted manifests can: the v1 compiled path
    /// (the legacy files this loader still serves) and a pack loaded from
    /// compiled-in bytes. An external pack's v2 manifest keeps the
    /// `E_FRONTMATTER`-only carve-out (#490/PD13).
    pub fn may_emit_builtin_codes(&self) -> bool {
        self.manifest_version == MANIFEST_VERSION || self.origin == PackOrigin::CompiledIn
    }

    /// Whether this is a manifest loaded from compiled-in bytes (#550).
    fn is_compiled_in(&self) -> bool {
        self.origin == PackOrigin::CompiledIn
    }

    /// Validate a v2 pack manifest: the v2 schema from #431 plus the
    /// capability limits (PD8). Called by [`parse_manifest_with_origin`];
    /// the finding wrapper (`E_PACK_INVALID`) comes in #438, so errors here
    /// are `DomainError::config`.
    ///
    /// A compiled-in manifest (#550) is trusted as core: the reserved-name
    /// rejection and the PD8 capability limits are for external packs
    /// (bytes read from the vault), so they are skipped when
    /// [`PackManifest::origin`] is [`PackOrigin::CompiledIn`]. The v2
    /// schema itself (rule ids, kinds, codes, message tables) still
    /// applies in full.
    fn validate_external(&self) -> Result<(), DomainError> {
        if !matches!(
            self.manifest_version,
            MANIFEST_VERSION_V2 | MANIFEST_VERSION_V3
        ) {
            return Err(manifest_err(format!(
                "manifest_version {} is not an external pack manifest (this loader expects 2 or 3)",
                self.manifest_version
            ))
            .with_fix("Set manifest_version = 2 or 3 for external packs"));
        }

        // PD14: name grammar and reserved names. A compiled-in built-in
        // legitimately reuses a reserved name (`personal`); an external
        // pack may not (#504 R8).
        if !is_valid_pack_name(&self.pack.name) {
            return Err(manifest_err(format!(
                "[pack].name '{}' is not a valid external pack name (must match ^[a-z][a-z0-9-]{{1,31}}$)",
                self.pack.name
            ))
            .with_fix("Use a lowercase name with dashes, e.g. name = \"example-pack\""));
        }
        if !self.is_compiled_in() && RESERVED_PACK_NAMES.contains(&self.pack.name.as_str()) {
            return Err(manifest_err(format!(
                "[pack].name '{}' is reserved for a compiled pack",
                self.pack.name
            ))
            .with_fix("Choose a different pack name"));
        }

        // PD11: requires_spec is required in v2, non-empty, each entry non-empty.
        if self.pack.requires_spec.is_empty() {
            return Err(
                manifest_err("[pack].requires_spec must be non-empty for external packs").with_fix(
                    "List the spec versions this pack supports, e.g. requires_spec = [\"0.1\"]",
                ),
            );
        }
        for spec in &self.pack.requires_spec {
            if spec.trim().is_empty() {
                return Err(
                    manifest_err("[pack].requires_spec entries must be non-empty")
                        .with_fix("Remove the empty entry or give it a spec version"),
                );
            }
        }

        // PD13: every finding_codes entry must pass the shape and collision
        // rules. Leak once at load time (same Box::leak pattern as #434).
        // A builtin code is allowed as an *emission claim* (#441): the v2
        // spec example (spec/pack-manifest.md §2) lists `E_FRONTMATTER`
        // this way, with the pack supplying only a template shell. A
        // compiled-in manifest (#550) may emit any builtin — it is trusted
        // as core, so a rule may name the stable codes directly.
        for code in &self.finding_codes {
            let leaked: &'static str = Box::leak(code.clone().into_boxed_str());
            if self.may_emit_builtin_codes() && FindingCode::is_builtin_code(leaked) {
                continue;
            }
            FindingCode::from_pack_str_or_builtin(leaked).map_err(|e| {
                manifest_err(format!("finding code '{code}' is invalid: {e}")).with_fix(
                    "Codes must match ^[EW]_[A-Z0-9_]{2,40}$; a pack-own code must not collide with an existing code",
                )
            })?;
        }

        // PD8 rules 1-3: no core verbs, record types or edge kinds. These
        // capability limits apply to external packs only; a compiled-in
        // built-in is trusted as core (#504 decision 3) and legitimately
        // claims `touch`, for example.
        if !self.is_compiled_in() {
            for verb in &self.verbs {
                if CORE_VERBS_V2.contains(&verb.name.as_str()) {
                    return Err(manifest_err(format!(
                        "verb '{}' is a core verb and cannot be claimed by an external pack",
                        verb.name
                    ))
                    .with_fix("Remove the verb or choose a different name"));
                }
            }

            for record_type in &self.record_types {
                if CORE_RECORD_TYPES.contains(&record_type.as_str()) {
                    return Err(manifest_err(format!(
                        "record type '{record_type}' is a core record type and cannot be claimed by an external pack",
                    ))
                    .with_fix("Remove the record type or choose a different name"));
                }
            }

            for edge_kind in &self.edge_kinds {
                if crate::packs::is_core_edge_kind(&edge_kind.name) {
                    return Err(manifest_err(format!(
                        "edge kind '{}' is a core edge kind and cannot be claimed by an external pack",
                        edge_kind.name
                    ))
                    .with_fix("Remove the edge kind or choose a different name"));
                }
            }
        }

        // PD8 rule 4 is covered by the from_pack_str collision check above.

        // Skill path must be a plain file name (no `/`, no `..`).
        if self.pack.skill.contains('/') || self.pack.skill.contains("..") {
            return Err(manifest_err(format!(
                "[pack].skill '{}' must be a plain file name (no `/`, no `..`)",
                self.pack.skill
            ))
            .with_fix("Use a plain file name like skill = \"SKILL.md\""));
        }

        // Rules validation: IDs first (validity + uniqueness), then the
        // per-rule checks. The ID pass runs separately so duplicate IDs are
        // caught even though KNOWN_RULE_KINDS is empty (kind check would
        // fire first otherwise).
        let mut seen_rule_ids = BTreeSet::new();
        for rule in &self.rules {
            if !is_valid_rule_id(&rule.id) {
                return Err(manifest_err(format!(
                    "rule id '{}' is not valid (must match ^[a-z][a-z0-9_]*$)",
                    rule.id
                ))
                .with_fix("Use a lowercase id with underscores, e.g. id = \"my_rule\""));
            }
            if !seen_rule_ids.insert(&rule.id) {
                return Err(manifest_err(format!("duplicate rule id '{}'", rule.id))
                    .with_fix("Each rule id may be declared only once"));
            }
        }
        let severity_keys: BTreeSet<&str> = self
            .checks
            .severity
            .iter()
            .map(|s| s.key.as_str())
            .collect();
        for rule in &self.rules {
            // A rule's code must be a pack-own code (#494 review): a
            // builtin as a rule's code would let an external pack emit
            // core security findings with a re-worded meaning. A
            // compiled-in built-in is trusted as core and may name the
            // stable codes (#550).
            if !self.may_emit_builtin_codes() && FindingCode::is_builtin_code(&rule.code) {
                return Err(manifest_err(format!(
                    "rule '{}' emits builtin code '{}'; a rule's code must be a pack-own code",
                    rule.id, rule.code
                ))
                .with_fix(
                    "Declare a pack-own code (e.g. W_<PACK>_<RULE>) in finding_codes and use it",
                ));
            }
            if !known_rule_kinds().contains(&rule.kind.as_str()) {
                return Err(manifest_err(format!(
                    "rule '{}' has unknown rule kind '{}'",
                    rule.id, rule.kind
                ))
                .with_fix("The kind list is empty until a kind issue adds its name"));
            }
            if !self.finding_codes.contains(&rule.code) {
                return Err(manifest_err(format!(
                    "rule '{}' emits code '{}' which is not in finding_codes",
                    rule.id, rule.code
                ))
                .with_fix("Add the code to finding_codes or use a declared code"));
            }
            if let Some(key) = &rule.severity_key {
                if !severity_keys.contains(key.as_str()) {
                    return Err(manifest_err(format!(
                        "rule '{}' names undeclared severity_key '{}'",
                        rule.id, key
                    ))
                    .with_fix("Declare the key in [[checks.severity]] or omit severity_key"));
                }
            }
        }

        // Fields: validating declared fields emits `E_FRONTMATTER`
        // through the pack's own message template (#441), so a pack that
        // declares fields must declare that code and template.
        if !self.fields.is_empty() && !self.finding_codes.iter().any(|c| c == "E_FRONTMATTER") {
            return Err(manifest_err(
                "a pack that declares fields must list E_FRONTMATTER in finding_codes",
            )
            .with_fix(
                "Add \"E_FRONTMATTER\" to finding_codes and a [messages.\"E_FRONTMATTER\"] table with a `default` variant",
            ));
        }

        // §13.9: the optional `[context]` table is validated here (the
        // view name, its balance-rule parameters and the recent cap).
        self.validate_context()?;

        self.validate_common()
    }

    /// #629: a retired code (`spec/findings.md`) is never a valid code
    /// value. Refuse it in a rule's generic `code` and in every `*_code`
    /// parameter, whatever the manifest's origin: the cutover retired those
    /// names, so no pack may revive one for a new meaning. The per-kind
    /// validators require the parameters; this guard checks their values.
    fn validate_rule_codes_not_retired(&self) -> Result<(), DomainError> {
        for rule in &self.rules {
            if FindingCode::is_retired_code(&rule.code) {
                return Err(manifest_err(format!(
                    "rule '{}': code '{}' is retired; nothing emits it in 0.1 and it must never be reused",
                    rule.id, rule.code
                ))
                .with_fix("Set code to a code the pack declares in finding_codes"));
            }
            for (name, value) in &rule.params {
                if !name.ends_with("_code") {
                    continue;
                }
                let Some(code) = value.as_str() else {
                    continue; // the kind's validator reports the bad type
                };
                if FindingCode::is_retired_code(code) {
                    return Err(manifest_err(format!(
                        "rule '{}': {name} '{code}' is retired; nothing emits it in 0.1 and it must never be reused",
                        rule.id
                    ))
                    .with_fix(format!(
                        "Set {name} to a code the pack declares in finding_codes"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Resolve a type name to its prefix: core types first, then this
    /// manifest's own declared types. Cross-pack type references are refused
    /// in 0.3; core is the shared vocabulary.
    pub(crate) fn type_prefix(&self, name: &str) -> Option<Prefix> {
        if let Some(prefix) = Prefix::from_type(name) {
            return Some(prefix);
        }
        if name == "package" {
            return Some(Prefix::Package);
        }
        self.record_types
            .decls
            .iter()
            .find(|decl| decl.name == name)
            .and_then(|decl| Prefix::parse(&decl.id_prefix))
    }

    /// Whether a type name is an entity for edge endpoints: core person/org
    /// or a declared type with `entity = true`.
    pub(crate) fn is_entity_type(&self, name: &str) -> bool {
        matches!(name, "person" | "org")
            || self
                .record_types
                .decls
                .iter()
                .any(|decl| decl.name == name && decl.entity)
    }

    /// Validate `[[record_types]]` (v3) and the v2 rule that a manifest may
    /// not claim a type without a declaration.
    fn validate_record_types(&self) -> Result<(), DomainError> {
        if self.manifest_version < MANIFEST_VERSION_V3 {
            if !self.record_types.names.is_empty() {
                return Err(manifest_err(
                    "record type declarations require manifest_version = 3",
                )
                .with_fix("Set manifest_version = 3 and use [[record_types]] tables, or remove the claim"));
            }
            return Ok(());
        }
        if self.record_types.decls.is_empty() {
            if !self.record_types.names.is_empty() {
                return Err(manifest_err(
                    "manifest_version = 3 must declare record types as [[record_types]] tables",
                )
                .with_fix("Replace the string array with one [[record_types]] table per type"));
            }
            return Ok(());
        }
        if !self.pack.requires_spec.iter().any(|spec| spec == "0.3") {
            return Err(manifest_err(
                "a manifest that declares record types must list \"0.3\" in requires_spec",
            )
            .with_fix("Add \"0.3\" to requires_spec"));
        }

        let field_names: BTreeSet<&str> = self.fields.iter().map(|f| f.name.as_str()).collect();
        let mut names = BTreeSet::new();
        let mut prefixes = BTreeSet::new();
        let mut collections = BTreeSet::new();
        for decl in &self.record_types.decls {
            if !crate::record_type::valid_type_name(&decl.name) {
                return Err(manifest_err(format!(
                    "record type '{}' is not valid (must match ^[a-z][a-z0-9_]{{0,31}}$)",
                    decl.name
                ))
                .with_fix("Use a lowercase type name with underscores"));
            }
            if crate::record_type::is_core_type_name(&decl.name) {
                return Err(manifest_err(format!(
                    "record type '{}' is a core type and cannot be claimed",
                    decl.name
                ))
                .with_fix("Remove the record type or choose a different name"));
            }
            if !crate::record_type::valid_pack_prefix(&decl.id_prefix) {
                return Err(manifest_err(format!(
                    "record type '{}' id_prefix '{}' must be two lowercase letters and must not end in p/o/d/i/n/e",
                    decl.name, decl.id_prefix
                ))
                .with_fix("Use a two-letter prefix such as pl or th; the second letter cannot shadow a core prefix"));
            }
            if matches!(
                decl.id_prefix.as_str(),
                "p" | "o" | "d" | "i" | "n" | "e" | "pkg"
            ) {
                return Err(manifest_err(format!(
                    "record type '{}' id_prefix '{}' is reserved",
                    decl.name, decl.id_prefix
                ))
                .with_fix("Choose a two-letter prefix"));
            }
            if !crate::record_type::valid_collection(&decl.collection) {
                return Err(manifest_err(format!(
                    "record type '{}' collection '{}' is not valid or is reserved",
                    decl.name, decl.collection
                ))
                .with_fix(
                    "Use a lowercase collection directory that is not a core or vault name",
                ));
            }
            if !crate::record_type::valid_main_file(&decl.main_file) {
                return Err(manifest_err(format!(
                    "record type '{}' main_file '{}' must be a plain .md file name",
                    decl.name, decl.main_file
                ))
                .with_fix("Use a name like place.md"));
            }
            if !names.insert(decl.name.as_str())
                || !prefixes.insert(decl.id_prefix.as_str())
                || !collections.insert(decl.collection.as_str())
            {
                return Err(manifest_err(format!(
                    "record type '{}' duplicates a name, prefix, or collection in this manifest",
                    decl.name
                ))
                .with_fix("Each declared type needs a unique name, prefix, and collection"));
            }
            let no_ai = crate::record_type::NoAiPolicy::parse(&decl.no_ai).ok_or_else(|| {
                manifest_err(format!(
                    "record type '{}' no_ai must be none, full, or notes",
                    decl.name
                ))
            })?;
            if decl.person_like && !decl.entity {
                return Err(manifest_err(format!(
                    "record type '{}' sets person_like without entity",
                    decl.name
                ))
                .with_fix("Set entity = true, or remove person_like"));
            }
            if no_ai == crate::record_type::NoAiPolicy::Notes && !decl.person_like {
                return Err(manifest_err(format!(
                    "record type '{}' sets no_ai = \"notes\" without person_like",
                    decl.name
                ))
                .with_fix("Set person_like = true, or use no_ai = \"full\""));
            }
            let mut required = BTreeSet::new();
            for key in &decl.required_fields {
                if *key != "name" && !field_names.contains(key.as_str()) {
                    return Err(manifest_err(format!(
                        "record type '{}' requires undeclared field '{}'",
                        decl.name, key
                    ))
                    .with_fix("Declare the field in [[fields]] or use name"));
                }
                if !required.insert(key.as_str()) {
                    return Err(manifest_err(format!(
                        "record type '{}' repeats required field '{}'",
                        decl.name, key
                    )));
                }
            }
            let mut optional = BTreeSet::new();
            for key in &decl.optional_fields {
                if !optional.insert(key.as_str()) {
                    return Err(manifest_err(format!(
                        "record type '{}' repeats optional field '{}'",
                        decl.name, key
                    )));
                }
                if *key != "name" && !field_names.contains(key.as_str()) {
                    return Err(manifest_err(format!(
                        "record type '{}' lists undeclared optional field '{}'",
                        decl.name, key
                    ))
                    .with_fix("Declare the field in [[fields]] or use name"));
                }
                if required.contains(key.as_str()) {
                    return Err(manifest_err(format!(
                        "record type '{}' lists field '{}' as both required and optional",
                        decl.name, key
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_common(&self) -> Result<(), DomainError> {
        if self.pack.name.trim().is_empty() {
            return Err(manifest_err("[pack].name must be non-empty")
                .with_fix("Set the pack's short name, e.g. name = \"personal\""));
        }
        if self.pack.name.contains('@') {
            return Err(manifest_err(format!(
                "[pack].name '{}' must not contain '@'; the version goes in [pack].version",
                self.pack.name
            )));
        }
        if self.pack.version.trim().is_empty() {
            return Err(manifest_err("[pack].version must be non-empty")
                .with_fix("Set the pack version, e.g. version = \"0.1\""));
        }
        if self.pack.version.contains('@') {
            return Err(manifest_err(
                "[pack].version must not contain '@'; the full name is \"{name}@{version}\"",
            ));
        }
        if self.pack.skill.trim().is_empty() {
            return Err(manifest_err("[pack].skill must be non-empty")
                .with_fix("Reference the skill text, e.g. skill = \"SKILL.md\""));
        }

        check_unique(&self.record_types, "record type")?;
        check_unique(&self.balance_metrics, "balance metric")?;
        check_unique(&self.finding_codes, "finding code")?;

        self.validate_rule_codes_not_retired()?;

        let verb_names: Vec<String> = self.verbs.iter().map(|v| v.name.clone()).collect();
        check_unique(&verb_names, "verb")?;
        let field_names: Vec<String> = self.fields.iter().map(|f| f.name.clone()).collect();
        check_unique(&field_names, "field")?;
        for field in &self.fields {
            if !KNOWN_GRAMMARS.contains(&field.grammar.as_str()) {
                return Err(manifest_err(format!(
                    "field '{}' names unknown grammar '{}'; expected one of: {}",
                    field.name,
                    field.grammar,
                    KNOWN_GRAMMARS.join(", ")
                ))
                .with_fix("Adding a grammar is a spec change plus a Rust parser — never a manifest-only change"));
            }
        }
        let edge_names: Vec<String> = self.edge_kinds.iter().map(|e| e.name.clone()).collect();
        check_unique(&edge_names, "edge kind")?;
        self.validate_record_types()?;
        for edge_kind in &self.edge_kinds {
            validate_edge_endpoints(edge_kind, self)?;
        }
        for verb in &self.verbs {
            if let Some(id_type) = &verb.id_type {
                if self.type_prefix(id_type).is_none() {
                    let mut accepted: Vec<String> = crate::record_type::CORE_TYPES
                        .iter()
                        .map(|d| d.name.to_owned())
                        .collect();
                    accepted.push("package".to_owned());
                    accepted.extend(self.record_types.decls.iter().map(|decl| decl.name.clone()));
                    return Err(manifest_err(format!(
                        "verb '{}' names unknown id_type '{}'; expected one of: {}",
                        verb.name,
                        id_type,
                        accepted.join(", ")
                    ))
                    .with_fix("Use a core type or a type declared by this pack"));
                }
            }
        }

        // [checks] keys are namespaced <pack-name>.<rule>; a pack may only
        // declare keys under its own name. `as_of` stays core-owned.
        let prefix = format!("{}.", self.pack.name);
        for entry in self
            .checks
            .severity
            .iter()
            .map(|s| &s.key)
            .chain(self.checks.int.iter().map(|i| &i.key))
        {
            if !entry.starts_with(&prefix) || entry.len() == prefix.len() {
                return Err(manifest_err(format!(
                    "checks key '{entry}' is not namespaced to this pack; keys must look like '{prefix}<rule>'"
                ))
                .with_fix("The `as_of` key stays core-owned and cannot be declared here"));
            }
        }
        for check in &self.checks.severity {
            if !KNOWN_SEVERITIES.contains(&check.default.as_str()) {
                return Err(manifest_err(format!(
                    "checks key '{}' has bad severity default '{}'; expected one of: {}",
                    check.key,
                    check.default,
                    KNOWN_SEVERITIES.join(", ")
                )));
            }
        }
        // Int defaults are whole values (windows, counts); a negative one
        // is a manifest mistake, refused here rather than silently folded
        // to 0 at evaluation (#528).
        for check in &self.checks.int {
            if check.default < 0 {
                return Err(manifest_err(format!(
                    "checks key '{}' has negative int default {}; expected 0 or more",
                    check.key, check.default
                ))
                .with_fix("Int check defaults are whole values (days, counts); use 0 or more"));
            }
        }

        // Every finding code needs a [messages.<CODE>] table with at least
        // one variant, and every [messages] key must be a finding code —
        // no orphan text, no undocumented codes. The #629 retired-code
        // guard runs above this loop, so a retired name reports as retired
        // rather than as a missing/undeclared code.
        for code in &self.finding_codes {
            match self.messages.get(code) {
                None => {
                    return Err(manifest_err(format!(
                        "finding code '{code}' has no [messages.\"{code}\"] table"
                    ))
                    .with_fix("Add one table per code, with at least one variant"))
                }
                Some(variants) if variants.is_empty() => {
                    return Err(manifest_err(format!(
                        "[messages.\"{code}\"] must declare at least one variant"
                    )))
                }
                _ => {}
            }
        }
        for code in self.messages.keys() {
            if !self.finding_codes.contains(code) {
                return Err(
                    manifest_err(format!("[messages.\"{code}\"] is not in finding_codes"))
                        .with_fix("Add the code to finding_codes or remove the table"),
                );
            }
        }
        for (code, variants) in &self.messages {
            for (variant, template) in variants {
                if variant.trim().is_empty() {
                    return Err(manifest_err(format!(
                        "[messages.\"{code}\"] has an empty variant name"
                    )));
                }
                check_template(template).map_err(|detail| {
                    manifest_err(format!(
                        "[messages.\"{code}\"].{variant} is not a plain template: {detail}"
                    ))
                    .with_fix("Templates allow {{placeholder}} substitution only — no conditionals or expressions")
                })?;
            }
        }

        Ok(())
    }
}

/// Parse and validate a pack manifest (`packs/<name>/manifest.toml`).
/// Returns the manifest on success; nothing is loaded from disk and no
/// pack reads its claims from it yet (steps 4-5).
pub fn parse_manifest(text: &str) -> Result<PackManifest, DomainError> {
    let manifest: PackManifest = toml::from_str(text).map_err(|err| {
        manifest_err(format!("manifest.toml is not valid TOML: {err}")).with_fix(
            "Top-level keys (record_types, balance_metrics, finding_codes) must come before the first [table] header",
        )
    })?;
    manifest.validate()?;
    Ok(manifest)
}

/// Parse and validate a v2 pack manifest from the given origin (#550).
/// Requires `manifest_version = 2` and applies the v2 schema; the PD8
/// capability limits and the reserved-name rejection apply only when
/// `origin` is [`PackOrigin::External`]. Returns the manifest on success;
/// nothing is read from disk.
pub fn parse_manifest_with_origin(
    text: &str,
    origin: PackOrigin,
) -> Result<PackManifest, DomainError> {
    let mut manifest: PackManifest = toml::from_str(text).map_err(|err| {
        manifest_err(format!("manifest.toml is not valid TOML: {err}")).with_fix(
            "Top-level keys (record_types, balance_metrics, finding_codes) must come before the first [table] header",
        )
    })?;
    manifest.origin = origin;
    manifest.validate_external()?;
    Ok(manifest)
}

/// Parse and validate an external (v2) pack manifest read from the vault.
/// Requires `manifest_version = 2` and applies the v2 schema plus
/// capability limits (PD8). Returns the manifest on success; nothing is
/// read from disk.
pub fn parse_manifest_external(text: &str) -> Result<PackManifest, DomainError> {
    parse_manifest_with_origin(text, PackOrigin::External)
}

/// Parse and validate a v2 pack manifest compiled into the binary (#550).
/// Same schema as [`parse_manifest_external`], but the bytes are trusted
/// as core: the reserved-name rejection and the PD8 capability limits are
/// skipped, and the resulting rules may name the stable finding codes. The
/// manifest's [`PackManifest::origin`] is [`PackOrigin::CompiledIn`].
pub fn parse_manifest_compiled_in(text: &str) -> Result<PackManifest, DomainError> {
    parse_manifest_with_origin(text, PackOrigin::CompiledIn)
}

/// Render a message template: `{placeholder}` substitution only — no
/// conditionals, no expressions, no filters (the loader already rejected
/// anything else). A placeholder the caller does not supply is a render
/// error: the manifest is compile-time data and the code must supply
/// every placeholder the template names (spec §7). Extra args are
/// ignored.
fn render_template(template: &str, args: &[(&str, &dyn std::fmt::Display)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '{' {
            out.push(c);
            continue;
        }
        let mut name = String::new();
        for c in chars.by_ref() {
            if c == '}' {
                break;
            }
            name.push(c);
        }
        let value = args.iter().find(|(k, _)| *k == name).unwrap_or_else(|| {
            panic!("manifest template names placeholder '{{{name}}}' with no value supplied")
        });
        out.push_str(&value.1.to_string());
    }
    out
}

impl PackManifest {
    /// Render a finding message (`messages[code][variant]`), substituting
    /// `{placeholder}` with the supplied values. Panics when the code or
    /// variant is missing, or when a placeholder has no value: the
    /// manifest is compile-time data, so a bad lookup is a programming
    /// error (spec §7: text in the manifest, selection in Rust).
    pub fn render_message(
        &self,
        code: &str,
        variant: &str,
        args: &[(&str, &dyn std::fmt::Display)],
    ) -> String {
        let template = self
            .messages
            .get(code)
            .and_then(|variants| variants.get(variant))
            .unwrap_or_else(|| panic!("manifest has no [messages.\"{code}\"].{variant}"));
        render_template(template, args)
    }

    /// Render the `<variant>_fix` template, or `None` when the manifest
    /// declares no fix for this variant.
    pub fn render_fix(
        &self,
        code: &str,
        variant: &str,
        args: &[(&str, &dyn std::fmt::Display)],
    ) -> Option<String> {
        let fix_variant = format!("{variant}_fix");
        let template = self.messages.get(code)?.get(&fix_variant)?;
        Some(render_template(template, args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid manifest exercising every section.
    fn valid_toml() -> String {
        r#"
manifest_version = 1
record_types = []
balance_metrics = ["sessions_remaining"]
finding_codes = ["E_WRONG", "W_LATE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"

[[verbs]]
name = "session"
id_type = "person"

[[verbs]]
name = "note"

[[fields]]
name = "birthday"
grammar = "recurring-date"

[[edge_kinds]]
name = "mentor"
symmetric = false

[checks]
[[checks.severity]]
key = "example-pack.wrong_thing"
default = "warning"

[[checks.int]]
key = "example-pack.lookback_days"
default = 7

[messages."E_WRONG"]
default = "wrong {id}"
default_fix = "fix {id}"

[messages."W_LATE"]
default = "late"
"#
        .to_string()
    }

    #[test]
    fn parses_valid_manifest() {
        let m = parse_manifest(&valid_toml()).unwrap();
        assert_eq!(m.manifest_version, 1);
        assert_eq!(m.pack.name, "example-pack");
        assert_eq!(m.pack.version, "0.1");
        assert_eq!(m.balance_metrics, vec!["sessions_remaining".to_string()]);
        assert_eq!(m.verbs.len(), 2);
        assert_eq!(m.verbs[0].id_type.as_deref(), Some("person"));
        assert_eq!(m.verbs[1].id_type, None);
        assert_eq!(m.fields[0].grammar, "recurring-date");
        assert!(!m.edge_kinds[0].symmetric);
        assert_eq!(m.checks.severity[0].default, "warning");
        assert_eq!(m.checks.int[0].default, 7);
        assert_eq!(m.messages["E_WRONG"]["default"], "wrong {id}".to_string());
    }

    #[test]
    fn minimal_manifest_with_defaults() {
        let text = r#"
manifest_version = 1
record_types = []
balance_metrics = []
finding_codes = ["E_X"]

[pack]
name = "tiny"
version = "0.1"
skill = "SKILL.md"

[messages."E_X"]
default = "x"
"#;
        let m = parse_manifest(text).unwrap();
        assert!(m.verbs.is_empty());
        assert!(m.fields.is_empty());
        assert!(m.edge_kinds.is_empty());
        assert!(m.checks.severity.is_empty());
        assert!(m.checks.int.is_empty());
    }

    #[test]
    fn rejects_invalid_toml() {
        let err = parse_manifest("manifest_version = ").unwrap_err();
        assert!(err.to_string().contains("not valid TOML"));
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let text = valid_toml() + "bogus_key = 1\n";
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("bogus_key"), "{err:?}");
    }

    #[test]
    fn rejects_unknown_key_in_verb() {
        let text = valid_toml().replace("name = \"session\"", "name = \"session\"\nbogus = true");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err:?}");
    }

    #[test]
    fn rejects_wrong_manifest_version() {
        let text = valid_toml().replace("manifest_version = 1", "manifest_version = 2");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err:?}");
    }

    #[test]
    fn rejects_duplicate_verb_names() {
        let text = valid_toml().replace(
            "[[verbs]]\nname = \"note\"",
            "[[verbs]]\nname = \"session\"",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("duplicate verb"), "{err:?}");
    }

    #[test]
    fn rejects_duplicate_field_names() {
        let text = valid_toml() + "[[fields]]\nname = \"birthday\"\ngrammar = \"cadence\"\n";
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("duplicate field"), "{err:?}");
    }

    #[test]
    fn rejects_duplicate_edge_kind_names() {
        let text = valid_toml() + "[[edge_kinds]]\nname = \"mentor\"\nsymmetric = true\n";
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("duplicate edge kind"), "{err:?}");
    }

    /// #813: a kind may declare its endpoint types; absent means the
    /// historical person↔person default.
    #[test]
    fn edge_endpoints_parse_and_default() {
        let text = valid_v2_toml()
            + "\n[[edge_kinds]]\nname = \"backs\"\nsymmetric = false\n\
               from = [\"org\"]\nto = [\"person\"]\n";
        let m = parse_manifest_external(&text).unwrap();
        assert_eq!(m.edge_kinds[0].name, "backs");
        assert_eq!(
            m.edge_kinds[0].from.as_deref(),
            Some(&["org".to_string()][..])
        );
        assert_eq!(
            m.edge_kinds[0].to.as_deref(),
            Some(&["person".to_string()][..])
        );

        // Existing v1 manifests keep the no-declaration default.
        let m = parse_manifest(&valid_toml()).unwrap();
        assert!(m.edge_kinds[0].from.is_none());
        assert!(m.edge_kinds[0].to.is_none());
    }

    /// #813: phase 1 declares person and org; anything else is a manifest
    /// error, not a silently ignored value.
    #[test]
    fn edge_endpoints_reject_unknown_type() {
        for bad in ["place", "deal", "note", "package"] {
            let text = valid_v2_toml()
                + &format!(
                    "\n[[edge_kinds]]\nname = \"backs\"\nsymmetric = false\n\
                     from = [\"person\"]\nto = [\"{bad}\"]\n"
                );
            let err = parse_manifest_external(&text).unwrap_err();
            assert!(
                err.to_string().contains("unknown to endpoint type"),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn edge_endpoints_require_both_sides() {
        for text in [
            valid_v2_toml()
                + "\n[[edge_kinds]]\nname = \"backs\"\nsymmetric = false\nfrom = [\"org\"]\n",
            valid_v2_toml()
                + "\n[[edge_kinds]]\nname = \"backs\"\nsymmetric = false\nto = [\"person\"]\n",
        ] {
            let err = parse_manifest_external(&text).unwrap_err();
            assert!(err.to_string().contains("from and to together"), "{err:?}");
        }
    }

    #[test]
    fn edge_endpoints_reject_empty_and_duplicate() {
        let empty = valid_v2_toml()
            + "\n[[edge_kinds]]\nname = \"backs\"\nsymmetric = false\n\
               from = []\nto = [\"person\"]\n";
        let err = parse_manifest_external(&empty).unwrap_err();
        assert!(err.to_string().contains("empty from endpoint"), "{err:?}");

        let duplicate = valid_v2_toml()
            + "\n[[edge_kinds]]\nname = \"backs\"\nsymmetric = false\n\
               from = [\"person\", \"person\"]\nto = [\"person\"]\n";
        let err = parse_manifest_external(&duplicate).unwrap_err();
        assert!(err.to_string().contains("repeats endpoint type"), "{err:?}");
    }

    #[test]
    fn symmetric_edge_kind_requires_equal_endpoint_sets() {
        let text = valid_v2_toml()
            + "\n[[edge_kinds]]\nname = \"peers\"\nsymmetric = true\n\
               from = [\"person\"]\nto = [\"person\", \"org\"]\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(
            err.to_string().contains("same endpoint types on both ends"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_finding_codes() {
        let text = valid_toml().replace(
            "finding_codes = [\"E_WRONG\", \"W_LATE\"]",
            "finding_codes = [\"E_WRONG\", \"E_WRONG\"]",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(
            err.to_string().contains("duplicate finding code"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_balance_metrics() {
        let text = valid_toml().replace(
            "balance_metrics = [\"sessions_remaining\"]",
            "balance_metrics = [\"sessions_remaining\", \"sessions_remaining\"]",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(
            err.to_string().contains("duplicate balance metric"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_unknown_grammar() {
        let text =
            valid_toml().replace("grammar = \"recurring-date\"", "grammar = \"fancy-regex\"");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("unknown grammar"), "{err:?}");
    }

    #[test]
    fn rejects_unknown_id_type() {
        let text = valid_toml().replace("id_type = \"person\"", "id_type = \"human\"");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("unknown id_type"), "{err:?}");
    }

    #[test]
    fn rejects_bad_template_unclosed() {
        let text = valid_toml().replace("wrong {id}", "wrong {id");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("unclosed"), "{err:?}");
    }

    #[test]
    fn rejects_bad_template_empty_placeholder() {
        let text = valid_toml().replace("wrong {id}", "wrong {}");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("empty placeholder"), "{err:?}");
    }

    #[test]
    fn rejects_bad_template_unmatched_close() {
        let text = valid_toml().replace("wrong {id}", "wrong {id}}");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("unmatched"), "{err:?}");
    }

    #[test]
    fn rejects_bad_template_nested() {
        let text = valid_toml().replace("wrong {id}", "wrong {{id}}");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("nested"), "{err:?}");
    }

    #[test]
    fn rejects_code_without_messages_table() {
        let text = valid_toml().replace(
            "finding_codes = [\"E_WRONG\", \"W_LATE\"]",
            "finding_codes = [\"E_WRONG\", \"W_LATE\", \"E_MISSING\"]",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("no [messages"), "{err:?}");
    }

    #[test]
    fn rejects_orphan_messages_table() {
        let text = valid_toml() + "[messages.\"E_ORPHAN\"]\ndefault = \"orphan\"\n";
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("not in finding_codes"), "{err:?}");
    }

    #[test]
    fn rejects_empty_messages_table() {
        // A table header with no variants under it.
        let text = valid_toml().replace(
            "[messages.\"W_LATE\"]\ndefault = \"late\"",
            "[messages.\"W_LATE\"]",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("at least one variant"), "{err:?}");
    }

    #[test]
    fn rejects_checks_key_wrong_namespace() {
        let text = valid_toml().replace(
            "key = \"example-pack.wrong_thing\"",
            "key = \"personal.wrong_thing\"",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("not namespaced"), "{err:?}");
    }

    #[test]
    fn rejects_checks_key_core_owned() {
        let text = valid_toml().replace("key = \"example-pack.wrong_thing\"", "key = \"as_of\"");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("not namespaced"), "{err:?}");
    }

    #[test]
    fn rejects_bad_severity_default() {
        let text = valid_toml().replace("default = \"warning\"", "default = \"loud\"");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("bad severity"), "{err:?}");
    }

    /// #528: a negative int default is refused at load. Without this the
    /// rule's window would silently fold to 0 at evaluation.
    #[test]
    fn rejects_negative_int_default() {
        let text = valid_toml().replace("default = 7", "default = -1");
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("negative int default"), "{err:?}");
        assert!(err.to_string().contains("expected 0 or more"), "{err:?}");
    }

    /// #528: the same refusal applies to external (v2) manifests, which
    /// run the shared `validate_common` checks. Rules — and so the
    /// `window_key` resolution this protects — only exist on v2.
    #[test]
    fn rejects_negative_int_default_external() {
        let text = r#"
manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_WRONG"]

[pack]
name = "example-test"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[checks.int]]
key = "example-test.window_days"
default = -1

[messages."E_WRONG"]
default = "wrong {id}"
"#;
        let err = parse_manifest_external(text).unwrap_err();
        assert!(err.to_string().contains("negative int default"), "{err:?}");
    }

    #[test]
    fn rejects_empty_pack_name() {
        let text = valid_toml().replace("name = \"example-pack\"\nversion", "name = \"\"\nversion");
        // Note: the first `name = "example-pack"` is under [pack]; verbs use
        // `name = "session"` so this replace is scoped to the pack table.
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("[pack].name"), "{err:?}");
    }

    #[test]
    fn rejects_pack_name_with_at() {
        let text = valid_toml().replace(
            "[pack]\nname = \"example-pack\"",
            "[pack]\nname = \"example-pack@0.1\"",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("must not contain '@'"), "{err:?}");
    }

    #[test]
    fn rejects_empty_finding_code() {
        let text = valid_toml().replace(
            "finding_codes = [\"E_WRONG\", \"W_LATE\"]",
            "finding_codes = [\"E_WRONG\", \"\"]",
        );
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("non-empty"), "{err:?}");
    }

    /// #629: a retired code (`spec/findings.md`) is never a valid rule
    /// parameter value, even though the name is still reserved as a
    /// builtin. The error names the parameter.
    #[test]
    fn rejects_retired_code_parameter() {
        let text = format!(
            "{}\n[[rules]]\nid = \"note\"\nkind = \"note-ref\"\ncode = \"E_EXAMPLE_FIELD\"\nverb = \"touch\"\npair = \"note\"\ninvalid_code = \"E_SESSION_WITHOUT_NOTES\"\nwrong_type_code = \"E_EXAMPLE_FIELD\"\n",
            valid_v2_toml()
        );
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid_code 'E_SESSION_WITHOUT_NOTES' is retired"),
            "{err:?}"
        );
    }

    /// #629: the generic `code` is refused too, and on a compiled-in pack
    /// (where PD13's builtin guard does not run) this is the only check
    /// that catches a retired name.
    #[test]
    fn rejects_retired_generic_code_for_compiled_in_pack() {
        let text = valid_v2_toml()
            .replace(
                "finding_codes = [\"E_FRONTMATTER\", \"E_EXAMPLE_FIELD\"]",
                "finding_codes = [\"E_FRONTMATTER\", \"E_EXAMPLE_FIELD\", \"E_PAID_SESSION_GAP\"]",
            )
            + "\n[messages.\"E_PAID_SESSION_GAP\"]\ndefault = \"retired\"\n[[rules]]\nid = \"gap\"\nkind = \"activity-gap\"\ncode = \"E_PAID_SESSION_GAP\"\n";
        let err = parse_manifest_compiled_in(&text).unwrap_err();
        assert!(
            err.to_string()
                .contains("code 'E_PAID_SESSION_GAP' is retired"),
            "{err:?}"
        );
    }

    /// A minimal valid v2 manifest from spec §13.6.
    fn valid_v2_toml() -> String {
        r#"
manifest_version = 2

record_types = []
balance_metrics = []
finding_codes = ["E_FRONTMATTER", "E_EXAMPLE_FIELD"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[[fields]]
name = "example_field"
grammar = "non-empty-string"

[checks]
[[checks.severity]]
key = "example-pack.example_rule"
default = "warning"

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"

[messages."E_EXAMPLE_FIELD"]
default = "example field '{key}' {problem}"
default_fix = "{fix}"
"#
        .to_string()
    }

    #[test]
    fn external_accepts_spec_example() {
        let m = parse_manifest_external(&valid_v2_toml()).unwrap();
        assert_eq!(m.manifest_version, 2);
        assert_eq!(m.pack.name, "example-pack");
        assert_eq!(m.pack.requires_spec, vec!["0.1".to_string()]);
        assert!(m.rules.is_empty());
    }

    #[test]
    fn external_accepts_no_rules() {
        // Valid v2 with no [[rules]] at all.
        let m = parse_manifest_external(&valid_v2_toml()).unwrap();
        assert!(m.rules.is_empty());
    }

    #[test]
    fn external_rejects_v1_version() {
        let text = valid_v2_toml().replace("manifest_version = 2", "manifest_version = 1");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(
            err.to_string()
                .contains("manifest_version 1 is not an external pack manifest"),
            "{err:?}"
        );
    }

    #[test]
    fn external_rejects_missing_requires_spec() {
        let text = valid_v2_toml().replace("requires_spec = [\"0.1\"]\n", "");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("requires_spec"), "{err:?}");
    }

    #[test]
    fn external_rejects_empty_requires_spec() {
        let text = valid_v2_toml().replace("requires_spec = [\"0.1\"]", "requires_spec = []");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("requires_spec"), "{err:?}");
    }

    #[test]
    fn external_rejects_reserved_name() {
        let text = valid_v2_toml().replace("name = \"example-pack\"", "name = \"personal\"");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err:?}");
    }

    /// #449: `coaching` is not reserved; an out-of-tree pack must load
    /// under its real name.
    #[test]
    fn external_accepts_coaching_name() {
        let text = valid_v2_toml()
            .replace("name = \"example-pack\"", "name = \"coaching\"")
            .replace("example-pack.example_rule", "coaching.example_rule");
        let m = parse_manifest_external(&text).expect("coaching is an external pack now");
        assert_eq!(m.pack.name, "coaching");
    }

    #[test]
    fn external_rejects_bad_name() {
        for bad in ["Bad_Name", "a", &"a".repeat(33)] {
            let text =
                valid_v2_toml().replace("name = \"example-pack\"", &format!("name = \"{bad}\""));
            let err = parse_manifest_external(&text).unwrap_err();
            assert!(err.to_string().contains("name"), "{bad}: {err:?}");
        }
    }

    #[test]
    fn external_rejects_core_verb() {
        for verb in ["touch", "merge"] {
            let text = valid_v2_toml() + &format!("\n[[verbs]]\nname = \"{verb}\"\n");
            let err = parse_manifest_external(&text).unwrap_err();
            assert!(err.to_string().contains("core verb"), "{verb}: {err:?}");
        }
    }

    #[test]
    fn external_rejects_core_edge_kind() {
        // Both the 0.1 kinds and the 0.2-only person→org kinds are core.
        for kind in ["married", "works_at"] {
            let text = valid_v2_toml()
                + &format!("\n[[edge_kinds]]\nname = \"{kind}\"\nsymmetric = true\n");
            let err = parse_manifest_external(&text).unwrap_err();
            assert!(
                err.to_string().contains("core edge kind"),
                "{kind}: {err:?}"
            );
        }
    }

    #[test]
    fn external_rejects_core_record_type() {
        let text = valid_v2_toml().replace("record_types = []", "record_types = [\"person\"]");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("core record type"), "{err:?}");
    }

    #[test]
    fn external_accepts_builtin_code_as_emission_claim() {
        // #441: a builtin code in finding_codes is an emission claim
        // (the pack emits it with its own template shell) — the v2 spec
        // example lists E_FRONTMATTER exactly this way. The semantics
        // stay core's; the fixture itself proves E_FRONTMATTER parses.
        let m = parse_manifest_external(&valid_v2_toml()).unwrap();
        assert!(m.finding_codes.iter().any(|c| c == "E_FRONTMATTER"));
    }

    #[test]
    fn external_rejects_bad_finding_code_shape() {
        let text = valid_v2_toml()
            .replace(
                "finding_codes = [\"E_EXAMPLE_FIELD\"]",
                "finding_codes = [\"w_x\"]",
            )
            .replace("[messages.\"E_EXAMPLE_FIELD\"]", "[messages.\"w_x\"]");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("finding code"), "{err:?}");
    }

    #[test]
    fn external_rejects_unknown_rule_kind() {
        let text = valid_v2_toml()
            + "\n[[rules]]\nid = \"my_rule\"\nkind = \"nope\"\ncode = \"E_EXAMPLE_FIELD\"\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("unknown rule kind"), "{err:?}");
    }

    #[test]
    fn external_rejects_rule_code_not_declared() {
        // #442 added "cadence-overdue" as a kind, so the
        // code-must-be-declared check now fires for it.
        let text = valid_v2_toml()
            + "\n[[rules]]\nid = \"my_rule\"\nkind = \"cadence-overdue\"\ncode = \"E_UNDECLARED\"\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(
            err.to_string()
                .contains("emits code 'E_UNDECLARED' which is not in finding_codes"),
            "{err:?}"
        );
    }

    #[test]
    fn external_rejects_rule_severity_key_undeclared() {
        // #442 added "cadence-overdue" as a kind, so the declared
        // severity_key check now fires for it.
        let text = valid_v2_toml()
            + "\n[[rules]]\nid = \"my_rule\"\nkind = \"cadence-overdue\"\ncode = \"E_EXAMPLE_FIELD\"\nseverity_key = \"example-pack.undeclared\"\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(
            err.to_string().contains("names undeclared severity_key"),
            "{err:?}"
        );
    }

    #[test]
    fn external_rejects_duplicate_rule_id() {
        // Duplicate IDs are checked before kind, so this hits the duplicate
        // check even with an empty kind list.
        let text = valid_v2_toml()
            + "\n[[rules]]\nid = \"dup\"\nkind = \"nope\"\ncode = \"E_EXAMPLE_FIELD\"\n"
            + "\n[[rules]]\nid = \"dup\"\nkind = \"nope\"\ncode = \"E_EXAMPLE_FIELD\"\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("duplicate rule id"), "{err:?}");
    }

    #[test]
    fn external_rejects_skill_path_traversal() {
        let text = valid_v2_toml().replace("skill = \"SKILL.md\"", "skill = \"../x.md\"");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("skill"), "{err:?}");
    }

    #[test]
    fn external_rejects_unknown_top_level_key() {
        let text = valid_v2_toml() + "bogus_key = 1\n";
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("bogus_key"), "{err:?}");
    }

    /// #550: the origin is set by the loader only. A manifest file cannot
    /// claim `origin`; a built-in is not trusted because a file says so.
    #[test]
    fn manifest_cannot_declare_its_own_origin() {
        let text = valid_v2_toml().replace(
            "manifest_version = 2",
            "manifest_version = 2\norigin = \"compiled-in\"",
        );
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("origin"), "{err:?}");
    }

    /// #550: the stable-code allowance is origin-based. The same v2 bytes
    /// parse compiled-in but fail as an external manifest, whatever the pack
    /// name.
    #[test]
    fn compiled_in_origin_allows_stable_codes() {
        let text = valid_v2_toml()
            .replace(
                "finding_codes = [\"E_FRONTMATTER\", \"E_EXAMPLE_FIELD\"]",
                "finding_codes = [\"E_FRONTMATTER\", \"W_CADENCE_OVERDUE\"]",
            )
            .replace(
                "[messages.\"E_EXAMPLE_FIELD\"]",
                "[messages.\"W_CADENCE_OVERDUE\"]",
            )
            + "\n[[rules]]\nid = \"cadence\"\nkind = \"cadence-overdue\"\ncode = \"W_CADENCE_OVERDUE\"\nseverity_key = \"example-pack.example_rule\"\ncadence_field = \"example_field\"\nevent_verbs = [\"touch\"]\n";
        assert!(
            parse_manifest_external(&text).is_err(),
            "an external pack must not claim W_CADENCE_OVERDUE"
        );
        let m = parse_manifest_compiled_in(&text).expect("compiled-in bytes may claim it");
        assert_eq!(m.origin, PackOrigin::CompiledIn);
        assert!(m.may_emit_builtin_codes());
    }

    /// #550: a compiled-in manifest may also claim a core verb and reuse a
    /// reserved name; an external one may not.
    #[test]
    fn compiled_in_origin_skips_capability_limits_and_reserved_name() {
        let text = valid_v2_toml()
            .replace("name = \"example-pack\"", "name = \"personal\"")
            .replace("example-pack.example_rule", "personal.example_rule")
            + "\n[[verbs]]\nname = \"touch\"\nid_type = \"person\"\n";
        assert!(parse_manifest_external(&text).is_err());
        let m = parse_manifest_compiled_in(&text).expect("compiled-in built-in parses");
        assert_eq!(m.origin, PackOrigin::CompiledIn);
        assert_eq!(m.verbs[0].name, "touch");
    }

    /// A minimal `ledger-balance` rule for the `[context]` tests: the five
    /// parameters `resolve_params` reads, nothing else.
    const CONTEXT_BALANCE_RULE: &str = r#"[[rules]]
id = "balance"
kind = "ledger-balance"
code = "E_EXAMPLE_FIELD"
open_verb = "open"
consume_verb = "session"
units_metric = "sessions_remaining"
minutes_metric = "icf_hours"
max_open_n = 100000
"#;

    /// #594: a `[context] ledger-sessions` table with one balance rule
    /// parses and resolves.
    #[test]
    fn external_accepts_ledger_sessions_context_view() {
        let text = format!(
            "{}\n[context]\nview = \"ledger-sessions\"\n{CONTEXT_BALANCE_RULE}",
            valid_v2_toml()
        );
        let m = parse_manifest_external(&text).expect("context view parses");
        assert_eq!(m.context.as_ref().unwrap().view, "ledger-sessions");
        assert_eq!(m.context.as_ref().unwrap().recent_limit, None);
    }

    /// #594: an unknown `[context].view` is refused.
    #[test]
    fn external_rejects_unknown_context_view() {
        let text = format!("{}\n[context]\nview = \"mystery\"\n", valid_v2_toml());
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("known core view"), "{err:?}");
    }

    /// #594: a `[context]` view needs a balance rule to name its verbs and
    /// metrics; none, or more than one, is refused.
    #[test]
    fn external_context_view_needs_exactly_one_balance_rule() {
        let none = format!(
            "{}\n[context]\nview = \"ledger-sessions\"\n",
            valid_v2_toml()
        );
        let err = parse_manifest_external(&none).unwrap_err();
        assert!(
            err.to_string().contains("needs a ledger-balance rule"),
            "{err:?}"
        );

        let two = format!(
            "{}\n[context]\nview = \"ledger-sessions\"\n{CONTEXT_BALANCE_RULE}{}",
            valid_v2_toml(),
            CONTEXT_BALANCE_RULE.replace("id = \"balance\"", "id = \"balance2\"")
        );
        let err = parse_manifest_external(&two).unwrap_err();
        assert!(
            err.to_string().contains("exactly one ledger-balance rule"),
            "{err:?}"
        );
    }

    /// #594: `recent_limit` must be positive.
    #[test]
    fn external_rejects_zero_recent_limit() {
        let text = format!(
            "{}\n[context]\nview = \"ledger-sessions\"\nrecent_limit = 0\n{CONTEXT_BALANCE_RULE}",
            valid_v2_toml()
        );
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(
            err.to_string().contains("recent_limit must be positive"),
            "{err:?}"
        );
    }

    /// #594: `[context]` is a v2 surface; a v1 file cannot name it.
    #[test]
    fn v1_rejects_context_table() {
        let text = valid_toml() + "\n[context]\nview = \"ledger-sessions\"\n";
        let err = parse_manifest(&text).unwrap_err();
        assert!(err.to_string().contains("manifest_version = 2"), "{err:?}");
    }
    fn v3_toml() -> String {
        r#"manifest_version = 3
balance_metrics = []
finding_codes = ["E_FRONTMATTER"]

[pack]
name = "place-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.3"]

[[record_types]]
name = "place"
id_prefix = "pl"
collection = "places"
main_file = "place.md"
entity = true
no_ai = "full"
required_fields = ["name"]
optional_fields = ["address"]

[[fields]]
name = "address"
grammar = "non-empty-string"

[[verbs]]
name = "visit"
id_type = "place"

[[edge_kinds]]
name = "visited"
symmetric = false
from = ["person"]
to = ["place"]

[messages."E_FRONTMATTER"]
default = "front matter key '{key}' {problem}"
default_fix = "{fix}"
"#
        .to_owned()
    }

    #[test]
    fn v3_declares_a_record_type_and_own_id_type() {
        let m = parse_manifest_external(&v3_toml()).unwrap();
        assert_eq!(m.manifest_version, 3);
        assert_eq!(m.record_types.names, vec!["place".to_owned()]);
        assert_eq!(m.record_types.decls.len(), 1);
        assert_eq!(m.record_types.decls[0].id_prefix, "pl");
        assert_eq!(m.verbs[0].id_type.as_deref(), Some("place"));
        assert!(m.is_entity_type("place"));
        assert_eq!(m.type_prefix("place"), Some(Prefix::Pack(*b"pl")));
    }

    #[test]
    fn v3_types_require_spec_03() {
        let text = v3_toml().replace("requires_spec = [\"0.3\"]", "requires_spec = [\"0.2\"]");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("0.3"), "{err:?}");
    }

    #[test]
    fn v2_may_not_claim_a_record_type() {
        let text = valid_v2_toml().replace("record_types = []", "record_types = [\"place\"]");
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("manifest_version = 3"), "{err:?}");
    }

    #[test]
    fn v3_rejects_bad_record_type_declarations() {
        for (from, to, needle) in [
            ("id_prefix = \"pl\"", "id_prefix = \"p\"", "two lowercase"),
            ("id_prefix = \"pl\"", "id_prefix = \"xp\"", "two lowercase"),
            ("name = \"place\"", "name = \"person\"", "core record type"),
            (
                "collection = \"places\"",
                "collection = \"people\"",
                "collection",
            ),
            ("no_ai = \"full\"", "no_ai = \"notes\"", "person_like"),
            (
                "optional_fields = [\"address\"]",
                "optional_fields = [\"missing\"]",
                "undeclared",
            ),
        ] {
            let text = v3_toml().replace(from, to);
            let err = parse_manifest_external(&text).unwrap_err();
            assert!(
                err.to_string().contains(needle),
                "expected {needle:?} for {to:?}: {err:?}"
            );
        }
    }

    #[test]
    fn v3_rejects_duplicate_type_prefix() {
        let text = v3_toml().replace(
            "[[fields]]",
            "[[record_types]]\nname = \"thing\"\nid_prefix = \"pl\"\ncollection = \"things\"\nmain_file = \"thing.md\"\n\n[[fields]]",
        );
        let err = parse_manifest_external(&text).unwrap_err();
        assert!(err.to_string().contains("duplicates"), "{err:?}");
    }

    #[test]
    fn v3_rejects_string_record_type_names() {
        let text = "manifest_version = 3\nrecord_types = [\"place\"]\nbalance_metrics = []\nfinding_codes = []\n\n[pack]\nname = \"place-pack\"\nversion = \"0.1\"\nskill = \"SKILL.md\"\nrequires_spec = [\"0.3\"]\n\n[messages]\n";
        let err = parse_manifest_external(text).unwrap_err();
        assert!(err.to_string().contains("tables"), "{err:?}");
    }
}
