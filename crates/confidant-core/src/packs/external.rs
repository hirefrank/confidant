//! External packs loaded from the vault at `check` time (#438).
//!
//! A pack listed in `confidant.toml` that no compiled pack implements
//! must be resolved from the vault's own install state:
//! `confidant.lock` (#437) pins `name@version` to a content hash, and
//! `packs/<name>@<version>/` (#436) holds the vendored, hash-verified
//! files. Everything resolves per vault and fails closed (PD12): a pack
//! that fails any step is reported as a [`PackProblem`] and is never
//! folded, while its claimed verbs — as far as they are still knowable —
//! stay in the known-verb set so the failure does not cascade into
//! `E_UNKNOWN_VERB` noise (spec/pack-lock.md §5).
//!
//! In this issue an external pack folds an empty state and emits no
//! findings: it participates in the registry only — claims, scoping,
//! `W_PACK_ORPHAN` — exactly like a compiled pack (PD16). Declarative
//! rules arrive in #441.
//!
//! No secrets here: the vendored files are a pack's text and data
//! (`SKILL.md`, manifest), and error details carry vault-relative ids
//! and counts only, never file contents (PD7).

use chrono::NaiveDate;

use crate::check::Finding;
use crate::check::MergeMap;
use crate::id::Prefix;
use crate::packs::dir::read_pack_dir;
use crate::packs::lock::{read_lockfile, Lockfile};
use crate::packs::manifest::{parse_manifest_external, PackManifest};
use crate::packs::registry::PackRegistry;
use crate::packs::{EdgeKind, Pack, PackState};
use crate::vault::{SourcedEntry, Vault};

/// Which step of the resolution failed (mapped to finding codes in
/// `check.rs`: `Unknown`→`E_PACK_UNKNOWN`, `Hash`→`E_PACK_HASH`,
/// `Invalid`→`E_PACK_INVALID`, `Version`→`E_PACK_VERSION`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackProblemKind {
    /// No `confidant.lock` entry for the pinned `name@version`, or the
    /// listed id is not even of that shape.
    Unknown,
    /// The vendored directory is missing, or its canonical hash differs
    /// from the lockfile pin.
    Hash,
    /// The vendored files fail validation (`read_pack_dir`, manifest).
    Invalid,
    /// The pack's `requires_spec` does not include the vault's spec.
    Version,
}

/// One listed external pack could not be loaded (PD12, fail closed).
#[derive(Clone, Debug)]
pub struct PackProblem {
    /// The `name@version` id exactly as listed in `confidant.toml`.
    pub name: String,
    /// Which step failed.
    pub kind: PackProblemKind,
    /// Human-readable failure detail; vault-relative ids only, no file
    /// contents.
    pub detail: String,
    /// Verb names the pack claims, as far as they could still be read
    /// (spec/pack-lock.md §5). Empty for `Unknown`.
    pub known_verbs: Vec<String>,
}

/// The result of resolving the vault's external pack list.
pub struct ExternalLoad {
    /// Successfully loaded external packs, in config-list order.
    pub packs: Vec<&'static dyn Pack>,
    /// The loaded packs' leaked manifests (config order), for the
    /// `[checks]` key handling (#433/#438) and the evaluator (#441).
    pub manifests: Vec<&'static PackManifest>,
    /// The listed packs that failed to load, fail closed. Empty when
    /// `lockfile_error` is set: the lockfile finding covers the whole
    /// list, and per-pack `Unknown`s would only stack noise on top of
    /// it (each pack gets its finding from the one broken pin).
    pub problems: Vec<PackProblem>,
    /// `confidant.lock` exists but could not be read or parsed. One
    /// finding (mapped to `E_PACK_INVALID` by `check.rs`) covers every
    /// listed external pack; no per-pack findings are produced.
    pub lockfile_error: bool,
}

impl std::fmt::Debug for ExternalLoad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalLoad")
            .field(
                "packs",
                &self.packs.iter().map(|p| p.name()).collect::<Vec<_>>(),
            )
            .field("problems", &self.problems)
            .finish()
    }
}

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// An external pack registered at runtime: a validated, spec-compatible
/// manifest whose claims are leaked once — the same pattern the compiled
/// packs use in `coaching.rs` — plus the vendored skill text and the
/// manifest for the declarative evaluator (#441). The claim slices are
/// leaked too (the `Pack` trait returns `&'static`), so all of them are
/// `'static` field references copied out per call.
pub struct ExternalPack {
    manifest: &'static PackManifest,
    /// The vendored `[pack].skill` file text.
    skill_text: String,
    name: &'static str,
    verbs: &'static [&'static str],
    verb_id_types: Vec<(&'static str, Prefix)>,
    record_types: &'static [&'static str],
    fields: &'static [&'static str],
    balance_metrics: &'static [&'static str],
    edge_kinds: &'static [EdgeKind],
    finding_codes: &'static [&'static str],
}

impl ExternalPack {
    /// Leak a validated manifest into a static pack instance.
    fn build(manifest: PackManifest, skill_text: String) -> &'static ExternalPack {
        let name = leak_str(format!("{}@{}", manifest.pack.name, manifest.pack.version));
        let verbs: Vec<&'static str> = manifest
            .verbs
            .iter()
            .map(|v| leak_str(v.name.clone()))
            .collect();
        let verb_id_types: Vec<(&'static str, Prefix)> = manifest
            .verbs
            .iter()
            .filter_map(|v| v.id_type.map(|p| (leak_str(v.name.clone()), p)))
            .collect();
        let record_types: Vec<&'static str> = manifest
            .record_types
            .iter()
            .map(|r| leak_str(r.clone()))
            .collect();
        let fields: Vec<&'static str> = manifest
            .fields
            .iter()
            .map(|f| leak_str(f.name.clone()))
            .collect();
        let balance_metrics: Vec<&'static str> = manifest
            .balance_metrics
            .iter()
            .map(|b| leak_str(b.clone()))
            .collect();
        let edge_kinds: Vec<EdgeKind> = manifest
            .edge_kinds
            .iter()
            .map(|e| EdgeKind {
                name: leak_str(e.name.clone()),
                symmetric: e.symmetric,
            })
            .collect();
        let finding_codes: Vec<&'static str> = manifest
            .finding_codes
            .iter()
            .map(|c| leak_str(c.clone()))
            .collect();
        Box::leak(Box::new(ExternalPack {
            manifest: Box::leak(Box::new(manifest)),
            skill_text,
            name,
            verbs: Box::leak(verbs.into_boxed_slice()),
            verb_id_types,
            record_types: Box::leak(record_types.into_boxed_slice()),
            fields: Box::leak(fields.into_boxed_slice()),
            balance_metrics: Box::leak(balance_metrics.into_boxed_slice()),
            edge_kinds: Box::leak(edge_kinds.into_boxed_slice()),
            finding_codes: Box::leak(finding_codes.into_boxed_slice()),
        }))
    }

    /// The pack's manifest (leaked once with the pack).
    pub fn pack_manifest(&self) -> &PackManifest {
        self.manifest
    }

    /// The vendored `[pack].skill` file text (used by #441 and the
    /// agent-facing contract; never printed by `check`).
    pub fn skill_text(&self) -> &str {
        &self.skill_text
    }
}

impl Pack for ExternalPack {
    fn name(&self) -> &'static str {
        self.name
    }

    fn verbs(&self) -> &'static [&'static str] {
        self.verbs
    }

    fn record_types(&self) -> &'static [&'static str] {
        self.record_types
    }

    fn fields(&self) -> &'static [&'static str] {
        self.fields
    }

    fn balance_metrics(&self) -> &'static [&'static str] {
        self.balance_metrics
    }

    fn edge_kinds(&self) -> &'static [EdgeKind] {
        self.edge_kinds
    }

    fn finding_codes(&self) -> &'static [&'static str] {
        self.finding_codes
    }

    /// `verb → id-type` constraints from the manifest's `[[verbs]]`.
    fn verb_id_type(&self, verb: &str) -> Option<Prefix> {
        self.verb_id_types
            .iter()
            .find(|(v, _)| *v == verb)
            .map(|(_, prefix)| *prefix)
    }

    /// PD16: an external pack folds an empty state; only the merge view
    /// is kept so the declarative rules (#441) already share exactly the
    /// view a compiled pack's rules use.
    fn fold(
        &self,
        _vault: &Vault,
        merges: &MergeMap,
        _as_of: NaiveDate,
        _findings: &mut Vec<Finding>,
    ) -> Box<dyn PackState> {
        Box::new(ExternalState {
            merge: crate::packs::groups::MergeGroups::new(merges.clone()),
        })
    }

    /// PD16: no rules yet; nothing fires.
    fn findings(
        &self,
        _vault: &Vault,
        _state: &dyn PackState,
        _as_of: NaiveDate,
        _findings: &mut Vec<Finding>,
    ) {
    }

    /// PD16: the metric is declared and owned, no rule verifies values
    /// yet (the `ledger-balance` rule kind arrives in #446).
    fn check_balance(
        &self,
        _vault: &Vault,
        _state: &dyn PackState,
        _sourced: &SourcedEntry,
        _findings: &mut Vec<Finding>,
    ) {
    }
}

/// External state for #438: the merge view only (PD16: empty behaviour).
/// `check` never reads it down-typed in this issue; `as_any` exists for
/// the #441 rules.
pub struct ExternalState {
    /// The merge view, kept for #441's rules; nothing reads it in #438.
    #[allow(dead_code)]
    merge: crate::packs::groups::MergeGroups,
}

impl PackState for ExternalState {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The manifest's verb names, when it still parses. Used to build
/// [`PackProblem::known_verbs`] so a failed load does not cascade into
/// `E_UNKNOWN_VERB` noise (spec/pack-lock.md §5).
fn manifest_verb_names(manifest: Option<&PackManifest>) -> Vec<String> {
    manifest
        .map(|m| m.verbs.iter().map(|v| v.name.clone()).collect())
        .unwrap_or_default()
}

/// Parse the vendored manifest from the bytes `read_pack_dir` hashed
/// and vetted — the success path's only manifest source.
fn manifest_from_packed(packed: &crate::packs::dir::PackDir) -> Option<PackManifest> {
    let bytes = packed.files.get("manifest.toml")?;
    let text = String::from_utf8(bytes.clone()).ok()?;
    parse_manifest_external(&text).ok()
}

/// Best-effort vendored-manifest verbs for a problem path: the read is
/// vetted (see [`vendored_manifest_text`]); an unusable read degrades
/// to no known verbs rather than following a link.
fn best_effort_manifest_verbs(dir: &std::path::Path) -> Vec<String> {
    manifest_verb_names(vendored_manifest_text(dir).as_ref())
}

/// Best-effort parse of the vendored `manifest.toml` for problem paths
/// only (the success path parses the hashed bytes instead, so what is
/// loaded is exactly what was verified). The read is vetted: only a
/// regular file (never a symlink — `read_pack_dir` would reject one),
/// at most `MAX_MANIFEST_BYTES` (the same bound `read_pack_dir` uses
/// per file), so a hostile pack cannot hang or OOM `check`. File
/// contents are used for parsing only, never reported.
fn vendored_manifest_text(dir: &std::path::Path) -> Option<PackManifest> {
    let path = dir.join("manifest.toml");
    // `symlink_metadata` never follows the link, so a symlinked
    // manifest.toml (or any non-regular file) is refused on every
    // platform — `read_pack_dir` rejects symlinks outright, and this
    // best-effort read must not be a way around that.
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() {
        return None;
    }
    if meta.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    parse_manifest_external(&text).ok()
}

/// The per-file size bound `read_pack_dir` enforces (1 MiB).
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Vendored pack directory relative to the vault root: `packs/<name>@<version>`.
fn vendored_rel(name: &str, version: &str) -> String {
    format!("packs/{name}@{version}")
}

/// The vendored directory id for a listed `name@version`, for findings
/// (opaque vault-relative; never absolute).
pub fn vendored_rel_of(listed: &str) -> String {
    match listed.split_once('@') {
        Some((name, version)) => vendored_rel(name, version),
        None => format!("packs/{listed}"),
    }
}

/// Resolve the vault's external pack list (#438 scope item 2).
///
/// For every `name@version` in `names` that no compiled pack in
/// `compiled` implements, verify the entry against the lockfile and the
/// vendored directory, then load it. Compiled names are simply skipped —
/// a compiled pack always wins on the same `name@version` (PD14) and
/// resolves without a lockfile.
pub fn load_external_packs(
    root: &std::path::Path,
    spec: &str,
    names: &[String],
    compiled: &PackRegistry,
) -> ExternalLoad {
    let is_compiled = |listed: &str| compiled.all().iter().any(|p| p.name() == listed);

    // The lockfile is read once; it decides content for every external
    // pack. A lock file that exists but does not parse fails every
    // external resolution closed (`Unknown`): the install state is not
    // trustworthy without a readable pin.
    let lock = match read_lockfile(root) {
        Ok(Some(lock)) => lock,
        Ok(None) => Lockfile::default(),
        Err(_err) => {
            // The broken pin covers the whole list: one lockfile finding
            // (mapped to E_PACK_INVALID by check.rs), no per-pack
            // findings (#493 review). The error's own text can quote
            // operator free text, so it never reaches a finding.
            return ExternalLoad {
                packs: Vec::new(),
                manifests: Vec::new(),
                problems: Vec::new(),
                lockfile_error: true,
            };
        }
    };

    let mut packs: Vec<&'static dyn Pack> = Vec::new();
    let mut manifests: Vec<&'static PackManifest> = Vec::new();
    let mut problems = Vec::new();
    let mut loaded_ids = std::collections::HashSet::new();
    for listed in names {
        if is_compiled(listed) {
            continue;
        }
        if !loaded_ids.insert(listed.clone()) {
            // A repeated listing folds once (same rule as compiled packs);
            // skip loading the second time.
            continue;
        }
        let Some((name, version)) = listed.split_once('@') else {
            problems.push(PackProblem {
                name: listed.clone(),
                kind: PackProblemKind::Unknown,
                detail: "the listed id is not name@version".to_owned(),
                known_verbs: Vec::new(),
            });
            continue;
        };
        let Some(entry) = lock.find(name, version) else {
            // (a) Lockfile entry missing -> Unknown.
            problems.push(PackProblem {
                name: listed.clone(),
                kind: PackProblemKind::Unknown,
                detail: format!(
                    "confidant.lock pins no {name}@{version}; the install is incomplete"
                ),
                known_verbs: Vec::new(),
            });
            continue;
        };

        let dir_rel = vendored_rel(name, version);
        let dir = root.join(dir_rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        if !dir.is_dir() {
            // (b) Directory missing/unreadable -> Hash.
            problems.push(PackProblem {
                name: listed.clone(),
                kind: PackProblemKind::Hash,
                detail: format!("the vendored files {dir_rel} are missing"),
                known_verbs: Vec::new(),
            });
            continue;
        }
        // (c)/(e) read_pack_dir error -> Invalid.
        let packed = match read_pack_dir(&dir) {
            Ok(packed) => packed,
            Err(err) => {
                problems.push(PackProblem {
                    name: listed.clone(),
                    kind: PackProblemKind::Invalid,
                    detail: err.to_string(),
                    known_verbs: best_effort_manifest_verbs(&dir),
                });
                continue;
            }
        };

        // (d) Hash differs from the lock pin -> Hash. The vendored
        // (unverified) manifest still sells the verbs; the content is
        // not trusted for anything else. The manifest comes from the
        // bytes `read_pack_dir` hashed (never a fresh, unvetted read).
        if packed.hash != entry.hash {
            let vendored_manifest = manifest_from_packed(&packed);
            problems.push(PackProblem {
                name: listed.clone(),
                kind: PackProblemKind::Hash,
                detail: format!(
                    "the vendored files hash to {}, not the pinned sha256",
                    packed.hash
                ),
                known_verbs: manifest_verb_names(vendored_manifest.as_ref()),
            });
            continue;
        }

        // `read_pack_dir` hashed and vetted the files, but this module's
        // own schema validation is the gate: parse the manifest from the
        // hashed bytes so the loaded manifest is exactly the verified
        // content.
        let manifest = match manifest_from_packed(&packed) {
            Some(manifest) => manifest,
            None => {
                problems.push(PackProblem {
                    name: listed.clone(),
                    kind: PackProblemKind::Invalid,
                    detail: "the vendored manifest.toml does not parse".to_owned(),
                    known_verbs: Vec::new(),
                });
                continue;
            }
        };

        // (f) Identity mismatch -> Invalid.
        if manifest.pack.name != name || manifest.pack.version != version {
            problems.push(PackProblem {
                name: listed.clone(),
                kind: PackProblemKind::Invalid,
                detail: format!(
                    "the vendored manifest declares {}@{}, not {name}@{version}",
                    manifest.pack.name, manifest.pack.version
                ),
                known_verbs: manifest_verb_names(Some(&manifest)),
            });
            continue;
        }

        // (g) Spec compatibility -> Version.
        if !manifest.pack.requires_spec.iter().any(|req| req == spec) {
            problems.push(PackProblem {
                name: listed.clone(),
                kind: PackProblemKind::Version,
                detail: format!(
                    "the pack requires spec {:?}, but the vault uses {spec}",
                    manifest.pack.requires_spec
                ),
                known_verbs: manifest_verb_names(Some(&manifest)),
            });
            continue;
        }

        // Load: leak the claims once, keep the skill text and manifest
        // for the declarative evaluator (#441).
        let skill_text = packed
            .files
            .get(&manifest.pack.skill)
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
            .unwrap_or_default();
        let pack = ExternalPack::build(manifest, skill_text);
        packs.push(pack);
        manifests.push(pack.pack_manifest());
    }
    ExternalLoad {
        packs,
        manifests,
        problems,
        lockfile_error: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const LOCK_REV: &str = "0123456789abcdef0123456789abcdef01234567";

    /// A minimal valid external manifest (v2). The skill file is named
    /// there; `mood` uses a grammar core knows.
    const MANIFEST: &str = r#"
manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["W_GREET_STALE"]

[pack]
name = "example-pack"
version = "0.1"
skill = "SKILL.md"
requires_spec = ["0.1"]

[messages."W_GREET_STALE"]
default = "{who} greets oddly"

[[verbs]]
name = "greet"

[[fields]]
name = "mood"
grammar = "non-empty-string"
"#;

    /// Does the v2 schema accept this shape? `parse_manifest_external`
    /// is the authority; this helper just proves the fixture above
    /// parses, so a test failing on its fixture names the fixture.
    #[test]
    fn fixture_manifest_parses() {
        let m = parse_manifest_external(MANIFEST).expect("the test manifest fixture must parse");
        assert_eq!(m.pack.name, "example-pack");
    }

    #[test]
    fn unknown_when_lock_entry_missing() {
        let dir = tempdir().unwrap();
        let compiled = PackRegistry::compiled();
        let load = load_external_packs(
            dir.path(),
            "0.1",
            &["example-pack@0.1".to_owned()],
            &compiled,
        );
        assert!(load.packs.is_empty());
        assert_eq!(load.problems.len(), 1);
        assert_eq!(load.problems[0].kind, PackProblemKind::Unknown);
        assert!(
            load.problems[0].detail.contains("confidant.lock"),
            "{err}",
            err = load.problems[0].detail
        );
    }

    #[test]
    fn hashed_without_directory_is_hash_problem() {
        let dir = tempdir().unwrap();
        let mut lock = Lockfile::default();
        lock.upsert(crate::packs::lock::LockEntry {
            name: "example-pack".to_owned(),
            version: "0.1".to_owned(),
            source: "https://example.invalid/org/example-pack.git".to_owned(),
            rev: LOCK_REV.to_owned(),
            subdir: "".to_owned(),
            hash: format!("sha256:{}", "0".repeat(64)),
        });
        std::fs::write(dir.path().join("confidant.lock"), lock.to_toml()).unwrap();
        let compiled = PackRegistry::compiled();
        let load = load_external_packs(
            dir.path(),
            "0.1",
            &["example-pack@0.1".to_owned()],
            &compiled,
        );
        assert_eq!(load.problems[0].kind, PackProblemKind::Hash);
        assert!(load.problems[0].detail.contains("missing"));
    }

    #[test]
    fn listed_id_without_at_is_unknown() {
        let dir = tempdir().unwrap();
        let compiled = PackRegistry::compiled();
        let load = load_external_packs(dir.path(), "0.1", &["example-pack".to_owned()], &compiled);
        assert_eq!(load.problems[0].kind, PackProblemKind::Unknown);
    }

    #[test]
    fn unreadable_lockfile_is_one_finding_not_per_pack() {
        // A broken pin covers the whole list: one lockfile problem (the
        // loader maps it to E_PACK_INVALID), no per-pack Unknowns that
        // would point the operator at `pack add` while the file itself
        // is broken (review of #493).
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("confidant.lock"), "lock_version = 999\n").unwrap();
        let compiled = PackRegistry::compiled();
        let load = load_external_packs(
            dir.path(),
            "0.1",
            &["a@1".to_owned(), "b@2".to_owned()],
            &compiled,
        );
        assert!(load.lockfile_error, "{:?}", load.lockfile_error);
        assert!(load.problems.is_empty(), "{:?}", load.problems);
    }

    #[test]
    fn compiled_names_are_skipped_without_lockfile() {
        let dir = tempdir().unwrap();
        let compiled = PackRegistry::compiled();
        let load = load_external_packs(dir.path(), "0.1", &["coaching@0.1".to_owned()], &compiled);
        assert!(load.packs.is_empty());
        assert!(
            load.problems.is_empty(),
            "compiled names must resolve silently: {:?}",
            load.problems
        );
    }
}
