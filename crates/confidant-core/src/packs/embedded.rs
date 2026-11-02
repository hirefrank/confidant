//! Built-in declarative packs compiled into the binary (#550).
//!
//! `personal@0.2` and `personal@0.3` ship inside the binary as small pack
//! directories (`manifest.toml`, `SKILL.md`, `<version>.md`) and are loaded
//! through the same declarative path external packs use — the same
//! [`ManifestPack`] type, the same rule kinds, the same field-grammar
//! validation. 0.2 is a v2 manifest for specs 0.1–0.3; 0.3 is a v3 manifest
//! for spec 0.4. The only difference is the manifest's [`PackOrigin`]:
//!
//! - the bytes are compiled in, so the manifest is parsed with
//!   [`parse_manifest_compiled_in`] and is trusted as core (#504 decision 3):
//!   its rules may name the stable finding codes and it may claim the core
//!   `touch` verb;
//! - a vault's own `packs/<name>@<version>/` directory is never read for a
//!   built-in name, and any lockfile pin or vendored directory for it fails
//!   closed as `E_PACK_INVALID` (`external.rs`, #504 R8). The allowance is
//!   keyed on the origin, **never the pack name**.
//!
//! This module is pure data: no filesystem, no network (PD9). The in-crate
//! 0.3 bytes are the vendored copy of repo-root `packs/personal/`; the 0.2
//! bytes are frozen (older fixtures and vaults). A drift test pins 0.3 to
//! the root, and another proves both versions pass the pack-directory loader
//! (allowlist and limits) and hash stably.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::config::SpecVersion;
use crate::packs::dir::tree_hash;
use crate::packs::manifest::{parse_manifest_compiled_in, PackManifest};
use crate::packs::manifest_pack::{build_manifest_pack, ManifestPack};
use crate::packs::Pack;

/// `name@version` of the built-in personal pack for specs 0.1–0.3 (#550).
pub const PERSONAL_0_2: &str = "personal@0.2";

/// `name@version` of the built-in personal pack for spec 0.4 (#745).
pub const PERSONAL_0_3: &str = "personal@0.3";

/// Whether `listed` names a built-in pack, at any version (#551).
///
/// A built-in is implicit: it is enabled in every vault and a
/// `personal@…` entry in `confidant.toml` is accepted as a no-op. The check
/// is by name against the embedded packs (not every reserved name): an
/// `example-pack@9.9` listing is still an unknown external pin. The version
/// must be non-empty, so a malformed `personal@` is not a listing.
pub fn is_builtin_listing(listed: &str) -> bool {
    let Some((name, version)) = listed.split_once('@') else {
        return false;
    };
    !version.is_empty() && embedded_packs().iter().any(|p| p.reserved_name() == name)
}

/// The embedded pack a built-in listing resolves to, at any version.
pub fn find_listing(listed: &str) -> Option<&'static EmbeddedPack> {
    let (name, _version) = listed.split_once('@')?;
    embedded_packs()
        .iter()
        .find(|p| p.listed == listed)
        .or_else(|| embedded_packs().iter().find(|p| p.reserved_name() == name))
}

/// The embedded personal@0.2 manifest (vendored from
/// `packs/personal/manifest.toml`).
const PERSONAL_0_2_MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/pack-manifests/personal-0.2/manifest.toml"
));

/// The embedded personal@0.2 skill text (vendored from
/// `packs/personal/SKILL.md`).
const PERSONAL_0_2_SKILL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/pack-manifests/personal-0.2/SKILL.md"
));

/// The embedded personal@0.2 contract doc (vendored from
/// `packs/personal/0.2.md`).
const PERSONAL_0_2_CONTRACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/pack-manifests/personal-0.2/0.2.md"
));

/// The embedded personal@0.3 manifest (vendored from
/// `packs/personal/manifest.toml`).
const PERSONAL_0_3_MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/pack-manifests/personal-0.3/manifest.toml"
));

/// The embedded personal@0.3 skill text (vendored from
/// `packs/personal/SKILL.md`).
const PERSONAL_0_3_SKILL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/pack-manifests/personal-0.3/SKILL.md"
));

/// The embedded personal@0.3 contract doc (vendored from
/// `packs/personal/0.3.md`).
const PERSONAL_0_3_CONTRACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/pack-manifests/personal-0.3/0.3.md"
));

/// One pack compiled into the binary as a declarative pack directory.
pub struct EmbeddedPack {
    /// The `name@version` a vault lists to enable it.
    listed: &'static str,
    /// The leaked declarative pack (built once).
    pack: &'static ManifestPack,
    /// The manifest the pack was built from, for `[checks]` key handling
    /// and the evaluator.
    manifest: &'static PackManifest,
    /// The pack directory's files, keyed by relative path (as the
    /// pack-directory hash uses). Kept so tests can prove the embedded
    /// bytes pass the loader.
    files: BTreeMap<String, Vec<u8>>,
    /// The canonical tree hash of [`EmbeddedPack::files`].
    hash: String,
}

impl EmbeddedPack {
    /// The `name@version` a vault lists to enable this pack.
    pub fn listed(&self) -> &'static str {
        self.listed
    }

    /// The pack's reserved name (`personal`), without the version.
    pub fn reserved_name(&self) -> &'static str {
        self.listed
            .split_once('@')
            .map(|(name, _)| name)
            .unwrap_or(self.listed)
    }

    /// Whether a vault listing names this built-in, at any version (#551).
    /// The version must be non-empty: a malformed `personal@` names nothing.
    pub fn matches_listing(&self, listed: &str) -> bool {
        listed
            .split_once('@')
            .is_some_and(|(name, version)| !version.is_empty() && name == self.reserved_name())
    }

    /// Whether this built-in version is active in a vault with `spec`.
    ///
    /// `personal@0.2` serves 0.1–0.3; `personal@0.3` serves 0.4. A future
    /// built-in defaults to active everywhere until it gets its own rule.
    pub fn active_in(&self, spec: SpecVersion) -> bool {
        if self.listed == PERSONAL_0_2 {
            spec < SpecVersion::V04
        } else if self.listed == PERSONAL_0_3 {
            spec >= SpecVersion::V04
        } else {
            true
        }
    }

    /// The registered pack.
    pub fn pack(&self) -> &'static dyn Pack {
        self.pack
    }

    /// The pack's manifest.
    pub fn manifest(&self) -> &'static PackManifest {
        self.manifest
    }

    /// The pack directory's files (relative path → bytes).
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    /// The canonical tree hash of the pack directory.
    pub fn hash(&self) -> &str {
        &self.hash
    }
}

/// Every built-in declarative pack, built once.
pub fn embedded_packs() -> &'static [EmbeddedPack] {
    static PACKS: OnceLock<Vec<EmbeddedPack>> = OnceLock::new();
    PACKS.get_or_init(|| {
        vec![
            build(
                PERSONAL_0_2,
                PERSONAL_0_2_MANIFEST,
                PERSONAL_0_2_SKILL,
                PERSONAL_0_2_CONTRACT,
            ),
            build(
                PERSONAL_0_3,
                PERSONAL_0_3_MANIFEST,
                PERSONAL_0_3_SKILL,
                PERSONAL_0_3_CONTRACT,
            ),
        ]
    })
}

/// The built-in versions active in a vault with `spec`, in registry order.
pub fn active_for_spec(spec: SpecVersion) -> Vec<&'static EmbeddedPack> {
    embedded_packs()
        .iter()
        .filter(|pack| pack.active_in(spec))
        .collect()
}

/// The built-in pack with this `name@version`, if any.
pub fn find(listed: &str) -> Option<&'static EmbeddedPack> {
    embedded_packs().iter().find(|p| p.listed == listed)
}

/// Build one embedded pack from its bytes. The manifest is parsed with the
/// compiled-in origin so the stable-code allowance applies (and only here).
fn build(
    listed: &str,
    manifest_toml: &'static str,
    skill: &'static str,
    contract: &'static str,
) -> EmbeddedPack {
    let manifest = parse_manifest_compiled_in(manifest_toml)
        .expect("an embedded pack manifest is compile-time data and must parse");
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    files.insert(
        "manifest.toml".to_owned(),
        manifest_toml.as_bytes().to_vec(),
    );
    files.insert(manifest.pack.skill.clone(), skill.as_bytes().to_vec());
    files.insert(
        format!("{}.md", manifest.pack.version),
        contract.as_bytes().to_vec(),
    );
    let hash = tree_hash(&files);
    let pack = build_manifest_pack(manifest, skill.to_owned());
    EmbeddedPack {
        listed: Box::leak(listed.to_owned().into_boxed_str()),
        pack,
        manifest: pack.pack_manifest(),
        files,
        hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::dir::{read_pack_dir, read_pack_dir_with_origin};
    use crate::packs::manifest::{parse_manifest_external, PackOrigin};

    /// The repo-root pack directory for a built-in, when the repo is present
    /// (a published crate tarball has no `../../packs`).
    fn repo_root_pack(name: &str) -> Option<std::path::PathBuf> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packs")
            .join(name);
        dir.is_dir().then_some(dir)
    }

    /// Drift test (#550, #745): the embedded personal@0.3 bytes must match
    /// the repo-root human contract (`packs/personal/`). 0.2 is frozen.
    #[test]
    fn embedded_personal_0_3_matches_repo_root() {
        let Some(root) = repo_root_pack("personal") else {
            return; // published crate tarball: no repo root to compare against
        };
        let declared = find(PERSONAL_0_3).expect("personal@0.3 is embedded");
        for (rel, bytes) in declared.files() {
            let actual = std::fs::read(root.join(rel))
                .unwrap_or_else(|e| panic!("read packs/personal/{rel}: {e}"));
            assert_eq!(
                &actual, bytes,
                "embedded pack-manifests/personal-0.3/{rel} has drifted from \
                 packs/personal/{rel}; copy the repo-root file over"
            );
        }
    }

    /// Acceptance (#550): both embedded versions pass the pack-directory
    /// loader — allowlist, PD6 limits, manifest parse — and hash stably. The
    /// bytes are materialized to a temp dir and read back with the compiled-in
    /// origin, the same reader `pack verify` uses for a vendored pack.
    #[test]
    fn embedded_packs_pass_pack_dir_loader_and_hash_stably() {
        for declared in embedded_packs() {
            let dir = tempfile::tempdir().expect("tempdir");
            for (rel, bytes) in declared.files() {
                let path = dir.path().join(rel);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            let read = read_pack_dir_with_origin(dir.path(), PackOrigin::CompiledIn)
                .expect("the embedded bytes must pass the pack-dir loader");
            assert_eq!(
                read.hash,
                declared.hash(),
                "{}: the embedded tree hash must equal the loader's",
                declared.listed()
            );
            // Stable across reads (no mtime/order in the hash).
            let again = read_pack_dir_with_origin(dir.path(), PackOrigin::CompiledIn).unwrap();
            assert_eq!(read.hash, again.hash);
        }
    }

    /// The same bytes must NOT load through the external path: the stable-code
    /// allowance is keyed on compiled-in origin, not the pack name (#504 R8).
    #[test]
    fn embedded_bytes_fail_the_external_reader() {
        for declared in embedded_packs() {
            let dir = tempfile::tempdir().expect("tempdir");
            for (rel, bytes) in declared.files() {
                std::fs::write(dir.path().join(rel), bytes).unwrap();
            }
            let err = read_pack_dir(dir.path())
                .expect_err("the embedded manifest must not load as an external pack");
            assert_eq!(err.code(), "E_PACK_INVALID", "{}", err.message());
        }
    }

    /// The stable-code allowance is origin-based: the embedded manifest parses
    /// compiled-in and fails as an external manifest, and an arbitrary external
    /// pack cannot claim a stable code.
    #[test]
    fn stable_code_allowance_is_origin_based_not_name_based() {
        assert!(
            parse_manifest_compiled_in(PERSONAL_0_2_MANIFEST).is_ok(),
            "the embedded manifest parses with the compiled-in origin"
        );
        assert!(
            parse_manifest_external(PERSONAL_0_2_MANIFEST).is_err(),
            "the same bytes must fail as an external manifest"
        );
        // Any external pack naming a stable code fails, whatever its name.
        let external =
            PERSONAL_0_2_MANIFEST.replace("name = \"personal\"", "name = \"example-pack\"");
        assert!(
            parse_manifest_external(&external).is_err(),
            "an external pack must not claim W_CADENCE_OVERDUE"
        );
    }

    /// Acceptance (#550): the embedded SKILL documents every finding code,
    /// every `[checks]` key, and every declared field, so the docs cannot
    /// drift from the manifest the binary loads.
    #[test]
    fn embedded_skill_documents_codes_keys_and_fields() {
        for declared in embedded_packs() {
            let manifest = declared.manifest();
            let skill = declared.pack().skill_text().expect("pack skill");
            for code in &manifest.finding_codes {
                assert!(
                    skill.contains(code.as_str()),
                    "{}: SKILL does not document {code}",
                    declared.listed()
                );
            }
            for check in manifest
                .checks
                .severity
                .iter()
                .map(|s| &s.key)
                .chain(manifest.checks.int.iter().map(|i| &i.key))
            {
                assert!(
                    skill.contains(&format!("`{check}`")),
                    "{}: SKILL does not document [checks] key {check}",
                    declared.listed()
                );
            }
            for field in &manifest.fields {
                assert!(
                    skill.contains(&field.name),
                    "{}: SKILL does not document field {}",
                    declared.listed(),
                    field.name
                );
            }
            assert!(
                skill.contains("never"),
                "{}: SKILL must document cadence `never`",
                declared.listed()
            );
            assert!(
                skill.contains("snooze_until"),
                "{}: SKILL must document snooze_until",
                declared.listed()
            );
        }
    }

    #[test]
    fn personal_version_is_selected_by_spec() {
        let older: Vec<&str> = active_for_spec(SpecVersion::V03)
            .iter()
            .map(|p| p.listed())
            .collect();
        assert_eq!(older, vec![PERSONAL_0_2]);
        let four: Vec<&str> = active_for_spec(SpecVersion::V04)
            .iter()
            .map(|p| p.listed())
            .collect();
        assert_eq!(four, vec![PERSONAL_0_3]);
        assert_eq!(find(PERSONAL_0_2).unwrap().manifest().pack.version, "0.2");
        assert_eq!(find(PERSONAL_0_3).unwrap().manifest().pack.version, "0.3");
    }

    /// #551 nit: a malformed `personal@` (empty version) is not a built-in
    /// listing; a real version is, at any value.
    #[test]
    fn builtin_listings_require_a_nonempty_version() {
        assert!(is_builtin_listing("personal@0.1"));
        assert!(is_builtin_listing("personal@0.2"));
        assert!(is_builtin_listing("personal@0.3"));
        assert!(is_builtin_listing("personal@9.9"));
        assert!(!is_builtin_listing("personal@"));
        assert!(!is_builtin_listing("personal"));
        assert!(!is_builtin_listing("example-pack@0.1"));
        let declared = find(PERSONAL_0_2).expect("personal@0.2 is embedded");
        assert!(declared.matches_listing("personal@0.1"));
        assert!(!declared.matches_listing("personal@"));
        assert!(!declared.matches_listing("personal"));
        let declared = find(PERSONAL_0_3).expect("personal@0.3 is embedded");
        assert!(declared.matches_listing("personal@0.2"));
        assert!(!declared.matches_listing("personal@"));
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn personal_versions_keep_the_same_checks_and_codes() {
        let old = find(PERSONAL_0_2).unwrap().manifest();
        let new = find(PERSONAL_0_3).unwrap().manifest();
        let severity = |m: &PackManifest| {
            m.checks
                .severity
                .iter()
                .map(|s| (s.key.clone(), s.default.clone()))
                .collect::<Vec<_>>()
        };
        let ints = |m: &PackManifest| {
            m.checks
                .int
                .iter()
                .map(|i| (i.key.clone(), i.default))
                .collect::<Vec<_>>()
        };
        assert_eq!(severity(old), severity(new));
        assert_eq!(ints(old), ints(new));
        assert_eq!(old.finding_codes, new.finding_codes);
        assert_eq!(new.pack.version, "0.3");
        assert_eq!(new.record_types.decls.len(), 2);
        assert!(new.edge_kinds.iter().any(|k| k.name == "visited"));
    }
}
