//! Pack directory reader and canonical tree hash (#436).
//!
//! This is the one place that decides "what files are in a pack" and "what
//! is its hash". Install (#439/#440) and load (#438) both call it.
//!
//! The canonical tree hash (PD6, spec §3 of `spec/pack-lock.md`):
//! 1. Take every file in the pack directory, as paths relative to the
//!    directory, with `/` separators, UTF-8.
//! 2. Sort the paths bytewise.
//! 3. For each path, compute `sha256(content)` in lowercase hex.
//! 4. The pack hash is `sha256` of the concatenation of the lines
//!    `"<content-hex>  <path>\n"` (two spaces, trailing newline), written
//!    `sha256:<64 hex>`.
//!
//! File mode and mtime are not hashed. The `.git/` directory is never
//! vendored and never hashed.
//!
//! Limits (PD6): at most 200 files, each at most 1 MiB, total at most 4 MiB.
//! Rejected: symlinks, non-UTF-8 names, absolute or `..` paths, directories
//! other than as path components, any `.git` component.
//!
//! Allowlist (PD7): `manifest.toml`, the `[pack].skill` file, `<version>.md`,
//! optional `README*` and `LICENSE*` (top level only, no subdirectories).

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::DomainError;
use crate::packs::manifest::{
    parse_manifest_external, parse_manifest_with_origin, PackManifest, PackOrigin,
};

/// The `name@version` ids of any vendored directories for `name` under a
/// vault root's `packs/` (#551). A built-in pack is never installed from the
/// vault, so a caller uses this to fail closed on `packs/personal@…`.
/// Best-effort: an absent or unreadable `packs/` yields no ids.
pub(crate) fn vendored_versions(root: &Path, name: &str) -> Vec<String> {
    let dir = root.join("packs");
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let prefix = format!("{name}@");
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(fname) = fname.to_str() else {
            continue;
        };
        if let Some(version) = fname.strip_prefix(&prefix) {
            if !version.is_empty() {
                out.push(format!("{name}@{version}"));
            }
        }
    }
    out
}

/// Maximum number of files in a pack directory.
const MAX_FILES: usize = 200;
/// Maximum size of a single file (1 MiB).
const MAX_FILE_SIZE: u64 = 1024 * 1024;
/// Maximum total size of all files (4 MiB).
const MAX_TOTAL_SIZE: u64 = 4 * 1024 * 1024;

/// A pack directory read from disk: the files (relative path → bytes) and
/// the canonical tree hash.
#[derive(Clone, Debug)]
pub struct PackDir {
    /// Files keyed by relative path (`/` separators, UTF-8), sorted bytewise.
    pub files: BTreeMap<String, Vec<u8>>,
    /// Canonical tree hash, `sha256:<64 lowercase hex>`.
    pub hash: String,
}

/// Lowercase hex, no `0x` prefix.
fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(CHARS[(b >> 4) as usize] as char);
        s.push(CHARS[(b & 15) as usize] as char);
    }
    s
}

/// Compute the canonical tree hash for `files` (pure function).
///
/// `files` maps relative paths (`/` separators, UTF-8) to content bytes.
/// Paths are sorted bytewise; for each, `sha256(content)` is computed in
/// lowercase hex; the pack hash is `sha256` over the concatenation of
/// `"<content-hex>  <path>\n"` lines (two spaces), written
/// `sha256:<64 hex>`.
pub fn tree_hash(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut lines = String::new();
    // BTreeMap iterates in bytewise sorted order for &str keys.
    for (path, content) in files {
        let mut h = Sha256::new();
        h.update(content);
        let content_hex = hex(&h.finalize());
        lines.push_str(&content_hex);
        lines.push_str("  ");
        lines.push_str(path);
        lines.push('\n');
    }
    let mut h = Sha256::new();
    h.update(lines.as_bytes());
    format!("sha256:{}", hex(&h.finalize()))
}

/// Error for a pack directory problem, naming the relative path (never an
/// absolute path) and suggesting a fix.
fn pack_dir_err(path: &str, message: impl Into<String>, fix: impl Into<String>) -> DomainError {
    // A pack's file names are untrusted: escape before they reach a
    // terminal, so a control character or bidi override in a name cannot
    // hide the error it caused (#499).
    DomainError::pack_invalid(format!(
        "pack file '{}': {}",
        crate::packs::untrusted::escape_line(path),
        message.into()
    ))
    .with_fix(fix)
}

/// Convert a directory entry name to UTF-8, rejecting names that are not
/// valid UTF-8 (PD6).
///
/// Kept separate from the directory walk so the rule is testable without
/// creating such a file: macOS APFS refuses a non-UTF-8 name at the syscall
/// (EILSEQ), so a directory-based fixture cannot exist there.
fn utf8_name(name: &OsStr) -> Result<&str, DomainError> {
    name.to_str().ok_or_else(|| {
        // The name itself is not UTF-8, so it cannot appear in the message;
        // this is the one rejection that does not name the path.
        DomainError::pack_invalid("pack file name is not valid UTF-8")
            .with_fix("Rename the file to a UTF-8 name")
    })
}

/// Check if `name` matches the PD7 allowlist.
///
/// The allowlist is: `manifest.toml`, the skill file, `<version>.md`,
/// `README*`, `LICENSE*`. All at the top level; no subdirectories.
fn is_allowed(name: &str, skill_file: &str, version_file: &str) -> bool {
    if name == "manifest.toml" {
        return true;
    }
    if name == skill_file {
        return true;
    }
    if name == version_file {
        return true;
    }
    // README* and LICENSE* (top level only).
    if name.starts_with("README") || name.starts_with("LICENSE") {
        // Must be a plain file name, no path separators.
        return !name.contains('/') && !name.contains('\\');
    }
    false
}

/// Read a pack directory from the vault (an external pack), enforcing PD6
/// limits and the PD7 allowlist, and compute the canonical tree hash.
///
/// Equivalent to [`read_pack_dir_with_origin`] with [`PackOrigin::External`].
pub fn read_pack_dir(dir: &Path) -> Result<PackDir, DomainError> {
    read_pack_dir_with_origin(dir, PackOrigin::External)
}

/// Read a pack directory from disk, enforcing PD6 limits and the PD7
/// allowlist, and compute the canonical tree hash.
///
/// The directory must contain `manifest.toml`; it is read and parsed first
/// (with [`parse_manifest_with_origin`]) to learn the skill file name and the
/// version for the `<version>.md` contract file. Then every other entry is
/// validated against the allowlist. `origin` decides the manifest's trust
/// level (#550): the vault's own vendored packs are [`PackOrigin::External`];
/// a test that materializes a compiled-in built-in's bytes uses
/// [`PackOrigin::CompiledIn`].
///
/// Symlinks are never followed. Every rejection names the relative path
/// (never an absolute path) and suggests a fix.
pub fn read_pack_dir_with_origin(dir: &Path, origin: PackOrigin) -> Result<PackDir, DomainError> {
    // Read manifest.toml first, without following symlinks.
    let manifest_path = dir.join("manifest.toml");
    let manifest_meta = fs::symlink_metadata(&manifest_path).map_err(|_| {
        DomainError::pack_invalid("pack directory has no manifest.toml")
            .with_fix("Add a manifest.toml (manifest_version = 2) to the pack directory")
    })?;
    if manifest_meta.file_type().is_symlink() {
        return Err(pack_dir_err(
            "manifest.toml",
            "is a symlink",
            "Replace the symlink with the actual manifest.toml file",
        ));
    }
    if !manifest_meta.is_file() {
        return Err(pack_dir_err(
            "manifest.toml",
            "is not a regular file",
            "Replace it with a regular manifest.toml file",
        ));
    }
    let manifest_bytes = fs::read(&manifest_path).map_err(|e| {
        DomainError::pack_invalid(format!("cannot read pack file 'manifest.toml': {e}"))
            .with_fix("Make sure manifest.toml is readable")
    })?;
    let manifest_text = std::str::from_utf8(&manifest_bytes).map_err(|_| {
        pack_dir_err(
            "manifest.toml",
            "is not valid UTF-8",
            "Save manifest.toml as UTF-8",
        )
    })?;
    let manifest = parse_manifest_with_origin(manifest_text, origin).map_err(|e| {
        // parse_manifest_with_origin already returns a DomainError with file
        // and fix; wrap it as a pack error for the stable E_PACK_INVALID
        // code while keeping the message.
        DomainError::pack_invalid(format!("invalid manifest.toml: {}", e.message()))
            .with_fix("Fix the manifest.toml errors listed above")
    })?;

    let skill_file = manifest.pack.skill.clone();
    let version_file = format!("{}.md", manifest.pack.version);

    // Walk the directory (top level only).
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total_size: u64 = 0;

    let entries = fs::read_dir(dir).map_err(|e| {
        DomainError::pack_invalid(format!("cannot read pack directory: {e}"))
            .with_fix("Make sure the pack directory exists and is readable")
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            DomainError::pack_invalid(format!("cannot list pack directory: {e}"))
                .with_fix("Make sure the pack directory is readable")
        })?;
        let file_name = entry.file_name();
        let name_os = file_name.as_os_str();

        // Reject non-UTF-8 names.
        let name = utf8_name(name_os)?;

        // Reject .git (any component, though we're top-level only).
        if name == ".git" {
            return Err(pack_dir_err(
                name,
                "the .git directory is never part of a pack",
                "Remove .git from the pack directory (it is never vendored or hashed)",
            ));
        }

        // Use symlink_metadata: never follow symlinks.
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| {
            pack_dir_err(
                name,
                format!("cannot stat: {e}"),
                "Make sure the file exists and is readable",
            )
        })?;

        if meta.file_type().is_symlink() {
            return Err(pack_dir_err(
                name,
                "is a symlink; symlinks are not allowed in packs",
                "Replace the symlink with the actual file",
            ));
        }

        if meta.is_dir() {
            return Err(pack_dir_err(
                name,
                "is a directory; packs have no subdirectories",
                "Move the files to the top level of the pack directory or remove them",
            ));
        }

        if !meta.is_file() {
            return Err(pack_dir_err(
                name,
                "is not a regular file",
                "Replace it with a regular file or remove it",
            ));
        }

        // Enforce the PD7 allowlist.
        if !is_allowed(name, &skill_file, &version_file) {
            return Err(pack_dir_err(
                name,
                "is not an allowed pack file",
                format!(
                    "A pack may only contain manifest.toml, {skill_file}, {version_file}, and README*/LICENSE*"
                ),
            ));
        }

        // Enforce per-file size limit.
        let size = meta.len();
        if size > MAX_FILE_SIZE {
            return Err(pack_dir_err(
                name,
                format!("is {size} bytes, over the 1 MiB per-file limit"),
                "Split the file or remove it from the pack",
            ));
        }

        // Read the file.
        let content = fs::read(entry.path()).map_err(|e| {
            pack_dir_err(
                name,
                format!("cannot read: {e}"),
                "Make sure the file is readable",
            )
        })?;

        total_size += content.len() as u64;
        files.insert(name.to_string(), content);

        // Machine-generated packs are untrusted input, so fail as soon as a
        // limit is crossed instead of reading the whole directory into memory
        // first: without this, a tree of 10k files would be read at up to
        // 1 MiB each before the post-walk check rejected it.
        if files.len() > MAX_FILES {
            return Err(DomainError::pack_invalid(format!(
                "pack has {} files, over the 200-file limit",
                files.len()
            ))
            .with_fix("Remove files from the pack directory"));
        }
        if total_size > MAX_TOTAL_SIZE {
            return Err(DomainError::pack_invalid(format!(
                "pack is {total_size} bytes total, over the 4 MiB limit"
            ))
            .with_fix("Remove files from the pack directory"));
        }
    }

    // The skill file must exist (manifest references it).
    if !files.contains_key(&skill_file) {
        return Err(pack_dir_err(
            &skill_file,
            "is named by [pack].skill but missing from the pack directory",
            format!("Add {skill_file} to the pack directory"),
        ));
    }

    let hash = tree_hash(&files);
    Ok(PackDir { files, hash })
}

/// Best-effort parse of a vendored `manifest.toml` for problem paths only
/// (#438/#445): the success path parses the bytes `read_pack_dir` hashed
/// instead, so what is loaded is exactly what was verified.
///
/// The read is vetted: only a regular file (never a symlink —
/// `read_pack_dir` would reject one), at most [`MAX_FILE_SIZE`] (the same
/// bound the walk uses per file), so a hostile pack cannot hang or OOM
/// `check`. File contents are used for parsing only, never reported.
///
/// This is here — the pack module's one filesystem reader — so the
/// evaluator sources (`declarative.rs`, `external.rs`) stay free of I/O
/// (PD9); `evaluator_sources_have_no_io_apis` enforces that.
pub fn read_manifest_best_effort(dir: &Path) -> Option<PackManifest> {
    let path = dir.join("manifest.toml");
    // `symlink_metadata` never follows the link, so a symlinked
    // manifest.toml (or any non-regular file) is refused on every
    // platform — `read_pack_dir` rejects symlinks outright, and this
    // best-effort read must not be a way around that.
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() {
        return None;
    }
    if meta.len() > MAX_FILE_SIZE {
        return None;
    }
    let text = fs::read_to_string(&path).ok()?;
    parse_manifest_external(&text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write `files` (name → content) into a fresh tempdir, in the given
    /// order. Returns the tempdir (must be kept alive).
    fn pack_dir_with(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (name, content) in files {
            let path = dir.path().join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            let mut f = fs::File::create(&path).expect("create file");
            f.write_all(content).expect("write file");
        }
        dir
    }

    /// A minimal valid v2 manifest for tests.
    fn minimal_manifest(skill: &str, version: &str) -> String {
        format!(
            r#"manifest_version = 2
record_types = []
balance_metrics = []
finding_codes = ["E_EXAMPLE_FIELD"]

[pack]
name = "example-pack"
version = "{version}"
skill = "{skill}"
requires_spec = ["0.1"]

[messages."E_EXAMPLE_FIELD"]
default = "example field"
"#
        )
    }

    #[test]
    fn hash_matches_spec_example() {
        // Worked example from spec/pack-lock.md §4 (PR #471).
        let mut files = BTreeMap::new();
        files.insert(
            "manifest.toml".to_string(),
            b"manifest_version = 2\n".to_vec(),
        );
        files.insert("SKILL.md".to_string(), b"# Example pack skill.\n".to_vec());
        assert_eq!(
            tree_hash(&files),
            "sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b"
        );
    }

    #[test]
    fn hash_independent_of_creation_order() {
        // Same files created in different orders give the same hash.
        let dir1 = pack_dir_with(&[
            (
                "manifest.toml",
                minimal_manifest("SKILL.md", "0.1").as_bytes(),
            ),
            ("SKILL.md", b"# Skill.\n" as &[u8]),
            ("0.1.md", b"# Contract.\n" as &[u8]),
        ]);
        let dir2 = pack_dir_with(&[
            ("0.1.md", b"# Contract.\n" as &[u8]),
            ("SKILL.md", b"# Skill.\n" as &[u8]),
            (
                "manifest.toml",
                minimal_manifest("SKILL.md", "0.1").as_bytes(),
            ),
        ]);
        let pack1 = read_pack_dir(dir1.path()).expect("read dir1");
        let pack2 = read_pack_dir(dir2.path()).expect("read dir2");
        assert_eq!(pack1.hash, pack2.hash);
        assert_eq!(pack1.files, pack2.files);
    }

    #[test]
    fn hash_changes_when_one_byte_changes() {
        let mut files = BTreeMap::new();
        files.insert("a.txt".to_string(), b"hello".to_vec());
        let h1 = tree_hash(&files);
        files.insert("a.txt".to_string(), b"hellp".to_vec());
        let h2 = tree_hash(&files);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_changes_when_a_file_is_renamed() {
        let mut files = BTreeMap::new();
        files.insert("a.txt".to_string(), b"hello".to_vec());
        let h1 = tree_hash(&files);
        let mut files2 = BTreeMap::new();
        files2.insert("b.txt".to_string(), b"hello".to_vec());
        let h2 = tree_hash(&files2);
        assert_ne!(h1, h2);
    }

    #[test]
    #[cfg(unix)]
    fn hash_ignores_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = pack_dir_with(&[
            (
                "manifest.toml",
                minimal_manifest("SKILL.md", "0.1").as_bytes(),
            ),
            ("SKILL.md", b"# Skill.\n" as &[u8]),
        ]);
        let pack1 = read_pack_dir(dir.path()).expect("read");
        // chmod one file to 755; hash must not change.
        let skill_path = dir.path().join("SKILL.md");
        fs::set_permissions(&skill_path, fs::Permissions::from_mode(0o755)).expect("chmod");
        let pack2 = read_pack_dir(dir.path()).expect("read after chmod");
        assert_eq!(pack1.hash, pack2.hash);
    }

    #[test]
    #[cfg(unix)]
    fn reject_symlink() {
        // The link target must itself be an allowed pack file. `read_dir`
        // order is not stable, so with an unlisted target the walk could
        // reject the target first and this test would then assert against
        // the wrong rejection (it did, on CI).
        let dir = pack_dir_with(&[
            (
                "manifest.toml",
                minimal_manifest("SKILL.md", "0.1").as_bytes(),
            ),
            ("README-target", b"# Real.\n" as &[u8]),
        ]);
        std::os::unix::fs::symlink("README-target", dir.path().join("SKILL.md")).expect("symlink");
        let err = read_pack_dir(dir.path()).expect_err("symlink should be rejected");
        assert_eq!(
            err.code(),
            "E_PACK_INVALID",
            "wrong code: {}",
            err.message()
        );
        let msg = err.message();
        assert!(msg.contains("SKILL.md"), "names the path: {msg}");
        assert!(msg.contains("symlink"), "says symlink: {msg}");
    }

    #[test]
    fn reject_unlisted_file() {
        for name in ["bin/run.sh", "install.sh"] {
            let dir = pack_dir_with(&[
                (
                    "manifest.toml",
                    minimal_manifest("SKILL.md", "0.1").as_bytes(),
                ),
                ("SKILL.md", b"# Skill.\n" as &[u8]),
                (name, b"#!/bin/sh\n" as &[u8]),
            ]);
            let err = read_pack_dir(dir.path()).expect_err("unlisted file should be rejected");
            let msg = err.message();
            // For bin/run.sh, the entry name is "run.sh" (top level walk
            // sees only the file name; the subdirectory itself is rejected
            // first as a directory).
            assert!(
                msg.contains("not an allowed pack file") || msg.contains("directory"),
                "rejects {name}: {msg}"
            );
        }
    }

    #[test]
    fn reject_subdirectory() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("manifest.toml"),
            minimal_manifest("SKILL.md", "0.1"),
        )
        .expect("manifest");
        fs::write(dir.path().join("SKILL.md"), "# Skill.\n").expect("skill");
        fs::create_dir(dir.path().join("subdir")).expect("subdir");
        let err = read_pack_dir(dir.path()).expect_err("subdir should be rejected");
        let msg = err.message();
        assert!(msg.contains("subdir"), "names the path: {msg}");
        assert!(msg.contains("directory"), "says directory: {msg}");
    }

    #[test]
    fn reject_dot_git() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("manifest.toml"),
            minimal_manifest("SKILL.md", "0.1"),
        )
        .expect("manifest");
        fs::write(dir.path().join("SKILL.md"), "# Skill.\n").expect("skill");
        fs::create_dir(dir.path().join(".git")).expect(".git");
        let err = read_pack_dir(dir.path()).expect_err(".git should be rejected");
        let msg = err.message();
        assert!(msg.contains(".git"), "names the path: {msg}");
    }

    #[test]
    fn reject_too_many_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("manifest.toml"),
            minimal_manifest("SKILL.md", "0.1"),
        )
        .expect("manifest");
        fs::write(dir.path().join("SKILL.md"), "# Skill.\n").expect("skill");
        // 201 files total (over the 200 limit). Use README* names so they
        // pass the allowlist.
        for i in 0..199 {
            fs::write(dir.path().join(format!("README-{i}")), "x").expect("file");
        }
        let err = read_pack_dir(dir.path()).expect_err("too many files should be rejected");
        let msg = err.message();
        assert!(msg.contains("200"), "mentions the limit: {msg}");
    }

    #[test]
    fn reject_file_over_1mib() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("manifest.toml"),
            minimal_manifest("SKILL.md", "0.1"),
        )
        .expect("manifest");
        fs::write(dir.path().join("SKILL.md"), "# Skill.\n").expect("skill");
        // 1 MiB + 1 byte README.
        let big = vec![b'x'; (1024 * 1024) + 1];
        fs::write(dir.path().join("README-big"), big).expect("big file");
        let err = read_pack_dir(dir.path()).expect_err("oversize file should be rejected");
        let msg = err.message();
        assert!(msg.contains("README-big"), "names the path: {msg}");
        assert!(msg.contains("1 MiB"), "mentions the limit: {msg}");
    }

    #[test]
    fn reject_total_over_4mib() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("manifest.toml"),
            minimal_manifest("SKILL.md", "0.1"),
        )
        .expect("manifest");
        fs::write(dir.path().join("SKILL.md"), "# Skill.\n").expect("skill");
        // Five 1 MiB files = 5 MiB total (over the 4 MiB limit), each under
        // the per-file limit.
        let chunk = vec![b'x'; 1024 * 1024];
        for i in 0..5 {
            fs::write(dir.path().join(format!("README-{i}")), &chunk).expect("file");
        }
        let err = read_pack_dir(dir.path()).expect_err("oversize total should be rejected");
        let msg = err.message();
        assert!(msg.contains("4 MiB"), "mentions the limit: {msg}");
    }

    #[test]
    fn reject_missing_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = read_pack_dir(dir.path()).expect_err("missing manifest should be rejected");
        let msg = err.message();
        assert!(msg.contains("manifest.toml"), "names the path: {msg}");
    }

    #[test]
    fn reject_missing_skill_file() {
        let dir = pack_dir_with(&[(
            "manifest.toml",
            minimal_manifest("SKILL.md", "0.1").as_bytes(),
        )]);
        let err = read_pack_dir(dir.path()).expect_err("missing skill should be rejected");
        let msg = err.message();
        assert!(msg.contains("SKILL.md"), "names the path: {msg}");
    }

    #[test]
    fn reject_invalid_manifest() {
        let dir = pack_dir_with(&[
            ("manifest.toml", b"not = [valid\n" as &[u8]),
            ("SKILL.md", b"# Skill.\n" as &[u8]),
        ]);
        let err = read_pack_dir(dir.path()).expect_err("invalid manifest should be rejected");
        let msg = err.message();
        assert!(msg.contains("manifest.toml"), "names the path: {msg}");
    }

    #[test]
    #[cfg(unix)]
    fn reject_non_utf8_name() {
        use std::os::unix::ffi::OsStrExt;
        // The name check on its own. `to_str` rejects these bytes on every
        // platform, including macOS, where APFS refuses to create such a file
        // at all (EILSEQ) so a directory-based fixture cannot exist. The
        // walk-level test below covers the same rejection on Linux.
        let bad_name = std::ffi::OsStr::from_bytes(b"\xff\xfe-bad");
        let err = utf8_name(bad_name).expect_err("non-UTF-8 name should be rejected");
        let msg = err.message();
        assert_eq!(err.code(), "E_PACK_INVALID", "wrong code: {msg}");
        assert!(msg.contains("UTF-8"), "says UTF-8: {msg}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn reject_non_utf8_name_in_directory() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("manifest.toml"),
            minimal_manifest("SKILL.md", "0.1"),
        )
        .expect("manifest");
        fs::write(dir.path().join("SKILL.md"), "# Skill.\n").expect("skill");
        // Non-UTF-8 file name. Linux filesystems accept these bytes, so this
        // exercises the rejection through `read_dir`; macOS APFS returns
        // EILSEQ on the write, hence Linux-only.
        let bad_name = std::ffi::OsStr::from_bytes(b"\xff\xfe-bad");
        fs::write(dir.path().join(bad_name), b"x").expect("bad name file");
        let err = read_pack_dir(dir.path()).expect_err("non-UTF-8 name should be rejected");
        let msg = err.message();
        assert!(msg.contains("UTF-8"), "says UTF-8: {msg}");
    }

    #[test]
    fn accepts_readme_and_license() {
        let dir = pack_dir_with(&[
            (
                "manifest.toml",
                minimal_manifest("SKILL.md", "0.1").as_bytes(),
            ),
            ("SKILL.md", b"# Skill.\n" as &[u8]),
            ("0.1.md", b"# Contract.\n" as &[u8]),
            ("README.md", b"# Readme.\n" as &[u8]),
            ("LICENSE-MIT", b"MIT\n" as &[u8]),
        ]);
        let pack = read_pack_dir(dir.path()).expect("should accept README/LICENSE");
        assert_eq!(pack.files.len(), 5);
        assert!(pack.hash.starts_with("sha256:"));
        assert_eq!(pack.hash.len(), 7 + 64);
    }
}
