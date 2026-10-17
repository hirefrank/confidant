//! `confidant.lock`: the file that pins which bytes an external pack
//! resolves to (#437; spec `spec/pack-lock.md` §2).
//!
//! Read, write and validate only. Nothing here touches the network, the
//! digest of a vendored directory (#436 computes that) or `check` (#438
//! consumes it). The lockfile is committed plaintext and holds no private
//! data.
//!
//! Canonicalisation: `parse` sorts the entries, so `parse(to_toml(x)) == x`
//! holds for any valid file and a hand-edited lockfile is normalised on the
//! next read. Unknown keys are an error (spec §2), not a warning: a newer
//! lockfile this reader does not understand must fail closed.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::packs::manifest::is_valid_pack_name;

/// The only `lock_version` this reader implements (spec §2). A reader that
/// does not implement the version in the file refuses rather than guessing.
pub const LOCK_VERSION: u32 = 1;

/// File name inside the vault.
pub const LOCKFILE_NAME: &str = "confidant.lock";

/// One `[[pack]]` entry.
///
/// Every field is a `String`: the lockfile is data, and the patterns are
/// enforced by [`Lockfile::parse`] rather than by types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockEntry {
    /// Pack name, PD14 grammar `^[a-z][a-z0-9-]{1,31}$`.
    pub name: String,
    /// The pack's own version string (`confidant.toml` pins `name@version`).
    pub version: String,
    /// `https://…` git URL, or the literal `"dir"` for `--from-dir` installs.
    pub source: String,
    /// Full 40-hex commit for `https://` sources; empty for `"dir"`.
    pub rev: String,
    /// Optional path inside the source repository; `""` means the root.
    #[serde(default)]
    pub subdir: String,
    /// Canonical tree digest of the vendored directory, `sha256:<64 hex>`.
    pub hash: String,
}

/// A parsed `confidant.lock`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lockfile {
    /// Entries, sorted by `name` then `version` (spec §2; the version
    /// tie-break is what this file adds, since the spec's "sorted by name"
    /// is ambiguous when two versions of one pack are installed).
    pub packs: Vec<LockEntry>,
}

/// Top-level shape for (de)serialisation. Kept private so the public
/// [`Lockfile`] has no `lock_version` field to get out of step with the
/// only value this reader implements.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockToml {
    lock_version: u32,
    #[serde(default)]
    pack: Vec<LockEntry>,
}

/// Sort entries canonically: by `name`, then `version`.
///
/// This is the lockfile's in-memory invariant, not just a formatting step
/// ([`Lockfile::parse`], [`Lockfile::upsert`] and [`Lockfile::to_toml`] all
/// keep it), so `parse(to_toml(x)) == x` holds and two lockfiles that
/// differ only in written order compare equal.
fn sort_packs(packs: &mut [LockEntry]) {
    packs.sort_by(|a, b| {
        a.name
            .as_str()
            .cmp(b.name.as_str())
            .then_with(|| a.version.cmp(&b.version))
    });
}

/// Reject an entry field, naming the offending pack.
fn entry_err(
    name: &str,
    what: &str,
    why: impl Into<String>,
    fix: impl Into<String>,
) -> DomainError {
    DomainError::pack_invalid(format!(
        "confidant.lock entry '{name}': {what}: {}",
        why.into()
    ))
    .with_fix(fix)
}

/// `sha256:` + 64 lowercase hex.
fn is_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 40 lowercase hex.
fn is_full_rev(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A relative path with no `..` or root components.
fn is_relative_subdir(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path.components().all(|c| {
            matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

impl LockEntry {
    /// Validate one parsed entry against spec §2.
    fn validate(&self) -> Result<(), DomainError> {
        if !is_valid_pack_name(&self.name) {
            return Err(DomainError::pack_invalid(format!(
                "confidant.lock entry '{}': name is not a valid pack name (must match ^[a-z][a-z0-9-]{{1,31}}$)",
                self.name
            ))
            .with_fix("Fix the name to lowercase letters, digits and hyphens"));
        }
        if self.version.is_empty() {
            return Err(entry_err(
                &self.name,
                "version",
                "is empty",
                "Write the pack's version, e.g. \"0.1\"",
            ));
        }
        if !is_sha256(&self.hash) {
            return Err(entry_err(
                &self.name,
                "hash",
                format!("'{}' is not sha256:<64 lowercase hex>", self.hash),
                "Use the canonical tree digest from `confidant pack add`",
            ));
        }
        if !is_relative_subdir(&self.subdir) {
            return Err(entry_err(
                &self.name,
                "subdir",
                format!("'{}' is absolute or contains `..`", self.subdir),
                "Use a path inside the source repository, or \"\" for its root",
            ));
        }
        if self.source == "dir" {
            if !self.rev.is_empty() {
                return Err(entry_err(
                    &self.name,
                    "rev",
                    "must be empty for a \"dir\" source (there is no commit)",
                    "Set rev = \"\"",
                ));
            }
            return Ok(());
        }
        if !self.source.starts_with("https://") {
            return Err(entry_err(
                &self.name,
                "source",
                format!("'{}' is not an https:// URL or \"dir\"", self.source),
                "Only https:// URLs are fetched (PD3)",
            ));
        }
        if self.rev.is_empty() {
            return Err(entry_err(
                &self.name,
                "rev",
                "is required for an https:// source",
                "Pin the full 40-hex commit the pack was fetched at",
            ));
        }
        if !is_full_rev(&self.rev) {
            return Err(entry_err(
                &self.name,
                "rev",
                format!("'{}' is not 40 lowercase hex characters", self.rev),
                "Use the full commit id, lowercase",
            ));
        }
        Ok(())
    }
}

impl Lockfile {
    /// Parse `confidant.lock` text, validating every entry (spec §2).
    ///
    /// Entries come back sorted by `name` then `version`.
    pub fn parse(text: &str) -> Result<Lockfile, DomainError> {
        let raw: LockToml = toml::from_str(text).map_err(|e| {
            DomainError::pack_invalid(format!("confidant.lock is not valid TOML: {e}"))
                .with_fix("Fix the lockfile, or re-run `confidant pack add --yes`")
        })?;
        if raw.lock_version != LOCK_VERSION {
            return Err(DomainError::pack_invalid(format!(
                "confidant.lock has lock_version {}; this version of confidant implements {}",
                raw.lock_version, LOCK_VERSION
            ))
            .with_fix("Upgrade confidant, or re-run `confidant pack add --yes`"));
        }
        let mut packs = raw.pack;
        for entry in &packs {
            entry.validate()?;
        }
        sort_packs(&mut packs);
        for pair in packs.windows(2) {
            if pair[0].name == pair[1].name && pair[0].version == pair[1].version {
                return Err(DomainError::pack_invalid(format!(
                    "confidant.lock lists '{}@{}' twice",
                    pair[0].name, pair[0].version
                ))
                .with_fix("Keep exactly one entry per name@version"));
            }
        }
        Ok(Lockfile { packs })
    }

    /// Canonical TOML: sorted, fixed key order, trailing newline.
    pub fn to_toml(&self) -> String {
        let mut packs = self.packs.clone();
        sort_packs(&mut packs);
        let text = toml::to_string(&LockToml {
            lock_version: LOCK_VERSION,
            pack: packs,
        })
        .expect("a lockfile always serialises");
        if text.ends_with('\n') {
            text
        } else {
            let mut text = text;
            text.push('\n');
            text
        }
    }

    /// The entry for `name@version`, if installed.
    pub fn find(&self, name: &str, version: &str) -> Option<&LockEntry> {
        self.packs
            .iter()
            .find(|e| e.name == name && e.version == version)
    }

    /// Insert `entry`, replacing the same `name@version` if present.
    pub fn upsert(&mut self, entry: LockEntry) {
        match self
            .packs
            .iter_mut()
            .find(|e| e.name == entry.name && e.version == entry.version)
        {
            Some(existing) => *existing = entry,
            None => self.packs.push(entry),
        }
        sort_packs(&mut self.packs);
    }

    /// Drop `name@version`. Removing something absent is a no-op.
    pub fn remove(&mut self, name: &str, version: &str) {
        self.packs
            .retain(|e| !(e.name == name && e.version == version));
    }
}

/// Read `<vault>/confidant.lock`.
///
/// `Ok(None)` when the file is absent. Conflict markers are
/// `E_CONFLICT`: the operator resolves them by hand, exactly as for a
/// conflicted record.
pub fn read_lockfile(vault_root: &Path) -> Result<Option<Lockfile>, DomainError> {
    let path = vault_root.join(LOCKFILE_NAME);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(
                DomainError::pack_invalid(format!("cannot read {LOCKFILE_NAME}: {e}"))
                    .with_fix("Make sure confidant.lock is readable"),
            )
        }
    };
    if crate::record::has_conflict_markers(&text) {
        return Err(DomainError::conflict(format!(
            "{LOCKFILE_NAME} has unresolved merge conflicts"
        ))
        .with_fix("Resolve the conflict markers (git mergetool), then retry"));
    }
    Lockfile::parse(&text).map(Some)
}

/// The bytes to commit for `lock`.
///
/// Writing goes through the ordinary write path (#440); this only
/// produces the canonical content, so nothing here touches the filesystem.
pub fn lockfile_bytes(lock: &Lockfile) -> Vec<u8> {
    lock.to_toml().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, version: &str) -> LockEntry {
        LockEntry {
            name: name.to_string(),
            version: version.to_string(),
            source: "https://example.invalid/org/pack.git".to_string(),
            rev: "0123456789abcdef0123456789abcdef01234567".to_string(),
            subdir: String::new(),
            hash: "sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b"
                .to_string(),
        }
    }

    /// Minimal valid lockfile text around `entries`.
    fn lock_text(entries: &str) -> String {
        format!("lock_version = 1\n{entries}")
    }

    fn https_entry(name: &str) -> String {
        format!(
            "[[pack]]\nname = \"{name}\"\nversion = \"0.1\"\n\
             source = \"https://example.invalid/org/{name}.git\"\n\
             rev = \"0123456789abcdef0123456789abcdef01234567\"\n\
             hash = \"sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n"
        )
    }

    #[test]
    fn roundtrip_and_sorted_output() {
        let mut lock = Lockfile::default();
        lock.upsert(entry("zeta", "0.1"));
        lock.upsert(entry("alpha", "0.1"));

        let text = lock.to_toml();
        let alpha = text.find("name = \"alpha\"").expect("alpha");
        let zeta = text.find("name = \"zeta\"").expect("zeta");
        assert!(alpha < zeta, "output must be sorted:\n{text}");
        assert!(text.ends_with('\n'), "trailing newline:\n{text:?}");

        let parsed = Lockfile::parse(&text).expect("round trip");
        assert_eq!(parsed, lock);
        assert_eq!(parsed.to_toml(), text, "output is byte-stable");
    }

    #[test]
    fn rejects_unknown_key() {
        let err = Lockfile::parse(&lock_text("bogus = 1\n")).expect_err("unknown key");
        assert!(
            err.message().contains("bogus"),
            "names the key: {}",
            err.message()
        );
    }

    #[test]
    fn rejects_unknown_key_in_entry() {
        let text = lock_text(&format!("{}bogus = 1\n", https_entry("alpha")));
        let err = Lockfile::parse(&text).expect_err("unknown entry key");
        assert!(
            err.message().contains("bogus"),
            "names the key: {}",
            err.message()
        );
    }

    #[test]
    fn rejects_unknown_lock_version() {
        let err = Lockfile::parse("lock_version = 2\n").expect_err("version 2");
        assert!(err.message().contains("lock_version"), "{}", err.message());
        assert!(err.message().contains('2'), "{}", err.message());
    }

    #[test]
    fn rejects_duplicate_entry() {
        let text = lock_text(&format!("{}{}", https_entry("alpha"), https_entry("alpha")));
        let err = Lockfile::parse(&text).expect_err("duplicate");
        assert!(err.message().contains("alpha@0.1"), "{}", err.message());
    }

    #[test]
    fn rejects_http_source() {
        let text = lock_text(
            "[[pack]]\nname = \"alpha\"\nversion = \"0.1\"\n\
             source = \"http://example.invalid/pack.git\"\n\
             rev = \"0123456789abcdef0123456789abcdef01234567\"\n\
             hash = \"sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n",
        );
        let err = Lockfile::parse(&text).expect_err("http");
        assert!(err.message().contains("http://"), "{}", err.message());
    }

    #[test]
    fn rejects_ssh_source() {
        let text = lock_text(
            "[[pack]]\nname = \"alpha\"\nversion = \"0.1\"\n\
             source = \"ssh://git@example.invalid/pack.git\"\n\
             rev = \"0123456789abcdef0123456789abcdef01234567\"\n\
             hash = \"sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n",
        );
        assert!(Lockfile::parse(&text).is_err(), "ssh must be refused");
    }

    #[test]
    fn rejects_file_source() {
        let text = lock_text(
            "[[pack]]\nname = \"alpha\"\nversion = \"0.1\"\n\
             source = \"file:///tmp/pack\"\n\
             rev = \"\"\n\
             hash = \"sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n",
        );
        assert!(Lockfile::parse(&text).is_err(), "file:// must be refused");
    }

    #[test]
    fn accepts_dir_source_with_empty_rev() {
        let text = lock_text(
            "[[pack]]\nname = \"alpha\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\n\
             hash = \"sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n",
        );
        let lock = Lockfile::parse(&text).expect("dir source is valid");
        assert_eq!(lock.packs.len(), 1);
        assert_eq!(lock.packs[0].subdir, "", "subdir defaults to empty");
    }

    #[test]
    fn rejects_short_rev() {
        let text = lock_text(
            "[[pack]]\nname = \"alpha\"\nversion = \"0.1\"\n\
             source = \"https://example.invalid/pack.git\"\nrev = \"0123456789abcdef\"\n\
             hash = \"sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n",
        );
        let err = Lockfile::parse(&text).expect_err("short rev");
        assert!(err.message().contains("rev"), "{}", err.message());
    }

    #[test]
    fn rejects_uppercase_rev() {
        let text = lock_text(
            "[[pack]]\nname = \"alpha\"\nversion = \"0.1\"\n\
             source = \"https://example.invalid/pack.git\"\n\
             rev = \"0123456789ABCDEF0123456789abcdef01234567\"\n\
             hash = \"sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n",
        );
        assert!(
            Lockfile::parse(&text).is_err(),
            "uppercase rev must be refused"
        );
    }

    #[test]
    fn rejects_missing_rev_for_https() {
        let text = lock_text(
            "[[pack]]\nname = \"alpha\"\nversion = \"0.1\"\n\
             source = \"https://example.invalid/pack.git\"\nrev = \"\"\n\
             hash = \"sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n",
        );
        let err = Lockfile::parse(&text).expect_err("empty rev for https");
        assert!(err.message().contains("rev"), "{}", err.message());
    }

    #[test]
    fn rejects_bad_hash_prefix() {
        let text = lock_text(
            "[[pack]]\nname = \"alpha\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\n\
             hash = \"md5:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n",
        );
        let err = Lockfile::parse(&text).expect_err("md5");
        assert!(err.message().contains("hash"), "{}", err.message());
    }

    #[test]
    fn rejects_short_hash() {
        let text = lock_text(
            "[[pack]]\nname = \"alpha\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\n\
             hash = \"sha256:b6340b6f\"\n",
        );
        assert!(
            Lockfile::parse(&text).is_err(),
            "short hash must be refused"
        );
    }

    #[test]
    fn rejects_subdir_with_dotdot() {
        let text = lock_text(
            "[[pack]]\nname = \"alpha\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\n\
             subdir = \"../elsewhere\"\n\
             hash = \"sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n",
        );
        let err = Lockfile::parse(&text).expect_err("..subdir");
        assert!(err.message().contains("subdir"), "{}", err.message());
    }

    #[test]
    fn rejects_absolute_subdir() {
        let text = lock_text(
            "[[pack]]\nname = \"alpha\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\n\
             subdir = \"/etc\"\n\
             hash = \"sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n",
        );
        assert!(
            Lockfile::parse(&text).is_err(),
            "absolute subdir must be refused"
        );
    }

    #[test]
    fn rejects_bad_name() {
        let text = lock_text(
            "[[pack]]\nname = \"Example_Pack\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\n\
             hash = \"sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b\"\n",
        );
        let err = Lockfile::parse(&text).expect_err("bad name");
        assert!(err.message().contains("name"), "{}", err.message());
    }

    #[test]
    fn read_lockfile_missing_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(read_lockfile(dir.path()).expect("read").is_none());
    }

    #[test]
    fn read_lockfile_conflict_markers_is_conflict_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(LOCKFILE_NAME),
            "<<<<<<< HEAD\nlock_version = 1\n=======\nlock_version = 1\n>>>>>>> other\n",
        )
        .expect("write");
        let err = read_lockfile(dir.path()).expect_err("conflict markers");
        assert_eq!(err.code(), "E_CONFLICT");
    }

    #[test]
    fn upsert_replaces_same_name_version() {
        let mut lock = Lockfile::default();
        lock.upsert(entry("alpha", "0.1"));
        let mut changed = entry("alpha", "0.1");
        changed.rev = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        lock.upsert(changed.clone());
        assert_eq!(lock.packs.len(), 1);
        assert_eq!(lock.find("alpha", "0.1"), Some(&changed));
    }

    #[test]
    fn remove_missing_is_noop() {
        let mut lock = Lockfile::default();
        lock.upsert(entry("alpha", "0.1"));
        lock.remove("absent", "0.1");
        assert_eq!(lock.packs.len(), 1);
        lock.remove("alpha", "0.1");
        assert!(lock.packs.is_empty());
    }

    #[test]
    fn bytes_are_the_canonical_toml() {
        let mut lock = Lockfile::default();
        lock.upsert(entry("alpha", "0.1"));
        assert_eq!(lockfile_bytes(&lock), lock.to_toml().as_bytes());
    }
}
