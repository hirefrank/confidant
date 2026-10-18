//! `confidant.lock` reader and writer (#437, spec/pack-lock.md).
//!
//! The lockfile pins exactly which bytes an external pack resolves to.
//! It is committed to the vault, plaintext, and holds no private data.
//! `pack add --yes` / `pack update` (#440) write it; `check` (#438) only
//! reads it. This module is pure format code: no network, no git, no
//! filesystem outside [`read_lockfile`].
//!
//! Canonical form: entries sorted by `(name, version)`, keys always in
//! the order `name, version, source, rev, subdir, hash`, trailing
//! newline. Writing is byte-stable for the same content; parse
//! normalizes by sorting, so `parse(to_toml(x)) == parse(x)` for every
//! valid input.

use std::path::Path;

use serde::Deserialize;

use crate::error::DomainError;
use crate::packs::manifest::is_valid_pack_name;
use crate::record::has_conflict_markers;

/// The only lockfile format version this loader implements (PD5).
const LOCK_VERSION: u8 = 1;

/// Whether `id` is a `name@version` pin that may join an agent-readable
/// finding message (the #490 echo carve-out).
///
/// Stricter than the lockfile's own version rule (non-empty, no surrounding
/// whitespace): that rule alone would pass operator free text such as
/// `ada@example.com` straight into `E_PACK_UNKNOWN` (#501). A pin must have
/// a valid pack name and a version that *looks* like a version: an ASCII
/// digit first byte, then only `[0-9A-Za-z.+-]`. A non-version-like version
/// (`nightly`) fails closed to the name-free message; that only costs
/// detail, never leaks.
pub(crate) fn is_valid_pack_pin(id: &str) -> bool {
    match id.split_once('@') {
        Some((name, version)) => is_valid_pack_name(name) && is_version_like(version),
        None => false,
    }
}

/// A version that can safely join a message: an ASCII digit first byte, then
/// `[0-9A-Za-z.+-]`, at most 64 bytes.
fn is_version_like(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version.as_bytes()[0].is_ascii_digit()
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// One pinned pack: `name@version` resolved to `source` at `rev`,
/// vendored under `packs/<name>@<version>/` with the canonical tree hash
/// `hash` (PD5, PD6).
#[derive(Clone, Debug, PartialEq)]
pub struct LockEntry {
    /// Pack name (PD14 grammar, `^[a-z][a-z0-9-]{1,31}$`).
    pub name: String,
    /// The pack's own version string.
    pub version: String,
    /// `https://` git URL, or the literal `"dir"` for `--from-dir`
    /// installs (PD3: no other scheme).
    pub source: String,
    /// Full 40-hex lowercase commit the source resolved to, or empty for
    /// `"dir"` sources, which have no commit.
    pub rev: String,
    /// Optional relative path inside the source repo; empty means the
    /// repo root.
    pub subdir: String,
    /// Canonical tree hash of the vendored directory: `sha256:` plus 64
    /// lowercase hex (PD6).
    pub hash: String,
}

impl LockEntry {
    /// The `name@version` id used by `confidant.toml` `packs = [...]`.
    pub fn id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    /// Validate the entry's fields (PD5). Writers (#440) call this
    /// before serializing, so a lockfile this module writes is always
    /// one its own reader accepts; `upsert`/`to_bytes` stay infallible.
    pub fn validate(&self) -> Result<(), DomainError> {
        let toml = LockEntryToml {
            name: self.name.clone(),
            version: self.version.clone(),
            source: self.source.clone(),
            rev: self.rev.clone(),
            subdir: self.subdir.clone(),
            hash: self.hash.clone(),
        };
        toml.validate(0).map(|_| ())
    }
}

/// The parsed `confidant.lock`, always in canonical (sorted) order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Lockfile {
    pub packs: Vec<LockEntry>,
}

impl Lockfile {
    /// Parse and validate lockfile text.
    ///
    /// Unknown keys, an unsupported `lock_version`, an invalid entry, or
    /// a duplicate `(name, version)` is an error naming the offending
    /// entry and key, with a fix. Entries are normalized to the
    /// canonical sort on read.
    pub fn parse(text: &str) -> Result<Lockfile, DomainError> {
        if has_conflict_markers(text) {
            return Err(DomainError::conflict(
                "confidant.lock contains unresolved conflict markers",
            )
            .with_file("confidant.lock")
            .with_fix(
                "Resolve the conflict markers (keep the pins you intend), then re-run the command",
            ));
        }
        let raw: LockToml = toml::from_str(text).map_err(|err| {
            lockfile_err(format!("confidant.lock is not valid TOML: {err}")).with_fix(
                "Keep `lock_version = 1` and one `[[pack]]` table per pinned pack (see spec/pack-lock.md)",
            )
        })?;
        if raw.lock_version != LOCK_VERSION {
            return Err(lockfile_err(format!(
                "confidant.lock lock_version {lock_version} is not supported (this loader implements {LOCK_VERSION})",
                lock_version = raw.lock_version
            ))
            .with_fix("Rewrite the lockfile with lock_version = 1, or upgrade the CLI"));
        }
        let mut packs: Vec<LockEntry> = Vec::with_capacity(raw.pack.len());
        for (index, entry) in raw.pack.into_iter().enumerate() {
            let entry = entry.validate(index)?;
            if packs
                .iter()
                .any(|p| p.name == entry.name && p.version == entry.version)
            {
                return Err(lockfile_err(format!(
                    "confidant.lock pins {}@{} more than once; entries must be unique",
                    entry.name, entry.version
                ))
                .with_fix("Remove the repeated `[[pack]]` entry"));
            }
            packs.push(entry);
        }
        packs.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        Ok(Lockfile { packs })
    }

    /// The canonical TOML serialization: `lock_version = 1`, then one
    /// `[[pack]]` table per entry in stored (sorted) order, fixed key
    /// order, trailing newline. Byte-stable for the same lockfile.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("lock_version = {LOCK_VERSION}\n"));
        for p in &self.packs {
            out.push_str("\n[[pack]]\n");
            out.push_str(&format!("name = {}\n", toml_str(&p.name)));
            out.push_str(&format!("version = {}\n", toml_str(&p.version)));
            out.push_str(&format!("source = {}\n", toml_str(&p.source)));
            out.push_str(&format!("rev = {}\n", toml_str(&p.rev)));
            out.push_str(&format!("subdir = {}\n", toml_str(&p.subdir)));
            out.push_str(&format!("hash = {}\n", toml_str(&p.hash)));
        }
        out
    }

    /// The canonical bytes (UTF-8 of [`Lockfile::to_toml`]) for the
    /// commit path (#440): the caller writes them; this module does not
    /// touch the filesystem.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_toml().into_bytes()
    }

    /// Find the entry for `name@version`.
    pub fn find(&self, name: &str, version: &str) -> Option<&LockEntry> {
        self.packs
            .iter()
            .find(|p| p.name == name && p.version == version)
    }

    /// Insert or replace the entry for `name@version`, keeping the
    /// canonical sort.
    pub fn upsert(&mut self, entry: LockEntry) {
        self.remove(&entry.name, &entry.version);
        self.packs.push(entry);
        self.packs
            .sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    }

    /// Remove the entry for `name@version`. Missing is a no-op.
    pub fn remove(&mut self, name: &str, version: &str) {
        self.packs
            .retain(|p| !(p.name == name && p.version == version));
    }
}

/// Read `<vault>/confidant.lock`. Missing file is `Ok(None)` (nothing
/// external installed); conflict markers in the file are a conflict
/// error, not a parse error. A read that fails for any other reason
/// (permissions, I/O) fails closed rather than pretending the lock is
/// absent. Nothing is ever written here.
pub fn read_lockfile(vault_root: &Path) -> Result<Option<Lockfile>, DomainError> {
    let path = vault_root.join("confidant.lock");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(
                lockfile_err(format!("cannot read {}: {err}", path.display()))
                    .with_fix("Check the file's permissions, then re-run"),
            )
        }
    };
    let text = String::from_utf8(bytes).map_err(|_| {
        lockfile_err("confidant.lock is not valid UTF-8").with_fix("Rewrite the file as UTF-8 TOML")
    })?;
    Lockfile::parse(&text).map(Some)
}

fn lockfile_err(message: impl Into<String>) -> DomainError {
    DomainError::config(message).with_file("confidant.lock")
}

/// One TOML basic string, quoted by the `toml` crate's own rules so any
/// character the grammar lets through survives the round trip.
fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

/// The TOML wire shape. Kept private; the validated form is
/// [`LockEntry`] / [`Lockfile`], and every field is checked there.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockToml {
    lock_version: u8,
    #[serde(default)]
    pack: Vec<LockEntryToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockEntryToml {
    name: String,
    version: String,
    source: String,
    rev: String,
    #[serde(default)]
    subdir: String,
    hash: String,
}

/// PD5 validation of one entry, returning the checked entry. `index` is
/// only for error messages (`pack[2]`).
impl LockEntryToml {
    fn validate(self, index: usize) -> Result<LockEntry, DomainError> {
        let entry_name = format!("pack[{index}] name '{}'", self.name);
        let label = |detail: String| lockfile_err(format!("confidant.lock {entry_name}: {detail}"));
        // The grammar check covers emptiness and whitespace (PD14).
        if !is_valid_pack_name(&self.name) {
            return Err(label(format!(
                "name '{}' is not a valid pack name (must match ^[a-z][a-z0-9-]{{1,31}}$)",
                self.name
            ))
            .with_fix("Use the pack's declared [pack].name from its manifest.toml"));
        }
        if self.version.trim() != self.version || self.version.is_empty() {
            return Err(label(
                "version must be a non-empty version without surrounding whitespace".to_owned(),
            )
            .with_fix("Use the pack's declared version, e.g. version = \"0.1\""));
        }

        let is_dir_source = self.source == "dir";
        let is_https = self.source.starts_with("https://");
        if !is_dir_source && !is_https {
            return Err(label(format!(
                "source '{}' is not allowed; use an https:// git URL or \"dir\"",
                self.source
            ))
            .with_fix(
                "Pin the https:// source the pack was installed from, or \"dir\" for --from-dir",
            ));
        }
        if is_https && url_has_userinfo(&self.source) {
            // `https://user:token@host/...` would commit credentials to
            // the vault (spec §1: plaintext, no private data).
            return Err(
                label("source must not embed credentials (user:token@host)".to_owned())
                    .with_fix("Use a credential-free https URL; git supplies credentials itself"),
            );
        }

        if is_dir_source {
            // A "dir" install vendors the directory as-is: there is no
            // commit to pin and no repo to descend into.
            if !self.rev.is_empty() {
                return Err(label("rev must be empty for source \"dir\"".to_owned())
                    .with_fix("Set rev = \"\" for --from-dir installs"));
            }
            if !self.subdir.is_empty() {
                return Err(label("subdir must be empty for source \"dir\"".to_owned())
                    .with_fix("Remove subdir from the entry"));
            }
        } else {
            if !is_full_commit(&self.rev) {
                return Err(label(format!(
                    "rev '{}' is not a full 40-hex lowercase commit",
                    self.rev
                ))
                .with_fix("Pin the full commit id the source resolved to at install time"));
            }
            if let Some(problem) = subdir_problem(&self.subdir) {
                return Err(label(format!(
                    "subdir '{}' is not a safe relative path: {problem}",
                    self.subdir
                )).with_fix("Use a relative path inside the source repo, or remove subdir for the repo root"));
            }
        }

        let Some(hash) = self.hash.strip_prefix("sha256:") else {
            return Err(
                label(format!("hash '{}' must start with 'sha256:'", self.hash)).with_fix(
                    "Write the canonical tree hash from spec/pack-lock.md §3 as sha256:<hex>",
                ),
            );
        };
        if !is_sha256_hex(hash) {
            return Err(label(
                "hash must be 'sha256:' plus exactly 64 lowercase hex characters".to_owned(),
            )
            .with_fix("Recompute the hash per spec/pack-lock.md §3"));
        }

        Ok(LockEntry {
            name: self.name,
            version: self.version,
            source: self.source,
            rev: self.rev,
            subdir: self.subdir,
            hash: self.hash,
        })
    }
}

/// Is `s` exactly 40 lowercase hex characters (a git commit id)?
fn is_full_commit(rev: &str) -> bool {
    rev.len() == 40
        && rev
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Is `s` exactly 64 lowercase hex characters?
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Does the URL carry userinfo (`https://user:token@host/…`)? The
/// authority part runs from after the scheme to the first `/`.
fn url_has_userinfo(source: &str) -> bool {
    let after_scheme = source.strip_prefix("https://").unwrap_or(source);
    match after_scheme.find('/') {
        Some(end) => after_scheme[..end].contains('@'),
        None => after_scheme.contains('@'),
    }
}

/// Why `subdir` is not a safe relative path inside the source repo.
/// Absolute, `.`/`..`, and empty segments are refused; the repo-root
/// form is the empty string, which never reaches this check.
fn subdir_problem(subdir: &str) -> Option<&'static str> {
    if subdir.is_empty() {
        // The repo root is the empty string, and it is valid.
        return None;
    }
    if subdir.starts_with('/') {
        return Some("it is absolute");
    }
    // Windows is a target: a `\` or a drive/colon prefix must never be
    // interpreted as a separator or device when #440 joins paths, and
    // control characters (incl. NUL) have no business in a path.
    if subdir.contains('\\') {
        return Some("it contains a backslash; use '/' separators");
    }
    if subdir.contains(':') {
        return Some("it contains a ':' (Windows drive/colon prefix)");
    }
    if subdir.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Some("it contains control characters");
    }
    if subdir.split('/').any(|c| matches!(c, "." | ".." | "")) {
        return Some("every segment must be a real directory name (no '.'/'..', no empty segments, no trailing slash)");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const REV: &str = "0123456789abcdef0123456789abcdef01234567";
    const HASH: &str = "sha256:b6340b6f41afedd67ba862df4eaf51eb82262aa1d24f90accbc0b6c4c0a08b4b";

    fn https_entry(name: &str, version: &str) -> LockEntry {
        LockEntry {
            name: name.to_owned(),
            version: version.to_owned(),
            source: "https://example.invalid/org/example-pack.git".to_owned(),
            rev: REV.to_owned(),
            subdir: "".to_owned(),
            hash: HASH.to_owned(),
        }
    }

    /// One-entry lockfile text with the given entry fields substituted.
    fn one_entry_text(source: &str, rev: &str, subdir: &str, hash: &str) -> String {
        format!(
            "lock_version = 1\n\n[[pack]]\nname = \"example-pack\"\nversion = \"0.1\"\nsource = {source}\nrev = {rev}\nsubdir = {subdir}\nhash = {hash}\n"
        )
    }

    fn parse_ok(text: &str) -> Lockfile {
        Lockfile::parse(text).unwrap_or_else(|err| panic!("lockfile should parse: {err}"))
    }

    fn parse_err(text: &str) -> String {
        let err = Lockfile::parse(text).expect_err("should be an error");
        format!("{err}")
    }

    #[test]
    fn roundtrip_and_sorted_output() {
        let mut lf = Lockfile::default();
        lf.upsert(https_entry("zeta-pack", "0.2"));
        lf.upsert(https_entry("alpha-pack", "0.1"));
        let toml = lf.to_toml();
        let alpha = toml
            .find("name = \"alpha-pack\"")
            .expect("alpha entry present");
        let zeta = toml
            .find("name = \"zeta-pack\"")
            .expect("zeta entry present");
        assert!(alpha < zeta, "alpha must be written first:\n{toml}");

        // Byte-stable write, and roundtrip preserves the lockfile.
        assert_eq!(toml, parse_ok(&toml).to_toml());
        assert_eq!(lf, parse_ok(&toml));
    }

    #[test]
    fn rejects_unknown_key() {
        let mut text = one_entry_text(
            "\"https://example.invalid/o/p.git\"",
            &format!("\"{REV}\""),
            "\"\"",
            &format!("\"{HASH}\""),
        );
        text.push_str("extra = 1\n");
        assert!(
            parse_err(&text).contains("unknown field"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_unknown_lock_version() {
        assert!(parse_err("lock_version = 2\n").contains("not supported"));
        // Not even a rewrite fixes an unrepresentable version: out of
        // range is a TOML error, into the invalid-text lane.
        assert!(!parse_err("lock_version = 999\n").contains("not supported"));
    }

    #[test]
    fn rejects_duplicate_entry() {
        let mut lf = Lockfile::default();
        lf.upsert(https_entry("example-pack", "0.1"));
        let text = lf.to_toml();
        let doubled = format!(
            "{text}\n[[pack]]\nname = \"example-pack\"\nversion = \"0.1\"\nsource = \"https://example.invalid/org/example-pack.git\"\nrev = \"{REV}\"\nsubdir = \"\"\nhash = \"{HASH}\"\n"
        );
        assert!(
            parse_err(&doubled).contains("more than once"),
            "{err}",
            err = parse_err(&doubled)
        );
    }

    #[test]
    fn rejects_http_source() {
        let text = one_entry_text(
            "\"http://example.invalid/o/p.git\"",
            &format!("\"{REV}\""),
            "\"\"",
            &format!("\"{HASH}\""),
        );
        assert!(
            parse_err(&text).contains("not allowed"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_ssh_and_file_sources() {
        for source in ["ssh://example.invalid/o/p.git", "file:///tmp/pack"] {
            let text = one_entry_text(
                &format!("\"{source}\""),
                &format!("\"{REV}\""),
                "\"\"",
                &format!("\"{HASH}\""),
            );
            assert!(
                parse_err(&text).contains("not allowed"),
                "{source}: {err}",
                err = parse_err(&text)
            );
        }
    }

    #[test]
    fn accepts_dir_source_with_empty_rev() {
        let text = one_entry_text("\"dir\"", "\"\"", "\"\"", &format!("\"{HASH}\""));
        let lf = parse_ok(&text);
        assert_eq!(lf.packs[0].source, "dir");
        assert_eq!(lf.packs[0].rev, "");
    }

    #[test]
    fn rejects_rev_for_dir_source() {
        let text = one_entry_text(
            "\"dir\"",
            &format!("\"{REV}\""),
            "\"\"",
            &format!("\"{HASH}\""),
        );
        assert!(
            parse_err(&text).contains("rev must be empty"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_subdir_for_dir_source() {
        let text = one_entry_text("\"dir\"", "\"\"", "\"inner\"", &format!("\"{HASH}\""));
        assert!(
            parse_err(&text).contains("subdir must be empty"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_short_rev() {
        let text = one_entry_text(
            "\"https://example.invalid/o/p.git\"",
            "\"0123456789abcdef\"",
            "\"\"",
            &format!("\"{HASH}\""),
        );
        assert!(
            parse_err(&text).contains("40-hex"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_uppercase_rev() {
        let text = one_entry_text(
            "\"https://example.invalid/o/p.git\"",
            "\"0123456789ABCDEF0123456789ABCDEF01234567\"",
            "\"\"",
            &format!("\"{HASH}\""),
        );
        assert!(
            parse_err(&text).contains("40-hex"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_missing_rev_for_https() {
        let text = one_entry_text(
            "\"https://example.invalid/o/p.git\"",
            "\"\"",
            "\"\"",
            &format!("\"{HASH}\""),
        );
        assert!(
            parse_err(&text).contains("40-hex"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_bad_hash_prefix() {
        let text = one_entry_text(
            "\"https://example.invalid/o/p.git\"",
            &format!("\"{REV}\""),
            "\"\"",
            &format!("\"md5:{}\"", "0".repeat(64)),
        );
        assert!(
            parse_err(&text).contains("must start with 'sha256:'"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_short_hash() {
        let text = one_entry_text(
            "\"https://example.invalid/o/p.git\"",
            &format!("\"{REV}\""),
            "\"\"",
            "\"sha256:012a\"",
        );
        assert!(
            parse_err(&text).contains("64 lowercase hex"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_subdir_with_dotdot() {
        let text = one_entry_text(
            "\"https://example.invalid/o/p.git\"",
            &format!("\"{REV}\""),
            "\"../packs\"",
            &format!("\"{HASH}\""),
        );
        assert!(
            parse_err(&text).contains("not a safe relative path"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_absolute_subdir() {
        let text = one_entry_text(
            "\"https://example.invalid/o/p.git\"",
            &format!("\"{REV}\""),
            "\"/etc\"",
            &format!("\"{HASH}\""),
        );
        assert!(
            parse_err(&text).contains("it is absolute"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn accepts_declared_subdir() {
        let text = one_entry_text(
            "\"https://example.invalid/o/p.git\"",
            &format!("\"{REV}\""),
            "\"packs/example\"",
            &format!("\"{HASH}\""),
        );
        let lf = parse_ok(&text);
        assert_eq!(lf.packs[0].subdir, "packs/example");
    }

    #[test]
    fn rejects_invalid_name() {
        let text = one_entry_text("\"dir\"", "\"\"", "\"\"", &format!("\"{HASH}\""))
            .replace("name = \"example-pack\"", "name = \"Bad Name\"");
        assert!(
            parse_err(&text).contains("valid pack name"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_empty_version() {
        let text = one_entry_text("\"dir\"", "\"\"", "\"\"", &format!("\"{HASH}\""))
            .replace("version = \"0.1\"", "version = \"\"");
        assert!(
            parse_err(&text).contains("version"),
            "{err}",
            err = parse_err(&text)
        );
    }

    #[test]
    fn rejects_conflict_markers() {
        assert!(parse_err("lock_version = 1\n<<<<<<< HEAD\n").contains("conflict markers"));
    }

    #[test]
    fn upsert_replaces_same_name_version() {
        let mut lf = Lockfile::default();
        lf.upsert(https_entry("example-pack", "0.1"));
        lf.upsert(https_entry("other-pack", "9.9"));
        let mut changed = https_entry("example-pack", "0.1");
        changed.hash = "sha256:aaaa".to_owned();
        lf.upsert(changed.clone());
        assert_eq!(lf.packs.len(), 2);
        assert_eq!(lf.find("example-pack", "0.1"), Some(&changed));
    }

    #[test]
    fn remove_missing_is_noop() {
        let mut lf = Lockfile::default();
        lf.upsert(https_entry("example-pack", "0.1"));
        lf.remove("nope-pack", "9.9");
        assert_eq!(lf.packs.len(), 1);
        lf.remove("example-pack", "0.1");
        assert!(lf.packs.is_empty());
    }

    #[test]
    fn find_matches_name_and_version() {
        let mut lf = Lockfile::default();
        lf.upsert(https_entry("example-pack", "0.1"));
        lf.upsert(https_entry("example-pack", "0.2"));
        assert!(lf.find("example-pack", "0.2").is_some());
        assert!(lf.find("example-pack", "3.0").is_none());
        assert!(lf.find("nope", "0.1").is_none());
    }

    #[test]
    fn entry_id_is_name_at_version() {
        assert_eq!(https_entry("example-pack", "0.1").id(), "example-pack@0.1");
    }

    #[test]
    fn toml_string_escaping() {
        let mut e = https_entry("example-pack", "0.1-with\"quote");
        e.subdir = "a/b".to_owned();
        let mut lf = Lockfile::default();
        lf.upsert(e.clone());
        let toml = lf.to_toml();
        // The `toml` crate may pick a basic or a literal string; either
        // way the value must survive byte for byte in both directions.
        assert_eq!(parse_ok(&toml).packs[0], e);
        assert_eq!(toml, parse_ok(&toml).to_toml());
    }

    #[test]
    fn read_lockfile_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_lockfile(dir.path()).unwrap(), None);
    }

    #[test]
    fn read_lockfile_conflict_markers_is_conflict_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.lock"),
            "lock_version = 1\n<<<<<<< HEAD\n=======\n>>>>>>> other\n",
        )
        .unwrap();
        let err = read_lockfile(dir.path()).expect_err("must refuse");
        assert!(format!("{err}").contains("conflict markers"), "{err}");
    }

    #[test]
    fn read_lockfile_parses() {
        let dir = tempfile::tempdir().unwrap();
        let mut lf = Lockfile::default();
        lf.upsert(https_entry("example-pack", "0.1"));
        std::fs::write(dir.path().join("confidant.lock"), lf.to_toml()).unwrap();
        assert_eq!(read_lockfile(dir.path()).unwrap(), Some(lf));
    }

    #[test]
    fn rejects_source_with_userinfo() {
        let text = one_entry_text(
            "\"https://user:token@example.invalid/o/p.git\"",
            &format!("\"{REV}\""),
            "\"\"",
            &format!("\"{HASH}\""),
        );
        let err = Lockfile::parse(&text).expect_err("credentials must be refused");
        assert!(
            format!("{err}").contains("must not embed credentials"),
            "{err}"
        );
    }

    #[test]
    fn accepts_credential_free_source_with_at_in_path() {
        // An `@` after the authority (repo path) is fine.
        let text = one_entry_text(
            "\"https://example.invalid/org/p@ack.git\"",
            &format!("\"{REV}\""),
            "\"\"",
            &format!("\"{HASH}\""),
        );
        Lockfile::parse(&text).expect("userinfo check applies to the authority only");
    }

    #[test]
    fn rejects_subdir_with_backslash_or_colon() {
        for bad in ["a\\\\..\\\\..\\\\x", "C:foo"] {
            let text = one_entry_text(
                "\"https://example.invalid/o/p.git\"",
                &format!("\"{REV}\""),
                &format!("\"{bad}\""),
                &format!("\"{HASH}\""),
            );
            let err = Lockfile::parse(&text).expect_err("must refuse");
            let msg = format!("{err}");
            assert!(
                msg.contains("backslash") || msg.contains("':'"),
                "{bad}: {msg}"
            );
        }
    }

    #[test]
    fn rejects_subdir_with_control_chars() {
        let text = one_entry_text(
            "\"https://example.invalid/o/p.git\"",
            &format!("\"{REV}\""),
            "\"a\\u0001b\"",
            &format!("\"{HASH}\""),
        );
        let err = Lockfile::parse(&text).expect_err("must refuse");
        assert!(format!("{err}").contains("control characters"), "{err}");
    }

    #[test]
    fn entry_validate_mirrors_parse_validation() {
        let mut e = https_entry("example-pack", "0.1");
        assert!(e.validate().is_ok());
        e.hash = "sha256:short".to_owned();
        assert!(e.validate().is_err());
        e.hash = HASH.to_owned();
        e.rev = "ZZ".to_owned();
        assert!(e.validate().is_err());
    }

    #[test]
    fn name_whitespace_check_is_covered_by_grammar() {
        // The removed pre-check is subsumed: whitespace fails the grammar.
        let text = one_entry_text("\"dir\"", "\"\"", "\"\"", &format!("\"{HASH}\""))
            .replace("name = \"example-pack\"", "name = \" example-pack\"");
        assert!(Lockfile::parse(&text).is_err());
    }

    #[test]
    fn echoable_pin_is_stricter_than_the_lockfile_rule() {
        // A real pin may echo (#490).
        assert!(is_valid_pack_pin("example-pack@0.1"));
        assert!(is_valid_pack_pin("example-pack@0.2.0-rc.1"));
        // Operator free text the lockfile rule alone would pass: the version
        // half is not version-like (#501).
        assert!(!is_valid_pack_pin("ada@example.com"));
        assert!(!is_valid_pack_pin("example-pack@nightly"));
        assert!(!is_valid_pack_pin("example-pack@0.1\nevil"));
        // Not a pin at all.
        assert!(!is_valid_pack_pin("justaname"));
        assert!(!is_valid_pack_pin("Upper@0.1"));
        assert!(!is_valid_pack_pin("@0.1"));
        assert!(!is_valid_pack_pin("example-pack@"));
    }
}
