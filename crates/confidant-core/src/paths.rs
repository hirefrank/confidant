// Portions adapted from cr (https://github.com/AnandChowdhary/cr) at f29f8d4,
// MIT License, Copyright (c) 2026 Anand Chowdhary.
//
// Refuse symbolic links, classify directory entries without following them,
// and write atomically via a temporary file plus rename. The Unix openat /
// O_NOFOLLOW walk is replaced with a portable symlink_metadata walk so the
// same crate builds on Linux and macOS (ADR-13).

//! Symlink-safe access to files beneath a vault root.
//!
//! Every file Confidant reads or writes lives beneath one vault root. A path
//! is never handed to the operating system as a single string that might
//! contain `..` or a planted symlink. Each component is checked with
//! `symlink_metadata` before descending. A planted symbolic link is refused
//! rather than followed, whatever it points at.
//!
//! Directory listings still use `read_dir` on the verified path; every name
//! they yield is re-checked before it is read.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::error::DomainError;

/// Names of files this module writes before publishing them under their final
/// name. The prefix keeps them out of collection listings.
const TEMPORARY_PREFIX: &str = ".confidant-tmp-";

/// What a directory entry is, determined without following symbolic links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

impl EntryKind {
    pub fn is_directory(self) -> bool {
        self == Self::Directory
    }

    pub fn is_file(self) -> bool {
        self == Self::File
    }

    pub fn from_metadata(meta: &fs::Metadata) -> Self {
        let ft = meta.file_type();
        if ft.is_symlink() {
            Self::Symlink
        } else if ft.is_dir() {
            Self::Directory
        } else if ft.is_file() {
            Self::File
        } else {
            Self::Other
        }
    }
}

/// One entry of a verified directory.
#[derive(Clone, Debug)]
pub struct DirectoryEntry {
    pub name: String,
    pub kind: EntryKind,
}

fn kind_of(path: &Path) -> Result<EntryKind> {
    let meta =
        fs::symlink_metadata(path).with_context(|| format!("could not stat {}", path.display()))?;
    Ok(EntryKind::from_metadata(&meta))
}

/// Split `relative` into normal components. Rejects absolute paths, parent
/// dirs, and prefixes.
pub fn components(relative: &Path) -> Result<Vec<&std::ffi::OsStr>> {
    if relative.is_absolute() {
        return Err(anyhow!(DomainError::invalid(
            "vault paths must be relative to the vault root",
        )));
    }
    let mut out = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => out.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(anyhow!(DomainError::invalid(
                    "vault paths must not contain '..'",
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(anyhow!(DomainError::invalid(
                    "vault paths must be relative to the vault root",
                )));
            }
        }
    }
    Ok(out)
}

/// Resolve `relative` beneath `root`, refusing to traverse a symbolic link
/// at any depth. The final component may be missing when `must_exist` is false.
pub fn resolve(root: &Path, relative: &Path, must_exist: bool) -> Result<PathBuf> {
    let mut current = root.to_path_buf();
    let parts = components(relative)?;
    if parts.is_empty() {
        let kind = kind_of(&current)?;
        if kind == EntryKind::Symlink {
            return Err(symlink_error("vault root"));
        }
        return Ok(current);
    }
    for (i, name) in parts.iter().enumerate() {
        current.push(name);
        let last = i + 1 == parts.len();
        match kind_of(&current) {
            Ok(EntryKind::Symlink) => {
                return Err(symlink_error(&current.display().to_string()));
            }
            Ok(EntryKind::Other) => {
                return Err(anyhow!(DomainError::conflict(format!(
                    "vault path '{}' is not a regular file or directory",
                    display_name(name)
                ))));
            }
            Ok(EntryKind::Directory) => {}
            Ok(EntryKind::File) => {
                if !last {
                    return Err(anyhow!(DomainError::conflict(format!(
                        "vault path '{}' is a file, not a directory",
                        display_name(name)
                    ))));
                }
            }
            Err(error) => {
                if last && !must_exist && crate::error::is_missing(&error) {
                    return Ok(current);
                }
                return Err(error);
            }
        }
    }
    Ok(current)
}

fn display_name(name: &std::ffi::OsStr) -> String {
    name.to_string_lossy().into_owned()
}

fn symlink_error(label: &str) -> anyhow::Error {
    anyhow!(DomainError::conflict(format!(
        "refusing to follow a symbolic link ({label})"
    )))
}

/// Read a UTF-8 file beneath `root` without following symlinks.
pub fn read_to_string(root: &Path, relative: &Path) -> Result<String> {
    let path = resolve(root, relative, true)?;
    let kind = kind_of(&path)?;
    if kind != EntryKind::File {
        return Err(anyhow!(DomainError::conflict(format!(
            "'{}' is not a regular file",
            relative.display()
        ))));
    }
    let mut file =
        File::open(&path).with_context(|| format!("could not open {}", relative.display()))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .with_context(|| format!("could not read {}", relative.display()))?;
    String::from_utf8(buf).map_err(|_| {
        anyhow!(DomainError::invalid(format!(
            "'{}' is not valid UTF-8",
            relative.display()
        )))
    })
}

/// List a directory beneath `root` without following the directory itself or
/// classifying children by following them.
pub fn read_dir(root: &Path, relative: &Path) -> Result<Vec<DirectoryEntry>> {
    let path = if relative.as_os_str().is_empty() {
        let kind = kind_of(root)?;
        if kind == EntryKind::Symlink {
            return Err(symlink_error("vault root"));
        }
        root.to_path_buf()
    } else {
        resolve(root, relative, true)?
    };
    let kind = kind_of(&path)?;
    if kind != EntryKind::Directory {
        return Err(anyhow!(DomainError::conflict(format!(
            "'{}' is not a directory",
            relative.display()
        ))));
    }
    let mut entries = Vec::new();
    for ent in
        fs::read_dir(&path).with_context(|| format!("could not list {}", relative.display()))?
    {
        let ent = ent?;
        let name = ent.file_name();
        let Some(name) = name.to_str().map(ToOwned::to_owned) else {
            return Err(anyhow!(DomainError::conflict(format!(
                "directory '{}' contains a non-UTF-8 name",
                relative.display()
            ))));
        };
        let child = ent.path();
        let meta =
            fs::symlink_metadata(&child).with_context(|| format!("could not stat {name}"))?;
        entries.push(DirectoryEntry {
            name,
            kind: EntryKind::from_metadata(&meta),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Write `contents` to `relative` beneath `root`, replacing any existing file
/// atomically: the bytes are written to a sibling temporary file and published
/// with `rename`. A crash during the write cannot leave a half-written file
/// at the destination (crash-safe pattern, ADR-13).
pub fn write_replace(root: &Path, relative: &Path, contents: &[u8]) -> Result<()> {
    let dest = writable_dest(root, relative)?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create parent of {}", relative.display()))?;
    }
    let mut tmp_name = dest
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "file".into());
    let mut prefixed = std::ffi::OsString::from(TEMPORARY_PREFIX);
    prefixed.push(&tmp_name);
    tmp_name = prefixed;
    let tmp_path = dest.with_file_name(tmp_name);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .with_context(|| format!("could not create temporary file for {}", relative.display()))?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .with_context(|| format!("could not write {}", relative.display()))?;
    drop(file);
    fs::rename(&tmp_path, &dest)
        .with_context(|| format!("could not publish {}", relative.display()))?;
    Ok(())
}

/// Build a destination path, refusing any symlink on the existing prefix.
fn writable_dest(root: &Path, relative: &Path) -> Result<PathBuf> {
    let parts = components(relative)?;
    if parts.is_empty() {
        return Err(anyhow!(DomainError::invalid("cannot write the vault root")));
    }
    let root_kind = kind_of(root)?;
    if root_kind == EntryKind::Symlink {
        return Err(symlink_error("vault root"));
    }
    let mut current = root.to_path_buf();
    for (i, name) in parts.iter().enumerate() {
        current.push(name);
        let last = i + 1 == parts.len();
        match kind_of(&current) {
            Ok(EntryKind::Symlink) => return Err(symlink_error(&display_name(name))),
            Ok(EntryKind::Directory) if !last => {}
            Ok(EntryKind::File) if last => {}
            Ok(EntryKind::Directory) if last => {
                return Err(anyhow!(DomainError::conflict(format!(
                    "'{}' is a directory",
                    relative.display()
                ))));
            }
            Ok(_) => {
                return Err(anyhow!(DomainError::conflict(format!(
                    "vault path '{}' is not a regular file or directory",
                    display_name(name)
                ))));
            }
            Err(error) if crate::error::is_missing(&error) => break,
            Err(error) => return Err(error),
        }
    }
    let mut dest = root.to_path_buf();
    for name in parts {
        dest.push(name);
    }
    Ok(dest)
}

/// POSIX-style relative path string for findings (`people/p-…/profile.md`).
pub fn display_relative(relative: &Path) -> String {
    relative
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => n.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Names that collection walks skip (dotfiles, gitkeep).
pub fn is_skipped_name(name: &str) -> bool {
    name.starts_with('.') || name == "README.md"
}

#[cfg(test)]
mod tests {
    use super::{components, read_dir, read_to_string, resolve, write_replace, EntryKind};
    use std::fs;
    use std::path::Path;

    #[test]
    fn rejects_parent_components() {
        let err = components(Path::new("people/../secret")).unwrap_err();
        assert!(err.to_string().contains(".."), "{err}");
    }

    #[test]
    fn write_replace_is_readable() {
        let dir = tempfile::tempdir().unwrap();
        write_replace(dir.path(), Path::new("a/b.txt"), b"hello").unwrap();
        assert_eq!(
            read_to_string(dir.path(), Path::new("a/b.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn refuses_symlink_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        fs::write(&target, "secret").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = resolve(dir.path(), Path::new("link.txt"), true).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
    }

    #[test]
    fn lists_without_following() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("ok.txt"), "x").unwrap();
        std::os::unix::fs::symlink("ok.txt", dir.path().join("s")).unwrap();
        let entries = read_dir(dir.path(), Path::new("")).unwrap();
        let kinds: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.kind)).collect();
        assert!(kinds.contains(&("ok.txt", EntryKind::File)));
        assert!(kinds.contains(&("s", EntryKind::Symlink)));
    }
}
