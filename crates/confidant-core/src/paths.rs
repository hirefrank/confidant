// Portions adapted from cr (https://github.com/AnandChowdhary/cr) at f29f8d4,
// MIT License, Copyright (c) 2026 Anand Chowdhary.
//
// Refuse symbolic links, classify directory entries without following them,
// and write atomically via a uniquely named temporary file plus rename.
// Unix (including macOS) uses the openat / O_NOFOLLOW walk. The portable
// symlink_metadata walk is compiled only for non-Unix targets (ADR-13).

//! Symlink-safe access to files beneath a vault root.
//!
//! Every file Confidant reads or writes lives beneath one vault root. A path
//! is never handed to the operating system as a single string that might
//! contain `..` or a planted symlink. On Unix each component is opened with
//! `openat` and `O_NOFOLLOW`. Elsewhere each component is checked with
//! `symlink_metadata` before descending.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
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

    pub fn from_metadata(meta: &std::fs::Metadata) -> Self {
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
    pub utf8: bool,
    pub kind: EntryKind,
}

/// Split `relative` into normal components. Rejects absolute paths, parent
/// dirs, and prefixes.
pub fn components(relative: &Path) -> Result<Vec<&OsStr>> {
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

fn split_parent(relative: &Path) -> Result<(&Path, &OsStr)> {
    let names = components(relative)?;
    let name = *names
        .last()
        .ok_or_else(|| anyhow!(DomainError::invalid("cannot write the vault root")))?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    Ok((parent, name))
}

fn refuse_symlink(label: &str) -> anyhow::Error {
    anyhow!(DomainError::conflict(format!(
        "refusing to follow a symbolic link ({label})"
    )))
}

fn refuse_not_regular(label: &str) -> anyhow::Error {
    anyhow!(DomainError::conflict(format!(
        "'{label}' is not a regular file"
    )))
}

fn refuse_not_directory(label: &str) -> anyhow::Error {
    anyhow!(DomainError::conflict(format!(
        "'{label}' is not a directory"
    )))
}

fn io_failure(error: io::Error, label: &str, context: String) -> anyhow::Error {
    anyhow!(error).context(context).context(label.to_string())
}

/// Resolve `relative` beneath `root`, refusing to traverse a symbolic link
/// at any depth. The final component may be missing when `must_exist` is false.
pub fn resolve(root: &Path, relative: &Path, must_exist: bool) -> Result<PathBuf> {
    let parts = components(relative)?;
    if parts.is_empty() {
        let directory = Directory::open_root(root).map_err(|error| {
            io_failure(error, "vault root", "could not open the vault root".into())
        })?;
        return Ok(directory.resolved().to_path_buf());
    }
    let (parent, name) = split_parent(relative)?;
    let directory = if parent.as_os_str().is_empty() {
        Directory::open_root(root).map_err(|error| {
            io_failure(error, "vault root", "could not open the vault root".into())
        })?
    } else {
        open_directory(root, parent)?
    };
    match directory.child_kind(name) {
        Ok(EntryKind::Symlink) => Err(refuse_symlink(&display_name(name))),
        Ok(EntryKind::Other) => Err(anyhow!(DomainError::conflict(format!(
            "vault path '{}' is not a regular file or directory",
            display_name(name)
        )))),
        Ok(_) => Ok(directory.resolved().join(name)),
        Err(error) if !must_exist && error.kind() == io::ErrorKind::NotFound => {
            Ok(directory.resolved().join(name))
        }
        Err(error) => Err(io_failure(
            error,
            &display_name(name),
            format!("could not stat {}", relative.display()),
        )),
    }
}

fn display_name(name: &OsStr) -> String {
    name.to_string_lossy().into_owned()
}

fn open_directory(root: &Path, relative: &Path) -> Result<Directory> {
    let mut directory = Directory::open_root(root)
        .map_err(|error| io_failure(error, "vault root", "could not open the vault root".into()))?;
    for name in components(relative)? {
        directory = match directory.open_child_directory(name) {
            Ok(child) => child,
            Err(error) => {
                return Err(match directory.child_kind(name) {
                    Ok(EntryKind::Symlink) => refuse_symlink(&display_name(name)),
                    Ok(_) => refuse_not_directory(&display_name(name)),
                    Err(_) => io_failure(
                        error,
                        &display_name(name),
                        format!("could not open {}", relative.display()),
                    ),
                });
            }
        };
    }
    Ok(directory)
}

fn create_directory_all(root: &Path, relative: &Path) -> Result<Directory> {
    let mut directory = Directory::open_root(root)
        .map_err(|error| io_failure(error, "vault root", "could not open the vault root".into()))?;
    for name in components(relative)? {
        directory = match directory.open_child_directory(name) {
            Ok(child) => child,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match directory.create_child_directory(name) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(io_failure(
                            error,
                            &display_name(name),
                            format!("could not create {}", relative.display()),
                        ));
                    }
                }
                directory.open_child_directory(name).map_err(|error| {
                    io_failure(
                        error,
                        &display_name(name),
                        format!("could not open {}", relative.display()),
                    )
                })?
            }
            Err(error) => {
                return Err(match directory.child_kind(name) {
                    Ok(EntryKind::Symlink) => refuse_symlink(&display_name(name)),
                    Ok(_) => refuse_not_directory(&display_name(name)),
                    Err(_) => io_failure(
                        error,
                        &display_name(name),
                        format!("could not open {}", relative.display()),
                    ),
                });
            }
        };
    }
    Ok(directory)
}

/// Read a UTF-8 file beneath `root` without following symlinks.
pub fn read_to_string(root: &Path, relative: &Path) -> Result<String> {
    let (parent, name) = split_parent(relative)?;
    let directory = if parent.as_os_str().is_empty() {
        Directory::open_root(root).map_err(|error| {
            io_failure(error, "vault root", "could not open the vault root".into())
        })?
    } else {
        open_directory(root, parent)?
    };
    let mut file = match directory.open_child_file(name) {
        Ok(file) => file,
        Err(error) => {
            return Err(match directory.child_kind(name) {
                Ok(EntryKind::Symlink) => refuse_symlink(&display_name(name)),
                Ok(_) => refuse_not_regular(&relative.display().to_string()),
                Err(_) => io_failure(
                    error,
                    &relative.display().to_string(),
                    format!("could not open {}", relative.display()),
                ),
            });
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect {}", relative.display()))?;
    if !metadata.file_type().is_file() {
        return Err(refuse_not_regular(&relative.display().to_string()));
    }
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
    let directory = if relative.as_os_str().is_empty() {
        Directory::open_root(root).map_err(|error| {
            io_failure(error, "vault root", "could not open the vault root".into())
        })?
    } else {
        open_directory(root, relative)?
    };
    let mut entries = Vec::new();
    for ent in std::fs::read_dir(directory.resolved())
        .with_context(|| format!("could not list {}", relative.display()))?
    {
        let ent = ent?;
        let os_name = ent.file_name();
        let (name, utf8) = match os_name.to_str() {
            Some(s) => (s.to_owned(), true),
            None => (os_name.to_string_lossy().into_owned(), false),
        };
        let kind = directory
            .child_kind(&os_name)
            .with_context(|| format!("could not stat {name}"))?;
        entries.push(DirectoryEntry { name, utf8, kind });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

fn temporary_name() -> OsString {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    if let Ok(dur) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        hasher.write_u128(dur.as_nanos());
    }
    OsString::from(format!("{TEMPORARY_PREFIX}{:016x}", hasher.finish()))
}

/// Write `contents` to `relative` beneath `root`, replacing any existing file
/// atomically: the bytes are written to a sibling temporary file created with
/// `create_new` (no symlink following) and a random suffix, then published
/// with `rename`. The parent directory is fsynced after the rename.
pub fn write_replace(root: &Path, relative: &Path, contents: &[u8]) -> Result<()> {
    let (parent, name) = split_parent(relative)?;
    let directory = if parent.as_os_str().is_empty() {
        Directory::open_root(root).map_err(|error| {
            io_failure(error, "vault root", "could not open the vault root".into())
        })?
    } else {
        create_directory_all(root, parent)?
    };
    match directory.child_kind(name) {
        Ok(EntryKind::Symlink) => return Err(refuse_symlink(&display_name(name))),
        Ok(EntryKind::Directory) | Ok(EntryKind::Other) => {
            return Err(refuse_not_regular(&relative.display().to_string()));
        }
        Ok(EntryKind::File) | Err(_) => {}
    }

    let mut last_error = None;
    for _ in 0..16 {
        let tmp = temporary_name();
        let mut file = match directory.create_child_file(&tmp) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
                continue;
            }
            Err(error) => {
                return Err(io_failure(
                    error,
                    &relative.display().to_string(),
                    format!("could not create temporary file for {}", relative.display()),
                ));
            }
        };
        let staged = file
            .write_all(contents)
            .and_then(|_| file.sync_all())
            .with_context(|| format!("could not write {}", relative.display()));
        if staged.is_err() {
            let _ = directory.unlink_child(&tmp);
            staged?;
        }
        let result = directory.rename_child(&tmp, name).map_err(|error| {
            io_failure(
                error,
                &relative.display().to_string(),
                format!("could not publish {}", relative.display()),
            )
        });
        if result.is_err() {
            let _ = directory.unlink_child(&tmp);
        }
        result?;
        directory.sync().with_context(|| {
            format!(
                "could not sync the directory holding {}",
                relative.display()
            )
        })?;
        return Ok(());
    }
    Err(io_failure(
        last_error.unwrap_or_else(|| io::Error::other("could not allocate a temporary name")),
        &relative.display().to_string(),
        format!("could not create temporary file for {}", relative.display()),
    ))
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

/// Names that collection walks skip when the entry is not a symbolic link.
/// Dot-named symbolic links are never skipped (they are `E_SYMLINK`).
pub fn is_skipped_name(name: &str) -> bool {
    name.starts_with('.') || name.eq_ignore_ascii_case("README.md")
}

pub fn skip_walk_entry(name: &str, kind: EntryKind) -> bool {
    kind != EntryKind::Symlink && is_skipped_name(name)
}

/// A directory reached without following a symbolic link.
#[cfg(unix)]
struct Directory {
    descriptor: std::os::fd::OwnedFd,
    path: PathBuf,
}

#[cfg(unix)]
#[allow(unsafe_code)]
mod unix {
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::{Directory, EntryKind};

    const SAFE_FLAGS: libc::c_int = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    const PRIVATE_MODE: libc::mode_t = 0o600;

    fn terminated(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a vault path cannot contain a NUL byte",
            )
        })
    }

    fn checked(result: libc::c_int) -> io::Result<libc::c_int> {
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result)
    }

    impl Directory {
        pub(super) fn open_root(path: &Path) -> io::Result<Self> {
            let name = terminated(path.as_os_str())?;
            // SAFETY: `name` is a valid NUL-terminated string that outlives the
            // call, and the returned descriptor is immediately owned.
            let descriptor = checked(unsafe {
                libc::open(
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            })?;
            // SAFETY: `descriptor` is a fresh, valid, unowned descriptor.
            let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
            Ok(Self {
                descriptor,
                path: path.to_path_buf(),
            })
        }

        fn open_child(
            &self,
            name: &OsStr,
            flags: libc::c_int,
            mode: libc::mode_t,
        ) -> io::Result<OwnedFd> {
            let terminated = terminated(name)?;
            // SAFETY: `terminated` outlives the call and `self.descriptor` is a
            // valid open directory descriptor; the result is immediately owned.
            let descriptor = checked(unsafe {
                libc::openat(
                    self.descriptor.as_raw_fd(),
                    terminated.as_ptr(),
                    flags | SAFE_FLAGS,
                    mode as libc::c_int,
                )
            })?;
            // SAFETY: `descriptor` is a fresh, valid, unowned descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
        }

        pub(super) fn open_child_directory(&self, name: &OsStr) -> io::Result<Self> {
            let descriptor = self.open_child(name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            Ok(Self {
                descriptor,
                path: self.path.join(name),
            })
        }

        pub(super) fn create_child_directory(&self, name: &OsStr) -> io::Result<()> {
            let terminated = terminated(name)?;
            // SAFETY: `terminated` outlives the call and `self.descriptor` is a
            // valid open directory descriptor.
            checked(unsafe {
                libc::mkdirat(self.descriptor.as_raw_fd(), terminated.as_ptr(), 0o777)
            })
            .map(|_| ())
        }

        pub(super) fn open_child_file(&self, name: &OsStr) -> io::Result<File> {
            self.open_child(name, libc::O_RDONLY, 0).map(File::from)
        }

        pub(super) fn create_child_file(&self, name: &OsStr) -> io::Result<File> {
            self.open_child(
                name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                PRIVATE_MODE,
            )
            .map(File::from)
        }

        pub(super) fn child_kind(&self, name: &OsStr) -> io::Result<EntryKind> {
            let terminated = terminated(name)?;
            let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: `terminated` outlives the call, `self.descriptor` is a
            // valid open directory descriptor, and `status` is writable and
            // correctly sized for one `struct stat`.
            checked(unsafe {
                libc::fstatat(
                    self.descriptor.as_raw_fd(),
                    terminated.as_ptr(),
                    status.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })?;
            // SAFETY: `fstatat` succeeded, so `status` is initialized.
            let status = unsafe { status.assume_init() };
            Ok(match status.st_mode & libc::S_IFMT {
                libc::S_IFDIR => EntryKind::Directory,
                libc::S_IFREG => EntryKind::File,
                libc::S_IFLNK => EntryKind::Symlink,
                _ => EntryKind::Other,
            })
        }

        pub(super) fn rename_child(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
            let from = terminated(from)?;
            let to = terminated(to)?;
            // SAFETY: both names outlive the call and `self.descriptor` is a
            // valid open directory descriptor.
            checked(unsafe {
                libc::renameat(
                    self.descriptor.as_raw_fd(),
                    from.as_ptr(),
                    self.descriptor.as_raw_fd(),
                    to.as_ptr(),
                )
            })
            .map(|_| ())
        }

        pub(super) fn unlink_child(&self, name: &OsStr) -> io::Result<()> {
            let terminated = terminated(name)?;
            // SAFETY: `terminated` outlives the call and `self.descriptor` is a
            // valid open directory descriptor.
            checked(unsafe { libc::unlinkat(self.descriptor.as_raw_fd(), terminated.as_ptr(), 0) })
                .map(|_| ())
        }

        pub(super) fn sync(&self) -> io::Result<()> {
            // SAFETY: `self.descriptor` is a valid open directory descriptor.
            checked(unsafe { libc::fsync(self.descriptor.as_raw_fd()) }).map(|_| ())
        }

        pub(super) fn resolved(&self) -> &Path {
            &self.path
        }
    }
}

/// Portable fallback used only where `openat` is unavailable.
#[cfg(not(unix))]
struct Directory {
    path: PathBuf,
}

#[cfg(not(unix))]
mod portable {
    use std::ffi::OsStr;
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::path::{Path, PathBuf};

    use super::{Directory, EntryKind};

    fn kind_of(path: &Path) -> io::Result<EntryKind> {
        let metadata = std::fs::symlink_metadata(path)?;
        Ok(EntryKind::from_metadata(&metadata))
    }

    impl Directory {
        pub(super) fn open_root(path: &Path) -> io::Result<Self> {
            match kind_of(path)? {
                EntryKind::Directory => Ok(Self {
                    path: path.to_path_buf(),
                }),
                _ => Err(io::Error::other("the vault root is not a directory")),
            }
        }

        pub(super) fn open_child_directory(&self, name: &OsStr) -> io::Result<Self> {
            let path = self.path.join(name);
            match kind_of(&path)? {
                EntryKind::Directory => Ok(Self { path }),
                EntryKind::Symlink => Err(io::Error::other("component is a symbolic link")),
                _ => Err(io::Error::other("component is not a directory")),
            }
        }

        pub(super) fn create_child_directory(&self, name: &OsStr) -> io::Result<()> {
            std::fs::create_dir(self.path.join(name))
        }

        fn checked_child(&self, name: &OsStr) -> io::Result<PathBuf> {
            let path = self.path.join(name);
            match kind_of(&path) {
                Ok(EntryKind::Symlink) => Err(io::Error::other("entry is a symbolic link")),
                Ok(_) => Ok(path),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
                Err(error) => Err(error),
            }
        }

        pub(super) fn open_child_file(&self, name: &OsStr) -> io::Result<File> {
            File::open(self.checked_child(name)?)
        }

        pub(super) fn create_child_file(&self, name: &OsStr) -> io::Result<File> {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.checked_child(name)?)
        }

        pub(super) fn child_kind(&self, name: &OsStr) -> io::Result<EntryKind> {
            kind_of(&self.path.join(name))
        }

        pub(super) fn rename_child(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
            std::fs::rename(self.checked_child(from)?, self.checked_child(to)?)
        }

        pub(super) fn unlink_child(&self, name: &OsStr) -> io::Result<()> {
            std::fs::remove_file(self.checked_child(name)?)
        }

        pub(super) fn sync(&self) -> io::Result<()> {
            if let Ok(dir) = File::open(&self.path) {
                let _ = dir.sync_all();
            }
            Ok(())
        }

        pub(super) fn resolved(&self) -> &Path {
            &self.path
        }
    }
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
        write_replace(dir.path(), Path::new("a/b.txt"), b"second").unwrap();
        assert_eq!(
            read_to_string(dir.path(), Path::new("a/b.txt")).unwrap(),
            "second"
        );
        let leftovers: Vec<_> = fs::read_dir(dir.path().join("a"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 1);
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
        assert!(read_to_string(dir.path(), Path::new("link.txt")).is_err());
        assert!(write_replace(dir.path(), Path::new("link.txt"), b"x").is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "secret");
    }

    #[test]
    fn lists_without_following() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("ok.txt"), "x").unwrap();
        std::os::unix::fs::symlink("ok.txt", dir.path().join("s")).unwrap();
        let entries = read_dir(dir.path(), Path::new("")).unwrap();
        let kinds: Vec<_> = entries
            .iter()
            .map(|e| (e.name.as_str(), e.kind, e.utf8))
            .collect();
        assert!(kinds.contains(&("ok.txt", EntryKind::File, true)));
        assert!(kinds.contains(&("s", EntryKind::Symlink, true)));
    }
}
