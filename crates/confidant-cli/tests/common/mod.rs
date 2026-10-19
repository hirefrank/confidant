//! Shared helpers for `confidant-cli` integration tests (#416 nit 3).

use std::path::Path;

/// Copy `src` into `dst` recursively (a throwaway vault a test may write to).
/// Not every test binary that includes `common` calls it.
#[allow(dead_code)]
pub fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}

/// Vendor the shipped external `coaching@0.1` pack into `vault` and pin its
/// canonical hash, as `pack add --from-dir` does (#449). Returns the hash.
/// Not every test binary that includes `common` calls it.
#[allow(dead_code)]
pub fn install_shipped_coaching(vault: &Path) -> String {
    let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/coaching");
    let dst = vault.join("packs/coaching@0.1");
    std::fs::create_dir_all(&dst).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
    let hash = confidant_core::packs::dir::read_pack_dir(&dst)
        .unwrap()
        .hash;
    std::fs::write(
        vault.join("confidant.lock"),
        format!(
            "lock_version = 1\n\n[[pack]]\nname = \"coaching\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"{hash}\"\n"
        ),
    )
    .unwrap();
    hash
}
