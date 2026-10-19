//! Shared helpers for `confidant-core` integration tests.

use std::path::{Path, PathBuf};

/// The shipped external coaching pack directory (#449).
pub fn shipped_coaching_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packs/coaching")
}

/// Vendor the shipped `coaching@0.1` pack into `root/packs/coaching@0.1` and
/// pin its canonical hash, exactly as `pack add` does (#449). Returns the
/// hash.
pub fn install_shipped_coaching(root: &Path) -> String {
    let src = shipped_coaching_dir();
    let dst = root.join("packs/coaching@0.1");
    std::fs::create_dir_all(&dst).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let entry = entry.unwrap();
        assert!(
            entry.file_type().unwrap().is_file(),
            "shipped pack dir must be flat: {}",
            entry.path().display()
        );
        std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
    let hash = confidant_core::packs::dir::read_pack_dir(&dst)
        .expect("shipped coaching pack dir must read")
        .hash;
    std::fs::write(
        root.join("confidant.lock"),
        format!(
            "lock_version = 1\n\n[[pack]]\nname = \"coaching\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"{hash}\"\n"
        ),
    )
    .unwrap();
    hash
}
