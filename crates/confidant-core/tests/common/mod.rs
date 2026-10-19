//! Shared helpers for `confidant-core` integration tests.

use std::path::{Path, PathBuf};

/// The neutral external-pack fixture.
pub fn example_pack_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/packs/example-pack")
}

/// Vendor the `example-pack@0.1` fixture into `root/packs/example-pack@0.1`
/// and pin its canonical hash, exactly as `pack add` does. Returns the hash.
pub fn install_example_pack(root: &Path) -> String {
    let src = example_pack_dir();
    let dst = root.join("packs/example-pack@0.1");
    std::fs::create_dir_all(&dst).unwrap();
    for entry in std::fs::read_dir(&src).unwrap() {
        let entry = entry.unwrap();
        assert!(
            entry.file_type().unwrap().is_file(),
            "fixture pack dir must be flat: {}",
            entry.path().display()
        );
        std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
    let hash = confidant_core::packs::dir::read_pack_dir(&dst)
        .expect("example pack dir must read")
        .hash;
    std::fs::write(
        root.join("confidant.lock"),
        format!(
            "lock_version = 1\n\n[[pack]]\nname = \"example-pack\"\nversion = \"0.1\"\nsource = \"dir\"\nrev = \"\"\nsubdir = \"\"\nhash = \"{hash}\"\n"
        ),
    )
    .unwrap();
    hash
}
