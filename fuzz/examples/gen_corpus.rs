//! One-off corpus generator for the `envelope_decode` fuzz target.
//!
//! Writes real valid envelopes (throwaway keys, fake data) into
//! `fuzz/corpus/envelope_decode/` so libfuzzer starts mutating from
//! well-formed inputs. Run once with:
//!
//! ```sh
//! cd fuzz && cargo run --example gen_corpus
//! ```
//!
//! The checked-in files are inputs only; the fuzz target regenerates its
//! own in-memory seeds (with fresh keys) for the exact-match assertions.

use std::path::PathBuf;

use confidant_crypt::{encrypt_record, envelope::NoAi, keys::DataKey, RecordCtx};

fn main() {
    let out_dir: PathBuf = [env!("CARGO_MANIFEST_DIR"), "corpus", "envelope_decode"]
        .iter()
        .collect();
    std::fs::create_dir_all(&out_dir).expect("create corpus dir");

    let key = DataKey::generate();
    let cases = [
        (
            "seed_person_false",
            "p-01FUZZ00000000000000000001",
            "person",
            "profile",
            NoAi::False,
            &b"fuzz profile one"[..],
        ),
        (
            "seed_person_notes",
            "p-01FUZZ00000000000000000002",
            "person",
            "profile",
            NoAi::Notes,
            &b"fuzz profile two"[..],
        ),
        (
            "seed_note_true",
            "p-01FUZZ00000000000000000003",
            "note",
            "note",
            NoAi::True,
            &b"fuzz hidden note"[..],
        ),
        (
            "seed_note_false",
            "p-01FUZZ00000000000000000004",
            "note",
            "note",
            NoAi::False,
            &b"fuzz visible note"[..],
        ),
    ];
    for (name, ulid, record_type, purpose, no_ai, plaintext) in cases {
        let ctx = RecordCtx {
            vault_id: "fuzz-vault".to_string(),
            ulid: ulid.to_string(),
            client_id: ulid.to_string(),
            path: format!("people/{ulid}.cfd"),
            purpose: purpose.to_string(),
            epoch: 1,
        };
        let bytes = encrypt_record(&ctx, &key, record_type, no_ai, plaintext)
            .expect("seed envelope must encrypt");
        std::fs::write(out_dir.join(name), &bytes).expect("write seed file");
        println!("wrote {} ({} bytes)", name, bytes.len());
    }
}
