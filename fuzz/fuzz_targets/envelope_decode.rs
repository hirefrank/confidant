//! Fuzz the §14 envelope decoder (`confidant_crypt::envelope`).
//!
//! The envelope parser handles whole-file `enc:` envelopes from git —
//! adversarial input is the threat model (issue #235, [crypto-review] #269).
//!
//! Two paths per input, both driven through the existing public entry
//! points (`envelope::parse`, `decrypt_record`); no `#[cfg(fuzzing)]`
//! shims were needed.
//!
//! Path 1 — raw decode: arbitrary bytes must never panic the parser.
//! A decode failure is `Err` (no plaintext escapes by construction: both
//! entry points return `Result`). A decrypt success must reproduce a known
//! seed exactly, otherwise unauthenticated bytes affected the output.
//!
//! Path 2 — structured mutation of a known-good seed envelope, so the
//! decrypt-success path (which random bytes almost never reach) is
//! exercised: input layout is `[seed_idx: u8][(offset_be_u16, xor_u8)...]`.
//! Any change to an authenticated byte (outer header / AAD-bound fields,
//! nonce, ciphertext, tag) must fail closed; a surviving decode must match
//! the seed's plaintext and bound metadata exactly.
//!
//! Seeds use throwaway keys generated inside the harness (ADR-14); the
//! `no-ai: notes` header value is covered.

#![no_main]

use std::sync::OnceLock;

use confidant_crypt::{
    decrypt_record, encrypt_record,
    envelope::{self, Envelope, NoAi},
    keys::DataKey,
    RecordCtx,
};
use libfuzzer_sys::fuzz_target;

/// A known-good seed: serialized bytes, parsed form, plaintext, and the
/// context/key that decrypt it.
struct Seed {
    ctx: RecordCtx,
    key: DataKey,
    envelope_bytes: Vec<u8>,
    envelope: Envelope,
    plaintext: Vec<u8>,
}

fn make_seed(
    key: &DataKey,
    ulid: &str,
    record_type: &str,
    purpose: &str,
    no_ai: NoAi,
    plaintext: &[u8],
) -> Seed {
    let ctx = RecordCtx {
        vault_id: "fuzz-vault".to_string(),
        ulid: ulid.to_string(),
        client_id: ulid.to_string(),
        path: format!("people/{ulid}.cfd"),
        purpose: purpose.to_string(),
        epoch: 1,
    };
    let envelope_bytes = encrypt_record(&ctx, key, record_type, no_ai, plaintext)
        .expect("seed envelope must encrypt");
    let envelope = envelope::parse(&envelope_bytes).expect("seed envelope must parse");
    Seed {
        ctx,
        key: key.clone(),
        envelope_bytes,
        envelope,
        plaintext: plaintext.to_vec(),
    }
}

fn seeds() -> &'static Vec<Seed> {
    static SEEDS: OnceLock<Vec<Seed>> = OnceLock::new();
    SEEDS.get_or_init(|| {
        let key = DataKey::generate();
        vec![
            make_seed(
                &key,
                "p-01FUZZ00000000000000000001",
                "person",
                "profile",
                NoAi::False,
                b"fuzz profile one",
            ),
            make_seed(
                &key,
                "p-01FUZZ00000000000000000002",
                "person",
                "profile",
                NoAi::Notes,
                b"fuzz profile two",
            ),
            make_seed(
                &key,
                "p-01FUZZ00000000000000000003",
                "note",
                "note",
                NoAi::True,
                b"fuzz hidden note",
            ),
            make_seed(
                &key,
                "p-01FUZZ00000000000000000004",
                "note",
                "note",
                NoAi::False,
                b"fuzz visible note",
            ),
        ]
    })
}

/// If `bytes` decrypt under `seed`, the result must be the seed exactly.
fn assert_matches_seed(seed: &Seed, env: &Envelope, plaintext: &[u8], bytes: &[u8]) {
    assert_eq!(
        plaintext,
        seed.plaintext.as_slice(),
        "decrypt success with wrong plaintext for {} input bytes",
        bytes.len()
    );
    assert_eq!(
        env,
        &seed.envelope,
        "decrypt success with wrong bound metadata for {} input bytes",
        bytes.len()
    );
}

fuzz_target!(|data: &[u8]| {
    let seeds = seeds();

    // Path 1: raw decode of arbitrary bytes. Never panics; failures are
    // Err (fail closed, no plaintext). A success must match a seed exactly.
    if let Ok(env) = envelope::parse(data) {
        for seed in seeds.iter() {
            match decrypt_record(&seed.ctx, &seed.key, data, false) {
                Err(_) => {}
                Ok(plaintext) => assert_matches_seed(seed, &env, &plaintext, data),
            }
        }
    }

    // Path 2: structured mutation of a known-good seed envelope.
    if data.is_empty() {
        return;
    }
    let seed = &seeds[data[0] as usize % seeds.len()];
    let mut mutated = seed.envelope_bytes.clone();
    if mutated.is_empty() {
        return;
    }
    for chunk in data[1..].chunks_exact(3) {
        let offset = u16::from_be_bytes([chunk[0], chunk[1]]) as usize % mutated.len();
        mutated[offset] ^= chunk[2];
    }
    match envelope::parse(&mutated) {
        Err(_) => {}
        Ok(env) => match decrypt_record(&seed.ctx, &seed.key, &mutated, false) {
            Err(_) => {}
            // Only reachable when the mutation hit bytes outside the
            // authenticated set; then everything must still match exactly.
            Ok(plaintext) => assert_matches_seed(seed, &env, &plaintext, &mutated),
        },
    }
});
