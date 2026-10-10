//! Integration tests for the milestone 2 crypto design test plan
//! (`docs/crypto-design.md` §12, tests 1–16).
//!
//! All fixtures use generated fake data and throwaway keys (ADR-14: CI
//! never holds vault keys).

use std::collections::HashSet;
use std::path::Path;

use age::secrecy::ExposeSecret;
use confidant_crypt::{
    aead, age_wrap, alias,
    anchor::{self, Anchor},
    decrypt_record, encrypt_record,
    envelope::{self, purpose_for_type},
    error::Error,
    history::{verify_history, SignerChecker},
    keys::{DataKey, DeviceKeypair, LookupKey},
    lifecycle::KeyStore,
    manifest::{RecipientEntry, RecipientMap},
    recovery::Recovery,
    scope::{authorize, sign as sign_scope, to_toml as scope_to_toml, Capability, Scope},
    RecordCtx,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    _tmp: tempfile::TempDir,
    keys: KeyStore,
    operator_sk: SigningKey,
    anchor: Anchor,
    device_id: age::x25519::Identity,
    device_recipient: String,
    recovery: Recovery,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let keys_dir = tmp.path().join("keys");
        let config_dir = tmp.path().join("config");
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&vault_dir).unwrap();

        let operator_sk = SigningKey::generate(&mut OsRng);
        let device_id = age::x25519::Identity::generate();
        let device_recipient = device_id.to_public().to_string();
        let recovery = Recovery::generate();

        // trust.toml with both recovery public halves pinned.
        let hex = |k: &[u8]| k.iter().map(|b| format!("{b:02x}")).collect::<String>();
        std::fs::write(
            config_dir.join("trust.toml"),
            format!(
                "[trust]\noperator_pubkey = \"{}\"\nrecovery_pubkey = \"{}\"\nrecovery_age_recipient = \"{}\"\n",
                hex(operator_sk.verifying_key().as_bytes()),
                hex(recovery.verifying_key().as_bytes()),
                recovery.age_identity().to_recipient_string(),
            ),
        )
        .unwrap();
        // Loosen perms so the loader doesn't warn (not what we're testing).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(
                config_dir.join("trust.toml"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let (anchor, warnings) = anchor::load(&config_dir, &vault_dir).unwrap();
        assert!(warnings.is_empty());

        let seq_tracker =
            confidant_crypt::manifest::SeqTracker::load(&config_dir.join("manifest-seq.toml"))
                .unwrap();
        let mut keys = KeyStore::new(keys_dir, "vault-01").with_seq_tracker(seq_tracker);
        keys.init_lookup_key(std::slice::from_ref(&device_recipient), &operator_sk)
            .unwrap();

        Fixture {
            _tmp: tmp,
            keys,
            operator_sk,
            anchor,
            device_id,
            device_recipient,
            recovery,
        }
    }

    fn recipients(&self, entries: &[(&str, &str)]) -> RecipientMap {
        let mut m = RecipientMap::new();
        for (id, pubkey) in entries {
            m.insert(
                id.to_string(),
                RecipientEntry {
                    age_pubkey: pubkey.to_string(),
                    label: id.to_string(),
                    scope_ref: String::new(),
                },
            );
        }
        m
    }

    fn recovery_recipient(&self) -> String {
        self.anchor.recovery_age.clone()
    }

    fn ctx(&self, ulid: &str, client_id: &str, purpose: &str, epoch: u64) -> RecordCtx {
        RecordCtx {
            vault_id: "vault-01".to_string(),
            ulid: ulid.to_string(),
            client_id: client_id.to_string(),
            path: format!("people/{ulid}.cfd"),
            purpose: purpose.to_string(),
            epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: AAD binding
// ---------------------------------------------------------------------------

#[test]
fn test1_aad_binding() {
    let f = Fixture::new();
    let key = DataKey::generate();
    let ctx = f.ctx("p-01ABC", "p-01ABC", "profile", 3);
    let bytes = encrypt_record(&ctx, &key, "person", false, b"secret").unwrap();

    // Baseline decrypts.
    assert!(decrypt_record(&ctx, &key, &bytes, false).is_ok());

    // Altered vault_id -> auth failure.
    let mut bad = ctx.clone();
    bad.vault_id = "vault-02".to_string();
    assert!(matches!(
        decrypt_record(&bad, &key, &bytes, false),
        Err(Error::Auth)
    ));

    // Altered ULID -> header inconsistency.
    let mut bad = ctx.clone();
    bad.ulid = "p-OTHER".to_string();
    assert!(matches!(
        decrypt_record(&bad, &key, &bytes, false),
        Err(Error::Header(_))
    ));

    // Altered path -> auth failure (path is in the AAD).
    let mut bad = ctx.clone();
    bad.path = "people/p-OTHER.cfd".to_string();
    assert!(matches!(
        decrypt_record(&bad, &key, &bytes, false),
        Err(Error::Auth)
    ));

    // Altered purpose -> header inconsistency (type maps to exactly one purpose).
    let mut bad = ctx.clone();
    bad.purpose = "note".to_string();
    assert!(matches!(
        decrypt_record(&bad, &key, &bytes, false),
        Err(Error::Header(_))
    ));

    // Altered epoch -> header inconsistency (key_id epoch mismatch).
    let mut bad = ctx.clone();
    bad.epoch = 4;
    assert!(matches!(
        decrypt_record(&bad, &key, &bytes, false),
        Err(Error::Header(_))
    ));
}

// ---------------------------------------------------------------------------
// Test 2: nonce uniqueness
// ---------------------------------------------------------------------------

#[test]
fn test2_nonce_uniqueness() {
    let key = [7u8; 32];
    let aad = b"test-aad";
    let mut nonces = HashSet::new();
    for _ in 0..1000 {
        let (nonce, _) = aead::encrypt(&key, aad, b"x");
        assert!(nonces.insert(nonce), "nonce repeated!");
    }
    assert_eq!(nonces.len(), 1000);
}

// ---------------------------------------------------------------------------
// Test 3: wrong key / tampered ciphertext
// ---------------------------------------------------------------------------

#[test]
fn test3_wrong_key_tampered() {
    let f = Fixture::new();
    let key = DataKey::generate();
    let wrong = DataKey::generate();
    let ctx = f.ctx("p-01ABC", "p-01ABC", "profile", 1);
    let bytes = encrypt_record(&ctx, &key, "person", false, b"top secret").unwrap();

    // Wrong key -> auth failure, no plaintext.
    assert!(matches!(
        decrypt_record(&ctx, &wrong, &bytes, false),
        Err(Error::Auth)
    ));

    // Tampered ciphertext -> auth failure (no partial plaintext).
    // Flip a byte in the decoded ciphertext via parse/modify/serialize.
    let mut env = envelope::parse(&bytes).unwrap();
    env.ciphertext[0] ^= 0xff;
    let tampered = envelope::serialize(&env);
    assert!(matches!(
        decrypt_record(&ctx, &key, &tampered, false),
        Err(Error::Auth)
    ));
}

// ---------------------------------------------------------------------------
// Test 4: age wrapping round-trip via the KeyStore
// ---------------------------------------------------------------------------

#[test]
fn test4_age_wrap_round_trip() {
    let mut f = Fixture::new();
    let recipients = f.recipients(&[("laptop", &f.device_recipient)]);
    let key = f
        .keys
        .init_client(
            "p-01ABC",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    // Unwrap with the device identity.
    let back = f
        .keys
        .unwrap_data_key("p-01ABC", "laptop", 1, &f.device_id, &f.anchor)
        .unwrap();
    assert_eq!(back.as_bytes(), key.as_bytes());

    // Unwrap with the recovery identity.
    let back = f
        .keys
        .unwrap_data_key(
            "p-01ABC",
            "recovery",
            1,
            &f.recovery.age_identity().to_age_identity().unwrap(),
            &f.anchor,
        )
        .unwrap();
    assert_eq!(back.as_bytes(), key.as_bytes());

    // Unknown recipient -> NoKey.
    let other = age::x25519::Identity::generate();
    assert!(matches!(
        f.keys
            .unwrap_data_key("p-01ABC", "laptop", 1, &other, &f.anchor),
        Err(Error::Age(_)) | Err(Error::NoKey(_))
    ));

    // Full record encrypt/decrypt with the unwrapped key.
    let ctx = f.ctx("p-01ABC", "p-01ABC", "profile", 1);
    let bytes = encrypt_record(&ctx, &back, "person", false, b"profile body").unwrap();
    let pt = decrypt_record(&ctx, &back, &bytes, false).unwrap();
    assert_eq!(pt, b"profile body");
}

// ---------------------------------------------------------------------------
// Test 5: manifest signatures
// ---------------------------------------------------------------------------

#[test]
fn test5_manifest_verification() {
    let mut f = Fixture::new();
    let recipients = f.recipients(&[("laptop", &f.device_recipient)]);
    f.keys
        .init_client(
            "p-01ABC",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    // Valid manifest verifies (implicit in unwrap).
    assert!(f
        .keys
        .unwrap_data_key("p-01ABC", "laptop", 1, &f.device_id, &f.anchor)
        .is_ok());

    // Tampered recipients.toml -> hard error, no unwrap.
    let keys_dir = f._tmp.path().join("keys");
    let toml_path = keys_dir.join("p-01ABC").join("recipients.toml");
    let mut toml = std::fs::read(&toml_path).unwrap();
    toml.extend_from_slice(b"\n# tampered\n");
    std::fs::write(&toml_path, toml).unwrap();
    assert!(matches!(
        f.keys
            .unwrap_data_key("p-01ABC", "laptop", 1, &f.device_id, &f.anchor),
        Err(Error::Manifest(_))
    ));
}

// ---------------------------------------------------------------------------
// Test 6: scope enforcement (integration-level re-check)
// ---------------------------------------------------------------------------

#[test]
fn test6_scope_enforcement() {
    let operator_sk = SigningKey::generate(&mut OsRng);
    let scope = Scope {
        key_id: "agent-1".to_string(),
        clients: vec!["p-01ABC".to_string()],
        types: vec!["note".to_string()],
        capabilities: vec!["read".to_string()],
        expires: "2026-12-01".to_string(),
    };
    let toml = scope_to_toml(&scope).unwrap();
    let sig = sign_scope(&operator_sk, "vault-01", &scope).unwrap();
    let pk = operator_sk.verifying_key();
    let auth = |today: &str, client: &str, rtype: &str, cap: Capability| {
        authorize(
            &pk, "vault-01", "agent-1", &toml, &sig, today, client, rtype, cap,
        )
    };

    // In-scope read allowed.
    assert!(auth("2026-10-08", "p-01ABC", "note", Capability::Read).is_ok());
    // Expired, wrong client, wrong type, write-with-read-only all refused.
    assert!(auth("2026-12-02", "p-01ABC", "note", Capability::Read).is_err());
    assert!(auth("2026-10-08", "p-OTHER", "note", Capability::Read).is_err());
    assert!(auth("2026-10-08", "p-01ABC", "deal", Capability::Read).is_err());
    assert!(auth("2026-10-08", "p-01ABC", "note", Capability::Write).is_err());
    // Wrong identity: the scope names agent-1.
    assert!(authorize(
        &pk,
        "vault-01",
        "agent-2",
        &toml,
        &sig,
        "2026-10-08",
        "p-01ABC",
        "note",
        Capability::Read
    )
    .is_err());
    // Wrong vault: the scope was minted for vault-01.
    assert!(authorize(
        &pk,
        "vault-02",
        "agent-1",
        &toml,
        &sig,
        "2026-10-08",
        "p-01ABC",
        "note",
        Capability::Read
    )
    .is_err());
}

// ---------------------------------------------------------------------------
// Test 7: revocation
// ---------------------------------------------------------------------------

#[test]
fn test7_revocation() {
    let mut f = Fixture::new();
    let dev2 = DeviceKeypair::generate();
    let dev2_recipient = dev2.recipient();
    let dev2_id = age::x25519::Identity::from_str(&{
        // DeviceKeypair doesn't export bech32; rebuild via raw secret.
        use confidant_crypt::age_wrap::RawX25519Identity;
        RawX25519Identity::new(*dev2.secret_bytes()).to_bech32()
    })
    .unwrap();

    let recipients = f.recipients(&[("laptop", &f.device_recipient), ("phone", &dev2_recipient)]);
    f.keys
        .init_client(
            "p-01ABC",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    // Both devices unwrap epoch 1.
    assert!(f
        .keys
        .unwrap_data_key("p-01ABC", "phone", 1, &dev2_id, &f.anchor)
        .is_ok());

    // Revoke the phone.
    f.keys
        .revoke("p-01ABC", &["phone"], &f.operator_sk, &f.anchor)
        .unwrap();

    // Revoked party's wrappings are gone from the working tree (all epochs).
    let wdir = f._tmp.path().join("keys").join("p-01ABC").join("wrapped");
    let names: Vec<String> = std::fs::read_dir(&wdir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(!names.iter().any(|n| n.starts_with("phone")), "{names:?}");

    // Rotate to a new epoch; revoked key cannot unwrap it.
    f.keys
        .rotate(
            "p-01ABC",
            &f.recovery_recipient(),
            &f.operator_sk,
            &f.anchor,
        )
        .unwrap();
    assert!(f.keys.current_epoch("p-01ABC").unwrap() == 2);
    assert!(matches!(
        f.keys
            .unwrap_data_key("p-01ABC", "phone", 2, &dev2_id, &f.anchor),
        Err(Error::NoKey(_))
    ));
    // Still-authorized device unwraps the new epoch.
    assert!(f
        .keys
        .unwrap_data_key("p-01ABC", "laptop", 2, &f.device_id, &f.anchor)
        .is_ok());
    // Old epoch still readable by the remaining device.
    assert!(f
        .keys
        .unwrap_data_key("p-01ABC", "laptop", 1, &f.device_id, &f.anchor)
        .is_ok());
}

// ---------------------------------------------------------------------------
// Test 8: shredding
// ---------------------------------------------------------------------------

#[test]
fn test8_shredding() {
    let mut f = Fixture::new();
    let recipients = f.recipients(&[("laptop", &f.device_recipient)]);
    let key_a = f
        .keys
        .init_client(
            "p-AAAA",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();
    let key_b = f
        .keys
        .init_client(
            "p-BBBB",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();
    // Rotate B so it has a retained old epoch: shred must keep history readable.
    let key_b_e1 = key_b.clone();
    let key_b = f
        .keys
        .rotate("p-BBBB", &f.recovery_recipient(), &f.operator_sk, &f.anchor)
        .unwrap();
    assert_ne!(key_b.as_bytes(), key_b_e1.as_bytes());

    // Encrypt a record for each client.
    let ctx_a = f.ctx("p-AAAA", "p-AAAA", "profile", 1);
    let ctx_b = f.ctx("p-BBBB", "p-BBBB", "profile", 2);
    let env_a = encrypt_record(&ctx_a, &key_a, "person", false, b"A secret").unwrap();
    let env_b = encrypt_record(&ctx_b, &key_b, "person", false, b"B secret").unwrap();
    assert!(decrypt_record(&ctx_a, &key_a, &env_a, false).is_ok());

    // New recipient set (fresh device key, like onboarding after shred).
    let dev_new = DeviceKeypair::generate();
    let new_recipients = f.recipients(&[("laptop-new", &dev_new.recipient())]);
    let new_id = age::x25519::Identity::from_str(&{
        use confidant_crypt::age_wrap::RawX25519Identity;
        RawX25519Identity::new(*dev_new.secret_bytes()).to_bech32()
    })
    .unwrap();

    // Shred client A using the old device identity.
    let outcome = f
        .keys
        .shred(
            "p-AAAA",
            &["p-AAAA", "p-BBBB"],
            &new_recipients,
            &f.operator_sk,
            &f.anchor,
            &f.device_id,
        )
        .unwrap();

    // A's key tree is gone: nothing to unwrap.
    assert!(!f._tmp.path().join("keys").join("p-AAAA").exists());
    assert!(matches!(
        f.keys
            .unwrap_data_key("p-AAAA", "laptop", 1, &f.device_id, &f.anchor),
        Err(Error::NoKey(_)) | Err(Error::Manifest(_))
    ));

    // B still decrypts under the new keys (current and retained old epoch).
    let key_b_new = f
        .keys
        .unwrap_data_key("p-BBBB", "laptop-new", 2, &new_id, &f.anchor)
        .unwrap();
    assert_eq!(key_b_new.as_bytes(), key_b.as_bytes());
    let pt = decrypt_record(&ctx_b, &key_b_new, &env_b, false).unwrap();
    assert_eq!(pt, b"B secret");
    let key_b_old = f
        .keys
        .unwrap_data_key("p-BBBB", "laptop-new", 1, &new_id, &f.anchor)
        .unwrap();
    assert_eq!(key_b_old.as_bytes(), key_b_e1.as_bytes());

    // Old device key cannot unwrap B anymore (wrappings replaced).
    assert!(f
        .keys
        .unwrap_data_key("p-BBBB", "laptop", 1, &f.device_id, &f.anchor)
        .is_err());

    // New recovery phrase: 24 words, differs from the old one; old phrase fails.
    let new_phrase = outcome.recovery_phrase_for_display();
    assert_eq!(new_phrase.split_whitespace().count(), 24);
    assert_ne!(new_phrase, f.recovery.phrase());
    let old_rec = Recovery::from_phrase(&f.recovery.phrase()).unwrap();
    let old_age_id = old_rec.age_identity().to_age_identity().unwrap();
    assert!(f
        .keys
        .unwrap_data_key("p-BBBB", "recovery", 2, &old_age_id, &f.anchor)
        .is_err());
    // New recovery identity unwraps (current and old epoch).
    let new_rec = Recovery::from_phrase(&new_phrase).unwrap();
    let new_age_id = new_rec.age_identity().to_age_identity().unwrap();
    assert!(f
        .keys
        .unwrap_data_key("p-BBBB", "recovery", 2, &new_age_id, &f.anchor)
        .is_ok());
    assert!(f
        .keys
        .unwrap_data_key("p-BBBB", "recovery", 1, &new_age_id, &f.anchor)
        .is_ok());

    // Output states the leftover limits.
    let warnings = outcome.warnings.join("\n");
    assert!(warnings.contains("keychain"), "{warnings}");
    assert!(warnings.contains("Drive"), "{warnings}");
    assert!(warnings.contains("new recovery phrase"), "{warnings}");

    // Debug never leaks the phrase: the full 24-word phrase (or any
    // 3-word run of it, which is distinctive) must not appear. Individual
    // common words may legitimately appear in warnings.
    let dbg = format!("{outcome:?}");
    assert!(
        !dbg.contains(&new_phrase),
        "phrase leaked in ShredOutcome Debug"
    );
    let words: Vec<&str> = new_phrase.split_whitespace().collect();
    for w in words.windows(3) {
        let seq = w.join(" ");
        assert!(
            !dbg.contains(&seq),
            "phrase fragment leaked in ShredOutcome Debug"
        );
    }
    assert!(
        dbg.contains("redacted"),
        "Recovery Debug should be redacted"
    );
}

// ---------------------------------------------------------------------------
// Revocation replay: restored pre-revocation manifest refused via seq
// ---------------------------------------------------------------------------

#[test]
fn test_revoke_replay_refused() {
    // Revoke re-signs at the SAME epoch. A restored pre-revocation manifest
    // (valid signature, same epoch) must still be refused via the seq
    // high-water mark.
    let mut f = Fixture::new();
    let dev2 = DeviceKeypair::generate();
    let recipients = f.recipients(&[
        ("laptop", &f.device_recipient),
        ("phone", &dev2.recipient()),
    ]);
    f.keys
        .init_client(
            "p-01ABC",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    // Save the pre-revocation manifest (has both recipients).
    let keys_dir = f._tmp.path().join("keys");
    let toml_path = keys_dir.join("p-01ABC").join("recipients.toml");
    let sig_path = keys_dir.join("p-01ABC").join("recipients.sig");
    let saved_toml = std::fs::read(&toml_path).unwrap();
    let saved_sig = std::fs::read(&sig_path).unwrap();

    // Revoke the phone: manifest re-signed at same epoch, seq bumped.
    f.keys
        .revoke("p-01ABC", &["phone"], &f.operator_sk, &f.anchor)
        .unwrap();
    // Sanity: phone is gone from the current manifest.
    let (_, map) = f.keys.verified_recipients("p-01ABC", &f.anchor).unwrap();
    assert!(!map.contains_key("phone"));

    // Restore the pre-revocation manifest (valid sig, same epoch, stale seq).
    std::fs::write(&toml_path, &saved_toml).unwrap();
    std::fs::write(&sig_path, &saved_sig).unwrap();
    let err = f
        .keys
        .verified_recipients("p-01ABC", &f.anchor)
        .unwrap_err();
    assert!(format!("{err}").contains("high-water mark"), "{err}");
}

// ---------------------------------------------------------------------------
// Shredding: destroy list covers historical recipients
// ---------------------------------------------------------------------------

#[test]
fn test_shred_destroy_list_covers_history() {
    // A recipient revoked BEFORE the shred still has old wrappings in git
    // history. The destroy list must include it.
    let mut f = Fixture::new();
    let dev2 = DeviceKeypair::generate();
    let recipients = f.recipients(&[
        ("laptop", &f.device_recipient),
        ("phone", &dev2.recipient()),
    ]);
    f.keys
        .init_client(
            "p-AAAA",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();
    f.keys
        .init_client(
            "p-BBBB",
            &f.recipients(&[("laptop", &f.device_recipient)]),
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    // Revoke phone from A (its old wrappings stay in history).
    // Init a git repo FIRST so history captures the pre-revoke manifest.
    let keys_dir = f._tmp.path().join("keys");
    let vault_dir = keys_dir.parent().unwrap();
    git(vault_dir, &["init", "-q"]);
    git(vault_dir, &["config", "user.email", "t@t"]);
    git(vault_dir, &["config", "user.name", "t"]);
    git(vault_dir, &["add", "keys"]);
    git(vault_dir, &["commit", "-qm", "init keys"]);
    f.keys
        .revoke("p-AAAA", &["phone"], &f.operator_sk, &f.anchor)
        .unwrap();
    git(vault_dir, &["add", "keys"]);
    git(vault_dir, &["commit", "-qm", "revoke phone"]);

    // Shred A.
    let dev_new = DeviceKeypair::generate();
    let new_recipients = f.recipients(&[("laptop-new", &dev_new.recipient())]);
    let outcome = f
        .keys
        .shred(
            "p-AAAA",
            &["p-AAAA", "p-BBBB"],
            &new_recipients,
            &f.operator_sk,
            &f.anchor,
            &f.device_id,
        )
        .unwrap();
    // phone was revoked before the shred but must still be named: its old
    // wrappings in history open A's historical data keys.
    assert!(
        outcome.destroy_key_ids.contains(&"phone".to_string()),
        "destroy list must include historically-present phone: {:?}",
        outcome.destroy_key_ids
    );
    assert!(outcome.destroy_key_ids.contains(&"laptop".to_string()));
}

// ---------------------------------------------------------------------------
// Test 9: recovery drill
// ---------------------------------------------------------------------------

#[test]
fn test9_recovery_drill() {
    let mut f = Fixture::new();
    let recipients = f.recipients(&[("laptop", &f.device_recipient)]);
    let key = f
        .keys
        .init_client(
            "p-01ABC",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();
    let old_phrase = f.recovery.phrase();

    // "Clean clone": recover using only the phrase.
    let recovered = Recovery::from_phrase(&old_phrase).unwrap();
    let rec_id = recovered.age_identity().to_age_identity().unwrap();
    let back = f
        .keys
        .unwrap_data_key("p-01ABC", "recovery", 1, &rec_id, &f.anchor)
        .unwrap();
    assert_eq!(back.as_bytes(), key.as_bytes());

    // Encrypt/decrypt works with the recovered key.
    let ctx = f.ctx("p-01ABC", "p-01ABC", "profile", 1);
    let bytes = encrypt_record(&ctx, &back, "person", false, b"after recovery").unwrap();
    assert_eq!(
        decrypt_record(&ctx, &back, &bytes, false).unwrap(),
        b"after recovery"
    );

    // Rotate to a new phrase; the old phrase stops working.
    let new_recovery = f
        .keys
        .rotate_recovery(&["p-01ABC"], &f.operator_sk, &f.anchor, &rec_id)
        .unwrap();
    assert_ne!(new_recovery.phrase(), old_phrase);
    // Old recovery identity can no longer unwrap.
    assert!(f
        .keys
        .unwrap_data_key("p-01ABC", "recovery", 1, &rec_id, &f.anchor)
        .is_err());
    // New one can.
    let new_id = new_recovery.age_identity().to_age_identity().unwrap();
    let back2 = f
        .keys
        .unwrap_data_key("p-01ABC", "recovery", 1, &new_id, &f.anchor)
        .unwrap();
    assert_eq!(back2.as_bytes(), key.as_bytes());
}

#[test]
fn test9b_recovery_key_signs_manifest() {
    // The recovery Ed25519 key (pinned in the anchor) alone can authorize
    // a manifest change — no operator key needed. This is what lets a
    // bare-phrase recovery authorize the new device's manifest (design §4).
    let mut f = Fixture::new();
    let recipients = f.recipients(&[("laptop", &f.device_recipient)]);
    f.keys
        .init_client(
            "p-01ABC",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    // Rotate, signing the new manifest with ONLY the recovery key.
    let rec_sk = f.recovery.signing_key().clone();
    let rotated = f
        .keys
        .rotate("p-01ABC", &f.recovery_recipient(), &rec_sk, &f.anchor)
        .unwrap();
    // Unwrap via the recovery identity (still valid — no rotate_recovery ran).
    let rec_id = f.recovery.age_identity().to_age_identity().unwrap();
    let back = f
        .keys
        .unwrap_data_key("p-01ABC", "recovery", 2, &rec_id, &f.anchor)
        .unwrap();
    assert_eq!(back.as_bytes(), rotated.as_bytes());
}

// ---------------------------------------------------------------------------
// Test 10: check without keys (structural envelope validation)
// ---------------------------------------------------------------------------

#[test]
fn test10_envelope_without_keys() {
    let f = Fixture::new();
    let key = DataKey::generate();
    let ctx = f.ctx("p-01ABC", "p-01ABC", "profile", 1);
    let bytes = encrypt_record(&ctx, &key, "person", true, b"secret").unwrap();

    // Structural validation needs no keys: parse + header checks only.
    let env = envelope::parse(&bytes).unwrap();
    assert_eq!(env.id, "p-01ABC");
    assert!(env.no_ai);
    assert!(envelope::check_header(&env, "p-01ABC", "p-01ABC", "profile", 1).is_ok());
    assert_eq!(purpose_for_type("person"), Some("profile"));
    assert_eq!(purpose_for_type("bogus"), None);

    // Malformed envelopes are rejected structurally.
    assert!(envelope::parse(b"not an envelope").is_err());
}

// ---------------------------------------------------------------------------
// Test 11: keep unchanged ciphertext (caller keeps bytes; re-encrypt differs)
// ---------------------------------------------------------------------------

#[test]
fn test11_reencrypt_produces_new_ciphertext() {
    // The crypt layer uses a fresh nonce per write, so byte-identical output
    // requires the caller to keep the old bytes — which is exactly what the
    // write path does for unchanged files (no diff churn).
    let f = Fixture::new();
    let key = DataKey::generate();
    let ctx = f.ctx("p-01ABC", "p-01ABC", "profile", 1);
    let a = encrypt_record(&ctx, &key, "person", false, b"same").unwrap();
    let b = encrypt_record(&ctx, &key, "person", false, b"same").unwrap();
    assert_ne!(a, b, "fresh nonce per write");
    // Both decrypt to the same plaintext.
    assert_eq!(decrypt_record(&ctx, &key, &a, false).unwrap(), b"same");
    assert_eq!(decrypt_record(&ctx, &key, &b, false).unwrap(), b"same");
}

// ---------------------------------------------------------------------------
// Test 13: never log the phrase (integration re-check)
// ---------------------------------------------------------------------------

#[test]
fn test13_never_log_phrase() {
    let r = Recovery::generate();
    let phrase = r.phrase();
    // Debug, Display of errors, and struct Debug impls never contain the phrase.
    let dbg = format!("{r:?}");
    assert!(dbg.contains("<redacted>"));
    assert!(!dbg.contains(&phrase), "phrase in Recovery Debug");
    let words: Vec<&str> = phrase.split_whitespace().collect();
    for w in words.windows(3) {
        assert!(!dbg.contains(&w.join(" ")), "phrase fragment in Debug");
    }
    // Error paths don't echo the phrase either.
    let err = Recovery::from_phrase("abandon abandon").unwrap_err();
    let msg = format!("{err}");
    assert!(!msg.contains("abandon") || msg.contains("24 words"));
}

// ---------------------------------------------------------------------------
// Test 14: header flip (especially no-ai true -> false)
// ---------------------------------------------------------------------------

#[test]
fn test14_header_flip() {
    let f = Fixture::new();
    let key = DataKey::generate();
    let ctx = f.ctx("p-01ABC", "p-01ABC", "profile", 3);
    let bytes = encrypt_record(&ctx, &key, "person", true, b"secret").unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();

    // Flip no-ai true -> false: decrypt must fail (header is in the AAD).
    let flipped = text.replacen("no-ai: true", "no-ai: false", 1);
    assert_ne!(flipped, text);
    assert!(decrypt_record(&ctx, &key, flipped.as_bytes(), false).is_err());

    // Flip id.
    let flipped = text.replacen("id: p-01ABC", "id: p-XXXXX", 1);
    assert!(decrypt_record(&ctx, &key, flipped.as_bytes(), false).is_err());

    // Flip type.
    let flipped = text.replacen("type: person", "type: note", 1);
    assert!(decrypt_record(&ctx, &key, flipped.as_bytes(), false).is_err());

    // Flip key_id epoch.
    let flipped = text.replacen("key_id: p-01ABC/e3", "key_id: p-01ABC/e9", 1);
    assert!(decrypt_record(&ctx, &key, flipped.as_bytes(), false).is_err());

    // no-ai: true records are withheld from agent output without decrypting,
    // even with the right key.
    assert!(matches!(
        decrypt_record(&ctx, &key, &bytes, true),
        Err(Error::Header(_))
    ));
}

// ---------------------------------------------------------------------------
// Test 15: rollback replay
// ---------------------------------------------------------------------------

struct FakeChecker {
    signers: std::collections::HashMap<String, Option<(char, String)>>,
}

impl SignerChecker for FakeChecker {
    fn commit_signature(&self, commit: &str) -> Result<Option<(char, String)>, Error> {
        Ok(self.signers.get(commit).cloned().flatten())
    }
}

#[test]
fn test15_rollback_replay_unsigned_refused() {
    // An older file version (valid AAD, stale no-ai: false) restored via an
    // UNSIGNED commit must be refused; the same restore via a trusted-signed
    // commit is honored.
    let checker = FakeChecker {
        signers: std::collections::HashMap::from([
            ("tip-signed".to_string(), Some(('G', "KEY1".to_string()))),
            ("v2-signed".to_string(), Some(('G', "KEY1".to_string()))),
            ("rollback-unsigned".to_string(), None),
        ]),
    };
    let trusted = vec!["KEY1".to_string()];

    // Unsigned rollback introducing the stale content -> hard error.
    let err = verify_history(
        &checker,
        &trusted,
        "tip-signed",
        &["rollback-unsigned".to_string()],
    )
    .unwrap_err();
    assert!(format!("{err}").contains("untrusted/unsigned"));

    // Same content via a trusted-signed commit -> honored.
    assert!(verify_history(&checker, &trusted, "tip-signed", &["v2-signed".to_string()]).is_ok());
}

fn git(repo: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test15_rollback_replay_real_git() {
    use confidant_crypt::history::GitSignerChecker;
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.email", "t@t"]);
    git(repo, &["config", "user.name", "t"]);
    git(repo, &["config", "commit.gpgsign", "false"]);

    // v1: stale no-ai: false. v2: no-ai: true. Then an UNSIGNED rollback to v1.
    std::fs::write(repo.join("rec.cfd"), "v1 no-ai false").unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "v1"]);
    std::fs::write(repo.join("rec.cfd"), "v2 no-ai true").unwrap();
    git(repo, &["commit", "-qam", "v2"]);
    git(repo, &["checkout", "-q", "HEAD~1", "--", "rec.cfd"]);
    git(repo, &["commit", "-qam", "rollback to v1"]);

    let tip = String::from_utf8(
        std::process::Command::new("git")
            .args(["-C", &repo.to_string_lossy(), "rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let tip = tip.trim().to_string();
    let rollback = String::from_utf8(
        std::process::Command::new("git")
            .args(["-C", &repo.to_string_lossy(), "rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let rollback = rollback.trim().to_string();
    assert_eq!(tip, rollback);

    let checker = GitSignerChecker::new(repo);
    // No signatures anywhere -> tip unsigned -> refused.
    let err = verify_history(&checker, &["KEY1".to_string()], &tip, &[rollback]).unwrap_err();
    assert!(format!("{err}").contains("not signed by a trusted key"));
}

#[test]
fn test15_merge_rollback_unsigned_side_refused() {
    // A SIGNED merge of an UNSIGNED rollback: the introducing walk must be
    // built with -m so the merge is included, and the unsigned side-branch
    // commit in the list is refused even though the merge itself is signed.
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path();
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.email", "test@example.com"]);
    git(repo, &["config", "user.name", "t"]);
    git(repo, &["config", "commit.gpgsign", "false"]);

    // main: v1 -> v2 (v2 has no-ai: true).
    std::fs::write(repo.join("rec.cfd"), "v1 no-ai false").unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "v1"]);
    std::fs::write(repo.join("rec.cfd"), "v2 no-ai true").unwrap();
    git(repo, &["commit", "-qam", "v2"]);

    // Side branch: unsigned rollback to v1 content.
    git(repo, &["checkout", "-qb", "side"]);
    git(repo, &["checkout", "-q", "HEAD~1", "--", "rec.cfd"]);
    git(repo, &["commit", "-qam", "unsigned rollback"]);
    let side = git_rev(repo, "HEAD");

    // SSH signing for the merge commit (throwaway key).
    let keydir = tempfile::tempdir().unwrap();
    let key = keydir.path().join("key");
    let gen = match std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-C", "test"])
        .arg("-f")
        .arg(&key)
        .output()
    {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping: ssh-keygen not installed");
            return;
        }
        Err(e) => panic!("spawning ssh-keygen failed: {e}"),
    };
    if !gen.status.success() {
        eprintln!("skipping: ssh-keygen unavailable");
        return;
    }
    let pubkey = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let allowed = keydir.path().join("allowed_signers");
    std::fs::write(
        &allowed,
        format!("test@example.com namespaces=\"git\" {pubkey}"),
    )
    .unwrap();
    let fp_out = std::process::Command::new("ssh-keygen")
        .args(["-lf"])
        .arg(&key)
        .output()
        .unwrap();
    let fp = String::from_utf8(fp_out.stdout).unwrap();
    let fingerprint = fp.split_whitespace().nth(1).unwrap().to_string();

    git(repo, &["checkout", "-q", "-"]);
    git(repo, &["config", "gpg.format", "ssh"]);
    git(repo, &["config", "user.signingkey", key.to_str().unwrap()]);
    git(
        repo,
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            allowed.to_str().unwrap(),
        ],
    );
    git(
        repo,
        &[
            "merge",
            "--no-ff",
            "-S",
            "-m",
            "signed merge of rollback",
            "side",
        ],
    );
    let merge_commit = git_rev(repo, "HEAD");

    // Without -m the merge commit's diff is suppressed: it does NOT appear
    // as touching the path (the hole).
    let plain = git_log_path(repo, false);
    assert!(
        !plain.contains(&merge_commit),
        "plain git log should miss the merge (documenting the hole)"
    );
    // With -m the merge IS included.
    let with_m = git_log_path(repo, true);
    assert!(
        with_m.contains(&merge_commit),
        "git log -m must include the merge commit"
    );
    assert!(with_m.contains(&side), "side commit must be listed");

    // The merge is signed by a trusted key, but the unsigned side commit in
    // the introducing list is refused.
    use confidant_crypt::history::GitSignerChecker;
    let checker = GitSignerChecker::new(repo);
    let err = verify_history(
        &checker,
        &[fingerprint],
        &merge_commit,
        &[merge_commit.clone(), side],
    )
    .unwrap_err();
    assert!(format!("{err}").contains("untrusted/unsigned"), "{err}");
}

fn git_rev(repo: &Path, rev: &str) -> String {
    String::from_utf8(
        std::process::Command::new("git")
            .args(["-C", &repo.to_string_lossy(), "rev-parse", rev])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string()
}

fn git_log_path(repo: &Path, with_m: bool) -> String {
    let mut args = vec!["log", "--format=%H"];
    if with_m {
        args.push("-m");
    }
    args.extend(["--end-of-options", "--", "rec.cfd"]);
    String::from_utf8(
        std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(&args)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Test 16: recovery public key pinning
// ---------------------------------------------------------------------------

#[test]
fn test16_recovery_pubkey_pinning() {
    let mut f = Fixture::new();

    // Attacker swaps the recovery public halves in a *vault config copy*.
    let evil_recovery = Recovery::generate();
    let evil_recipient = evil_recovery.age_identity().to_recipient_string();
    assert_ne!(evil_recipient, f.recovery_recipient());

    // Our code paths take the recovery recipient from the off-vault anchor,
    // never from a vault copy: init_client wraps to the anchor's recipient.
    let recipients = f.recipients(&[("laptop", &f.device_recipient)]);
    f.keys
        .init_client(
            "p-01ABC",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    // The attacker's recovery identity cannot unwrap (nothing was wrapped to it).
    let evil_id = evil_recovery.age_identity().to_age_identity().unwrap();
    assert!(f
        .keys
        .unwrap_data_key("p-01ABC", "recovery", 1, &evil_id, &f.anchor)
        .is_err());

    // The real recovery identity (matching the pinned anchor) can.
    let real_id = f.recovery.age_identity().to_age_identity().unwrap();
    assert!(f
        .keys
        .unwrap_data_key("p-01ABC", "recovery", 1, &real_id, &f.anchor)
        .is_ok());

    // Manifest verification uses the anchor's operator key; a manifest
    // "verified" against a swapped in-vault operator key is meaningless to us
    // because we never read operator keys from the vault.
    assert_eq!(
        f.anchor.recovery_age,
        f.recovery.age_identity().to_recipient_string()
    );
}

// ---------------------------------------------------------------------------
// Alias HMAC integration
// ---------------------------------------------------------------------------

#[test]
fn alias_hmac_round_trip() {
    let key = LookupKey::generate();
    let h = alias::alias_hmac(&key, "Alice@Example.com ");
    assert!(alias::matches(&key, "alice@example.com", &h));
    assert!(!alias::matches(&key, "bob@example.com", &h));
}

// ---------------------------------------------------------------------------
// DeviceKeypair sanity
// ---------------------------------------------------------------------------

#[test]
fn device_keypair_recipient_unwraps() {
    let kp = DeviceKeypair::generate();
    let recipient = kp.recipient();
    assert!(recipient.starts_with("age1"));
    let wrapped = age_wrap::wrap_to_recipient(b"data", &recipient).unwrap();
    let back = age_wrap::unwrap_with_raw_secret(&wrapped, kp.secret_bytes()).unwrap();
    assert_eq!(back, b"data");
}

// ---------------------------------------------------------------------------
// Legacy file-level API
// ---------------------------------------------------------------------------

#[test]
fn legacy_file_api_round_trip() {
    // Device key via env var (Bech32 identity).
    let id = age::x25519::Identity::generate();
    std::env::set_var("CONFIDANT_DEVICE_KEY", id.to_string().expose_secret());
    let ct = confidant_crypt::encrypt_file(b"file bytes").unwrap();
    let pt = confidant_crypt::decrypt_file(&ct).unwrap();
    assert_eq!(pt, b"file bytes");
    std::env::remove_var("CONFIDANT_DEVICE_KEY");
    // Without a key -> fail closed.
    assert!(confidant_crypt::decrypt_file(&ct).is_err());
}

// ---------------------------------------------------------------------------
// Key commitment regression tests (must-fix 1)
// ---------------------------------------------------------------------------

#[test]
fn test_commitment_planted_device_wrapping_refused() {
    let mut f = Fixture::new();
    let recipients = f.recipients(&[("laptop", &f.device_recipient)]);
    f.keys
        .init_client(
            "p-01ABC",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    // Attacker with push access plants a wrapping of an attacker-known key.
    let attacker_key = [0xAAu8; 32];
    let planted = age_wrap::wrap_to_recipient(&attacker_key, &f.device_recipient).unwrap();
    let keys_dir = f._tmp.path().join("keys");
    std::fs::write(
        keys_dir.join("p-01ABC").join("wrapped").join("laptop.age"),
        planted,
    )
    .unwrap();

    // Unwrap must fail closed: commitment mismatch, no key returned.
    match f
        .keys
        .unwrap_data_key("p-01ABC", "laptop", 1, &f.device_id, &f.anchor)
    {
        Err(Error::Manifest(_)) => {}
        Err(e) => panic!("expected Manifest error, got: {e:?}"),
        Ok(_) => panic!("planted device wrapping must be refused"),
    }
}

#[test]
fn test_commitment_planted_recovery_wrapping_refused() {
    let mut f = Fixture::new();
    let recipients = f.recipients(&[("laptop", &f.device_recipient)]);
    f.keys
        .init_client(
            "p-01ABC",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    // Plant a recovery wrapping of an attacker-known key.
    let attacker_key = [0xBBu8; 32];
    let planted = age_wrap::wrap_to_recipient(&attacker_key, &f.recovery_recipient()).unwrap();
    let keys_dir = f._tmp.path().join("keys");
    std::fs::write(
        keys_dir
            .join("p-01ABC")
            .join("wrapped")
            .join("recovery.age"),
        planted,
    )
    .unwrap();

    match f.keys.unwrap_data_key(
        "p-01ABC",
        "recovery",
        1,
        &f.recovery.age_identity().to_age_identity().unwrap(),
        &f.anchor,
    ) {
        Err(Error::Manifest(_)) => {}
        Err(e) => panic!("expected Manifest error, got: {e:?}"),
        Ok(_) => panic!("planted recovery wrapping must be refused"),
    }
}

#[test]
fn test_commitment_planted_lookup_age_refused() {
    let mut f = Fixture::new();
    // Fixture::new already ran init_lookup_key for the device recipient.

    // Plant a lookup.age wrapping of an attacker-known key.
    let attacker_key = [0xCCu8; 32];
    let planted = age_wrap::wrap_to_recipient(&attacker_key, &f.device_recipient).unwrap();
    let keys_dir = f._tmp.path().join("keys");
    std::fs::write(keys_dir.join("vault").join("lookup.age"), planted).unwrap();

    match f.keys.read_lookup_key(&f.device_id, &f.anchor) {
        Err(Error::Manifest(_)) => {}
        Err(e) => panic!("expected Manifest error, got: {e:?}"),
        Ok(_) => panic!("planted lookup.age must be refused"),
    }
}

// ---------------------------------------------------------------------------
// Key id charset regression tests (must-fix 4)
// ---------------------------------------------------------------------------

#[test]
fn test_revoke_recovery_reserved() {
    let mut f = Fixture::new();
    let recipients = f.recipients(&[("laptop", &f.device_recipient)]);
    f.keys
        .init_client(
            "p-01ABC",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    // "recovery" is reserved: revoke must reject it before touching anything.
    let err = f
        .keys
        .revoke("p-01ABC", &["recovery"], &f.operator_sk, &f.anchor)
        .expect_err("revoke([\"recovery\"]) must be rejected");
    assert!(
        matches!(err, Error::Manifest(_)),
        "expected Manifest error, got: {err:?}"
    );
    // The recovery wrapping must still be there.
    let keys_dir = f._tmp.path().join("keys");
    assert!(keys_dir
        .join("p-01ABC")
        .join("wrapped")
        .join("recovery.age")
        .exists());
}

#[test]
fn test_recipient_named_recovery_rejected() {
    // A recipient literally named "recovery" would collide with recovery.age.
    let mut map = RecipientMap::new();
    map.insert(
        "recovery".to_string(),
        RecipientEntry {
            age_pubkey: "age1fake".to_string(),
            label: "recovery".to_string(),
            scope_ref: String::new(),
        },
    );
    let err = confidant_crypt::manifest::to_toml(1, &map, &[])
        .expect_err("recipient named \"recovery\" must be rejected");
    assert!(
        matches!(err, Error::Manifest(_)),
        "expected Manifest error, got: {err:?}"
    );
}

#[test]
fn test_key_id_charset_rejects_dots_and_slashes() {
    for bad in ["agent.eu", "../", "UPPER", "with space", ""] {
        let mut map = RecipientMap::new();
        map.insert(
            bad.to_string(),
            RecipientEntry {
                age_pubkey: "age1fake".to_string(),
                label: bad.to_string(),
                scope_ref: String::new(),
            },
        );
        let err = confidant_crypt::manifest::to_toml(1, &map, &[])
            .expect_err(&format!("key id {bad:?} must be rejected"));
        assert!(
            matches!(err, Error::Manifest(_)),
            "expected Manifest error for {bad:?}, got: {err:?}"
        );
    }
    // Sanity: a valid id still works.
    let mut map = RecipientMap::new();
    map.insert(
        "laptop-2".to_string(),
        RecipientEntry {
            age_pubkey: "age1fake".to_string(),
            label: "laptop-2".to_string(),
            scope_ref: String::new(),
        },
    );
    assert!(confidant_crypt::manifest::to_toml(1, &map, &[]).is_ok());
}

// ---------------------------------------------------------------------------
// RecordCtx client_id regression tests (must-fix 2)
// ---------------------------------------------------------------------------

#[test]
fn test_note_round_trip_under_person_key() {
    // n-… records encrypt under the person's key (p-…/eN), per spec §1.
    let mut f = Fixture::new();
    let recipients = f.recipients(&[("laptop", &f.device_recipient)]);
    let key = f
        .keys
        .init_client(
            "p-01ABC",
            &recipients,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    let ctx = f.ctx("n-01NOTE", "p-01ABC", "note", 1);
    let bytes = encrypt_record(&ctx, &key, "note", false, b"note body").unwrap();

    // The key_id header names the person's key, not the note's id.
    let env = envelope::parse(&bytes).unwrap();
    assert_eq!(env.key_id, "p-01ABC/e1");

    // Round-trip with the person's key.
    let back = decrypt_record(&ctx, &key, &bytes, false).unwrap();
    assert_eq!(back, b"note body");
}

#[test]
fn test_note_under_a_key_fails_as_b() {
    // A note encrypted under client A's key must not decrypt as client B,
    // even with B's key (AAD binds the client id).
    let mut f = Fixture::new();
    let recipients_a = f.recipients(&[("laptop", &f.device_recipient)]);
    let key_a = f
        .keys
        .init_client(
            "p-AAAA",
            &recipients_a,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();
    let recipients_b = f.recipients(&[("laptop", &f.device_recipient)]);
    let key_b = f
        .keys
        .init_client(
            "p-BBBB",
            &recipients_b,
            &f.recovery_recipient(),
            &f.operator_sk,
        )
        .unwrap();

    let ctx_a = f.ctx("n-01NOTE", "p-AAAA", "note", 1);
    let bytes = encrypt_record(&ctx_a, &key_a, "note", false, b"note body").unwrap();

    // As client B: header check fails (key_id client != ctx client).
    let ctx_b = f.ctx("n-01NOTE", "p-BBBB", "note", 1);
    let err = decrypt_record(&ctx_b, &key_b, &bytes, false)
        .expect_err("note under A's key must fail as B");
    assert!(
        matches!(err, Error::Header(_)),
        "expected Header error, got: {err:?}"
    );
}
