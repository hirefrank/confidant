//! OS-keychain storage for the device key and the inbox key (#61).
//!
//! Per `docs/crypto-design.md` §2 and §8a.2, both keys live in the OS
//! keychain — macOS Keychain Services and Linux Secret Service, via the
//! `keyring` crate — and never in files. Linux uses keyring's pure-Rust
//! Secret Service backend (no system libdbus needed).
//!
//! The keys are distinct keychain items with different lifecycles:
//!
//! - **device key** (`confidant` / `device-key`): this device's age
//!   identity. Stable; used to unwrap per-client data keys.
//! - **inbox key** (`confidant-inbox` / `inbox-key`): the vault-wide inbox
//!   keypair's private half. Rotates on every `keys shred` and on inbox
//!   device revocation/compromise; it is never wrapped into `keys/` and
//!   never leaves the inbox device's keychain.
//! - **previous inbox key** (`confidant-inbox` / `inbox-key-previous`):
//!   the old private half during the rotation window (§8a.3). `inbox
//!   rotate` moves the current key here before installing the new one, so
//!   in-flight items ("tries old then new") stay drainable; `inbox rotate
//!   --finish` deletes it.
//!
//! Resolution order for each slot:
//! 1. `${CONFIDANT_DEVICE_KEY}` / `${CONFIDANT_INBOX_KEY}` /
//!    `${CONFIDANT_INBOX_KEY_PREVIOUS}` env var (tests, CI, agent hosts).
//! 2. The OS keychain.
//! 3. Otherwise fail closed ([`Error::NoKey`]).
//!
//! Before any of that: if a legacy plaintext key file
//! (`~/.config/confidant/device.key` or `inbox.key`) exists, loading
//! **refuses** with instructions to import the key into the keychain and
//! delete the file. Confidant never reads plaintext key files, and never
//! silently keeps using one.
//!
//! Headless Linux: Secret Service needs a D-Bus session bus. On headless
//! hosts the keychain is unreachable (keyring reports no storage access)
//! — use the env-var overrides there. macOS always has a keychain.
//!
//! Everything is stored as the age identity's Bech32 encoding
//! (`AGE-SECRET-KEY-1…`), the same format the env vars take, so keychain
//! and env var are interchangeable.
//!
//! ## Test isolation
//!
//! The keychain is behind [`KeychainBackend`]: the real OS keychain in
//! production, an in-memory map in tests. Unit tests never touch the real
//! keychain or the real `$HOME` — the config dir is passed in, and
//! `MemoryKeychain` stands in for the OS store. (`keyring`'s built-in mock
//! does not share state between separate `Entry::new` calls, so it cannot
//! do a store→load→delete round trip.)
//!
//! ## Zeroization
//!
//! Key material is [`Zeroizing`]-wrapped from the moment it exists in this
//! module: the `std::env::var` / `get_password()` `String` is wrapped
//! immediately, trimmed through the wrapper (no extra copy), and the one
//! unavoidable copy — the trimmed bytes moved into the returned
//! `Zeroizing<Vec<u8>>` — is itself zeroized on drop. Copies made
//! *inside* the `keyring` crate (e.g. its own `String` buffers) are
//! outside this module's control.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use keyring::Entry;
use zeroize::Zeroizing;

use crate::Error;

/// Keychain service name for the device age identity.
pub const DEVICE_SERVICE: &str = "confidant";
/// Keychain account name for the device age identity.
pub const DEVICE_ACCOUNT: &str = "device-key";
/// Keychain service name for the inbox keypair's private half.
pub const INBOX_SERVICE: &str = "confidant-inbox";
/// Keychain account name for the inbox keypair's private half.
pub const INBOX_ACCOUNT: &str = "inbox-key";
/// Keychain account name for the previous inbox key, kept during the
/// rotation window (§8a.3) so in-flight items stay drainable.
pub const INBOX_PREVIOUS_ACCOUNT: &str = "inbox-key-previous";

/// Env-var override for the device key (tests, CI, agent hosts).
pub const DEVICE_KEY_ENV: &str = "CONFIDANT_DEVICE_KEY";
/// Env-var override for the inbox key (tests, CI, agent hosts).
pub const INBOX_KEY_ENV: &str = "CONFIDANT_INBOX_KEY";
/// Env-var override for the previous inbox key (tests).
pub const INBOX_KEY_PREVIOUS_ENV: &str = "CONFIDANT_INBOX_KEY_PREVIOUS";

/// Legacy plaintext device-key file. Its presence is a hard error, never
/// a fallback — see the module docs.
const LEGACY_DEVICE_FILE: &str = "device.key";
/// Legacy plaintext inbox-key file. Its presence is a hard error, never
/// a fallback — see the module docs.
const LEGACY_INBOX_FILE: &str = "inbox.key";

/// The inbox keypair's private half as `(current, previous)`. `previous`
/// is `Some` only during the rotation window (§8a.3).
pub type InboxKeys = (Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>);

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// How key material is read and written. The production backend is the
/// real OS keychain; tests use an in-memory map so they never touch the
/// real keychain.
trait KeychainBackend {
    fn get_password(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<Zeroizing<String>>, Error>;
    fn set_password(&self, service: &str, account: &str, password: &str) -> Result<(), Error>;
    fn delete_credential(&self, service: &str, account: &str) -> Result<(), Error>;
}

/// The production backend: the real OS keychain via `keyring`.
struct OsKeychain;

impl KeychainBackend for OsKeychain {
    fn get_password(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<Zeroizing<String>>, Error> {
        let entry = Entry::new(service, account).map_err(|e| {
            Error::Keychain(format!(
                "cannot open keychain entry {service}/{account}: {e}"
            ))
        })?;
        match entry.get_password() {
            // Wrap immediately: the only copy of this String this module
            // ever holds is zeroized on drop.
            Ok(s) => Ok(Some(Zeroizing::new(s))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::Keychain(format!(
                "OS keychain read failed ({service}/{account}): {e}"
            ))),
        }
    }

    fn set_password(&self, service: &str, account: &str, password: &str) -> Result<(), Error> {
        let entry = Entry::new(service, account).map_err(|e| {
            Error::Keychain(format!(
                "cannot open keychain entry {service}/{account}: {e}"
            ))
        })?;
        entry.set_password(password).map_err(|e| {
            Error::Keychain(format!(
                "OS keychain write failed ({service}/{account}): {e}"
            ))
        })
    }

    fn delete_credential(&self, service: &str, account: &str) -> Result<(), Error> {
        let entry = Entry::new(service, account).map_err(|e| {
            Error::Keychain(format!(
                "cannot open keychain entry {service}/{account}: {e}"
            ))
        })?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(Error::Keychain(format!(
                "OS keychain delete failed ({service}/{account}): {e}"
            ))),
        }
    }
}

/// In-memory backend for tests. `keyring`'s built-in mock does not share
/// state between separate `Entry::new` calls, so it cannot do a
/// store→load→delete round trip; this one can.
#[cfg(test)]
struct MemoryKeychain {
    map: std::sync::Mutex<std::collections::HashMap<(String, String), String>>,
}

#[cfg(test)]
impl MemoryKeychain {
    fn new() -> Self {
        MemoryKeychain {
            map: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[cfg(test)]
impl KeychainBackend for MemoryKeychain {
    fn get_password(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<Zeroizing<String>>, Error> {
        let key = (service.to_string(), account.to_string());
        Ok(self
            .map
            .lock()
            .expect("memory keychain lock")
            .get(&key)
            .cloned()
            .map(Zeroizing::new))
    }

    fn set_password(&self, service: &str, account: &str, password: &str) -> Result<(), Error> {
        let key = (service.to_string(), account.to_string());
        self.map
            .lock()
            .expect("memory keychain lock")
            .insert(key, password.to_string());
        Ok(())
    }

    fn delete_credential(&self, service: &str, account: &str) -> Result<(), Error> {
        let key = (service.to_string(), account.to_string());
        self.map.lock().expect("memory keychain lock").remove(&key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load the device key's Bech32 age identity (`AGE-SECRET-KEY-1…`),
/// zeroized. Env var → OS keychain → fail closed. Refuses when a legacy
/// plaintext `device.key` file exists.
pub fn device_key() -> Result<Zeroizing<Vec<u8>>, Error> {
    load_key(
        &OsKeychain,
        config_dir().as_deref(),
        DEVICE_SERVICE,
        DEVICE_ACCOUNT,
        DEVICE_KEY_ENV,
        LEGACY_DEVICE_FILE,
        "device key",
    )
}

/// Load the inbox key's Bech32 age identity (`AGE-SECRET-KEY-1…`),
/// zeroized. Env var → OS keychain → fail closed. Refuses when a legacy
/// plaintext `inbox.key` file exists.
pub fn inbox_key() -> Result<Zeroizing<Vec<u8>>, Error> {
    load_key(
        &OsKeychain,
        config_dir().as_deref(),
        INBOX_SERVICE,
        INBOX_ACCOUNT,
        INBOX_KEY_ENV,
        LEGACY_INBOX_FILE,
        "inbox key",
    )
}

/// Load the inbox keypair's private half as `(current, previous)`.
/// `previous` is `Some` during the rotation window (§8a.3): `inbox rotate`
/// moves the old key there before installing the new one ("tries old then
/// new"), and `inbox rotate --finish` deletes it. Each slot resolves
/// independently: env var, then the OS keychain, then absent.
pub fn inbox_keys() -> Result<InboxKeys, Error> {
    inbox_keys_with(&OsKeychain, config_dir().as_deref())
}

fn inbox_keys_with(
    backend: &dyn KeychainBackend,
    config_dir: Option<&Path>,
) -> Result<InboxKeys, Error> {
    let current = load_key(
        backend,
        config_dir,
        INBOX_SERVICE,
        INBOX_ACCOUNT,
        INBOX_KEY_ENV,
        LEGACY_INBOX_FILE,
        "inbox key",
    )?;
    let previous = load_key_opt(
        backend,
        config_dir,
        INBOX_SERVICE,
        INBOX_PREVIOUS_ACCOUNT,
        INBOX_KEY_PREVIOUS_ENV,
        LEGACY_INBOX_FILE,
        "previous inbox key",
    )?;
    Ok((current, previous))
}

/// Parse [`device_key`] into an age identity for decryption.
pub fn device_identity() -> Result<age::x25519::Identity, Error> {
    parse_identity(&device_key()?, "device key")
}

/// Parse [`inbox_key`] into an age identity for decryption. This is the
/// decrypt entry point used by the inbox clear path.
pub fn inbox_identity() -> Result<age::x25519::Identity, Error> {
    parse_identity(&inbox_key()?, "inbox key")
}

/// Parse both inbox slots into age identities for decryption ("tries old
/// then new", §8a.3).
pub fn inbox_identities() -> Result<(age::x25519::Identity, Option<age::x25519::Identity>), Error> {
    let (current, previous) = inbox_keys()?;
    let current = parse_identity(&current, "inbox key")?;
    let previous = previous
        .map(|p| parse_identity(&p, "previous inbox key"))
        .transpose()?;
    Ok((current, previous))
}

fn load_key(
    backend: &dyn KeychainBackend,
    config_dir: Option<&Path>,
    service: &str,
    account: &str,
    env_var: &str,
    legacy_file: &str,
    what: &str,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    load_key_opt(
        backend,
        config_dir,
        service,
        account,
        env_var,
        legacy_file,
        what,
    )?
    .ok_or_else(|| {
        Error::NoKey(format!(
            "no {what}: not in the OS keychain ({service}/{account}) and {env_var} is not set"
        ))
    })
}

fn load_key_opt(
    backend: &dyn KeychainBackend,
    config_dir: Option<&Path>,
    service: &str,
    account: &str,
    env_var: &str,
    legacy_file: &str,
    what: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    // A plaintext key file on disk is never used — refuse loudly so the
    // operator imports it into the keychain and deletes it.
    if let Some(dir) = config_dir {
        refuse_if_legacy_file(dir, legacy_file, service, account, what)?;
    }

    if let Ok(raw) = std::env::var(env_var) {
        // Wrap the env String immediately so it is zeroized on drop;
        // trim through the wrapper, so the only other copy is the
        // returned zeroized Vec.
        let raw = Zeroizing::new(raw);
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            validate_bech32(trimmed, what, env_var)?;
            return Ok(Some(Zeroizing::new(trimmed.as_bytes().to_vec())));
        }
    }

    match backend.get_password(service, account)? {
        Some(raw) => {
            let trimmed = raw.trim();
            validate_bech32(trimmed, what, &format!("keychain {service}/{account}"))?;
            Ok(Some(Zeroizing::new(trimmed.as_bytes().to_vec())))
        }
        None => Ok(None),
    }
}

fn parse_identity(raw: &[u8], what: &str) -> Result<age::x25519::Identity, Error> {
    let s = std::str::from_utf8(raw)
        .map_err(|e| Error::Age(format!("{what} is not valid UTF-8: {e}")))?;
    age::x25519::Identity::from_str(s.trim()).map_err(|e| Error::Age(format!("bad {what}: {e}")))
}

/// Check that `s` parses as an age X25519 identity before we store or
/// trust it. `source` names where the value came from, for errors.
fn validate_bech32(s: &str, what: &str, source: &str) -> Result<(), Error> {
    age::x25519::Identity::from_str(s)
        .map(|_| ())
        .map_err(|e| Error::Age(format!("bad {what} from {source}: {e}")))
}

// ---------------------------------------------------------------------------
// Storing / deleting (for `init`, `inbox rotate`, etc.)
// ---------------------------------------------------------------------------

/// Store the device key in the OS keychain. `bech32` must be the
/// `AGE-SECRET-KEY-1…` encoding; anything else is refused before it
/// touches the keychain.
pub fn store_device_key(bech32: &str) -> Result<(), Error> {
    store_key(
        &OsKeychain,
        DEVICE_SERVICE,
        DEVICE_ACCOUNT,
        bech32.trim(),
        "device key",
    )
}

/// Store the inbox key in the OS keychain. `bech32` must be the
/// `AGE-SECRET-KEY-1…` encoding; anything else is refused before it
/// touches the keychain.
pub fn store_inbox_key(bech32: &str) -> Result<(), Error> {
    store_key(
        &OsKeychain,
        INBOX_SERVICE,
        INBOX_ACCOUNT,
        bech32.trim(),
        "inbox key",
    )
}

/// Store the previous inbox key (the rotation-window slot, §8a.3).
pub fn store_inbox_key_previous(bech32: &str) -> Result<(), Error> {
    store_key(
        &OsKeychain,
        INBOX_SERVICE,
        INBOX_PREVIOUS_ACCOUNT,
        bech32.trim(),
        "previous inbox key",
    )
}

/// Delete the device key from the OS keychain. Deleting a key that is
/// not there is a no-op.
pub fn delete_device_key() -> Result<(), Error> {
    delete_key(&OsKeychain, DEVICE_SERVICE, DEVICE_ACCOUNT, "device key")
}

/// Delete the inbox key from the OS keychain. Deleting a key that is
/// not there is a no-op.
pub fn delete_inbox_key() -> Result<(), Error> {
    delete_key(&OsKeychain, INBOX_SERVICE, INBOX_ACCOUNT, "inbox key")
}

/// Delete the previous inbox key. Deleting a key that is not there is a
/// no-op.
pub fn delete_inbox_key_previous() -> Result<(), Error> {
    delete_key(
        &OsKeychain,
        INBOX_SERVICE,
        INBOX_PREVIOUS_ACCOUNT,
        "previous inbox key",
    )
}

/// Rotate the inbox key (§8a.3): move the current key into the previous
/// slot (if there is one) so in-flight items stay drainable, then install
/// `new_bech32` as the current key. `inbox rotate --finish` later calls
/// [`delete_inbox_key_previous`].
pub fn rotate_inbox_key(new_bech32: &str) -> Result<(), Error> {
    rotate_inbox_key_with(&OsKeychain, config_dir().as_deref(), new_bech32)
}

fn rotate_inbox_key_with(
    backend: &dyn KeychainBackend,
    config_dir: Option<&Path>,
    new_bech32: &str,
) -> Result<(), Error> {
    // Validate the new key before touching anything.
    let new_bech32 = new_bech32.trim();
    validate_bech32(new_bech32, "inbox key", "caller")?;
    // Preserve the current key in the previous slot so items encrypted to
    // it stay drainable ("tries old then new"). When the current key comes
    // from the env var (tests), the env value is what gets preserved.
    if let Some(current) = load_key_opt(
        backend,
        config_dir,
        INBOX_SERVICE,
        INBOX_ACCOUNT,
        INBOX_KEY_ENV,
        LEGACY_INBOX_FILE,
        "inbox key",
    )? {
        let current_str = std::str::from_utf8(&current)
            .map_err(|e| Error::Age(format!("current inbox key is not valid UTF-8: {e}")))?;
        store_key(
            backend,
            INBOX_SERVICE,
            INBOX_PREVIOUS_ACCOUNT,
            current_str,
            "previous inbox key",
        )?;
    }
    store_key(
        backend,
        INBOX_SERVICE,
        INBOX_ACCOUNT,
        new_bech32,
        "inbox key",
    )
}

fn store_key(
    backend: &dyn KeychainBackend,
    service: &str,
    account: &str,
    bech32: &str,
    what: &str,
) -> Result<(), Error> {
    validate_bech32(bech32, what, "caller")?;
    backend.set_password(service, account, bech32).map_err(|e| {
        // `set_password` already wraps backend errors; keep the `what`
        // context uniform here.
        match e {
            Error::Keychain(msg) => Error::Keychain(format!("{what}: {msg}")),
            other => other,
        }
    })
}

fn delete_key(
    backend: &dyn KeychainBackend,
    service: &str,
    account: &str,
    what: &str,
) -> Result<(), Error> {
    backend
        .delete_credential(service, account)
        .map_err(|e| match e {
            Error::Keychain(msg) => Error::Keychain(format!("{what}: {msg}")),
            other => other,
        })
}

// ---------------------------------------------------------------------------
// Legacy plaintext-file refusal
// ---------------------------------------------------------------------------

/// `~/.config/confidant`, the operator config dir. `None` when `HOME`
/// is unset (then there is no legacy file to find).
fn config_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join("confidant"))
}

/// Refuse when a legacy plaintext key file exists. This is checked
/// before the env var and the keychain: a stray plaintext secret must
/// never be silently ignored while another source is used.
fn refuse_if_legacy_file(
    config_dir: &Path,
    file_name: &str,
    service: &str,
    account: &str,
    what: &str,
) -> Result<(), Error> {
    let path = config_dir.join(file_name);
    // `is_file` (not `exists`): a dangling symlink or directory named
    // `device.key` is not a readable secret; only a real file refuses.
    if path.is_file() {
        return Err(Error::Keychain(format!(
            "refusing to load {what}: legacy plaintext key file exists at {}. \
             Import it into the OS keychain (service \"{service}\", account \"{account}\") \
             and delete the file. Confidant never reads plaintext key files \
             (docs/crypto-design.md §2).",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    /// Serializes env-var access: tests in this module share the process,
    /// so each test takes the lock once and the guard restores every var
    /// it touched on drop.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn lock() -> Self {
            EnvGuard {
                saved: Vec::new(),
                _lock: ENV_LOCK.lock().unwrap(),
            }
        }
        fn set(&mut self, key: &'static str, val: &str) {
            // Save once: repeated sets of the same key restore the
            // pre-test value, not an intermediate one.
            if !self.saved.iter().any(|(k, _)| *k == key) {
                self.saved.push((key, std::env::var(key).ok()));
            }
            std::env::set_var(key, val);
        }
        fn unset(&mut self, key: &'static str) {
            if !self.saved.iter().any(|(k, _)| *k == key) {
                self.saved.push((key, std::env::var(key).ok()));
            }
            std::env::remove_var(key);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, prev) in self.saved.drain(..) {
                match prev {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn fresh_identity_bech32() -> String {
        age::x25519::Identity::generate()
            .to_string()
            .expose_secret()
            .to_owned()
    }

    /// A hermetic loading context: in-memory keychain plus a temp config
    /// dir. Nothing here touches the real OS keychain or the real `$HOME`.
    struct Harness {
        backend: MemoryKeychain,
        dir: tempfile::TempDir,
    }

    impl Harness {
        fn new() -> Self {
            Harness {
                backend: MemoryKeychain::new(),
                dir: tempfile::tempdir().unwrap(),
            }
        }
        fn dir(&self) -> Option<&Path> {
            Some(self.dir.path())
        }
        fn load_device(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
            load_key(
                &self.backend,
                self.dir(),
                DEVICE_SERVICE,
                DEVICE_ACCOUNT,
                DEVICE_KEY_ENV,
                LEGACY_DEVICE_FILE,
                "device key",
            )
        }
        fn load_inbox(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
            load_key(
                &self.backend,
                self.dir(),
                INBOX_SERVICE,
                INBOX_ACCOUNT,
                INBOX_KEY_ENV,
                LEGACY_INBOX_FILE,
                "inbox key",
            )
        }
        fn load_inbox_keys(&self) -> Result<InboxKeys, Error> {
            inbox_keys_with(&self.backend, self.dir())
        }
        fn store_inbox(&self, bech32: &str) {
            store_key(
                &self.backend,
                INBOX_SERVICE,
                INBOX_ACCOUNT,
                bech32,
                "inbox key",
            )
            .unwrap();
        }
        fn rotate(&self, new_bech32: &str) {
            rotate_inbox_key_with(&self.backend, self.dir(), new_bech32).unwrap();
        }
        fn finish(&self) {
            delete_key(
                &self.backend,
                INBOX_SERVICE,
                INBOX_PREVIOUS_ACCOUNT,
                "previous inbox key",
            )
            .unwrap();
        }
    }

    #[test]
    fn device_key_loads_from_env() {
        let bech32 = fresh_identity_bech32();
        let mut _g = EnvGuard::lock();
        _g.set(DEVICE_KEY_ENV, &bech32);
        let raw = device_key().expect("env var set");
        assert_eq!(raw.as_slice(), bech32.as_bytes());
        let id = device_identity().expect("env var set");
        assert_eq!(id.to_public().to_string(), bech32_public(&bech32));
    }

    #[test]
    fn inbox_key_loads_from_env() {
        let bech32 = fresh_identity_bech32();
        let mut _g = EnvGuard::lock();
        _g.set(INBOX_KEY_ENV, &bech32);
        let raw = inbox_key().expect("env var set");
        assert_eq!(raw.as_slice(), bech32.as_bytes());
        let id = inbox_identity().expect("env var set");
        assert_eq!(id.to_public().to_string(), bech32_public(&bech32));
    }

    #[test]
    fn device_and_inbox_are_independent() {
        let d = fresh_identity_bech32();
        let i = fresh_identity_bech32();
        let mut _g = EnvGuard::lock();
        _g.set(DEVICE_KEY_ENV, &d);
        _g.set(INBOX_KEY_ENV, &i);
        assert_ne!(
            device_key().unwrap().as_slice(),
            inbox_key().unwrap().as_slice()
        );
        // A device key must not decrypt inbox-key material and vice versa:
        // the identities differ.
        assert_ne!(
            device_identity().unwrap().to_public().to_string(),
            inbox_identity().unwrap().to_public().to_string()
        );
    }

    #[test]
    fn bad_env_value_fails_closed() {
        let mut _g = EnvGuard::lock();
        _g.set(DEVICE_KEY_ENV, "not-a-key");
        let h = Harness::new();
        let err = h.load_device().unwrap_err();
        assert!(matches!(err, Error::Age(_)), "unexpected: {err:?}");
    }

    #[test]
    fn empty_env_falls_through_to_backend() {
        // Empty env var is treated as unset: the backend is consulted.
        let bech32 = fresh_identity_bech32();
        let h = Harness::new();
        h.store_inbox(&bech32);
        let mut _g = EnvGuard::lock();
        _g.set(INBOX_KEY_ENV, "");
        let raw = h.load_inbox().expect("backend has the key");
        assert_eq!(raw.as_slice(), bech32.as_bytes());
    }

    #[test]
    fn no_key_anywhere_fails_closed() {
        // Hermetic: empty in-memory backend, empty temp config dir, env
        // vars unset. Must fail closed — never Ok, never plaintext — and
        // never touch the real OS keychain.
        let h = Harness::new();
        let mut _g = EnvGuard::lock();
        _g.unset(DEVICE_KEY_ENV);
        _g.unset(INBOX_KEY_ENV);
        let err = h.load_device().unwrap_err();
        assert!(matches!(err, Error::NoKey(_)), "unexpected: {err:?}");
        let err = h.load_inbox().unwrap_err();
        assert!(matches!(err, Error::NoKey(_)), "unexpected: {err:?}");
    }

    #[test]
    fn store_load_delete_round_trip() {
        let bech32 = fresh_identity_bech32();
        let h = Harness::new();
        store_key(
            &h.backend,
            DEVICE_SERVICE,
            DEVICE_ACCOUNT,
            &bech32,
            "device key",
        )
        .unwrap();
        let raw = h.load_device().expect("just stored");
        assert_eq!(raw.as_slice(), bech32.as_bytes());
        delete_key(&h.backend, DEVICE_SERVICE, DEVICE_ACCOUNT, "device key").unwrap();
        let err = h.load_device().unwrap_err();
        assert!(matches!(err, Error::NoKey(_)), "unexpected: {err:?}");
        // Deleting again is a no-op.
        delete_key(&h.backend, DEVICE_SERVICE, DEVICE_ACCOUNT, "device key").unwrap();
    }

    #[test]
    fn legacy_file_refuses_even_with_valid_env_var() {
        // The refusal is checked through `load_key`, with a valid env var
        // set: the stray plaintext file must still refuse.
        let bech32 = fresh_identity_bech32();
        let h = Harness::new();
        std::fs::write(h.dir.path().join(LEGACY_DEVICE_FILE), &bech32).unwrap();
        let mut _g = EnvGuard::lock();
        _g.set(DEVICE_KEY_ENV, &bech32);
        let err = h.load_device().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("legacy plaintext key file"), "{msg}");
        assert!(msg.contains("delete the file"), "{msg}");
    }

    #[test]
    fn legacy_inbox_file_refuses() {
        let h = Harness::new();
        std::fs::write(h.dir.path().join(LEGACY_INBOX_FILE), "whatever").unwrap();
        let err = h.load_inbox().unwrap_err();
        assert!(err.to_string().contains("legacy plaintext key file"));
    }

    #[test]
    fn no_legacy_file_is_fine() {
        let h = Harness::new();
        refuse_if_legacy_file(
            h.dir.path(),
            LEGACY_DEVICE_FILE,
            DEVICE_SERVICE,
            DEVICE_ACCOUNT,
            "device key",
        )
        .expect("no file → no refusal");
    }

    #[test]
    fn previous_slot_rotation_sequence() {
        // §8a.3: rotate moves current→previous and installs the new key;
        // --finish deletes previous. All through the loader.
        let old = fresh_identity_bech32();
        let new = fresh_identity_bech32();
        let h = Harness::new();
        let mut _g = EnvGuard::lock();
        _g.unset(INBOX_KEY_ENV);
        _g.unset(INBOX_KEY_PREVIOUS_ENV);

        h.store_inbox(&old);
        h.rotate(&new);

        let (current, previous) = h.load_inbox_keys().expect("after rotate");
        assert_eq!(current.as_slice(), new.as_bytes());
        assert_eq!(previous.expect("previous kept").as_slice(), old.as_bytes());

        h.finish();
        let (current, previous) = h.load_inbox_keys().expect("after finish");
        assert_eq!(current.as_slice(), new.as_bytes());
        assert!(previous.is_none(), "previous deleted by --finish");
    }

    #[test]
    fn rotate_with_no_current_installs_new() {
        let new = fresh_identity_bech32();
        let h = Harness::new();
        let mut _g = EnvGuard::lock();
        _g.unset(INBOX_KEY_ENV);
        _g.unset(INBOX_KEY_PREVIOUS_ENV);

        h.rotate(&new);
        let (current, previous) = h.load_inbox_keys().expect("after rotate");
        assert_eq!(current.as_slice(), new.as_bytes());
        assert!(previous.is_none());
    }

    #[test]
    fn rotate_preserves_env_provided_current() {
        // When the current key comes from the env var (tests), the env
        // value is what moves into the previous slot.
        let old = fresh_identity_bech32();
        let new = fresh_identity_bech32();
        let h = Harness::new();
        let mut _g = EnvGuard::lock();
        _g.set(INBOX_KEY_ENV, &old);
        _g.unset(INBOX_KEY_PREVIOUS_ENV);

        h.rotate(&new);
        // The env var still points at the old key; clear it so the loader
        // reads what rotate actually wrote to the backend.
        _g.unset(INBOX_KEY_ENV);
        let (current, previous) = h.load_inbox_keys().expect("after rotate");
        assert_eq!(current.as_slice(), new.as_bytes());
        assert_eq!(previous.expect("previous kept").as_slice(), old.as_bytes());
    }

    #[test]
    fn previous_slot_env_override() {
        let cur = fresh_identity_bech32();
        let prev = fresh_identity_bech32();
        let h = Harness::new();
        let mut _g = EnvGuard::lock();
        _g.set(INBOX_KEY_ENV, &cur);
        _g.set(INBOX_KEY_PREVIOUS_ENV, &prev);

        let (current, previous) = h.load_inbox_keys().expect("env overrides");
        assert_eq!(current.as_slice(), cur.as_bytes());
        assert_eq!(previous.expect("env previous").as_slice(), prev.as_bytes());
    }

    #[test]
    fn bad_previous_value_fails_closed() {
        let cur = fresh_identity_bech32();
        let h = Harness::new();
        let mut _g = EnvGuard::lock();
        _g.set(INBOX_KEY_ENV, &cur);
        _g.set(INBOX_KEY_PREVIOUS_ENV, "not-a-key");
        let err = h.load_inbox_keys().unwrap_err();
        assert!(matches!(err, Error::Age(_)), "unexpected: {err:?}");
    }

    #[test]
    fn keychain_items_are_distinct() {
        assert_ne!(DEVICE_SERVICE, INBOX_SERVICE);
        assert_ne!(DEVICE_ACCOUNT, INBOX_ACCOUNT);
        assert_ne!(INBOX_ACCOUNT, INBOX_PREVIOUS_ACCOUNT);
        assert_ne!(
            (DEVICE_SERVICE, DEVICE_ACCOUNT),
            (INBOX_SERVICE, INBOX_ACCOUNT)
        );
        assert_ne!(
            (INBOX_SERVICE, INBOX_ACCOUNT),
            (INBOX_SERVICE, INBOX_PREVIOUS_ACCOUNT)
        );
    }

    #[test]
    fn store_validates_before_touching_keychain() {
        // Invalid Bech32 is refused before any keychain write is attempted.
        let h = Harness::new();
        let err = store_key(
            &h.backend,
            DEVICE_SERVICE,
            DEVICE_ACCOUNT,
            "not-a-key",
            "device key",
        )
        .unwrap_err();
        assert!(matches!(err, Error::Age(_)), "unexpected: {err:?}");
        // Nothing was written.
        assert!(h.load_device().is_err());
        let err = store_key(
            &h.backend,
            INBOX_SERVICE,
            INBOX_PREVIOUS_ACCOUNT,
            "",
            "previous inbox key",
        )
        .unwrap_err();
        assert!(matches!(err, Error::Age(_)), "unexpected: {err:?}");
    }

    fn bech32_public(bech32: &str) -> String {
        age::x25519::Identity::from_str(bech32)
            .unwrap()
            .to_public()
            .to_string()
    }
}
