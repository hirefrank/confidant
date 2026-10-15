//! Encrypted file envelope: plaintext front matter + base64 ciphertext.
//!
//! ```markdown
//! ---
//! id: p-01M3TC5H00MPJG000000000000
//! type: person
//! no-ai: false
//! enc: xchacha20poly1305
//! key_id: p-01M3TC5H00MPJG000000000000/e3
//! nonce: base64(24 bytes)
//! ---
//! <base64 ciphertext of the inner record>
//! ```
//!
//! The outer header is authenticated via the AAD (see [`crate::aead`]):
//! flipping any header field with only git write access fails decryption.
//! `check` validates the envelope structurally without keys.

use base64::prelude::*;

use crate::aead::ALG;
use crate::error::Error;

/// A parsed encrypted-file envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Opaque record id (`p-<ULID>`).
    pub id: String,
    /// Record type: `person`, `note`, `interaction`, `org`, `deal`.
    pub record_type: String,
    /// AI opt-out flag. Plaintext so `find`/`context` fail closed without keys.
    pub no_ai: NoAi,
    /// AEAD algorithm; must be [`ALG`].
    pub enc: String,
    /// Key id: `<client-id>/e<epoch>`.
    pub key_id: String,
    /// Key epoch parsed from `key_id`.
    pub epoch: u64,
    /// 24-byte nonce.
    pub nonce: Vec<u8>,
    /// Raw ciphertext bytes.
    pub ciphertext: Vec<u8>,
}

/// Map an envelope `type` to its AAD `purpose`. Each type maps to exactly
/// one purpose (design §5).
pub fn purpose_for_type(record_type: &str) -> Option<&'static str> {
    match record_type {
        "person" => Some("profile"),
        "note" => Some("note"),
        "interaction" => Some("interaction"),
        "org" => Some("org"),
        "deal" => Some("deal"),
        "edge" => Some("edge"),
        _ => None,
    }
}

/// Tri-state AI opt-out for the envelope outer header (issue #181).
///
/// - `False` (`no-ai: false`): the record is visible to agents.
/// - `True` (`no-ai: true`): the record is hidden from agents — never
///   decrypted on agent paths, loaded as a shell, excluded from the
///   allowlist.
/// - `Notes` (`no-ai: notes`): only valid on `person` records. The person
///   record itself stays visible to agents, but their notes and
///   interactions default to hidden unless a child sets an explicit
///   `no-ai: true`/`false`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoAi {
    False,
    True,
    Notes,
}

impl NoAi {
    /// Parse a header value. Anything else fails closed — in particular,
    /// readers that only know `true`/`false` reject `notes`, so a
    /// `notes`-mode person can never be misread as a plain visible bool.
    pub fn parse(v: &str) -> Result<NoAi, Error> {
        match v.trim() {
            "true" => Ok(NoAi::True),
            "false" => Ok(NoAi::False),
            "notes" => Ok(NoAi::Notes),
            other => Err(Error::Envelope(format!("bad no-ai value: {other}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NoAi::True => "true",
            NoAi::False => "false",
            NoAi::Notes => "notes",
        }
    }

    /// Is this record itself hidden from agents? Only `True` — a `Notes`
    /// person stays visible (their children default hidden instead).
    pub fn hidden_from_agents(self) -> bool {
        matches!(self, NoAi::True)
    }

    /// Should children of a person with this mode default to hidden at
    /// encrypt time? `True` for both `True` and `Notes`.
    pub fn default_child_hidden(self) -> bool {
        matches!(self, NoAi::True | NoAi::Notes)
    }
}

impl std::fmt::Display for NoAi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn parse_key_id(key_id: &str) -> Result<(String, u64), Error> {
    let (client, epoch) = key_id
        .rsplit_once("/e")
        .ok_or_else(|| Error::Envelope(format!("bad key_id: {key_id}")))?;
    // Second validation layer (issue #133): the client half of a `key_id`
    // must be a safe client id before any caller can route it into a
    // `keys/<client_id>/` path. `KeyStore` validates again at its boundary
    // (the choke point); this catches a hostile envelope early, at parse,
    // so a writer that trusts the parsed envelope never sees a traversal id.
    crate::manifest::validate_client_id(client)?;
    let epoch: u64 = epoch
        .parse()
        .map_err(|_| Error::Envelope(format!("bad key_id epoch: {key_id}")))?;
    Ok((client.to_string(), epoch))
}

/// Client half of a `key_id` (`<client>/e<epoch>`).
///
/// The key id layout is defined here, once — callers that need the client
/// out of an envelope's key id use this instead of re-splitting the string.
pub fn key_id_client(key_id: &str) -> Result<String, Error> {
    parse_key_id(key_id).map(|(client, _)| client)
}

/// Parse an envelope from file bytes. Structural only — no keys needed.
pub fn parse(bytes: &[u8]) -> Result<Envelope, Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Envelope("envelope is not valid UTF-8".to_string()))?;
    let mut lines = text.lines();

    if lines.next() != Some("---") {
        return Err(Error::Envelope("missing opening ---".to_string()));
    }
    let mut id = None;
    let mut record_type = None;
    let mut no_ai = None;
    let mut enc = None;
    let mut key_id = None;
    let mut nonce = None;
    // A repeated header key is ambiguous (first-value vs last-value readers
    // disagree); reject it rather than silently taking the last one.
    let mut seen = std::collections::HashSet::new();
    let mut closed = false;
    for line in &mut lines {
        if line == "---" {
            closed = true;
            break;
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| Error::Envelope(format!("bad header line: {line}")))?;
        let key = k.trim();
        if !seen.insert(key) {
            return Err(Error::Envelope(format!("duplicate header field: {key}")));
        }
        match key {
            "id" => id = Some(v.trim().to_string()),
            "type" => record_type = Some(v.trim().to_string()),
            "no-ai" => no_ai = Some(NoAi::parse(v)?),
            "enc" => enc = Some(v.trim().to_string()),
            "key_id" => key_id = Some(v.trim().to_string()),
            "nonce" => {
                let n = BASE64_STANDARD
                    .decode(v.trim())
                    .map_err(|_| Error::Envelope("bad nonce base64".to_string()))?;
                if n.len() != 24 {
                    return Err(Error::Envelope("nonce must be 24 bytes".to_string()));
                }
                nonce = Some(n);
            }
            other => return Err(Error::Envelope(format!("unknown header field: {other}"))),
        }
    }
    // A header block that never closes is a distinct failure: without this
    // the first missing field ("missing id") was reported instead, which
    // points at the wrong thing (issue #136 item 7).
    if !closed {
        return Err(Error::Envelope(
            "unterminated header: missing closing ---".to_string(),
        ));
    }
    let id = id.ok_or_else(|| Error::Envelope("missing id".to_string()))?;
    let record_type = record_type.ok_or_else(|| Error::Envelope("missing type".to_string()))?;
    let no_ai = no_ai.ok_or_else(|| Error::Envelope("missing no-ai".to_string()))?;
    let enc = enc.ok_or_else(|| Error::Envelope("missing enc".to_string()))?;
    if enc != ALG {
        return Err(Error::Envelope(format!("unsupported enc: {enc}")));
    }
    let key_id = key_id.ok_or_else(|| Error::Envelope("missing key_id".to_string()))?;
    let (_, epoch) = parse_key_id(&key_id)?;
    let nonce = nonce.ok_or_else(|| Error::Envelope("missing nonce".to_string()))?;
    let body: String = lines.collect::<Vec<_>>().join("");
    let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if body.is_empty() {
        return Err(Error::Envelope("missing ciphertext body".to_string()));
    }
    let ciphertext = BASE64_STANDARD
        .decode(&body)
        .map_err(|_| Error::Envelope("bad ciphertext base64".to_string()))?;

    Ok(Envelope {
        id,
        record_type,
        no_ai,
        enc,
        key_id,
        epoch,
        nonce,
        ciphertext,
    })
}

/// Serialize an envelope to file bytes.
pub fn serialize(env: &Envelope) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("---\n");
    out.push_str(&format!("id: {}\n", env.id));
    out.push_str(&format!("type: {}\n", env.record_type));
    out.push_str(&format!("no-ai: {}\n", env.no_ai));
    out.push_str(&format!("enc: {}\n", env.enc));
    out.push_str(&format!("key_id: {}\n", env.key_id));
    out.push_str(&format!("nonce: {}\n", BASE64_STANDARD.encode(&env.nonce)));
    out.push_str("---\n");
    out.push_str(&BASE64_STANDARD.encode(&env.ciphertext));
    out.push('\n');
    out.into_bytes()
}

/// Check header consistency against the AAD-bound values (design §5):
/// `id` equals the record ULID, `key_id`'s client equals the ctx client id
/// (compared exactly — no prefix stripping), `key_id`'s epoch equals the
/// AAD epoch, and `type` maps to exactly one `purpose`. Any inconsistency
/// fails closed.
pub fn check_header(
    env: &Envelope,
    ulid: &str,
    client_id: &str,
    purpose: &str,
    epoch: u64,
) -> Result<(), Error> {
    // id must equal the record ULID bound in the AAD, compared exactly.
    if env.id != ulid {
        return Err(Error::Header(format!(
            "header id {} does not match AAD ULID {ulid}",
            env.id
        )));
    }
    if env.epoch != epoch {
        return Err(Error::Header(format!(
            "key_id epoch {} does not match AAD epoch {epoch}",
            env.epoch
        )));
    }
    let (key_client, _) = parse_key_id(&env.key_id)?;
    if key_client != client_id {
        return Err(Error::Header(format!(
            "key_id client {} does not match ctx client {client_id}",
            env.key_id
        )));
    }
    match purpose_for_type(&env.record_type) {
        Some(p) if p == purpose => Ok(()),
        _ => Err(Error::Header(format!(
            "type {} does not map to purpose {purpose}",
            env.record_type
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample() -> Envelope {
        Envelope {
            id: "p-01ABC".to_string(),
            record_type: "person".to_string(),
            no_ai: NoAi::False,
            enc: ALG.to_string(),
            key_id: "p-01ABC/e3".to_string(),
            epoch: 3,
            nonce: vec![0u8; 24],
            ciphertext: vec![1, 2, 3],
        }
    }

    #[test]
    fn round_trip() {
        let env = sample();
        let bytes = serialize(&env);
        let back = parse(&bytes).unwrap();
        assert_eq!(env, back);
    }

    // Issue #181: tri-state no-ai.
    #[test]
    fn notes_mode_round_trip() {
        let mut env = sample();
        env.no_ai = NoAi::Notes;
        let bytes = serialize(&env);
        let back = parse(&bytes).unwrap();
        assert_eq!(back.no_ai, NoAi::Notes);
        assert!(!back.no_ai.hidden_from_agents());
        assert!(back.no_ai.default_child_hidden());
        // Only `true` hides the record itself.
        assert!(NoAi::True.hidden_from_agents());
        assert!(!NoAi::False.hidden_from_agents());
    }

    #[test]
    fn rejects_bad_no_ai_value() {
        // Readers fail closed on unknown values — in particular, old
        // readers that only know `true`/`false` reject `notes`, so a
        // `notes`-mode person can never be misread as a plain visible bool.
        let bytes = b"---\nid: p-01ABC\ntype: person\nno-ai: sometimes\nenc: xchacha20poly1305\nkey_id: p-01ABC/e3\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\nAQID\n";
        match parse(bytes) {
            Err(Error::Envelope(m)) if m.contains("bad no-ai value") => {}
            other => panic!("expected bad-no-ai Envelope error, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_field() {
        let bytes = b"---\nid: p-01ABC\ntype: person\nno-ai: false\nenc: xchacha20poly1305\nkey_id: p-01ABC/e3\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nevil: 1\n---\nAQID\n";
        assert!(parse(bytes).is_err());
    }

    #[test]
    fn header_checks() {
        let env = sample();
        assert!(check_header(&env, "p-01ABC", "p-01ABC", "profile", 3).is_ok());
        assert!(check_header(&env, "p-OTHER", "p-OTHER", "profile", 3).is_err());
        assert!(check_header(&env, "p-01ABC", "p-01ABC", "profile", 4).is_err());
        assert!(check_header(&env, "p-01ABC", "p-01ABC", "note", 3).is_err());
        // key_id client must match ctx client exactly.
        assert!(check_header(&env, "p-01ABC", "p-OTHER", "profile", 3).is_err());
    }

    #[test]
    fn rejects_duplicate_header_field() {
        // no-ai: false then no-ai: true — last-one-wins is ambiguous, reject.
        let bytes = b"---\nid: p-01ABC\ntype: person\nno-ai: false\nno-ai: true\nenc: xchacha20poly1305\nkey_id: p-01ABC/e3\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\nAQID\n";
        match parse(bytes) {
            Err(Error::Envelope(m)) if m.contains("duplicate header field") => {}
            other => panic!("expected duplicate-header Envelope error, got: {other:?}"),
        }
    }

    // #136 item 7: the error branches below had no test coverage.

    #[test]
    fn rejects_unterminated_header() {
        // No closing `---`: report the layout problem, not "missing id".
        let bytes = b"---\nid: p-01ABC\ntype: person\nno-ai: false\nenc: xchacha20poly1305\nkey_id: p-01ABC/e3\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
        match parse(bytes) {
            Err(Error::Envelope(m)) if m.contains("unterminated header") => {}
            other => panic!("expected unterminated-header error, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_nonce_length() {
        // 16 bytes, not 24.
        let bytes = b"---\nid: p-01ABC\ntype: person\nno-ai: false\nenc: xchacha20poly1305\nkey_id: p-01ABC/e3\nnonce: AAAAAAAAAAAAAAAAAAAAAAAA\n---\nAQID\n";
        match parse(bytes) {
            Err(Error::Envelope(m)) if m.contains("nonce must be 24 bytes") => {}
            other => panic!("expected nonce-length error, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_body() {
        let bytes = b"---\nid: p-01ABC\ntype: person\nno-ai: false\nenc: xchacha20poly1305\nkey_id: p-01ABC/e3\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\n\n";
        match parse(bytes) {
            Err(Error::Envelope(m)) if m.contains("missing ciphertext body") => {}
            other => panic!("expected empty-body error, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_key_id_epoch() {
        let bytes = b"---\nid: p-01ABC\ntype: person\nno-ai: false\nenc: xchacha20poly1305\nkey_id: p-01ABC/eNOTANUMBER\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\nAQID\n";
        match parse(bytes) {
            Err(Error::Envelope(m)) if m.contains("bad key_id epoch") => {}
            other => panic!("expected bad-epoch error, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_unsupported_enc() {
        let bytes = b"---\nid: p-01ABC\ntype: person\nno-ai: false\nenc: aes-gcm\nkey_id: p-01ABC/e3\nnonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n---\nAQID\n";
        match parse(bytes) {
            Err(Error::Envelope(m)) if m.contains("unsupported enc") => {}
            other => panic!("expected unsupported-enc error, got: {other:?}"),
        }
    }
}
