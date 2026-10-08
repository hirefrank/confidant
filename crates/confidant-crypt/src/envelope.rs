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
    pub no_ai: bool,
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
        _ => None,
    }
}

fn parse_bool(v: &str) -> Result<bool, Error> {
    match v.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(Error::Envelope(format!("bad no-ai value: {other}"))),
    }
}

fn parse_key_id(key_id: &str) -> Result<(String, u64), Error> {
    let (client, epoch) = key_id
        .rsplit_once("/e")
        .ok_or_else(|| Error::Envelope(format!("bad key_id: {key_id}")))?;
    let epoch: u64 = epoch
        .parse()
        .map_err(|_| Error::Envelope(format!("bad key_id epoch: {key_id}")))?;
    Ok((client.to_string(), epoch))
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
    for line in &mut lines {
        if line == "---" {
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
            "no-ai" => no_ai = Some(parse_bool(v)?),
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
            no_ai: false,
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
}
