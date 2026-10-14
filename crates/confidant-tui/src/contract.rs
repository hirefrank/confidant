//! ADR-7 CLI JSON contract types consumed by `confidant-tui`.
//!
//! The TUI never links `confidant-core` or reads vault files directly. It
//! deserializes only the JSON envelopes emitted by `confidant --json --no-input`
//! on stdout. Optional fields use `#[serde(default)]`, and structs never use
//! `deny_unknown_fields` so additive CLI fields remain non-breaking.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::runner::RawOutput;

/// Supported ADR-7 JSON schema version.
pub const SUPPORTED_SCHEMA_VERSION: &str = "1";

/// Top-level JSON envelope emitted by `confidant --json`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Envelope<T> {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub schema_version: String,
    #[serde(default)]
    pub vault: Option<String>,
    #[serde(default)]
    pub error: Option<ErrorBody>,
    #[serde(flatten)]
    pub data: T,
}

/// Structured error payload inside an error envelope (`ok: false`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct ErrorBody {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub fix: Option<String>,
}

/// Output of `confidant check --json --no-input`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct CheckReport {
    #[serde(default)]
    pub schema_version: String,
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub vault: Option<String>,
    #[serde(default)]
    pub spec: String,
    #[serde(default)]
    pub summary: Summary,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// One integrity finding inside a [`CheckReport`] or [`FindResult`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Finding {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub fix: Option<String>,
}

/// Summary counts in a [`CheckReport`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Summary {
    #[serde(default)]
    pub errors: usize,
    #[serde(default)]
    pub warnings: usize,
    #[serde(default)]
    pub records: usize,
    #[serde(default)]
    pub ledger_entries: usize,
}

/// Output of `confidant find <query> --json --no-input`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct FindResult {
    #[serde(default)]
    pub query: String,
    #[serde(default, alias = "hits")]
    pub matches: Vec<Hit>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub skipped_encrypted: u32,
    #[serde(default)]
    pub refused_envelopes: u32,
    #[serde(default)]
    pub scope: Vec<String>,
}

/// One search match inside a [`FindResult`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Hit {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub line: u32,
    #[serde(default)]
    pub excerpt: String,
}

/// Output of `confidant context <person-id> --json --no-input`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Context {
    #[serde(default)]
    pub person: PersonView,
    #[serde(default)]
    pub notes: Vec<NoteView>,
    #[serde(default)]
    pub interactions: Vec<InteractionView>,
    #[serde(default)]
    pub touchpoints: Vec<TouchpointView>,
    #[serde(default)]
    pub coaching: Option<CoachingView>,
    #[serde(default)]
    pub packs: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub skipped_encrypted: u32,
    #[serde(default)]
    pub refused_envelopes: u32,
    #[serde(default)]
    pub scope: Vec<String>,
}

/// Person identity and profile inside [`Context`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct PersonView {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub no_ai: bool,
    #[serde(default)]
    pub profile: Option<String>,
}

/// One note inside [`Context`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct NoteView {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
}

/// One interaction inside [`Context`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct InteractionView {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
}

/// One mirrored touchpoint inside [`Context`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct TouchpointView {
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub kind: Option<String>,
}

/// Coaching pack view inside [`Context`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct CoachingView {
    #[serde(default)]
    pub sessions_remaining: i64,
    #[serde(default)]
    pub icf_hours: f64,
    #[serde(default)]
    pub recent_sessions: Vec<RecentSession>,
}

/// One recent session inside [`CoachingView`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct RecentSession {
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub duration_minutes: Option<u32>,
    #[serde(default)]
    pub tag: Option<String>,
}

/// Output of `confidant doctor --json --no-input`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct DoctorReport {
    #[serde(default)]
    pub checks: Vec<DoctorCheck>,
}

/// One diagnostic check inside [`DoctorReport`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct DoctorCheck {
    #[serde(default, alias = "name")]
    pub id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub message: String,
}

/// Parsed outcome of a CLI invocation.
#[derive(Clone, Debug, PartialEq)]
pub enum ContractOutcome<T> {
    /// Valid command payload (`schema_version == "1"`, no `error` object).
    Ok {
        ok: bool,
        vault: Option<String>,
        data: T,
    },
    /// Blocking schema version mismatch (`schema_version != "1"`).
    VersionMismatch { reported_version: String },
    /// Structured CLI error envelope (exit 1) or usage error (exit 2).
    CliError {
        status: i32,
        usage_error: bool,
        error: ErrorBody,
    },
    /// CLI stdout could not be parsed as JSON.
    InvalidJson { status: i32 },
}

#[derive(Clone, Debug, Default, Deserialize)]
struct EnvelopeHeader {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    schema_version: String,
    #[serde(default)]
    vault: Option<String>,
    #[serde(default)]
    error: Option<ErrorBody>,
}

/// Parse stdout before checking exit code.
///
/// `check` (and `doctor`) exit 1 when findings/checks fail threshold while
/// still emitting a valid JSON report on stdout. We distinguish a valid report
/// from an error by checking `schema_version` first, then the presence of
/// `error` and `ok`.
pub fn parse_raw_output<T: DeserializeOwned + Default>(raw: &RawOutput) -> ContractOutcome<T> {
    let header: EnvelopeHeader = match serde_json::from_slice(&raw.stdout) {
        Ok(h) => h,
        Err(_) => {
            if raw.status == 2 {
                return ContractOutcome::CliError {
                    status: 2,
                    usage_error: true,
                    error: ErrorBody {
                        code: "usage_error".to_owned(),
                        message: "usage error (CLI exited with code 2)".to_owned(),
                        file: None,
                        line: None,
                        fix: None,
                    },
                };
            }
            return ContractOutcome::InvalidJson { status: raw.status };
        }
    };

    if header.schema_version != SUPPORTED_SCHEMA_VERSION {
        let reported = if header.schema_version.is_empty() {
            "<missing>".to_owned()
        } else {
            header.schema_version
        };
        return ContractOutcome::VersionMismatch {
            reported_version: reported,
        };
    }

    if let Some(mut err) = header.error {
        let usage_error = raw.status == 2 || err.code == "usage_error";
        if usage_error && err.code.is_empty() {
            err.code = "usage_error".to_owned();
        }
        return ContractOutcome::CliError {
            status: raw.status,
            usage_error,
            error: err,
        };
    }

    if raw.status == 2 {
        return ContractOutcome::CliError {
            status: 2,
            usage_error: true,
            error: ErrorBody {
                code: "usage_error".to_owned(),
                message: "usage error (CLI exited with code 2)".to_owned(),
                file: None,
                line: None,
                fix: None,
            },
        };
    }

    let data: T = match serde_json::from_slice(&raw.stdout) {
        Ok(d) => d,
        Err(_) => return ContractOutcome::InvalidJson { status: raw.status },
    };

    ContractOutcome::Ok {
        ok: header.ok,
        vault: header.vault,
        data,
    }
}
