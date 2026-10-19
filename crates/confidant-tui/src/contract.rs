//! ADR-7 CLI JSON contract types consumed by `confidant-tui`.
//!
//! The TUI never links `confidant-core` or reads vault files directly. It
//! deserializes only the JSON envelopes emitted by `confidant --json --no-input`
//! on stdout. Optional fields use `#[serde(default)]`, and structs never use
//! `deny_unknown_fields` so additive CLI fields remain non-breaking.

use std::collections::BTreeMap;

use serde::de::{DeserializeOwned, Visitor};
use serde::{Deserialize, Deserializer};

use crate::runner::RawOutput;

/// Tri-state `no-ai` mode as the CLI reports it (#559/#572).
///
/// The roster and the operator `context` path carry the string form
/// (`"true"` | `"notes"` | `"false"`); the agent `context` path carries the
/// boolean `no_ai` and notes/interactions simply omit the field. Both shapes
/// deserialize here so one badge helper serves every view, and an absent or
/// `false` value renders as it did before operator mode existed. An unknown
/// string fails toward [`NoAiMode::Hidden`] so a mode this build does not know
/// never renders as cleared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NoAiMode {
    /// `no-ai: false`, or an absent value: nothing hidden.
    #[default]
    False,
    /// `no-ai: true` (JSON `true` or `"true"`): the record is hidden from
    /// agent reads.
    Hidden,
    /// `no-ai: notes` (JSON `"notes"`): the person is listable but their
    /// notes are hidden from agent reads.
    Notes,
}

impl NoAiMode {
    /// True when the record itself is hidden from agent reads (`no-ai: true`).
    pub fn is_hidden(self) -> bool {
        matches!(self, Self::Hidden)
    }

    /// The badge text for this mode, or `None` when nothing is hidden.
    /// Matches the CLI's human-output badges.
    pub fn badge(self) -> Option<&'static str> {
        match self {
            Self::Hidden => Some("[no-ai]"),
            Self::Notes => Some("[no-ai: notes]"),
            Self::False => None,
        }
    }
}

impl<'de> Deserialize<'de> for NoAiMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ModeVisitor;

        impl Visitor<'_> for ModeVisitor {
            type Value = NoAiMode;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a boolean or one of \"true\", \"notes\", \"false\"")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(if value {
                    NoAiMode::Hidden
                } else {
                    NoAiMode::False
                })
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(match value {
                    "notes" => NoAiMode::Notes,
                    "false" => NoAiMode::False,
                    // Fail toward showing a badge: an unknown mode must never
                    // render as cleared. `"true"` and anything the CLI adds
                    // later get the hidden badge.
                    _ => NoAiMode::Hidden,
                })
            }
        }

        deserializer.deserialize_any(ModeVisitor)
    }
}

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
    /// Optional ranked-search hint (#386): present only when qmd is on
    /// PATH and the corpus exists. Absent otherwise; readers must accept
    /// both shapes.
    #[serde(default)]
    pub hint: Option<String>,
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

/// Output of `qmd-query.py --vault V <query>` (TUI Search view, #212 3a).
///
/// Same shape as `find --json`, plus the QMD mode, an optional fallback
/// reason, per-match `via`/`score`, and the uncleared-drop count.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct SearchResult {
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub fallback: Option<String>,
    #[serde(default)]
    pub matches: Vec<SearchHit>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub dropped_uncleared: u32,
    #[serde(default)]
    pub skipped_encrypted: u32,
    #[serde(default)]
    pub refused_envelopes: u32,
}

/// One search match inside a [`SearchResult`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct SearchHit {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub line: u32,
    #[serde(default)]
    pub excerpt: String,
    /// Provenance of the match: `"qmd"` or `"find"`. Anything else is
    /// dropped at render time (fail closed).
    #[serde(default)]
    pub via: String,
    #[serde(default)]
    pub score: f64,
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
    /// Present (`true`) only when the operator path answered
    /// (`--for-operator`). Absent on the agent path, so its JSON is
    /// unchanged.
    #[serde(default)]
    pub for_operator: bool,
}

/// Person identity and profile inside [`Context`].
///
/// `no_ai` is a boolean on the agent path and the tri-state string on the
/// operator path (#572); [`NoAiMode`] accepts both, and a viewer that only
/// needs "is this hidden" uses [`NoAiMode::is_hidden`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct PersonView {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub no_ai: NoAiMode,
    #[serde(default)]
    pub profile: Option<String>,
}

/// One note inside [`Context`].
///
/// `no_ai` is the operator-path tri-state (#572) and absent on the agent
/// path.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct NoteView {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub no_ai: Option<NoAiMode>,
}

/// One interaction inside [`Context`].
///
/// `no_ai` is the operator-path tri-state (#572) and absent on the agent
/// path.
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
    #[serde(default)]
    pub no_ai: Option<NoAiMode>,
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

/// Output of `confidant record list --json --no-input` (#558).
///
/// The TUI calls the roster without `--for-operator` unless operator mode is
/// on; without it this is the section 12 cleared set, so a `no-ai: true`
/// person is absent (never present with a nulled name). With the operator
/// flag the decrypt path is the operator one and entries carry the tri-state
/// `no_ai` the #559 ruling specifies.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Roster {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub for_operator: bool,
    #[serde(default)]
    pub records: Vec<RosterEntry>,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub skipped_encrypted: u32,
    #[serde(default)]
    pub refused_envelopes: u32,
}

/// One roster entry inside a [`Roster`].
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct RosterEntry {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub no_ai: NoAiMode,
    #[serde(default)]
    pub kind: String,
}

/// Output of `confidant record show <id> --for-edit --json --no-input`
/// (#216) and `confidant note show <n-id> --for-edit --json --no-input`
/// (#557), the two operator-only reads that prepare an edit.
///
/// `text` is decrypted plaintext (a `no-ai` record is decrypted in full
/// here), so the manual [`std::fmt::Debug`] impl redacts it: plaintext must
/// never reach logs or panic messages.
#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct EditSource {
    #[serde(default)]
    pub id: String,
    /// `"person"`, `"note"`, `"interaction"`, … (the JSON key is `type`).
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub no_ai: bool,
    #[serde(default)]
    pub text: String,
}

impl std::fmt::Debug for EditSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EditSource")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("path", &self.path)
            .field("no_ai", &self.no_ai)
            .field("text", &"<redacted>")
            .finish()
    }
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

/// One item in an `inbox --dry-run` report.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct InboxItem {
    #[serde(default)]
    pub name: String,
    /// `"ledger"` or `"record"`.
    #[serde(default)]
    pub kind: String,
    /// Vault-relative merge target.
    #[serde(default)]
    pub target: String,
    /// `"merge"` or `"skip"` (already present / idempotent no-op).
    #[serde(default)]
    pub action: String,
}

/// One operator-deferred item in an `inbox --dry-run` report (`--skip`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct InboxSkipped {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub target: String,
}

/// Output of `confidant inbox --dry-run --json --no-input`.
///
/// The same envelope shape is returned by the real (applying) run, with
/// `dry_run: false`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct InboxReport {
    #[serde(default)]
    pub branch: String,
    #[serde(default)]
    pub dry_run: bool,
    /// True when there is no inbox branch: nothing to do.
    #[serde(default)]
    pub empty: bool,
    #[serde(default)]
    pub merged: usize,
    #[serde(default)]
    pub cleared: usize,
    #[serde(default)]
    pub items: Vec<InboxItem>,
    #[serde(default)]
    pub skipped: Vec<InboxSkipped>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// One decrypted side of a conflicted record
/// (`confidant record resolve <id> --show --json --no-input`, #453).
///
/// `text` holds decrypted plaintext: the manual [`std::fmt::Debug`] impl
/// redacts it so plaintext never reaches logs or panic messages.
#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct ResolveSide {
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub text: String,
}

impl std::fmt::Debug for ResolveSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolveSide")
            .field("label", &self.label)
            .field("text", &"<redacted>")
            .finish()
    }
}

/// Output of `confidant record resolve <id> --show --json --no-input`.
///
/// Plaintext lives in memory only: the TUI never writes it to disk.
/// The manual [`std::fmt::Debug`] impl redacts both sides.
#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct ResolveShow {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub ours: ResolveSide,
    #[serde(default)]
    pub theirs: ResolveSide,
}

impl std::fmt::Debug for ResolveShow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolveShow")
            .field("id", &self.id)
            .field("path", &self.path)
            .field("ours", &self.ours)
            .field("theirs", &self.theirs)
            .finish()
    }
}

/// Output of `confidant record resolve <id> --take ours|theirs --json
/// --no-input` (#454).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct ResolveApplied {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub side: String,
    #[serde(default)]
    pub staged: bool,
    #[serde(default)]
    pub next: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_ai_mode_accepts_boolean_and_tri_state_strings() {
        // Agent `context` sends a boolean; the roster and operator `context`
        // send the tri-state string. Both must land in the same type, and an
        // unknown string must fail toward a badge (never look cleared).
        let from = |json: &str| serde_json::from_str::<NoAiMode>(json).unwrap();
        assert_eq!(from("true"), NoAiMode::Hidden);
        assert_eq!(from("false"), NoAiMode::False);
        assert_eq!(from("\"true\""), NoAiMode::Hidden);
        assert_eq!(from("\"false\""), NoAiMode::False);
        assert_eq!(from("\"notes\""), NoAiMode::Notes);
        assert_eq!(from("\"weird\""), NoAiMode::Hidden);
        assert_eq!(from("\"\""), NoAiMode::Hidden);
    }

    #[test]
    fn person_and_note_views_accept_both_no_ai_shapes() {
        // Agent path: boolean `no_ai`, no per-note field.
        let agent: PersonView = serde_json::from_str(r#"{"id": "p-1", "no_ai": false}"#).unwrap();
        assert_eq!(agent.no_ai, NoAiMode::False);
        // Operator path: tri-state strings.
        let op: PersonView = serde_json::from_str(r#"{"id": "p-1", "no_ai": "notes"}"#).unwrap();
        assert_eq!(op.no_ai, NoAiMode::Notes);
        let note: NoteView = serde_json::from_str(r#"{"id": "n-1", "no_ai": "true"}"#).unwrap();
        assert_eq!(note.no_ai, Some(NoAiMode::Hidden));
        // Absent note field stays `None` (the agent path).
        let plain: NoteView = serde_json::from_str(r#"{"id": "n-1"}"#).unwrap();
        assert_eq!(plain.no_ai, None);
    }

    #[test]
    fn badge_matches_cli_human_output() {
        assert_eq!(NoAiMode::False.badge(), None);
        assert_eq!(NoAiMode::Hidden.badge(), Some("[no-ai]"));
        assert_eq!(NoAiMode::Notes.badge(), Some("[no-ai: notes]"));
        assert!(NoAiMode::Hidden.is_hidden());
        assert!(!NoAiMode::Notes.is_hidden());
        assert!(!NoAiMode::False.is_hidden());
    }

    #[test]
    fn edit_source_debug_redacts_plaintext() {
        let source = EditSource {
            id: "p-1".to_owned(),
            kind: "person".to_owned(),
            path: "people/p-1/profile.md".to_owned(),
            no_ai: true,
            text: "SENTINEL-SECRET-BODY".to_owned(),
        };
        let debug = format!("{source:?}");
        assert!(!debug.contains("SENTINEL"), "plaintext leaked: {debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
        // The non-secret fields survive for debugging.
        assert!(debug.contains("people/p-1/profile.md"), "{debug}");
    }
}
