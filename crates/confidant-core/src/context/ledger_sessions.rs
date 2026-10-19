//! The core-owned `ledger-sessions` `context` view and its `[context]`
//! opt-in (#594, spec §13.9).
//!
//! `context`'s `packs` map carries one entry per enabled pack. This module
//! builds the entry for a pack that opts in with a manifest `[context]`
//! table naming `view = "ledger-sessions"`, and it is also the one builder
//! the compiled `coaching@0.1` pack delegates to — so a compiled pack and a
//! declarative pack reach the same arithmetic and the same JSON shape.
//!
//! # The contract
//!
//! The view is exactly the three ledger-derived keys the compiled coaching
//! pack served before #594:
//!
//! ```json
//! {
//!   "sessions_remaining": 4,
//!   "icf_hours": 1.0,
//!   "recent_sessions": [{"date": "2026-10-01", "duration_minutes": 60, "tag": "paid"}]
//! }
//! ```
//!
//! - `sessions_remaining` is the pack's per-person unit balance, the same
//!   number `ledger-balance` verifies: opens minus consuming sessions, over
//!   the merge group, as of the resolved `as_of`.
//! - `icf_hours` is the merge group's total session minutes in hours, two
//!   decimal places (hundredths, never floating point internally).
//! - `recent_sessions` is the person's own consuming-verb ledger lines
//!   (the `ledger-balance` rule's `consume_verb`, `session` for coaching),
//!   newest first (date descending, no tiebreak), capped at the
//!   `[context].recent_limit` (default [`DEFAULT_RECENT_LIMIT`]). Each entry
//!   carries the date, the parsed duration in minutes (if any) and the first
//!   of `paid`/`pps`/`comp`.
//!
//! # Privacy: ledger metadata only
//!
//! The view reads **only** ledger metadata: verbs, dates, opaque ids and the
//! pack's own balance metrics. There is no record field, no profile, no
//! note/interaction body and no decrypted content in it. That is why the
//! `no-ai` §12 cleared set does not gate it and why `--exclude-private`
//! leaves it byte-identical: there is nothing in it for either to remove.
//! Spec §13.9 pins `[context]` to exactly this freedom; a future builder
//! that wanted record fields would need its own review, a `private_fields`
//! key and a `no-ai` deny-by-default allowlist, none of which this module
//! provides.
//!
//! The arithmetic is not re-implemented here: [`crate::packs::rules::ledger`]
//! owns the fold and the merge-aware queries, and the compiled pack's fold
//! already produces a [`LedgerFacts`] this builder consumes.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::check::duration_of;
use crate::error::DomainError;
use crate::id::RecordId;
use crate::ledger::LedgerEntry;
use crate::packs::manifest::PackManifest;
use crate::packs::rules::balance::{BalanceParams, KIND as LEDGER_BALANCE_KIND};
use crate::packs::rules::ledger::{FoldParams, LedgerFacts};
use crate::vault::Vault;

/// The one core view kind a `[context]` table may name today (spec §13.9).
pub const LEDGER_SESSIONS_VIEW: &str = "ledger-sessions";

/// The pack whose row is the legacy top-level `coaching` alias (ADR-7).
///
/// The compiled `coaching@0.1` today and the external pack of the same base
/// name after the #449 cutover: one pack identity at different origins and
/// versions (PD14 reserves `coaching`). Any other `[context]` pack serves its
/// own `packs` entry only — a different pack that happens to serve the same
/// `ledger-sessions` kind must **not** populate the legacy alias.
pub(crate) const LEGACY_COACHING_PACK: &str = "coaching";

/// Whether a pack's `name@version` is the coaching pack that owns the legacy
/// `coaching` alias. Keyed on the base name only; origin and version do not
/// matter (see [`LEGACY_COACHING_PACK`]).
pub(crate) fn owns_legacy_coaching_alias(name: &str) -> bool {
    name.split('@').next() == Some(LEGACY_COACHING_PACK)
}

/// How many recent sessions the view keeps when `[context].recent_limit` is
/// omitted.
pub(crate) const DEFAULT_RECENT_LIMIT: usize = 10;

/// One ledger session for the person (`recent_sessions`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RecentSession {
    pub date: String,
    pub duration_minutes: Option<u32>,
    pub tag: Option<String>,
}

/// Merge-aware coaching facts for the person.
///
/// This is the agent-contract shape of the legacy `coaching` field and the
/// `[context]` pack's `packs` entry (ADR-7): declaration order here is the
/// serialization order of the `PersonContext::coaching` field.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LedgerSessionsView {
    pub sessions_remaining: i64,
    pub icf_hours: f64,
    pub recent_sessions: Vec<RecentSession>,
}

/// The validated parameters of a `[context] view = "ledger-sessions"` table,
/// resolved at manifest load from the pack's single `ledger-balance` rule.
#[derive(Clone, Debug)]
pub(crate) struct LedgerSessionsParams {
    pub(crate) open_verb: String,
    pub(crate) consume_verb: String,
    pub(crate) max_open_n: i64,
    pub(crate) recent_limit: usize,
}

impl LedgerSessionsParams {
    /// The fold parameters the shared ledger arithmetic takes.
    pub(crate) fn fold_params(&self) -> FoldParams<'_> {
        FoldParams {
            open_verb: &self.open_verb,
            consume_verb: &self.consume_verb,
            max_open_n: self.max_open_n,
        }
    }
}

fn view_err(message: impl Into<String>) -> DomainError {
    DomainError::config(message).with_file("manifest.toml")
}

/// Resolve and validate a manifest's `[context]` table.
///
/// Returns `Ok(None)` when the manifest declares no `[context]`; otherwise
/// the resolved parameters. Anything the design refuses — an unknown view,
/// a missing or duplicated `ledger-balance` rule, a zero `recent_limit` —
/// is a `DomainError` the loader maps to `E_PACK_INVALID`.
pub(crate) fn resolve_params(
    manifest: &PackManifest,
) -> Result<Option<LedgerSessionsParams>, DomainError> {
    let Some(decl) = manifest.context.as_ref() else {
        return Ok(None);
    };
    if decl.view != LEDGER_SESSIONS_VIEW {
        return Err(view_err(format!(
            "[context].view '{}' is not a known core view (expected '{}')",
            decl.view, LEDGER_SESSIONS_VIEW
        ))
        .with_fix("Use view = \"ledger-sessions\""));
    }
    let recent_limit = match decl.recent_limit {
        None => DEFAULT_RECENT_LIMIT,
        Some(0) => {
            return Err(view_err("[context].recent_limit must be positive")
                .with_fix("Set recent_limit to a positive integer, or omit it (default 10)"));
        }
        Some(n) => usize::try_from(n).map_err(|_| {
            view_err(format!("[context].recent_limit {n} is too large"))
                .with_fix("Use a smaller recent_limit")
        })?,
    };

    // The view names its verbs and metrics through the pack's balance rule
    // (PD1: the manifest names a core builder and supplies its params; core
    // implements the builder). Exactly one rule can own those params.
    let mut balances = manifest
        .rules
        .iter()
        .filter(|rule| rule.kind == LEDGER_BALANCE_KIND);
    let Some(rule) = balances.next() else {
        return Err(view_err(
            "a [context] ledger-sessions view needs a ledger-balance rule to name its verbs and metrics",
        )
        .with_fix("Add one ledger-balance rule, or remove the [context] table"));
    };
    if balances.next().is_some() {
        return Err(view_err(
            "a [context] ledger-sessions view needs exactly one ledger-balance rule, but this pack declares more",
        )
        .with_fix("Let one ledger-balance rule own the session balance"));
    }
    let params = BalanceParams::parse(rule).ok_or_else(|| {
        view_err(format!(
            "the ledger-balance rule '{}' does not supply the parameters the context view needs",
            rule.id
        ))
        .with_fix("Declare open_verb, consume_verb, units_metric, minutes_metric and max_open_n")
    })?;

    Ok(Some(LedgerSessionsParams {
        open_verb: params.open_verb.to_owned(),
        consume_verb: params.consume_verb.to_owned(),
        max_open_n: params.max_open_n,
        recent_limit,
    }))
}

/// The resolved `[context]` params for a manifest the loader has already
/// validated, or `None` when it declares no `[context]`.
///
/// Non-panicking companion to [`resolve_params`]: `PackManifest::validate_context`
/// refuses a bad `[context]` as `E_PACK_INVALID` at parse time, before any pack
/// is built, so for a loaded manifest this matches `resolve_params`. Pack
/// construction cannot fail (its callers are infallible for a compiled-in
/// pack), so a hypothetical violation degrades to "no view" here rather than
/// panicking; the manifest was already refused on its way in, so that branch
/// is unreachable.
pub(crate) fn params(manifest: &PackManifest) -> Option<LedgerSessionsParams> {
    resolve_params(manifest).ok().flatten()
}

/// Build the `ledger-sessions` view for one person.
///
/// `facts` is the fold the caller already produced from the same shared
/// arithmetic ([`crate::packs::rules::ledger::fold`]); `consume_verb` is the
/// verb whose lines become `recent_sessions`. `canonical` is the
/// merge-canonical person id.
///
/// Returns `None` only if the view cannot be serialized, which cannot
/// happen for a plain JSON object; the caller treats it as "no view".
pub(crate) fn build_ledger_sessions_view(
    vault: &Vault,
    canonical: &RecordId,
    as_of: NaiveDate,
    facts: &LedgerFacts,
    consume_verb: &str,
    recent_limit: usize,
) -> Option<Value> {
    let mut sessions: Vec<RecentSession> = vault
        .entries
        .iter()
        .filter(|s| {
            s.entry.verb == consume_verb && facts.canonical_on(&s.entry.id, as_of) == *canonical
        })
        .map(|s| RecentSession {
            date: s.entry.date.to_string(),
            duration_minutes: duration_of(&s.entry),
            tag: billing_tag(&s.entry),
        })
        .collect();
    sessions.sort_by(|a, b| b.date.cmp(&a.date));
    sessions.truncate(recent_limit);
    let view = LedgerSessionsView {
        sessions_remaining: facts.sessions_remaining_on(canonical, as_of),
        icf_hours: facts.icf_hours_hundredths_on(canonical, as_of) as f64 / 100.0,
        recent_sessions: sessions,
    };
    serde_json::to_value(view).ok()
}

/// The entry's billing tag: the first of `paid`, `pps`, `comp` present.
fn billing_tag(entry: &LedgerEntry) -> Option<String> {
    for tag in ["paid", "pps", "comp"] {
        if entry.has_token(tag) {
            return Some(tag.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::owns_legacy_coaching_alias;

    /// #594: the legacy `coaching` alias is keyed on the pack's base name, so
    /// a `[context]` pack under any other name (e.g. the `coaching-ext`
    /// fixture) can never own it, and a future coaching pack at any version
    /// or origin does.
    #[test]
    fn legacy_coaching_alias_is_keyed_on_the_base_name() {
        assert!(owns_legacy_coaching_alias("coaching@0.1"));
        assert!(owns_legacy_coaching_alias("coaching@2.0"));
        assert!(owns_legacy_coaching_alias("coaching"));
        assert!(!owns_legacy_coaching_alias("coaching-ext@0.1"));
        assert!(!owns_legacy_coaching_alias("coachingext@0.1"));
        assert!(!owns_legacy_coaching_alias("personal@0.2"));
        assert!(!owns_legacy_coaching_alias(""));
    }
}
