//! The built-in personal pack's `context` view and its private-field list
//! (#510).
//!
//! `context`'s `packs` map carries one entry per enabled pack, keyed by the
//! pack's `name@version` (`"personal@0.2"`). This module builds that entry
//! for the built-in personal pack, served by the embedded declarative pack
//! (#551).
//!
//! # The contract
//!
//! The view is a JSON object built from the pack's **declared fields**
//! ([`FieldDecl`], parsed with [`parse_field_grammar`]) plus ledger and
//! record metadata. Every declared field that is not `cadence` appears under
//! its own declared name; the shape of the value follows the grammar:
//!
//! | Grammar | JSON |
//! |---|---|
//! | `recurring-date` | the raw string (`YYYY-MM-DD` or `--MM-DD`) |
//! | `dates-list` | `[{"label": …, "date": …}, …]` |
//! | `non-empty-string` | the trimmed string |
//! | `list` | `[string, …]` |
//! | `labeled-list` | `[{"label": …, "value": …}, …]` |
//! | `date` | the raw `YYYY-MM-DD` string |
//! | `cadence` | not emitted raw; drives `cadence_days` instead |
//!
//! A field is omitted when no merge-group member has a value that parses, and
//! a `list` / `dates-list` / `labeled-list` field is omitted when it is empty.
//!
//! Derived keys, always present unless marked optional:
//!
//! - `cadence_days`: the day count, omitted for `cadence: never` and when no
//!   cadence is set. `never` means the person is never overdue.
//! - `snooze_until`: emitted by the declared `date` field of that name when
//!   set (so an agent can see why no nudge fired).
//! - `last_touch`, `days_since_touch`: the latest contact on or before
//!   `as_of`, omitted when there is none.
//! - `overdue`: false for `cadence: never` and while `as_of < snooze_until`
//!   (eligible again on the date); otherwise true when the last contact is
//!   older than the cadence window, or when there has never been contact.
//! - `recent_touches`: the person's own `touch` ledger lines, newest first
//!   (date descending, then kind), capped at ten. Entries are
//!   `{"date": …, "kind": …}`; `kind` is omitted when the line carries none.
//!
//! Contact for `last_touch` / `overdue` follows the counts-as-contact rule
//! that predates #444: a `touch` or a coaching `session` ledger line, or an
//! `interaction` record whose primary `person:` is a merge-group member or
//! that lists one in `with:`. `recent_touches` is ledger-only (the core
//! `touch` verb). Everything is merge-aware: a value or a touchpoint
//! recorded against a merged-away id counts for the canonical person.
//!
//! For every declared field the merge rule is the 0.1 rule: the canonical
//! person's own value first, else the first merged member's value in record
//! (id) order.
//!
//! # Privacy: two separate rules
//!
//! They are not the same rule, and neither is a superset of the other.
//!
//! **`--exclude-private`** (operator-controlled, `context.rs`) removes the
//! keys [`PRIVATE_CONTEXT_FIELDS`] names, which is the pack's own PII:
//! `birthday`, `dates`, `relationship` (`relationship_to_me` until #444),
//! `location`, `emails`, `phones`, `links`, `tags`. Everything else is kept —
//! `title`, `company`, `cadence_days`, `snooze_until` and the touch metadata.
//!
//! **`no-ai`** (the §12 cleared set) is deny-by-default: a person outside it
//! (`no-ai: true`, or uncleared through a merge-group peer) exposes **no
//! declared field at all** except [`UNCLEARED_VISIBLE_FIELDS`], today only
//! `snooze_until`, plus the derived cadence and touch metadata
//! (`cadence_days`, `last_touch`, `days_since_touch`, `overdue`,
//! `recent_touches`). A field a later manifest adds is hidden until it is
//! listed in that allowlist, so a new 0.2+ field cannot leak to agents by
//! default. `title` and `company` are *not* allowlisted: `no-ai` hides a
//! person's profile front matter today, and the view must not widen that.
//!
//! Ledger-derived touch metadata (dates and kinds) is not record content and
//! is kept, exactly as the `context` module documents; no decrypted content
//! is added to any of it.

use std::collections::{BTreeMap, HashSet};

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::check::{canonical_on, check_aliases_and_merges, Finding};
use crate::id::{Prefix, RecordId};
use crate::ledger::parse_strict_date;
use crate::packs::grammars::{
    parse_field_grammar, Cadence, FieldValue, GRAMMAR_CADENCE, GRAMMAR_DATE, GRAMMAR_DATES_LIST,
    GRAMMAR_LABELED_LIST, GRAMMAR_LIST, GRAMMAR_NON_EMPTY_STRING, GRAMMAR_RECURRING_DATE,
};
use crate::packs::manifest::FieldDecl;
use crate::record::{parse_with_list, RecordKind};
use crate::search::cleared_record_ids;
use crate::touch::extract_touch_kind;
use crate::vault::Vault;

/// Top-level keys of the personal `context` view that carry PII (#510,
/// Frank 2026-10-18). **This is the `--exclude-private` list only**: it is a
/// denylist for one operator-controlled flag and says nothing about `no-ai`,
/// which is deny-by-default over the declared fields (see
/// [`UNCLEARED_VISIBLE_FIELDS`] and the module docs). This is the single
/// list: the built-in personal pack serves it through
/// `ManifestPack::private_context_fields` (#551).
///
/// `title`, `company`, `cadence`, and `snooze_until` are deliberately
/// absent: they stay so an agent can still see the cadence state that drove a
/// nudge.
///
/// `relationship` is the 0.2 name (#509). `relationship_to_me` is kept in the
/// list too: it is harmless (no view carries it after the #551 cutover) and
/// keeps a stale listing from leaking if any older build's text is replayed.
pub const PRIVATE_CONTEXT_FIELDS: &[&str] = &[
    "location",
    "emails",
    "phones",
    "links",
    "tags",
    "birthday",
    "dates",
    "relationship",
    "relationship_to_me",
];

/// Declared fields a person outside the §12 cleared set still exposes: the
/// `no-ai` allowlist. Deny by default — anything a manifest declares that is
/// not named here is dropped, so a new 0.2+ field cannot leak to agents by
/// default. `snooze_until` is the one exception because the derived
/// `overdue` already reports that a nudge was suppressed and the date
/// explains it.
pub const UNCLEARED_VISIBLE_FIELDS: &[&str] = &[SNOOZE_FIELD];

/// The declared field that suppresses the overdue nudge while
/// `as_of < value` (missing means no snooze). Read from the pack's declared
/// fields, so a pack that does not declare it has no snooze.
pub const SNOOZE_FIELD: &str = "snooze_until";

/// Keys the view derives itself. A declared field with one of these names
/// would collide with a typed field when the flattened map is serialized
/// (duplicate JSON keys), so it is skipped and a debug build asserts.
const DERIVED_VIEW_KEYS: &[&str] = &[
    "cadence_days",
    "last_touch",
    "days_since_touch",
    "overdue",
    "recent_touches",
];

/// How many recent touchpoints `recent_touches` keeps.
pub const RECENT_TOUCHES_LIMIT: usize = 10;

/// One important date entry (`dates`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportantDateView {
    pub label: String,
    pub date: String,
}

/// One `labeled-list` entry (`links`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LabeledEntryView {
    pub label: String,
    pub value: String,
}

/// One recent touchpoint (`recent_touches`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentTouch {
    pub date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// The personal pack's `context` view (`packs["personal@0.2"]`).
///
/// The declared fields live in the flattened `fields` map, keyed by the
/// pack's declared field name, so the view follows the manifest (#510).
/// `serde_json`'s object is a sorted map, so the JSON key order is stable.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PersonalView {
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cadence_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_touch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_since_touch: Option<i64>,
    pub overdue: bool,
    pub recent_touches: Vec<RecentTouch>,
}

/// Build the personal pack's `context` view for one person.
///
/// `declared` is the pack's declared field list (its manifest's `[[fields]]`
/// entries), so the same builder serves the compiled 0.1 pack today and the
/// embedded 0.2 pack after #444. `canonical` is the merge-canonical person
/// id. Returns `None` only if the view cannot be serialized, which cannot
/// happen for a plain JSON object; the caller treats it as "no view".
///
/// Cost: this recomputes the merge map, the merge group and the §12 cleared
/// set on every call. That is fine for `context` (one view per invocation);
/// a caller that builds a view for every person in a list should hoist those
/// three out of the loop.
pub fn build_personal_view(
    vault: &Vault,
    person: &RecordId,
    canonical: &RecordId,
    as_of: NaiveDate,
    declared: &[FieldDecl],
) -> Option<Value> {
    // A declared field named after a derived key would serialize a duplicate
    // JSON key; skip it in release and fail loudly in debug.
    debug_assert!(
        declared
            .iter()
            .all(|f| !DERIVED_VIEW_KEYS.contains(&f.name.as_str())),
        "a declared field name collides with a derived view key"
    );

    let merges = merge_map(vault, as_of);
    let members = merge_members(vault, canonical, &merges, as_of);

    let mut view = PersonalView {
        fields: BTreeMap::new(),
        cadence_days: None,
        last_touch: None,
        days_since_touch: None,
        overdue: false,
        recent_touches: Vec::new(),
    };

    let mut cadence: Option<Cadence> = None;
    let mut snooze_until: Option<NaiveDate> = None;
    for field in declared {
        // Reserved derived keys are never emitted from the declared map.
        if DERIVED_VIEW_KEYS.contains(&field.name.as_str()) {
            continue;
        }
        let Some(value) = merged_field_value(vault, canonical, &members, field) else {
            continue;
        };
        match field.grammar.as_str() {
            GRAMMAR_CADENCE => {
                if let FieldValue::Cadence(value) = value {
                    cadence = Some(value);
                }
            }
            GRAMMAR_DATE => {
                if let FieldValue::Date(date) = value {
                    if field.name == SNOOZE_FIELD {
                        snooze_until = Some(date);
                    }
                    view.fields
                        .insert(field.name.clone(), Value::String(date.to_string()));
                }
            }
            GRAMMAR_RECURRING_DATE => {
                if let FieldValue::RecurringDate(date) = value {
                    view.fields
                        .insert(field.name.clone(), Value::String(date.raw));
                }
            }
            GRAMMAR_NON_EMPTY_STRING => {
                if let FieldValue::Text(text) = value {
                    view.fields.insert(field.name.clone(), Value::String(text));
                }
            }
            GRAMMAR_DATES_LIST => {
                if let FieldValue::DatesList(dates) = value {
                    if !dates.is_empty() {
                        let dates: Vec<ImportantDateView> = dates
                            .into_iter()
                            .map(|d| ImportantDateView {
                                label: d.label,
                                date: d.raw,
                            })
                            .collect();
                        view.fields.insert(field.name.clone(), value_of(dates));
                    }
                }
            }
            GRAMMAR_LIST => {
                if let FieldValue::List(list) = value {
                    if !list.is_empty() {
                        view.fields.insert(field.name.clone(), value_of(list));
                    }
                }
            }
            GRAMMAR_LABELED_LIST => {
                if let FieldValue::LabeledList(list) = value {
                    if !list.is_empty() {
                        let list: Vec<LabeledEntryView> = list
                            .into_iter()
                            .map(|(label, value)| LabeledEntryView { label, value })
                            .collect();
                        view.fields.insert(field.name.clone(), value_of(list));
                    }
                }
            }
            _ => {} // the manifest loader rejects unknown grammars
        }
    }

    view.cadence_days = match cadence {
        Some(Cadence::Days(days)) => Some(days),
        // `never` has no day count and is never overdue.
        Some(Cadence::Never) | None => None,
    };

    let last_touch = last_contact_on(vault, canonical, &members, as_of);
    view.days_since_touch = last_touch.map(|d| as_of.signed_duration_since(d).num_days());
    view.last_touch = last_touch.map(|d| d.to_string());
    view.overdue = match view.cadence_days {
        None => false,
        Some(_) if snooze_until.is_some_and(|until| as_of < until) => false,
        Some(cadence_days) => match view.days_since_touch {
            Some(days) => days > i64::from(cadence_days),
            None => true,
        },
    };

    view.recent_touches = recent_touches(vault, canonical, &merges, as_of);

    // §12: a person outside the cleared set keeps no declared field except
    // the `no-ai` allowlist — deny by default, so a field a later manifest
    // adds cannot leak. The derived cadence/touch metadata above stays, and
    // `context` strips `--exclude-private` separately through the pack's
    // `private_context_fields`.
    if !cleared_record_ids(vault).contains(person) {
        view.fields
            .retain(|name, _| UNCLEARED_VISIBLE_FIELDS.contains(&name.as_str()));
    }

    serde_json::to_value(view).ok()
}

/// The merge map for `as_of`. Merge problems are reported by `check`; here
/// they are dropped, exactly as `context` does for its own copy.
fn merge_map(vault: &Vault, as_of: NaiveDate) -> crate::check::MergeMap {
    let known_ids: HashSet<RecordId> = vault.records.keys().cloned().collect();
    let mut findings: Vec<Finding> = Vec::new();
    check_aliases_and_merges(vault, &known_ids, as_of, &mut findings)
}

/// The canonical person's merge group as of `as_of`: every person record (and
/// every merge endpoint) that canonicalizes to `canonical`, sorted by id.
/// Deterministic "record order" for the field merge rule.
fn merge_members(
    vault: &Vault,
    canonical: &RecordId,
    merges: &crate::check::MergeMap,
    as_of: NaiveDate,
) -> Vec<RecordId> {
    let mut members: Vec<RecordId> = vault
        .records
        .values()
        .filter(|r| r.kind == RecordKind::Person)
        .map(|r| r.id.clone())
        .chain(merges.keys().cloned())
        .chain(merges.values().map(|(to, _)| to.clone()))
        .filter(|id| id.prefix() == Prefix::Person)
        .filter(|id| canonical_on(id, merges, as_of) == *canonical)
        .collect();
    members.sort();
    members.dedup();
    members
}

/// The field's value: the canonical person's own first, else the first
/// merged member's in record order. A value the grammar rejects counts as
/// absent (`check` reports it as `E_FRONTMATTER`).
fn merged_field_value(
    vault: &Vault,
    canonical: &RecordId,
    members: &[RecordId],
    field: &FieldDecl,
) -> Option<FieldValue> {
    std::iter::once(canonical)
        .chain(members.iter())
        .find_map(|id| {
            let record = vault.records.get(id)?;
            if record.kind != RecordKind::Person {
                return None;
            }
            let raw = record.field(&field.name)?;
            parse_field_grammar(&field.grammar, field.name.clone(), raw)
        })
}

/// Latest contact on or before `as_of` for any merge-group member: a `touch`
/// or coaching `session` ledger line, or an `interaction` record whose
/// primary is a member or that lists one in `with:`.
fn last_contact_on(
    vault: &Vault,
    canonical: &RecordId,
    members: &[RecordId],
    as_of: NaiveDate,
) -> Option<NaiveDate> {
    let is_member = |id: &RecordId| id == canonical || members.contains(id);
    let ledger = vault
        .entries
        .iter()
        .filter(|s| s.entry.verb == "touch" || s.entry.verb == "session")
        .filter(|s| s.entry.date <= as_of)
        .filter(|s| is_member(&s.entry.id))
        .map(|s| s.entry.date)
        .max();
    let interactions = vault
        .records
        .values()
        .filter(|r| r.kind == RecordKind::Interaction)
        .filter_map(|r| {
            let date = r.field("date").and_then(parse_strict_date)?;
            if date > as_of {
                return None;
            }
            let mut touched = r.person().is_some_and(|p| is_member(&p));
            if !touched {
                if let Some(list) = r.field("with").and_then(parse_with_list) {
                    touched = list.iter().any(&is_member);
                }
            }
            touched.then_some(date)
        })
        .max();
    [ledger, interactions].into_iter().flatten().max()
}

/// The person's own `touch` ledger lines, newest first, capped at
/// [`RECENT_TOUCHES_LIMIT`].
fn recent_touches(
    vault: &Vault,
    canonical: &RecordId,
    merges: &crate::check::MergeMap,
    as_of: NaiveDate,
) -> Vec<RecentTouch> {
    let mut touches: Vec<RecentTouch> = vault
        .entries
        .iter()
        .filter(|s| {
            s.entry.verb == "touch"
                && s.entry.date <= as_of
                && canonical_on(&s.entry.id, merges, as_of) == *canonical
        })
        .map(|s| RecentTouch {
            date: s.entry.date.to_string(),
            kind: extract_touch_kind(&s.entry),
        })
        .collect();
    touches.sort_by(|a, b| b.date.cmp(&a.date).then(a.kind.cmp(&b.kind)));
    touches.truncate(RECENT_TOUCHES_LIMIT);
    touches
}

/// Serialize a view fragment. The fragments are plain strings and structs, so
/// this cannot fail; `Null` on the impossible error keeps the builder total.
fn value_of<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// Remove the private top-level keys from a built view. `context` does this
/// through [`crate::packs::Pack::private_context_fields`]; this helper keeps
/// the core list and its stripping testable together.
pub fn strip_private_fields(view: &mut Value) {
    if let Some(object) = view.as_object_mut() {
        for field in PRIVATE_CONTEXT_FIELDS {
            object.remove(*field);
        }
    }
}
