//! `record list`: the roster a caller may enumerate (#558).
//!
//! One entry per record of the requested kind, in a deterministic order
//! (case-folded display name, then opaque id as the tiebreak). Without the
//! operator flag the roster is exactly the §12 cleared set, so a
//! `no-ai: true` record is **absent** (never present with a nulled name).
//! With `for_operator`, records excluded because of their own `no-ai: true`
//! mode are added and every entry carries the tri-state `no_ai` string the
//! #559 ruling specifies.
//!
//! The flag is operator-only by construction, the same mechanism as
//! `record show --for-edit`: `crates/confidant-cli/src/mcp.rs` maps a fixed
//! tool whitelist to argv and `record list` is not in it, so no agent
//! connection can reach the command, and the `--for-operator` decrypt path
//! (`RecordDecryptor::for_edit`) is never selected by an agent-facing read.

use serde::Serialize;

use crate::id::RecordId;
use crate::record::RecordKind;
use crate::scope::PackScope;
use crate::search::cleared_record_ids;
use crate::vault::Vault;

/// One roster entry: the identity fields a list view needs.
#[derive(Clone, Debug, Serialize)]
pub struct RosterEntry {
    /// Opaque record id (`p-…`, `o-…`, `d-…`).
    pub id: String,
    /// Display name, falling back to the opaque id when the record is
    /// unnamed. Never `null`: a list view always has something to render.
    pub name: String,
    /// Tri-state `no-ai` mode as a string: `"true"`, `"notes"`, or
    /// `"false"` (absent field = `"false"`). Only meaningful with the
    /// operator flag; a `no-ai: true` record is absent without it.
    pub no_ai: &'static str,
    /// Record kind (`"person"`, `"org"`, `"deal"`).
    pub kind: &'static str,
}

/// The whole roster plus the envelope-level context a reader needs.
#[derive(Clone, Debug, Serialize)]
pub struct Roster {
    /// The requested record kind (`"person"`, `"org"`, `"deal"`).
    pub kind: &'static str,
    /// Whether the operator-only visibility flag was set.
    pub for_operator: bool,
    pub records: Vec<RosterEntry>,
    /// Pack names in scope for this call, sorted. For an unscoped call,
    /// every enabled pack. Entries are core-owned identity records, so the
    /// scope does not remove them today; it is reported for contract
    /// consistency with `find` / `context` and validates `--packs`.
    pub scope: Vec<String>,
    /// Envelopes skipped as unreadable by the content hook (spec 4, ⚠2).
    pub skipped_encrypted: u32,
    /// Envelopes refused as tampered/corrupt (spec 4, ⚠2c).
    pub refused_envelopes: u32,
}

/// Build the roster for `kind`.
///
/// A record is listed when it is in the §12 cleared set, or — with
/// `for_operator` — when its own mode is `no-ai: true` (the only reason a
/// record is added by the flag: a `no-ai: notes` person already clears).
///
/// The flag adds records by their *own* mode only, so with `--for-operator`
/// a deal or org that is uncleared only because it links to a `no-ai` person
/// stays hidden — only the person roster is the complete case. Showing
/// those requires a per-kind "uncleared because of a reference" rule that
/// the §12 allowlist does not expose as a single check.
pub fn build_roster(
    vault: &Vault,
    kind: RecordKind,
    scope: &PackScope,
    for_operator: bool,
) -> Roster {
    let cleared = cleared_record_ids(vault);
    let (enabled, _) = vault.pack_registry().resolve_enabled(&vault.config.packs);
    let scope_names = scope.names(&enabled);

    let mut sortable: Vec<(String, RecordId, RosterEntry)> = Vec::new();
    for rec in vault.records.values() {
        if rec.kind != kind {
            continue;
        }
        if !cleared.contains(&rec.id) && !(for_operator && rec.no_ai()) {
            continue;
        }
        let name = rec.name.clone().unwrap_or_else(|| rec.id.to_string());
        let no_ai = rec.no_ai_mode().map(|m| m.as_str()).unwrap_or("false");
        sortable.push((
            crate::search::case_fold(&name),
            rec.id.clone(),
            RosterEntry {
                id: rec.id.to_string(),
                name,
                no_ai,
                kind: rec.kind.as_str(),
            },
        ));
    }
    sortable.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    Roster {
        kind: kind.as_str(),
        for_operator,
        records: sortable.into_iter().map(|(_, _, entry)| entry).collect(),
        scope: scope_names,
        skipped_encrypted: vault.skipped_encrypted,
        refused_envelopes: vault.refused_envelopes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_vault() -> Vault {
        let root =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault");
        crate::vault::load_vault(&root).unwrap()
    }

    #[test]
    fn roster_without_flag_is_the_cleared_set() {
        let vault = demo_vault();
        let roster = build_roster(&vault, RecordKind::Person, &PackScope::All, false);
        let names: Vec<&str> = roster.records.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["Dana Example", "Eli Sample", "Fay Demo", "Gus Example"]
        );
        assert!(roster.records.iter().all(|r| r.no_ai == "false"));
        assert_eq!(roster.kind, "person");
        assert!(!roster.for_operator);
        assert!(roster.scope.contains(&"personal@0.2".to_string()));
    }

    #[test]
    fn operator_roster_lists_the_demo_people_with_tri_state() {
        let vault = demo_vault();
        let roster = build_roster(&vault, RecordKind::Person, &PackScope::All, true);
        let names: Vec<&str> = roster.records.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["Dana Example", "Eli Sample", "Fay Demo", "Gus Example"]
        );
        assert!(roster.records.iter().all(|r| r.no_ai == "false"));
        assert!(roster.for_operator);
    }

    #[test]
    fn roster_orders_by_case_folded_name_then_id() {
        // Two people with the same display name: the id breaks the tie.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
        )
        .unwrap();
        for (id, name) in [
            ("p-01M3TC5H00MPJG0000000000AA", "ada"),
            ("p-01M3TC5H00MPJG0000000000AB", "Ada"),
            ("p-01M3TC5H00MPJG0000000000BB", "zed"),
        ] {
            let d = dir.path().join("people").join(id).join("profile.md");
            std::fs::create_dir_all(d.parent().unwrap()).unwrap();
            std::fs::write(
                &d,
                format!("---\nid: {id}\ntype: person\nname: {name}\n---\n\n"),
            )
            .unwrap();
        }
        let vault = crate::vault::load_vault(dir.path()).unwrap();
        let roster = build_roster(&vault, RecordKind::Person, &PackScope::All, false);
        let ids: Vec<&str> = roster.records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "p-01M3TC5H00MPJG0000000000AA",
                "p-01M3TC5H00MPJG0000000000AB",
                "p-01M3TC5H00MPJG0000000000BB",
            ]
        );
    }

    #[test]
    fn roster_names_fall_back_to_the_id() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
        )
        .unwrap();
        let id = "p-01M3TC5H00MPJG0000000000AA";
        let d = dir.path().join("people").join(id).join("profile.md");
        std::fs::create_dir_all(d.parent().unwrap()).unwrap();
        std::fs::write(&d, format!("---\nid: {id}\ntype: person\n---\n\n")).unwrap();
        let vault = crate::vault::load_vault(dir.path()).unwrap();
        let roster = build_roster(&vault, RecordKind::Person, &PackScope::All, false);
        assert_eq!(roster.records.len(), 1);
        assert_eq!(roster.records[0].name, id);
    }

    #[test]
    fn roster_reports_notes_mode_without_the_flag() {
        // A `no-ai: notes` person is in the cleared set, so the roster
        // lists them without `--for-operator` and badges the mode.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
        )
        .unwrap();
        let id = "p-01M3TC5H00MPJG0000000000AA";
        let d = dir.path().join("people").join(id).join("profile.md");
        std::fs::create_dir_all(d.parent().unwrap()).unwrap();
        std::fs::write(
            &d,
            format!("---\nid: {id}\ntype: person\nname: Notes Mode\nno-ai: notes\n---\n\n"),
        )
        .unwrap();
        let vault = crate::vault::load_vault(dir.path()).unwrap();
        let roster = build_roster(&vault, RecordKind::Person, &PackScope::All, false);
        assert_eq!(roster.records.len(), 1);
        assert_eq!(roster.records[0].no_ai, "notes");
    }

    #[test]
    fn roster_lists_orgs_and_deals_without_no_ai() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("confidant.toml"),
            "spec = \"0.1\"\nvault_id = \"01J9Z3K4QF0000000000000000\"\n",
        )
        .unwrap();
        let org = "o-01J9Z3K4QF0000000000000001";
        std::fs::create_dir_all(dir.path().join("orgs").join(org)).unwrap();
        std::fs::write(
            dir.path().join("orgs").join(org).join("org.md"),
            format!("---\nid: {org}\ntype: org\nname: Example Org\n---\n\n"),
        )
        .unwrap();
        let deal = "d-01J9Z3K4QF0000000000000002";
        std::fs::create_dir_all(dir.path().join("deals").join(deal)).unwrap();
        std::fs::write(
            dir.path().join("deals").join(deal).join("deal.md"),
            format!("---\nid: {deal}\ntype: deal\nname: Example Deal\n---\n\n"),
        )
        .unwrap();
        let vault = crate::vault::load_vault(dir.path()).unwrap();
        let orgs = build_roster(&vault, RecordKind::Org, &PackScope::All, false);
        assert_eq!(orgs.records.len(), 1);
        assert_eq!(orgs.records[0].name, "Example Org");
        assert_eq!(orgs.records[0].kind, "org");
        assert_eq!(orgs.records[0].no_ai, "false");
        let deals = build_roster(&vault, RecordKind::Deal, &PackScope::All, false);
        assert_eq!(deals.records.len(), 1);
        assert_eq!(deals.records[0].name, "Example Deal");
        assert_eq!(deals.records[0].kind, "deal");
    }
}
