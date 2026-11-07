//! Property-based tests for ADR-7 idempotency and the correction view (#886).
//!
//! Two guarantees live here:
//!
//! * A `--request-id` binds a write's canonical request. Replaying the same
//!   request applies it exactly once; reusing the id for different content is
//!   `E_IDEMPOTENCY_CONFLICT` and writes nothing.
//! * A retraction voids its target in the effective view, and rebuilding the
//!   correction graph from the same ledger is idempotent (duplicates included).

use std::fs;
use std::path::Path;

use confidant_core::config::SpecVersion;
use confidant_core::corrections::Corrections;
use confidant_core::error::{DomainError, ErrorKind};
use confidant_core::ledger::{format_entry, line_ref, parse_line, LineRef};
use confidant_core::load_vault;
use confidant_core::write::{
    apply_write, git, idempotency_digests, FileChange, PendingWrite, WriteOptions, WriteOutcome,
};
use proptest::prelude::*;

const PERSON: &str = "p-01M3TC5H00MPJG000000000000";
const BASE_LINE: &str = "2026-10-01 touch p-01M3TC5H00MPJG000000000000 email";

fn write_file(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture directory");
    }
    fs::write(path, contents).expect("write fixture file");
}

/// A minimal git-backed spec-0.2 vault: one fake person and one committed
/// ledger line. `checks.as_of` is pinned so the write pipeline's pre- and
/// post-checks never depend on the wall clock.
fn make_git_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write_file(
        root,
        "confidant.toml",
        "spec = \"0.2\"\npacks = []\nvault_id = \"test-vault\"\n\n[checks]\nas_of = \"2026-10-13\"\n",
    );
    write_file(
        root,
        &format!("people/{PERSON}/profile.md"),
        &format!("---\nid: {PERSON}\ntype: person\nname: \"Robin Example\"\n---\n\nFake person.\n"),
    );
    write_file(root, "ledger/2026/10.cfd", &format!("{BASE_LINE}\n"));

    git(root, &["init", "-q"], true).expect("git init");
    git(root, &["config", "user.name", "Test"], true).expect("git name");
    git(
        root,
        &["config", "user.email", "test@example.invalid"],
        true,
    )
    .expect("git email");
    git(root, &["add", "-A"], true).expect("git add");
    git(root, &["commit", "-qm", "init"], true).expect("git commit");
    dir
}

fn pending(line: &str, canonical_request: &str) -> PendingWrite {
    PendingWrite {
        changes: vec![FileChange::AppendLines {
            path: "ledger/2026/10.cfd".into(),
            lines: vec![line.to_owned()],
        }],
        summary: "test: property write".to_owned(),
        canonical_request: canonical_request.to_owned(),
    }
}

fn commits(root: &Path) -> usize {
    git(root, &["rev-list", "--count", "HEAD"], true)
        .expect("git rev-list")
        .trim()
        .parse()
        .expect("commit count is a number")
}

fn ledger(root: &Path) -> String {
    fs::read_to_string(root.join("ledger/2026/10.cfd")).expect("ledger file")
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Each case shells out to git a handful of times; keep the case count
        // small so the suite stays fast on Linux and macOS.
        cases: 12,
        ..ProptestConfig::default()
    })]

    /// Same request id + canonical request applies exactly once. A replay with
    /// different content is a typed conflict and leaves the vault untouched.
    #[test]
    fn replay_applies_once_and_conflicts_on_changed_content(
        nonce in any::<u64>(),
        other in any::<u64>(),
    ) {
        let dir = make_git_vault();
        let root = dir.path();
        let request_id = format!("PROPTEST{nonce:018}");
        let canonical = format!("write:call:{nonce}");
        let changed = format!("write:meet:{other}");
        let replay_line = format!("2026-10-01 touch {PERSON} call");
        let changed_line = format!("2026-10-01 touch {PERSON} meet");
        let opts = WriteOptions {
            request_id: Some(request_id.clone()),
            no_input: true,
            ..WriteOptions::default()
        };

        let first = apply_write(
            root,
            pending(&replay_line, &canonical),
            &opts,
        )
        .expect("first write must apply");
        let WriteOutcome::Applied { commit, .. } = first else {
            prop_assert!(false, "first write was not applied: {first:?}");
            return Ok(());
        };
        prop_assert_eq!(commits(root), 2, "first write committed once");
        prop_assert_eq!(ledger(root).matches(replay_line.as_str()).count(), 1);

        // Exact retry: the pipeline replays the recorded commit before it
        // touches a file.
        let replay = apply_write(
            root,
            pending(&replay_line, &canonical),
            &opts,
        )
        .expect("exact replay must succeed");
        let WriteOutcome::Idempotent { commit: replay_commit } = replay else {
            prop_assert!(false, "exact replay was not idempotent: {replay:?}");
            return Ok(());
        };
        prop_assert_eq!(&replay_commit, &commit);
        prop_assert_eq!(commits(root), 2, "replay committed nothing new");
        prop_assert_eq!(
            ledger(root).matches(replay_line.as_str()).count(),
            1,
            "replay appended a second line"
        );

        // Same id, different canonical request and different logical change:
        // typed conflict, nothing written, nothing committed.
        let conflict = apply_write(
            root,
            pending(&changed_line, &changed),
            &opts,
        )
        .expect_err("changed content under the same id must conflict");
        let domain = DomainError::of(&conflict).expect("conflict is a typed domain error");
        prop_assert_eq!(domain.kind(), ErrorKind::IdempotencyConflict);
        prop_assert_eq!(domain.code(), "E_IDEMPOTENCY_CONFLICT");
        prop_assert_eq!(commits(root), 2, "conflict committed nothing");
        prop_assert_eq!(ledger(root).matches(replay_line.as_str()).count(), 1);
        prop_assert!(
            !ledger(root).contains(&changed_line),
            "conflict content reached the ledger"
        );
    }

    /// The digests bind content to the id: they are stable, the id hash is
    /// independent of the canonical request, and a different id or content
    /// moves the corresponding digest.
    #[test]
    fn idempotency_digests_are_stable_and_separated(
        request_id in "[A-Z0-9]{22,26}",
        left in any::<u64>(),
        right in any::<u64>(),
    ) {
        let left = format!("canonical:{left}");
        let right = format!("canonical:{right}");
        let (id_a, req_a) = idempotency_digests(&request_id, &left);
        let (id_b, req_b) = idempotency_digests(&request_id, &left);
        prop_assert_eq!((&id_a, &req_a), (&id_b, &req_b));
        prop_assert_eq!(&id_a, &idempotency_digests(&request_id, &right).0);
        if left != right {
            prop_assert_ne!(&req_a, &idempotency_digests(&request_id, &right).1);
        }
        let (other_id, _) = idempotency_digests(&format!("{request_id}Z"), &left);
        prop_assert_ne!(&id_a, &other_id);
        prop_assert_eq!(id_a.len(), 64);
        prop_assert_eq!(req_a.len(), 64);
    }

    /// A retraction voids its target, the target stays out of the effective
    /// view, and rebuilding the graph from the same entries is idempotent.
    #[test]
    fn retract_is_idempotent_in_the_effective_view(
        kind in prop::sample::select(vec!["call", "meet"]),
        reason in prop::sample::select(vec![
            "duplicate", "wrong-date", "wrong-kind", "wrong-person", "wrong-amount",
            "wrong-note", "wrong-record", "typo", "other",
        ]),
        offset_days in 0u32..=30,
        duplicate in any::<bool>(),
    ) {
        let target_text = format!("2026-10-01 touch {PERSON} {kind}");
        let target_ref: LineRef =
            line_ref(&parse_line(&target_text).unwrap().unwrap(), 1);
        let retract_date = chrono::NaiveDate::from_ymd_opt(2026, 11, 1)
            .unwrap()
            .checked_add_days(chrono::Days::new(u64::from(offset_days)))
            .unwrap();
        let retract_text = format!(
            "{retract_date} retract {PERSON} line:{} reason:{reason}",
            target_ref.hash_hex()
        );
        // A retract line read back through the serializer is the same line.
        let retract_entry = parse_line(&retract_text).unwrap().unwrap();
        prop_assert_eq!(
            parse_line(&format_entry(&retract_entry)).unwrap().unwrap(),
            retract_entry
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write_file(
            root,
            "confidant.toml",
            "spec = \"0.4\"\npacks = []\nvault_id = \"test-vault\"\n",
        );
        write_file(
            root,
            &format!("people/{PERSON}/profile.md"),
            &format!("---\nid: {PERSON}\ntype: person\nname: \"Robin Example\"\n---\n\nFake person.\n"),
        );
        write_file(root, "ledger/2026/10.cfd", &format!("{target_text}\n"));
        let retract_block = if duplicate {
            format!("{retract_text}\n{retract_text}\n")
        } else {
            format!("{retract_text}\n")
        };
        write_file(root, "ledger/2026/11.cfd", &retract_block);

        let vault = load_vault(root).expect("generated correction vault must load");
        let corrections = vault.corrections();
        prop_assert!(
            corrections.is_voided(&target_ref),
            "retracted target is still effective: {retract_text}"
        );
        prop_assert!(corrections.is_voided_location("ledger/2026/10.cfd", 1));

        let effective: Vec<LineRef> = vault.effective_entries().map(|s| s.line_ref).collect();
        prop_assert!(
            !effective.contains(&target_ref),
            "superseded line stayed in the effective view"
        );
        for sourced in &vault.entries {
            if sourced.entry.verb == "retract" {
                prop_assert!(
                    effective.contains(&sourced.line_ref),
                    "the retract line itself was hidden"
                );
            }
        }

        // Reading the same ledger back twice yields the same graph.
        let rebuilt = Corrections::build(&vault.entries, Some(SpecVersion::V04));
        for sourced in &vault.entries {
            prop_assert_eq!(
                rebuilt.is_voided(&sourced.line_ref),
                corrections.is_voided(&sourced.line_ref),
                "rebuild disagreed for {}:{}",
                sourced.file,
                sourced.line
            );
        }
        // A duplicate identical retraction is still a retraction: the target
        // stays voided (the chain finding is a separate diagnostic).
        if duplicate {
            prop_assert!(corrections.is_voided(&target_ref));
            prop_assert!(
                corrections
                    .findings()
                    .iter()
                    .any(|f| f.code.as_str() == "E_RETRACT_CHAIN"),
                "duplicate retraction did not report a chain finding"
            );
        } else {
            prop_assert!(
                corrections.findings().is_empty(),
                "clean retraction reported findings: {:?}",
                corrections.findings()
            );
        }
    }
}
