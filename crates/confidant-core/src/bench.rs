//! Generate a realistic-size fake vault for search-speed measurement.

use std::path::Path;

use anyhow::Result;
use chrono::NaiveDate;

use crate::error::DomainError;
use crate::id::{ulid_from_parts, Prefix, RecordId};
use crate::paths;

const TIME_MS: u64 = 1_790_812_800_000; // 2026-10-01 UTC
const SESSIONS_PER_PERSON: usize = 24;
const NOTE_BODY_KB: usize = 3;

/// Write a vault of `people` clients, each with `notes_per_person` notes.
/// All names and emails are synthetic. Returns the unique token planted in
/// person 0's profile (for a one-hit search) and a common token planted in
/// every profile.
///
/// Refuses to run on a non-empty directory or an existing vault.
pub fn generate_realistic_vault(
    root: &Path,
    people: usize,
    notes_per_person: usize,
) -> Result<(String, String)> {
    refuse_existing(root)?;
    std::fs::create_dir_all(root)?;
    let unique = "zxqvUniqueTokenAda0";
    let common = "coaching-practice";
    let vault_id = ulid_from_parts(TIME_MS, 1);
    let cfg = format!(
        r#"spec = "0.1"
packs = ["coaching@0.1"]
vault_id = "{vault_id}"

[checks]
as_of = "2026-10-08"
coaching.require_duration = "error"
coaching.balance_nonnegative = "error"
coaching.session_notes = "off"
coaching.paid_session_gap = "off"
coaching.paid_session_gap_days = 45
coaching.pps_lookback_days = 180
"#
    );
    paths::write_replace(root, Path::new("confidant.toml"), cfg.as_bytes())?;

    let mut ledgers: std::collections::BTreeMap<(i32, u32), String> =
        std::collections::BTreeMap::new();
    let pkg = RecordId::new(Prefix::Package, ulid_from_parts(TIME_MS, 99))?.to_string();
    let filler = "transcript line about goals, blockers, and next actions. ".repeat(40);

    for i in 0..people {
        let pid = RecordId::new(Prefix::Person, ulid_from_parts(TIME_MS, 1_000 + i as u128))?;
        let dir = format!("people/{pid}");
        let mut body =
            format!("Fake person {i} in a generated vault. They work on {common} goals.\n");
        if i == 0 {
            body.push_str(unique);
            body.push('\n');
        }
        let profile =
            format!("---\nid: {pid}\ntype: person\nname: Generated Person {i}\n---\n\n{body}");
        paths::write_replace(
            root,
            Path::new(&dir).join("profile.md").as_path(),
            profile.as_bytes(),
        )?;

        for n in 0..notes_per_person {
            let nid = RecordId::new(
                Prefix::Note,
                ulid_from_parts(TIME_MS, 50_000 + (i as u128) * 256 + n as u128),
            )?;
            let note_date =
                NaiveDate::from_ymd_opt(2024 + (n / 12) as i32, (n % 12) as u32 + 1, 15)
                    .unwrap_or(NaiveDate::from_ymd_opt(2026, 10, 1).expect("valid"));
            let mut note_body =
                format!("Session note {n} for generated person {i}. Themes: {common}.\n{filler}\n");
            while note_body.len() < NOTE_BODY_KB * 1024 {
                note_body.push_str(&filler);
            }
            let note = format!(
                "---\nid: {nid}\ntype: note\nperson: {pid}\ndate: {note_date}\n---\n\n{note_body}"
            );
            let path = Path::new(&dir).join("notes").join(format!("{nid}.md"));
            paths::write_replace(root, &path, note.as_bytes())?;
        }

        let pps_client = i % 10 == 1;
        if !pps_client {
            push_ledger(
                &mut ledgers,
                2024,
                1,
                &format!("2024-01-01 open {pid} package {pkg} 36 sessions\n"),
            );
        }
        for s in 0..SESSIONS_PER_PERSON {
            let month_offset = (s as u32) % 12;
            let year = 2024 + (s as i32 / 12);
            let month = month_offset + 1;
            let day = 8;
            let nid = RecordId::new(
                Prefix::Note,
                ulid_from_parts(TIME_MS, 50_000 + (i as u128) * 256),
            )?;
            let tag = if pps_client { "pps" } else { "paid" };
            push_ledger(
                &mut ledgers,
                year,
                month,
                &format!("{year}-{month:02}-{day:02} session {pid} 60m {tag} note:{nid}\n"),
            );
        }
        if !pps_client {
            push_ledger(
                &mut ledgers,
                2026,
                10,
                &format!(
                    "2026-10-01 balance {pid} sessions_remaining {}\n",
                    36 - SESSIONS_PER_PERSON
                ),
            );
        }
    }

    for ((year, month), body) in ledgers {
        let mut text = String::from("; generated fake ledger — not real clients\n");
        text.push_str(&body);
        paths::write_replace(
            root,
            Path::new(&format!("ledger/{year}/{month:02}.cfd")),
            text.as_bytes(),
        )?;
    }
    Ok((unique.to_owned(), common.to_owned()))
}

fn push_ledger(
    ledgers: &mut std::collections::BTreeMap<(i32, u32), String>,
    year: i32,
    month: u32,
    line: &str,
) {
    ledgers.entry((year, month)).or_default().push_str(line);
}

fn refuse_existing(root: &Path) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    if root.join("confidant.toml").is_file() {
        return Err(anyhow::Error::new(DomainError::already_exists(format!(
            "refusing to overwrite existing vault at {}",
            root.display()
        ))));
    }
    if root.is_file() {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "'{}' exists and is not a directory",
            root.display()
        ))));
    }
    if std::fs::read_dir(root)?.next().is_some() {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "refusing to generate a vault in a non-empty directory ({})",
            root.display()
        ))));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::generate_realistic_vault;
    use crate::search::search;
    use crate::vault::load_vault;

    #[test]
    fn generated_vault_is_searchable() {
        let dir = tempfile::tempdir().unwrap();
        let (unique, common) = generate_realistic_vault(dir.path(), 3, 2).unwrap();
        let vault = load_vault(dir.path()).unwrap();
        assert_eq!(vault.records.len(), 3 + 6); // people + notes
        assert_eq!(search(&vault, &unique).hits.len(), 1);
        assert!(search(&vault, &common).hits.len() >= 3);
        let report = crate::check_vault(&vault, &crate::CheckOptions::default());
        assert!(
            report.findings.is_empty(),
            "generated vault should check clean: {:?}",
            report.findings
        );
        assert!(generate_realistic_vault(dir.path(), 1, 1).is_err());
    }

    #[test]
    fn bench_gen_vault_stays_within_search_timings() {
        use std::time::{Duration, Instant};
        let dir = tempfile::tempdir().unwrap();
        let (unique, common) = generate_realistic_vault(dir.path(), 400, 5).unwrap();
        let vault = load_vault(dir.path()).unwrap();
        assert!(
            vault.records.len() >= 2_400,
            "expected ~2500 files, got {} records",
            vault.records.len()
        );
        let budget = if cfg!(debug_assertions) {
            Duration::from_secs(8)
        } else {
            Duration::from_millis(200)
        };
        let t0 = Instant::now();
        let one = search(&vault, &unique);
        let find_unique = t0.elapsed();
        let t1 = Instant::now();
        let many = search(&vault, &common);
        let find_common = t1.elapsed();
        let t2 = Instant::now();
        let report = crate::check_vault(&vault, &crate::CheckOptions::default());
        let check = t2.elapsed();
        assert_eq!(one.hits.len(), 1, "{:?}", one.hits);
        assert!(many.hits.len() >= 400, "{}", many.hits.len());
        assert!(
            report.findings.is_empty(),
            "generated vault should check clean: {:?}",
            report.findings
        );
        assert!(
            find_unique <= budget,
            "find unique {find_unique:?} exceeded {budget:?}"
        );
        assert!(
            find_common <= budget,
            "find common {find_common:?} exceeded {budget:?}"
        );
        assert!(check <= budget, "check {check:?} exceeded {budget:?}");
    }
}
