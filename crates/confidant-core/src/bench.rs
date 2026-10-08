//! Generate a realistic-size fake vault for search-speed measurement.

use std::path::Path;

use anyhow::Result;
use chrono::NaiveDate;

use crate::id::{ulid_from_parts, Prefix, RecordId};
use crate::paths;

const TIME_MS: u64 = 1_790_812_800_000; // 2026-10-01 UTC

/// Write a vault of `people` clients, each with `notes_per_person` notes.
/// All names and emails are synthetic. Returns the unique token planted in
/// person 0's profile (for a one-hit search) and a common token planted in
/// every profile.
pub fn generate_realistic_vault(
    root: &Path,
    people: usize,
    notes_per_person: usize,
) -> Result<(String, String)> {
    std::fs::create_dir_all(root)?;
    let unique = "zxqv-unique-token-ada-0";
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
coaching.session_notes = "warning"
coaching.paid_session_gap = "warning"
coaching.paid_session_gap_days = 45
"#
    );
    paths::write_replace(root, Path::new("confidant.toml"), cfg.as_bytes())?;

    let mut ledger = String::from("; generated fake ledger — not real clients\n");
    let pkg = RecordId::new(Prefix::Package, ulid_from_parts(TIME_MS, 99))?.to_string();

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

        let note_date = NaiveDate::from_ymd_opt(2026, 10, 1).expect("valid date");
        for n in 0..notes_per_person {
            let nid = RecordId::new(
                Prefix::Note,
                ulid_from_parts(TIME_MS, 50_000 + (i as u128) * 64 + n as u128),
            )?;
            let note = format!(
                "---\nid: {nid}\ntype: note\nperson: {pid}\ndate: {note_date}\n---\n\nSession note {n} for generated person {i}. Themes: {common}.\n"
            );
            let path = Path::new(&dir).join("notes").join(format!("{nid}.md"));
            paths::write_replace(root, &path, note.as_bytes())?;
        }

        ledger.push_str(&format!(
            "2026-10-01 open {pid} package {pkg} 6 sessions\n2026-10-01 session {pid} 60m paid note:{nid_placeholder}\n",
            nid_placeholder = RecordId::new(
                Prefix::Note,
                ulid_from_parts(TIME_MS, 50_000 + (i as u128) * 64),
            )?,
        ));
        ledger.push_str(&format!("2026-10-01 balance {pid} sessions_remaining 5\n"));
    }

    paths::write_replace(root, Path::new("ledger/2026/10.cfd"), ledger.as_bytes())?;
    Ok((unique.to_owned(), common.to_owned()))
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
        assert_eq!(search(&vault, &unique).len(), 1);
        assert!(search(&vault, &common).len() >= 3);
    }
}
