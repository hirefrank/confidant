//! Load a vault from disk: config, records, ledger.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::check::{Finding, FindingCode, Severity};
use crate::config::{VaultConfig, SPEC_VERSION};
use crate::id::{Prefix, RecordId};
use crate::ledger::{parse_ledger, LedgerEntry, ParseErrorKind};
use crate::paths::{self, EntryKind};
use crate::record::{has_conflict_markers, parse_record, Record, RecordKind};

const COLLECTIONS: &[&str] = &["people", "orgs", "deals", "interactions", "notes"];

#[derive(Clone, Debug)]
pub struct SourcedEntry {
    pub file: String,
    pub line: u32,
    pub entry: LedgerEntry,
}

#[derive(Clone, Debug)]
pub struct Vault {
    pub root: PathBuf,
    pub config: VaultConfig,
    pub records: BTreeMap<RecordId, Record>,
    pub entries: Vec<SourcedEntry>,
    pub load_findings: Vec<Finding>,
}

pub fn load_vault(root: &Path) -> Result<Vault, crate::error::DomainError> {
    let root = root
        .canonicalize()
        .map_err(|_| crate::error::DomainError::vault_not_found())?;
    load_vault_inner(&root).map_err(|err| {
        crate::error::DomainError::of(&err)
            .cloned()
            .unwrap_or_else(|| crate::error::DomainError::invalid(err.to_string()))
    })
}

fn load_vault_inner(root: &Path) -> anyhow::Result<Vault> {
    let cfg_text = paths::read_to_string(root, Path::new("confidant.toml")).map_err(|err| {
        if crate::error::is_missing(&err) {
            anyhow::Error::new(crate::error::DomainError::vault_not_found())
        } else {
            err
        }
    })?;
    if has_conflict_markers(&cfg_text) {
        return Err(anyhow::Error::new(
            crate::error::DomainError::conflict("confidant.toml contains git conflict markers")
                .with_file("confidant.toml"),
        ));
    }
    let mut config = VaultConfig::parse(&cfg_text)
        .map_err(|err| anyhow::Error::new(err.with_file("confidant.toml")))?;

    let mut findings = config.config_findings();
    let mut records = BTreeMap::new();
    let mut entries = Vec::new();

    if config.spec == SPEC_VERSION {
        scan_collections(root, &mut records, &mut findings);
        scan_ledger(root, &mut entries, &mut findings);
        scan_unexpected_top_level(root, &mut findings);
    }

    Ok(Vault {
        root: root.to_path_buf(),
        config,
        records,
        entries,
        load_findings: findings,
    })
}

fn list_dir(root: &Path, rel: &Path, findings: &mut Vec<Finding>) -> Vec<paths::DirectoryEntry> {
    match paths::read_dir(root, rel) {
        Ok(entries) => entries,
        Err(err) => {
            let file = if rel.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                paths::display_relative(rel)
            };
            findings.push(
                Finding::new(FindingCode::Unreadable, Severity::Error, err.to_string())
                    .at_file(file)
                    .with_fix("Fix directory permissions or replace the unreadable path"),
            );
            Vec::new()
        }
    }
}

fn flag_entry(ent: &paths::DirectoryEntry, child: &Path, findings: &mut Vec<Finding>) {
    let file = paths::display_relative(child);
    if !ent.utf8 {
        findings.push(
            Finding::new(
                FindingCode::InvalidFilename,
                Severity::Error,
                format!("non-UTF-8 name at '{file}'"),
            )
            .at_file(&file)
            .with_fix("Rename the file to a UTF-8 record ID"),
        );
        return;
    }
    if ent.kind == EntryKind::Symlink {
        findings.push(
            Finding::new(
                FindingCode::Symlink,
                Severity::Error,
                format!("symbolic link '{file}'"),
            )
            .at_file(&file)
            .with_fix("Replace the symlink with a real file or directory"),
        );
    }
}

fn scan_unexpected_top_level(root: &Path, findings: &mut Vec<Finding>) {
    let allowed = [
        "confidant.toml",
        "people",
        "orgs",
        "deals",
        "interactions",
        "notes",
        "ledger",
        "keys",
        "README.md",
        "LICENSE",
    ];
    for ent in list_dir(root, Path::new(""), findings) {
        let child = Path::new(&ent.name);
        if !ent.utf8 || ent.kind == EntryKind::Symlink {
            flag_entry(&ent, child, findings);
            continue;
        }
        if paths::skip_walk_entry(&ent.name, ent.kind) {
            continue;
        }
        if !allowed.contains(&ent.name.as_str()) {
            findings.push(
                Finding::new(
                    FindingCode::InvalidFilename,
                    Severity::Error,
                    format!("unexpected vault entry '{}'", ent.name),
                )
                .at_file(&ent.name)
                .with_fix("Use the layout in spec/0.1.md (people/, orgs/, deals/, ledger/, …)"),
            );
        }
    }
}

fn scan_collections(
    root: &Path,
    records: &mut BTreeMap<RecordId, Record>,
    findings: &mut Vec<Finding>,
) {
    for collection in COLLECTIONS {
        let rel = Path::new(collection);
        match paths::read_dir(root, rel) {
            Err(err) if crate::error::is_missing(&err) => continue,
            Err(_) => {
                let _ = list_dir(root, rel, findings);
                continue;
            }
            Ok(entries) => {
                let prefix = Prefix::from_collection(collection).expect("known collection");
                for ent in entries {
                    let child = rel.join(&ent.name);
                    if !ent.utf8 || ent.kind == EntryKind::Symlink {
                        flag_entry(&ent, &child, findings);
                        continue;
                    }
                    if paths::skip_walk_entry(&ent.name, ent.kind) {
                        continue;
                    }
                    match ent.kind {
                        EntryKind::File => {
                            if let Some(stem) = ent.name.strip_suffix(".md") {
                                ingest_file(root, &child, stem, prefix, records, findings);
                            } else {
                                findings.push(
                                    Finding::new(
                                        FindingCode::InvalidFilename,
                                        Severity::Error,
                                        format!(
                                            "collection '{collection}' contains a file named '{}' that is not a record ID",
                                            ent.name
                                        ),
                                    )
                                    .at_file(paths::display_relative(&child))
                                    .with_fix("Rename to <prefix>-<ULID>.md or move it out of the collection"),
                                );
                            }
                        }
                        EntryKind::Directory => {
                            ingest_dir(root, &child, &ent.name, prefix, records, findings);
                        }
                        EntryKind::Other => findings.push(
                            Finding::new(
                                FindingCode::InvalidFilename,
                                Severity::Error,
                                format!(
                                    "collection '{collection}' contains a non-file named '{}'",
                                    ent.name
                                ),
                            )
                            .at_file(paths::display_relative(&child)),
                        ),
                        EntryKind::Symlink => {}
                    }
                }
            }
        }
    }
}

fn ingest_file(
    root: &Path,
    relative: &Path,
    stem: &str,
    expected_prefix: Prefix,
    records: &mut BTreeMap<RecordId, Record>,
    findings: &mut Vec<Finding>,
) {
    let file = paths::display_relative(relative);
    let path_id = match RecordId::parse(stem) {
        Ok(id) => id,
        Err(_) => {
            findings.push(
                Finding::new(
                    FindingCode::InvalidFilename,
                    Severity::Error,
                    format!("filename '{stem}' cannot be a record ID"),
                )
                .at_file(&file)
                .with_fix("Name the file <prefix>-<26-character ULID>.md"),
            );
            return;
        }
    };
    if path_id.prefix() != expected_prefix {
        findings.push(
            Finding::new(
                FindingCode::TypePathMismatch,
                Severity::Error,
                format!(
                    "id '{path_id}' does not belong in '{}'",
                    expected_prefix.collection().unwrap_or("?")
                ),
            )
            .at_file(&file)
            .for_id(&path_id),
        );
    }
    load_markdown(root, relative, Some(&path_id), records, findings);
}

fn ingest_dir(
    root: &Path,
    relative: &Path,
    name: &str,
    expected_prefix: Prefix,
    records: &mut BTreeMap<RecordId, Record>,
    findings: &mut Vec<Finding>,
) {
    let dir = paths::display_relative(relative);
    let path_id = match RecordId::parse(name) {
        Ok(id) => id,
        Err(_) => {
            findings.push(
                Finding::new(
                    FindingCode::InvalidFilename,
                    Severity::Error,
                    format!("directory '{name}' cannot be a record ID"),
                )
                .at_file(&dir)
                .with_fix("Name the directory <prefix>-<26-character ULID>"),
            );
            return;
        }
    };
    if path_id.prefix() != expected_prefix {
        findings.push(
            Finding::new(
                FindingCode::TypePathMismatch,
                Severity::Error,
                format!(
                    "id '{path_id}' does not belong in '{}'",
                    expected_prefix.collection().unwrap_or("?")
                ),
            )
            .at_file(&dir)
            .for_id(&path_id),
        );
    }
    let main = expected_prefix
        .main_filename()
        .expect("collection records have a main file");
    let mut saw_main = false;
    for ent in list_dir(root, relative, findings) {
        let child = relative.join(&ent.name);
        if !ent.utf8 || ent.kind == EntryKind::Symlink {
            flag_entry(&ent, &child, findings);
            if ent.name == main {
                saw_main = true;
            }
            continue;
        }
        if paths::skip_walk_entry(&ent.name, ent.kind) {
            continue;
        }
        if ent.name == main && ent.kind == EntryKind::File {
            saw_main = true;
            load_markdown(root, &child, Some(&path_id), records, findings);
            continue;
        }
        if expected_prefix == Prefix::Person
            && ent.name == "notes"
            && ent.kind == EntryKind::Directory
        {
            scan_person_notes(root, relative, &path_id, records, findings);
            continue;
        }
        findings.push(
            Finding::new(
                FindingCode::InvalidFilename,
                Severity::Error,
                format!(
                    "record directory '{dir}' contains unexpected '{}'",
                    ent.name
                ),
            )
            .at_file(paths::display_relative(&child))
            .for_id(&path_id)
            .with_fix(format!(
                "Keep only {main} (and notes/ for people) in the record directory"
            )),
        );
    }
    if !saw_main {
        findings.push(
            Finding::new(
                FindingCode::Frontmatter,
                Severity::Error,
                format!("record directory '{dir}' is missing {main}"),
            )
            .at_file(&dir)
            .for_id(&path_id)
            .with_fix(format!("Add {main} with id/type front matter")),
        );
    }
}

fn scan_person_notes(
    root: &Path,
    person_dir: &Path,
    person_id: &RecordId,
    records: &mut BTreeMap<RecordId, Record>,
    findings: &mut Vec<Finding>,
) {
    let notes_rel = person_dir.join("notes");
    match paths::read_dir(root, &notes_rel) {
        Err(err) if crate::error::is_missing(&err) => {}
        Err(_) => {
            let _ = list_dir(root, &notes_rel, findings);
        }
        Ok(entries) => {
            for ent in entries {
                let child = notes_rel.join(&ent.name);
                if !ent.utf8 || ent.kind == EntryKind::Symlink {
                    flag_entry(&ent, &child, findings);
                    continue;
                }
                if paths::skip_walk_entry(&ent.name, ent.kind) {
                    continue;
                }
                if ent.kind != EntryKind::File || !ent.name.ends_with(".md") {
                    findings.push(
                        Finding::new(
                            FindingCode::InvalidFilename,
                            Severity::Error,
                            format!(
                                "notes directory contains '{}' which is not n-<ULID>.md",
                                ent.name
                            ),
                        )
                        .at_file(paths::display_relative(&child)),
                    );
                    continue;
                }
                let stem = ent.name.trim_end_matches(".md");
                ingest_file(root, &child, stem, Prefix::Note, records, findings);
                if let Ok(id) = RecordId::parse(stem) {
                    if let Some(rec) = records.get(&id) {
                        if rec.person().as_ref().is_some_and(|p| p != person_id) {
                            findings.push(
                                Finding::new(
                                    FindingCode::IdPathMismatch,
                                    Severity::Error,
                                    format!(
                                        "note {id} is under {person_id} but front matter person is {}",
                                        rec.field("person").unwrap_or("missing")
                                    ),
                                )
                                .at_file(paths::display_relative(&child))
                                .for_id(&id),
                            );
                        }
                    }
                }
            }
        }
    }
}

fn load_markdown(
    root: &Path,
    relative: &Path,
    path_id: Option<&RecordId>,
    records: &mut BTreeMap<RecordId, Record>,
    findings: &mut Vec<Finding>,
) {
    let file = paths::display_relative(relative);
    let text = match paths::read_to_string(root, relative) {
        Ok(t) => t,
        Err(err) => {
            let msg = err.to_string();
            findings.push(
                Finding::new(FindingCode::Unreadable, Severity::Error, msg)
                    .at_file(&file)
                    .with_fix("Replace the file with valid UTF-8 Markdown"),
            );
            return;
        }
    };
    if has_conflict_markers(&text) {
        findings.push(
            Finding::new(
                FindingCode::MergeConflict,
                Severity::Error,
                format!("'{file}' contains git conflict markers"),
            )
            .at_file(&file)
            .with_fix("Resolve the conflict; check keeps both sides visible until you do"),
        );
    }
    match parse_record(&text, &file) {
        Err(err) => findings.push(
            Finding::new(FindingCode::Frontmatter, Severity::Error, err.message)
                .at_file(&file)
                .with_fix(err.fix),
        ),
        Ok(mut rec) => {
            rec.path = file.clone();
            if let Some(pid) = path_id {
                if rec.id != *pid {
                    findings.push(
                        Finding::new(
                            FindingCode::IdPathMismatch,
                            Severity::Error,
                            format!(
                                "front matter id '{}' does not match path id '{pid}'",
                                rec.id
                            ),
                        )
                        .at_file(&file)
                        .for_id(&rec.id)
                        .with_fix("Make the path and the front matter id the same ULID"),
                    );
                }
            }
            if rec.id.prefix() != rec.kind.prefix() {
                findings.push(
                    Finding::new(
                        FindingCode::TypePathMismatch,
                        Severity::Error,
                        format!(
                            "id '{}' prefix does not match type '{}'",
                            rec.id,
                            rec.kind.as_str()
                        ),
                    )
                    .at_file(&file)
                    .for_id(&rec.id),
                );
            }
            if let Some(expected) = rec.kind.prefix().collection() {
                if !file.starts_with(expected)
                    && !(rec.kind == RecordKind::Note && file.contains("/notes/"))
                {
                    findings.push(
                        Finding::new(
                            FindingCode::TypePathMismatch,
                            Severity::Error,
                            format!("type '{}' does not belong at '{file}'", rec.kind.as_str()),
                        )
                        .at_file(&file)
                        .for_id(&rec.id),
                    );
                }
            }
            if let Some(existing) = records.get(&rec.id) {
                findings.push(
                    Finding::new(
                        FindingCode::DuplicateId,
                        Severity::Error,
                        format!(
                            "id '{}' appears in '{}' and '{}'",
                            rec.id, existing.path, rec.path
                        ),
                    )
                    .at_file(&file)
                    .for_id(&rec.id)
                    .with_fix("Keep one file per id"),
                );
            } else {
                records.insert(rec.id.clone(), rec);
            }
        }
    }
}

fn scan_ledger(root: &Path, entries: &mut Vec<SourcedEntry>, findings: &mut Vec<Finding>) {
    let ledger_rel = Path::new("ledger");
    match paths::read_dir(root, ledger_rel) {
        Err(err) if crate::error::is_missing(&err) => {}
        Err(_) => {
            let _ = list_dir(root, ledger_rel, findings);
        }
        Ok(years) => {
            for year_ent in years {
                let year_rel = ledger_rel.join(&year_ent.name);
                if !year_ent.utf8 || year_ent.kind == EntryKind::Symlink {
                    flag_entry(&year_ent, &year_rel, findings);
                    continue;
                }
                if paths::skip_walk_entry(&year_ent.name, year_ent.kind) {
                    continue;
                }
                if year_ent.kind != EntryKind::Directory || !is_yyyy(&year_ent.name) {
                    findings.push(
                        Finding::new(
                            FindingCode::LedgerPath,
                            Severity::Error,
                            format!(
                                "ledger/{} is not a four-digit year directory",
                                year_ent.name
                            ),
                        )
                        .at_file(paths::display_relative(&year_rel))
                        .with_fix("Use ledger/YYYY/MM.cfd"),
                    );
                    continue;
                }
                for month_ent in list_dir(root, &year_rel, findings) {
                    let file_rel = year_rel.join(&month_ent.name);
                    let file = paths::display_relative(&file_rel);
                    if !month_ent.utf8 || month_ent.kind == EntryKind::Symlink {
                        flag_entry(&month_ent, &file_rel, findings);
                        continue;
                    }
                    if paths::skip_walk_entry(&month_ent.name, month_ent.kind) {
                        continue;
                    }
                    if month_ent.kind != EntryKind::File || !is_month_cfd(&month_ent.name) {
                        findings.push(
                            Finding::new(
                                FindingCode::LedgerPath,
                                Severity::Error,
                                format!("'{file}' is not MM.cfd"),
                            )
                            .at_file(&file)
                            .with_fix("Name monthly ledgers 01.cfd through 12.cfd"),
                        );
                        continue;
                    }
                    let text = match paths::read_to_string(root, &file_rel) {
                        Ok(t) => t,
                        Err(err) => {
                            findings.push(
                                Finding::new(
                                    FindingCode::Unreadable,
                                    Severity::Error,
                                    err.to_string(),
                                )
                                .at_file(&file),
                            );
                            continue;
                        }
                    };
                    if has_conflict_markers(&text) {
                        findings.push(
                            Finding::new(
                                FindingCode::MergeConflict,
                                Severity::Error,
                                format!("'{file}' contains git conflict markers"),
                            )
                            .at_file(&file),
                        );
                    }
                    let (parsed, errors) = parse_ledger(&text);
                    for err in errors {
                        let code = match err.kind {
                            ParseErrorKind::InvalidId => FindingCode::InvalidId,
                            ParseErrorKind::Grammar => FindingCode::Parse,
                        };
                        findings.push(
                            Finding::new(code, Severity::Error, err.message)
                                .at_file(&file)
                                .at_line(err.line)
                                .with_fix(err.fix),
                        );
                    }
                    for (line, entry) in parsed {
                        entries.push(SourcedEntry {
                            file: file.clone(),
                            line,
                            entry,
                        });
                    }
                }
            }
        }
    }
}

fn is_yyyy(s: &str) -> bool {
    s.len() == 4 && s.chars().all(|c| c.is_ascii_digit())
}

fn is_month_cfd(s: &str) -> bool {
    let Some(mm) = s.strip_suffix(".cfd") else {
        return false;
    };
    matches!(
        mm,
        "01" | "02" | "03" | "04" | "05" | "06" | "07" | "08" | "09" | "10" | "11" | "12"
    )
}

#[cfg(test)]
mod tests {
    use super::is_month_cfd;

    #[test]
    fn month_names() {
        assert!(is_month_cfd("10.cfd"));
        assert!(!is_month_cfd("1.cfd"));
        assert!(!is_month_cfd("13.cfd"));
        assert!(!is_month_cfd("10.md"));
    }
}
