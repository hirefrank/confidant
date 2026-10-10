//! Load a vault from disk: config, records, ledger.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use crate::check::{Finding, FindingCode, Severity};
use crate::config::{VaultConfig, SPEC_VERSION};
use crate::id::{
    collect_uncovered_ulid_windows, record_id_from_entry_name, scan_id_tokens, IdToken, Prefix,
    RecordId,
};
use crate::ledger::{parse_ledger, LedgerEntry, ParseErrorKind};
use crate::paths::{self, EntryKind};
use crate::record::{
    frontmatter_line_spec_key, has_conflict_markers, parse_record, Record, RecordKind,
};

const COLLECTIONS: &[&str] = &["people", "orgs", "deals", "interactions", "notes"];

#[derive(Clone, Debug)]
pub struct SourcedEntry {
    pub file: String,
    pub line: u32,
    pub entry: LedgerEntry,
}

/// Original ledger file line, including unparsable ones, for search.
#[derive(Clone, Debug)]
pub struct LedgerLine {
    pub file: String,
    pub line: u32,
    pub text: String,
    pub id: Option<String>,
    /// Canonical `ledger/YYYY/MM.cfd` lines are searchable. Other `*.cfd`
    /// files are read only for link tokens (notes, merges, package openers).
    pub searchable: bool,
}

#[derive(Clone, Debug)]
pub struct Vault {
    pub root: PathBuf,
    pub config: VaultConfig,
    pub records: BTreeMap<RecordId, Record>,
    pub entries: Vec<SourcedEntry>,
    pub ledger_lines: Vec<LedgerLine>,
    pub load_findings: Vec<Finding>,
    /// Number of unreadable ledger paths (code+count only; never a path).
    /// `find` refuses when this is greater than zero.
    pub ledger_unread_count: u32,
    /// Path-derived record IDs, including files/directories that failed to load.
    /// Always uncleared when not present in `records`.
    pub path_ids: BTreeSet<RecordId>,
    /// Crockford ULIDs taken from visited file/directory names whose windows
    /// are not already a loaded record's own exact name.
    pub path_ulids: BTreeSet<String>,
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
    let mut path_ids = BTreeSet::new();
    let mut path_ulids = BTreeSet::new();
    let mut entries = Vec::new();
    let mut ledger_lines = Vec::new();
    let mut ledger_unread_count = 0u32;

    if config.spec == SPEC_VERSION {
        scan_collections(root, &mut records, &mut path_ids, &mut findings);
        scan_ledger(
            root,
            &mut entries,
            &mut ledger_lines,
            &mut findings,
            &mut ledger_unread_count,
        );
        scan_unexpected_top_level(root, &mut findings);
        let mut names = Vec::new();
        walk_seed_names(root, Path::new(""), &mut path_ids, &mut names);
        seed_path_ulids(&names, &records, &mut path_ulids);
    }

    Ok(Vault {
        root: root.to_path_buf(),
        config,
        records,
        entries,
        ledger_lines,
        load_findings: findings,
        ledger_unread_count,
        path_ids,
        path_ulids,
    })
}

enum Listed {
    Ok(Vec<paths::DirectoryEntry>),
    Failed,
}

fn list_dir(root: &Path, rel: &Path, findings: &mut Vec<Finding>) -> Listed {
    match paths::read_dir(root, rel) {
        Ok(listing) => {
            for (name, _) in listing.errors {
                findings.push(
                    Finding::new(
                        FindingCode::Unreadable,
                        Severity::Error,
                        "path is unreadable".to_owned(),
                    )
                    .at_file(redacted_filename(&rel.join(name)))
                    .with_fix("Fix permissions or replace the unreadable entry"),
                );
            }
            Listed::Ok(listing.entries)
        }
        Err(_) => {
            // #7: keep "." for the empty root; anything else goes through
            // the redactor so a leaky directory name never reaches JSON.
            let file = if rel.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                redacted_filename(rel)
            };
            findings.push(
                Finding::new(
                    FindingCode::Unreadable,
                    Severity::Error,
                    "path is unreadable".to_owned(),
                )
                .at_file(file)
                .with_fix("Fix directory permissions or replace the unreadable path"),
            );
            Listed::Failed
        }
    }
}

fn seed_entry_id(name: &str, path_ids: &mut BTreeSet<RecordId>) {
    if let Some(id) = record_id_from_entry_name(name) {
        path_ids.insert(id);
    }
}

fn seed_name_tokens(name: &str, path_ids: &mut BTreeSet<RecordId>, names: &mut Vec<String>) {
    names.push(name.to_owned());
    for tok in scan_id_tokens(name) {
        for id in tok.record_ids() {
            path_ids.insert(id.clone());
        }
    }
}

fn name_matches_loaded_record_exactly(name: &str, records: &BTreeMap<RecordId, Record>) -> bool {
    let mut candidate = name;
    loop {
        if let Ok(id) = RecordId::parse(candidate) {
            return records.contains_key(&id);
        }
        match candidate.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => candidate = stem,
            _ => break,
        }
    }
    false
}

fn seed_path_ulids(
    names: &[String],
    records: &BTreeMap<RecordId, Record>,
    path_ulids: &mut BTreeSet<String>,
) {
    for name in names {
        if name_matches_loaded_record_exactly(name, records) {
            continue;
        }
        collect_uncovered_ulid_windows(name, path_ulids);
    }
}

fn walk_seed_names(
    root: &Path,
    rel: &Path,
    path_ids: &mut BTreeSet<RecordId>,
    names: &mut Vec<String>,
) {
    let Ok(listing) = paths::read_dir(root, rel) else {
        return;
    };
    for (name, _) in listing.errors {
        seed_name_tokens(&name, path_ids, names);
    }
    for ent in listing.entries {
        if ent.utf8 {
            seed_name_tokens(&ent.name, path_ids, names);
        }
        if !ent.utf8 || ent.kind == EntryKind::Symlink {
            continue;
        }
        if paths::skip_walk_entry(&ent.name, ent.kind) {
            continue;
        }
        if ent.kind == EntryKind::Directory {
            walk_seed_names(root, &rel.join(&ent.name), path_ids, names);
        }
    }
}

fn leftover_tmp(name: &str, child: &Path, findings: &mut Vec<Finding>) -> bool {
    if !paths::is_leftover_temp(name) {
        return false;
    }
    findings.push(
        Finding::new(
            FindingCode::InvalidFilename,
            Severity::Error,
            "leftover temporary file".to_owned(),
        )
        .at_file(redacted_filename(child))
        .with_fix("Delete .confidant-tmp-* leftovers from a crashed write"),
    );
    true
}

/// `file` value for a finding about a path that is not a valid vault path
/// (#7). Any component could be a client name — the threat model (§4)
/// protects against filenames revealing who is a client — so the path is
/// reported only up to the first untrusted component, which is replaced
/// with a marker. The operator lists that directory to find the offending
/// file; `check --json` output an agent might forward to a model never
/// carries the name. When every component is trusted, the joined path is
/// returned unchanged (callers must pass vault-relative paths: an absolute
/// or `./`-prefixed path fails the trust test on its first component and
/// collapses to a bare marker, losing the parent directory).
fn redacted_filename(child: &Path) -> String {
    const MARKER: &str = "<invalid-filename>";
    let mut kept: Vec<&str> = Vec::new();
    let mut truncated = false;
    for comp in child.components() {
        let Some(s) = comp.as_os_str().to_str() else {
            truncated = true;
            break;
        };
        if is_trusted_component(s) {
            kept.push(s);
        } else {
            truncated = true;
            break;
        }
    }
    if kept.is_empty() {
        return MARKER.to_owned();
    }
    if truncated {
        format!("{}/{MARKER}", kept.join("/"))
    } else {
        kept.join("/")
    }
}

/// Path components that can never be a client name: structural directories,
/// valid record IDs (bare or with the `.md` record-file suffix), ledger
/// years/months, and fixed filenames.
fn is_trusted_component(name: &str) -> bool {
    matches!(
        name,
        "people"
            | "orgs"
            | "deals"
            | "interactions"
            | "notes"
            | "ledger"
            | "keys"
            | ".confidant"
            | "confidant.toml"
            | "profile.md"
            | "deal.md"
            | "interaction.md"
    ) || is_yyyy(name)
        || is_month_cfd(name)
        || RecordId::parse(name).is_ok()
        || name
            .strip_suffix(".md")
            .is_some_and(|stem| RecordId::parse(stem).is_ok())
}

fn flag_entry(ent: &paths::DirectoryEntry, child: &Path, findings: &mut Vec<Finding>) {
    if !ent.utf8 {
        findings.push(
            Finding::new(
                FindingCode::InvalidFilename,
                Severity::Error,
                "non-UTF-8 filename".to_owned(),
            )
            .at_file(redacted_filename(child))
            .with_fix("Rename the file to a UTF-8 record ID"),
        );
        return;
    }
    if ent.kind == EntryKind::Symlink {
        findings.push(
            Finding::new(
                FindingCode::Symlink,
                Severity::Error,
                "symbolic link".to_owned(),
            )
            .at_file(redacted_filename(child))
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
    let Listed::Ok(entries) = list_dir(root, Path::new(""), findings) else {
        return;
    };
    for ent in entries {
        let child = Path::new(&ent.name);
        if leftover_tmp(&ent.name, child, findings) {
            continue;
        }
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
                    "unexpected vault entry".to_owned(),
                )
                .at_file(redacted_filename(Path::new(&ent.name)))
                .with_fix("Use the layout in spec/0.1.md (people/, orgs/, deals/, ledger/, …)"),
            );
        }
    }
}

fn scan_collections(
    root: &Path,
    records: &mut BTreeMap<RecordId, Record>,
    path_ids: &mut BTreeSet<RecordId>,
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
            Ok(listing) => {
                for (name, _) in listing.errors {
                    seed_entry_id(&name, path_ids);
                    findings.push(
                        Finding::new(
                            FindingCode::Unreadable,
                            Severity::Error,
                            "path is unreadable".to_owned(),
                        )
                        .at_file(redacted_filename(&rel.join(&name)))
                        .with_fix("Fix permissions or replace the unreadable entry"),
                    );
                }
                let prefix = Prefix::from_collection(collection).expect("known collection");
                for ent in listing.entries {
                    let child = rel.join(&ent.name);
                    if ent.utf8 {
                        seed_entry_id(&ent.name, path_ids);
                    }
                    if leftover_tmp(&ent.name, &child, findings) {
                        continue;
                    }
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
                                ingest_file(
                                    root, &child, stem, prefix, records, path_ids, findings,
                                );
                            } else {
                                findings.push(
                                    Finding::new(
                                        FindingCode::InvalidFilename,
                                        Severity::Error,
                                        "filename is not a valid record ID".to_owned(),
                                    )
                                    .at_file(redacted_filename(&child))
                                    .with_fix("Rename to <prefix>-<ULID>.md or move it out of the collection"),
                                );
                            }
                        }
                        EntryKind::Directory => {
                            ingest_dir(
                                root, &child, &ent.name, prefix, records, path_ids, findings,
                            );
                        }
                        EntryKind::Other => findings.push(
                            Finding::new(
                                FindingCode::InvalidFilename,
                                Severity::Error,
                                "record directory contains an unexpected entry".to_owned(),
                            )
                            .at_file(redacted_filename(&child)),
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
    path_ids: &mut BTreeSet<RecordId>,
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
                    "filename is not a valid record ID".to_owned(),
                )
                .at_file(redacted_filename(relative))
                .with_fix("Name the file <prefix>-<26-character ULID>.md"),
            );
            return;
        }
    };
    path_ids.insert(path_id.clone());
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
    path_ids: &mut BTreeSet<RecordId>,
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
                    "directory name is not a valid record ID".to_owned(),
                )
                .at_file(redacted_filename(relative))
                .with_fix("Name the directory <prefix>-<26-character ULID>"),
            );
            return;
        }
    };
    path_ids.insert(path_id.clone());
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
    let entries = match list_dir(root, relative, findings) {
        Listed::Failed => return,
        Listed::Ok(entries) => entries,
    };
    for ent in entries {
        let child = relative.join(&ent.name);
        if ent.utf8 {
            seed_entry_id(&ent.name, path_ids);
        }
        if leftover_tmp(&ent.name, &child, findings) {
            continue;
        }
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
            scan_person_notes(root, relative, &path_id, records, path_ids, findings);
            continue;
        }
        findings.push(
            Finding::new(
                FindingCode::InvalidFilename,
                Severity::Error,
                "record directory contains an unexpected entry".to_owned(),
            )
            .at_file(redacted_filename(&child))
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
                "record directory is missing the main file".to_owned(),
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
    path_ids: &mut BTreeSet<RecordId>,
    findings: &mut Vec<Finding>,
) {
    let notes_rel = person_dir.join("notes");
    match paths::read_dir(root, &notes_rel) {
        Err(err) if crate::error::is_missing(&err) => {}
        Err(_) => {
            let _ = list_dir(root, &notes_rel, findings);
        }
        Ok(listing) => {
            for (name, _) in listing.errors {
                seed_entry_id(&name, path_ids);
                findings.push(
                    Finding::new(
                        FindingCode::Unreadable,
                        Severity::Error,
                        "path is unreadable".to_owned(),
                    )
                    .at_file(redacted_filename(&notes_rel.join(&name)))
                    .with_fix("Fix permissions or replace the unreadable entry"),
                );
            }
            for ent in listing.entries {
                let child = notes_rel.join(&ent.name);
                if ent.utf8 {
                    seed_entry_id(&ent.name, path_ids);
                }
                if leftover_tmp(&ent.name, &child, findings) {
                    continue;
                }
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
                            "filename is not a valid record ID".to_owned(),
                        )
                        .at_file(redacted_filename(&child)),
                    );
                    continue;
                }
                let stem = ent.name.trim_end_matches(".md");
                ingest_file(
                    root,
                    &child,
                    stem,
                    Prefix::Note,
                    records,
                    path_ids,
                    findings,
                );
                if let Ok(id) = RecordId::parse(stem) {
                    if let Some(rec) = records.get(&id) {
                        if rec.person().as_ref().is_some_and(|p| p != person_id) {
                            findings.push(
                                Finding::new(
                                    FindingCode::IdPathMismatch,
                                    Severity::Error,
                                    "front matter key 'person' does not match the path".to_owned(),
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
        Err(_) => {
            findings.push(
                Finding::new(
                    FindingCode::Unreadable,
                    Severity::Error,
                    "path is unreadable".to_owned(),
                )
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
                "file contains git conflict markers".to_owned(),
            )
            .at_file(&file)
            .with_fix("Resolve the conflict; check keeps both sides visible until you do"),
        );
    }
    match parse_record(&text, &file) {
        Err(err) => {
            let mut finding =
                Finding::new(FindingCode::Frontmatter, Severity::Error, err.message).at_file(&file);
            if let Some(line) = err.line {
                finding = finding.at_line(line);
            }
            findings.push(finding.with_fix(err.fix));
        }
        Ok(mut rec) => {
            rec.path = file.clone();
            flag_malformed_frontmatter(&rec, findings);
            if let Some(pid) = path_id {
                if rec.id != *pid {
                    findings.push(
                        Finding::new(
                            FindingCode::IdPathMismatch,
                            Severity::Error,
                            "front matter key 'id' does not match the path".to_owned(),
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
                            format!("type '{}' does not belong at this path", rec.kind.as_str()),
                        )
                        .at_file(&file)
                        .for_id(&rec.id),
                    );
                }
            }
            if records.contains_key(&rec.id) {
                findings.push(
                    Finding::new(
                        FindingCode::DuplicateId,
                        Severity::Error,
                        "the same id appears in two files".to_owned(),
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

fn flag_malformed_frontmatter(rec: &Record, findings: &mut Vec<Finding>) {
    let text = rec.source.trim_start_matches('\u{feff}');
    for (idx, line) in text.lines().enumerate() {
        let line_no = idx as u32 + 1;
        if line_no >= rec.body_start_line {
            break;
        }
        if !scan_id_tokens(line).iter().any(IdToken::is_malformed) {
            continue;
        }
        let message = match frontmatter_line_spec_key(line) {
            Some(key) => format!("front matter key '{key}' is not a record ID (line {line_no})"),
            None => format!("front matter line {line_no} is not a record ID"),
        };
        findings.push(
            Finding::new(FindingCode::InvalidId, Severity::Error, message)
                .at_file(&rec.path)
                .at_line(line_no)
                .for_id(&rec.id)
                .with_fix("Use a prefixed 26-character Crockford ULID"),
        );
    }
}

fn scan_ledger(
    root: &Path,
    entries: &mut Vec<SourcedEntry>,
    ledger_lines: &mut Vec<LedgerLine>,
    findings: &mut Vec<Finding>,
    unread: &mut u32,
) {
    let ledger_rel = Path::new("ledger");
    let mut visited = HashSet::new();
    match paths::read_dir(root, ledger_rel) {
        Err(err) if crate::error::is_missing(&err) => {}
        Err(_) => {
            let _ = list_dir(root, ledger_rel, findings);
            *unread += 1;
        }
        Ok(_) => walk_ledger(
            root,
            ledger_rel,
            entries,
            ledger_lines,
            findings,
            unread,
            &mut visited,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_ledger(
    root: &Path,
    rel: &Path,
    entries: &mut Vec<SourcedEntry>,
    ledger_lines: &mut Vec<LedgerLine>,
    findings: &mut Vec<Finding>,
    unread: &mut u32,
    visited: &mut HashSet<PathBuf>,
) {
    if let Some(canon) = canonicalize_under_root(root, rel) {
        if !visited.insert(canon) {
            return;
        }
    }
    let listing = match paths::read_dir(root, rel) {
        Err(_) => {
            let _ = list_dir(root, rel, findings);
            *unread += 1;
            return;
        }
        Ok(listing) => {
            *unread += listing.errors.len() as u32;
            for (name, _) in listing.errors {
                findings.push(
                    Finding::new(
                        FindingCode::Unreadable,
                        Severity::Error,
                        "path is unreadable".to_owned(),
                    )
                    // #7: entry names from a directory listing are unvalidated.
                    .at_file(redacted_filename(&rel.join(&name)))
                    .with_fix("Fix permissions or replace the unreadable entry"),
                );
            }
            listing.entries
        }
    };
    for ent in listing {
        process_ledger_entry(
            root,
            rel,
            &ent,
            None,
            entries,
            ledger_lines,
            findings,
            unread,
            visited,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_ledger_resolved(
    root: &Path,
    rel: &Path,
    canon: &Path,
    entries: &mut Vec<SourcedEntry>,
    ledger_lines: &mut Vec<LedgerLine>,
    findings: &mut Vec<Finding>,
    unread: &mut u32,
    visited: &mut HashSet<PathBuf>,
) {
    if !visited.insert(canon.to_path_buf()) {
        return;
    }
    let listing = match std::fs::read_dir(canon) {
        Err(_) => {
            *unread += 1;
            findings.push(
                Finding::new(
                    FindingCode::Unreadable,
                    Severity::Error,
                    "path is unreadable".to_owned(),
                )
                // #7: the symlinked directory's vault-relative name is
                // unvalidated.
                .at_file(redacted_filename(rel))
                .with_fix("Fix permissions or replace the unreadable path"),
            );
            return;
        }
        Ok(rd) => rd,
    };
    for ent in listing {
        let Ok(ent) = ent else {
            *unread += 1;
            continue;
        };
        let name_os = ent.file_name();
        let utf8 = name_os.to_str().is_some();
        let name = name_os.to_string_lossy().into_owned();
        let kind = match ent.file_type() {
            Ok(ft) if ft.is_symlink() => EntryKind::Symlink,
            Ok(ft) if ft.is_dir() => EntryKind::Directory,
            Ok(ft) if ft.is_file() => EntryKind::File,
            Ok(_) => EntryKind::Other,
            Err(_) => {
                *unread += 1;
                continue;
            }
        };
        let fake = paths::DirectoryEntry { name, utf8, kind };
        process_ledger_entry(
            root,
            rel,
            &fake,
            Some(canon),
            entries,
            ledger_lines,
            findings,
            unread,
            visited,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn process_ledger_entry(
    root: &Path,
    parent: &Path,
    ent: &paths::DirectoryEntry,
    parent_canon: Option<&Path>,
    entries: &mut Vec<SourcedEntry>,
    ledger_lines: &mut Vec<LedgerLine>,
    findings: &mut Vec<Finding>,
    unread: &mut u32,
    visited: &mut HashSet<PathBuf>,
) {
    let child = parent.join(&ent.name);
    if leftover_tmp(&ent.name, &child, findings) {
        return;
    }
    if !ent.utf8 {
        flag_entry(ent, &child, findings);
        *unread += 1;
        return;
    }
    if ent.name.starts_with('.') {
        return;
    }
    if ent.kind == EntryKind::Symlink {
        flag_entry(ent, &child, findings);
        match resolve_in_vault(root, &child) {
            Some(InVault::File(canon)) => {
                load_ledger_file(
                    root,
                    &child,
                    Some(&canon),
                    entries,
                    ledger_lines,
                    findings,
                    unread,
                );
            }
            Some(InVault::Directory(canon)) => {
                walk_ledger_resolved(
                    root,
                    &child,
                    &canon,
                    entries,
                    ledger_lines,
                    findings,
                    unread,
                    visited,
                );
            }
            None => {
                *unread += 1;
            }
        }
        return;
    }
    match ent.kind {
        EntryKind::Directory => {
            if parent == Path::new("ledger") && !is_yyyy(&ent.name) {
                findings.push(
                    Finding::new(
                        FindingCode::LedgerPath,
                        Severity::Error,
                        "ledger year directory is not a four-digit year".to_owned(),
                    )
                    .at_file(redacted_filename(&child))
                    .with_fix("Use ledger/YYYY/MM.cfd"),
                );
            }
            if let Some(base) = parent_canon {
                walk_ledger_resolved(
                    root,
                    &child,
                    &base.join(&ent.name),
                    entries,
                    ledger_lines,
                    findings,
                    unread,
                    visited,
                );
            } else {
                walk_ledger(
                    root,
                    &child,
                    entries,
                    ledger_lines,
                    findings,
                    unread,
                    visited,
                );
            }
        }
        EntryKind::File => {
            let from = parent_canon.map(|base| base.join(&ent.name));
            load_ledger_file(
                root,
                &child,
                from.as_deref(),
                entries,
                ledger_lines,
                findings,
                unread,
            );
        }
        EntryKind::Other => {
            *unread += 1;
        }
        EntryKind::Symlink => {}
    }
}

enum InVault {
    File(PathBuf),
    Directory(PathBuf),
}

fn canonicalize_under_root(root: &Path, rel: &Path) -> Option<PathBuf> {
    let path = if rel.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    };
    path.canonicalize()
        .ok()
        .filter(|canon| is_under(root, canon))
}

fn is_under(root: &Path, path: &Path) -> bool {
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    path == root || path.starts_with(&root)
}

fn resolve_in_vault(root: &Path, rel: &Path) -> Option<InVault> {
    let link_path = root.join(rel);
    let target = std::fs::read_link(&link_path).ok()?;
    let joined = if target.is_absolute() {
        target
    } else {
        link_path.parent().unwrap_or(root).join(target)
    };
    let canon = joined.canonicalize().ok()?;
    if !is_under(root, &canon) {
        return None;
    }
    if canon.is_dir() {
        Some(InVault::Directory(canon))
    } else if canon.is_file() {
        Some(InVault::File(canon))
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn load_ledger_file(
    root: &Path,
    rel: &Path,
    read_from: Option<&Path>,
    entries: &mut Vec<SourcedEntry>,
    ledger_lines: &mut Vec<LedgerLine>,
    findings: &mut Vec<Finding>,
    unread: &mut u32,
) {
    // #7: the file value feeds E_MERGE_CONFLICT and E_UNREADABLE findings as
    // well as ledger lines, so it must be redacted here. A canonical
    // ledger/YYYY/MM.cfd is fully trusted and comes back unchanged.
    let file = redacted_filename(rel);
    let searchable = is_canonical_ledger_cfd(rel);
    if !searchable {
        findings.push(
            Finding::new(
                FindingCode::LedgerPath,
                Severity::Error,
                "ledger file is not MM.cfd".to_owned(),
            )
            .at_file(redacted_filename(rel))
            .with_fix("Name monthly ledgers 01.cfd through 12.cfd"),
        );
    }
    let text = match read_from {
        Some(canon) => match std::fs::read(canon) {
            Ok(buf) => match String::from_utf8(buf) {
                Ok(t) => t,
                Err(_) => {
                    *unread += 1;
                    findings.push(
                        Finding::new(
                            FindingCode::Unreadable,
                            Severity::Error,
                            "file is not valid UTF-8".to_owned(),
                        )
                        .at_file(&file)
                        .with_fix("Fix permissions or replace the unreadable path"),
                    );
                    return;
                }
            },
            Err(_) => {
                *unread += 1;
                findings.push(
                    Finding::new(
                        FindingCode::Unreadable,
                        Severity::Error,
                        "path is unreadable".to_owned(),
                    )
                    .at_file(&file)
                    .with_fix("Fix permissions or replace the unreadable path"),
                );
                return;
            }
        },
        None => match paths::read_to_string(root, rel) {
            Ok(t) => t,
            Err(_) => {
                *unread += 1;
                findings.push(
                    Finding::new(
                        FindingCode::Unreadable,
                        Severity::Error,
                        "path is unreadable".to_owned(),
                    )
                    .at_file(&file)
                    .with_fix("Fix permissions or replace the unreadable path"),
                );
                return;
            }
        },
    };
    ingest_ledger_text(&text, &file, searchable, entries, ledger_lines, findings);
}

fn ingest_ledger_text(
    text: &str,
    file: &str,
    searchable: bool,
    entries: &mut Vec<SourcedEntry>,
    ledger_lines: &mut Vec<LedgerLine>,
    findings: &mut Vec<Finding>,
) {
    if has_conflict_markers(text) {
        findings.push(
            Finding::new(
                FindingCode::MergeConflict,
                Severity::Error,
                "file contains git conflict markers".to_owned(),
            )
            .at_file(file),
        );
    }
    let text = text.trim_start_matches('\u{feff}');
    let mut by_line: BTreeMap<u32, LedgerEntry> = BTreeMap::new();
    if searchable {
        let (parsed, errors) = parse_ledger(text);
        for err in errors {
            let code = match err.kind {
                ParseErrorKind::InvalidId => FindingCode::InvalidId,
                ParseErrorKind::Grammar => FindingCode::Parse,
            };
            findings.push(
                Finding::new(code, Severity::Error, err.message)
                    .at_file(file)
                    .at_line(err.line)
                    .with_fix(err.fix),
            );
        }
        for (line, entry) in parsed {
            by_line.insert(line, entry);
        }
    }
    for (idx, raw) in text.lines().enumerate() {
        let line = idx as u32 + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let entry = by_line.remove(&line);
        ledger_lines.push(LedgerLine {
            file: file.to_owned(),
            line,
            text: raw.to_owned(),
            id: entry.as_ref().map(|e| e.id.to_string()),
            searchable,
        });
        if searchable {
            if let Some(entry) = entry {
                entries.push(SourcedEntry {
                    file: file.to_owned(),
                    line,
                    entry,
                });
            }
        }
    }
}

fn is_canonical_ledger_cfd(rel: &Path) -> bool {
    let mut parts = rel.iter().filter_map(|s| s.to_str());
    parts.next() == Some("ledger")
        && parts.next().is_some_and(is_yyyy)
        && parts.next().is_some_and(is_month_cfd)
        && parts.next().is_none()
}

fn is_yyyy(s: &str) -> bool {
    s.len() == 4 && s.chars().all(|c| c.is_ascii_digit())
}

fn is_month_cfd(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
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
    use super::{is_month_cfd, redacted_filename};
    use std::path::Path;

    #[test]
    fn month_names() {
        assert!(is_month_cfd("10.cfd"));
        assert!(is_month_cfd("10.CFD"));
        assert!(!is_month_cfd("1.cfd"));
        assert!(!is_month_cfd("13.cfd"));
        assert!(!is_month_cfd("10.md"));
    }

    #[test]
    fn redacted_filename_cases() {
        // A valid record file is trusted: returned unchanged, no marker.
        assert_eq!(
            redacted_filename(Path::new("people/p-01M3TC5H00MPJG000000000000.md")),
            "people/p-01M3TC5H00MPJG000000000000.md"
        );
        // Bare valid record IDs stay trusted too.
        assert_eq!(
            redacted_filename(Path::new("people/p-01M3TC5H00MPJG000000000000")),
            "people/p-01M3TC5H00MPJG000000000000"
        );
        // Nested note path: every component trusted, unchanged.
        assert_eq!(
            redacted_filename(Path::new(
                "people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG002NAM000005.md"
            )),
            "people/p-01M3TC5H00MPJG000000000000/notes/n-01M3TC5H00MPJG002NAM000005.md"
        );
        // Untrusted filename: redacted at the first bad component.
        assert_eq!(
            redacted_filename(Path::new("people/ZXQVLEAK.md")),
            "people/<invalid-filename>"
        );
        // A non-record .md is not trusted.
        assert_eq!(
            redacted_filename(Path::new("people/notes.md")),
            "people/<invalid-filename>"
        );
        // Absolute paths fail the trust test on the first component and
        // collapse to a bare marker (callers must pass vault-relative paths).
        assert_eq!(
            redacted_filename(Path::new("/vault/people/ZXQVLEAK.md")),
            "<invalid-filename>"
        );
        // Same for ./-prefixed paths.
        assert_eq!(
            redacted_filename(Path::new("./people/ZXQVLEAK.md")),
            "<invalid-filename>"
        );
    }
}
