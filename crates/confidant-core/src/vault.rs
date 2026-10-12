//! Load a vault from disk: config, records, ledger.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::check::{Finding, FindingCode, Severity};
use crate::config::{VaultConfig, SPEC_VERSION};
use crate::id::{collect_uncovered_ulid_windows, scan_id_tokens, IdToken, Prefix, RecordId};
use crate::ledger::{parse_ledger, LedgerEntry, ParseErrorKind};
use crate::paths::{self, EntryKind};
use crate::record::{
    frontmatter_line_spec_key, has_conflict_markers, parse_record, Record, RecordKind,
};

const COLLECTIONS: &[&str] = &["people", "orgs", "deals", "interactions", "notes"];

/// Per-file outcome of the read-path content hook (spec 4, issue #148).
///
/// Core stays keyless: it never sees key material or `confidant-crypt`
/// types. The CLI implements the hook with its decryptor; `check` passes
/// no hook and keeps today's structural behavior.
#[derive(Debug)]
pub enum ContentOutcome {
    /// Bytes for core to parse as the record: plaintext passthrough or
    /// decrypted inner record.
    Content(Vec<u8>),
    /// Envelope with `no-ai: true` in the outer header. Core synthesizes a
    /// shell record from the header (`id`/`type`/`no-ai: true`, empty body)
    /// so `context` keeps working and `find` keeps excluding it via the
    /// existing §12 allowlist rule. Never decrypted.
    NoAiShell { id: String, record_type: String },
    /// Encrypted record this device cannot read (no device key, or the data
    /// key won't unwrap). Not loaded; counted as `skipped_encrypted`.
    Skipped,
    /// Envelope failed structural parse or AEAD authentication
    /// (tampered/corrupt). Not loaded; counted as `refused_envelopes`.
    /// Never folded into the skip count.
    Refused,
}

/// Opaque per-file content provider for the read path: vault-relative path
/// and raw file bytes in, [`ContentOutcome`] out. `Send + Sync` because
/// record files load on worker threads.
pub type ContentHook = Arc<dyn Fn(&str, &[u8]) -> ContentOutcome + Send + Sync>;

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
    /// Record files skipped as encrypted-but-unreadable by the content hook
    /// (spec 4). No-ai envelopes are loaded as shells, not counted here.
    pub skipped_encrypted: u32,
    /// Envelopes refused as tampered/corrupt by the content hook (spec 4).
    /// Never folded into `skipped_encrypted`.
    pub refused_envelopes: u32,
}

pub fn load_vault(root: &Path) -> Result<Vault, crate::error::DomainError> {
    load_vault_with_hook(root, None)
}

/// Load a vault, applying `hook` to every record file's raw bytes before
/// parsing (spec 4). `None` keeps the historical behavior: raw bytes are
/// parsed as-is (`check` stays keyless and structural).
pub fn load_vault_with_hook(
    root: &Path,
    hook: Option<ContentHook>,
) -> Result<Vault, crate::error::DomainError> {
    let root = root
        .canonicalize()
        .map_err(|_| crate::error::DomainError::vault_not_found())?;
    load_vault_inner(&root, hook.as_ref()).map_err(|err| {
        crate::error::DomainError::of(&err)
            .cloned()
            .unwrap_or_else(|| crate::error::DomainError::invalid(err.to_string()))
    })
}

fn load_vault_inner(root: &Path, hook: Option<&ContentHook>) -> anyhow::Result<Vault> {
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
    let mut skipped_encrypted = 0u32;
    let mut refused_envelopes = 0u32;

    if config.spec == SPEC_VERSION {
        let mut jobs = Vec::new();
        let mut names = Vec::new();
        scan_collections(root, &mut path_ids, &mut findings, &mut jobs, &mut names);
        let outs = load_markdown_jobs(root, &jobs, hook);
        for (job, out) in jobs.iter().zip(outs) {
            skipped_encrypted += out.skipped;
            refused_envelopes += out.refused;
            merge_markdown_job(job, (out.record, out.findings), &mut records, &mut findings);
        }
        scan_ledger(
            root,
            &mut entries,
            &mut ledger_lines,
            &mut findings,
            &mut ledger_unread_count,
        );
        scan_unexpected_top_level(root, &mut findings);
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
        skipped_encrypted,
        refused_envelopes,
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
            // Collection subtrees were already seeded name-by-name during
            // scan_collections; descending again would re-list hundreds of
            // directories for identical seeds (#2).
            if rel.as_os_str().is_empty() && COLLECTIONS.contains(&ent.name.as_str()) {
                continue;
            }
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
            | "org.md"
            | "note.md"
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
    path_ids: &mut BTreeSet<RecordId>,
    findings: &mut Vec<Finding>,
    jobs: &mut Vec<MarkdownJob>,
    names: &mut Vec<String>,
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
                    seed_name_tokens(&name, path_ids, names);
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
                        seed_name_tokens(&ent.name, path_ids, names);
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
                                ingest_file(&child, stem, prefix, path_ids, findings, jobs, None);
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
                                root, &child, &ent.name, prefix, path_ids, findings, jobs, names,
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
    relative: &Path,
    stem: &str,
    expected_prefix: Prefix,
    path_ids: &mut BTreeSet<RecordId>,
    findings: &mut Vec<Finding>,
    jobs: &mut Vec<MarkdownJob>,
    note_owner: Option<&RecordId>,
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
    // Content loads in parallel; the walk keeps going.
    jobs.push(MarkdownJob {
        relative: relative.to_path_buf(),
        path_id: Some(path_id),
        note_owner: note_owner.cloned(),
    });
}

#[allow(clippy::too_many_arguments)]
fn ingest_dir(
    root: &Path,
    relative: &Path,
    name: &str,
    expected_prefix: Prefix,
    path_ids: &mut BTreeSet<RecordId>,
    findings: &mut Vec<Finding>,
    jobs: &mut Vec<MarkdownJob>,
    names: &mut Vec<String>,
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
            // The walk stops here, but the seed walk must still see the
            // names below: an unexpected directory can hide ID-shaped file
            // names that seed bare-ULID matching (#116 hold).
            walk_seed_names(root, relative, path_ids, names);
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
            seed_name_tokens(&ent.name, path_ids, names);
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
            jobs.push(MarkdownJob {
                relative: child,
                path_id: Some(path_id.clone()),
                note_owner: None,
            });
            continue;
        }
        if expected_prefix == Prefix::Person
            && ent.name == "notes"
            && ent.kind == EntryKind::Directory
        {
            scan_person_notes(root, relative, &path_id, path_ids, findings, jobs, names);
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
        // Same seed-walk reasoning as the invalid-dir return above: the
        // walk stops here, so an unexpected directory's subtree still
        // needs name seeding (#116 hold).
        if ent.kind == EntryKind::Directory {
            walk_seed_names(root, &child, path_ids, names);
        }
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
    path_ids: &mut BTreeSet<RecordId>,
    findings: &mut Vec<Finding>,
    jobs: &mut Vec<MarkdownJob>,
    names: &mut Vec<String>,
) {
    let notes_rel = person_dir.join("notes");
    match paths::read_dir(root, &notes_rel) {
        Err(err) if crate::error::is_missing(&err) => {}
        Err(_) => {
            let _ = list_dir(root, &notes_rel, findings);
        }
        Ok(listing) => {
            for (name, _) in listing.errors {
                seed_name_tokens(&name, path_ids, names);
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
                    seed_name_tokens(&ent.name, path_ids, names);
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
                    // Unexpected directories (e.g. notes/sub/) still need
                    // name seeding for the seed walk (#116 hold).
                    if ent.kind == EntryKind::Directory {
                        walk_seed_names(root, &child, path_ids, names);
                    }
                    continue;
                }
                let stem = ent.name.trim_end_matches(".md");
                ingest_file(
                    &child,
                    stem,
                    Prefix::Note,
                    path_ids,
                    findings,
                    jobs,
                    Some(person_id),
                );
            }
        }
    }
}

/// One markdown record file whose content loads in parallel. The
/// directory walk collects jobs serially; worker threads read, parse and
/// check them; the merge step folds results back in walk order, so
/// findings, records and duplicate detection match a serial load
/// exactly (#2).
struct MarkdownJob {
    relative: PathBuf,
    path_id: Option<RecordId>,
    /// Owning person directory for a note under `people/<id>/notes/`.
    /// The person-mismatch check runs at merge against the merged
    /// (first-inserted) record, mirroring the serial walk.
    note_owner: Option<RecordId>,
}

/// Read, parse and check the jobs on worker threads, preserving job
/// order in the output so the merge is deterministic.
fn load_markdown_jobs(
    root: &Path,
    jobs: &[MarkdownJob],
    hook: Option<&ContentHook>,
) -> Vec<JobOutput> {
    if jobs.is_empty() {
        return Vec::new();
    }
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(jobs.len());
    let chunk = jobs.len().div_ceil(threads);
    let mut out = Vec::with_capacity(jobs.len());
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(threads);
        for part in jobs.chunks(chunk) {
            handles.push(s.spawn(|| {
                part.iter()
                    .map(|job| run_markdown_job(root, job, hook))
                    .collect::<Vec<_>>()
            }));
        }
        for handle in handles {
            out.extend(handle.join().expect("markdown loader thread panicked"));
        }
    });
    out
}

/// One job's result: the parsed record (if any), its findings, and the
/// spec-4 hook counts.
struct JobOutput {
    record: Option<Record>,
    findings: Vec<Finding>,
    skipped: u32,
    refused: u32,
}

/// Merge one job result: content findings first (walk order is preserved
/// by the caller), then duplicate detection and insert, then the
/// note-owner mismatch check against the merged record.
fn merge_markdown_job(
    job: &MarkdownJob,
    out: (Option<Record>, Vec<Finding>),
    records: &mut BTreeMap<RecordId, Record>,
    findings: &mut Vec<Finding>,
) {
    let (parsed, mut job_findings) = out;
    findings.append(&mut job_findings);
    let Some(rec) = parsed else { return };
    let id = rec.id.clone();
    if records.contains_key(&id) {
        findings.push(
            Finding::new(
                FindingCode::DuplicateId,
                Severity::Error,
                "the same id appears in two files".to_owned(),
            )
            .at_file(&rec.path)
            .for_id(&id)
            .with_fix("Keep one file per id"),
        );
    } else {
        records.insert(id.clone(), rec);
    }
    if let Some(owner) = &job.note_owner {
        if let Some(merged) = records.get(&id) {
            if merged.person().as_ref().is_some_and(|p| p != owner) {
                findings.push(
                    Finding::new(
                        FindingCode::IdPathMismatch,
                        Severity::Error,
                        "front matter key 'person' does not match the path".to_owned(),
                    )
                    .at_file(paths::display_relative(&job.relative))
                    .for_id(&id),
                );
            }
        }
    }
}

fn run_markdown_job(root: &Path, job: &MarkdownJob, hook: Option<&ContentHook>) -> JobOutput {
    let mut findings = Vec::new();
    let file = paths::display_relative(&job.relative);
    let fail = |findings: Vec<Finding>| JobOutput {
        record: None,
        findings,
        skipped: 0,
        refused: 0,
    };
    let text = match paths::read_to_string(root, &job.relative) {
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
            return fail(findings);
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
    // Spec 4: the content hook maps raw bytes to the bytes core parses
    // (decrypted inner record), a no-ai shell, or a skip/refuse decision.
    // `check` passes no hook and keeps the historical behavior.
    let bytes: Vec<u8> = match hook {
        None => text.into_bytes(),
        Some(hook) => match hook(&file, text.as_bytes()) {
            ContentOutcome::Content(bytes) => bytes,
            ContentOutcome::NoAiShell { id, record_type } => {
                // Synthesize the public shell from the outer header:
                // id/type/no-ai are plaintext in the envelope, the body
                // stays empty. The allowlist excludes it via `no_ai()`
                // exactly like a plaintext no-ai record.
                format!("---\nid: {id}\ntype: {record_type}\nno-ai: true\n---\n").into_bytes()
            }
            ContentOutcome::Skipped => {
                return JobOutput {
                    record: None,
                    findings,
                    skipped: 1,
                    refused: 0,
                }
            }
            ContentOutcome::Refused => {
                return JobOutput {
                    record: None,
                    findings,
                    skipped: 0,
                    refused: 1,
                }
            }
        },
    };
    let text = match String::from_utf8(bytes) {
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
            return fail(findings);
        }
    };
    match parse_record(&text, &file) {
        Err(err) => {
            let mut finding =
                Finding::new(FindingCode::Frontmatter, Severity::Error, err.message).at_file(&file);
            if let Some(line) = err.line {
                finding = finding.at_line(line);
            }
            findings.push(finding.with_fix(err.fix));
            JobOutput {
                record: None,
                findings,
                skipped: 0,
                refused: 0,
            }
        }
        Ok(mut rec) => {
            rec.path = file.clone();
            flag_malformed_frontmatter(&rec, &mut findings);
            if let Some(pid) = &job.path_id {
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
            // Duplicate detection and insert happen at merge, in walk
            // order, so parallel results match a serial load exactly.
            JobOutput {
                record: Some(rec),
                findings,
                skipped: 0,
                refused: 0,
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
        // Valid org and note files keep their last component (#100-12:
        // org.md and note.md are trusted components per spec section 2).
        assert_eq!(
            redacted_filename(Path::new("orgs/o-01M3TC5H00MPJG000000000000/org.md")),
            "orgs/o-01M3TC5H00MPJG000000000000/org.md"
        );
        assert_eq!(
            redacted_filename(Path::new("notes/n-01M3TC5H00MPJG002NAM000005/note.md")),
            "notes/n-01M3TC5H00MPJG002NAM000005/note.md"
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
