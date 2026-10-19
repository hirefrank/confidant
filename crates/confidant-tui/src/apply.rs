//! Proposal apply engine: the #211 apply sequence as a plan + runner calls.
//!
//! The engine never invents ids (a grep test on this file enforces that no
//! id-generation helpers or crates are used here) and never writes into the
//! vault tree — every write goes through the `confidant` CLI over the
//! Phase 1 [`Runner`]. Plaintext from dry-run output is returned to the
//! caller for on-screen rendering only; it is never logged.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::contract::{parse_raw_output, CheckReport, ContractOutcome};
use crate::proposals::{
    is_planned_under_dir, is_under_dir, manifest_stem, open_secure_write, progress_file_corrupt,
    progress_path, read_manifest, read_progress, write_progress, ProposalManifest, TuiProgress,
};
use crate::runner::{RawOutput, Runner};

/// One file change previewed by a `--dry-run` write.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct DryRunChange {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub content: String,
}

/// Outcome of a single CLI write invocation (dry-run or real).
#[derive(Clone, Debug, PartialEq)]
pub enum WriteOutcome {
    /// `--dry-run` preview: nothing written, nothing committed.
    DryRun {
        command: String,
        changes: Vec<DryRunChange>,
    },
    /// Applied: one commit.
    Applied { command: String, commit: String },
    /// The request id was already applied, or the write would not change
    /// anything (`unchanged`): the desired state already holds, so it
    /// counts as done.
    Idempotent { command: String, commit: String },
    /// `check` blocked the write (exit 1 with a bare `CheckReport`).
    CheckBlocked { report: CheckReport },
    /// Anything else: usage error, error envelope, bad JSON, version skew.
    CliError {
        code: String,
        message: String,
        fix: Option<String>,
    },
}

#[derive(Clone, Debug, Default, Deserialize)]
struct WriteEnvelope {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    commit: Option<String>,
    #[serde(default)]
    changes: Vec<DryRunChange>,
    #[serde(default)]
    idempotent: bool,
    /// The write changed nothing: the content already matches (ADR-7
    /// `unchanged`). No commit is reported with it.
    #[serde(default)]
    unchanged: bool,
}

/// Run one CLI write command and classify its JSON output.
///
/// `argv` must not contain `--dry-run`; pass `dry_run = true` to add it.
pub fn run_write_step<R: Runner>(
    runner: &R,
    argv: &[String],
    dry_run: bool,
) -> Result<WriteOutcome> {
    let mut full: Vec<&str> = argv.iter().map(String::as_str).collect();
    if dry_run {
        full.push("--dry-run");
    }
    let raw = runner.run(&full)?;
    Ok(classify_write_output(&raw))
}

/// Classify raw CLI output into a [`WriteOutcome`] without running anything.
pub fn classify_write_output(raw: &RawOutput) -> WriteOutcome {
    match parse_raw_output::<WriteEnvelope>(raw) {
        ContractOutcome::Ok { ok, data, .. } => {
            let Some(command) = data.command else {
                // No `command` key: this may be a bare CheckReport from a
                // check-blocked write (exit 1), which also deserializes as
                // an (empty) WriteEnvelope.
                return match parse_raw_output::<CheckReport>(raw) {
                    ContractOutcome::Ok { data: report, .. } if !report.ok => {
                        WriteOutcome::CheckBlocked { report }
                    }
                    _ => WriteOutcome::CliError {
                        code: "command_failed".to_owned(),
                        message: "command reported ok: false without an error envelope".to_owned(),
                        fix: None,
                    },
                };
            };
            if data.dry_run {
                return WriteOutcome::DryRun {
                    command,
                    changes: data.changes,
                };
            }
            if data.idempotent || data.unchanged {
                return WriteOutcome::Idempotent {
                    command,
                    commit: data.commit.unwrap_or_default(),
                };
            }
            match data.commit {
                Some(commit) => WriteOutcome::Applied { command, commit },
                None if !ok => WriteOutcome::CliError {
                    code: "command_failed".to_owned(),
                    message: "command reported ok: false without an error envelope".to_owned(),
                    fix: None,
                },
                None => WriteOutcome::CliError {
                    code: "missing_commit".to_owned(),
                    message: "apply returned no commit and no error".to_owned(),
                    fix: None,
                },
            }
        }
        ContractOutcome::CliError { error, .. } => WriteOutcome::CliError {
            code: error.code,
            message: error.message,
            fix: error.fix,
        },
        ContractOutcome::InvalidJson { status } => {
            // A blocked write prints a bare CheckReport on stdout with exit 1.
            match parse_raw_output::<CheckReport>(raw) {
                ContractOutcome::Ok { data: report, .. } => WriteOutcome::CheckBlocked { report },
                _ => WriteOutcome::CliError {
                    code: "invalid_json".to_owned(),
                    message: format!("CLI output on stdout was not valid JSON (exit {status})"),
                    fix: Some(
                        "Verify that the confidant binary supports --json --no-input".to_owned(),
                    ),
                },
            }
        }
        ContractOutcome::VersionMismatch { reported_version } => WriteOutcome::CliError {
            code: "schema_version_mismatch".to_owned(),
            message: format!("TUI built for agent contract v1; CLI reports v{reported_version}"),
            fix: Some("Install matching versions of confidant and confidant-tui".to_owned()),
        },
    }
}

/// One planned apply step: the argv for the dry-run and the real run, plus a
/// stable key for the progress file.
#[derive(Clone, Debug, PartialEq)]
pub struct PlannedStep {
    /// `ledger`, `note:<request_id>` or `record:<request_id>`.
    pub key: String,
    /// Human-readable label for the step list.
    pub label: String,
    /// Argv without `--dry-run` (the engine adds it for previews).
    pub argv: Vec<String>,
    /// Scratch file this step stages before running (records only).
    pub scratch: Option<StagedScratch>,
    /// Manifest-declared file the CLI reads at run time: the ledger
    /// `lines_file` or a note's `body_file`. Its bytes are hashed when the
    /// step is dry-run and re-checked before the real apply, so a source
    /// that changed after the review refuses instead of committing content
    /// the operator never saw (#611). Records pin their content in memory
    /// via [`PlannedStep::scratch`], so they carry `None` here.
    pub source_file: Option<PathBuf>,
    /// Set when the step must not run: the message to show instead.
    pub blocked: Option<String>,
}

/// A record `content` staged to a 0600 scratch file under
/// `<manifest stem>/records/` (dir 0700), ready for `record add --file`.
#[derive(Clone, Debug, PartialEq)]
pub struct StagedScratch {
    pub path: PathBuf,
    pub content: String,
}

/// Build the apply plan for a manifest, in #211 order: ledger, then notes,
/// then records. Manifest-declared paths are refused unless they sit under
/// `.confidant/proposals/`.
pub fn plan_manifest(
    manifest: &ProposalManifest,
    manifest_path: &Path,
    vault_root: &Path,
) -> Result<Vec<PlannedStep>, String> {
    let proposals_dir = vault_root.join(".confidant").join("proposals");
    let mut steps = Vec::new();

    // 1. Ledger.
    if let Some(lines_file) = manifest.lines_file.as_deref().filter(|s| !s.is_empty()) {
        let lf = PathBuf::from(lines_file);
        if !is_under_dir(&proposals_dir, &lf) {
            return Err(format!(
                "lines_file is outside .confidant/proposals/: {lines_file}"
            ));
        }
        let line_count = std::fs::read_to_string(&lf)
            .map_err(|e| format!("cannot read lines_file {}: {e}", lf.display()))?;
        let line_count = line_count.lines().count();
        if line_count > 0 {
            steps.push(PlannedStep {
                key: "ledger".to_owned(),
                label: format!("Ledger import ({line_count} lines)"),
                argv: vec![
                    "import".to_owned(),
                    "--file".to_owned(),
                    lines_file.to_owned(),
                    "--request-id".to_owned(),
                    manifest.request_id.clone(),
                ],
                scratch: None,
                source_file: Some(lf),
                blocked: None,
            });
        }
    }

    // 2. Notes, then 3. records.
    let stem = manifest_stem(manifest_path);
    for (index, record) in manifest.records.iter().enumerate() {
        if record.note_id.is_some() {
            steps.push(plan_note(record, index, &proposals_dir)?);
        } else {
            steps.push(plan_record(record, index, manifest, &stem, &proposals_dir)?);
        }
    }

    Ok(steps)
}

fn plan_note(
    record: &crate::proposals::ProposalRecord,
    index: usize,
    proposals_dir: &Path,
) -> Result<PlannedStep, String> {
    let note_id = record.note_id.as_deref().unwrap_or("?");
    let label = format!(
        "Note {} for {} on {}",
        note_id,
        record.person.as_deref().unwrap_or("?"),
        record.date.as_deref().unwrap_or("?"),
    );
    let request_id = record.request_id.clone().filter(|s| !s.is_empty());
    let person = record.person.clone().filter(|s| !s.is_empty());
    let body_file = record.body_file.clone().filter(|s| !s.is_empty());
    let note_id_value = record.note_id.clone().filter(|s| !s.is_empty());
    let (Some(note_id_value), Some(request_id), Some(person), Some(body_file)) =
        (note_id_value, request_id, person, body_file)
    else {
        return Ok(PlannedStep {
            key: format!("note:refused-{index}"),
            label,
            argv: Vec::new(),
            scratch: None,
            source_file: None,
            blocked: Some(format!(
                "note {note_id} is missing note_id, person, body_file or request_id; \
                 re-run the proposer (the TUI never mints ids)"
            )),
        });
    };
    // The body file is committed verbatim as the note body, so it gets the
    // same under-proposals/ check as lines_file: a manifest must not point
    // it at an arbitrary readable file.
    if !is_under_dir(proposals_dir, Path::new(&body_file)) {
        return Err(format!(
            "note {note_id} body_file is outside .confidant/proposals/: {body_file}"
        ));
    };
    // #611: pass the manifest's own note id through, so the dry-run the
    // operator reviews names the exact path and id the apply writes. The
    // CLI still mints an id when `--id` is absent (the skill workflow), and
    // refuses a forced id that already exists unless this request already
    // committed it.
    let source_file = PathBuf::from(&body_file);
    let mut argv = vec![
        "note".to_owned(),
        "add".to_owned(),
        "--person".to_owned(),
        person,
        "--id".to_owned(),
        note_id_value,
    ];
    if let Some(date) = record.date.as_deref().filter(|s| !s.is_empty()) {
        argv.push("--date".to_owned());
        argv.push(date.to_owned());
    }
    if record.no_ai {
        argv.push("--no-ai".to_owned());
    }
    argv.push("--body-file".to_owned());
    argv.push(body_file);
    argv.push("--request-id".to_owned());
    argv.push(request_id.clone());
    Ok(PlannedStep {
        key: format!("note:{request_id}"),
        label,
        argv,
        scratch: None,
        source_file: Some(source_file),
        blocked: None,
    })
}

fn plan_record(
    record: &crate::proposals::ProposalRecord,
    index: usize,
    manifest: &ProposalManifest,
    stem: &Path,
    proposals_dir: &Path,
) -> Result<PlannedStep, String> {
    let label = format!("Record {}", record.path);
    if !manifest.records_blocked {
        return Ok(PlannedStep {
            key: format!("record:refused-{index}"),
            label,
            argv: Vec::new(),
            scratch: None,
            source_file: None,
            blocked: Some("pre-M2 records must be applied by the skill workflow".to_owned()),
        });
    }
    let Some(request_id) = record.request_id.clone().filter(|s| !s.is_empty()) else {
        return Ok(PlannedStep {
            key: format!("record:refused-{index}"),
            label,
            argv: Vec::new(),
            scratch: None,
            source_file: None,
            blocked: Some(format!(
                "record {} has no request_id; re-run the proposer \
                 (the TUI never mints ids)",
                record.path
            )),
        });
    };
    let scratch_path = stem.join("records").join(format!("{index:03}.md"));
    // The scratch file doesn't exist yet (it is staged at apply time), so
    // check the nearest existing ancestor instead of canonicalizing it.
    if !is_planned_under_dir(proposals_dir, &scratch_path) {
        return Err(format!(
            "record scratch path is outside .confidant/proposals/: {}",
            scratch_path.display()
        ));
    }
    Ok(PlannedStep {
        key: format!("record:{request_id}"),
        label,
        argv: vec![
            "record".to_owned(),
            "add".to_owned(),
            "--file".to_owned(),
            scratch_path.display().to_string(),
            "--request-id".to_owned(),
            request_id,
        ],
        scratch: Some(StagedScratch {
            path: scratch_path,
            content: record.content.clone(),
        }),
        source_file: None,
        blocked: None,
    })
}

/// Stage a record's scratch file (0700 dir, 0600 file). Idempotent: staging
/// twice writes the same bytes.
pub fn stage_scratch(scratch: &StagedScratch) -> Result<()> {
    if let Some(parent) = scratch.path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", parent.display()))?;
        }
    }
    use std::io::Write;
    open_secure_write(&scratch.path)
        .and_then(|mut f| f.write_all(scratch.content.as_bytes()))
        .with_context(|| format!("write {}", scratch.path.display()))?;
    Ok(())
}

/// The proposal-set paths the TUI may delete on cleanup: the manifest, the
/// lines file, the notes dir, the staged records dir, and the progress file.
/// Every path must resolve under `.confidant/proposals/`; anything else is
/// refused, never deleted. The TUI's own scratch dirs may not exist yet, so
/// the check canonicalizes the nearest existing ancestor.
pub fn cleanup_paths(
    manifest: &ProposalManifest,
    manifest_path: &Path,
    vault_root: &Path,
) -> Result<Vec<PathBuf>, String> {
    let proposals_dir = vault_root.join(".confidant").join("proposals");
    let stem = manifest_stem(manifest_path);
    let mut paths = vec![
        manifest_path.to_path_buf(),
        crate::proposals::progress_path(manifest_path),
    ];
    for raw in manifest.lines_file.iter().chain(manifest.notes_dir.iter()) {
        if raw.is_empty() {
            continue;
        }
        paths.push(PathBuf::from(raw));
    }
    // The TUI's own scratch dirs (may not exist yet — that's fine).
    paths.push(stem.join("notes"));
    paths.push(stem.join("records"));
    // The stem dir itself, once emptied.
    paths.push(stem);

    for path in &paths {
        if !is_planned_under_dir(&proposals_dir, path) {
            return Err(format!(
                "refusing cleanup: {} is outside .confidant/proposals/",
                path.display()
            ));
        }
    }
    Ok(paths)
}

/// Interactive apply flow for one open proposal: the #211 sequence
/// (ledger, notes, records) with dry-run → explicit confirm → apply per
/// step, progress persisted after every applied step, and cleanup at the end.
///
/// The flow never mints ids and never writes into the vault tree; every
/// write goes through the CLI via the [`Runner`].
#[derive(Clone, Debug, PartialEq)]
pub struct ApplyFlow {
    pub manifest_path: PathBuf,
    pub manifest: ProposalManifest,
    pub vault_root: PathBuf,
    pub steps: Vec<FlowStep>,
    pub progress: TuiProgress,
    pub phase: FlowPhase,
}

/// One planned step plus its current status.
#[derive(Clone, Debug, PartialEq)]
pub struct FlowStep {
    pub plan: PlannedStep,
    pub status: StepStatus,
    /// SHA-256 (lowercase hex) of [`PlannedStep::source_file`]'s bytes as
    /// they were when the last dry-run reviewed the step. `apply_step`
    /// refuses when the file no longer matches, so the confirm can only
    /// commit what was on screen (#611).
    pub reviewed_source_hash: Option<String>,
}

/// Status of a single step.
#[derive(Clone, Debug, PartialEq)]
pub enum StepStatus {
    Pending,
    Done {
        commit: String,
    },
    /// Refused by the plan (pre-M2 records, missing id): shown, never run.
    Blocked {
        message: String,
    },
    /// A dry-run or apply failed: the message explains what to do.
    Failed {
        message: String,
    },
}

/// Where the interactive flow currently is.
#[derive(Clone, Debug, PartialEq)]
pub enum FlowPhase {
    /// Detail view; no step in flight.
    Browsing,
    /// Dry-run output on screen, waiting for `y` (confirm modal) or Esc.
    Diff { step: usize, outcome: DryRunData },
    /// Confirm modal open: `y` applies, any other key cancels.
    Confirm { step: usize, outcome: DryRunData },
    /// A step failed; the detail view shows the message.
    StepFailed {
        step: usize,
        code: String,
        message: String,
        fix: Option<String>,
    },
    /// Final `check` after all steps was not clean.
    CheckFailed,
    /// All steps done and final check clean: prompt to delete the set.
    CleanupPrompt,
    /// Lightfield cleanup: asking for the export file path.
    CleanupExportInput { input: String },
    /// Cleanup failed; nothing was deleted.
    CleanupFailed { message: String },
    /// Proposal set deleted.
    Finished,
    /// The progress file was corrupt: ask before treating the proposal as
    /// fresh (a corrupt file could make an applied step look pending).
    CorruptProgress,
}

/// The dry-run preview the diff view renders.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DryRunData {
    pub command: String,
    pub changes: Vec<DryRunChange>,
}

/// What happened when the operator confirmed a step.
#[derive(Clone, Debug, PartialEq)]
pub enum StepApplyOutcome {
    /// The step applied (or was already applied); `more` says whether steps
    /// remain.
    Done { more: bool },
    /// The step failed; the flow phase is `StepFailed` with details.
    Failed,
    /// `check` blocked the write; the step is not marked done and the
    /// report should be shown in the Check view.
    CheckBlocked { report: CheckReport },
}

/// Lowercase hex SHA-256 of `bytes`, for the #611 source pin.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl ApplyFlow {
    /// Open a proposal: parse the manifest, build the plan, load progress,
    /// and mark already-done steps.
    pub fn open(manifest_path: &Path, vault_root: &Path) -> Result<Self, String> {
        let manifest = read_manifest(manifest_path)
            .map_err(|e| format!("{}: {e}", manifest_path.display()))?;
        let planned = plan_manifest(&manifest, manifest_path, vault_root)?;
        let corrupt_progress = progress_file_corrupt(manifest_path);
        let progress = read_progress(manifest_path);
        let steps = planned
            .into_iter()
            .map(|plan| {
                let status = if let Some(blocked) = plan.blocked.clone() {
                    StepStatus::Blocked { message: blocked }
                } else if let Some(commit) = progress.commit_for(&plan.key) {
                    StepStatus::Done {
                        commit: commit.to_owned(),
                    }
                } else {
                    StepStatus::Pending
                };
                FlowStep {
                    plan,
                    status,
                    reviewed_source_hash: None,
                }
            })
            .collect();
        Ok(Self {
            manifest_path: manifest_path.to_path_buf(),
            manifest,
            vault_root: vault_root.to_path_buf(),
            steps,
            progress,
            phase: if corrupt_progress {
                FlowPhase::CorruptProgress
            } else {
                FlowPhase::Browsing
            },
        })
    }

    /// Index of the first step that still needs work (pending or failed),
    /// if any.
    pub fn first_pending(&self) -> Option<usize> {
        self.steps
            .iter()
            .position(|s| matches!(s.status, StepStatus::Pending | StepStatus::Failed { .. }))
    }

    /// True when every runnable step is done (blocked steps don't count).
    pub fn all_done(&self) -> bool {
        self.steps
            .iter()
            .all(|s| !matches!(s.status, StepStatus::Pending))
    }

    /// True when every step is done or blocked and none failed.
    pub fn appliable_done(&self) -> bool {
        self.steps.iter().all(|s| {
            matches!(
                s.status,
                StepStatus::Done { .. } | StepStatus::Blocked { .. }
            )
        })
    }

    /// Run the dry-run for `step`, stage scratch files first for records.
    /// On success the phase becomes `Diff`; on failure `StepFailed`.
    ///
    /// #611: for a step whose CLI run re-reads a manifest file
    /// (`source_file`), its bytes are read before the CLI and again after,
    /// and the stable hash is remembered as the reviewed source. A file
    /// that changes while the preview is built refuses instead of pinning
    /// bytes the operator never saw.
    pub fn dry_run_step<R: Runner>(&mut self, runner: &R, step: usize) -> Result<()> {
        let plan = self.steps.get(step).map(|s| s.plan.clone());
        let Some(plan) = plan else {
            return Err(anyhow::anyhow!("no such step {step}"));
        };
        let before = match plan.source_file.as_deref().map(std::fs::read).transpose() {
            Ok(bytes) => bytes,
            Err(e) => {
                let path = plan
                    .source_file
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                self.mark_failed(
                    step,
                    "source_unreadable",
                    &format!("cannot read the reviewed source {path}: {e}"),
                    Some("Re-run the proposer so the file exists, then review again".to_owned()),
                );
                return Ok(());
            }
        };
        if let Some(scratch) = &plan.scratch {
            stage_scratch(scratch)?;
        }
        match run_write_step(runner, &plan.argv, true)? {
            WriteOutcome::DryRun { command, changes } => {
                if let (Some(path), Some(before)) = (plan.source_file.as_deref(), before.as_deref())
                {
                    match std::fs::read(path) {
                        Ok(after) if after == before => {
                            self.steps[step].reviewed_source_hash = Some(sha256_hex(before));
                        }
                        Ok(_) => {
                            self.mark_failed(
                                step,
                                "source_changed",
                                &format!(
                                    "{} changed while the dry-run ran; the preview cannot be trusted",
                                    path.display()
                                ),
                                Some("Re-open the proposal and review the dry-run again".to_owned()),
                            );
                            return Ok(());
                        }
                        Err(e) => {
                            self.mark_failed(
                                step,
                                "source_unreadable",
                                &format!(
                                    "cannot re-read the reviewed source {}: {e}",
                                    path.display()
                                ),
                                Some(
                                    "Re-open the proposal and review the dry-run again".to_owned(),
                                ),
                            );
                            return Ok(());
                        }
                    }
                }
                self.phase = FlowPhase::Diff {
                    step,
                    outcome: DryRunData { command, changes },
                };
                Ok(())
            }
            WriteOutcome::CheckBlocked { .. } => {
                // A dry-run never writes, so a blocked check here is really
                // about the current vault state; surface it like a failure.
                self.mark_failed(
                    step,
                    "check_blocked",
                    "check blocked the dry-run: fix the vault findings first",
                    None,
                );
                Ok(())
            }
            WriteOutcome::CliError { code, message, fix } => {
                self.mark_failed(step, &code, &message, fix);
                Ok(())
            }
            WriteOutcome::Applied { .. } | WriteOutcome::Idempotent { .. } => {
                self.mark_failed(
                    step,
                    "unexpected_outcome",
                    "dry-run returned an apply outcome; refusing to continue",
                    None,
                );
                Ok(())
            }
        }
    }

    /// Run the real apply for `step` (the operator already confirmed).
    /// Updates the progress file on success. A check-blocked write is
    /// returned to the caller so the report can be shown in the Check view;
    /// the step is not marked done.
    pub fn apply_step<R: Runner>(&mut self, runner: &R, step: usize) -> Result<StepApplyOutcome> {
        let plan = self.steps.get(step).map(|s| s.plan.clone());
        let Some(plan) = plan else {
            return Err(anyhow::anyhow!("no such step {step}"));
        };
        // #611: only apply the bytes the dry-run pinned. Refusing here
        // happens before any CLI call, so the vault and the progress file
        // are untouched.
        if let Some(path) = plan.source_file.as_deref() {
            let reviewed = self.steps[step].reviewed_source_hash.clone();
            match (std::fs::read(path), reviewed) {
                (Ok(bytes), Some(hash)) if sha256_hex(&bytes) == hash => {}
                (Ok(_), Some(_)) => {
                    self.mark_failed(
                        step,
                        "source_changed",
                        &format!(
                            "{} changed after the dry-run you reviewed; nothing was applied",
                            path.display()
                        ),
                        Some(
                            "Re-open the proposal and review the new content, then confirm"
                                .to_owned(),
                        ),
                    );
                    return Ok(StepApplyOutcome::Failed);
                }
                (Ok(_), None) => {
                    self.mark_failed(
                        step,
                        "source_unreviewed",
                        &format!(
                            "{} has not been dry-run in this session, so there is nothing to confirm",
                            path.display()
                        ),
                        Some("Re-open the proposal and review the dry-run first".to_owned()),
                    );
                    return Ok(StepApplyOutcome::Failed);
                }
                (Err(e), _) => {
                    self.mark_failed(
                        step,
                        "source_unreadable",
                        &format!("cannot read the reviewed source {}: {e}", path.display()),
                        Some(
                            "Re-run the proposer so the file exists, then review again".to_owned(),
                        ),
                    );
                    return Ok(StepApplyOutcome::Failed);
                }
            }
        }
        match run_write_step(runner, &plan.argv, false)? {
            WriteOutcome::Applied { commit, .. } | WriteOutcome::Idempotent { commit, .. } => {
                self.progress.mark_done(&plan.key, &commit);
                write_progress(&self.manifest_path, &self.progress)?;
                self.steps[step].status = StepStatus::Done { commit };
                self.phase = FlowPhase::Browsing;
                Ok(StepApplyOutcome::Done {
                    more: self.first_pending().is_some(),
                })
            }
            WriteOutcome::DryRun { .. } => {
                self.mark_failed(
                    step,
                    "unexpected_outcome",
                    "apply returned a dry-run outcome; refusing to continue",
                    None,
                );
                Ok(StepApplyOutcome::Failed)
            }
            WriteOutcome::CheckBlocked { report } => Ok(StepApplyOutcome::CheckBlocked { report }),
            WriteOutcome::CliError { code, message, fix } => {
                // A request-id reuse with a *different* body surfaces here;
                // the fix text names a fresh --request-id. The TUI never
                // mints one — the operator re-runs the proposer.
                self.mark_failed(step, &code, &message, fix);
                Ok(StepApplyOutcome::Failed)
            }
        }
    }

    fn mark_failed(&mut self, step: usize, code: &str, message: &str, fix: Option<String>) {
        self.steps[step].status = StepStatus::Failed {
            message: message.to_owned(),
        };
        self.phase = FlowPhase::StepFailed {
            step,
            code: code.to_owned(),
            message: message.to_owned(),
            fix,
        };
    }

    /// Run the final `confidant check --json --no-input`. Returns true when
    /// clean; on failure the phase becomes `CheckFailed` and the caller
    /// should surface the report in the Check view.
    pub fn final_check<R: Runner>(&mut self, runner: &R) -> Result<Option<CheckReport>> {
        let raw = runner.run(&["check"])?;
        match parse_raw_output::<CheckReport>(&raw) {
            ContractOutcome::Ok { data: report, .. } => {
                if report.ok {
                    Ok(None)
                } else {
                    self.phase = FlowPhase::CheckFailed;
                    Ok(Some(report))
                }
            }
            other => Err(anyhow::anyhow!("final check failed to parse: {other:?}")),
        }
    }

    /// Delete the proposal set. For `lightfield-import` the skill's own
    /// `--cleanup` script handles the export, manifest, lines file and note
    /// bodies (it needs the export path, which the TUI asks for); the TUI
    /// then removes its own scratch dirs and the progress file. For other
    /// skills the TUI removes exactly the manifest-listed paths, each
    /// validated to sit under `.confidant/proposals/`.
    pub fn cleanup<R: Runner>(&mut self, runner: &R, export_path: Option<&str>) -> Result<()> {
        if self.manifest.skill == "lightfield-import" {
            let export = export_path
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow::anyhow!("lightfield cleanup needs the export file path"))?;
            let skills_dir = self.skills_dir(runner)?;
            let script = skills_dir
                .join("lightfield-import")
                .join("bin")
                .join("lightfield-import.py");
            let manifest_str = self.manifest_path.display().to_string();
            let script_str = script.display().to_string();
            let out = runner.run_program(
                "python3",
                &[
                    &script_str,
                    "--cleanup",
                    "--export",
                    export,
                    "--manifest",
                    &manifest_str,
                    "--i-verified-the-import",
                ],
            )?;
            if out.status != 0 {
                let tail = String::from_utf8_lossy(&out.stdout);
                let tail: Vec<&str> = tail.lines().collect();
                let shown = tail
                    .iter()
                    .rev()
                    .take(5)
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n");
                self.phase = FlowPhase::CleanupFailed {
                    message: format!("skill --cleanup failed (exit {}):\n{shown}", out.status),
                };
                return Ok(());
            }
            // The skill removed the export, manifest, lines file and notes;
            // remove the TUI's own scratch and progress file.
            let stem = manifest_stem(&self.manifest_path);
            remove_paths(&[
                progress_path(&self.manifest_path),
                stem.join("records"),
                stem,
            ])?;
        } else {
            let paths = cleanup_paths(&self.manifest, &self.manifest_path, &self.vault_root)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            remove_paths(&paths)?;
        }
        self.phase = FlowPhase::Finished;
        Ok(())
    }

    /// Resolve the installed skills directory via `confidant which`.
    fn skills_dir<R: Runner>(&self, runner: &R) -> Result<PathBuf> {
        #[derive(Deserialize, Default)]
        struct WhichOutput {
            #[serde(default)]
            skills_dir: String,
        }
        let raw = runner.run(&["which", "--skills-dir"])?;
        match parse_raw_output::<WhichOutput>(&raw) {
            ContractOutcome::Ok { data, .. } if !data.skills_dir.is_empty() => {
                Ok(PathBuf::from(data.skills_dir))
            }
            ContractOutcome::Ok { .. } => {
                Err(anyhow::anyhow!("`which --skills-dir` returned no path"))
            }
            ContractOutcome::CliError { error, .. } => Err(anyhow::anyhow!(
                "cannot locate skills dir: {}",
                error.message
            )),
            ContractOutcome::InvalidJson { status } => Err(anyhow::anyhow!(
                "cannot parse `which --skills-dir` output (exit {status})"
            )),
            ContractOutcome::VersionMismatch { reported_version } => Err(anyhow::anyhow!(
                "contract version mismatch: {reported_version}"
            )),
        }
    }
}

/// Delete the given paths: files are removed, directories are removed
/// recursively, missing paths are skipped. Symlinks are never followed.
pub fn remove_paths(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            anyhow::bail!("refusing to delete symlink {}", path.display());
        }
        if meta.is_dir() {
            std::fs::remove_dir_all(path)
                .with_context(|| format!("remove dir {}", path.display()))?;
        } else {
            std::fs::remove_file(path)
                .with_context(|| format!("remove file {}", path.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposals::{test_temp_dir, ProposalManifest};

    fn manifest_fixture() -> ProposalManifest {
        ProposalManifest {
            skill: "lightfield-import".to_owned(),
            request_id: "01AAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            vault: String::new(),
            lines_file: None,
            notes_dir: None,
            records: Vec::new(),
            records_blocked: true,
            summary: None,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn classify_dry_run_envelope() {
        let raw = RawOutput {
            status: 0,
            stdout: br#"{"ok": true, "schema_version": "1", "vault": "/v", "command": "import", "dry_run": true, "commit": null, "changes": [{"path": "ledger/2026-10.cfd", "action": "append", "content": "2026-10-01 open d-1 proposal\n"}]}"#.to_vec(),
        };
        match classify_write_output(&raw) {
            WriteOutcome::DryRun { command, changes } => {
                assert_eq!(command, "import");
                assert_eq!(changes.len(), 1);
                assert_eq!(changes[0].path, "ledger/2026-10.cfd");
            }
            other => panic!("expected DryRun, got {other:?}"),
        }
    }

    #[test]
    fn classify_applied_and_idempotent() {
        let applied = RawOutput {
            status: 0,
            stdout: br#"{"ok": true, "schema_version": "1", "command": "import", "commit": "abc123", "files": ["ledger/2026-10.cfd"]}"#.to_vec(),
        };
        match classify_write_output(&applied) {
            WriteOutcome::Applied { commit, .. } => assert_eq!(commit, "abc123"),
            other => panic!("expected Applied, got {other:?}"),
        }
        let idem = RawOutput {
            status: 0,
            stdout: br#"{"ok": true, "schema_version": "1", "command": "import", "idempotent": true, "commit": "abc123"}"#.to_vec(),
        };
        match classify_write_output(&idem) {
            WriteOutcome::Idempotent { commit, .. } => assert_eq!(commit, "abc123"),
            other => panic!("expected Idempotent, got {other:?}"),
        }
    }

    #[test]
    fn classify_check_blocked() {
        let raw = RawOutput {
            status: 1,
            stdout: br#"{"schema_version": "1", "ok": false, "vault": "/v", "spec": "0.1", "summary": {"errors": 1, "warnings": 0, "records": 0, "ledger_entries": 0}, "findings": []}"#.to_vec(),
        };
        match classify_write_output(&raw) {
            WriteOutcome::CheckBlocked { report } => assert!(!report.ok),
            other => panic!("expected CheckBlocked, got {other:?}"),
        }
    }

    #[test]
    fn classify_error_envelope() {
        let raw = RawOutput {
            status: 1,
            stdout: br#"{"ok": false, "schema_version": "1", "error": {"code": "E_REQUEST_ID_REUSE", "message": "id reused", "fix": "use a fresh --request-id"}}"#.to_vec(),
        };
        match classify_write_output(&raw) {
            WriteOutcome::CliError { code, fix, .. } => {
                assert_eq!(code, "E_REQUEST_ID_REUSE");
                assert_eq!(fix.as_deref(), Some("use a fresh --request-id"));
            }
            other => panic!("expected CliError, got {other:?}"),
        }
    }

    #[test]
    fn plan_record_without_request_id_is_refused() {
        use crate::proposals::ProposalRecord;
        let mut manifest = manifest_fixture();
        manifest.records = vec![ProposalRecord {
            path: "people/p-1/person.md".to_owned(),
            content: "---\nid: p-1\n---\n".to_owned(),
            note_id: None,
            person: None,
            date: None,
            no_ai: false,
            body_file: None,
            request_id: None,
        }];
        let dir = test_temp_dir("tui-apply-test-plan");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        let manifest_path = proposals.join("m.json");
        let steps = plan_manifest(&manifest, &manifest_path, &dir).unwrap();
        assert_eq!(steps.len(), 1);
        assert!(steps[0].blocked.is_some());
        assert!(steps[0]
            .blocked
            .as_deref()
            .unwrap()
            .contains("no request_id"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plan_record_pre_m2_is_blocked() {
        use crate::proposals::ProposalRecord;
        let mut manifest = manifest_fixture();
        manifest.records_blocked = false;
        manifest.records = vec![ProposalRecord {
            path: "people/p-1/person.md".to_owned(),
            content: "---\nid: p-1\n---\n".to_owned(),
            note_id: None,
            person: None,
            date: None,
            no_ai: false,
            body_file: None,
            request_id: Some("01BBBBBBBBBBBBBBBBBBBBBBBB".to_owned()),
        }];
        let dir = test_temp_dir("tui-apply-test-prem2");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        let manifest_path = proposals.join("m.json");
        let steps = plan_manifest(&manifest, &manifest_path, &dir).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(
            steps[0].blocked.as_deref(),
            Some("pre-M2 records must be applied by the skill workflow")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plan_record_fresh_scratch_opens() {
        // Regression test for the #348 review blocker: on a fresh proposal
        // the stem dir (and the scratch file) doesn't exist yet, and the
        // plan must still open the record step.
        use crate::proposals::ProposalRecord;
        let mut manifest = manifest_fixture();
        manifest.records = vec![ProposalRecord {
            path: "people/p-1/person.md".to_owned(),
            content: "---\nid: p-1\n---\n".to_owned(),
            note_id: None,
            person: None,
            date: None,
            no_ai: false,
            body_file: None,
            request_id: Some("01CCCCCCCCCCCCCCCCCCCCCCCC".to_owned()),
        }];
        let dir = test_temp_dir("tui-apply-test-fresh-record");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        let manifest_path = proposals.join("m.json");
        // The stem dir is deliberately absent: nothing staged yet.
        assert!(!proposals.join("m").exists());
        let steps =
            plan_manifest(&manifest, &manifest_path, &dir).expect("fresh record step must open");
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].key, "record:01CCCCCCCCCCCCCCCCCCCCCCCC");
        assert!(steps[0].blocked.is_none());
        assert!(steps[0].scratch.is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plan_note_body_file_outside_proposals_is_refused() {
        use crate::proposals::ProposalRecord;
        let mut manifest = manifest_fixture();
        manifest.records = vec![ProposalRecord {
            path: "people/p-1/notes/n-1.md".to_owned(),
            content: String::new(),
            note_id: Some("n-1".to_owned()),
            person: Some("p-1".to_owned()),
            date: Some("2026-10-15".to_owned()),
            no_ai: false,
            body_file: Some("/etc/passwd".to_owned()),
            request_id: Some("01DDDDDDDDDDDDDDDDDDDDDDDD".to_owned()),
        }];
        let dir = test_temp_dir("tui-apply-test-body-outside");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        let manifest_path = proposals.join("m.json");
        let err = plan_manifest(&manifest, &manifest_path, &dir).expect_err("must refuse");
        assert!(err.contains("outside .confidant/proposals/"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plan_note_body_file_under_proposals_opens() {
        use crate::proposals::ProposalRecord;
        let dir = test_temp_dir("tui-apply-test-body-inside");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        let body = proposals.join("body.md");
        std::fs::write(&body, "note body\n").unwrap();
        let mut manifest = manifest_fixture();
        manifest.records = vec![ProposalRecord {
            path: "people/p-1/notes/n-1.md".to_owned(),
            content: String::new(),
            note_id: Some("n-1".to_owned()),
            person: Some("p-1".to_owned()),
            date: Some("2026-10-15".to_owned()),
            no_ai: false,
            body_file: Some(body.to_string_lossy().into_owned()),
            request_id: Some("01EEEEEEEEEEEEEEEEEEEEEEEE".to_owned()),
        }];
        let manifest_path = proposals.join("m.json");
        let steps = plan_manifest(&manifest, &manifest_path, &dir).expect("must open");
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].key, "note:01EEEEEEEEEEEEEEEEEEEEEEEE");
        assert!(steps[0].blocked.is_none());
        // #611: the manifest's own note id is passed through, so the
        // dry-run the operator reviews names the id and path the apply
        // writes, and the body file is the reviewed source to pin.
        let id_pos = steps[0]
            .argv
            .iter()
            .position(|a| a == "--id")
            .expect("plan_note must pass --id");
        assert_eq!(steps[0].argv[id_pos + 1], "n-1");
        assert_eq!(steps[0].source_file.as_deref(), Some(body.as_path()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A minimal `import --dry-run` envelope for the fake runner.
    const DRY_RUN_IMPORT: &str = r#"{
        "ok": true, "schema_version": "1", "vault": "/v",
        "command": "import", "dry_run": true, "commit": null,
        "changes": [
            {"path": "ledger/2026/10.cfd", "action": "append",
             "content": "2026-10-01 open d-1 proposal src:test/1\n"}
        ]
    }"#;

    #[test]
    fn apply_refuses_when_the_reviewed_source_changed() {
        // #611: the file the dry-run read changed before the operator
        // confirmed. The apply must refuse without running the CLI, so the
        // vault stays clean and the proposal state is untouched.
        use crate::proposals::read_progress;
        use crate::runner::FakeRunner;
        let dir = test_temp_dir("tui-apply-test-source-changed");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        let lines = proposals.join("m.cfd");
        std::fs::write(&lines, "2026-10-01 open d-1 proposal src:test/1\n").unwrap();
        let manifest = serde_json::json!({
            "skill": "s",
            "request_id": "01AAAAAAAAAAAAAAAAAAAAAAAA",
            "lines_file": lines.to_string_lossy(),
            "records": [],
        });
        let manifest_path = proposals.join("m.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let fake = FakeRunner::new().with_response("import", 0, DRY_RUN_IMPORT);
        let mut flow = ApplyFlow::open(&manifest_path, &dir).expect("open flow");
        flow.dry_run_step(&fake, 0).expect("dry-run");
        assert!(matches!(flow.phase, FlowPhase::Diff { .. }));
        // Change the source after the review, before the confirm.
        std::fs::write(&lines, "2026-10-01 open d-1 proposal src:test/CHANGED\n").unwrap();
        // Put the step in the Confirm phase the way the keymap does.
        if let FlowPhase::Diff { step, outcome } = flow.phase.clone() {
            flow.phase = FlowPhase::Confirm { step, outcome };
        }

        let outcome = flow.apply_step(&fake, 0).expect("apply call");
        assert_eq!(outcome, StepApplyOutcome::Failed);
        assert!(
            matches!(&flow.phase, FlowPhase::StepFailed { code, .. } if code == "source_changed"),
            "expected source_changed, got {:?}",
            flow.phase
        );
        // Only the dry-run reached the runner: nothing was applied.
        assert!(fake
            .recorded_calls()
            .iter()
            .all(|c| c.iter().any(|a| a == "--dry-run")));
        // The proposal state is intact: the step is not done.
        assert!(read_progress(&manifest_path).commit_for("ledger").is_none());
        assert!(matches!(flow.steps[0].status, StepStatus::Failed { .. }));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stage_scratch_writes_file() {
        let dir = test_temp_dir("tui-apply-test-stage");
        let scratch = StagedScratch {
            path: dir.join("records").join("000.md"),
            content: "---\nid: p-1\n---\n".to_owned(),
        };
        stage_scratch(&scratch).unwrap();
        assert_eq!(
            std::fs::read_to_string(&scratch.path).unwrap(),
            "---\nid: p-1\n---\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&scratch.path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            let dir_mode = std::fs::metadata(dir.join("records"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cleanup_refuses_paths_outside_proposals() {
        let dir = test_temp_dir("tui-apply-test-cleanup");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        let mut manifest = manifest_fixture();
        manifest.lines_file = Some("/etc/passwd".to_owned());
        let manifest_path = proposals.join("m.json");
        let err = cleanup_paths(&manifest, &manifest_path, &dir).expect_err("must refuse");
        assert!(err.contains("outside .confidant/proposals/"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cleanup_refuses_proposals_dir_itself() {
        let dir = test_temp_dir("tui-apply-test-cleanup-self");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        // A lines_file equal to the proposals/ directory would let cleanup
        // delete the whole directory: the strict-child check must refuse it.
        let mut manifest = manifest_fixture();
        manifest.lines_file = Some(proposals.to_string_lossy().into_owned());
        let manifest_path = proposals.join("m.json");
        let err = cleanup_paths(&manifest, &manifest_path, &dir).expect_err("must refuse");
        assert!(err.contains("outside .confidant/proposals/"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_with_corrupt_progress_asks_before_fresh() {
        let dir = test_temp_dir("tui-apply-test-corrupt-progress");
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        let manifest_path = proposals.join("m.json");
        std::fs::write(
            &manifest_path,
            r#"{"skill": "s", "request_id": "01AAAAAAAAAAAAAAAAAAAAAAAA", "records": []}"#,
        )
        .unwrap();
        // Corrupt progress file: open must land in the CorruptProgress phase
        // (in-UI alert), not silently treat the proposal as fresh.
        std::fs::write(proposals.join("m.tui-progress.json"), b"\xffnot json").unwrap();
        let flow = ApplyFlow::open(&manifest_path, &dir).expect("must open");
        assert_eq!(flow.phase, FlowPhase::CorruptProgress);
        assert!(flow
            .steps
            .iter()
            .all(|s| matches!(s.status, StepStatus::Pending)));
        // Valid progress: straight to Browsing.
        std::fs::write(proposals.join("m.tui-progress.json"), r#"{"done": {}}"#).unwrap();
        let flow = ApplyFlow::open(&manifest_path, &dir).expect("must open");
        assert_eq!(flow.phase, FlowPhase::Browsing);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
