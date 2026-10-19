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
    /// Manifest-declared file the CLI would re-read at run time (the ledger
    /// `lines_file` or a note's `body_file`) plus the 0600 scratch its
    /// reviewed bytes are staged to (#618). [`PlannedStep::argv`] points at
    /// `staged`, never at `source`, so a writer that swaps the shared
    /// manifest file between the review and the confirm cannot change what
    /// is applied. Records pin their content in memory via
    /// [`PlannedStep::scratch`], so they carry `None` here.
    pub reviewed_source: Option<ReviewedSource>,
    /// Set when the step must not run: the message to show instead.
    pub blocked: Option<String>,
}

/// A step's reviewed source: the manifest-declared file read once when the
/// step is dry-run, and the 0600 scratch file under
/// `<manifest stem>/staged/` its bytes are staged to (#618).
///
/// `source` is still hashed and re-read before the real apply, so a reviewed
/// input that changed refuses instead of silently applying the staged copy
/// (#611); `staged` is what the CLI is handed, which closes the window
/// between that check and the CLI's own read.
#[derive(Clone, Debug, PartialEq)]
pub struct ReviewedSource {
    pub source: PathBuf,
    pub staged: PathBuf,
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
    let stem = manifest_stem(manifest_path);
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
            // #618: the reviewed lines are staged under the manifest stem and
            // the CLI is handed that scratch, never the shared manifest file.
            let staged = staged_source_path(&stem, "ledger.cfd");
            if !is_planned_under_dir(&proposals_dir, &staged) {
                return Err(format!(
                    "ledger scratch path is outside .confidant/proposals/: {}",
                    staged.display()
                ));
            }
            steps.push(PlannedStep {
                key: "ledger".to_owned(),
                label: format!("Ledger import ({line_count} lines)"),
                argv: vec![
                    "import".to_owned(),
                    "--file".to_owned(),
                    staged.display().to_string(),
                    "--request-id".to_owned(),
                    manifest.request_id.clone(),
                ],
                scratch: None,
                reviewed_source: Some(ReviewedSource { source: lf, staged }),
                blocked: None,
            });
        }
    }

    // 2. Notes, then 3. records.
    for (index, record) in manifest.records.iter().enumerate() {
        if record.note_id.is_some() {
            steps.push(plan_note(record, index, &stem, &proposals_dir)?);
        } else {
            steps.push(plan_record(record, index, manifest, &stem, &proposals_dir)?);
        }
    }

    Ok(steps)
}

/// The scratch path a step's reviewed bytes are staged to:
/// `<manifest stem>/staged/<name>`. A sibling of the record scratch
/// (`<stem>/records/`), under `.confidant/proposals/` so cleanup and the
/// gitignore gate already cover it.
fn staged_source_path(stem: &Path, name: &str) -> PathBuf {
    stem.join("staged").join(name)
}

fn plan_note(
    record: &crate::proposals::ProposalRecord,
    index: usize,
    stem: &Path,
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
            reviewed_source: None,
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
    // #618: stage the reviewed body under the manifest stem and hand the CLI
    // that scratch; the shared body_file is only read to stage and to check.
    let staged = staged_source_path(stem, &format!("note-{index:03}.md"));
    if !is_planned_under_dir(proposals_dir, &staged) {
        return Err(format!(
            "note {note_id} scratch path is outside .confidant/proposals/: {}",
            staged.display()
        ));
    }
    // #611: pass the manifest's own note id through, so the dry-run the
    // operator reviews names the exact path and id the apply writes. The
    // CLI still mints an id when `--id` is absent (the skill workflow), and
    // refuses a forced id that already exists unless this request already
    // committed it.
    let source = PathBuf::from(&body_file);
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
    argv.push(staged.display().to_string());
    argv.push("--request-id".to_owned());
    argv.push(request_id.clone());
    Ok(PlannedStep {
        key: format!("note:{request_id}"),
        label,
        argv,
        scratch: None,
        reviewed_source: Some(ReviewedSource { source, staged }),
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
            reviewed_source: None,
            blocked: Some("pre-M2 records must be applied by the skill workflow".to_owned()),
        });
    }
    let Some(request_id) = record.request_id.clone().filter(|s| !s.is_empty()) else {
        return Ok(PlannedStep {
            key: format!("record:refused-{index}"),
            label,
            argv: Vec::new(),
            scratch: None,
            reviewed_source: None,
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
        reviewed_source: None,
        blocked: None,
    })
}

/// Stage `bytes` to a 0600 scratch file (0700 dir), refusing to follow a
/// pre-planted symlink at the file path. Idempotent: staging twice writes the
/// same bytes.
pub fn stage_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", parent.display()))?;
        }
    }
    use std::io::Write;
    open_secure_write(path)
        .and_then(|mut f| f.write_all(bytes))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Stage a record's scratch file. Idempotent: staging twice writes the same
/// bytes.
pub fn stage_scratch(scratch: &StagedScratch) -> Result<()> {
    stage_bytes(&scratch.path, scratch.content.as_bytes())
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
    // #618: the staged reviewed bytes (ledger lines, note bodies).
    paths.push(stem.join("staged"));
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
    /// SHA-256 (lowercase hex) of the reviewed source bytes as they were when
    /// the last successful dry-run staged and reviewed the step. `apply_step`
    /// checks it against both the staged copy and the manifest source, so a
    /// confirm can only commit what was on screen (#611, #618). A failed
    /// re-run clears it ([`ApplyFlow::dry_run_step`]).
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
        let mut flow = Self {
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
        };
        // #618: a staged reviewed source from a crashed or abandoned session
        // is stale — the operator has not reviewed it in this session. Sweep
        // it so plaintext does not linger (the same hygiene the edit scratch
        // sweep does, #455/#556).
        flow.sweep_all_staged_sources();
        Ok(flow)
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

    /// Run the dry-run for `step`, staging its scratch files first.
    /// On success the phase becomes `Diff`; on failure `StepFailed`.
    ///
    /// #618: the reviewed bytes of a step whose CLI run reads a manifest file
    /// are read once, staged to 0600 scratch under the manifest stem, and
    /// hashed. The CLI is handed the staged path (see [`PlannedStep`]'s
    /// `argv`), so nothing re-reads the shared manifest file. The hash is
    /// cleared first, so a re-run that fails can never be confirmed with a
    /// hash left over from an earlier preview.
    pub fn dry_run_step<R: Runner>(&mut self, runner: &R, step: usize) -> Result<()> {
        let plan = self.steps.get(step).map(|s| s.plan.clone());
        let Some(plan) = plan else {
            return Err(anyhow::anyhow!("no such step {step}"));
        };
        // #618: reset before anything else can fail, so a failed re-run
        // cannot leave a stale hash a confirm could use.
        self.steps[step].reviewed_source_hash = None;
        let mut staged_hash: Option<String> = None;
        if let Some(reviewed) = plan.reviewed_source.as_ref() {
            let bytes = match std::fs::read(&reviewed.source) {
                Ok(bytes) => bytes,
                Err(e) => {
                    self.mark_failed(
                        step,
                        "source_unreadable",
                        &format!(
                            "cannot read the reviewed source {}: {e}",
                            reviewed.source.display()
                        ),
                        Some(
                            "Re-run the proposer so the file exists, then review again".to_owned(),
                        ),
                    );
                    return Ok(());
                }
            };
            stage_bytes(&reviewed.staged, &bytes)?;
            staged_hash = Some(sha256_hex(&bytes));
        }
        if let Some(scratch) = &plan.scratch {
            stage_scratch(scratch)?;
        }
        match run_write_step(runner, &plan.argv, true)? {
            WriteOutcome::DryRun { command, changes } => {
                // Only a preview that actually completed pins the bytes: a
                // failed CLI call leaves the hash cleared (#618).
                self.steps[step].reviewed_source_hash = staged_hash;
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
        // #611/#618: only apply the bytes the dry-run staged. The CLI reads
        // the staged 0600 copy, and the hash is checked against both that
        // copy (what the CLI reads) and the manifest source (what the
        // operator reviewed), so a swap between the review and the confirm
        // refuses. Refusing happens before any CLI call, so the vault and
        // the progress file are untouched.
        if let Some(reviewed) = plan.reviewed_source.as_ref() {
            let hash = self.steps[step].reviewed_source_hash.clone();
            let Some(hash) = hash else {
                self.mark_failed(
                    step,
                    "source_unreviewed",
                    &format!(
                        "{} has not been dry-run in this session, so there is nothing to confirm",
                        reviewed.source.display()
                    ),
                    Some("Re-open the proposal and review the dry-run first".to_owned()),
                );
                return Ok(StepApplyOutcome::Failed);
            };
            for (path, what) in [
                (&reviewed.staged, "staged copy"),
                (&reviewed.source, "reviewed source"),
            ] {
                match std::fs::read(path) {
                    Ok(bytes) if sha256_hex(&bytes) == hash => {}
                    Ok(_) => {
                        self.mark_failed(
                            step,
                            "source_changed",
                            &format!(
                                "the {what} {} changed after the dry-run you reviewed; nothing was applied",
                                path.display()
                            ),
                            Some(
                                "Re-open the proposal and review the new content, then confirm"
                                    .to_owned(),
                            ),
                        );
                        return Ok(StepApplyOutcome::Failed);
                    }
                    Err(e) => {
                        self.mark_failed(
                            step,
                            "source_unreadable",
                            &format!("cannot read the {what} {}: {e}", path.display()),
                            Some(
                                "Re-run the proposer so the file exists, then review again"
                                    .to_owned(),
                            ),
                        );
                        return Ok(StepApplyOutcome::Failed);
                    }
                }
            }
        }
        // The CLI has read the staged copy by the time `run_write_step`
        // returns. The staged reviewed bytes are swept on every terminal
        // outcome (done, failed, runner error); a check-blocked write keeps
        // them so the operator can retry after fixing the findings (#618).
        match run_write_step(runner, &plan.argv, false) {
            Ok(WriteOutcome::Applied { commit, .. } | WriteOutcome::Idempotent { commit, .. }) => {
                self.sweep_staged_source(step);
                self.progress.mark_done(&plan.key, &commit);
                write_progress(&self.manifest_path, &self.progress)?;
                self.steps[step].status = StepStatus::Done { commit };
                self.phase = FlowPhase::Browsing;
                Ok(StepApplyOutcome::Done {
                    more: self.first_pending().is_some(),
                })
            }
            Ok(WriteOutcome::DryRun { .. }) => {
                self.mark_failed(
                    step,
                    "unexpected_outcome",
                    "apply returned a dry-run outcome; refusing to continue",
                    None,
                );
                Ok(StepApplyOutcome::Failed)
            }
            Ok(WriteOutcome::CheckBlocked { report }) => {
                Ok(StepApplyOutcome::CheckBlocked { report })
            }
            Ok(WriteOutcome::CliError { code, message, fix }) => {
                // A request-id reuse with a *different* body surfaces here;
                // the fix text names a fresh --request-id. The TUI never
                // mints one — the operator re-runs the proposer.
                self.mark_failed(step, &code, &message, fix);
                Ok(StepApplyOutcome::Failed)
            }
            Err(e) => {
                self.sweep_staged_source(step);
                Err(e)
            }
        }
    }

    /// Cancel a pending review of `step`: back to browsing, with the staged
    /// reviewed bytes removed and the review hash cleared, so a later confirm
    /// cannot use them (#618).
    pub fn cancel_step(&mut self, step: usize) {
        self.sweep_staged_source(step);
        if let Some(flow_step) = self.steps.get_mut(step) {
            flow_step.reviewed_source_hash = None;
        }
        self.phase = FlowPhase::Browsing;
    }

    /// Remove every step's staged reviewed bytes (best-effort). Called when
    /// the proposal is abandoned, so no stale plaintext scratch survives
    /// (#618).
    pub fn sweep_all_staged_sources(&mut self) {
        let paths: Vec<PathBuf> = self
            .steps
            .iter()
            .filter_map(|s| s.plan.reviewed_source.as_ref().map(|r| r.staged.clone()))
            .collect();
        for path in paths {
            remove_staged_source(&path);
        }
    }

    /// Remove one step's staged reviewed bytes, if the step has any.
    fn sweep_staged_source(&mut self, step: usize) {
        if let Some(staged) = self
            .steps
            .get(step)
            .and_then(|s| s.plan.reviewed_source.as_ref())
            .map(|r| r.staged.clone())
        {
            remove_staged_source(&staged);
        }
    }

    fn mark_failed(&mut self, step: usize, code: &str, message: &str, fix: Option<String>) {
        // A failed step must be re-reviewed, so its staged reviewed bytes go
        // with it (#618).
        self.sweep_staged_source(step);
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

/// Remove a staged reviewed-source file: best-effort overwrite-with-zeros,
/// unlink, then prune the now-empty `staged/` dir. Never removes the manifest
/// stem dir itself (it holds the record scratch and, for lightfield, the
/// notes). This is not secure deletion — see [`crate::edit::remove_scratch`]
/// for the same caveat. Missing paths are skipped; a symlink is unlinked
/// without following it.
fn remove_staged_source(path: &Path) {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_symlink() {
            crate::edit::zero_and_remove(path);
        } else {
            let _ = std::fs::remove_file(path);
        }
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir(dir);
    }
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
        // #611/#618: the manifest's own note id is passed through, and the
        // reviewed body is staged under the stem, so the dry-run/apply name
        // the exact path and id and the CLI reads the staged copy.
        let id_pos = steps[0]
            .argv
            .iter()
            .position(|a| a == "--id")
            .expect("plan_note must pass --id");
        assert_eq!(steps[0].argv[id_pos + 1], "n-1");
        let reviewed = steps[0]
            .reviewed_source
            .as_ref()
            .expect("note step reviews its body");
        assert_eq!(reviewed.source.as_path(), body.as_path());
        assert!(
            reviewed.staged.ends_with("staged/note-000.md"),
            "{reviewed:?}"
        );
        let body_pos = steps[0]
            .argv
            .iter()
            .position(|a| a == "--body-file")
            .expect("plan_note must pass --body-file");
        assert_eq!(
            steps[0].argv[body_pos + 1],
            reviewed.staged.display().to_string()
        );
        assert!(
            !steps[0].argv.iter().any(|a| a == &body.to_string_lossy()),
            "the shared body_file is never handed to the CLI: {:?}",
            steps[0].argv
        );
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

    /// A minimal applied `import` envelope.
    const APPLIED_IMPORT: &str = r#"{
        "ok": true, "schema_version": "1", "vault": "/v",
        "command": "import", "commit": "abc123",
        "files": ["ledger/2026/10.cfd"]
    }"#;

    /// A ledger proposal fixture: `<dir>/.confidant/proposals/m.json` with a
    /// single `lines_file` import step. Returns `(dir, manifest_path, lines,
    /// staged)`, where `staged` is the scratch the plan hands the CLI.
    fn ledger_fixture(name: &str, lines_text: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let dir = test_temp_dir(name);
        let proposals = dir.join(".confidant").join("proposals");
        std::fs::create_dir_all(&proposals).unwrap();
        let lines = proposals.join("m.cfd");
        std::fs::write(&lines, lines_text).unwrap();
        let manifest = serde_json::json!({
            "skill": "s",
            "request_id": "01AAAAAAAAAAAAAAAAAAAAAAAA",
            "lines_file": lines.to_string_lossy(),
            "records": [],
        });
        let manifest_path = proposals.join("m.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let staged = proposals.join("m").join("staged").join("ledger.cfd");
        (dir, manifest_path, lines, staged)
    }

    /// Move a `Diff` phase to `Confirm` the way the keymap does.
    fn confirm_phase(flow: &mut ApplyFlow) {
        if let FlowPhase::Diff { step, outcome } = flow.phase.clone() {
            flow.phase = FlowPhase::Confirm { step, outcome };
        }
    }

    #[test]
    fn dry_run_stages_the_reviewed_bytes_and_hands_the_scratch_to_the_cli() {
        // #618: the reviewed ledger lines are staged, and both the dry-run
        // and the apply hand the CLI the staged 0600 scratch — never the
        // shared manifest file. Changing the source cannot change what the
        // real run reads. Fails without staging: the plan would name the
        // source path and no scratch would exist.
        use crate::runner::FakeRunner;
        let (dir, manifest_path, lines, staged) = ledger_fixture(
            "tui-apply-test-staged",
            "2026-10-01 open d-1 proposal src:test/1\n",
        );
        let fake = FakeRunner::new();
        fake.push_response(0, DRY_RUN_IMPORT);
        fake.push_response(0, APPLIED_IMPORT);

        let mut flow = ApplyFlow::open(&manifest_path, &dir).expect("open flow");
        // The plan names the scratch, never the source.
        let file_arg = flow.steps[0]
            .plan
            .argv
            .iter()
            .position(|a| a == "--file")
            .map(|i| flow.steps[0].plan.argv[i + 1].clone())
            .expect("--file");
        assert_eq!(file_arg, staged.display().to_string());
        assert!(
            !flow.steps[0]
                .plan
                .argv
                .iter()
                .any(|a| a == &lines.display().to_string()),
            "the shared lines_file is never handed to the CLI: {:?}",
            flow.steps[0].plan.argv
        );

        flow.dry_run_step(&fake, 0).expect("dry-run");
        assert!(matches!(flow.phase, FlowPhase::Diff { .. }));
        assert!(flow.steps[0].reviewed_source_hash.is_some());
        assert_eq!(
            std::fs::read_to_string(&staged).unwrap(),
            std::fs::read_to_string(&lines).unwrap(),
            "the staged copy holds the reviewed bytes"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&staged).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the staged copy is 0600");
            let dir_mode = std::fs::metadata(staged.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700, "the staged dir is 0700");
        }

        confirm_phase(&mut flow);
        let outcome = flow.apply_step(&fake, 0).expect("apply");
        assert_eq!(outcome, StepApplyOutcome::Done { more: false });
        // The real run's argv names the scratch, and its bytes are the
        // reviewed bytes.
        let write = fake
            .recorded_calls()
            .into_iter()
            .find(|c| {
                c.first().map(String::as_str) == Some("import")
                    && !c.contains(&"--dry-run".to_owned())
            })
            .expect("a real import call");
        let file_arg = write
            .iter()
            .position(|a| a == "--file")
            .map(|i| write[i + 1].clone())
            .expect("--file");
        assert_eq!(file_arg, staged.display().to_string());
        // Swept on confirm.
        assert!(!staged.exists(), "the staged copy is swept after the apply");
        assert!(
            !staged.parent().unwrap().exists(),
            "the staged dir is pruned once empty"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_refuses_when_the_staged_copy_was_swapped() {
        // #618: the CLI reads the staged copy, so the pin covers it too: a
        // writer that swaps the scratch between the review and the confirm
        // gets a refusal, not unreviewed bytes committed.
        use crate::runner::FakeRunner;
        let (dir, manifest_path, _lines, staged) = ledger_fixture(
            "tui-apply-test-staged-swap",
            "2026-10-01 open d-1 proposal src:test/1\n",
        );
        let fake = FakeRunner::new().with_response("import", 0, DRY_RUN_IMPORT);
        let mut flow = ApplyFlow::open(&manifest_path, &dir).expect("open flow");
        flow.dry_run_step(&fake, 0).expect("dry-run");
        std::fs::write(&staged, "2026-10-01 open d-1 proposal src:test/SWAPPED\n").unwrap();
        confirm_phase(&mut flow);

        let outcome = flow.apply_step(&fake, 0).expect("apply");
        assert_eq!(outcome, StepApplyOutcome::Failed);
        assert!(
            matches!(&flow.phase, FlowPhase::StepFailed { code, .. } if code == "source_changed"),
            "expected source_changed, got {:?}",
            flow.phase
        );
        assert!(fake
            .recorded_calls()
            .iter()
            .all(|c| c.iter().any(|a| a == "--dry-run")));
        assert!(!staged.exists(), "the staged copy is swept on failure");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn failed_rerun_clears_the_reviewed_hash_so_a_confirm_cannot_go_through() {
        // #618: a hash from an earlier successful preview must not survive a
        // failed re-run; the hash is reset at the top of `dry_run_step`, so
        // the later confirm refuses independent of the keymap phase.
        use crate::runner::FakeRunner;
        let (dir, manifest_path, _lines, staged) = ledger_fixture(
            "tui-apply-test-stale-hash",
            "2026-10-01 open d-1 proposal src:test/1\n",
        );
        let fake = FakeRunner::new();
        fake.push_response(0, DRY_RUN_IMPORT);
        fake.push_response(
            1,
            r#"{"ok": false, "schema_version": "1", "error":
               {"code": "E_BOOM", "message": "import refused", "fix": null}}"#,
        );
        let mut flow = ApplyFlow::open(&manifest_path, &dir).expect("open flow");
        flow.dry_run_step(&fake, 0).expect("first dry-run");
        assert!(flow.steps[0].reviewed_source_hash.is_some());

        // The re-run fails: the hash must be gone.
        flow.dry_run_step(&fake, 0).expect("re-run");
        assert!(
            matches!(&flow.phase, FlowPhase::StepFailed { code, .. } if code == "E_BOOM"),
            "expected E_BOOM, got {:?}",
            flow.phase
        );
        assert_eq!(
            flow.steps[0].reviewed_source_hash, None,
            "a failed re-run must clear the review hash"
        );
        assert!(!staged.exists(), "the failed re-run sweeps its staging");

        // Even if the keymap left us on the confirm modal, the confirm
        // refuses: there is nothing reviewed to apply.
        flow.phase = FlowPhase::Confirm {
            step: 0,
            outcome: DryRunData::default(),
        };
        let outcome = flow.apply_step(&fake, 0).expect("apply");
        assert_eq!(outcome, StepApplyOutcome::Failed);
        assert!(
            matches!(&flow.phase, FlowPhase::StepFailed { code, .. } if code == "source_unreviewed"),
            "expected source_unreviewed, got {:?}",
            flow.phase
        );
        assert!(fake
            .recorded_calls()
            .iter()
            .all(|c| c.iter().any(|a| a == "--dry-run")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sweep_all_staged_sources_removes_every_steps_staging() {
        let (dir, manifest_path, _lines, staged) = ledger_fixture(
            "tui-apply-test-sweep-all",
            "2026-10-01 open d-1 proposal src:test/1\n",
        );
        let mut flow = ApplyFlow::open(&manifest_path, &dir).expect("open flow");
        stage_bytes(&staged, b"2026-10-01 open d-1 proposal src:test/1\n").unwrap();
        assert!(staged.exists());
        flow.sweep_all_staged_sources();
        assert!(!staged.exists());
        assert!(!staged.parent().unwrap().exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_refuses_when_the_reviewed_source_changed() {
        // #611: the file the dry-run read changed before the operator
        // confirmed. The apply must refuse without running the CLI, so the
        // vault stays clean and the proposal state is untouched. #618 keeps
        // this check alongside staging: the staged copy is what the CLI
        // reads, but a changed reviewed input still refuses.
        use crate::proposals::read_progress;
        use crate::runner::FakeRunner;
        let (dir, manifest_path, lines, staged) = ledger_fixture(
            "tui-apply-test-source-changed",
            "2026-10-01 open d-1 proposal src:test/1\n",
        );

        let fake = FakeRunner::new().with_response("import", 0, DRY_RUN_IMPORT);
        let mut flow = ApplyFlow::open(&manifest_path, &dir).expect("open flow");
        flow.dry_run_step(&fake, 0).expect("dry-run");
        assert!(matches!(flow.phase, FlowPhase::Diff { .. }));
        assert!(staged.exists(), "the review staged a copy");
        // #618: the reviewed bytes were staged, and the plan hands the CLI
        // the scratch — not the shared `.cfd` the writer can swap. Both
        // assertions fail on the pre-staging code.
        assert_eq!(
            std::fs::read_to_string(&staged).unwrap(),
            "2026-10-01 open d-1 proposal src:test/1\n",
            "the staged copy holds the reviewed bytes"
        );
        assert!(
            flow.steps[0]
                .plan
                .argv
                .iter()
                .any(|a| a == &staged.display().to_string()),
            "the CLI is handed the staged scratch: {:?}",
            flow.steps[0].plan.argv
        );
        assert!(
            !flow.steps[0]
                .plan
                .argv
                .iter()
                .any(|a| a == &lines.display().to_string()),
            "the shared lines_file is never handed to the CLI: {:?}",
            flow.steps[0].plan.argv
        );
        // Change the source after the review, before the confirm.
        std::fs::write(&lines, "2026-10-01 open d-1 proposal src:test/CHANGED\n").unwrap();
        confirm_phase(&mut flow);

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
        // And the staged copy is swept on the refusal.
        assert!(!staged.exists(), "the staged copy is swept on failure");
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
