//! `status`: readiness rollup and the completion brief.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::doctor::{
    cli_staleness_check, collect_doctor_checks, corpus_freshness, git_upstream, latest_release_tag,
    parse_git_remote_urls, qmd_embedded_vectors, qmd_state, skills_links_check, staleness_offline,
    system_of_record_check, tui_version_check, CorpusFreshness, DoctorCheck, QmdState,
    DOCTOR_STATUS_UNKNOWN,
};
use crate::commands::find::QMD_CORPUS_REL;
use crate::commands::init::current_branch;
use crate::commands::install::staleness_update_hint;
use crate::commands::shared::{display_remote_url, find_on_path};
use crate::{ok_envelope, print_json, setup, Cli};
use confidant_core::record::RecordKind;
use confidant_core::{check_vault, load_vault, CheckOptions};
use serde_json::Value;

/// One line in the readiness rollup. `absent` is a fifth status for an
/// optional layer that is not installed: it is never `ok`, and it does not
/// fail readiness unless the check is required.
#[derive(Debug, Clone)]
pub(crate) struct ReadinessCheck {
    id: &'static str,
    status: &'static str,
    message: String,
    fix: Option<String>,
    required: bool,
}

impl ReadinessCheck {
    fn from_doctor(check: DoctorCheck, required: bool) -> Self {
        ReadinessCheck {
            id: check.id,
            status: check.status,
            message: check.message,
            fix: check.fix,
            required,
        }
    }

    fn to_json(&self) -> Value {
        let mut item = serde_json::json!({
            "id": self.id,
            "status": self.status,
            "message": self.message,
            "required": self.required,
        });
        if let Some(fix) = &self.fix {
            item["fix"] = Value::String(fix.clone());
        }
        item
    }
}

/// Which doctor checks must be `ok` for setup to count as complete. Optional
/// layers (TUI, QMD, remote, ahead/behind) may be absent or warning without
/// blocking readiness; they are still reported.
pub(crate) fn readiness_required(id: &str) -> bool {
    matches!(
        id,
        "cli-staleness"
            | "vault-discovery"
            | "vault-access"
            | "vault-load"
            | "git-repo"
            | "git-identity"
            | "git-remote"
            | "spec"
            | "skills-links"
            | "system-of-record"
    )
}

pub(crate) fn readiness_checks(cli: &Cli, vault: Option<&Path>) -> Vec<ReadinessCheck> {
    let mut checks: Vec<ReadinessCheck> = match vault {
        Some(root) => collect_doctor_checks(cli, root)
            .into_iter()
            .map(|check| {
                let required = readiness_required(check.id);
                ReadinessCheck::from_doctor(check, required)
            })
            .collect(),
        None => {
            let offline = staleness_offline();
            let latest = if offline { None } else { latest_release_tag() };
            vec![
                ReadinessCheck::from_doctor(
                    cli_staleness_check(latest, offline, staleness_update_hint()),
                    true,
                ),
                ReadinessCheck::from_doctor(tui_version_check(), false),
                ReadinessCheck {
                    id: "vault-discovery",
                    status: "absent",
                    message: "no vault resolved; pass --vault, set CONFIDANT_VAULT, or run inside a vault"
                        .to_owned(),
                    fix: Some(
                        "Pass `--vault <path>`, set `CONFIDANT_VAULT`, or run `confidant init --create`"
                            .to_owned(),
                    ),
                    required: true,
                },
                ReadinessCheck::from_doctor(skills_links_check(), true),
                ReadinessCheck::from_doctor(system_of_record_check(None), true),
                ReadinessCheck {
                    id: "qmd-search",
                    status: "absent",
                    message: "no vault to inspect for a search corpus; search is unavailable until a vault is set"
                        .to_owned(),
                    fix: None,
                    required: false,
                },
            ]
        }
    };

    // An optional layer that is not installed is `absent`, never a false
    // `ok`. The doctor checks keep their historical `ok` for compatibility.
    if find_on_path("confidant-tui").is_none() {
        for check in &mut checks {
            if check.id == "tui-version" {
                check.status = "absent";
            }
        }
    }
    if vault.is_some() && matches!(qmd_state(), QmdState::Missing) {
        for check in &mut checks {
            if check.id == "qmd-search" {
                check.status = "absent";
            }
        }
    }

    // A host with no agent has nothing to link or instruct; that is absent,
    // not a failure of the install. A host that has agents but was never
    // targeted is not set up: keep those checks required and non-ok.
    let home = setup::home_dir().ok();
    let agent_health = home
        .as_deref()
        .map(setup::agents_health)
        .unwrap_or_default();
    let detected = agent_health.iter().any(|agent| agent.detected);
    let targeted = agent_health
        .iter()
        .any(|agent| agent.detected && agent.targeted);
    if home.is_none() {
        // `skills-links` already warns that home could not be determined;
        // do not overwrite that with an optional "no agents" line.
    } else if !detected {
        for check in &mut checks {
            if check.id == "skills-links" || check.id == "system-of-record" {
                check.status = "absent";
                check.required = false;
                check.message =
                    "no agents detected; install one, then run `confidant setup --agent auto`"
                        .to_owned();
                check.fix = None;
            }
        }
    } else if !targeted {
        for check in &mut checks {
            if check.id == "skills-links" || check.id == "system-of-record" {
                check.status = "absent";
                check.message =
                    "agents detected but setup has not linked them; run `confidant setup --agent auto`"
                        .to_owned();
            }
        }
    }
    checks
}

pub(crate) fn readiness_summary(checks: &[ReadinessCheck]) -> Value {
    let count = |status: &str| checks.iter().filter(|c| c.status == status).count();
    // Any error blocks readiness, even from a check that is advisory for
    // setup (a vault check error means writes are blocked). Optional
    // warnings do not block; a warning on a required check does.
    let ready = checks
        .iter()
        .all(|check| !check.required || check.status == "ok")
        && !checks.iter().any(|check| check.status == "error");
    serde_json::json!({
        "ready": ready,
        "ok": count("ok"),
        "warning": count("warning"),
        "absent": count("absent"),
        "unknown": count(DOCTOR_STATUS_UNKNOWN),
        "error": count("error"),
    })
}

pub(crate) fn cmd_status(cli: &Cli, vault: Option<&Path>) -> anyhow::Result<ExitCode> {
    let checks = readiness_checks(cli, vault);
    let summary = readiness_summary(&checks);
    let ready = summary["ready"].as_bool().unwrap_or(false);
    let brief = completion_brief(cli, vault);
    if cli.json {
        let items: Vec<Value> = checks.iter().map(ReadinessCheck::to_json).collect();
        let mut extra = serde_json::Map::new();
        extra.insert(
            "readiness".to_owned(),
            serde_json::json!({
                "summary": summary,
                "checks": items,
            }),
        );
        extra.insert("brief".to_owned(), brief.to_json());
        let mut envelope = ok_envelope(vault, Value::Object(extra));
        envelope["ok"] = Value::Bool(ready);
        print_json(&envelope)?;
    } else {
        println!("Confidant readiness");
        for check in &checks {
            let marker = if check.required { "" } else { " (optional)" };
            println!(
                "{:8} {:<18} {}{}",
                check.status, check.id, check.message, marker
            );
            if let Some(fix) = &check.fix {
                println!("         fix: {fix}");
            }
        }
        println!();
        let not_ready: Vec<&str> = checks
            .iter()
            .filter(|check| (check.required && check.status != "ok") || check.status == "error")
            .map(|check| check.id)
            .collect();
        if ready {
            println!("Ready: every required check is ok.");
        } else {
            println!("Not ready: {}.", not_ready.join(", "));
        }
        println!(
            "          {} ok, {} warning, {} absent, {} unknown, {} error",
            summary["ok"],
            summary["warning"],
            summary["absent"],
            summary["unknown"],
            summary["error"]
        );
        println!();
        print_completion_brief(cli, vault);
    }
    Ok(if ready {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

pub(crate) struct BriefSection {
    key: &'static str,
    title: &'static str,
    lines: Vec<String>,
}

pub(crate) struct CompletionBrief {
    sections: Vec<BriefSection>,
    routines: Vec<String>,
}

impl CompletionBrief {
    fn to_json(&self) -> Value {
        serde_json::json!({
            "sections": self.sections.iter().map(|section| serde_json::json!({
                "key": section.key,
                "title": section.title,
                "lines": section.lines,
            })).collect::<Vec<_>>(),
            "routines": self.routines,
        })
    }
}

pub(crate) fn completion_brief_json(cli: &Cli, vault: Option<&Path>) -> Value {
    completion_brief(cli, vault).to_json()
}

pub(crate) fn print_completion_brief(cli: &Cli, vault: Option<&Path>) {
    let brief = completion_brief(cli, vault);
    println!("Completion brief");
    for section in &brief.sections {
        println!();
        println!("{}", section.title);
        for line in &section.lines {
            println!("  {line}");
        }
    }
    println!();
    println!("Jumping-off routines");
    for (index, routine) in brief.routines.iter().enumerate() {
        println!("  {}. {routine}", index + 1);
    }
}

/// One row of the #715 optional-layers checklist. `state` is a short word
/// (`present`, `absent`, `unknown`, `not working`); nothing here is
/// required, so the checklist only reports and leaves the choice to the
/// operator.
pub(crate) struct OptionalLayer {
    id: &'static str,
    state: &'static str,
    detail: String,
    tradeoff: &'static str,
}

/// The optional layers `setup` ends with (#715): vault present, skills
/// linked, qmd installed, corpus built, embeddings present. States are
/// structural only (paths, counts, versions) — no record content is read.
pub(crate) fn optional_layers(vault: Option<&Path>) -> Vec<OptionalLayer> {
    let mut layers = Vec::new();

    // Vault.
    let (vault_state, vault_detail) = match vault {
        Some(root) => {
            let state = if load_vault(root).is_ok() {
                "present"
            } else {
                "unknown"
            };
            (state, root.display().to_string())
        }
        None => (
            "absent",
            "no vault configured; set CONFIDANT_VAULT or pass --vault".to_owned(),
        ),
    };
    layers.push(OptionalLayer {
        id: "vault",
        state: vault_state,
        detail: vault_detail,
        tradeoff: "Plaintext records in a private git repo on this disk; back it up and keep full-disk encryption on.",
    });

    // Skills.
    let skills = match setup::home_dir() {
        Ok(home) => {
            let health = match setup::skills_dir_override() {
                Some(dir) => vec![setup::agent_health_for_dir("custom", &dir)],
                None => setup::agents_health(&home),
            };
            let mut seen: Vec<PathBuf> = Vec::new();
            let mut targeted: Vec<setup::AgentHealth> = Vec::new();
            for entry in health {
                if entry.detected && entry.targeted && !seen.iter().any(|d| d == &entry.dir) {
                    seen.push(entry.dir.clone());
                    targeted.push(entry);
                }
            }
            if targeted.is_empty() {
                (
                    "absent",
                    "no agent skills dir linked; run `confidant setup --agent auto`".to_owned(),
                )
            } else {
                let linked: usize = targeted.iter().map(|entry| entry.linked).sum();
                let total: usize = targeted.iter().map(|entry| entry.total).sum();
                let names: Vec<&str> = targeted.iter().map(|entry| entry.name.as_str()).collect();
                let state = if linked == total { "present" } else { "absent" };
                (
                    state,
                    format!("linked {linked}/{total} for {}", names.join(", ")),
                )
            }
        }
        Err(err) => (
            "unknown",
            format!("cannot determine home directory: {err:#}"),
        ),
    };
    layers.push(OptionalLayer {
        id: "skills",
        state: skills.0,
        detail: skills.1,
        tradeoff: "Workflow guidance and guardrails for agents that shell out to the CLI; `confidant setup` re-links them.",
    });

    // QMD binary (#715: presence means a working probe, not a name on PATH).
    let qmd = qmd_state();
    let (qmd_state, qmd_detail) = match &qmd {
        QmdState::Working { path, version } => {
            ("present", format!("{} ({})", path.display(), version))
        }
        QmdState::Missing => (
            "absent",
            "optional; install with `npm install -g @tobilu/qmd`".to_owned(),
        ),
        QmdState::NotWorking { path } => (
            "not working",
            format!("{} did not report a version", path.display()),
        ),
    };
    layers.push(OptionalLayer {
        id: "qmd",
        state: qmd_state,
        detail: qmd_detail,
        tradeoff: "A second toolchain (Node 20+ and a global npm install); adds hybrid BM25 + vector + rerank recall beyond `confidant find`.",
    });

    // Corpus.
    let corpus = vault.map(|root| root.join(QMD_CORPUS_REL));
    let corpus_built = corpus
        .as_deref()
        .filter(|path| path.is_dir())
        .map(std::path::Path::to_path_buf);
    let (corpus_state, corpus_detail) = match (&corpus_built, vault) {
        (Some(path), _) => ("present", path.display().to_string()),
        (None, Some(_)) => (
            "absent",
            "not built; run the qmd-search skill's `qmd-index.py`".to_owned(),
        ),
        (None, None) => ("absent", "no vault to build a corpus from".to_owned()),
    };
    layers.push(OptionalLayer {
        id: "corpus",
        state: corpus_state,
        detail: corpus_detail,
        tradeoff: "Plaintext chunks and embeddings of cleared records under `<vault>/.confidant/`; gitignored, never synced, rebuild after content changes.",
    });

    // Embeddings.
    let (embed_state, embed_detail) = match (&corpus_built, &qmd) {
        (None, _) => ("absent", "no corpus to embed".to_owned()),
        (Some(_), QmdState::Working { path, .. }) => {
            let root = vault.expect("a corpus implies a vault");
            match qmd_embedded_vectors(root, path) {
                Some(n) if n > 0 => ("present", format!("{n} embedded vectors")),
                Some(_) => (
                    "absent",
                    "none yet; keyword (BM25) search works without them".to_owned(),
                ),
                None => (
                    "unknown",
                    "`qmd status` did not report an embedding count".to_owned(),
                ),
            }
        }
        (Some(_), QmdState::NotWorking { .. }) => (
            "unknown",
            "qmd did not answer, so the embedding count is unknown".to_owned(),
        ),
        (Some(_), QmdState::Missing) => (
            "absent",
            "qmd is not installed, so nothing can be embedded".to_owned(),
        ),
    };
    layers.push(OptionalLayer {
        id: "embeddings",
        state: embed_state,
        detail: embed_detail,
        tradeoff: "First embed downloads multi-GB GGUF models; enables semantic/hybrid ranking.",
    });

    layers
}

pub(crate) fn optional_layers_json(vault: Option<&Path>) -> Value {
    Value::Array(
        optional_layers(vault)
            .into_iter()
            .map(|layer| {
                serde_json::json!({
                    "id": layer.id,
                    "state": layer.state,
                    "detail": layer.detail,
                    "tradeoff": layer.tradeoff,
                })
            })
            .collect(),
    )
}

pub(crate) fn print_optional_layers(vault: Option<&Path>) {
    println!("Optional layers (each is independent; nothing above requires them)");
    for layer in optional_layers(vault) {
        println!("  {:<11} {:<12} {}", layer.id, layer.state, layer.detail);
        println!("  {:<11} {:<12} tradeoff: {}", "", "", layer.tradeoff);
    }
}

pub(crate) fn machine_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|name| !name.trim().is_empty())
        .or_else(|| {
            std::env::var("COMPUTERNAME")
                .ok()
                .filter(|name| !name.trim().is_empty())
        })
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .filter(|out| out.status.success())
                .and_then(|out| String::from_utf8(out.stdout).ok())
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
        })
        .unwrap_or_else(|| "this machine".to_owned())
}

pub(crate) fn format_system_time(time: std::time::SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time)
        .format("%Y-%m-%d %H:%M UTC")
        .to_string()
}

pub(crate) fn completion_brief(cli: &Cli, vault: Option<&Path>) -> CompletionBrief {
    let loaded = vault.and_then(|root| load_vault(root).ok());
    let counts = loaded
        .as_ref()
        .map(|vault| {
            let count = |kind: RecordKind| {
                vault
                    .records
                    .values()
                    .filter(|record| record.kind == kind)
                    .count()
            };
            (
                count(RecordKind::Person),
                count(RecordKind::Org),
                count(RecordKind::Deal),
                count(RecordKind::Interaction),
                count(RecordKind::Note),
            )
        })
        .unwrap_or((0, 0, 0, 0, 0));
    let (people, orgs, deals, interactions, notes) = counts;
    let cadence_warnings = loaded
        .as_ref()
        .map(|vault| {
            check_vault(vault, &CheckOptions::default())
                .findings
                .iter()
                .filter(|finding| {
                    finding.code == confidant_core::check::FindingCode::CadenceOverdue
                })
                .count()
        })
        .unwrap_or(0);
    // Only infer branch/remote/fleet from the vault's own repository, never
    // from a parent checkout that happens to contain it.
    let has_git = vault.is_some_and(|root| root.join(".git").exists());
    let branch = vault
        .filter(|_| has_git)
        .and_then(|root| current_branch(root, cli.no_input));

    let mut sections = Vec::new();

    // 1. The vault.
    let mut vault_lines = Vec::new();
    match (vault, loaded.as_ref()) {
        (Some(root), Some(loaded)) => {
            vault_lines.push(format!("Name: {}", loaded.config.vault_id));
            vault_lines.push(format!("Location: {}", root.display()));
            vault_lines.push(format!(
                "Branch: {}",
                branch
                    .as_deref()
                    .unwrap_or("unknown (git did not report a branch)")
            ));
            vault_lines.push(format!(
                "Records: {people} people, {orgs} orgs, {deals} deals, \
                 {interactions} interactions, {notes} notes."
            ));
        }
        (Some(root), None) => {
            vault_lines.push(format!("Location: {}", root.display()));
            vault_lines.push(
                "The vault could not be loaded. Run `confidant check` and fix the error before relying on it."
                    .to_owned(),
            );
        }
        (None, _) => {
            vault_lines.push("No vault is configured on this machine.".to_owned());
            vault_lines.push("New vault: `confidant init --create --no-input`.".to_owned());
            vault_lines.push(
                "Existing vault: set `CONFIDANT_VAULT` or pass `--vault <path>`, then re-run `confidant setup` so agent instructions get the pointer."
                    .to_owned(),
            );
        }
    }
    sections.push(BriefSection {
        key: "vault",
        title: "The vault",
        lines: vault_lines,
    });

    // 2. This machine.
    let writable = vault
        .and_then(|root| std::fs::metadata(root).ok())
        .map(|meta| !meta.permissions().readonly())
        .unwrap_or(false);
    let mut machine_lines = vec![format!("Machine: {}", machine_name())];
    if vault.is_some() {
        machine_lines.push(format!(
            "Can read this vault: {}",
            if loaded.is_some() { "yes" } else { "no" }
        ));
        machine_lines.push(format!(
            "Can write this vault: {} (permission bits; no write was attempted)",
            if writable { "yes" } else { "no" }
        ));
    } else {
        machine_lines
            .push("No vault is configured, so there is nothing to read or write yet.".to_owned());
    }
    sections.push(BriefSection {
        key: "machine",
        title: "This machine",
        lines: machine_lines,
    });

    // 3. The fleet, inferred from the remote and recent commits.
    let mut fleet_lines = Vec::new();
    let mut remote: Option<(String, String)> = None;
    let mut upstream: Option<(String, String)> = None;
    let mut authors: Vec<String> = Vec::new();
    if let (Some(root), true) = (vault, has_git) {
        if let Ok(output) = confidant_core::write::git(root, &["remote", "-v"], cli.no_input) {
            let entries = parse_git_remote_urls(&output);
            remote = entries
                .iter()
                .find(|(name, _)| name == "origin")
                .or_else(|| entries.first())
                .map(|(name, url)| (name.clone(), url.clone()));
        }
        upstream = git_upstream(root, cli.no_input);
        if let Ok(output) =
            confidant_core::write::git(root, &["log", "-n", "50", "--format=%an"], cli.no_input)
        {
            for name in output
                .lines()
                .map(str::trim)
                .filter(|name| !name.is_empty())
            {
                if !authors.iter().any(|seen| seen == name) {
                    authors.push(name.to_owned());
                }
            }
        }
        fleet_lines.push(format!("This clone: {}", root.display()));
    }
    match &remote {
        Some((name, url)) => fleet_lines.push(format!(
            "Remote: {name} {}",
            display_remote_url(url)
        )),
        None if vault.is_some() && !has_git => fleet_lines.push(
            "This vault is not a git repository, so there is no remote. Writes need git; run `confidant doctor`."
                .to_owned(),
        ),
        None => fleet_lines.push(
            "No git remote. This vault lives on one machine; a lost disk has no copy.".to_owned(),
        ),
    }
    if !authors.is_empty() {
        fleet_lines.push(format!(
            "Recent commits (last 50) show {} author {}: {}. Confidant cannot see how many machines clone this repo.",
            authors.len(),
            if authors.len() == 1 { "identity" } else { "identities" },
            authors.join(", ")
        ));
    } else if vault.is_some() {
        fleet_lines.push(
            "No commits yet, so there is no recent-author evidence about other machines."
                .to_owned(),
        );
    }
    sections.push(BriefSection {
        key: "fleet",
        title: "The fleet",
        lines: fleet_lines,
    });

    // 4. The remote and the perimeter, stated plainly.
    let mut perimeter_lines = vec!["Records are plaintext on disk and in git history.".to_owned()];
    if remote.is_some() {
        perimeter_lines.push(
            "The remote must be private: anyone with access can read every record, history included. Confidant cannot verify the host's visibility setting."
                .to_owned(),
        );
        perimeter_lines.push(
            "There is no application-level encryption. The perimeter is the private remote plus full-disk encryption (LUKS, FileVault) on every machine."
                .to_owned(),
        );
    } else {
        perimeter_lines.push(
            "There is no remote. The perimeter is this machine and any backup copy you keep."
                .to_owned(),
        );
        perimeter_lines.push(
            "There is no application-level encryption. Keep the disk and every backup under full-disk encryption (LUKS, FileVault)."
                .to_owned(),
        );
    }
    perimeter_lines.push(
        "Full-disk encryption is an OS setting. Confidant does not verify it, and no check was run."
            .to_owned(),
    );
    sections.push(BriefSection {
        key: "perimeter",
        title: "The remote and the perimeter",
        lines: perimeter_lines,
    });

    // 5. Sync posture, with the reason.
    let mut sync_lines = Vec::new();
    match &upstream {
        Some((branch, upstream)) => {
            sync_lines.push(format!("This clone tracks {upstream} on branch {branch}."));
            sync_lines.push(
                "Commits stay local until you run `confidant sync --push`; that is an explicit, confirmed network write."
                    .to_owned(),
            );
        }
        None if remote.is_some() => {
            sync_lines.push(format!(
                "A remote is configured, but branch {} has no upstream yet.",
                branch.as_deref().unwrap_or("main")
            ));
            sync_lines.push(format!(
                "Set one with `git push -u {} {}` before using `confidant sync`.",
                remote
                    .as_ref()
                    .map(|(name, _)| name.as_str())
                    .unwrap_or("origin"),
                branch.as_deref().unwrap_or("main")
            ));
        }
        None => {
            sync_lines.push(
                "Local-only: no remote, so nothing syncs. Back up the disk another way.".to_owned(),
            );
        }
    }
    sync_lines.push(
        "Nothing pushes or pulls as a side effect of a write. `confidant sync` reports ahead/behind from the last fetch."
            .to_owned(),
    );
    sync_lines.push(
        "If the branch has diverged, `confidant sync` reports it and refuses to fast-forward; reconcile explicitly."
            .to_owned(),
    );
    if remote.is_some() {
        sync_lines.push(
            "Who can write: this machine can change its local clone; any machine with push access to the remote can change the shared copy. Confidant does not probe credentials."
                .to_owned(),
        );
    } else {
        sync_lines
            .push("Who can write: this machine only; there is no remote to push to.".to_owned());
    }
    sections.push(BriefSection {
        key: "sync",
        title: "Sync posture",
        lines: sync_lines,
    });

    // 6. Search state and its upkeep truth.
    let qmd = qmd_state();
    let corpus_path = vault.map(|root| root.join(QMD_CORPUS_REL));
    let corpus = corpus_path
        .as_deref()
        .filter(|path| path.is_dir())
        .map(std::path::Path::to_path_buf);
    let mut search_lines = Vec::new();
    if vault.is_none() {
        search_lines.push(
            "No vault, so there is no corpus. `confidant find` becomes available once a vault is configured."
                .to_owned(),
        );
    } else if matches!(qmd, QmdState::Missing) {
        search_lines.push(
            "QMD is not installed; semantic search is off. `confidant find` reads the live vault."
                .to_owned(),
        );
    } else if let QmdState::NotWorking { path } = &qmd {
        // #715: presence is not availability. A stub on PATH must not read
        // as a working semantic-search layer.
        search_lines.push(format!(
            "QMD at {} did not report a version; semantic search is off. `confidant find` reads the live vault.",
            path.display()
        ));
    } else if let Some(path) = &corpus {
        let modified = std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .map(format_system_time)
            .unwrap_or_else(|_| "unknown".to_owned());
        search_lines.push(format!(
            "QMD corpus: {}; last modified {modified}.",
            path.display()
        ));
        // #725: the doctor check is the safety net, but `setup`/`status`
        // print this brief, so state staleness here too.
        if let Some(root) = vault {
            match corpus_freshness(root) {
                CorpusFreshness::Current { built_at, embedded } => {
                    if embedded {
                        search_lines.push(format!(
                            "Index current with the vault HEAD (built {built_at})."
                        ));
                    } else {
                        search_lines.push(format!(
                            "Index built {built_at} is current with the vault HEAD but was \
                             last built without `--embed`; vector results may be incomplete."
                        ));
                    }
                }
                CorpusFreshness::Behind { commits, built_at } => search_lines.push(format!(
                    "Index is {commits} commit{} behind the vault HEAD (built {built_at}); rebuild before relying on ranked results.",
                    if commits == 1 { "" } else { "s" }
                )),
                CorpusFreshness::Unknown(reason) => search_lines.push(format!(
                    "Index freshness is unknown ({reason}); rebuild to record the HEAD."
                )),
            }
        }
        search_lines.push(
            "Search results are a snapshot from that time. Refresh the corpus after changes; exact lookups (`resolve`, `context`, `find`) read the live vault."
                .to_owned(),
        );
    } else {
        search_lines.push(
            "QMD is installed but this vault has no corpus. Keyword search falls back to `confidant find`; build the corpus with the qmd-search skill."
                .to_owned(),
        );
    }
    search_lines.push(
        "QMD is optional: embeddings can download multi-GB models and use disk under `.confidant/` (gitignored)."
            .to_owned(),
    );
    sections.push(BriefSection {
        key: "search",
        title: "Search",
        lines: search_lines,
    });

    // 7. The standing orders, and where they live.
    let mut standing_lines = Vec::new();
    match setup::home_dir() {
        Ok(home) => {
            let health = setup::system_of_record_health(&home, vault);
            if health.is_empty() {
                standing_lines.push(
                    "No agent detected; no standing orders were installed. Run `confidant setup --agent auto` after installing one."
                        .to_owned(),
                );
            } else {
                for entry in health {
                    let state = if !entry.installed {
                        "missing"
                    } else if vault.is_some() && !entry.matches_vault {
                        "installed, but points at another vault"
                    } else {
                        "installed"
                    };
                    standing_lines.push(format!(
                        "{} -> {} ({state})",
                        entry.agent,
                        entry.path.display()
                    ));
                }
            }
        }
        Err(err) => standing_lines.push(format!("Cannot determine home directory: {err:#}")),
    }
    standing_lines.push("Re-print the exact rule with `confidant routing`.".to_owned());
    sections.push(BriefSection {
        key: "standing-orders",
        title: "Standing orders",
        lines: standing_lines,
    });

    // 8. The work discipline in force.
    sections.push(BriefSection {
        key: "discipline",
        title: "Work discipline",
        lines: vec![
            "Writes are propose (`--dry-run`) → operator confirms → apply.".to_owned(),
            "Each write runs `check` and commits once; a failing check blocks the write."
                .to_owned(),
            "Nothing pushes, publishes, or spends as a side effect.".to_owned(),
            "`sync --pull` and `sync --push` are explicit, confirmed network writes.".to_owned(),
            "`no-ai: true` records, and the notes of `no-ai: notes` people, never enter agent output.".to_owned(),
        ],
    });

    // 9. 3–5 jumping-off routines, grounded in this vault's contents.
    let mut routines = Vec::new();
    if let Some(root) = vault {
        if loaded.is_none() {
            routines.push(format!(
                "Inspect the vault: `confidant check --vault {}` and fix the error it reports.",
                root.display()
            ));
            routines.push(format!(
                "Load it in the agent: `confidant resolve <name> --vault {}` once `check` is clean.",
                root.display()
            ));
            routines.push(format!(
                "Re-run setup after fixing it: `confidant setup --vault {}`.",
                root.display()
            ));
            routines.push("Check readiness: `confidant status`.".to_owned());
        } else if people > 0 {
            routines.push(
                "Before a conversation: `confidant resolve <name>` then `confidant context <id>`."
                    .to_owned(),
            );
            routines.push(
                "After a conversation: `confidant log touch <person> meet --note \"what happened\" --dry-run`, review it, then rerun without `--dry-run`."
                    .to_owned(),
            );
            if cadence_warnings > 0 {
                routines.push(format!(
                    "Keep in touch: `confidant check` lists {cadence_warnings} cadence warning(s); log a touch with `confidant log touch <person> meal` after contact."
                ));
            }
        } else {
            routines.push(
                "Add the first person: `confidant record add --file <person.md>` (see `confidant help record add`)."
                    .to_owned(),
            );
        }
        routines.push(
            "Search: `confidant find <query>` reads the live vault; use the qmd-search skill for fuzzy questions when enabled."
                .to_owned(),
        );
        if interactions + notes > 0 && routines.len() < 5 {
            routines.push(format!(
                "Review context: `confidant context <id>` includes {interactions} interaction(s) and {notes} note(s)."
            ));
        }
        if routines.len() < 5 {
            routines.push(
                "Check the vault: `confidant check` (read-only; finding codes are stable)."
                    .to_owned(),
            );
        }
    } else {
        routines.push("Create a vault: `confidant init --create --no-input`.".to_owned());
        routines.push(
            "Point this machine at an existing vault: set `CONFIDANT_VAULT` or pass `--vault <path>`."
                .to_owned(),
        );
        routines.push(
            "Re-run `confidant setup --vault <path>` so the pointer is in agent instructions."
                .to_owned(),
        );
        routines.push("Check readiness: `confidant status`.".to_owned());
    }

    CompletionBrief { sections, routines }
}
