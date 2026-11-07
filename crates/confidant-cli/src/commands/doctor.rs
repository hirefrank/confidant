//! `doctor` checks and the health primitives `status` reuses.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::find::{QMD_BUILD_MARKER_REL, QMD_CORPUS_REL, QMD_STORE_REL};
use crate::commands::install::staleness_update_hint;
use crate::commands::shared::find_on_path;
use crate::{ok_envelope, print_json, setup, Cli};
use confidant_core::error::DomainError;
use confidant_core::write::require_git_repo;
use confidant_core::{check_vault, load_vault, CheckOptions};
use serde_json::Value;

pub(crate) struct DoctorCheck {
    pub(crate) id: &'static str,
    pub(crate) status: &'static str,
    pub(crate) message: String,
    /// Actionable next step for a non-ok check, serialized as `fix` (the
    /// ADR-7 error-envelope field name). `None` when nothing needs doing.
    pub(crate) fix: Option<String>,
}

/// #809: a vault written by the encrypted Confidant (≤0.7) cannot be read
/// as plaintext. One clear check replaces the stream of record and ledger
/// parse errors the normal checks would report.
pub(crate) fn legacy_encrypted_vault_check() -> DoctorCheck {
    DoctorCheck {
        id: "legacy-encrypted-vault",
        status: "error",
        message: confidant_core::error::LEGACY_ENCRYPTED_VAULT_MESSAGE.to_owned(),
        fix: None,
    }
}

/// Latest GitHub Release endpoint (#165). Release builds always use the
/// real endpoint. `test-overrides` builds use `CONFIDANT_TEST_RELEASES_URL`
/// when set, and an unroutable loopback URL otherwise, so the test suite
/// never touches the network (the connection is refused instantly and the
/// check degrades to "unknown", exactly as an offline user would see).
pub(crate) fn releases_url() -> String {
    #[cfg(feature = "test-overrides")]
    {
        std::env::var("CONFIDANT_TEST_RELEASES_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:9/".to_owned())
    }
    #[cfg(not(feature = "test-overrides"))]
    {
        "https://api.github.com/repos/hirefrank/confidant/releases/latest".to_owned()
    }
}

/// Message whenever staleness cannot be determined: offline, DNS
/// failure, timeout, non-200, or malformed JSON. The check reports
/// status `unknown` for it (#709): an undetermined check never renders
/// `ok`. `unknown` is warning-tier — it never fails `doctor` — so an
/// offline user still passes, just not with a green line.
pub(crate) const STALENESS_UNKNOWN: &str = "staleness unknown (could not reach github releases)";

/// `ok` message when the operator disables the staleness checks outright
/// with `CONFIDANT_OFFLINE=1`: no request is made and no release tag is
/// fetched (see README and docs/privacy.md).
pub(crate) const STALENESS_DISABLED: &str = "staleness check disabled (CONFIDANT_OFFLINE=1)";

/// True when the operator has opted out of the outbound release check with
/// `CONFIDANT_OFFLINE`. Unset or empty means normal behaviour; any other
/// value (conventionally `1`) skips the fetch entirely.
pub(crate) fn staleness_offline() -> bool {
    std::env::var("CONFIDANT_OFFLINE")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// The `tag_name` of the latest GitHub Release, or `None` if it cannot be
/// fetched for any reason. A single failure mode (offline, timeout,
/// non-200, bad JSON) all collapse to `None`; only the parsed tag name is
/// ever returned, never the response body.
pub(crate) fn latest_release_tag() -> Option<String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(3)))
        .build()
        .into();
    let mut response = agent
        .get(&releases_url())
        .header("User-Agent", "confidant-cli")
        .header("Accept", "application/vnd.github+json")
        .call()
        .ok()?;
    let body = response.body_mut().read_to_string().ok()?;
    let value: Value = serde_json::from_str(&body).ok()?;
    value.get("tag_name")?.as_str().map(str::to_owned)
}

/// Parse a release tag like `v1.2.3` into `(major, minor, patch)`. The
/// leading `v` is optional and any suffix on the patch (e.g. `-rc.1`) is
/// ignored: `/releases/latest` never returns a prerelease, so dropping the
/// suffix cannot mask one. Returns `None` for anything that is not
/// `major.minor.patch`, which the caller treats the same as "unknown".
pub(crate) fn parse_release_version(tag: &str) -> Option<(u64, u64, u64)> {
    let trimmed = tag.trim().trim_start_matches('v');
    let mut parts = trimmed.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch: String = parts
        .next()?
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    Some((major, minor, patch.parse::<u64>().ok()?))
}

/// Build the CLI staleness check given the latest release tag (or `None`
/// when it could not be fetched). Never an error: behind is `warning`,
/// ahead and equal are `ok`, and undetermined (no tag, or an unparseable
/// tag) is `unknown` (#709). With `offline`, the fetch was skipped by
/// operator choice — a determined state, not an undetermined one — so
/// the check reports `ok` "disabled". `update_hint` is the per-method update
/// command from [`InstallMethod::update_command`] (#876); `None` keeps the
/// `cargo install` fallback that older installs already know.
pub(crate) fn cli_staleness_check(
    latest: Option<String>,
    offline: bool,
    update_hint: Option<&str>,
) -> DoctorCheck {
    let local = env!("CARGO_PKG_VERSION");
    let update_hint = update_hint.unwrap_or("cargo install confidant-cli");
    let (status, message) = if offline {
        ("ok", STALENESS_DISABLED.to_owned())
    } else {
        match latest {
            None => (DOCTOR_STATUS_UNKNOWN, STALENESS_UNKNOWN.to_owned()),
            Some(tag) => match (parse_release_version(local), parse_release_version(&tag)) {
                (Some(local_v), Some(latest_v)) if local_v < latest_v => (
                    "warning",
                    format!(
                        "confidant-cli {local} is behind the latest release {tag}; \
                         update with `{update_hint}`"
                    ),
                ),
                (Some(local_v), Some(latest_v)) if local_v > latest_v => (
                    "ok",
                    format!(
                        "confidant-cli {local} is ahead of the latest release {tag} (dev build)"
                    ),
                ),
                (Some(_), Some(_)) => (
                    "ok",
                    format!("confidant-cli {local} matches the latest release {tag}"),
                ),
                _ => (DOCTOR_STATUS_UNKNOWN, STALENESS_UNKNOWN.to_owned()),
            },
        }
    };
    DoctorCheck {
        id: "cli-staleness",
        status,
        message,
        fix: None,
    }
}

/// Minimum git version Confidant relies on. Confidant shells out to git
/// for every write, commit, and sync; older clients miss behavior the
/// agent contract assumes.
pub(crate) const MIN_GIT_VERSION: (u64, u64, u64) = (2, 34, 0);

/// Parse `git --version` output into `(major, minor, patch)`. Handles
/// real-world suffixes: `git version 2.39.3 (Apple Git-145)` and
/// `git version 2.47.1.windows.1`. Missing minor/patch default to 0.
/// Returns `None` when no leading version number can be read.
pub(crate) fn parse_git_version(output: &str) -> Option<(u64, u64, u64)> {
    let token = output
        .trim()
        .strip_prefix("git version ")?
        .split_whitespace()
        .next()?;
    let mut parts = token.split('.');
    let leading_digits = |s: &str| -> Option<u64> {
        let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            None
        } else {
            digits.parse().ok()
        }
    };
    let major = leading_digits(parts.next()?)?;
    let minor = parts.next().and_then(leading_digits).unwrap_or(0);
    let patch = parts.next().and_then(leading_digits).unwrap_or(0);
    Some((major, minor, patch))
}

/// Build the `git-version` doctor check from a parsed `git --version`
/// result. Below the floor the check is a `warning`: nothing verifies
/// signatures today, so an old git is a portability nudge, not a vault
/// defect. `None` (git missing or unparseable output) is `unknown` (#709,
/// following the #174 precedent it generalizes): the `git-repo` check
/// already errors when the vault is not a git repository, and an
/// unparseable version string is an odd environment, not a known-bad git.
/// `unknown` is warning-tier, so it never fails `doctor`.
pub(crate) fn git_version_check_from(version: Option<(u64, u64, u64)>) -> DoctorCheck {
    let floor = format!(
        "{}.{}.{}",
        MIN_GIT_VERSION.0, MIN_GIT_VERSION.1, MIN_GIT_VERSION.2
    );
    match version {
        Some(v) if v >= MIN_GIT_VERSION => DoctorCheck {
            id: "git-version",
            status: "ok",
            message: format!("git {}.{}.{} (>= {floor})", v.0, v.1, v.2),
            fix: None,
        },
        Some(v) => DoctorCheck {
            id: "git-version",
            status: "warning",
            message: format!(
                "git {}.{}.{} is below the minimum {floor}; upgrade git to >= {floor}",
                v.0, v.1, v.2
            ),
            fix: None,
        },
        None => DoctorCheck {
            id: "git-version",
            status: DOCTOR_STATUS_UNKNOWN,
            message: format!("could not determine git version; Confidant needs git >= {floor}"),
            fix: None,
        },
    }
}

/// The `git-version` doctor check: runs `git --version` and compares
/// against `MIN_GIT_VERSION`. See `git_version_check_from` for the
/// status rules.
pub(crate) fn git_version_check() -> DoctorCheck {
    let version = std::process::Command::new("git")
        .arg("--version")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| parse_git_version(&String::from_utf8_lossy(&out.stdout)));
    git_version_check_from(version)
}

pub(crate) fn skills_links_check() -> DoctorCheck {
    let home = match setup::home_dir() {
        Ok(h) => h,
        Err(e) => {
            return DoctorCheck {
                id: "skills-links",
                status: "warning",
                message: format!("cannot determine home directory: {e:#}"),
                fix: None,
            };
        }
    };
    let health: Vec<setup::AgentHealth> = match setup::skills_dir_override() {
        Some(dir) => vec![setup::agent_health_for_dir("custom", &dir)],
        None => setup::agents_health(&home),
    };
    // Dedupe entries that resolve to the same dir.
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut unique: Vec<&setup::AgentHealth> = Vec::new();
    for h in &health {
        if seen.iter().any(|d| d == &h.dir) {
            continue;
        }
        seen.push(h.dir.clone());
        unique.push(h);
    }
    let targeted: Vec<_> = unique.iter().filter(|h| h.detected && h.targeted).collect();
    if targeted.is_empty() {
        return DoctorCheck {
            id: "skills-links",
            status: "ok",
            message: "no agents set up; run `confidant setup --agent auto` to install skills"
                .to_owned(),
            fix: None,
        };
    }
    let total_expected: usize = targeted.iter().map(|h| h.total).sum();
    let total_linked: usize = targeted.iter().map(|h| h.linked).sum();
    if total_linked == total_expected {
        let names: Vec<_> = targeted.iter().map(|h| h.name.as_str()).collect();
        DoctorCheck {
            id: "skills-links",
            status: "ok",
            message: format!(
                "skills linked ({total_linked}/{total_expected}) for {}",
                names.join(", ")
            ),
            fix: None,
        }
    } else {
        let mut parts = Vec::new();
        for h in targeted {
            parts.push(format!(
                "{} {}/{} ({})",
                h.name,
                h.linked,
                h.total,
                h.dir.display()
            ));
        }
        DoctorCheck {
            id: "skills-links",
            status: "warning",
            message: format!(
                "skills missing (linked {total_linked}/{total_expected}: {}); run `confidant setup --agent auto`",
                parts.join(", ")
            ),
            fix: None,
        }
    }
}

/// What a `qmd` presence check actually found (#715). A name on PATH is not
/// proof: the field report had a test shim named `qmd` that returned canned
/// query results, so presence means "answers `--version`/`--help` like a CLI".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QmdState {
    /// No `qmd` on PATH.
    Missing,
    /// A file named `qmd` is on PATH but did not report a version or usage.
    NotWorking { path: PathBuf },
    /// A `qmd` that answered a probe; `version` is its first output line.
    Working { path: PathBuf, version: String },
}

/// Probe a binary's `--version` (falling back to `--help`) with the same
/// bounded spawn `tui_binary_version` uses: 2s, 64 KiB per pipe. A broken
/// shim must not hang `doctor` or `setup`.
pub(crate) fn probe_binary_text(bin: &Path, arg: &str) -> Option<String> {
    use std::io::Read as _;
    const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
    const MAX_OUTPUT: u64 = 64 * 1024;

    let mut child = std::process::Command::new(bin)
        .arg(arg)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let mut stdout_thread = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = (&mut out).take(MAX_OUTPUT).read_to_end(&mut buf);
            buf
        })
    });
    let mut stderr_thread = child.stderr.take().map(|mut err| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = (&mut err).take(MAX_OUTPUT).read_to_end(&mut buf);
            buf
        })
    });
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait().ok()? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= PROBE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    // Do not join the drain threads: a wrapper script can
                    // leave a grandchild holding the pipes after the direct
                    // child is killed (#659).
                    let _ = stdout_thread.take();
                    let _ = stderr_thread.take();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    };
    let stdout = stdout_thread
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = stderr_thread
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    if !status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&stdout).trim().to_owned();
    let text = if text.is_empty() {
        String::from_utf8_lossy(&stderr).trim().to_owned()
    } else {
        text
    };
    (!text.is_empty()).then_some(text)
}

/// True when probe output looks like a version/usage banner rather than a
/// canned query result. Only the first non-empty line is judged: a canned
/// hit list can contain a version-shaped score like `0.87` (or the tool name
/// in its body), and any later line must not rescue it. On that line, `qmd`
/// in the text, or a `major.minor`-style token, is enough.
pub(crate) fn looks_like_version_or_usage(output: &str) -> bool {
    let Some(line) = first_nonempty_line(output) else {
        return false;
    };
    line.to_ascii_lowercase().contains("qmd")
        || line.split_whitespace().any(|token| {
            let mut parts = token.split('.');
            parts
                .next()
                .is_some_and(|first| !first.is_empty() && first.chars().all(|c| c.is_ascii_digit()))
                && parts.next().is_some_and(|second| {
                    !second.is_empty() && second.chars().all(|c| c.is_ascii_digit())
                })
        })
}

/// The first line with content, trimmed; `None` for blank output.
pub(crate) fn first_nonempty_line(output: &str) -> Option<&str> {
    output.lines().map(str::trim).find(|line| !line.is_empty())
}

/// Detect a *working* qmd (#715), not just a name on PATH.
///
/// Cached for the life of the process: `setup` and `status` ask more than
/// once, and a hanging shim costs the full 2s probe each time otherwise. The
/// CLI is one-shot, so a cache can never go stale across commands.
pub(crate) fn qmd_state() -> QmdState {
    static CACHED: std::sync::OnceLock<QmdState> = std::sync::OnceLock::new();
    CACHED.get_or_init(probe_qmd_state).clone()
}

/// The uncached probe behind [`qmd_state`].
pub(crate) fn probe_qmd_state() -> QmdState {
    let Some(path) = find_on_path("qmd") else {
        return QmdState::Missing;
    };
    let banner = probe_binary_text(&path, "--version")
        .filter(|text| looks_like_version_or_usage(text))
        .or_else(|| {
            probe_binary_text(&path, "--help").filter(|text| looks_like_version_or_usage(text))
        });
    match banner {
        Some(text) => QmdState::Working {
            path,
            version: first_nonempty_line(&text).unwrap_or_default().to_owned(),
        },
        None => QmdState::NotWorking { path },
    }
}

/// #725: how the corpus build compares with the vault's current HEAD.
/// `Unknown` is never "ok": a corpus with no usable build record (built by
/// an older skill, or by a failed rebuild) still gets a warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CorpusFreshness {
    Current { built_at: String, embedded: bool },
    Behind { commits: u64, built_at: String },
    Unknown(String),
}

/// `git -C <root> rev-parse HEAD`, or `None` when the vault has no git HEAD.
pub(crate) fn git_head(root: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let head = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (!head.is_empty()).then_some(head)
}

/// Commits reachable from `to` but not from `from`. `None` when git cannot
/// compare (the build commit is not in this history, e.g. after a rebase).
pub(crate) fn git_commits_between(root: &Path, from: &str, to: &str) -> Option<u64> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-list", "--count", &format!("{from}..{to}")])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Compare `<vault>/.confidant/qmd-build.json` (written by `qmd-index.py`)
/// with the live HEAD (#725). A missing or unreadable record is `Unknown`,
/// never a silent `Current`: the caller reports it at warn level.
pub(crate) fn corpus_freshness(root: &Path) -> CorpusFreshness {
    let raw = match std::fs::read_to_string(root.join(QMD_BUILD_MARKER_REL)) {
        Ok(raw) => raw,
        Err(_) => {
            return CorpusFreshness::Unknown(
                "no build record; re-run the index step to record one".to_owned(),
            );
        }
    };
    let value: Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(_) => {
            return CorpusFreshness::Unknown(
                "the build record is unreadable; rebuild it".to_owned(),
            );
        }
    };
    let built_at = value["built_at"]
        .as_str()
        .unwrap_or("unknown time")
        .to_owned();
    let built = value["commit"]
        .as_str()
        .map(str::trim)
        .filter(|commit| !commit.is_empty());
    let embedded = value["embedded"].as_bool().unwrap_or(false);
    let Some(built) = built else {
        return CorpusFreshness::Unknown(
            "the corpus was built before the vault had a commit".to_owned(),
        );
    };
    let Some(current) = git_head(root) else {
        return CorpusFreshness::Unknown("cannot read the vault's git HEAD".to_owned());
    };
    if built == current {
        return CorpusFreshness::Current { built_at, embedded };
    }
    match git_commits_between(root, built, &current) {
        Some(commits) if commits > 0 => CorpusFreshness::Behind { commits, built_at },
        // 0 with different commits means the recorded build is not behind
        // (a rewound or replaced history); do not claim "current".
        Some(_) => CorpusFreshness::Unknown(
            "the build commit is not an ancestor of the current HEAD".to_owned(),
        ),
        None => {
            CorpusFreshness::Unknown("the build commit is not in this vault's history".to_owned())
        }
    }
}

/// The rebuild instruction shared by every staleness warning.
pub(crate) fn qmd_rebuild_fix(root: &Path) -> String {
    format!(
        "Run \"$(confidant which --skills-dir)\"/qmd-search/bin/qmd-index.py \
         --vault \"{}\" --embed, then verify with one query",
        root.display()
    )
}

/// #386: informational `qmd` search-availability check. qmd is optional,
/// so a missing qmd is `ok` — the same rule as the offline staleness check:
/// it just means search falls back to `confidant find` (see
/// `qmd-query.py`). A qmd that is installed but has no corpus is a
/// `warning` (#657): the fallback still works, but the operator asked for
/// semantic search and a corpus built by the `qmd-search` skill is needed
/// to enable it, so an `ok` badge on that message is easy to miss.
///
/// Reports, in order: qmd on PATH and working (#715)? corpus built?
/// corpus built from the current HEAD (#725)? embeddings present?
/// (BM25 keyword search is ready without embeddings; semantic/hybrid
/// ranking needs the skill wrapper's `--embed`, not a bare `qmd embed`,
/// because QMD's store is relocated under the vault. #666)
///
/// Staleness wins over "ready": a corpus built from an older HEAD is a
/// warning even when it has vectors, and a missing/unreadable build record
/// is `unknown`, never a silent `ok` (#725).
pub(crate) fn qmd_search_check(root: &Path) -> DoctorCheck {
    const ID: &str = "qmd-search";
    const INSTALL_HINT: &str = "npm install -g @tobilu/qmd";
    let ok = |message: String| DoctorCheck {
        id: ID,
        status: "ok",
        message,
        fix: None,
    };

    let qmd = match qmd_state() {
        QmdState::Missing => {
            return ok(format!(
                "qmd not found on PATH; search falls back to `confidant find` \
                 (install with `{INSTALL_HINT}` to enable semantic search)"
            ));
        }
        // #715: a shim or broken install is present but cannot answer a
        // version probe. That is not "search is ready", so warn instead of
        // reporting the keyword fallback as ok.
        QmdState::NotWorking { path } => {
            return DoctorCheck {
                id: ID,
                status: "warning",
                message: format!(
                    "qmd at {} did not report a version (a stub or broken install?); \
                     search falls back to `confidant find`",
                    path.display()
                ),
                fix: Some(format!(
                    "Reinstall with `{INSTALL_HINT}`, or remove the broken binary at {}",
                    path.display()
                )),
            };
        }
        QmdState::Working { path, .. } => path,
    };
    if !root.join(QMD_CORPUS_REL).is_dir() {
        return DoctorCheck {
            id: ID,
            status: "warning",
            message: "qmd is on PATH but the search corpus is missing; \
                 build it with the qmd-search skill \
                 (search falls back to `confidant find`)"
                .to_owned(),
            fix: Some(
                "Run `confidant setup` to install the qmd-search skill, then build the corpus"
                    .to_owned(),
            ),
        };
    }
    // #725: staleness is checked before the embeddings probe, because a
    // stale index is never "ready" even when it has vectors.
    match corpus_freshness(root) {
        CorpusFreshness::Behind { commits, built_at } => {
            return DoctorCheck {
                id: ID,
                status: "warning",
                message: format!(
                    "search index is {commits} commit{} behind the vault HEAD \
                     (last built {built_at}); results may be incomplete or out of date",
                    if commits == 1 { "" } else { "s" }
                ),
                fix: Some(qmd_rebuild_fix(root)),
            };
        }
        CorpusFreshness::Unknown(reason) => {
            return DoctorCheck {
                id: ID,
                status: "warning",
                message: format!(
                    "search index freshness is unknown ({reason}); rebuild it to record the HEAD"
                ),
                fix: Some(qmd_rebuild_fix(root)),
            };
        }
        CorpusFreshness::Current {
            embedded: false, ..
        } => {
            return DoctorCheck {
                id: ID,
                status: "warning",
                message: "search index is current with the vault HEAD but was last built \
                          without `--embed`; vector results may be incomplete"
                    .to_owned(),
                fix: Some(qmd_rebuild_fix(root)),
            };
        }
        CorpusFreshness::Current { .. } => {}
    }
    match qmd_embedded_vectors(root, &qmd) {
        Some(n) if n > 0 => ok(format!(
            "hybrid/vector search available ({n} embedded vectors); \
             keyword (BM25) search is also ready; index current with the vault HEAD"
        )),
        Some(_) => DoctorCheck {
            id: ID,
            status: "ok",
            message: "keyword (BM25) search ready; index current with the vault HEAD; \
                      semantic/hybrid ranking is optional and not enabled (no embeddings)"
                .to_owned(),
            // #666: a bare `qmd embed` would target QMD's default store.
            // This project relocates QMD under the vault via
            // INDEX_PATH/QMD_CONFIG_DIR, so use the skill wrapper.
            fix: Some(format!(
                "Run \"$(confidant which --skills-dir)\"/qmd-search/bin/qmd-index.py \
                 --vault \"{}\" --embed to enable semantic/hybrid ranking \
                 (the first run downloads multi-GB GGUF models and needs network)",
                root.display()
            )),
        },
        // The probe itself could not report (status failed or timed out):
        // do not point at `qmd embed`, which would not fix a broken status.
        None => ok(
            "qmd status did not report embedded vectors; run `qmd status` \
             with INDEX_PATH=<vault>/.confidant/qmd/index.sqlite to diagnose \
             (search falls back to `confidant find`)"
                .to_owned(),
        ),
    }
}

/// Probe the vault-local qmd store for embedded vectors, mirroring
/// `qmd-query.py`'s `vectors_available` (same env, same `status` parse).
/// Returns `None` when qmd cannot report (missing store, failing status,
/// timeout). Never creates the store: when `index.sqlite` is absent the
/// probe is skipped, because some `qmd` versions create an empty index
/// file as a side effect of `status`.
pub(crate) fn qmd_embedded_vectors(root: &Path, qmd: &Path) -> Option<u64> {
    let store = root.join(QMD_STORE_REL);
    if !store.join("index.sqlite").is_file() {
        return Some(0);
    }
    let mut child = std::process::Command::new(qmd)
        .arg("status")
        .env("INDEX_PATH", store.join("index.sqlite"))
        .env("QMD_CONFIG_DIR", store.join("config"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    // Drain stdout on a helper thread while we poll: if qmd ever prints
    // more than the pipe buffer, it would block on write and never exit,
    // and we would only ever see the timeout below. Cap what we keep —
    // we only need the `Vectors:` line. (#416 nit 1)
    const MAX_STDOUT: u64 = 1 << 20; // 1 MiB
    let stdout_thread = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = (&mut out).take(MAX_STDOUT).read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        })
    });
    // `qmd status` has no built-in timeout (unlike `qmd-query.py`, which
    // uses timeout=30); a hung qmd must not hang `doctor` or the TUI
    // Doctor tab. Poll with try_wait and kill after the grace period.
    const QMD_STATUS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait().ok()? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= QMD_STATUS_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    };
    // The pipe's write end is closed now (child exited or was killed), so
    // the drain thread always terminates.
    let stdout = stdout_thread
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();
    if !status.success() {
        return None;
    }
    parse_embedded_vectors(&stdout)
}

/// Parse `qmd status` output for a `Vectors: <n> embedded` line.
pub(crate) fn parse_embedded_vectors(output: &str) -> Option<u64> {
    for line in output.lines() {
        if let Some(rest) = line.trim().strip_prefix("Vectors:") {
            let digits: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(n) = digits.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}

/// Parse the version out of `confidant-tui --version` output. Accepts
/// `confidant-tui 1.2.3`, `confidant-tui v1.2.3`, and a bare `1.2.3`;
/// scans tokens so a build suffix (`1.2.3 (abc)`) or a leading banner
/// line still resolves. Returns the normalized `major.minor.patch`, or
/// `None` when no version token is present.
pub(crate) fn parse_tui_version(output: &str) -> Option<String> {
    for token in output.split_whitespace() {
        let token = token.trim_start_matches('v');
        let mut parts = token.split('.');
        let major = parts.next()?;
        if major.is_empty() || !major.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(minor) = parts.next() else {
            continue;
        };
        if minor.is_empty() || !minor.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(patch) = parts.next() else {
            continue;
        };
        let patch: String = patch.chars().take_while(|c| c.is_ascii_digit()).collect();
        if patch.is_empty() {
            continue;
        }
        return Some(format!("{major}.{minor}.{patch}"));
    }
    None
}

/// Run `<bin> --version` and return its normalized version. `None` when
/// the probe fails, times out, or prints no recognizable version; the
/// caller treats that as "unknown", never as an error.
///
/// A broken TUI must not hang `doctor` or `confidant tui`, so this mirrors
/// the qmd probe: spawn, poll `try_wait`, and kill after the grace period
/// (a `--version` that takes two seconds is already pathological).
pub(crate) fn tui_binary_version(bin: &Path) -> Option<String> {
    use std::io::Read as _;
    const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
    const MAX_OUTPUT: u64 = 64 * 1024;

    let mut child = std::process::Command::new(bin)
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    // Drain both pipes on helper threads: a chatty binary that fills a
    // pipe would otherwise block on write and never exit, leaving only
    // the timeout to fire.
    let mut stdout_thread = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = (&mut out).take(MAX_OUTPUT).read_to_end(&mut buf);
            buf
        })
    });
    let mut stderr_thread = child.stderr.take().map(|mut err| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = (&mut err).take(MAX_OUTPUT).read_to_end(&mut buf);
            buf
        })
    });
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait().ok()? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= PROBE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    // Do not join the drain threads: a wrapper script can
                    // leave a grandchild (e.g. `sleep`) holding the pipes
                    // after the direct child is killed, and joining would
                    // wait for it. They end when the pipes close, and
                    // process exit detaches them either way. (#659)
                    let _ = stdout_thread.take();
                    let _ = stderr_thread.take();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    };
    // Both pipes are closed now, so the drain threads always terminate.
    let stdout = stdout_thread
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = stderr_thread
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    if !status.success() {
        return None;
    }
    parse_tui_version(&String::from_utf8_lossy(&stdout))
        .or_else(|| parse_tui_version(&String::from_utf8_lossy(&stderr)))
}

/// #659: `tui-version` doctor check. `confidant-tui` is optional and
/// installed separately, so a missing TUI is `ok`. An installed TUI whose
/// version differs from this CLI is a `warning`: the TUI speaks the same
/// ADR-7 contract, and a stale one can render unknown finding codes.
pub(crate) fn tui_version_check() -> DoctorCheck {
    const ID: &str = "tui-version";
    const INSTALL: &str = "cargo install confidant-tui";
    let cli_version = env!("CARGO_PKG_VERSION");
    let Some(bin) = find_on_path("confidant-tui") else {
        return DoctorCheck {
            id: ID,
            status: "ok",
            message: format!("optional TUI not installed; install it with `{INSTALL}`"),
            fix: None,
        };
    };
    let Some(tui_version) = tui_binary_version(&bin) else {
        // A broken or unusual `--version` must not make doctor noisy; the
        // TUI is optional and may still work.
        return DoctorCheck {
            id: ID,
            status: "ok",
            message: "confidant-tui is installed but did not report a version".to_owned(),
            fix: None,
        };
    };
    if tui_version == cli_version {
        DoctorCheck {
            id: ID,
            status: "ok",
            message: format!("confidant-tui {tui_version} matches confidant-cli {cli_version}"),
            fix: None,
        }
    } else {
        DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "confidant-tui {tui_version} does not match confidant-cli {cli_version}; \
                 the TUI may render stale or unknown state"
            ),
            fix: Some(format!("Run `{INSTALL}` to install the matching version")),
        }
    }
}

/// Parse `git remote -v` output into unique remote names, in first-seen
/// order. URLs are deliberately discarded: they may carry credentials.
pub(crate) fn parse_git_remotes(output: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in output.lines() {
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        if name.is_empty() || names.iter().any(|n| n == name) {
            continue;
        }
        names.push(name.to_owned());
    }
    names
}

/// One configured remote URL from `git remote -v`, paired with its remote
/// name. Fetch and push URLs can differ, so both are kept. URLs are never
/// printed: they may carry credentials.
pub(crate) fn parse_git_remote_urls(output: &str) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = Vec::new();
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(url)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name.is_empty() || entries.iter().any(|(n, u)| n == name && u == url) {
            continue;
        }
        entries.push((name.to_owned(), url.to_owned()));
    }
    entries
}

/// How a configured remote URL carries vault content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoteTransport {
    /// Encrypted in transit (`https://`, `ssh://`, scp-like `git@host:path`)
    /// or local (`file://`, a filesystem path), which never leaves the
    /// machine.
    Safe,
    /// A cleartext network transport; record bodies would cross the wire
    /// readable.
    Cleartext(&'static str),
    /// A scheme this check cannot vouch for.
    Unverified,
}

/// Classify a git remote URL without contacting it. Credentials in the URL
/// never affect the answer.
pub(crate) fn remote_transport(url: &str) -> RemoteTransport {
    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("ssh://") || lower.starts_with("file://")
    {
        return RemoteTransport::Safe;
    }
    if lower.starts_with("http://") {
        return RemoteTransport::Cleartext("http");
    }
    if lower.starts_with("git://") {
        return RemoteTransport::Cleartext("git");
    }
    if lower.contains("://") {
        return RemoteTransport::Unverified;
    }
    // The scp-like `user@host:path` (or `host:path`) form: git speaks ssh.
    if let Some((authority, path)) = url.split_once(':') {
        if !authority.is_empty() && !authority.contains('/') && !path.is_empty() {
            return RemoteTransport::Safe;
        }
    }
    // Anything else is a local filesystem path (`/srv/vault.git`,
    // `../remote.git`), which never leaves the machine.
    RemoteTransport::Safe
}

/// #660: `git-remote` doctor check. Read-only and offline: it never
/// fetches, pushes, or contacts a remote. It reports the configured
/// remotes by name and warns when one would carry plaintext record bodies
/// over an unencrypted transport (`http://`, `git://`) or a scheme this
/// check cannot vouch for. `https://`, `ssh://`, scp-like `git@host:path`
/// and local paths are safe.
///
/// `root` is the resolved vault. When it is not a directory (doctor never
/// reaches this today), the check stays `ok`: a missing vault is not a
/// remote problem.
pub(crate) fn git_remote_check(root: &Path, no_input: bool) -> DoctorCheck {
    const ID: &str = "git-remote";
    if !root.is_dir() {
        return DoctorCheck {
            id: ID,
            status: "ok",
            message: "no vault to inspect for git remotes".to_owned(),
            fix: None,
        };
    }
    let output = match confidant_core::write::git(root, &["remote", "-v"], no_input) {
        Ok(out) => out,
        Err(e) => {
            // Never a panic or an error: `git-repo` already reports a
            // missing repository, and this check is advisory.
            return DoctorCheck {
                id: ID,
                status: "warning",
                message: format!("could not read git remotes: {e}"),
                fix: None,
            };
        }
    };
    let remotes = parse_git_remotes(&output);
    if remotes.is_empty() {
        return DoctorCheck {
            id: ID,
            status: "ok",
            message: "local-only; add a remote for backup".to_owned(),
            fix: Some(
                "Run `git remote add origin <url>` (or `confidant init --create --remote <url>` \
                 on a new vault)"
                    .to_owned(),
            ),
        };
    }
    let named = remotes.join(", ");
    let entries = parse_git_remote_urls(&output);
    let cleartext: Vec<(&str, &'static str)> = entries
        .iter()
        .filter_map(|(name, url)| match remote_transport(url) {
            RemoteTransport::Cleartext(scheme) => Some((name.as_str(), scheme)),
            _ => None,
        })
        .collect();
    if let Some((name, scheme)) = cleartext.first() {
        return DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "git remote configured ({named}) over an unencrypted {scheme} transport; \
                 record bodies are readable in transit"
            ),
            fix: Some(format!(
                "Use an https:// or ssh:// URL, or remove the remote (`git remote remove {name}`)"
            )),
        };
    }
    let unverified: Vec<&str> = entries
        .iter()
        .filter(|(_, url)| remote_transport(url) == RemoteTransport::Unverified)
        .map(|(name, _)| name.as_str())
        .collect();
    if let Some(name) = unverified.first() {
        return DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "git remote configured ({named}) with a transport this check cannot verify; \
                 record bodies may be readable in transit"
            ),
            fix: Some(format!(
                "Use an https:// or ssh:// URL, or remove the remote (`git remote remove {name}`)"
            )),
        };
    }
    DoctorCheck {
        id: ID,
        status: "ok",
        message: format!("git remote configured ({named}); transport is encrypted or local"),
        fix: None,
    }
}

/// Ahead/behind counts from `git rev-list --left-right --count @{u}...HEAD`.
/// `ahead` counts commits only on HEAD; `behind` counts commits only on the
/// upstream. Both are from the last fetch (or push) — this helper never
/// touches the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AheadBehind {
    pub(crate) ahead: u64,
    pub(crate) behind: u64,
}

/// Refspec for `sync --push`: `HEAD:<upstream-branch>` on the remote that
/// was fetched. `upstream` is `rev-parse --abbrev-ref @{u}` (`origin/main`).
pub(crate) fn sync_push_refspec(remote: &str, upstream: &str) -> Option<String> {
    let prefix = format!("{remote}/");
    let branch = upstream.strip_prefix(&prefix)?;
    if branch.is_empty() {
        return None;
    }
    Some(format!("HEAD:{branch}"))
}

/// Parse `git rev-list --left-right --count @{u}...HEAD` output
/// (`<behind>\t<ahead>`). Returns `None` for anything unexpected.
pub(crate) fn parse_ahead_behind(output: &str) -> Option<AheadBehind> {
    let mut parts = output.split_whitespace();
    let behind = parts.next()?.parse().ok()?;
    let ahead = parts.next()?.parse().ok()?;
    Some(AheadBehind { ahead, behind })
}

/// Run the offline ahead/behind comparison. Callers resolve the upstream
/// first; a failure here is surfaced as a command error, never as a silent
/// zero.
pub(crate) fn git_ahead_behind(root: &Path, no_input: bool) -> anyhow::Result<AheadBehind> {
    let out = confidant_core::write::git(
        root,
        &["rev-list", "--left-right", "--count", "@{u}...HEAD"],
        no_input,
    )?;
    parse_ahead_behind(&out).ok_or_else(|| {
        anyhow::Error::new(DomainError::invalid(
            "could not parse the ahead/behind counts from git",
        ))
    })
}

/// Resolve the current branch and its upstream (e.g. `main` and
/// `origin/main`) without contacting a remote. `None` means "no upstream",
/// which is a valid local-only setup rather than a failure.
pub(crate) fn git_upstream(root: &Path, no_input: bool) -> Option<(String, String)> {
    let branch = confidant_core::write::git(root, &["rev-parse", "--abbrev-ref", "HEAD"], no_input)
        .ok()?
        .trim()
        .to_owned();
    let upstream = confidant_core::write::git(
        root,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        no_input,
    )
    .ok()?
    .trim()
    .to_owned();
    if branch.is_empty() || upstream.is_empty() || branch == "HEAD" {
        return None;
    }
    Some((branch, upstream))
}

/// #665: `local-commits` doctor check. Offline and advisory: it reports
/// ahead/behind from the **last fetch** and never calls fetch, pull, or
/// push. No remote, no upstream, or an unreadable comparison is `ok`; only
/// a real difference warns (a warning, never an error).
pub(crate) fn local_commits_check(root: &Path, no_input: bool) -> DoctorCheck {
    const ID: &str = "local-commits";
    let ok = |message: String, fix: Option<String>| DoctorCheck {
        id: ID,
        status: "ok",
        message,
        fix,
    };
    if !root.is_dir() {
        return ok("no vault to inspect for local commits".to_owned(), None);
    }
    let Some((_, upstream)) = git_upstream(root, no_input) else {
        // Distinguish "no remote at all" from "remote, no upstream branch":
        // the first is a valid local-only setup, the second needs one git
        // command. Neither is an error, and `git-remote` already carries the
        // add-a-remote instructions.
        let remotes = confidant_core::write::git(root, &["remote"], no_input)
            .map(|out| parse_git_remotes(&out))
            .unwrap_or_default();
        let branch =
            confidant_core::write::git(root, &["rev-parse", "--abbrev-ref", "HEAD"], no_input)
                .map(|out| out.trim().to_owned())
                .unwrap_or_else(|_| "HEAD".to_owned());
        if remotes.is_empty() {
            return ok(
                "local-only; no remote to compare local commits with".to_owned(),
                None,
            );
        }
        return ok(
            format!(
                "no upstream branch for '{branch}'; cannot compare local commits with {}",
                remotes.join(", ")
            ),
            Some(format!(
                "Set an upstream with `git push -u {} {branch}`",
                remotes[0]
            )),
        );
    };
    let state = match git_ahead_behind(root, no_input) {
        Ok(state) => state,
        Err(e) => {
            return ok(
                format!("could not compare with {upstream}: {e}"),
                Some("Run `git status` to check the repository".to_owned()),
            )
        }
    };
    match (state.ahead, state.behind) {
        (0, 0) => ok(
            format!("up to date with {upstream} (as of the last fetch)"),
            None,
        ),
        (ahead, 0) => DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "{ahead} local commit(s) not pushed to {upstream} (as of the last fetch)"
            ),
            fix: Some("Run `confidant sync --push`".to_owned()),
        },
        (0, behind) => DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "{upstream} has {behind} new commit(s) not local (as of the last fetch)"
            ),
            fix: Some("Run `confidant sync --pull`".to_owned()),
        },
        (ahead, behind) => DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "diverged from {upstream}: {ahead} local commit(s) not pushed, \
                 {behind} remote commit(s) not local (as of the last fetch)"
            ),
            fix: Some(
                "Merge or rebase the branch explicitly, then run `confidant sync`".to_owned(),
            ),
        },
    }
}

/// Doctor status vocabulary (#709): `ok` means the check ran and passed,
/// `warning` means it ran and found something to act on, `error` means
/// it ran and found something blocking, and `unknown` means it could
/// not run to a determination at all. `unknown` is warning-tier: it
/// never fails `doctor` (only `error` does, in `cmd_doctor`), but it
/// never renders `ok` either — an undetermined check is not a pass.
/// Callers branch on this status string, never on message text (ADR-7):
/// `unknown` is a stable fourth value, alongside the existing three.
pub(crate) const DOCTOR_STATUS_UNKNOWN: &str = "unknown";

pub(crate) fn collect_doctor_checks(cli: &Cli, root: &Path) -> Vec<DoctorCheck> {
    let mut checks: Vec<DoctorCheck> = Vec::new();

    checks.push(DoctorCheck {
        id: "vault-discovery",
        status: "ok",
        message: format!("vault resolved to {}", root.display()),
        fix: None,
    });
    checks.push(vault_access_check(root));

    // #809: detect the encrypted ≤0.7 vault shape before loading it. One
    // clear error beats a stream of parse and check findings, and the
    // normal `spec` / `check` checks cannot say anything useful about a
    // vault this binary has no reader for.
    let legacy_encrypted = confidant_core::vault::is_legacy_encrypted_vault(root);
    if legacy_encrypted {
        checks.push(legacy_encrypted_vault_check());
    }

    match require_git_repo(root, cli.no_input) {
        Ok(()) => checks.push(DoctorCheck {
            id: "git-repo",
            status: "ok",
            message: "vault is a git repository".to_owned(),
            fix: None,
        }),
        Err(_) => checks.push(DoctorCheck {
            id: "git-repo",
            status: "error",
            message: "vault is not a git repository; writes need git".to_owned(),
            fix: None,
        }),
    }

    let identity: Vec<String> = ["user.name", "user.email"]
        .iter()
        .map(|k| {
            confidant_core::write::git(root, &["config", "--get", k], cli.no_input)
                .map(|v| v.trim().to_owned())
                .unwrap_or_default()
        })
        .collect();
    if identity.iter().all(|v| !v.is_empty()) {
        checks.push(DoctorCheck {
            id: "git-identity",
            status: "ok",
            message: format!("git identity is {} <{}>", identity[0], identity[1]),
            fix: None,
        });
    } else {
        checks.push(DoctorCheck {
            id: "git-identity",
            status: "error",
            message: "git user.name / user.email are not configured; commits will fail".to_owned(),
            fix: None,
        });
    }

    // #174: minimum git version. Confidant shells out to git, so a very
    // old client is reported.
    checks.push(git_version_check());

    // #660: remote visibility. Read-only and offline.
    checks.push(git_remote_check(root, cli.no_input));

    // #665: ahead/behind visibility from the last fetch. Offline and
    // advisory: no remote/upstream stays `ok`, and a real difference warns.
    checks.push(local_commits_check(root, cli.no_input));

    if !legacy_encrypted {
        match load_vault(root) {
            Ok(vault) => {
                if confidant_core::SpecVersion::is_supported(&vault.config.spec) {
                    checks.push(DoctorCheck {
                        id: "spec",
                        status: "ok",
                        message: format!("vault spec {} supported", vault.config.spec),
                        fix: None,
                    });
                } else {
                    checks.push(DoctorCheck {
                        id: "spec",
                        status: "error",
                        message: format!("unsupported vault spec: {}", vault.config.spec),
                        fix: None,
                    });
                }
                let report = check_vault(&vault, &CheckOptions::default());
                if report.summary.errors > 0 {
                    checks.push(DoctorCheck {
                        id: "check",
                        status: "error",
                        message: format!(
                            "check reports {} error(s); writes are blocked until fixed",
                            report.summary.errors
                        ),
                        fix: None,
                    });
                } else if report.summary.warnings > 0 {
                    checks.push(DoctorCheck {
                        id: "check",
                        status: "warning",
                        message: format!("check reports {} warning(s)", report.summary.warnings),
                        fix: None,
                    });
                } else {
                    checks.push(DoctorCheck {
                        id: "check",
                        status: "ok",
                        message: "check is clean".to_owned(),
                        fix: None,
                    });
                }
            }
            Err(e) => checks.push(DoctorCheck {
                id: "vault-load",
                status: "error",
                message: format!("cannot load vault: {e}"),
                fix: None,
            }),
        }
    }

    // #165: staleness vs the latest GitHub Release. Warning-only: a stale
    // install is never an error, so exit-code semantics are unchanged. Any
    // network failure degrades to `unknown` "unknown" (#709, offline-first):
    // staleness is informational, so `doctor` must not punish offline users
    // — but an undetermined check is not a pass either.
    //
    // `CONFIDANT_OFFLINE=1` opts out entirely: the fetch is skipped before
    // any request is made and the check reports `ok` "disabled". See the
    // README Privacy section and docs/privacy.md for the disclosure.
    // Skills ship in the binary and are version-locked to it, so there is
    // no separate skills checkout to compare — `skills-links` below reports
    // link health instead.
    {
        let offline = staleness_offline();
        let latest = if offline { None } else { latest_release_tag() };
        checks.push(cli_staleness_check(
            latest,
            offline,
            staleness_update_hint(),
        ));
        checks.push(skills_links_check());
        // #727: skill links only reach sessions that load a skill; the
        // system-of-record rule belongs in the agent's always-on file.
        checks.push(system_of_record_check(Some(root)));
        // #659: the optional TUI must match the CLI's agent contract.
        checks.push(tui_version_check());
        // #386/#657: qmd search availability. Missing qmd is `ok`; an
        // installed qmd without a corpus warns and points at the skill.
        checks.push(qmd_search_check(root));
    }

    checks
}

/// Count the doctor statuses without letting an unknown status silently
/// disappear from the summary.
pub(crate) fn doctor_status_counts(checks: &[DoctorCheck]) -> [(&'static str, usize); 4] {
    [
        ("ok", checks.iter().filter(|c| c.status == "ok").count()),
        (
            "warning",
            checks.iter().filter(|c| c.status == "warning").count(),
        ),
        (
            "error",
            checks.iter().filter(|c| c.status == "error").count(),
        ),
        (
            "unknown",
            checks
                .iter()
                .filter(|c| c.status == DOCTOR_STATUS_UNKNOWN)
                .count(),
        ),
    ]
}

pub(crate) fn cmd_doctor(cli: &Cli, root: &Path) -> anyhow::Result<ExitCode> {
    let checks = collect_doctor_checks(cli, root);
    let ok = !checks.iter().any(|c| c.status == "error");
    let counts = doctor_status_counts(&checks);
    if cli.json {
        let items: Vec<serde_json::Value> = checks
            .iter()
            .map(|c| {
                let mut item = serde_json::json!({
                    "id": c.id,
                    "status": c.status,
                    "message": c.message,
                });
                // `fix` only when there is one: the field stays absent on
                // healthy checks, matching the ADR-7 error envelope.
                if let Some(fix) = &c.fix {
                    item["fix"] = serde_json::Value::String(fix.clone());
                }
                item
            })
            .collect();
        let mut extra = serde_json::Map::new();
        extra.insert("checks".to_owned(), serde_json::Value::Array(items));
        extra.insert(
            "summary".to_owned(),
            serde_json::json!({
                "ok": counts[0].1,
                "warning": counts[1].1,
                "error": counts[2].1,
                "unknown": counts[3].1,
            }),
        );
        let mut envelope = ok_envelope(Some(root), serde_json::Value::Object(extra));
        envelope["ok"] = serde_json::Value::Bool(ok);
        print_json(&envelope)?;
    } else {
        for c in &checks {
            println!("{:7} {}: {}", c.status, c.id, c.message);
            if let Some(fix) = &c.fix {
                println!("        fix: {fix}");
            }
        }
        println!();
        println!(
            "Summary: {} ok, {} warning, {} error, {} unknown",
            counts[0].1, counts[1].1, counts[2].1, counts[3].1
        );
        println!("Full readiness rollup: confidant status");
    }
    if ok {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

/// `vault-access` reports what the permission bits say without attempting a
/// write (`status` and `doctor` are read-only). A false `ok` would be worse
/// than the honest caveat in the message.
pub(crate) fn vault_access_check(root: &Path) -> DoctorCheck {
    const ID: &str = "vault-access";
    match std::fs::metadata(root) {
        Ok(meta) if !meta.is_dir() => DoctorCheck {
            id: ID,
            status: "error",
            message: "vault path is not a directory".to_owned(),
            fix: None,
        },
        Ok(meta) if meta.permissions().readonly() => DoctorCheck {
            id: ID,
            status: "warning",
            message: "vault directory has no write permission; reads work, writes will fail"
                .to_owned(),
            fix: Some("Make the vault directory writable by this user".to_owned()),
        },
        Ok(_) => DoctorCheck {
            id: ID,
            status: "ok",
            message:
                "vault directory is readable and writable (permission bits; no write was attempted)"
                    .to_owned(),
            fix: None,
        },
        Err(err) => DoctorCheck {
            id: ID,
            status: "error",
            message: format!("cannot inspect the vault directory: {err}"),
            fix: None,
        },
    }
}

/// #727: is the system-of-record rule present in every detected agent's
/// always-on file, and does it point at this vault? Missing or stale is a
/// warning (setup fixes it); never an error, because a hand-written vault
/// and a host with no agent are both valid.
pub(crate) fn system_of_record_check(root: Option<&Path>) -> DoctorCheck {
    const ID: &str = "system-of-record";
    let home = match setup::home_dir() {
        Ok(home) => home,
        Err(err) => {
            return DoctorCheck {
                id: ID,
                status: "warning",
                message: format!("cannot determine home directory: {err:#}"),
                fix: None,
            };
        }
    };
    let health = setup::system_of_record_health(&home, root);
    if health.is_empty() {
        return DoctorCheck {
            id: ID,
            status: "ok",
            message: "no agents detected; run `confidant setup --agent auto` when one is installed"
                .to_owned(),
            fix: None,
        };
    }
    let fix = root
        .map(|root| {
            format!(
                "Run `confidant setup --agent auto --vault {}` to install or refresh the rule",
                root.display()
            )
        })
        .unwrap_or_else(|| {
            "Run `confidant setup --agent auto --vault <path>` to install or refresh the rule"
                .to_owned()
        });
    let missing: Vec<&setup::InstructionHealth> = health.iter().filter(|h| !h.installed).collect();
    if !missing.is_empty() {
        let paths: Vec<String> = missing
            .iter()
            .map(|h| format!("{} ({})", h.agent, h.path.display()))
            .collect();
        return DoctorCheck {
            id: ID,
            status: "warning",
            message: format!("system-of-record rule missing for {}", paths.join(", ")),
            fix: Some(fix),
        };
    }
    let stale: Vec<&setup::InstructionHealth> = health
        .iter()
        .filter(|h| h.installed && !h.matches_vault)
        .collect();
    if !stale.is_empty() {
        let paths: Vec<String> = stale
            .iter()
            .map(|h| {
                format!(
                    "{} ({}, points at {})",
                    h.agent,
                    h.path.display(),
                    h.pointer.as_deref().unwrap_or("no vault")
                )
            })
            .collect();
        return DoctorCheck {
            id: ID,
            status: "warning",
            message: format!(
                "system-of-record rule points at another vault for {}",
                paths.join(", ")
            ),
            fix: Some(fix),
        };
    }
    DoctorCheck {
        id: ID,
        status: "ok",
        message: format!(
            "system-of-record rule installed for {}",
            health
                .iter()
                .map(|h| h.agent.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        fix: None,
    }
}
