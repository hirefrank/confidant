//! `update`: replace the binary and re-link skills.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::doctor::{
    latest_release_tag, parse_release_version, staleness_offline, STALENESS_DISABLED,
    STALENESS_UNKNOWN,
};
use crate::commands::install::{
    confirm_yn, detect_install_method, normalized_path, offer_exe_path, offerable_update,
    run_offered_command, InstallMethod, DIST_INSTALLER_ONELINER,
};
use crate::commands::setup::setup_result_json;
use crate::{ok_envelope, print_json, setup, Cli, FixExt};
use confidant_core::error::{DomainError, ErrorKind};
use serde_json::Value;

pub(crate) fn cmd_update(
    cli: &Cli,
    agent: &str,
    force: bool,
    verbose: bool,
) -> anyhow::Result<ExitCode> {
    // `update` reports the latest release, offers to run the matching
    // upgrade command (#376), self-replaces a cargo-dist install (#876),
    // and re-links skills from this binary.
    // Honor CONFIDANT_OFFLINE=1 like `doctor` (no network at all).
    let offline = staleness_offline();
    let exe = offer_exe_path();
    let detection = detect_install_method(&exe);
    // #876: a receipt on disk that names a different copy must never drive a
    // self-replacement (the two-copies-on-PATH failure mode). Fail loudly
    // before any network call instead of silently updating the wrong one.
    if let Some(stray) = &detection.stray_receipt {
        return Err(anyhow::Error::new(DomainError::conflict(format!(
            "a cargo-dist install receipt at {} names {}, but this binary is {}; refusing to update either copy",
            stray.path.display(),
            stray.install_prefix.display(),
            exe.display(),
        )))
        .with_fix(
            "Run the copy the receipt names, or remove the stale receipt and reinstall with the one-liner",
        ));
    }
    let method = detection.method;
    let latest = if offline { None } else { latest_release_tag() };
    let local = env!("CARGO_PKG_VERSION");
    // Behind-ness is computed once and shared by the human and JSON paths.
    // `None` when the check is disabled or the release couldn't be fetched.
    let behind: Option<bool> = latest.as_deref().and_then(|tag| {
        parse_release_version(local)
            .zip(parse_release_version(tag))
            .map(|(l, r)| l < r)
    });
    // The generic wording is the fallback for installs we cannot name.
    let upgrade_cmd = match method.update_command() {
        Some(cmd) => format!("update with `{cmd}`, then re-run `confidant setup`."),
        None => "update the binary first (re-run the installer or `cargo install confidant-cli`), then re-run `confidant setup`.".to_owned(),
    };
    // Whether this install can be replaced in place, and whether this run
    // would do it. `--json` is inspect-only (#376), so it never self-updates.
    let self_update = if !method.self_updates() {
        "unavailable"
    } else if offline {
        "disabled"
    } else {
        match behind {
            Some(true) => "available",
            Some(false) => "current",
            None => "unknown",
        }
    };
    if cli.json {
        // The JSON path never prompts and never runs anything (#376); the
        // new fields are additive.
        let mut update_info = match &latest {
            None if offline => {
                serde_json::json!({"status": "disabled", "message": STALENESS_DISABLED, "behind": Value::Null})
            }
            None => {
                serde_json::json!({"status": "unknown", "message": STALENESS_UNKNOWN, "behind": Value::Null})
            }
            Some(tag) if behind.is_some() => {
                serde_json::json!({"status": "fetched", "latest": tag, "local": local, "behind": behind})
            }
            Some(tag) => {
                serde_json::json!({"status": "unknown", "latest": tag, "local": local, "behind": Value::Null})
            }
        };
        if let Value::Object(ref mut obj) = update_info {
            obj.insert(
                "install_method".to_owned(),
                Value::String(method.as_str().to_owned()),
            );
            obj.insert(
                "update_command".to_owned(),
                method
                    .update_command()
                    .map(|c| Value::String(c.to_owned()))
                    .unwrap_or(Value::Null),
            );
            obj.insert(
                "self_update".to_owned(),
                Value::String(self_update.to_owned()),
            );
        }
        if behind == Some(true) {
            // Never re-link from a behind binary: the installed skills would
            // be stale on arrival. Tell the operator how to upgrade instead.
            let value = serde_json::json!({
                "update": update_info,
                "message": format!("confidant {local} is behind; {upgrade_cmd}"),
            });
            print_json(&ok_envelope(None, value))?;
            return Ok(ExitCode::SUCCESS);
        }
        let result = setup::run_setup(agent, force, false, cli.dry_run)?;
        let mut value = setup_result_json(&result, None, "", false);
        if let Value::Object(ref mut obj) = value {
            obj.insert("update".to_owned(), update_info);
        }
        print_json(&ok_envelope(None, value))?;
        return Ok(ExitCode::SUCCESS);
    }
    if offline {
        println!("{STALENESS_DISABLED}");
    } else {
        match &latest {
            None => println!("{STALENESS_UNKNOWN}"),
            Some(tag) => {
                if behind == Some(true) {
                    // Never re-link from a behind binary: the installed
                    // skills would be stale on arrival.
                    if let InstallMethod::CargoDist { install_prefix } = &method {
                        // A cargo-dist install replaces itself (#876): the
                        // operating system swap is the update, so no y/N
                        // offer is needed. `--dry-run` only reports (#668).
                        // Native Windows cannot overwrite a running exe, and
                        // is unsupported anyway (#502): print the one-liner.
                        if cli.dry_run {
                            println!("confidant {local} is behind the latest release {tag}; would self-update in place, then re-run `confidant setup`.");
                        } else if cfg!(windows) {
                            println!("confidant {local} is behind the latest release {tag}; run `{DIST_INSTALLER_ONELINER}`, then re-run `confidant setup`.");
                        } else {
                            println!("confidant {local} is behind the latest release {tag}; updating in place…");
                            let new_version = self_update_cargo_dist(install_prefix, &exe, tag)?;
                            println!(
                                "updated to {new_version}. Run `confidant setup` to re-link skills from the new binary."
                            );
                        }
                        return Ok(ExitCode::SUCCESS);
                    }
                    // Print the single command that fits this install; in an
                    // interactive terminal, offer to run it (default No).
                    // `--dry-run` prints the command and never offers or
                    // runs it (#668).
                    if let (Some(cmd), Some((program, args))) =
                        (method.update_command(), method.run_spec())
                    {
                        if cli.dry_run {
                            println!("confidant {local} is behind the latest release {tag}; would run `{cmd}`, then re-run `confidant setup`.");
                        } else {
                            println!("confidant {local} is behind the latest release {tag}; run `{cmd}`, then re-run `confidant setup`.");
                            if offerable_update(&method, true)
                                && confirm_yn(&format!("run `{cmd}` now?"), cli.no_input, cli.json)?
                            {
                                match run_offered_command(cmd, program, args) {
                                    Ok(()) => {
                                        println!("updated via `{cmd}`.");
                                        if confirm_yn(
                                            "run `confidant setup` now?",
                                            cli.no_input,
                                            cli.json,
                                        )? {
                                            return relink_after_update(
                                                agent,
                                                force,
                                                verbose,
                                                cli.dry_run,
                                            );
                                        }
                                    }
                                    Err(err) => eprintln!("update failed: {err:#}"),
                                }
                            }
                        }
                    } else {
                        println!(
                            "confidant {local} is behind the latest release {tag}; {upgrade_cmd}"
                        );
                    }
                    return Ok(ExitCode::SUCCESS);
                }
                let version_status = if behind == Some(false) {
                    format!("confidant {local} is current (latest: {tag})")
                } else {
                    format!("cannot compare confidant {local} with release tag {tag}")
                };
                if cli.dry_run {
                    println!("{version_status}. Would re-link skills from this binary…");
                } else {
                    println!("{version_status}. Re-linking skills from this binary…");
                }
            }
        }
    }
    relink_after_update(agent, force, verbose, cli.dry_run)
}

/// A typed, expected update failure (ADR-7): exit 1 with a stable code, not
/// `internal_error`. The fix names the one-liner, which always works.
pub(crate) fn update_failed(detail: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(DomainError::new(ErrorKind::UpdateFailed, detail)).with_fix(
        "Re-run the installer: curl --proto '=https' --tlsv1.2 -LsSf \
         https://github.com/hirefrank/confidant/releases/latest/download/confidant-cli-installer.sh | sh",
    )
}

/// Release-asset download base (everything before the tag). Integration
/// tests point this at a local stub so no test touches GitHub.
pub(crate) fn release_download_base() -> String {
    #[cfg(feature = "test-overrides")]
    if let Ok(base) = std::env::var("CONFIDANT_TEST_RELEASE_DOWNLOAD_URL") {
        return base;
    }
    "https://github.com/hirefrank/confidant/releases/download".to_owned()
}

/// The release archive for the platform this binary was built for, matching
/// `dist-workspace.toml`'s targets. `None` on anything else: self-update
/// refuses with a typed error whose fix is the one-liner, rather than
/// guessing at an archive name.
pub(crate) fn release_target_archive() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("confidant-cli-x86_64-unknown-linux-gnu.tar.xz")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("confidant-cli-aarch64-apple-darwin.tar.xz")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("confidant-cli-x86_64-apple-darwin.tar.xz")
    } else {
        None
    }
}

/// Lowercase hex SHA-256. `sha2` is already in the dependency graph (the
/// vault's content hash uses it); this reuses it instead of pulling a
/// checksum crate for one call.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Parse a cargo-dist `sha256.sum` into `(asset name, lowercase hex)`.
/// Handles both `<hex> *<name>` (GNU binary marker) and `<hex>  <name>`;
/// malformed lines are skipped, never trusted.
pub(crate) fn parse_sha256_sum(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let hash = parts.next()?;
            let name = parts.next()?;
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            Some((
                name.trim_start_matches('*').to_owned(),
                hash.to_ascii_lowercase(),
            ))
        })
        .collect()
}

/// The archive checksums a cargo-dist installer embeds
/// (`_checksum_value="<hex>"`); every one is verified by the installer
/// itself before it installs anything.
pub(crate) fn installer_embedded_checksums(script: &str) -> Vec<String> {
    const MARKER: &str = "_checksum_value=\"";
    script
        .match_indices(MARKER)
        .filter_map(|(start, marker)| {
            let rest = &script[start + marker.len()..];
            let end = rest.find('"')?;
            let value = &rest[..end];
            (value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()))
                .then(|| value.to_ascii_lowercase())
        })
        .collect()
}

/// Verify the downloaded release installer before running it (#876).
///
/// cargo-dist 0.32 publishes `sha256.sum` with an entry per archive and per
/// source tarball, but **no entry for the installer script itself** (checked
/// against the v0.8.0 assets and the release's `dist-manifest.json`). So:
///
/// - If a future release does publish an installer line, verify the script's
///   SHA-256 against it (the strongest check).
/// - Otherwise require that every archive checksum the installer embeds is
///   present in `sha256.sum`, and that this platform's archive is covered.
///   The installer then re-verifies that archive before installing it, the
///   same chain the published one-liner uses — but a script whose embedded
///   hashes disagree with the release checksums is refused here, unrun.
pub(crate) fn verify_installer(
    tag: &str,
    installer: &[u8],
    sums: &[(String, String)],
    archive: &str,
) -> anyhow::Result<()> {
    const INSTALLER_NAME: &str = "confidant-cli-installer.sh";
    let installer_sha = sha256_hex(installer);
    if let Some((_, expected)) = sums.iter().find(|(name, _)| name == INSTALLER_NAME) {
        if !installer_sha.eq_ignore_ascii_case(expected) {
            return Err(update_failed(format!(
                "the release installer for {tag} does not match sha256.sum \
                 (expected {expected}, got {installer_sha}); refusing to run it"
            )));
        }
        return Ok(());
    }

    let Some((_, expected)) = sums.iter().find(|(name, _)| name == archive) else {
        return Err(update_failed(format!(
            "the release checksums for {tag} do not cover {archive}; refusing to run the installer"
        )));
    };
    let script = String::from_utf8_lossy(installer);
    let embedded = installer_embedded_checksums(&script);
    if embedded.is_empty() {
        return Err(update_failed(format!(
            "the release installer for {tag} embeds no archive checksums; refusing to run it"
        )));
    }
    let known: BTreeSet<&str> = sums.iter().map(|(_, hash)| hash.as_str()).collect();
    if let Some(unknown) = embedded.iter().find(|hash| !known.contains(hash.as_str())) {
        return Err(update_failed(format!(
            "the release installer for {tag} embeds checksum {unknown}, which is not in \
             sha256.sum; refusing to run it"
        )));
    }
    if !embedded.iter().any(|hash| hash == expected) {
        return Err(update_failed(format!(
            "the release installer for {tag} does not embed the checksum for {archive}; \
             refusing to run it"
        )));
    }
    Ok(())
}

/// Download a release asset. Fails closed with an actionable code; the body
/// is never echoed beyond the URL and the HTTP error.
pub(crate) fn fetch_release_bytes(url: &str) -> anyhow::Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(60)))
        .build()
        .into();
    let mut response = agent
        .get(url)
        .header("User-Agent", "confidant-cli")
        .header("Accept", "application/octet-stream")
        .call()
        .map_err(|err| update_failed(format!("could not download {url}: {err}")))?;
    response
        .body_mut()
        .read_to_vec()
        .map_err(|err| update_failed(format!("could not read {url}: {err}")))
}

/// Write the verified installer to a temp file and run it with the receipt's
/// install prefix pinned, so it replaces this copy even when the caller's
/// environment points elsewhere. The installer verifies the platform
/// archive's checksum itself before installing it.
pub(crate) fn run_release_installer(installer: &[u8], install_prefix: &Path) -> anyhow::Result<()> {
    let dir = tempfile::tempdir().map_err(|err| {
        update_failed(format!(
            "could not create a temp dir for the installer: {err}"
        ))
    })?;
    let script = dir.path().join("confidant-cli-installer.sh");
    std::fs::write(&script, installer)
        .map_err(|err| update_failed(format!("could not write the installer: {err}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).map_err(
            |err| update_failed(format!("could not make the installer executable: {err}")),
        )?;
    }
    // Integration-test hook: record the run instead of executing a real
    // installer, and reuse the same failure switch as the #376 offer path.
    // The suite never executes a downloaded installer: a test that forgot
    // the recorder gets a clear failure instead of running a script.
    #[cfg(feature = "test-overrides")]
    {
        let display = format!(
            "sh {} (CONFIDANT_CLI_INSTALL_DIR={})",
            script.display(),
            install_prefix.display()
        );
        if let Ok(path) = std::env::var("CONFIDANT_TEST_COMMAND_RECORDER") {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            writeln!(f, "{display}")?;
            if std::env::var("CONFIDANT_TEST_COMMAND_FAIL").is_ok() {
                return Err(update_failed("simulated installer failure"));
            }
            return Ok(());
        }
        Err(update_failed(
            "refusing to run an installer under test-overrides without a command recorder",
        ))
    }
    #[cfg(not(feature = "test-overrides"))]
    {
        let status = std::process::Command::new("sh")
            .arg(&script)
            .env("CONFIDANT_CLI_INSTALL_DIR", install_prefix)
            .env("CARGO_DIST_FORCE_INSTALL_DIR", install_prefix)
            .status()
            .map_err(|err| update_failed(format!("could not run the release installer: {err}")))?;
        if !status.success() {
            return Err(update_failed(format!(
                "the release installer exited with status {status}"
            )));
        }
        Ok(())
    }
}

/// The installer treats its forced directory as a Cargo home and appends
/// `/bin`. Older receipts can name that bin directory instead of its root.
/// Require an exact match with the running binary before choosing the root.
pub(crate) fn cargo_dist_install_root(install_prefix: &Path, exe: &Path) -> Option<PathBuf> {
    let bin = exe.parent()?;
    if normalized_path(bin) == normalized_path(&install_prefix.join("bin")) {
        return Some(install_prefix.to_path_buf());
    }
    if bin.file_name().is_some_and(|name| name == "bin")
        && normalized_path(bin) == normalized_path(install_prefix)
    {
        return bin.parent().map(Path::to_path_buf);
    }
    None
}

/// Replace a cargo-dist install in place (#876) without an updater
/// framework: fetch the release's `sha256.sum` and installer, verify the
/// installer against those checksums, then run it with the receipt prefix
/// pinned. The installer verifies the platform archive before installing it,
/// so the binary that lands is the one the release checksums cover.
pub(crate) fn self_update_cargo_dist(
    install_prefix: &Path,
    exe: &Path,
    tag: &str,
) -> anyhow::Result<String> {
    let install_root = cargo_dist_install_root(install_prefix, exe).ok_or_else(|| {
        update_failed(format!(
            "the install receipt prefix {} does not match the running binary {}; refusing to install into a different directory",
            install_prefix.display(),
            exe.display(),
        ))
    })?;
    let base = release_download_base();
    let archive = release_target_archive().ok_or_else(|| {
        update_failed(format!(
            "no self-update archive is published for {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
    })?;
    let sums_body = fetch_release_bytes(&format!("{base}/{tag}/sha256.sum"))?;
    let sums = parse_sha256_sum(&String::from_utf8_lossy(&sums_body));
    let installer = fetch_release_bytes(&format!("{base}/{tag}/confidant-cli-installer.sh"))?;
    verify_installer(tag, &installer, &sums, archive)?;
    run_release_installer(&installer, &install_root)?;
    // The installer installed the release the tag names; report that tag
    // without its `v` so it reads like `confidant --version`.
    Ok(tag.trim_start_matches('v').to_owned())
}

/// Shared tail of `update`: re-link skills from this binary and report.
/// `force` is the operator's own flag: owned entries are re-pointed
/// regardless, unowned entries need it. `dry_run` (#668) plans the relink
/// and writes nothing.
pub(crate) fn relink_after_update(
    agent: &str,
    force: bool,
    verbose: bool,
    dry_run: bool,
) -> anyhow::Result<ExitCode> {
    let result = setup::run_setup(agent, force, false, dry_run)?;
    if verbose {
        for line in &result.verbose_lines {
            println!("{line}");
        }
    }
    for unknown in &result.unknown_agents {
        eprintln!("warning: unknown agent '{unknown}' — skipped");
    }
    if dry_run {
        println!(
            "would re-link {} skills → {}",
            result.linked_count(),
            result.agent_labels().join(", ")
        );
    } else {
        println!(
            "re-linked {} skills → {}",
            result.linked_count(),
            result.agent_labels().join(", ")
        );
    }
    if !result.removed_stale.is_empty() {
        println!(
            "{} {} stale skill link(s)",
            if dry_run { "would remove" } else { "removed" },
            result.removed_stale.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}
