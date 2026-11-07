//! Install-method detection and the interactive confirmation helper.

#[cfg(not(feature = "test-overrides"))]
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::setup;
use serde_json::Value;
use std::io::Write;

/// The app name cargo-dist uses for Confidant: the package name. It names
/// the release assets (`confidant-cli-installer.sh`) and the receipt
/// directory/file (`<config>/confidant-cli/confidant-cli-receipt.json`).
pub(crate) const DIST_APP_NAME: &str = "confidant-cli";

/// The published one-liner. For a cargo-dist install it is also the update
/// command: re-running it installs the latest release over the old copy.
pub(crate) const DIST_INSTALLER_ONELINER: &str = "curl --proto '=https' --tlsv1.2 -LsSf \
     https://github.com/hirefrank/confidant/releases/latest/download/confidant-cli-installer.sh | sh";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InstallMethod {
    /// A cargo-dist install (the one-liner / release installer), identified
    /// by the receipt that installer writes (#876). The receipt's install
    /// prefix is captured so `update` can refuse the wrong-copy case.
    CargoDist {
        install_prefix: PathBuf,
    },
    /// A Homebrew formula install (`brew upgrade confidant-cli`).
    Brew,
    /// The binary lives in `<cargo-home>/bin`, installed with
    /// `cargo install confidant-cli`.
    CargoInstall,
    Unknown,
}

impl InstallMethod {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            InstallMethod::CargoDist { .. } => "cargo-dist",
            InstallMethod::Brew => "brew",
            InstallMethod::CargoInstall => "cargo-install",
            InstallMethod::Unknown => "unknown",
        }
    }

    /// The single update command to print for this method, or `None` when
    /// the method is unknown (the caller prints the generic wording).
    pub(crate) fn update_command(&self) -> Option<&'static str> {
        match self {
            InstallMethod::CargoDist { .. } => Some(DIST_INSTALLER_ONELINER),
            InstallMethod::Brew => Some("brew upgrade confidant-cli"),
            InstallMethod::CargoInstall => Some("cargo install confidant-cli"),
            InstallMethod::Unknown => None,
        }
    }

    /// Program + argv to run when the operator confirms the offer. Only
    /// `cargo install` is offered: a cargo-dist install self-replaces from
    /// its verified release installer (#876), and brew must never be
    /// replaced by hand.
    pub(crate) fn run_spec(&self) -> Option<(&'static std::ffi::OsStr, &'static [&'static str])> {
        match self {
            InstallMethod::CargoInstall => {
                Some((std::ffi::OsStr::new("cargo"), &["install", "confidant-cli"]))
            }
            InstallMethod::CargoDist { .. } | InstallMethod::Brew | InstallMethod::Unknown => None,
        }
    }

    /// Whether `confidant update` can replace this install in place.
    pub(crate) fn self_updates(&self) -> bool {
        matches!(self, InstallMethod::CargoDist { .. })
    }
}

/// A cargo-dist install receipt, reduced to what detection and the
/// wrong-copy guard need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstallReceipt {
    /// Where the receipt was found (for the wrong-copy message).
    pub(crate) path: PathBuf,
    /// The prefix the installer wrote to (`install_prefix` in the receipt).
    pub(crate) install_prefix: PathBuf,
}

/// Result of install-method detection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InstallDetection {
    pub(crate) method: InstallMethod,
    /// Set when a cargo-dist receipt exists but its install prefix does not
    /// contain the running binary: two copies on disk, so trusting the
    /// receipt could replace the wrong one (#876). `update` refuses loudly;
    /// every other caller falls back to the generic wording.
    pub(crate) stray_receipt: Option<InstallReceipt>,
}

/// Candidate receipt directories, mirroring the cargo-dist installer's
/// search: `$XDG_CONFIG_HOME` first, then the platform default
/// (`%LOCALAPPDATA%` on Windows, `~/.config` elsewhere). Windows is not a
/// supported target (#502), but detection stays in parity with the
/// installer so a WSL2-adjacent native run still reads its own receipt.
pub(crate) fn receipt_config_roots(
    xdg_config_home: Option<PathBuf>,
    local_app_data: Option<PathBuf>,
    home: Option<PathBuf>,
    windows: bool,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(xdg) = xdg_config_home.filter(|p| !p.as_os_str().is_empty()) {
        roots.push(xdg.join(DIST_APP_NAME));
    }
    if windows {
        if let Some(local) = local_app_data.filter(|p| !p.as_os_str().is_empty()) {
            roots.push(local.join(DIST_APP_NAME));
        }
    } else if let Some(home) = home.filter(|p| !p.as_os_str().is_empty()) {
        roots.push(home.join(".config").join(DIST_APP_NAME));
    }
    roots
}

/// The first existing install receipt, in the same order the installer
/// looks. `None` when no receipt exists (a `cargo install`, brew, or
/// distro-package install).
pub(crate) fn install_receipt_path() -> Option<PathBuf> {
    // Integration-test hook: point detection at a known receipt (or at a
    // path that does not exist) without touching the real config dir.
    #[cfg(feature = "test-overrides")]
    if let Ok(path) = std::env::var("CONFIDANT_TEST_RECEIPT_PATH") {
        return Some(PathBuf::from(path));
    }
    receipt_config_roots(
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
        setup::home_dir().ok(),
        cfg!(windows),
    )
    .into_iter()
    .map(|root| root.join(format!("{DIST_APP_NAME}-receipt.json")))
    .find(|path| path.is_file())
}

/// Parse a cargo-dist install receipt. A missing, unreadable, or malformed
/// receipt is `None`: detection then falls back to the binary path, never to
/// a guess about a partial file.
pub(crate) fn read_install_receipt(path: &Path) -> Option<InstallReceipt> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let install_prefix = value.get("install_prefix")?.as_str()?;
    if install_prefix.is_empty() {
        return None;
    }
    Some(InstallReceipt {
        path: path.to_path_buf(),
        install_prefix: PathBuf::from(install_prefix),
    })
}

/// Normalize a path for the receipt comparison: forward slashes, no trailing
/// separator. Windows-style input stays comparable on every platform, the
/// same trick the existing path-based detection uses.
pub(crate) fn normalized_path(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('\\', "/");
    if normalized.len() > 1 {
        normalized.trim_end_matches('/').to_owned()
    } else {
        normalized
    }
}

/// Whether the receipt's install prefix would have put the binary at
/// `exe_path`. The receipt may name either the prefix root (`~/.cargo`) or
/// its `bin` dir (`~/.cargo/bin`, cargo-dist wrote that shape for a while);
/// both contain the running binary.
pub(crate) fn receipt_contains_exe(install_prefix: &Path, exe_path: &Path) -> bool {
    let prefix = normalized_path(install_prefix);
    let exe = normalized_path(exe_path);
    if prefix.is_empty() || exe.is_empty() {
        return false;
    }
    exe == prefix || exe.starts_with(&format!("{prefix}/"))
}

/// Detect the install method from the running binary and any cargo-dist
/// install receipt (#376, #876). The path is injected so detection is
/// unit-testable; production passes `std::env::current_exe()`.
pub(crate) fn detect_install_method(exe_path: &Path) -> InstallDetection {
    let receipt = install_receipt_path().and_then(|path| read_install_receipt(&path));
    detect_install_with_receipt(exe_path, receipt)
}

pub(crate) fn detect_install_with_receipt(
    exe_path: &Path,
    receipt: Option<InstallReceipt>,
) -> InstallDetection {
    if let Some(receipt) = receipt {
        if receipt_contains_exe(&receipt.install_prefix, exe_path) {
            return InstallDetection {
                method: InstallMethod::CargoDist {
                    install_prefix: receipt.install_prefix,
                },
                stray_receipt: None,
            };
        }
        // Wrong-copy case (#876): the receipt describes a different copy
        // (for example a one-liner install in `~/.local/bin` while this
        // binary came from a package manager, or the reverse). Never trust
        // it and never fall through to a path-based guess that could
        // replace the wrong copy: report Unknown here, and let `update`
        // turn it into a loud E_CONFLICT.
        return InstallDetection {
            method: InstallMethod::Unknown,
            stray_receipt: Some(receipt),
        };
    }
    InstallDetection {
        method: detect_install_method_from_path(exe_path),
        stray_receipt: None,
    }
}

/// Path-only detection, used when no receipt is present.
pub(crate) fn detect_install_method_from_path(exe_path: &Path) -> InstallMethod {
    // Normalize separators so Windows-style paths stay detectable on any
    // platform (unit tests run on Linux/macOS/Windows alike).
    let normalized = normalized_path(exe_path);
    // `cargo install` (and a cargo-dist install without a receipt) puts the
    // binary in `<cargo-home>/bin`.
    if normalized.contains("/.cargo/bin/") {
        return InstallMethod::CargoInstall;
    }
    // Homebrew: the Cellar for versioned kegs, or any homebrew prefix.
    if normalized.contains("/Cellar/") || normalized.contains("/homebrew/") {
        return InstallMethod::Brew;
    }
    InstallMethod::Unknown
}

/// The update command to show in the `doctor`/`status` staleness nudge, or
/// `None` to keep the generic `cargo install` fallback.
pub(crate) fn staleness_update_hint() -> Option<&'static str> {
    detect_install_method(&offer_exe_path())
        .method
        .update_command()
}

/// The binary path the update/check offers reason about. Under
/// `test-overrides`, `CONFIDANT_TEST_EXE_PATH` overrides
/// `std::env::current_exe()` so integration tests can force a known
/// install method (the real test binary is not under `.cargo/bin`).
pub(crate) fn offer_exe_path() -> PathBuf {
    #[cfg(feature = "test-overrides")]
    if let Ok(p) = std::env::var("CONFIDANT_TEST_EXE_PATH") {
        return PathBuf::from(p);
    }
    std::env::current_exe().unwrap_or_default()
}

/// Whether `update` may offer to run the update command itself (#376): the
/// install method must be known and replacing the running binary must be
/// safe. `self_replace_safe` is injected for tests; production passes `true`
/// (unix always allows overwriting the running binary).
pub(crate) fn offerable_update(method: &InstallMethod, self_replace_safe: bool) -> bool {
    method.run_spec().is_some() && self_replace_safe
}

#[cfg(feature = "test-overrides")]
pub(crate) static TEST_PROMPT_ANSWER_IDX: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Next scripted answer from `CONFIDANT_TEST_PROMPT_ANSWERS`
/// (newline-separated, consumed in prompt order), or `None` when the hook
/// is unset or exhausted.
#[cfg(feature = "test-overrides")]
pub(crate) fn test_prompt_answer() -> Option<String> {
    let list = std::env::var("CONFIDANT_TEST_PROMPT_ANSWERS").ok()?;
    let idx = TEST_PROMPT_ANSWER_IDX.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    list.split('\n').nth(idx).map(str::to_owned)
}

/// Shared y/N prompt for the `update` and `setup` offers (#376). Matches
/// the `prompt_fallback_inbox` style: stderr, `[y/N]`, default No — only an
/// explicit `y`/`yes` confirms, EOF fails closed.
///
/// Never prompts (returns `false`) when the session is non-interactive: no
/// TTY on stdin, `--no-input`, or `--json`. Nothing is ever run without an
/// explicit confirmation.
pub(crate) fn confirm_yn(question: &str, no_input: bool, json: bool) -> anyhow::Result<bool> {
    #[cfg(feature = "test-overrides")]
    let interactive = std::env::var("CONFIDANT_TEST_FORCE_INTERACTIVE").is_ok();
    #[cfg(not(feature = "test-overrides"))]
    let interactive = std::io::stdin().is_terminal();
    if !interactive || no_input || json {
        return Ok(false);
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    // Integration-test hook: piped stdin is never a TTY, so tests supply
    // answers (one per line, in prompt order) instead of typing. Unset =
    // read stdin as usual (a closed pipe reads EOF and fails closed).
    #[cfg(feature = "test-overrides")]
    if let Some(answer) = test_prompt_answer() {
        let answer = answer.trim();
        return Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"));
    }
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes"))
}

/// Runs a command the operator explicitly confirmed (#376). Production
/// spawns it and reports a non-zero exit as an error. Under
/// `test-overrides`, `CONFIDANT_TEST_COMMAND_RECORDER` names a file the
/// rendered command is appended to instead of executing — tests never run
/// a real install or a real `check`. `CONFIDANT_TEST_COMMAND_FAIL=1`
/// simulates a failure after recording.
pub(crate) fn run_offered_command(
    display: &str,
    program: &std::ffi::OsStr,
    args: &[&str],
) -> anyhow::Result<()> {
    #[cfg(feature = "test-overrides")]
    if let Ok(path) = std::env::var("CONFIDANT_TEST_COMMAND_RECORDER") {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        use std::io::Write as _;
        writeln!(f, "{display}")?;
        if std::env::var("CONFIDANT_TEST_COMMAND_FAIL").is_ok() {
            anyhow::bail!("simulated command failure (CONFIDANT_TEST_COMMAND_FAIL)");
        }
        return Ok(());
    }
    let status = std::process::Command::new(program).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("`{display}` exited with status {status}")
    }
}
