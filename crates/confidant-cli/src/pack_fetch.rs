//! `confidant pack add` (#439): fetch a candidate pack into a temp
//! directory, validate it with the same reader the loader uses, and
//! describe it for the operator to review.
//!
//! Writes nothing to the vault — applying a pack is a later step (#440).
//! Operator-only: `mcp.rs` maps a fixed tool whitelist and `pack` is not
//! in it.
//!
//! Fetching shells out to `git` with a locked-down argv (PD3): `https://`
//! only, no submodules, no hooks, no other protocol, no terminal prompt.
//! The candidate's own code is never run; only its files are read.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use confidant_core::error::DomainError;
use confidant_core::packs::dir::read_pack_dir;
use confidant_core::packs::manifest::{parse_manifest_external, PackManifest};

/// How long one `git` invocation may run before it is killed.
const GIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Where a candidate pack comes from.
#[derive(Debug)]
pub(crate) enum Source {
    /// An `https://` git URL, optionally with a ref resolved from `#<ref>`.
    Https {
        /// URL without the `#<ref>` suffix: what a lockfile entry records.
        url: String,
        /// Tag, branch or sha from after the `#`, already validated.
        git_ref: Option<String>,
    },
    /// A directory on this machine (`--from-dir`): no git involved.
    Dir(PathBuf),
}

/// A usage error (exit 2) with a fix.
fn usage(message: impl Into<String>, fix: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(DomainError::usage(message).with_fix(fix))
}

/// A ref is passed to `git fetch` as a refspec, so it must not look like an
/// option or smuggle a second refspec.
fn is_safe_ref(git_ref: &str) -> bool {
    !git_ref.is_empty()
        && !git_ref.starts_with('-')
        && !git_ref.contains(':')
        && !git_ref.contains(char::is_whitespace)
        && git_ref
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '~' | '^'))
}

/// A subdir must stay inside the fetched directory.
pub(crate) fn is_safe_subdir(subdir: &str) -> bool {
    let path = Path::new(subdir);
    !subdir.is_empty()
        && !path.is_absolute()
        && path.components().all(|c| {
            matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

/// Parse `pack add` arguments into a [`Source`].
///
/// Exactly one of `url` / `from_dir` is required. A URL must be `https://`
/// with no embedded credentials (PD3); the error never echoes the URL, so a
/// password cannot reach stderr.
pub(crate) fn parse_add_source(
    url: Option<&str>,
    from_dir: Option<&Path>,
) -> anyhow::Result<Source> {
    match (url, from_dir) {
        (Some(_), Some(_)) => Err(usage(
            "pass either a URL or --from-dir, not both",
            "Use `confidant pack add <https-url>` or `confidant pack add --from-dir <path>`",
        )),
        (None, None) => Err(usage(
            "pack add needs a source",
            "Use `confidant pack add <https-url>` or `confidant pack add --from-dir <path>`",
        )),
        (_, Some(dir)) => {
            if !dir.is_dir() {
                return Err(usage(
                    format!("--from-dir {} is not a directory", dir.display()),
                    "Point --from-dir at a pack directory",
                ));
            }
            Ok(Source::Dir(dir.to_path_buf()))
        }
        (Some(spec), None) => {
            let (url, git_ref) = match spec.split_once('#') {
                Some((url, git_ref)) => (url, Some(git_ref)),
                None => (spec, None),
            };
            if !url.starts_with("https://") {
                // Covers http://, ssh://, git://, file:// and the scp-like
                // `git@host:path` form. The URL is not echoed: it may carry
                // credentials.
                return Err(usage(
                    "only https:// git URLs can be fetched",
                    "Use an https:// URL, or --from-dir for a local directory",
                ));
            }
            if url["https://".len()..].contains('@') {
                return Err(usage(
                    "the URL appears to carry credentials",
                    "Use a credential helper or a URL without user:password",
                ));
            }
            let git_ref = match git_ref {
                Some(r) if is_safe_ref(r) => Some(r.to_string()),
                Some(_) => {
                    return Err(usage(
                        "the ref after `#` is not a valid git ref",
                        "Use a tag, branch or full commit id, e.g. `#v0.1.0`",
                    ))
                }
                None => None,
            };
            Ok(Source::Https {
                url: url.to_string(),
                git_ref,
            })
        }
    }
}

/// The `git clone` argv for `url` into `dest`, locked down per PD3.
///
/// Exposed for the unit test that locks the flags in place: a hostile repo
/// must not be able to run hooks, fetch submodules, or redirect the
/// transport.
pub(crate) fn clone_argv(url: &str, dest: &Path) -> Vec<String> {
    [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "clone",
        "--depth",
        "1",
        "--no-recurse-submodules",
        "--quiet",
        url,
    ]
    .into_iter()
    .map(str::to_string)
    .chain(std::iter::once(dest.display().to_string()))
    .collect()
}

/// Environment every fetch runs with (PD3): no terminal prompt, so a URL
/// that needs credentials fails instead of hanging.
pub(crate) fn fetch_env() -> Vec<(&'static str, &'static str)> {
    vec![("GIT_TERMINAL_PROMPT", "0")]
}

/// Build a `git` command with the fetch environment (no prompts).
fn git_command(args: &[String], cwd: Option<&Path>) -> Command {
    let mut cmd = Command::new("git");
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    for (key, value) in fetch_env() {
        cmd.env(key, value);
    }
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Run `git` with a hard timeout, returning stdout on success.
///
/// A killed command is an error, never a hang: the candidate is untrusted
/// input and a slow or malicious remote must not stall the operator.
fn run_git(args: &[String], cwd: Option<&Path>, what: &str) -> anyhow::Result<String> {
    let mut child = git_command(args, cwd)
        .spawn()
        .map_err(|e| anyhow::Error::new(DomainError::invalid(format!("could not run git: {e}"))))?;
    let deadline = Instant::now() + GIT_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read as _;
                    let _ = out.read_to_string(&mut stdout);
                }
                if !status.success() {
                    let mut stderr = String::new();
                    if let Some(mut err) = child.stderr.take() {
                        use std::io::Read as _;
                        let _ = err.read_to_string(&mut stderr);
                    }
                    let detail = stderr.trim().lines().last().unwrap_or("").to_string();
                    return Err(anyhow::Error::new(DomainError::pack_invalid(format!(
                        "{what} failed{}",
                        if detail.is_empty() {
                            String::new()
                        } else {
                            format!(": {detail}")
                        }
                    ))));
                }
                return Ok(stdout);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(anyhow::Error::new(DomainError::pack_invalid(format!(
                        "{what} took longer than {}s and was stopped",
                        GIT_TIMEOUT.as_secs()
                    ))));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(anyhow::Error::new(DomainError::internal(format!(
                    "could not wait for git: {e}"
                ))))
            }
        }
    }
}

/// One fetched candidate: the directory to read, the rev it resolved to,
/// and the subdir inside it.
pub(crate) struct Fetched {
    /// Keep-alive for the checkout: the temp directory is removed when this
    /// drops, so the report must be built while it is held. `None` for
    /// `--from-dir`, whose directory belongs to the operator.
    pub _temp: Option<tempfile::TempDir>,
    /// Directory to validate (the temp dir, or a subdir of it).
    pub pack_dir: PathBuf,
    /// `""` for `--from-dir`, else the full 40-hex commit.
    pub rev: String,
    /// Lockfile `source` value: the URL, or the literal `"dir"`.
    pub source: String,
    /// Lockfile `subdir` value (`""` for the root).
    pub subdir: String,
}

/// Fetch `source` into a fresh 0700 temp dir and resolve its rev.
pub(crate) fn fetch(source: &Source, subdir: &str) -> anyhow::Result<Fetched> {
    if !subdir.is_empty() && !is_safe_subdir(subdir) {
        return Err(usage(
            format!("--subdir '{subdir}' is not a safe relative path"),
            "Use a path inside the pack repository, with no `..`",
        ));
    }
    match source {
        Source::Dir(dir) => {
            // No copy: read the directory in place, exactly as the loader
            // will read the vendored copy (#436 already refuses anything
            // unsafe inside it).
            let pack_dir = if subdir.is_empty() {
                dir.clone()
            } else {
                dir.join(subdir)
            };
            Ok(Fetched {
                _temp: None,
                pack_dir,
                rev: String::new(),
                source: "dir".to_string(),
                subdir: subdir.to_string(),
            })
        }
        Source::Https { url, git_ref } => {
            let temp = tempfile::Builder::new()
                .prefix("confidant-pack-")
                .tempdir()
                .map_err(|e| {
                    anyhow::Error::new(DomainError::internal(format!("no temp dir: {e}")))
                })?;
            let checkout = temp.path().join("checkout");
            run_git(
                &clone_argv(url, &checkout),
                None,
                "fetching the pack repository",
            )?;

            // Resolve the rev: the clone's HEAD, or the requested ref.
            let rev = match git_ref {
                None => {
                    let args = vec!["rev-parse".to_string(), "HEAD".to_string()];
                    run_git(&args, Some(&checkout), "resolving HEAD")?
                }
                Some(r) => {
                    let fetch = vec![
                        "fetch".to_string(),
                        "--depth".to_string(),
                        "1".to_string(),
                        "--quiet".to_string(),
                        "origin".to_string(),
                        r.clone(),
                    ];
                    run_git(&fetch, Some(&checkout), "fetching the requested ref")?;
                    let checkout_args = vec![
                        "checkout".to_string(),
                        "--quiet".to_string(),
                        "--detach".to_string(),
                        "FETCH_HEAD".to_string(),
                    ];
                    run_git(&checkout_args, Some(&checkout), "checking out the ref")?;
                    let args = vec!["rev-parse".to_string(), "FETCH_HEAD".to_string()];
                    run_git(&args, Some(&checkout), "resolving the ref")?
                }
            };
            let rev = rev.trim().to_string();
            if rev.len() != 40 || !rev.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(anyhow::Error::new(DomainError::pack_invalid(format!(
                    "the source resolved to '{rev}', which is not a full commit id"
                ))));
            }
            let pack_dir = if subdir.is_empty() {
                checkout
            } else {
                checkout.join(subdir)
            };
            Ok(Fetched {
                _temp: Some(temp),
                pack_dir,
                rev,
                source: url.clone(),
                subdir: subdir.to_string(),
            })
        }
    }
}

/// A pack description for the review report (PD10).
pub(crate) struct PackReport {
    pub name: String,
    pub version: String,
    pub hash: String,
    pub files: Vec<(String, u64)>,
    pub skill_text: String,
    pub manifest: PackManifest,
}

/// Validate the fetched directory and describe it.
///
/// Validation is [`read_pack_dir`] (#436) plus the manifest parse (#435) —
/// the same code the loader runs — so what the operator reviews is what
/// the vault would receive.
pub(crate) fn describe(fetched: &Fetched) -> anyhow::Result<PackReport> {
    let dir = read_pack_dir(&fetched.pack_dir).map_err(anyhow::Error::new)?;
    let manifest_bytes = dir.files.get("manifest.toml").ok_or_else(|| {
        anyhow::Error::new(DomainError::pack_invalid(
            "the pack directory has no manifest.toml",
        ))
    })?;
    let text = std::str::from_utf8(manifest_bytes).map_err(|_| {
        anyhow::Error::new(DomainError::pack_invalid(
            "manifest.toml is not valid UTF-8",
        ))
    })?;
    let manifest = parse_manifest_external(text).map_err(anyhow::Error::new)?;

    let skill_text = dir
        .files
        .get(&manifest.pack.skill)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::to_string)
        .unwrap_or_default();

    let files = dir
        .files
        .iter()
        .map(|(path, bytes)| (path.clone(), bytes.len() as u64))
        .collect();

    Ok(PackReport {
        name: manifest.pack.name.clone(),
        version: manifest.pack.version.clone(),
        hash: dir.hash,
        files,
        skill_text,
        manifest,
    })
}

impl PackReport {
    /// The `claims` object: every claim the pack makes, by name.
    pub(crate) fn claims_json(&self) -> serde_json::Value {
        let m = &self.manifest;
        serde_json::json!({
            "verbs": m.verbs.iter().map(|v| v.name.clone()).collect::<Vec<_>>(),
            "fields": m.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
            "record_types": m.record_types.clone(),
            "edge_kinds": m.edge_kinds.iter().map(|e| e.name.clone()).collect::<Vec<_>>(),
            "balance_metrics": m.balance_metrics.clone(),
            "finding_codes": m.finding_codes.clone(),
            "checks_keys": m
                .checks
                .severity
                .iter()
                .map(|s| s.key.clone())
                .chain(m.checks.int.iter().map(|i| i.key.clone()))
                .collect::<Vec<_>>(),
        })
    }

    /// The `rules` array: id, kind, code and severity key per `[[rules]]`.
    pub(crate) fn rules_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.manifest
                .rules
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "kind": r.kind,
                        "code": r.code,
                        "severity_key": r.severity_key,
                    })
                })
                .collect(),
        )
    }

    /// Human-readable report lines: hash, claims, rules, files, skill text.
    ///
    /// The caller prints the source/rev/subdir header, which needs
    /// [`Fetched`] as well as the report.
    pub(crate) fn human_lines(&self) -> Vec<String> {
        let m = &self.manifest;
        let mut lines = vec![
            format!("hash    {}", self.hash),
            format!(
                "claims  {} verb(s), {} field(s), {} record type(s), {} edge kind(s), {} metric(s), {} finding code(s)",
                m.verbs.len(),
                m.fields.len(),
                m.record_types.len(),
                m.edge_kinds.len(),
                m.balance_metrics.len(),
                m.finding_codes.len()
            ),
        ];
        for r in &m.rules {
            lines.push(format!(
                "rule    {} (kind {}, code {}, severity {})",
                r.id,
                r.kind,
                r.code,
                r.severity_key.as_deref().unwrap_or("(fixed)")
            ));
        }
        lines.push(format!("files   {} file(s)", self.files.len()));
        for (path, bytes) in &self.files {
            lines.push(format!("  {path}  {bytes} bytes"));
        }
        lines.push(format!(
            "skill   {} ({} bytes):",
            m.pack.skill,
            self.skill_text.len()
        ));
        for line in self.skill_text.lines() {
            lines.push(format!("  {line}"));
        }
        lines
    }

    /// The `--json` payload for `pack add` (ADR-7 envelope keys are added
    /// by the caller).
    pub(crate) fn to_json(&self, source: &str, rev: &str, subdir: &str) -> serde_json::Value {
        serde_json::json!({
            "command": "pack-add",
            "dry_run": true,
            "pack": {
                "name": &self.name,
                "version": &self.version,
                "source": source,
                "rev": rev,
                "subdir": subdir,
                "hash": &self.hash,
            },
            "claims": self.claims_json(),
            "rules": self.rules_json(),
            "files": self
                .files
                .iter()
                .map(|(path, bytes)| serde_json::json!({"path": path, "bytes": bytes}))
                .collect::<Vec<_>>(),
            "skill_text": &self.skill_text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_argv_is_locked_down() {
        let argv = clone_argv("https://example.invalid/x.git", Path::new("/tmp/checkout"));
        let joined = argv.join(" ");
        for expected in [
            "core.hooksPath=/dev/null",
            "protocol.allow=never",
            "protocol.https.allow=always",
            "--depth 1",
            "--no-recurse-submodules",
            "https://example.invalid/x.git",
        ] {
            assert!(joined.contains(expected), "missing {expected} in {joined}");
        }
        assert_eq!(argv.last().unwrap(), "/tmp/checkout");
        assert_eq!(fetch_env(), vec![("GIT_TERMINAL_PROMPT", "0")]);
    }

    #[test]
    fn rejects_non_https_schemes() {
        for url in [
            "http://example.invalid/x.git",
            "ssh://git@example.invalid/x.git",
            "git://example.invalid/x.git",
            "file:///tmp/x",
            "git@example.invalid:x/y.git",
        ] {
            let err = parse_add_source(Some(url), None).expect_err(url);
            assert_eq!(DomainError::of(&err).unwrap().exit_code(), 2, "{url}");
        }
    }

    #[test]
    fn rejects_credentials_without_echoing_them() {
        let err = parse_add_source(Some("https://ada:hunter2@example.invalid/x.git"), None)
            .expect_err("credentials");
        let text = format!("{err:#}");
        assert!(!text.contains("hunter2"), "password echoed: {text}");
    }

    #[test]
    fn accepts_https_with_and_without_ref() {
        let Source::Https { url, git_ref } =
            parse_add_source(Some("https://example.invalid/x.git#v0.1.0"), None).unwrap()
        else {
            panic!("expected https");
        };
        assert_eq!(url, "https://example.invalid/x.git");
        assert_eq!(git_ref.as_deref(), Some("v0.1.0"));
    }

    #[test]
    fn rejects_option_like_ref() {
        let err = parse_add_source(Some("https://example.invalid/x.git#--upload-pack=x"), None)
            .expect_err("ref must not look like an option");
        assert_eq!(DomainError::of(&err).unwrap().exit_code(), 2);
    }

    #[test]
    fn rejects_unsafe_subdir() {
        assert!(!is_safe_subdir(""));
        assert!(!is_safe_subdir("../elsewhere"));
        assert!(!is_safe_subdir("/etc"));
        assert!(is_safe_subdir("packs/example"));
    }
}
