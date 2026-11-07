//! Pack commands: init, add, list, verify, remove, update.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::commands::shared::{finish_write, write_options};
use crate::{ok_envelope, print_json, shell_quote, Cli, FixExt};
use crate::{pack_fetch, pack_init};
use confidant_core::error::DomainError;
use confidant_core::packs::dir::read_pack_dir;
use confidant_core::write::{
    apply_write, apply_write_repairing, FileChange, PendingWrite, WriteOutcome,
};
use confidant_core::{check_vault, load_vault, CheckOptions};

/// `pack init <dir>`: scaffold a local external pack (#674).
///
/// No vault is needed and nothing outside `dir` is touched. The generated
/// pack is read back with the installer's readers before success is
/// reported, so a scaffold cannot be born broken.
pub(crate) fn cmd_pack_init(
    cli: &Cli,
    dir: &Path,
    name: Option<&str>,
    version: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let report = pack_init::init(dir, name, version, cli.dry_run)
        .map_err(pack_fetch::escape_domain_error)?;
    let dir_arg = shell_quote(&report.dir.display().to_string());
    let review = format!("confidant pack add --from-dir {dir_arg}");
    let install = format!("{review} --yes");

    if cli.json {
        print_json(&ok_envelope(
            None,
            serde_json::json!({
                "command": "pack-init",
                "dry_run": report.dry_run,
                "dir": report.dir.display().to_string(),
                "name": report.name,
                "version": report.version,
                "files": report.files,
                "next_steps": {
                    "review": review,
                    "install": install,
                },
            }),
        ))?;
        return Ok(ExitCode::SUCCESS);
    }

    let verb = if report.dry_run {
        "would create"
    } else {
        "created"
    };
    println!(
        "{verb} {}@{} in {}",
        pack_fetch::escape_line(&report.name),
        pack_fetch::escape_line(&report.version),
        pack_fetch::escape_line(&report.dir.display().to_string())
    );
    println!("files:");
    for file in &report.files {
        println!("  {file}");
    }
    println!("next:");
    println!("  review   {}", pack_fetch::escape_line(&review));
    println!("  install  {}", pack_fetch::escape_line(&install));
    if report.dry_run {
        println!("dry run: nothing was written");
    }
    Ok(ExitCode::SUCCESS)
}

/// Fetch a candidate pack, validate it, and print a review report (#439),
/// or apply the install with `--yes` (#440).
///
/// Without `--yes` it is read-only: the fetch happens in a temp directory and
/// nothing under the vault is created. Operator-only: `pack` is not in the
/// MCP tool whitelist.
pub(crate) fn cmd_pack_add(
    cli: &Cli,
    vault_root: Option<&Path>,
    url: Option<&str>,
    from_dir: Option<&Path>,
    subdir: Option<&str>,
    yes: bool,
    allow_unresolved: bool,
) -> anyhow::Result<ExitCode> {
    // The pack reader, manifest parser and git all quote untrusted
    // repository text; escape it before any error reaches the terminal or
    // the JSON error envelope (#499).
    cmd_pack_add_inner(
        cli,
        vault_root,
        url,
        from_dir,
        subdir,
        yes,
        allow_unresolved,
    )
    .map_err(pack_fetch::escape_domain_error)
}

/// #694: refuse `pack add --yes` before the generic pre-check when the
/// vault already references the pack without listing it. The pre-check
/// cannot pass while the pack's `[checks]` keys are unresolvable, and an
/// unlisted vendored copy is an ambiguous install state rather than
/// something the add should silently paper over. Both cases have the same
/// one-line fix: list the exact `name@version` (or remove the dependent
/// `[checks]` keys) first.
pub(crate) fn preflight_unlisted_pack(
    root: &Path,
    cfg: &confidant_core::config::VaultConfig,
    report: &pack_fetch::PackReport,
) -> anyhow::Result<()> {
    let has_checks = checks_reference_pack(cfg, &report.name);
    let rel = vendored_rel(&report.name, &report.version);
    // An unreadable `packs/` entry is an error, not evidence of a vendored
    // copy: surface it instead of claiming the pack is already there.
    let vendored = confidant_core::paths::exists(root, Path::new(&rel))?;
    if !has_checks && !vendored {
        return Ok(());
    }
    let name = pack_fetch::escape_line(&report.name);
    let version = pack_fetch::escape_line(&report.version);
    let rel = pack_fetch::escape_line(&rel);
    let listed = format!("{name}@{version}");
    let checks_fix = format!(
        "Add \"{listed}\" to `packs` in confidant.toml first (or remove the [checks] keys under `{name}.`), then re-run `confidant pack add`"
    );
    let (message, fix) = match (has_checks, vendored) {
        (true, true) => (
            format!(
                "{listed} is not listed in `packs`, but the vault already vendors it at {rel} and sets its [checks] keys"
            ),
            checks_fix,
        ),
        (true, false) => (
            format!(
                "{listed} is not listed in `packs`, but the vault already sets its [checks] keys; the pre-write check cannot pass until the pack is listed"
            ),
            checks_fix,
        ),
        (false, true) => (
            format!("{listed} is already vendored at {rel} but is not listed in `packs`"),
            format!(
                "Add \"{listed}\" to `packs` in confidant.toml to use the vendored copy, then re-run `confidant pack add`"
            ),
        ),
        (false, false) => unreachable!("preflight requires a reason"),
    };
    Err(anyhow::Error::new(DomainError::invalid(message)).with_fix(&fix))
}

/// Whether any `[checks]` leaf in `cfg` names `name` or sits under it
/// (`name.` prefix). Dotted TOML keys and `[checks.name]` tables both parse
/// as nested tables, so walk the tree to the leaves.
pub(crate) fn checks_reference_pack(cfg: &confidant_core::config::VaultConfig, name: &str) -> bool {
    fn walk<'a, I>(prefix: &str, entries: I, name: &str) -> bool
    where
        I: IntoIterator<Item = (&'a String, &'a toml::Value)>,
    {
        entries.into_iter().any(|(key, value)| {
            let dotted = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            // Exact match or a prefix under the pack's namespace. A pack
            // name cannot collide with a built-in `[checks]` namespace: the
            // manifest name rules reject the reserved built-in names (PD14).
            if dotted == name || dotted.starts_with(&format!("{name}.")) {
                return true;
            }
            match value {
                toml::Value::Table(table) => walk(&dotted, table.iter(), name),
                _ => false,
            }
        })
    }
    walk("", cfg.checks.rules.iter(), name)
}

/// #694 review: whether a blocked-check finding can be blamed on the pack
/// being added or removed.
///
/// A finding counts when its message names the pack — an unknown `[checks]`
/// key renders as `unknown [checks] key 'name.key'` — or when the file:line
/// it points at contains one of the pack's declared verbs, metrics, or edge
/// kinds. Findings with no readable location do not count: the hint must
/// never blame this pack for another pack's data.
pub(crate) fn finding_names_pack(
    root: &Path,
    finding: &confidant_core::check::Finding,
    name: &str,
    owned: &[String],
) -> bool {
    let quoted = format!("'{name}.");
    let bare = format!("'{name}'");
    if finding.message.contains(&quoted) || finding.message.contains(&bare) {
        return true;
    }
    let Some(file) = finding.file.as_deref() else {
        return false;
    };
    let Some(line) = finding.line.and_then(|line| line.checked_sub(1)) else {
        return false;
    };
    let Ok(text) = confidant_core::paths::read_to_string(root, Path::new(file)) else {
        return false;
    };
    text.lines()
        .nth(line as usize)
        .is_some_and(|text| line_mentions_any(text, owned))
}

/// Whether `line` carries one of `owned` as a whole token, so a short verb
/// like `use` does not match `user`.
pub(crate) fn line_mentions_any(line: &str, owned: &[String]) -> bool {
    line.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'))
        .filter(|token| !token.is_empty())
        .any(|token| owned.iter().any(|owned| owned.eq_ignore_ascii_case(token)))
}

/// The finding codes a pack's own data can produce once it is missing or
/// unlisted: an unknown `[checks]` key and an unresolved verb/metric/edge
/// kind.
pub(crate) fn is_pack_data_finding(finding: &confidant_core::check::Finding) -> bool {
    matches!(
        finding.code.as_str(),
        "E_CONFIG" | "E_UNKNOWN_VERB" | "E_UNKNOWN_METRIC" | "E_UNKNOWN_EDGE_KIND"
    )
}

/// The names a manifest declares: verbs, balance metrics, and edge kinds.
pub(crate) fn manifest_tokens(
    manifest: &confidant_core::packs::manifest::PackManifest,
) -> Vec<String> {
    manifest
        .verbs
        .iter()
        .map(|verb| verb.name.clone())
        .chain(manifest.balance_metrics.iter().cloned())
        .chain(manifest.edge_kinds.iter().map(|kind| kind.name.clone()))
        .collect()
}

/// The names the vault's loaded copy of `name` declares. An unlisted
/// vendored pack is not in the registry, so its manifest is read from the
/// tree instead (the #694 hint must name its data too). Empty when the pack
/// is not loadable (a missing or unreadable copy), so the hint stays silent
/// rather than guessing.
pub(crate) fn installed_pack_tokens(root: &Path, name: &str) -> Vec<String> {
    let registry_tokens = confidant_core::load_vault(root).ok().and_then(|vault| {
        vault
            .pack_registry()
            .all()
            .iter()
            .find(|pack| {
                pack.name() == name
                    || pack
                        .name()
                        .split_once('@')
                        .is_some_and(|(base, _)| base == name)
            })
            .map(|pack| {
                pack.verbs()
                    .iter()
                    .map(|verb| (*verb).to_owned())
                    .chain(
                        pack.balance_metrics()
                            .iter()
                            .map(|metric| (*metric).to_owned()),
                    )
                    .chain(pack.edge_kinds().iter().map(|kind| kind.name.to_owned()))
                    .collect()
            })
    });
    if let Some(tokens) = registry_tokens {
        return tokens;
    }
    for id in vendored_ids_for(root, name).unwrap_or_default() {
        let Some((id_name, id_version)) = id.split_once('@') else {
            continue;
        };
        let dir = root.join(vendored_rel(id_name, id_version));
        if let Some(manifest) = confidant_core::packs::dir::read_manifest_best_effort(&dir) {
            return manifest_tokens(&manifest);
        }
    }
    Vec::new()
}

/// #694: a stderr hint after `pack add --yes` is blocked, tailored to the
/// findings that name this pack's data. Returns `None` when the block is
/// unrelated (for example a pack conflict), so the hint never misdiagnoses.
///
/// #696: with `--allow-unresolved` the pre-check was already skipped, so the
/// hint must not suggest listing the pack again or claim the flag fixes
/// unrelated findings; it only says the post-check is what rolled back.
pub(crate) fn pack_add_blocked_hint(
    root: &Path,
    report: &confidant_core::check::CheckReport,
    name: &str,
    version: &str,
    manifest: &confidant_core::packs::manifest::PackManifest,
    allow_unresolved: bool,
) -> Option<String> {
    let owned = manifest_tokens(manifest);
    let scoped: Vec<&confidant_core::check::Finding> = report
        .findings
        .iter()
        .filter(|finding| is_pack_data_finding(finding))
        .filter(|finding| finding_names_pack(root, finding, name, &owned))
        .collect();
    let listed = format!(
        "{}@{}",
        pack_fetch::escape_line(name),
        pack_fetch::escape_line(version)
    );
    let sets_checks = scoped
        .iter()
        .any(|finding| finding.code.as_str() == "E_CONFIG");
    let uses_ledger = scoped
        .iter()
        .any(|finding| finding.code.as_str() != "E_CONFIG");
    if allow_unresolved {
        if scoped.is_empty() {
            return None;
        }
        return Some(format!(
            "hint: --allow-unresolved skipped the pre-check, but the post-check still failed, so nothing was committed. The findings above name data {listed} resolves or `[checks]` keys the vault already sets; fix them, then re-run `confidant pack add`."
        ));
    }
    let mut lines = Vec::new();
    if sets_checks {
        lines.push(format!(
            "hint: the findings above name [checks] keys the vault already carries for {listed}; add \"{listed}\" to `packs` in confidant.toml first (or remove those keys), then re-run `confidant pack add`"
        ));
    }
    if uses_ledger {
        lines.push(format!(
            "hint: the findings above name ledger entries or edges that use {listed}'s verbs, metrics, or edge kinds; add \"{listed}\" to `packs` in confidant.toml first so the write lists it (or migrate/remove those lines if the pack is going away), then re-run `confidant pack add`"
        ));
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// #696: additive JSON field for `pack add`, present only when the flag was
/// passed so existing envelopes keep their shape.
pub(crate) fn with_allow_unresolved(
    mut payload: serde_json::Value,
    allow_unresolved: bool,
) -> serde_json::Value {
    if allow_unresolved {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("allow_unresolved".to_owned(), serde_json::Value::Bool(true));
        }
    }
    payload
}

/// #694/#699: a stderr hint after `pack remove --yes` is blocked. The report
/// still prints unchanged and the exit stays 1; this only names the
/// workaround. Returns `None` when no finding names this pack, so a
/// pre-check failure on an unrelated vault does not blame the removal.
///
/// `listed` says whether the pack still has a `packs` entry (a plain removal)
/// or is already unlisted (`--allow-unresolved` ran earlier). With
/// `allow_unresolved` the hint must not claim the flag again: the post-check
/// failed on findings unlisting cannot resolve.
pub(crate) fn pack_remove_blocked_hint(
    root: &Path,
    report: &confidant_core::check::CheckReport,
    name: &str,
    owned: &[String],
    listed: bool,
    allow_unresolved: bool,
) -> Option<String> {
    let blocked = report
        .findings
        .iter()
        .filter(|finding| is_pack_data_finding(finding))
        .any(|finding| finding_names_pack(root, finding, name, owned));
    if !blocked {
        return None;
    }
    let name = pack_fetch::escape_line(name);
    if allow_unresolved {
        return Some(
            "hint: --allow-unresolved unlisted the pack, but the post-check still failed, so nothing was committed. The findings above are not ones unlisting can resolve; fix them, then re-run `confidant pack remove`."
                .to_owned(),
        );
    }
    if !listed {
        return Some(format!(
            "hint: {name} is already unlisted; its data and [checks] keys warn W_PACK_ORPHAN until migrated. Remove or migrate those entries, then re-run `confidant pack remove {name} --yes`."
        ));
    }
    Some(format!(
        "hint: the vault still uses {name}'s verbs, metrics, [checks] keys, or edge kinds, so removing the pack would leave orphan data. Migrate or remove those entries first, or run `confidant pack remove {name} --allow-unresolved --yes` to unlist the pack and keep its files while you migrate (the data then warns W_PACK_ORPHAN)."
    ))
}

pub(crate) fn cmd_pack_add_inner(
    cli: &Cli,
    vault_root: Option<&Path>,
    url: Option<&str>,
    from_dir: Option<&Path>,
    subdir: Option<&str>,
    yes: bool,
    allow_unresolved: bool,
) -> anyhow::Result<ExitCode> {
    let source = pack_fetch::parse_add_source(url, from_dir)?;
    let fetched = pack_fetch::fetch(&source, subdir.unwrap_or(""))?;
    let report = pack_fetch::describe(&fetched)?;
    // A reserved or compiled name can never be installed from outside the
    // binary (PD14), so refuse before the report either way.
    refuse_uninstallable(&report.name, &report.version)?;

    if yes {
        let root = vault_root_required(vault_root, "pack add --yes")?;
        let cfg_text = read_config_text(root)?;
        let cfg =
            confidant_core::config::VaultConfig::parse(&cfg_text).map_err(anyhow::Error::new)?;
        let listed_id = format!("{}@{}", report.name, report.version);
        // #694: the vault may already carry this pack's data or its vendored
        // copy without listing the pack. The pre-check would then refuse the
        // install with a generic finding, so name the exact listing change
        // first. A listing for another version of the same name is left to
        // the one-version-at-a-time refusal below.
        let listed_name = cfg.packs.iter().any(|listed| {
            listed == &report.name
                || listed
                    .split_once('@')
                    .is_some_and(|(name, _)| name == report.name)
        });
        if !listed_name {
            // #696: the explicit install-over-existing-data path skips this
            // preflight. The post-check still gates the commit, so an
            // unrelated error rolls the whole write back.
            if !allow_unresolved {
                preflight_unlisted_pack(root, &cfg, &report)?;
            }
        }
        let lock = read_lockfile_or_empty(root)?;
        if let Some(entry) = lock.find(&report.name, &report.version) {
            if entry.hash == report.hash && listed_name {
                // Same pin, same bytes, already listed: nothing to write
                // (PD10 idempotence).
                if cli.json {
                    print_json(&ok_envelope(
                        Some(root),
                        with_allow_unresolved(
                            serde_json::json!({
                                "command": "pack-add",
                                "unchanged": true,
                                "pack": {"name": report.name, "version": report.version, "hash": report.hash},
                            }),
                            allow_unresolved,
                        ),
                    ))?;
                } else {
                    println!(
                        "{}@{} is already installed at this hash; nothing to do",
                        pack_fetch::escape_line(&report.name),
                        pack_fetch::escape_line(&report.version)
                    );
                }
                return Ok(ExitCode::SUCCESS);
            }
            if entry.hash != report.hash {
                return Err(anyhow::Error::new(DomainError::invalid(format!(
                    "{}@{} is already installed with a different hash",
                    report.name, report.version
                )))
                .with_fix("Use `confidant pack update <name> --rev <ref>` to move it"));
            }
            // #696 review: pinned at this hash but missing from `packs`. The
            // vendored copy is already the right bytes, so the only repair is
            // adding the listing; fall through to the write instead of
            // claiming "nothing to do" while `check` still fails.
        }
        // One version at a time: installing a second version of the same name
        // side by side leaves `pack update` unable to tell which to move, so
        // refuse up front and point at `update` (which replaces in place). The
        // same name and version as the pin already handled above is not a
        // second version.
        if let Some(other) = lock
            .packs
            .iter()
            .find(|e| e.name == report.name && e.version != report.version)
        {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "{}@{} is already installed; {}@{} cannot be added alongside it",
                report.name, other.version, report.name, report.version
            )))
            .with_fix(
                "Use `confidant pack update <name> --rev <ref>` to replace the installed version",
            ));
        }
        let files = read_pack_dir(&fetched.pack_dir).map_err(anyhow::Error::new)?;
        // Pin the reviewed bytes to the written bytes: `report` came from an
        // earlier read of the same directory, so a `--from-dir` source that
        // changed in between must be refused rather than vendored un-reviewed.
        if files.hash != report.hash {
            return Err(anyhow::Error::new(DomainError::conflict(
                "the pack directory changed between the review and the write",
            ))
            .with_fix("Re-run `confidant pack add` and review the report again"));
        }
        // #612: the pack may already be listed in `confidant.toml` with no
        // lockfile pin (a lost lock, a bad merge, a partial restore). That is
        // the exact `E_PACK_UNKNOWN` the pre-check reports and this write
        // repairs by writing the pin, so route it through the repairing path;
        // the post-check still gates the commit. With no such listing the
        // pre-check runs as usual.
        //
        // #696: `--allow-unresolved` opts into the same repairing path for a
        // vault that already carries this pack's checks/verbs/metrics/edge
        // kinds but does not list it. The pre-check is skipped; the
        // post-check still refuses to commit an unclean vault, so unrelated
        // errors roll back.
        let unpinned_listing = cfg.packs.iter().any(|listed| listed == &listed_id);
        let changes = install_changes(root, &report, &files, &fetched, None)?;
        let summary = format!(
            "pack: add {}@{} ({})",
            report.name,
            report.version,
            short_hash(&report.hash)
        );
        let pending = PendingWrite {
            changes,
            canonical_request: summary.clone(),
            summary,
        };
        let outcome = if unpinned_listing || allow_unresolved {
            apply_write_repairing(root, pending, &write_options(cli))?
        } else {
            apply_write(root, pending, &write_options(cli))?
        };
        // #694: the check report still prints unchanged (exit 1); this only
        // adds a stderr hint, so `--json` stdout stays valid.
        let hint = match &outcome {
            WriteOutcome::CheckBlocked {
                report: check_report,
            } => pack_add_blocked_hint(
                root,
                check_report,
                &report.name,
                &report.version,
                &report.manifest,
                allow_unresolved,
            ),
            _ => None,
        };
        let code = finish_write(
            cli,
            root,
            "pack-add",
            outcome,
            with_allow_unresolved(
                serde_json::json!({
                    "pack": {"name": report.name, "version": report.version, "hash": report.hash},
                }),
                allow_unresolved,
            ),
        )?;
        if let Some(hint) = hint {
            writeln!(io::stderr(), "{hint}")?;
        }
        return Ok(code);
    }
    if cli.json {
        let payload = report.to_json(&fetched.source, &fetched.rev, &fetched.subdir);
        print_json(&ok_envelope(
            vault_root,
            with_allow_unresolved(payload, allow_unresolved),
        ))?;
    } else {
        // Everything here except `rev` (40 hex) and `hash` (ours) comes from
        // an untrusted repository, so control characters are escaped before
        // they reach the terminal: a hostile SKILL.md must not be able to
        // hide the lines the operator is meant to read (PD10).
        println!(
            "pack    {}@{}",
            pack_fetch::escape_line(&report.name),
            pack_fetch::escape_line(&report.version)
        );
        println!("source  {}", pack_fetch::escape_line(&fetched.source));
        println!(
            "rev     {}",
            if fetched.rev.is_empty() {
                "(none: local directory)"
            } else {
                fetched.rev.as_str()
            }
        );
        println!(
            "subdir  {}",
            if fetched.subdir.is_empty() {
                "(root)".to_string()
            } else {
                pack_fetch::escape_line(&fetched.subdir)
            }
        );
        for line in report.human_lines() {
            println!("{line}");
        }
        println!("nothing was written: applying a pack is a separate step");
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// pack install / list / verify / remove / update (#440)
// ---------------------------------------------------------------------------

/// The vault root, or a clear error for a command that needs one.
pub(crate) fn vault_root_required<'a>(
    root: Option<&'a Path>,
    what: &str,
) -> anyhow::Result<&'a Path> {
    root.ok_or_else(|| {
        anyhow::Error::new(DomainError::vault_not_found()).context(format!("{what} needs a vault"))
    })
}

/// Refuse to install a reserved (`personal`) or built-in pack (PD14).
/// Both can only come from the binary. An external pack is an ordinary
/// pack since #449.
pub(crate) fn refuse_uninstallable(name: &str, version: &str) -> anyhow::Result<()> {
    use confidant_core::packs::manifest::is_reserved_pack_name;
    if is_reserved_pack_name(name) {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "pack name '{name}' is reserved for a built-in pack"
        )))
        .with_fix("Choose a different pack name"));
    }
    let listed = format!("{name}@{version}");
    if confidant_core::packs::registry::PackRegistry::compiled()
        .all()
        .iter()
        .any(|p| p.name() == listed)
    {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "{listed} is compiled into this binary"
        )))
        .with_fix("Remove the listing; a compiled pack is always available"));
    }
    Ok(())
}

/// `<vault>/confidant.lock`, parsed; an absent file is an empty lockfile.
pub(crate) fn read_lockfile_or_empty(
    root: &Path,
) -> anyhow::Result<confidant_core::packs::lock::Lockfile> {
    match std::fs::read_to_string(root.join("confidant.lock")) {
        Ok(text) => confidant_core::packs::lock::Lockfile::parse(&text).map_err(anyhow::Error::new),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(confidant_core::packs::lock::Lockfile { packs: Vec::new() })
        }
        Err(e) => Err(anyhow::anyhow!("cannot read confidant.lock: {e}")),
    }
}

pub(crate) fn read_config_text(root: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(root.join("confidant.toml"))
        .map_err(|e| anyhow::anyhow!("cannot read confidant.toml: {e}"))
}

/// Vendored directory for a pack, relative to the vault root.
pub(crate) fn vendored_rel(name: &str, version: &str) -> String {
    format!("packs/{name}@{version}")
}

/// The first 12 hex characters of a `sha256:<hex>` hash, for a commit subject
/// or report header. Slicing the whole string would show only the prefix
/// (`sha256:abcde`), because the algorithm label is 7 bytes long.
pub(crate) fn short_hash(hash: &str) -> String {
    hash.strip_prefix("sha256:")
        .unwrap_or(hash)
        .chars()
        .take(12)
        .collect()
}

/// One change set that installs `report`'s files and pins them: the vendored
/// tree, the lockfile entry, and the `packs` listing (PD4/PD5/PD10).
///
/// `replace` is an existing `name@version` this install supersedes (an
/// update): its lock entry drops and its `packs` listing is replaced, so the
/// config is rewritten exactly once.
pub(crate) fn install_changes(
    root: &Path,
    report: &pack_fetch::PackReport,
    files: &confidant_core::packs::dir::PackDir,
    fetched: &pack_fetch::Fetched,
    replace: Option<&str>,
) -> anyhow::Result<Vec<FileChange>> {
    let base = vendored_rel(&report.name, &report.version);
    let mut changes: Vec<FileChange> = files
        .files
        .iter()
        .map(|(rel, bytes)| FileChange::WriteBytes {
            path: PathBuf::from(format!("{base}/{rel}")),
            contents: bytes.clone(),
        })
        .collect();

    changes.push(lockfile_change(root, report, fetched, replace)?);

    let cfg_text = read_config_text(root)?;
    let mut packs = confidant_core::config::VaultConfig::parse(&cfg_text)
        .map_err(anyhow::Error::new)?
        .packs;
    if let Some(old) = replace {
        packs.retain(|p| p != old);
    }
    let listed = format!("{}@{}", report.name, report.version);
    if !packs.contains(&listed) {
        packs.push(listed);
    }
    changes.push(FileChange::WriteFile {
        path: PathBuf::from("confidant.toml"),
        contents: confidant_core::config::VaultConfig::set_packs(&cfg_text, &packs)
            .map_err(anyhow::Error::new)?,
    });
    Ok(changes)
}

/// The `confidant.lock` change for installing `report`: drop the pin named
/// by `replace` (when re-vendoring a version) and upsert the fetched one.
pub(crate) fn lockfile_change(
    root: &Path,
    report: &pack_fetch::PackReport,
    fetched: &pack_fetch::Fetched,
    replace: Option<&str>,
) -> anyhow::Result<FileChange> {
    let mut lock = read_lockfile_or_empty(root)?;
    if let Some(old) = replace {
        if let Some((name, version)) = old.split_once('@') {
            lock.remove(name, version);
        }
    }
    lock.upsert(confidant_core::packs::lock::LockEntry {
        name: report.name.clone(),
        version: report.version.clone(),
        source: fetched.source.clone(),
        rev: fetched.rev.clone(),
        subdir: fetched.subdir.clone(),
        hash: report.hash.clone(),
    });
    Ok(FileChange::WriteFile {
        path: PathBuf::from("confidant.lock"),
        contents: lock.to_toml(),
    })
}

/// `DeleteFile` changes for every regular file in a vendored pack dir.
///
/// Lists with [`confidant_core::paths::read_dir`], which refuses to follow a
/// symbolic link at any depth, so a planted `packs/<id>` (or `packs/`)
/// symlink can never steer a delete into files outside the vault (#440). A
/// non-regular entry (a symlink, a directory, a special file) is refused
/// before any change is built: `apply_write` applies its change list in order
/// without rolling back a mid-list failure, so queuing one would delete the
/// earlier files and then fail, leaving a half-deleted pack (#529 review). A
/// missing vendored tree is not an error — removal must still clean up the
/// lockfile and listing — but an unlistable one is.
pub(crate) fn delete_vendored_changes(
    root: &Path,
    name: &str,
    version: &str,
) -> anyhow::Result<Vec<FileChange>> {
    let rel = vendored_rel(name, version);
    let rel_path = Path::new(&rel);
    let listing = match confidant_core::paths::read_dir(root, rel_path) {
        Ok(listing) => listing,
        Err(error) => {
            // A missing vendored tree is not an error — removal must still
            // clean up the lockfile and listing. Anything else (a symlink,
            // an unreadable tree) fails closed rather than guessing.
            if !confidant_core::paths::exists(root, rel_path).unwrap_or(true) {
                return Ok(Vec::new());
            }
            return Err(error);
        }
    };
    if let Some((entry, cause)) = listing.errors.first() {
        return Err(anyhow::Error::new(
            DomainError::pack_invalid(format!(
                "cannot list {}: {}: {cause}",
                pack_fetch::escape_line(&rel),
                pack_fetch::escape_line(entry)
            ))
            .with_fix("Restore the vendored tree (git checkout -- packs) and retry"),
        ));
    }
    let mut out = Vec::new();
    for entry in listing.entries {
        // Refuse before any delete is queued: a mid-list refusal inside
        // `apply_write` would have already unlinked the earlier files.
        if !entry.kind.is_file() {
            return Err(anyhow::Error::new(
                DomainError::pack_invalid(format!(
                    "cannot remove {}: {} is {}",
                    pack_fetch::escape_line(&rel),
                    pack_fetch::escape_line(&entry.name),
                    describe_non_regular(entry.kind)
                ))
                .with_fix(
                    "Restore the vendored tree (git checkout -- packs) or remove the entry, then retry",
                ),
            ));
        }
        out.push(FileChange::DeleteFile {
            path: PathBuf::from(&rel).join(&entry.name),
        });
    }
    Ok(out)
}

/// Describe a directory entry that is not a regular file, for a refusal
/// message. `File` is unreachable (callers check `is_file` first) but keeps
/// the match exhaustive.
pub(crate) fn describe_non_regular(kind: confidant_core::paths::EntryKind) -> &'static str {
    use confidant_core::paths::EntryKind;
    match kind {
        EntryKind::Symlink => "a symbolic link",
        EntryKind::Directory => "a directory",
        EntryKind::Other => "a special file",
        EntryKind::File => "a regular file",
    }
}

/// `pack update` reviews the change with `git diff --no-index`, which follows
/// symlinks. The vendored tree is checked with the vault's no-follow helpers
/// first, so a planted `packs/<id>` symlink (or a symlinked file inside) cannot
/// feed content from outside the vault into the review (PD12). A tree that is
/// not a real directory of regular files is "cannot diff".
pub(crate) fn ensure_vendored_tree_diffable(
    root: &Path,
    name: &str,
    version: &str,
) -> anyhow::Result<()> {
    let rel = vendored_rel(name, version);
    let cannot_diff = |detail: String| {
        anyhow::Error::new(
            DomainError::pack_invalid(format!("cannot diff {rel}: {detail}")).with_fix(
                "Restore the vendored tree (git checkout -- packs) or remove the pack, then retry",
            ),
        )
    };
    let listing = confidant_core::paths::read_dir(root, Path::new(&rel))
        .map_err(|error| cannot_diff(pack_fetch::escape_line(&format!("{error:#}"))))?;
    if let Some((entry, cause)) = listing.errors.first() {
        return Err(cannot_diff(format!(
            "cannot list {}: {}",
            pack_fetch::escape_line(entry),
            pack_fetch::escape_line(cause)
        )));
    }
    if listing.entries.iter().any(|entry| !entry.kind.is_file()) {
        return Err(cannot_diff(
            "the vendored tree holds a non-regular entry (a symlink or directory)".to_owned(),
        ));
    }
    Ok(())
}

/// Verification status of one installed pack (PD12: fail closed).
pub(crate) struct PackStatus {
    name: String,
    version: String,
    source: String,
    rev: String,
    hash: String,
    status: &'static str,
}

impl PackStatus {
    fn verify(root: &Path, entry: &confidant_core::packs::lock::LockEntry) -> Self {
        let rel = vendored_rel(&entry.name, &entry.version);
        let rel_path = Path::new(&rel);
        let dir = root.join(&rel);
        // `read_pack_dir` takes a path and follows a symlink at the tree root,
        // so classify with the vault's no-follow helpers first: a planted
        // `packs/<id>` symlink (or a symlinked file inside) is `invalid`,
        // never read (#529).
        let status = match confidant_core::paths::exists(root, rel_path) {
            // Only a definite absence is `missing`; a helper error fails
            // closed as `invalid` rather than masquerading as absent.
            Ok(false) => "missing",
            Err(_) => "invalid",
            Ok(true) => match confidant_core::paths::read_dir(root, rel_path) {
                Ok(listing)
                    if listing.errors.is_empty()
                        && listing.entries.iter().all(|e| e.kind.is_file()) =>
                {
                    // The no-follow check above and this `read_pack_dir` are
                    // separate syscalls: a tree swapped for a symlink in
                    // between would still be followed. That window is local
                    // only (an attacker with vault write access), and
                    // `read_pack_dir` refuses symlinked entries inside the
                    // tree, so the tree is not re-read to close it.
                    match read_pack_dir(&dir) {
                        Ok(packed) if packed.hash == entry.hash => "ok",
                        Ok(_) => "tampered",
                        Err(_) => "invalid",
                    }
                }
                _ => "invalid",
            },
        };
        Self {
            name: entry.name.clone(),
            version: entry.version.clone(),
            source: entry.source.clone(),
            rev: entry.rev.clone(),
            hash: entry.hash.clone(),
            status,
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "rev": self.rev,
            "hash": self.hash,
            "status": self.status,
        })
    }

    fn print_human(&self) {
        println!(
            "{:<20} {:<8} {:<8} {:<12} {}",
            pack_fetch::escape_line(&self.name),
            pack_fetch::escape_line(&self.version),
            self.status,
            if self.rev.is_empty() {
                "(dir)".to_owned()
            } else {
                // A hand-edited non-ASCII rev must not panic a byte slice.
                self.rev.chars().take(8).collect()
            },
            pack_fetch::escape_line(&self.source)
        );
    }
}

/// `pack list`: installed packs and their verification status. Read-only and
/// offline.
pub(crate) fn cmd_pack_list(cli: &Cli, vault_root: Option<&Path>) -> anyhow::Result<ExitCode> {
    let root = vault_root_required(vault_root, "pack list")?;
    let lock = read_lockfile_or_empty(root)?;
    let statuses: Vec<PackStatus> = lock
        .packs
        .iter()
        .map(|e| PackStatus::verify(root, e))
        .collect();
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "command": "pack-list",
                "packs": statuses.iter().map(PackStatus::to_json).collect::<Vec<_>>(),
            }),
        ))?;
    } else if statuses.is_empty() {
        println!("no external packs installed");
    } else {
        for status in &statuses {
            status.print_human();
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `pack verify [name]`: re-hash the vendored trees against the lockfile.
/// Exit 1 on any mismatch.
pub(crate) fn cmd_pack_verify(
    cli: &Cli,
    vault_root: Option<&Path>,
    name: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let root = vault_root_required(vault_root, "pack verify")?;
    let lock = read_lockfile_or_empty(root)?;
    let selected: Vec<&confidant_core::packs::lock::LockEntry> = match name {
        Some(name) => {
            let matching: Vec<_> = lock.packs.iter().filter(|e| e.name == name).collect();
            if matching.is_empty() {
                return Err(anyhow::Error::new(DomainError::not_found(format!(
                    "pack '{name}' is not installed"
                )))
                .with_fix("Run `confidant pack list` to see installed packs"));
            }
            matching
        }
        None => lock.packs.iter().collect(),
    };
    let statuses: Vec<PackStatus> = selected
        .iter()
        .map(|e| PackStatus::verify(root, e))
        .collect();
    let ok = statuses.iter().all(|s| s.status == "ok");
    if cli.json {
        print_json(&ok_envelope(
            Some(root),
            serde_json::json!({
                "command": "pack-verify",
                "ok": ok,
                "packs": statuses.iter().map(PackStatus::to_json).collect::<Vec<_>>(),
            }),
        ))?;
    } else if statuses.is_empty() {
        println!("no external packs installed");
    } else {
        for status in &statuses {
            status.print_human();
        }
        if !ok {
            eprintln!(
                "pack verify: a vendored tree does not match confidant.lock; \
                 reinstall with `confidant pack add` or fix the lockfile"
            );
        }
    }
    Ok(ExitCode::from(if ok { 0 } else { 1 }))
}

/// Whether `version` is safe to join into `<root>/packs/<name>@<version>`:
/// one path segment, not `.`/`..`, portable across Windows (no `/`, `\`, `:`,
/// or control characters). Mirrors the lockfile's own `subdir` rule so a
/// hand-edited `confidant.toml` listing can never steer a delete out of the
/// vendored tree.
pub(crate) fn is_safe_version_part(version: &str) -> bool {
    !version.is_empty()
        && version != "."
        && version != ".."
        && !version.contains('/')
        && !version.contains('\\')
        && !version.contains(':')
        && !version.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// The `name@version` ids of vendored pack directories under
/// `<root>/packs` for `name`, listed without following a symbolic link
/// (#440). A missing `packs/` is an empty list; an unlistable one fails
/// closed. Ids whose version is not a single safe path segment are skipped.
pub(crate) fn vendored_ids_for(root: &Path, name: &str) -> anyhow::Result<Vec<String>> {
    let listing = match confidant_core::paths::read_dir(root, Path::new("packs")) {
        Ok(listing) => listing,
        Err(error) => {
            // A missing `packs/` is not an error (there is simply nothing
            // vendored); anything else — including a planted `packs` symlink,
            // which the no-follow reader refuses — fails closed.
            if !confidant_core::paths::exists(root, Path::new("packs")).unwrap_or(true) {
                return Ok(Vec::new());
            }
            return Err(error);
        }
    };
    if let Some((entry, cause)) = listing.errors.first() {
        return Err(anyhow::anyhow!(
            "cannot list packs/: {}: {cause}",
            pack_fetch::escape_line(entry)
        ));
    }
    let prefix = format!("{name}@");
    let mut ids = Vec::new();
    for entry in listing.entries {
        if !entry.kind.is_directory() {
            continue;
        }
        let Some(version) = entry.name.strip_prefix(&prefix) else {
            continue;
        };
        if is_safe_version_part(version) {
            ids.push(format!("{name}@{version}"));
        }
    }
    Ok(ids)
}

/// `pack remove <name>`: delete the vendored files, the lockfile entries and
/// the `packs` listing. Needs `--yes`.
///
/// #612: the pack's install state is keyed off every source — the lockfile,
/// the `confidant.toml` listing, and the vendored tree — not the lockfile
/// alone. When `confidant.lock` is missing (a lost lock, a bad merge, a
/// partial restore) the listing and the vendored directory still identify the
/// pack, so removal is the escape `check`'s `E_PACK_UNKNOWN` fix can point at.
///
/// #699: with `--allow-unresolved` the command *unlists* the pack instead:
/// it drops the `packs` entry but keeps the vendored tree and lock pin. The
/// registry still owns the pack's claims as a disabled pack, so its data and
/// `[checks]` keys are durable `W_PACK_ORPHAN` warnings rather than errors.
/// `check` and every later write keep working while the operator migrates; a
/// later plain `pack remove` deletes the files once the data is gone.
pub(crate) fn cmd_pack_remove(
    cli: &Cli,
    vault_root: Option<&Path>,
    name: String,
    yes: bool,
    allow_unresolved: bool,
) -> anyhow::Result<ExitCode> {
    let root = vault_root_required(vault_root, "pack remove")?;
    let mut lock = read_lockfile_or_empty(root)?;
    let lock_entries: Vec<confidant_core::packs::lock::LockEntry> = lock
        .packs
        .iter()
        .filter(|e| e.name == name)
        .cloned()
        .collect();

    let cfg_text = read_config_text(root)?;
    let cfg_packs = confidant_core::config::VaultConfig::parse(&cfg_text)
        .map_err(anyhow::Error::new)?
        .packs;

    // Well-formed `name@version` ids to delete (the vendored tree) and
    // un-pin (the lockfile): the lock entries plus any safe listing.
    // `drop_listings` is every `confidant.toml` entry for this name, including
    // one that is not a well-formed id (a bare `example-pack`), so a malformed
    // listing is repaired too.
    let mut ids: BTreeSet<String> = lock_entries.iter().map(|e| e.id()).collect();
    let mut drop_listings: BTreeSet<String> = BTreeSet::new();
    for listed in &cfg_packs {
        let matches_name = listed == &name
            || listed
                .split_once('@')
                .is_some_and(|(listed_name, _)| listed_name == name);
        if !matches_name {
            continue;
        }
        drop_listings.insert(listed.clone());
        if let Some((_, version)) = listed.split_once('@') {
            if is_safe_version_part(version) {
                ids.insert(listed.clone());
            }
        }
    }
    // The vendored tree is the last resort: only when neither the lockfile nor
    // the listing names the pack (a listing hand-edited away, a partial
    // restore) is it consulted. A healthy removal keeps its prior behaviour.
    if lock_entries.is_empty() && drop_listings.is_empty() {
        ids.extend(vendored_ids_for(root, &name)?);
    }
    if ids.is_empty() && drop_listings.is_empty() {
        return Err(anyhow::Error::new(DomainError::not_found(format!(
            "pack '{name}' is not installed"
        )))
        .with_fix("Run `confidant pack list` to see installed packs"));
    }
    let listed: Vec<String> = ids
        .iter()
        .chain(drop_listings.iter().filter(|l| !ids.contains(*l)))
        .cloned()
        .collect();
    let was_listed = !drop_listings.is_empty();

    // Already unlisted (tree and/or lock entry still there): the flag has
    // nothing to drop. Say so and report the warnings left to migrate;
    // a plain `pack remove` is the command that deletes the files.
    if allow_unresolved && drop_listings.is_empty() {
        let total = pack_orphan_total(root);
        if cli.json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "command": "pack-remove",
                    "outcome": "unlisted",
                    "allow_unresolved": true,
                    "unchanged": true,
                    "unlisted": Vec::<String>::new(),
                    "kept": listed,
                    "orphans": { "new": 0, "total": total },
                }),
            ))?;
        } else {
            println!(
                "{} is already unlisted; nothing to unlist",
                listed
                    .iter()
                    .map(|id| pack_fetch::escape_line(id))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("check: {total} W_PACK_ORPHAN warning(s)");
            println!(
                "next: migrate or remove the orphaned data, then run `confidant pack remove {} --yes`",
                pack_fetch::escape_line(&name)
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    if !yes {
        if cli.json {
            let payload = if allow_unresolved {
                serde_json::json!({
                    "command": "pack-remove",
                    "dry_run": true,
                    "outcome": "unlisted",
                    "allow_unresolved": true,
                    "would_unlist": drop_listings.iter().cloned().collect::<Vec<_>>(),
                    "kept": listed,
                })
            } else {
                serde_json::json!({
                    "command": "pack-remove",
                    "dry_run": true,
                    "outcome": "removed",
                    "would_remove": listed,
                })
            };
            print_json(&ok_envelope(Some(root), payload))?;
        } else if allow_unresolved {
            println!("would unlist (keep files and the lock entry; pass --yes to apply):");
            for id in &drop_listings {
                println!("  {}", pack_fetch::escape_line(id));
            }
            println!("kept:");
            for id in &listed {
                println!("  {}", pack_fetch::escape_line(id));
            }
        } else {
            println!("would remove (pass --yes to apply):");
            for id in &listed {
                // A hand-edited lockfile or listing id must not hide itself.
                println!("  {}", pack_fetch::escape_line(id));
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    if allow_unresolved {
        return cmd_pack_unlist(
            cli,
            root,
            UnlistPlan {
                cfg_text: &cfg_text,
                cfg_packs,
                drop_listings: &drop_listings,
                kept: &listed,
                name: &name,
                lock_entries: &lock_entries,
            },
        );
    }

    let mut changes = Vec::new();
    for id in &ids {
        // Ids are always `name@version` (the lockfile's id, or a validated
        // listing / vendored name); the name half carries no `@`.
        let (id_name, id_version) = id.split_once('@').expect("ids are name@version");
        changes.extend(delete_vendored_changes(root, id_name, id_version)?);
        lock.remove(id_name, id_version);
    }
    // A lockfile that is absent stays absent: removing the last pin must not
    // conjure an empty `confidant.lock` (a vault with no external packs has
    // no lockfile).
    let lock_exists =
        confidant_core::paths::exists(root, Path::new("confidant.lock")).unwrap_or(true);
    if lock_exists {
        changes.push(FileChange::WriteFile {
            path: PathBuf::from("confidant.lock"),
            contents: lock.to_toml(),
        });
    }
    let mut packs = cfg_packs;
    packs.retain(|p| !drop_listings.contains(p));
    // An unlisted pack has no listing to rewrite; skip the file so a later
    // plain removal does not normalize an unrelated `confidant.toml`.
    if !drop_listings.is_empty() {
        changes.push(FileChange::WriteFile {
            path: PathBuf::from("confidant.toml"),
            contents: confidant_core::config::VaultConfig::set_packs(&cfg_text, &packs)
                .map_err(anyhow::Error::new)?,
        });
    }

    let summary = format!("pack: remove {}", listed.join(", "));
    let pending = PendingWrite {
        changes,
        canonical_request: summary.clone(),
        summary,
    };
    // #612: with no lockfile entry for this pack the pre-check reports exactly
    // the `E_PACK_UNKNOWN` this removal repairs, so the write goes through the
    // repairing path. Its post-check still gates the commit, so a removal can
    // never commit a vault that is still broken. With a lock entry the
    // pre-check runs as usual.
    let outcome = if lock_entries.is_empty() {
        apply_write_repairing(root, pending, &write_options(cli))?
    } else {
        apply_write(root, pending, &write_options(cli))?
    };
    if matches!(outcome, WriteOutcome::Applied { .. }) {
        for id in &ids {
            if let Some((id_name, id_version)) = id.split_once('@') {
                let _ = std::fs::remove_dir(root.join(vendored_rel(id_name, id_version)));
            }
        }
    }
    // #694: the report still prints unchanged (exit 1); this only adds a
    // stderr hint, so `--json` stdout stays valid. Only findings that name
    // this pack produce one, so an unrelated pre-check failure stays quiet.
    let hint = match &outcome {
        WriteOutcome::CheckBlocked { report } => {
            let owned = installed_pack_tokens(root, &name);
            pack_remove_blocked_hint(root, report, &name, &owned, was_listed, false)
        }
        _ => None,
    };
    let code = finish_write(
        cli,
        root,
        "pack-remove",
        outcome,
        serde_json::json!({ "outcome": "removed", "removed": listed }),
    )?;
    if let Some(hint) = hint {
        writeln!(io::stderr(), "{hint}")?;
    }
    Ok(code)
}

/// The state `cmd_pack_remove` hands to its `--allow-unresolved` path.
pub(crate) struct UnlistPlan<'a> {
    cfg_text: &'a str,
    cfg_packs: Vec<String>,
    drop_listings: &'a BTreeSet<String>,
    kept: &'a [String],
    name: &'a str,
    lock_entries: &'a [confidant_core::packs::lock::LockEntry],
}

/// `pack remove --allow-unresolved --yes`: drop the pack from `packs` but keep
/// its vendored tree and lock pin (#699). The registry still knows the pack,
/// so its data and `[checks]` keys become durable `W_PACK_ORPHAN` warnings;
/// the post-check gates the commit exactly as a plain removal does, so an
/// unrelated error still rolls back.
pub(crate) fn cmd_pack_unlist(
    cli: &Cli,
    root: &Path,
    plan: UnlistPlan<'_>,
) -> anyhow::Result<ExitCode> {
    let UnlistPlan {
        cfg_text,
        cfg_packs,
        drop_listings,
        kept,
        name,
        lock_entries,
    } = plan;
    let before = pack_orphan_total(root);
    let mut packs = cfg_packs;
    packs.retain(|listed| !drop_listings.contains(listed));
    let contents = confidant_core::config::VaultConfig::set_packs(cfg_text, &packs)
        .map_err(anyhow::Error::new)?;
    let changes = vec![FileChange::WriteFile {
        path: PathBuf::from("confidant.toml"),
        contents,
    }];
    let unlisted: Vec<String> = drop_listings.iter().cloned().collect();
    let summary = format!("pack: unlist {} (keep files)", unlisted.join(", "));
    let pending = PendingWrite {
        changes,
        canonical_request: summary.clone(),
        summary,
    };
    // A listing without a lock pin is the `E_PACK_UNKNOWN` this unlisting
    // repairs, so that case skips the pre-check; the post-check still gates.
    // A healthy listing runs the usual pre-check and refuses unrelated
    // errors before applying anything.
    let all_pinned = unlisted.iter().all(|id| {
        id.split_once('@').is_some_and(|(id_name, id_version)| {
            lock_entries
                .iter()
                .any(|entry| entry.name == id_name && entry.version == id_version)
        })
    });
    let outcome = if all_pinned {
        apply_write(root, pending, &write_options(cli))?
    } else {
        apply_write_repairing(root, pending, &write_options(cli))?
    };
    let applied = matches!(outcome, WriteOutcome::Applied { .. });
    // `new` is the count the unlisting added: a fresh load's warning total
    // minus the pre-removal total. Other disabled packs' warnings sit in both
    // counts and cancel; only data this pack owned appears new.
    let total = if applied {
        pack_orphan_total(root)
    } else {
        before
    };
    let new = total.saturating_sub(before);
    let hint = match &outcome {
        WriteOutcome::CheckBlocked { report } => {
            let owned = installed_pack_tokens(root, name);
            pack_remove_blocked_hint(root, report, name, &owned, true, true)
        }
        _ => None,
    };
    let code = finish_write(
        cli,
        root,
        "pack-remove",
        outcome,
        serde_json::json!({
            "outcome": "unlisted",
            "allow_unresolved": true,
            "unlisted": unlisted,
            "kept": kept,
            "orphans": { "new": new, "total": total },
        }),
    )?;
    if applied && !cli.json {
        println!(
            "unlisted {}: vendored copy and lock entry kept (where present)",
            unlisted
                .iter()
                .map(|id| pack_fetch::escape_line(id))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("check: {total} W_PACK_ORPHAN warning(s), {new} new; the vault stays writable");
        println!(
            "next: migrate or remove the orphaned data (each warning names its file and line), then run"
        );
        println!(
            "  confidant pack remove {} --yes",
            pack_fetch::escape_line(name)
        );
        println!(
            "to keep using it instead, re-list the vendored pack with `confidant pack add --from-dir <pack> --allow-unresolved --yes`"
        );
    }
    if let Some(hint) = hint {
        writeln!(io::stderr(), "{hint}")?;
    }
    Ok(code)
}

/// The number of `W_PACK_ORPHAN` warnings in the vault, read from a fresh
/// load so it matches what the next `check` reports. Zero when the vault
/// cannot be loaded: the write's own post-check has already gated the commit,
/// so this is a reporting convenience, never a gate.
pub(crate) fn pack_orphan_total(root: &Path) -> usize {
    let Ok(vault) = load_vault(root) else {
        return 0;
    };
    check_vault(&vault, &CheckOptions::default())
        .findings
        .iter()
        .filter(|finding| finding.code.as_str() == "W_PACK_ORPHAN")
        .count()
}

/// `pack update <name> --rev <ref>`: re-fetch a new rev, print the diff, and
/// (with `--yes`) re-vendor, re-pin and commit.
pub(crate) fn cmd_pack_update(
    cli: &Cli,
    vault_root: Option<&Path>,
    name: String,
    rev: Option<&str>,
    from_dir: Option<&Path>,
    yes: bool,
) -> anyhow::Result<ExitCode> {
    let root = vault_root_required(vault_root, "pack update")?;
    let lock = read_lockfile_or_empty(root)?;
    let matching: Vec<&confidant_core::packs::lock::LockEntry> =
        lock.packs.iter().filter(|e| e.name == name).collect();
    let entry = match matching.as_slice() {
        [] => {
            return Err(anyhow::Error::new(DomainError::not_found(format!(
                "pack '{name}' is not installed"
            )))
            .with_fix("Run `confidant pack list` to see installed packs"))
        }
        [entry] => *entry,
        _ => {
            return Err(anyhow::Error::new(DomainError::invalid(format!(
                "pack '{name}' is installed at more than one version"
            )))
            .with_fix("Remove the version you do not want, then update again"))
        }
    };
    let source = match (rev, from_dir) {
        (Some(_), Some(_)) => {
            return Err(anyhow::Error::new(DomainError::usage(
                "pass either --rev or --from-dir, not both",
            ))
            .with_fix(
                "Use `pack update <name> --rev <ref>` or `pack update <name> --from-dir <path>`",
            ))
        }
        (None, None) => {
            return Err(anyhow::Error::new(DomainError::usage(
                "pack update needs --rev or --from-dir",
            ))
            .with_fix(
                "Use `pack update <name> --rev <ref>` or `pack update <name> --from-dir <path>`",
            ))
        }
        (Some(rev), None) => {
            if entry.source == "dir" {
                return Err(anyhow::Error::new(DomainError::invalid(format!(
                    "pack '{name}' was installed from a directory, so it has no git source to fetch --rev from"
                )))
                .with_fix("Use `pack update <name> --from-dir <path>` instead"));
            }
            pack_fetch::Source::Https {
                url: entry.source.clone(),
                git_ref: Some(rev.to_owned()),
            }
        }
        (None, Some(dir)) => pack_fetch::parse_add_source(None, Some(dir))?,
    };
    let fetched = pack_fetch::fetch(&source, &entry.subdir)?;
    let report = pack_fetch::describe(&fetched)?;
    refuse_uninstallable(&report.name, &report.version)?;
    if report.name != entry.name {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "the fetched pack is {}, not {}",
            report.name, entry.name
        )))
        .with_fix("Update that pack instead, or add this one"));
    }

    let old_dir = root.join(vendored_rel(&entry.name, &entry.version));
    ensure_vendored_tree_diffable(root, &entry.name, &entry.version)?;
    let diff = pack_fetch::diff_dirs(&old_dir, &fetched.pack_dir)?;
    let new_files = read_pack_dir(&fetched.pack_dir).map_err(anyhow::Error::new)?;
    if new_files.hash != report.hash {
        return Err(anyhow::Error::new(DomainError::conflict(
            "the pack directory changed between the review and the write",
        ))
        .with_fix("Re-run `confidant pack update` and review the diff again"));
    }

    // `--from-dir` on a git-installed pack rewrites the lock `source` to
    // `dir` and drops the rev: say so, rather than silently losing the pin.
    let source_changed = entry.source != fetched.source;
    if source_changed && !cli.json {
        println!(
            "note    the lock source changes from {} to {}",
            pack_fetch::escape_line(&entry.source),
            pack_fetch::escape_line(&fetched.source)
        );
    }

    if !yes {
        // Review gate before applying (PD10): the diff is the whole point of
        // an update.
        let escaped_diff = pack_fetch::escape_text(&diff);
        if cli.json {
            print_json(&ok_envelope(
                Some(root),
                serde_json::json!({
                    "command": "pack-update",
                    "dry_run": true,
                    "pack": {"name": report.name, "version": report.version, "hash": report.hash},
                    "from_version": entry.version,
                    "source_changed": source_changed,
                    "diff": diff,
                }),
            ))?;
        } else {
            println!(
                "{}: {}@{} -> {}@{} ({}..)",
                pack_fetch::escape_line(&report.name),
                pack_fetch::escape_line(&entry.name),
                pack_fetch::escape_line(&entry.version),
                pack_fetch::escape_line(&report.name),
                pack_fetch::escape_line(&report.version),
                short_hash(&report.hash)
            );
            // The diff is `git diff --no-index` over untrusted files: escape
            // control and bidi characters so a hostile pack cannot hide or
            // reorder the lines the operator reviews (#499/PD10).
            print!("{escaped_diff}");
            println!("pass --yes to apply");
        }
        return Ok(ExitCode::SUCCESS);
    }

    // A pin that would not move: the version/source/rev/subdir match and the
    // listing already names it. What to do then depends on the tree and the
    // lock hash.
    //
    // Re-vendoring here instead would emit a `DeleteFile` and a rewrite of
    // every path, and `apply_write`'s Unchanged guard checks each change on
    // its own: the path a `DeleteFile` targets still exists because the same
    // list rewrites it, so the guard misses the net no-op and the empty
    // changeset fails `git commit` with an empty message (#602). The guard's
    // comment says it exists precisely to avoid that empty commit; the
    // delete+rewrite list is what defeated it. Reading the tree off disk
    // (rather than trusting the lock hash) keeps a tampered tree out of this
    // branch: its hash no longer matches the fetched pack, so it falls
    // through to the normal path, where the pre-check reports the mismatch.
    let extra = serde_json::json!({
        "pack": {
            "name": report.name.clone(),
            "version": report.version.clone(),
            "hash": report.hash.clone(),
        },
        "from_version": entry.version.clone(),
        "source_changed": source_changed,
    });
    let pin_metadata_unchanged = entry.version == report.version
        && entry.source == fetched.source
        && entry.rev == fetched.rev
        && entry.subdir == fetched.subdir;
    let listed = {
        let cfg_text = read_config_text(root)?;
        confidant_core::config::VaultConfig::parse(&cfg_text)
            .map_err(anyhow::Error::new)?
            .packs
            .iter()
            .any(|p| p == &format!("{}@{}", report.name, report.version))
    };
    let tree_matches = read_pack_dir(&old_dir).is_ok_and(|dir| dir.hash == report.hash);
    if tree_matches && pin_metadata_unchanged && listed {
        if entry.hash == report.hash {
            // Nothing to do: tree, pin and listing are all current.
            return finish_write(cli, root, "pack-update", WriteOutcome::Unchanged, extra);
        }
        // #606: the installed tree matches the fetched pack but the lock hash
        // is stale. Rewrite the pin so `pack update` is usable as the repair.
        // The stale pin is an E_PACK_HASH error to the pre-check, so the
        // write goes through the repairing path; the post-check still gates
        // the commit, so this cannot leave the vault broken.
        let summary = format!(
            "pack: update {}@{} -> {}@{} ({})",
            entry.name,
            entry.version,
            report.name,
            report.version,
            short_hash(&report.hash)
        );
        let pending = PendingWrite {
            changes: vec![lockfile_change(root, &report, &fetched, None)?],
            canonical_request: summary.clone(),
            summary,
        };
        let outcome = apply_write_repairing(root, pending, &write_options(cli))?;
        return finish_write(cli, root, "pack-update", outcome, extra);
    }

    // Re-vendor: clear the old version's files, then write the new tree and
    // rewrite `confidant.lock`/`confidant.toml` once (the old listing is
    // replaced, not appended).
    let mut changes = delete_vendored_changes(root, &entry.name, &entry.version)?;
    let replace = format!("{}@{}", entry.name, entry.version);
    changes.extend(install_changes(
        root,
        &report,
        &new_files,
        &fetched,
        Some(&replace),
    )?);
    let summary = format!(
        "pack: update {}@{} -> {}@{} ({})",
        entry.name,
        entry.version,
        report.name,
        report.version,
        short_hash(&report.hash)
    );
    let pending = PendingWrite {
        changes,
        canonical_request: summary.clone(),
        summary,
    };
    let outcome = apply_write(root, pending, &write_options(cli))?;
    // A version change leaves the old, now-empty directory behind (git does
    // not track directories). Best-effort cleanup after a successful apply.
    if report.version != entry.version && matches!(outcome, WriteOutcome::Applied { .. }) {
        let _ = std::fs::remove_dir(root.join(vendored_rel(&entry.name, &entry.version)));
    }
    finish_write(cli, root, "pack-update", outcome, extra)
}
