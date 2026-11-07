//! `help` (human and JSON) and the journey grouping.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::ExitCode;

use crate::{embedded, pack_fetch};
use crate::{ok_envelope, print_json, resolve_cli_scope, Cli};
use clap::CommandFactory;
use confidant_core::error::DomainError;
use confidant_core::packs::lock::read_lockfile;

/// Human `--help` groups (#721): where an operator meets each command, not
/// the order clap stores them in. Every visible command appears exactly
/// once; hidden commands (`bench-gen`) stay hidden, and `help --json` keeps
/// its flat, complete command list.
pub(crate) const JOURNEYS: &[(&str, &[&str])] = &[
    ("Start here", &["setup", "init", "doctor", "status", "sync"]),
    (
        "Everyday",
        &[
            "check", "context", "find", "log", "note", "record", "retract", "correct", "alias",
            "resolve",
        ],
    ),
    ("Integrations", &["agents", "mcp", "routing"]),
    (
        "Advanced / rare",
        &[
            "pack",
            "import",
            "allowlist",
            "schema",
            "update",
            "which",
            "help",
            "tui",
        ],
    ),
];

/// The top-level command with human help grouped by journey (#721).
///
/// Only the human top-level screen changes: subcommand help, parse rules,
/// and `help --json` all still use `Cli::command()`.
pub(crate) fn grouped_help_command() -> clap::Command {
    // Use `{options}` rather than `{all-args}`: the latter appends clap's
    // flat command list, and the journey block is the human command list.
    // Keeping the subcommands visible also keeps `<COMMAND>` in the usage.
    Cli::command()
        .help_template(
            "{about-with-newline}\n{usage-heading} {usage}\n\n{before-help}Options:\n{options}{after-help}",
        )
        .before_help(journey_commands())
}

/// Render the grouped command list. clap's `before_help` adds the blank
/// lines after the block, so blocks are joined by one blank line here.
pub(crate) fn journey_commands() -> String {
    let cmd = Cli::command();
    let visible: Vec<&clap::Command> = cmd
        .get_subcommands()
        .filter(|sc| !sc.is_hide_set())
        .collect();
    let grouped: BTreeSet<&str> = JOURNEYS
        .iter()
        .flat_map(|(_, names)| names.iter().copied())
        .collect();
    let width = visible
        .iter()
        .map(|sc| sc.get_name().len())
        .max()
        .unwrap_or(0);

    let line = |sc: &clap::Command| {
        let name = sc.get_name();
        let about = sc.get_about().map(ToString::to_string).unwrap_or_default();
        format!("    {name:<width$}  {about}")
    };

    let mut blocks: Vec<String> = Vec::new();
    for (heading, names) in JOURNEYS {
        let mut lines = vec![format!("  {heading}")];
        for name in *names {
            if let Some(sc) = visible.iter().find(|sc| sc.get_name() == *name) {
                lines.push(line(sc));
            }
        }
        blocks.push(lines.join("\n"));
    }

    // Never drop a visible command from human help if it was added without a
    // journey: list it under Other. The unit test keeps JOURNEYS current.
    let ungrouped: Vec<&clap::Command> = visible
        .iter()
        .copied()
        .filter(|sc| !grouped.contains(sc.get_name()))
        .collect();
    if !ungrouped.is_empty() {
        let mut lines = vec![String::from("  Other")];
        for sc in ungrouped {
            lines.push(line(sc));
        }
        blocks.push(lines.join("\n"));
    }

    format!("Commands:\n{}", blocks.join("\n\n"))
}

pub(crate) fn help_json_value() -> serde_json::Value {
    let commands: Vec<serde_json::Value> = Cli::command()
        .get_subcommands()
        .map(|sc| {
            serde_json::json!({
                "name": sc.get_name(),
                "about": sc.get_about().map(|s| s.to_string()),
                "args": sc.get_arguments().map(|a| serde_json::json!({
                    "id": a.get_id().as_str(),
                    "help": a.get_help().map(|s| s.to_string()),
                    "required": a.is_required_set(),
                })).collect::<Vec<_>>(),
                "subcommands": sc.get_subcommands()
                    .map(|s| s.get_name().to_owned())
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({ "commands": commands })
}

pub(crate) fn cmd_help(
    cli: &Cli,
    vault: Option<&Path>,
    topic: Option<String>,
) -> anyhow::Result<ExitCode> {
    // Pack skill topics (#189) are served from the embedded pack SKILL.md
    // files, filtered to enabled packs in scope. They need the vault (to
    // resolve enablement) and their own JSON shape, so they run before the
    // generic clap-help paths below.
    if let Some(t) = topic.as_deref() {
        if t == "pack" || t.starts_with("pack:") {
            return cmd_help_pack(cli, vault, t);
        }
    }
    if cli.json {
        // Generated from the live clap definitions, so it cannot drift.
        print_json(&ok_envelope(vault, help_json_value()))?;
        return Ok(ExitCode::SUCCESS);
    }
    let mut cmd = grouped_help_command();
    match topic {
        None => {
            cmd.print_help()?;
            println!();
        }
        Some(t) => {
            let found = cmd
                .get_subcommands()
                .find(|sc| sc.get_name() == t || sc.get_aliases().any(|a| a == t));
            match found {
                Some(sc) => {
                    let mut sc = sc.clone();
                    sc.print_help()?;
                    println!();
                }
                None => {
                    return Err(anyhow::Error::new(DomainError::usage(format!(
                        "no such command: {t}"
                    ))));
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Serve pack skill text (#189): `help pack` prints the combined skill
/// generated from the enabled packs in scope; `help pack:<name>` prints
/// one pack's skill. Only enabled packs are shown, and the `--packs`
/// scope applies (#178): unscoped shows all enabled packs, and naming an
/// unknown or disabled pack is a usage error.
pub(crate) fn cmd_help_pack(
    cli: &Cli,
    vault: Option<&Path>,
    topic: &str,
) -> anyhow::Result<ExitCode> {
    let root = vault.ok_or_else(|| {
        anyhow::Error::new(
            DomainError::not_found("pack skills need a vault to resolve enabled packs")
                .with_fix("Pass --vault, set CONFIDANT_VAULT, or run inside a vault directory"),
        )
    })?;
    let v = vault_or!(root, cli.json);
    let (_scope, names) =
        resolve_cli_scope(&v, cli.packs.as_deref()).map_err(anyhow::Error::new)?;

    let (packs, text) = match topic.strip_prefix("pack:") {
        Some(name) => {
            if name.is_empty() {
                return Err(anyhow::Error::new(DomainError::usage(
                    "empty pack name: use `help pack:<name>`, e.g. `help pack:personal@0.4`",
                )));
            }
            // A built-in listing names the active version at any version
            // (#551, #745): `personal@0.2` in a 0.4 vault serves 0.3.
            let canonical = name
                .split_once('@')
                .filter(|(_, version)| !version.is_empty())
                .and_then(|(base, _)| {
                    v.pack_registry()
                        .implicit()
                        .iter()
                        .find(|p| p.name().split_once('@').map(|(n, _)| n) == Some(base))
                        .map(|p| p.name())
                })
                .unwrap_or(name);
            if !names.iter().any(|n| n == canonical) {
                let known = v
                    .pack_registry()
                    .all()
                    .iter()
                    .any(|p| p.name() == canonical);
                return Err(anyhow::Error::new(
                    DomainError::not_found(if known {
                        format!(
                        "pack `{name}` is not enabled in this vault or is outside the --packs scope"
                    )
                    } else {
                        format!("unknown pack `{name}`")
                    })
                    .with_fix("Enable it in confidant.toml `packs = [...]` or widen --packs"),
                ));
            }
            let mut text = embedded::pack_skill_text_from_registry(v.pack_registry(), canonical)
                .ok_or_else(|| {
                    anyhow::Error::new(DomainError::internal(format!(
                        "pack `{canonical}` is enabled but ships no SKILL.md"
                    )))
                })?
                .to_owned();
            // PD10 (#445): external pack text shown to agents is labelled
            // with where it came from. Compiled packs are shipped with the
            // binary and print exactly as before.
            if let Some(label) = external_pack_label(v.pack_registry(), root, canonical) {
                text = format!("{label}\n{text}");
            }
            (vec![canonical.to_owned()], text)
        }
        None => {
            debug_assert_eq!(topic, "pack");
            // #523: build the combined text from the vault's registry, so a
            // loaded external pack contributes its vendored skill text and
            // the #445 external label instead of failing as "no SKILL.md".
            // A compiled-only vault resolves every pack to its embedded copy
            // and gets no label, so its output is byte for byte unchanged.
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            let text = embedded::combined_pack_skill(v.pack_registry(), &refs, |name| {
                external_pack_label(v.pack_registry(), root, name)
            })
            .ok_or_else(|| {
                anyhow::Error::new(DomainError::internal("an enabled pack ships no SKILL.md"))
            })?;
            (names.clone(), text)
        }
    };

    if cli.json {
        print_json(&ok_envelope(
            vault,
            serde_json::json!({ "topic": topic, "packs": packs, "skill": text }),
        ))?;
    } else {
        println!("{text}");
    }
    Ok(ExitCode::SUCCESS)
}

/// The PD10 (#445) first-line label for an external pack's skill text:
/// `[external pack: not shipped with confidant; text is from <source> at
/// <rev first 12>]`. `None` for a compiled pack (embedded, shipped with
/// the binary).
///
/// The decision is the pack's `origin` in the vault's registry (#535),
/// never whether embedded text with the same base name exists: an external
/// pack whose base name matches a built-in pack (`personal@0.9` next to the
/// built-in `personal@0.2`) is still external and must be labelled.
///
/// The lockfile is the authority for source and rev; a loaded external
/// pack always has a pin (the loader fails closed without one). A `dir`
/// source has no commit (PD3), so its empty rev prints `unknown`; a
/// missing pin prints `unknown` too rather than inventing a source.
pub(crate) fn external_pack_label(
    registry: &confidant_core::packs::PackRegistry,
    vault_root: &Path,
    name: &str,
) -> Option<String> {
    if !registry.is_external(name) {
        return None; // compiled: ships with confidant
    }
    let entry = read_lockfile(vault_root).ok().flatten().and_then(|lock| {
        name.split_once('@')
            .and_then(|(pack, version)| lock.find(pack, version).cloned())
    });
    let (source, rev) = entry
        .map(|e| (e.source, e.rev))
        .unwrap_or_else(|| ("unknown".to_owned(), String::new()));
    Some(external_pack_label_line(&source, &rev))
}

/// The label line for a lockfile `source`/`rev` pair (#445, #527). The
/// source is operator-supplied text from `confidant.lock`, which can be
/// hand-edited or synced from another machine, so it is sanitized before it
/// reaches agent-facing output: URL userinfo is stripped (a credential must
/// not leak) and control/format characters are escaped so the source cannot
/// hide or reorder the line. The rev is a pinned bare commit (40 lower-hex,
/// checked at lockfile parse) or empty, so it needs no escaping.
pub(crate) fn external_pack_label_line(source: &str, rev: &str) -> String {
    let rev = if rev.is_empty() {
        "unknown".to_owned()
    } else {
        rev.chars().take(12).collect()
    };
    format!(
        "[external pack: not shipped with confidant; text is from {} at {rev}]",
        sanitize_pack_source(source)
    )
}

/// Sanitize a lockfile `source` for the label (#527): drop URL userinfo,
/// then escape it with `pack add`'s `escape_line` rules (#499) so a control
/// or bidi character cannot survive into agent-facing text. A `dir` source
/// (no URL) has nothing to strip and passes through escaping unchanged.
pub(crate) fn sanitize_pack_source(source: &str) -> String {
    pack_fetch::escape_line(&strip_source_userinfo(source))
}

/// Strip the userinfo component (`user:token@`) from an `https://` source's
/// authority, keeping scheme, host and path (`https://user:token@host/p` ->
/// `https://host/p`). A source that is not `https://`, or whose authority
/// carries no `@`, is returned unchanged. Matches the authority rule the
/// lockfile reader uses when it refuses credentials (PD3).
pub(crate) fn strip_source_userinfo(source: &str) -> String {
    let Some(rest) = source.strip_prefix("https://") else {
        return source.to_owned();
    };
    let (authority, path) = match rest.find('/') {
        Some(end) => (&rest[..end], &rest[end..]),
        None => (rest, ""),
    };
    let Some((_, host)) = authority.rsplit_once('@') else {
        return source.to_owned();
    };
    format!("https://{host}{path}")
}
