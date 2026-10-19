//! `confidant pack init`: scaffold a local external pack (#674).
//!
//! The scaffold is deliberately small and valid as written: a v2 manifest
//! with no claims, the agent-facing `SKILL.md`, the human contract
//! (`<version>.md`), and a `README.md` describing the local review loop.
//! Every example in the manifest is a comment, so a fresh directory parses
//! before its author edits a line.
//!
//! The command writes only into a new (or existing empty) directory, never
//! through a symlink, and validates the result with the same
//! [`read_pack_dir`] and [`parse_manifest_external`] the installer uses. If
//! that validation fails, the directory it created is removed again.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use confidant_core::error::DomainError;
use confidant_core::packs::dir::read_pack_dir;
use confidant_core::packs::manifest::{
    is_reserved_pack_name, is_valid_pack_name, parse_manifest_external,
};

use crate::FixExt;

/// What [`init`] planned or wrote.
#[derive(Debug, Clone)]
pub(crate) struct InitReport {
    pub dir: PathBuf,
    pub name: String,
    pub version: String,
    /// Pack-relative file names, in the order they were written.
    pub files: Vec<String>,
    pub dry_run: bool,
}

/// Scaffold an external pack at `dir`.
///
/// `name` defaults to the directory's basename; `version` defaults to `0.1`
/// and must be `major.minor`. A missing directory is created (parents
/// included); an existing directory must be empty. With `dry_run`, the plan
/// is validated and returned without touching the filesystem.
pub(crate) fn init(
    dir: &Path,
    name: Option<&str>,
    version: Option<&str>,
    dry_run: bool,
) -> anyhow::Result<InitReport> {
    let version = version.unwrap_or("0.1").to_owned();
    validate_version(&version)?;
    let name = match name {
        Some(name) => name.to_owned(),
        None => default_name(dir)?,
    };
    validate_name(&name)?;

    let exists = inspect_dir(dir)?;
    let files = vec![
        "manifest.toml".to_owned(),
        "SKILL.md".to_owned(),
        format!("{version}.md"),
        "README.md".to_owned(),
    ];
    let manifest = manifest_text(&name, &version);
    let contents = [
        manifest.as_str(),
        &skill_text(&name),
        &contract_text(&name, &version),
        &readme_text(&name, &version),
    ];

    // Validate the manifest before writing even in a dry run: a scaffold
    // must not be born broken, and `--dry-run` should report the same
    // failure the real run would.
    parse_manifest_external(&manifest).map_err(anyhow::Error::new)?;

    let report = InitReport {
        dir: dir.to_path_buf(),
        name,
        version,
        files,
        dry_run,
    };
    if dry_run {
        return Ok(report);
    }

    let created_dir = !exists;
    if created_dir {
        std::fs::create_dir_all(dir).map_err(|e| {
            anyhow::Error::new(DomainError::internal(format!(
                "cannot create {}: {e}",
                dir.display()
            )))
        })?;
    }

    for (written, (rel, body)) in report.files.iter().zip(contents).enumerate() {
        if let Err(err) = write_new(dir, rel, body) {
            cleanup(dir, &report.files[..written], created_dir);
            return Err(err);
        }
    }

    if let Err(err) = validate_written(dir, &report.name, &report.version) {
        cleanup(dir, &report.files, created_dir);
        return Err(err);
    }
    Ok(report)
}

/// The directory basename, or a clear error when there is none (`.`, `..`).
fn default_name(dir: &Path) -> anyhow::Result<String> {
    dir.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            anyhow::Error::new(DomainError::usage(
                "cannot derive a pack name from the directory",
            ))
            .with_fix("Pass --name with a lowercase pack name")
        })
}

/// Validate a pack name against the v2 grammar and the reserved list.
fn validate_name(name: &str) -> anyhow::Result<()> {
    let escaped = confidant_core::packs::untrusted::escape_line(name);
    if is_reserved_pack_name(name) {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "pack name '{escaped}' is reserved for the built-in personal pack"
        )))
        .with_fix("Choose a different pack name"));
    }
    if !is_valid_pack_name(name) {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "pack name '{escaped}' does not match ^[a-z][a-z0-9-]{{1,31}}$"
        )))
        .with_fix(
            "Use 2 to 32 characters: a lowercase letter, then lowercase \
             letters, digits or hyphens",
        ));
    }
    Ok(())
}

/// Validate `major.minor`. External packs in this repo use `0.1`; the
/// manifest itself only requires a non-empty version, but a scaffold should
/// not teach a version that `pack add` cannot use as a directory segment.
fn validate_version(version: &str) -> anyhow::Result<()> {
    let escaped = confidant_core::packs::untrusted::escape_line(version);
    let parts: Vec<&str> = version.split('.').collect();
    let valid = parts.len() == 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && crate::is_safe_version_part(version);
    if !valid {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "pack version '{escaped}' is not major.minor"
        )))
        .with_fix("Use two dot-separated numbers, for example --version 0.1"));
    }
    Ok(())
}

/// `Ok(false)` when `dir` is absent, `Ok(true)` when it is an empty
/// directory. A symlink is refused even when it points at a directory.
fn inspect_dir(dir: &Path) -> anyhow::Result<bool> {
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(anyhow::Error::new(DomainError::internal(format!(
                "cannot inspect {}: {err}",
                dir.display()
            ))))
        }
    };
    if meta.file_type().is_symlink() {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "refusing to scaffold through the symlink {}",
            dir.display()
        )))
        .with_fix("Point at a new directory, or pass a real directory path"));
    }
    if !meta.is_dir() {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "{} is not a directory",
            dir.display()
        )))
        .with_fix("Point at a new directory, or pass --name with an empty one"));
    }
    let mut entries = std::fs::read_dir(dir).map_err(|err| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot read {}: {err}",
            dir.display()
        )))
    })?;
    if entries.next().is_some() {
        return Err(anyhow::Error::new(DomainError::invalid(format!(
            "refusing to scaffold into the non-empty directory {}",
            dir.display()
        )))
        .with_fix("Choose a new or empty directory; pack init never overwrites"));
    }
    Ok(true)
}

/// Write a file that must not already exist. `create_new` refuses to follow
/// an existing symlink as well as overwriting a regular file.
fn write_new(dir: &Path, rel: &str, body: &str) -> anyhow::Result<()> {
    let path = dir.join(rel);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|err| {
            anyhow::Error::new(DomainError::internal(format!(
                "cannot write {}: {err}",
                path.display()
            )))
        })?;
    file.write_all(body.as_bytes()).map_err(|err| {
        anyhow::Error::new(DomainError::internal(format!(
            "cannot write {}: {err}",
            path.display()
        )))
    })
}

/// Remove the files this run wrote (and the directory, when this run created
/// it). Best-effort: the original error is the one worth reporting.
fn cleanup(dir: &Path, files: &[String], created_dir: bool) {
    for rel in files {
        let _ = std::fs::remove_file(dir.join(rel));
    }
    if created_dir {
        let _ = std::fs::remove_dir(dir);
    }
}

/// Re-read and parse the scaffold with the installer's readers. A template
/// bug (or an environment that changed the bytes) must not leave a broken
/// pack behind.
fn validate_written(dir: &Path, name: &str, version: &str) -> anyhow::Result<()> {
    let pack_dir = read_pack_dir(dir).map_err(anyhow::Error::new)?;
    let manifest_bytes = pack_dir.files.get("manifest.toml").ok_or_else(|| {
        anyhow::Error::new(DomainError::internal(
            "the scaffold has no manifest.toml after writing",
        ))
    })?;
    let text = std::str::from_utf8(manifest_bytes).map_err(|_| {
        anyhow::Error::new(DomainError::internal(
            "the scaffold manifest is not valid UTF-8",
        ))
    })?;
    let manifest = parse_manifest_external(text).map_err(anyhow::Error::new)?;
    if manifest.pack.name != name || manifest.pack.version != version {
        return Err(anyhow::Error::new(DomainError::internal(
            "the scaffold manifest does not name the requested pack",
        )));
    }
    Ok(())
}

fn manifest_text(name: &str, version: &str) -> String {
    MANIFEST_TEMPLATE
        .replace("@NAME@", name)
        .replace("@VERSION@", version)
}

fn skill_text(name: &str) -> String {
    SKILL_TEMPLATE.replace("@NAME@", name)
}

fn contract_text(name: &str, version: &str) -> String {
    CONTRACT_TEMPLATE
        .replace("@NAME@", name)
        .replace("@VERSION@", version)
}

fn readme_text(name: &str, version: &str) -> String {
    README_TEMPLATE
        .replace("@NAME@", name)
        .replace("@VERSION@", version)
}

/// A valid v2 skeleton. Every example is commented out, so the file parses
/// exactly as written; each example names real keys from the manifest spec.
const MANIFEST_TEMPLATE: &str = r#"# Confidant external pack manifest (spec/pack-manifest.md §13).
#
# This file is the pack's declarative contract. It names claims and rule
# kinds; the CLI supplies every parser, fold and finding. Pack text never
# executes. Unknown keys are an error, and a claim that collides with core
# or with another enabled pack is refused.
manifest_version = 2

# Top-level keys must come before the first [table] header.
record_types = []
balance_metrics = []
finding_codes = []

[pack]
name = "@NAME@"
version = "@VERSION@"
# The skill served to agents from this pack directory.
skill = "SKILL.md"
# Exact vault spec versions this pack supports.
requires_spec = ["0.1"]

# Finding message templates, one table per code ([messages."<CODE>"]). The
# empty table is required even while no code is declared; see the example
# below.
[messages]

# ---------------------------------------------------------------------------
# Examples. Everything below is commented out, so this manifest parses as
# written. Uncomment only what the pack needs, then review it with:
#   confidant pack add --from-dir <this-directory>
# ---------------------------------------------------------------------------

# A front-matter field this pack owns. `grammar` names a fixed parser from
# spec/pack-manifest.md §6: recurring-date, cadence, date, non-empty-string,
# list, labeled-list, or dates-list. Declaring a field also requires
# E_FRONTMATTER in finding_codes, with a [messages."E_FRONTMATTER"] table.
# [[fields]]
# name = "example_birthday"
# grammar = "recurring-date"

# A ledger verb this pack owns. Core verbs (alias, merge, stage, balance,
# touch) are refused. `id_type`, when present, is one of person, org, deal,
# interaction, note, edge, or package.
# [[verbs]]
# name = "greet"
# id_type = "person"

# A severity key the operator can tune in confidant.toml. Keys are
# namespaced to this pack; the default is error, warning, or off.
# [[checks.severity]]
# key = "@NAME@.example_rule"
# default = "warning"

# A finding code and its message template. Add the code to finding_codes
# above first (for example ["W_EXAMPLE_REMINDER"]). Codes match
# ^[EW]_[A-Z0-9_]{2,40}$ and must not reuse a core or compiled-pack code.
# `default` and `default_fix` are the variant names for rules that use the
# `default` variant; check the kind's section in the spec.
# [messages."W_EXAMPLE_REMINDER"]
# default = "person {id} has an upcoming date on {occ} ({delta} days)"
# default_fix = "Log a touchpoint with `confidant log touch {id} <kind>`"

# A declarative rule emits a finding by naming a core rule kind. The logic
# lives in the CLI; the manifest supplies parameters only. This example uses
# the `date-upcoming` kind, so it needs the `example_birthday` field above
# and both check keys below. See the kind's parameter table in the spec.
# [[rules]]
# id = "example_dates"
# kind = "date-upcoming"
# code = "W_EXAMPLE_REMINDER"
# severity_key = "@NAME@.example_rule"
# date_fields = ["example_birthday"]
# window_key = "@NAME@.example_window_days"

# A non-negative integer check key (a window in days, a count).
# [[checks.int]]
# key = "@NAME@.example_window_days"
# default = 7
"#;

/// Agent-facing text. It becomes instructions, so its first rule is
/// propose-then-wait.
const SKILL_TEMPLATE: &str = r#"---
name: "@NAME@"
description: "@NAME@ pack for a Confidant vault. Declarative claims only; propose changes and wait for explicit operator confirmation before installing or updating."
---

# @NAME@ pack

This pack extends a Confidant vault's vocabulary (fields, verbs, finding
codes and checks) through `manifest.toml`. It carries no executable code:
every parser, fold and finding runs in the CLI, and a pack cannot add Rust
logic.

## When to use it

Use this skill when the operator asks for a claim or check this pack owns,
or when an agent proposes a new declarative rule. Do not use it to change
core behaviour; that needs a Confidant core change.

## Propose, then wait

1. Read `manifest.toml` and this file. State the claims in plain language:
   verbs, fields, finding codes, and each rule's parameters.
2. Show the operator the exact manifest and SKILL.md diff. Pack text becomes
   agent instructions, so the operator must read it.
3. Wait for explicit confirmation. Never install, update, or commit a pack
   on your own.
4. After confirmation, install or update with the commands in `README.md`,
   then run `confidant check --json --no-input` and `confidant pack verify`.
5. If a check reports a finding, report it. Never silence it by editing the
   vault or the pack without the operator's confirmation.

## Boundaries

- A pack cannot widen the §12 allowlist or read `no-ai` content. The CLI
  enforces that; pack text cannot change it.
- A pack cannot add code, run scripts, or define a new rule kind. New logic
  is a core change.
- Keep claims namespaced to this pack (`@NAME@.<key>`), and never reuse a
  core verb, record type, edge kind, or finding code.
"#;

/// Human contract: what the pack claims and where to edit it.
const CONTRACT_TEMPLATE: &str = r#"# @NAME@ @VERSION@

## What this pack claims

Nothing yet. The starter manifest declares no fields, verbs, edge kinds,
balance metrics, finding codes, or rules.

## The contract

`manifest.toml` is the single source of truth. It may claim:

- `[[fields]]` — front-matter fields and one of the fixed grammars;
- `[[verbs]]` — ledger verbs (never a core verb);
- `[[edge_kinds]]` — relationship kinds and symmetry;
- `balance_metrics` — metrics a compiled fold computes;
- `finding_codes` plus `[messages.<CODE>]` — the text the pack can emit;
- `[checks]` — operator-tunable severity and integer keys;
- `[[rules]]` — parameters for a core rule kind.

It cannot claim behaviour. `fold`, `findings`, balance math, date math and
every grammar parser stay in Confidant's Rust core; adding a rule kind is a
core change (spec/pack-manifest.md §13.2).

## Editing

Keep the source outside the vault. Edit `manifest.toml` and this file
together, then review the result:

```sh
confidant pack add --from-dir <this-directory>
```

Bump `[pack].version` and rename this file to `<new-version>.md` whenever
the claims change: installed vaults pin `name@version`.

## Install and update

```sh
confidant pack add --from-dir <this-directory> --yes
confidant pack verify
confidant pack update @NAME@ --from-dir <this-directory> --yes
```
"#;

/// The local loop and the trust boundary, for whoever opens the directory.
const README_TEMPLATE: &str = r#"# @NAME@

A local Confidant schema pack, version @VERSION@. It is data and agent text:
the CLI reads it, and nothing in this directory executes.

## Where to edit

Keep this directory outside the vault, for example
`~/confidant-packs/@NAME@/`. The generated copy under `<vault>/packs/` is
vendored and pinned by `confidant.lock`; it is not the editing surface, and
edits there are overwritten by the next install.

## Review, install, verify

```sh
# Review: validates the pack and prints every claim and the skill text.
# Writes nothing.
confidant pack add --from-dir <this-directory>

# Install after the operator has read the review.
confidant pack add --from-dir <this-directory> --yes

confidant check --json --no-input
confidant pack verify
```

## Iterate

1. Edit `manifest.toml` (and `SKILL.md` / `<version>.md`).
2. Bump `[pack].version` and rename the contract file to `<new-version>.md`.
3. Review again: `confidant pack add --from-dir <this-directory>`.
4. Apply: `confidant pack update @NAME@ --from-dir <this-directory> --yes`.
5. Run `confidant check --json --no-input` and `confidant pack verify`.

## Trust

- No code runs from this pack. The CLI reads claims and text only.
- A pack cannot widen the §12 allowlist or read `no-ai` content; that is
  enforced by the CLI, not by pack text.
- A local install is unsigned but hash-pinned. `pack verify` detects drift.
- `SKILL.md` becomes agent instructions. Review it as carefully as code.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pack_parses() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("example-pack");
        let report = init(&dir, None, None, false).expect("scaffold");

        assert_eq!(report.name, "example-pack");
        assert_eq!(report.version, "0.1");
        assert_eq!(report.dir, dir);
        assert!(!report.dry_run);
        assert_eq!(
            report.files,
            vec!["manifest.toml", "SKILL.md", "0.1.md", "README.md"]
        );

        let pack = read_pack_dir(&dir).expect("read pack dir");
        let manifest = parse_manifest_external(
            std::str::from_utf8(pack.files.get("manifest.toml").unwrap()).unwrap(),
        )
        .expect("generated manifest parses");
        assert_eq!(manifest.pack.name, "example-pack");
        assert_eq!(manifest.pack.version, "0.1");
        assert_eq!(manifest.pack.skill, "SKILL.md");
        assert_eq!(manifest.pack.requires_spec, vec!["0.1".to_owned()]);
        assert!(manifest.record_types.is_empty());
        assert!(manifest.balance_metrics.is_empty());
        assert!(manifest.finding_codes.is_empty());
        assert!(manifest.verbs.is_empty());
        assert!(manifest.fields.is_empty());

        let skill = std::str::from_utf8(pack.files.get("SKILL.md").unwrap()).unwrap();
        assert!(skill.contains("Never install, update, or commit"));
        assert!(skill.contains("cannot widen the §12 allowlist"));
    }

    #[test]
    fn defaults_name_from_the_directory_and_version() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("weekly-checkin");
        let report = init(&dir, None, None, false).expect("scaffold");
        assert_eq!(report.name, "weekly-checkin");
        assert_eq!(report.version, "0.1");
        assert!(dir.join("0.1.md").is_file());
    }

    #[test]
    fn accepts_an_existing_empty_directory_and_a_custom_version() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("local-pack");
        std::fs::create_dir(&dir).unwrap();
        let report = init(&dir, None, Some("1.2"), false).expect("scaffold");
        assert_eq!(report.version, "1.2");
        assert!(dir.join("1.2.md").is_file());
    }

    #[test]
    fn rejects_reserved_and_malformed_names() {
        let parent = tempfile::tempdir().unwrap();
        for name in ["personal", "Example", "a", "has_underscore", "with space"] {
            let dir = parent.path().join(format!("pack-{name}"));
            let err = init(&dir, Some(name), None, false).expect_err(name);
            assert_eq!(DomainError::of(&err).unwrap().exit_code(), 1, "{name}");
            assert!(!dir.exists(), "{name} wrote a directory");
        }
    }

    #[test]
    fn rejects_malformed_versions() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("example-pack");
        for version in ["", "1", "0.1.2", "v0.1", "0..1", "../0.1", "0.1 "] {
            let err = init(&dir, None, Some(version), false).expect_err(version);
            assert_eq!(DomainError::of(&err).unwrap().exit_code(), 1, "{version}");
            assert!(!dir.exists(), "{version} wrote a directory");
        }
    }

    #[test]
    fn refuses_a_non_empty_directory_without_touching_it() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("occupied");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("keep.txt"), "user data").unwrap();

        let err = init(&dir, None, None, false).expect_err("non-empty dir");
        assert!(err.to_string().contains("non-empty"), "{err}");
        assert_eq!(
            std::fs::read_to_string(dir.join("keep.txt")).unwrap(),
            "user data"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn dry_run_writes_nothing_and_reports_the_plan() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("planned");
        let report = init(&dir, None, None, true).expect("plan");
        assert!(report.dry_run);
        assert_eq!(report.files.len(), 4);
        assert!(!dir.exists());
    }

    #[test]
    fn dry_run_still_refuses_an_occupied_directory() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("occupied");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("keep.txt"), "user data").unwrap();
        assert!(init(&dir, None, None, true).is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_directory() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = init(&link, None, None, false).expect_err("symlink");
        assert!(err.to_string().contains("symlink"), "{err}");
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    }

    #[test]
    fn generated_skill_and_contract_use_the_pack_name() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("named-pack");
        init(&dir, Some("named-pack"), Some("0.2"), false).expect("scaffold");
        let skill = std::fs::read_to_string(dir.join("SKILL.md")).unwrap();
        let contract = std::fs::read_to_string(dir.join("0.2.md")).unwrap();
        let readme = std::fs::read_to_string(dir.join("README.md")).unwrap();
        assert!(skill.contains("name: \"named-pack\""), "{skill}");
        assert!(contract.contains("# named-pack 0.2"), "{contract}");
        assert!(
            readme.contains("confidant pack update named-pack"),
            "{readme}"
        );
    }

    /// The commented examples must name real keys. Uncomment the code-like
    /// lines and parse the result: a future edit that invents a key or a
    /// grammar fails here rather than in an operator's first install.
    #[test]
    fn fully_expanded_examples_parse() {
        let text = manifest_text("example-pack", "0.1").replace(
            "finding_codes = []",
            "finding_codes = [\"E_FRONTMATTER\", \"W_EXAMPLE_REMINDER\"]",
        );
        let mut expanded = String::new();
        let mut in_examples = false;
        for line in text.lines() {
            if line.contains("# Examples.") {
                in_examples = true;
            }
            if in_examples {
                if let Some(body) = line.strip_prefix("# ") {
                    if is_example_code_line(body) {
                        expanded.push_str(body);
                        expanded.push('\n');
                        continue;
                    }
                }
            }
            expanded.push_str(line);
            expanded.push('\n');
        }
        // A field requires the core front-matter code; the prose says so,
        // but the code table itself is not part of the example set.
        expanded.push_str(
            "\n[messages.\"E_FRONTMATTER\"]\n\
             default = \"front matter key {key} {problem}\"\n\
             default_fix = \"{fix}\"\n",
        );
        let manifest =
            parse_manifest_external(&expanded).expect("every commented example is schema-valid");
        assert_eq!(manifest.fields.len(), 1);
        assert_eq!(manifest.verbs.len(), 1);
        assert_eq!(manifest.rules.len(), 1);
        assert_eq!(manifest.checks.severity.len(), 1);
        assert_eq!(manifest.checks.int.len(), 1);
    }

    fn is_example_code_line(body: &str) -> bool {
        const PREFIXES: &[&str] = &[
            "[",
            "name =",
            "grammar =",
            "id_type =",
            "key =",
            "default =",
            "id =",
            "kind =",
            "code =",
            "severity_key =",
            "date_fields =",
            "window_key =",
        ];
        PREFIXES.iter().any(|prefix| body.starts_with(prefix))
    }
}
