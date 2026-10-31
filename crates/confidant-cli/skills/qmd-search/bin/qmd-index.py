#!/usr/bin/env python3
"""Build (or rebuild) the QMD search corpus + collection for a vault.

Usage: qmd-index.py [--vault PATH] [--cli PATH] [--embed] [--skip-preflight]

Ends by running the sibling qmd-preflight.py (issue #722) with
--persist unless --skip-preflight is given, so setup itself both
surfaces a cold-start or unreachable-hub problem AND records the
recommendation where qmd-query.py honors it, instead of leaving either
for the first real query.

The corpus is staged from the CLI's cleared set (issue #795). The vault is
plaintext on disk now, so there is no decryption step and no
`confidant reindex` command:

- `confidant allowlist --json` is the single source of truth for §12
  clearance. This script copies each cleared record file to
  `<vault>/.confidant/qmd-corpus/<rel>`, and copies only the cleared
  1-based lines of each cleared ledger file to
  `<vault>/.confidant/qmd-corpus/<rel>.md` (the `.cfd.md` suffix QMD's
  `**/*.md` collection pattern needs). `no-ai` records stay out by
  construction, because the CLI never lists them as cleared. A full
  rebuild: the old corpus is wiped first.
- Registers the corpus as the `confidant` QMD collection (removing any
  previous one first, so rebuilds are idempotent).
- --embed runs `qmd embed` afterwards for vector search (downloads models
  on first run; keyword-only `search` works without it).

Guardrails (the skill owns them now that it writes the corpus):
- The corpus is plaintext and local. Before writing, refuse unless
  `.confidant/` is git-ignored in the vault's repo (a vault that is not a
  git repo yet, or a host without git, gets a loud warning instead); write
  the corpus dir `0700` and its files `0600`.
- QMD's own store is moved under <vault>/.confidant/qmd/ (INDEX_PATH +
  QMD_CONFIG_DIR env), created 0700; on macOS it is added to the Time
  Machine exclusion list. A previous default-store `confidant` collection
  is removed on first run (migration).

Re-run after pulls/merges/writes. A stale index cannot return a record or
ledger line the CLI does not clear — query-time allowlist filtering runs
against the live cleared set (#538). It can still miss or mislabel results,
or return a stale snippet of a still-cleared record: excerpts come from the
corpus copy, so a note edited in the vault keeps returning its old text
until this script reruns. In a ledger file, an edited or removed vault line
now costs only the corpus lines that no longer align: the line map is built
from a text index and every other line still resolves (fail closed per
line), and a rerun clears it.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

COLLECTION = "confidant"
CORPUS_REL = os.path.join(".confidant", "qmd-corpus")
STORE_REL = os.path.join(".confidant", "qmd")
LEDGER_SUFFIX = ".cfd"


def resolve_vault(explicit):
    if explicit:
        vault = explicit
    else:
        vault = os.environ.get("CONFIDANT_VAULT")
    if not vault:
        sys.exit("error: no vault: pass --vault or set CONFIDANT_VAULT")
    vault = os.path.abspath(os.path.expanduser(vault))
    if not os.path.isfile(os.path.join(vault, "confidant.toml")):
        sys.exit(f"error: {vault} does not look like a vault (no confidant.toml)")
    return vault


def ensure_corpus_gitignored(vault):
    """Refuse to write the plaintext corpus into a tracked directory.

    The corpus is a readable mirror of cleared vault content, so it must
    stay under the gitignored `.confidant/`. Mirrors the CLI's own check on
    writes: a missing git binary, or a vault that is not a git repo yet,
    only warns — the corpus is local either way and the operator is told
    what to add before committing.
    """
    git = shutil.which("git")
    if git is None:
        print("warning: git not found; cannot check that `.confidant/` is "
              "git-ignored. The corpus is a plaintext mirror — add "
              "`.confidant/` to .gitignore before this vault is committed.",
              file=sys.stderr)
        return
    repo = subprocess.run([git, "-C", vault, "rev-parse", "--git-dir"],
                          capture_output=True, text=True)
    if repo.returncode != 0:
        print("warning: this vault is not a git repo yet; the `.confidant/` "
              "gitignore check is skipped. Add `.confidant/` to .gitignore "
              "before initializing a repo and committing.", file=sys.stderr)
        return
    probe = subprocess.run([git, "-C", vault, "check-ignore", "-q",
                            ".confidant/.probe"], capture_output=True)
    if probe.returncode == 0:
        return
    sys.exit("error: refusing to build the search corpus: `.confidant/` is "
             "not git-ignored in this vault.\n"
             "The corpus is a plaintext mirror of cleared records and must "
             "never be committed.\n"
             "Fix: echo '.confidant/' >> "
             + os.path.join(vault, ".gitignore"))


def _read_vault_lines(path):
    """File lines split on '\\n' (like the CLI's ledger reader), or None."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError):
        return None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def stage_cleared_corpus(vault, cli=None):
    """Copy the §12 cleared set into `<vault>/.confidant/qmd-corpus/`.

    The vault is plaintext on disk (issue #795), so staging is a copy, not
    a decryption: `confidant allowlist --json` is the single source of truth
    for clearance, and everything it does not list stays out of the corpus.

    - Cleared record files are copied whole, preserving relative paths.
    - A cleared ledger file is mirrored as `<rel>.md` (the suffix QMD's
      `**/*.md` collection pattern requires) with only its cleared 1-based
      lines, in vault order.
    - The corpus dir is rebuilt from scratch, `0700`, its files `0600`.
    - Refuses (writes nothing) when `.confidant/` is not git-ignored.

    Returns (corpus_path, record_files_written, ledger_lines_written).
    """
    ensure_corpus_gitignored(vault)
    exe = cli or shutil.which("confidant")
    if exe is None:
        sys.exit("error: `confidant` not found. Pass --cli PATH or put it on "
                 "PATH; the cleared set comes from the CLI (ADR-6).")
    try:
        p = subprocess.run([exe, "allowlist", "--json", "--no-input",
                            "--vault", vault],
                           capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as e:
        sys.exit(f"error: `confidant allowlist` could not run: {e}")
    try:
        data = json.loads(p.stdout)
    except ValueError:
        data = None
    if p.returncode != 0 or not isinstance(data, dict) or not data.get("ok"):
        detail = (p.stderr or "").strip() or (p.stdout or "").strip()
        if isinstance(data, dict) and isinstance(data.get("error"), dict):
            err = data["error"]
            detail = f"{err.get('code')}: {err.get('message')}"
            if err.get("fix"):
                detail += f"\n  fix: {err['fix']}"
        sys.exit("error: `confidant allowlist` failed "
                 f"(exit {p.returncode}):\n{detail}")

    corpus = os.path.join(vault, CORPUS_REL)
    if os.path.isdir(corpus):
        shutil.rmtree(corpus)
    os.makedirs(corpus, mode=0o700, exist_ok=True)
    os.chmod(corpus, 0o700)

    record_files = [f for f in data.get("cleared_files", [])
                    if isinstance(f, str)]
    for rel in record_files:
        src = os.path.join(vault, rel)
        dest = os.path.join(corpus, rel)
        if not os.path.isfile(src):
            sys.exit(f"error: cleared record vanished during staging: {rel}")
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        shutil.copyfile(src, dest)
        os.chmod(dest, 0o600)

    ledger_lines = {}
    for entry in data.get("cleared_ledger_lines", []):
        if not isinstance(entry, dict):
            continue
        rel, line = entry.get("file"), entry.get("line")
        if isinstance(rel, str) and isinstance(line, int) and line > 0:
            ledger_lines.setdefault(rel, []).append(line)

    ledger_written = 0
    for rel, line_numbers in ledger_lines.items():
        if not rel.endswith(LEDGER_SUFFIX):
            continue
        vault_lines = _read_vault_lines(os.path.join(vault, rel))
        if vault_lines is None:
            sys.exit(f"error: cannot read cleared ledger file: {rel}")
        dest = os.path.join(corpus, rel + ".md")
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as out:
            for n in sorted(set(line_numbers)):
                if n > len(vault_lines):
                    continue  # stale line number: fail closed, skip it
                out.write(vault_lines[n - 1] + "\n")
                ledger_written += 1
        os.chmod(dest, 0o600)

    print(f"corpus: {corpus} ({len(record_files)} files)")
    print(f"  ledger: {ledger_written} cleared line(s) in "
          f"{len(ledger_lines)} file(s)")
    return corpus, len(record_files), ledger_written


def qmd_store_paths(vault):
    """QMD's own index store lives under the vault, never in ~/.cache."""
    store = os.path.join(vault, STORE_REL)
    return store, os.path.join(store, "index.sqlite"), os.path.join(store, "config")


def qmd_env(vault):
    """Env moving QMD's index DB + collection registry under the vault."""
    store, db, config = qmd_store_paths(vault)
    env = dict(os.environ)
    env["INDEX_PATH"] = db        # SQLite index location (documented override)
    env["QMD_CONFIG_DIR"] = config  # collection registry (documented override)
    return env


def ensure_store_dirs(vault):
    """Create the vault-local QMD store 0700 (before any index writes)."""
    store, _db, _config = qmd_store_paths(vault)
    os.makedirs(store, mode=0o700, exist_ok=True)
    os.chmod(store, 0o700)


def exclude_from_backups(vault):
    """Keep the plaintext corpus and index out of macOS Time Machine backups.

    Must run AFTER the corpus is (re)built: a rebuild wipes and recreates
    the corpus dir, which would destroy an exclusion set earlier.
    Best-effort: warns loudly on failure but does not refuse (the primary
    protections are the gitignore refusal and the 0700/0600 modes).
    """
    if sys.platform != "darwin" or shutil.which("tmutil") is None:
        return
    store, _db, _config = qmd_store_paths(vault)
    for path in (os.path.join(vault, CORPUS_REL), store):
        try:
            p = subprocess.run(["tmutil", "addexclusion", path],
                               capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as e:
            print(f"warning: tmutil addexclusion failed for {path}: {e}",
                  file=sys.stderr)
            continue
        if p.returncode != 0:
            print(f"warning: tmutil addexclusion failed for {path}: "
                  f"{p.stderr.strip()}", file=sys.stderr)
        else:
            print(f"time machine: excluded {path}")


def migrate_default_store():
    """Best-effort: drop the `confidant` collection from qmd's default store.

    Previous versions registered the collection in the default store
    (~/.cache/qmd); the store now lives under the vault. Leaving the old
    registration would keep plaintext indexed outside the vault.
    """
    if shutil.which("qmd") is None:
        return
    env = {k: v for k, v in os.environ.items()
           if k not in ("INDEX_PATH", "QMD_CONFIG_DIR")}
    try:
        lst = subprocess.run(["qmd", "collection", "list"], capture_output=True,
                             text=True, timeout=30, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return
    if re.search(rf"(?m)^{re.escape(COLLECTION)} ", lst.stdout or ""):
        try:
            subprocess.run(["qmd", "collection", "remove", COLLECTION],
                           capture_output=True, timeout=60, env=env)
            print(f"migrated: removed '{COLLECTION}' collection "
                  f"from qmd's default store")
        except (OSError, subprocess.TimeoutExpired):
            print("warning: could not remove old default-store collection; "
                  "remove it manually: qmd collection remove confidant",
                  file=sys.stderr)


def run_qmd(args, env, check=True):
    if shutil.which("qmd") is None:
        sys.exit("error: `qmd` not found. Install it first: npm install -g @tobilu/qmd")
    p = subprocess.run(["qmd"] + args, capture_output=True, text=True, env=env)
    if check and p.returncode != 0:
        sys.exit(f"error: qmd {' '.join(args)} failed:\n{p.stderr.strip()}")
    return p


def run_setup_preflight(preflight, vault):
    """Run preflight as the last setup step, recording via --persist.

    The offline decision must land in the vault-local [qmd] preflight
    file during setup itself (issue #722 item 3): a report-only
    auto-run would leave the operator to rerun preflight with
    --persist by hand before the query wrapper honored anything.
    The run passes --chained, so it never writes default_mode,
    whatever the probe returns (#778 fix round): a mode change
    needs an explicit --query preflight run, and the settled
    fallback applies until then. Returns the preflight exit code;
    a nonzero code is reported as a rerun note, never a setup failure
    — the index build above already succeeded.
    """
    p = subprocess.run([sys.executable, preflight, "--vault", vault,
                        "--persist", "--chained"], capture_output=False)
    if p.returncode != 0:
        print("note: qmd-preflight.py did not complete (exit "
              f"{p.returncode}); the index above is still built — rerun "
              "bin/qmd-preflight.py --vault " + vault + " --persist "
              "--query <term> on its own to record a default mode")
    return p.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=None)
    ap.add_argument("--embed", action="store_true",
                    help="run `qmd embed` after indexing (enables vector search)")
    ap.add_argument("--cli", default=None,
                    help="path to the confidant binary whose allowlist defines "
                         "the cleared set (default: confidant on PATH)")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="skip the automatic qmd-preflight.py run at the "
                         "end of setup (issue #722: preflight is part of "
                         "setup so the first real query is not the first "
                         "cold-start surprise)")
    args = ap.parse_args()

    vault = resolve_vault(args.vault)
    ensure_store_dirs(vault)
    migrate_default_store()

    env = qmd_env(vault)
    # Stage the corpus from the CLI's §12 cleared set (issue #795). The
    # script keeps the gitignore refusal and the 0700/0600 modes.
    corpus, _files, _lines = stage_cleared_corpus(vault, args.cli)
    exclude_from_backups(vault)

    # idempotent collection registration: drop the old one if present
    # (exact name match: a "confidant-backup" collection must not trigger this)
    lst = run_qmd(["collection", "list"], env, check=False)
    if re.search(rf"(?m)^{re.escape(COLLECTION)} ", lst.stdout):
        run_qmd(["collection", "remove", COLLECTION], env)
        print(f"removed stale '{COLLECTION}' collection")
    run_qmd(["collection", "add", corpus, "--name", COLLECTION], env)
    print(f"registered '{COLLECTION}' collection")

    if args.embed:
        print("embedding (first run downloads models)...")
        run_qmd(["embed"], env)
    print("done. query with: bin/qmd-query.py --vault "
          + vault + ' "your question"')

    # #722: preflight is part of setup, not an optional extra. An
    # operator who runs only this script must not meet the old
    # first-query timeout as their first impression, and must not
    # need a second command before the query wrapper honors the
    # offline decision — hence --persist (chained: offline only,
    # never default_mode — a mode change needs an explicit --query
    # run). The preflight report is
    # printed in full; its exit code is never a gate (it is 0 whenever
    # the report completes), and a preflight failure never fails the
    # index build that just succeeded.
    if args.skip_preflight:
        print("note: preflight skipped (--skip-preflight); run "
              "bin/qmd-preflight.py --vault " + vault + " --persist "
              "--query <term> before relying on hybrid/vector search")
        return
    preflight = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "qmd-preflight.py")
    if not os.path.isfile(preflight):
        print("REQUIRED SETUP STEP (preflight script not found beside "
              "this script): run qmd-preflight.py --vault " + vault +
              " --persist --query <term> to check the host, hub "
              "reachability, and per-mode timings, and record the "
              "recommendation, before the first real query (issue #722)")
        return
    print("running qmd-preflight.py --persist --chained (issue #722) "
          "— spec, hub, and cold/warm smoke per mode; this is part "
          "of setup, its offline decision is recorded in [qmd] "
          "config (a default_mode change needs an explicit --query "
          "run), and its report "
          "(not its exit code) is the result to read. Worst case is "
          "~18 minutes at the default 180s per-mode timeout; progress "
          "lines go to stderr:")
    run_setup_preflight(preflight, vault)


if __name__ == "__main__":
    main()
