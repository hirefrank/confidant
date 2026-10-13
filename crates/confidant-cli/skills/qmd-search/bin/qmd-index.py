#!/usr/bin/env python3
"""Build (or rebuild) the QMD search corpus + collection for a vault.

Usage: qmd-index.py [--vault PATH] [--cli PATH] [--embed]

The corpus build lives in the CLI (issue #37, ADR-6). This script is the
QMD integration on top:

- Delegates the corpus to `confidant reindex`, which owns content, the §12
  cleared set, decryption through the read path, and file permissions. The
  CLI writes `<vault>/.confidant/qmd-corpus/` (gitignored, trusted devices
  only), preserving relative paths, and refuses rather than silently
  omitting encrypted records it cannot decrypt. `no-ai` records stay out
  by construction (the CLI never decrypts them into the corpus), crediting
  #38's index-time exclusion — now enforced inside the CLI.
- Registers the corpus as the `confidant` QMD collection (removing any
  previous one first, so rebuilds are idempotent).
- --embed runs `qmd embed` afterwards for vector search (downloads models
  on first run; keyword-only `search` works without it).

Guardrails:
- The encrypted-disk assertion STAYS HERE (architecture §9b item 4): the
  corpus and QMD's index hold plaintext chunks, so the script refuses
  unless the disk is encrypted (auto-detected: FileVault on macOS,
  dm-crypt ancestor in lsblk on Linux) or the operator passes
  --i-confirm-encrypted-disk. It is device policy, not a per-command check.
- QMD's own store is moved under <vault>/.confidant/qmd/ (INDEX_PATH +
  QMD_CONFIG_DIR env), created 0700; on macOS it is added to the Time
  Machine exclusion list. A previous default-store `confidant` collection
  is removed on first run (migration).
- The corpus gitignore refusal and the 0700/0600 permissions moved into
  `confidant reindex` (it writes the corpus); this script no longer checks
  them itself.

Re-run after pulls/merges/writes. A stale index can only miss results:
query-time allowlist filtering means staleness can never leak.
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


def run_reindex(vault, cli):
    """Delegate the corpus build to `confidant reindex`.

    The CLI owns corpus content, clearance, decryption, and permissions
    (#37); the skill never walks the vault. Returns the corpus path from
    the CLI's JSON. Refuses (exits) when reindex refuses — e.g. an
    encrypted vault this device cannot decrypt, or a corpus path that is
    not git-ignored.
    """
    exe = cli or shutil.which("confidant")
    if exe is None:
        sys.exit("error: `confidant` not found. Pass --cli PATH or put it on "
                 "PATH; the corpus build lives in the CLI (ADR-6).")
    try:
        p = subprocess.run([exe, "reindex", "--json", "--no-input",
                            "--vault", vault],
                           capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as e:
        sys.exit(f"error: `confidant reindex` could not run: {e}")
    try:
        data = json.loads(p.stdout)
    except ValueError:
        data = None
    if (p.returncode != 0 or not isinstance(data, dict) or not data.get("ok")
            or not isinstance(data.get("corpus"), str)):
        detail = (p.stderr or "").strip() or (p.stdout or "").strip()
        if isinstance(data, dict) and isinstance(data.get("error"), dict):
            err = data["error"]
            detail = f"{err.get('code')}: {err.get('message')}"
            if err.get("fix"):
                detail += f"\n  fix: {err['fix']}"
            if data.get("skipped_encrypted") or data.get("refused_envelopes"):
                detail += (f"\n  skipped_encrypted={data.get('skipped_encrypted', 0)}, "
                           f"refused_envelopes={data.get('refused_envelopes', 0)}")
        sys.exit(f"error: `confidant reindex` failed (exit {p.returncode}):\n{detail}")
    corpus = data["corpus"]
    print(f"corpus: {corpus} ({data.get('files_copied', '?')} files)")
    print(f"  records: {data.get('records_copied', '?')} copied, "
          f"{data.get('records_decrypted', '?')} decrypted; "
          f"{data.get('ledger_lines_kept', '?')} ledger lines kept")
    return corpus


def encrypted_disk_detected(vault):
    """Best-effort encrypted-disk detection. True/False, or None if unknown.

    macOS: `fdesetup isactive` (FileVault). Linux: the vault's backing
    device has a `crypt`-type ancestor in lsblk (dm-crypt, incl. LUKS
    under LVM).
    """
    if sys.platform == "darwin":
        fdesetup = shutil.which("fdesetup")
        if fdesetup is None:
            return None
        try:
            p = subprocess.run([fdesetup, "isactive"], capture_output=True,
                               text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            return None
        out = p.stdout.strip().lower()
        if out.startswith("true"):
            return True
        if out.startswith("false"):
            return False
        return None
    # Linux (and others with lsblk): walk the backing device's ancestors.
    lsblk = shutil.which("lsblk")
    if lsblk is None:
        return None
    try:
        st = os.stat(vault)
        majmin = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    except OSError:
        return None
    try:
        p = subprocess.run([lsblk, "-rno", "NAME,TYPE,MAJ:MIN,PKNAME"],
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0:
        return None
    by_name, by_majmin = {}, {}
    for line in p.stdout.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        name, typ, mm = parts[0], parts[1], parts[2]
        pk = parts[3] if len(parts) > 3 else ""
        by_name[name] = (typ, pk)
        by_majmin[mm] = name
    node = by_majmin.get(majmin)
    seen = set()
    while node and node not in seen:
        seen.add(node)
        typ, pk = by_name.get(node, (None, ""))
        if typ == "crypt":
            return True
        node = pk or None
    return False


def ensure_encrypted_disk(vault, confirmed_flag):
    """Refuse unless the disk is encrypted (detected) or the operator asserts it."""
    detected = encrypted_disk_detected(vault)
    if detected is True:
        print("encrypted disk: detected — ok")
        return
    if confirmed_flag:
        print("encrypted disk: asserted via --i-confirm-encrypted-disk — ok")
        return
    sys.exit(
        "error: refusing to build: could not confirm the disk is encrypted.\n"
        "The QMD index holds plaintext vault content (including no-ai records)\n"
        "and architecture §9b item 4 requires an encrypted disk.\n"
        "Fix: run on a FileVault/dm-crypt volume, or re-run with\n"
        "  --i-confirm-encrypted-disk   (only if you have verified it yourself)")


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

    Must run AFTER `confidant reindex` (re)builds the corpus: reindex wipes
    and recreates the corpus dir, which would destroy an exclusion set
    earlier. Best-effort: warns loudly on failure but does not refuse (the
    primary protections are the CLI's gitignore refusal and this script's
    encrypted-disk gate).
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=None)
    ap.add_argument("--embed", action="store_true",
                    help="run `qmd embed` after indexing (enables vector search)")
    ap.add_argument("--cli", default=None,
                    help="path to the confidant binary that builds the corpus "
                         "(default: confidant on PATH)")
    ap.add_argument("--i-confirm-encrypted-disk", action="store_true",
                    help="assert the disk is encrypted (only if you have "
                         "verified it yourself; detection is attempted first)")
    args = ap.parse_args()

    vault = resolve_vault(args.vault)
    # Device policy stays here (architecture §9b item 4): the corpus and the
    # QMD store hold plaintext chunks.
    ensure_encrypted_disk(vault, args.i_confirm_encrypted_disk)
    ensure_store_dirs(vault)
    migrate_default_store()

    env = qmd_env(vault)
    # The CLI owns the corpus build (gitignore refusal, 0700/0600
    # permissions, §12 clearance, decryption). This script only registers it.
    corpus = run_reindex(vault, args.cli)
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


if __name__ == "__main__":
    main()
