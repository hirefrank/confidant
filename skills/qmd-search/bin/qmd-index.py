#!/usr/bin/env python3
"""Build (or rebuild) the QMD search corpus + collection for a vault.

Usage: qmd-index.py [--vault PATH] [--embed]

- Copies decrypted vault content into <vault>/.confidant/qmd-corpus/
  (gitignored, trusted devices only), preserving relative paths.
- Registers it as the `confidant` QMD collection (removing any previous
  one first, so rebuilds are idempotent).
- Skips files with an `enc:` envelope (post-M2 encrypted records): indexing
  ciphertext is useless, and the corpus step must decrypt through the CLI
  once confidant-crypt lands. Skipped files are reported, never silent.
- --embed runs `qmd embed` afterwards for vector search (downloads models
  on first run; keyword-only `search` works without it).

Guardrails (the corpus is a plaintext mirror of the vault, INCLUDING
no-ai records — these are enforced in code, not just docs):
- REFUSES to build unless `.confidant/qmd-corpus/` AND `.confidant/qmd/`
  (the QMD store, whose index.sqlite holds plaintext FTS chunks) are
  git-ignored in the vault's repo (one `git add -A` must never commit
  the corpus or the index).
- REFUSES to build unless the disk is encrypted (auto-detected: FileVault
  on macOS, dm-crypt ancestor in lsblk on Linux) or the operator passes
  --i-confirm-encrypted-disk.
- QMD's own store is moved under <vault>/.confidant/qmd/ (INDEX_PATH +
  QMD_CONFIG_DIR env), both directories created 0700; on macOS both are
  added to the Time Machine exclusion list. A previous default-store
  `confidant` collection is removed on first run (migration).

Re-run after pulls/merges/writes. A stale index can only miss results:
query-time allowlist filtering means staleness can never leak.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys

COLLECTION = "confidant"
SKIP_DIRS = {".git", ".confidant", "keys"}
SKIP_FILES = {"confidant.toml", "README.md", "LICENSE"}
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


def is_encrypted_envelope(path):
    """True if the file carries a post-M2 `enc:` front-matter envelope."""
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as f:
            head = f.read(2048)
    except (OSError, UnicodeDecodeError):
        return False
    if not head.startswith("---"):
        return False
    for line in head.splitlines()[1:12]:
        if line.strip().startswith("enc:"):
            return True
        if line.strip() == "---":
            break
    return False


def is_decodable_text(path):
    """True if the file reads as UTF-8 text (binaries don't belong in a text corpus)."""
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as f:
            f.read(2048)
        return True
    except (OSError, UnicodeDecodeError):
        return False


def ensure_corpus_gitignored(vault):
    """Refuse unless the corpus AND the QMD store are git-ignored.

    The corpus is a plaintext mirror of the vault (including no-ai
    records), and the QMD store's index.sqlite holds the plaintext FTS
    chunks; a single `git add -A` in a vault that doesn't ignore them
    would commit the whole thing.
    """
    git = shutil.which("git")
    if git is None:
        print("note: git not found; skipping gitignore check "
              "(nothing to commit the corpus with)", file=sys.stderr)
        return
    rp = subprocess.run([git, "-C", vault, "rev-parse", "--git-dir"],
                        capture_output=True, text=True)
    if rp.returncode != 0:
        print("note: vault is not a git repo; skipping gitignore check",
              file=sys.stderr)
        return
    # check-ignore -q exits 0 if ANY path is ignored, so probe each path
    # separately; the probe files need not exist on disk.
    probes = {os.path.join(CORPUS_REL, ".probe"): ".confidant/qmd-corpus/",
              os.path.join(STORE_REL, ".probe"): ".confidant/qmd/"}
    unignored = [label for probe, label in probes.items()
                 if subprocess.run([git, "-C", vault, "check-ignore", "-q",
                                    probe], capture_output=True).returncode != 0]
    if unignored:
        sys.exit(
            "error: refusing to build: not git-ignored in this vault: "
            f"{', '.join(unignored)}\n"
            "The corpus is a plaintext mirror of the vault (including no-ai "
            "records), and the QMD store's index.sqlite holds the plaintext "
            "FTS chunks; one `git add -A` would commit them.\n"
            "Fix: add `.confidant/` to the vault's .gitignore, e.g.:\n"
            f"  (cd {vault} && echo '.confidant/' >> .gitignore)\n"
            "then re-run qmd-index.")
    print("gitignore: corpus and QMD store paths are ignored — ok")


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

    Must run AFTER the corpus is (re)built: build_corpus wipes and recreates
    the corpus dir, which would destroy an exclusion set earlier.
    Best-effort: warns loudly on failure but does not refuse (the primary
    protections are the gitignore and encrypted-disk gates).
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


def build_corpus(vault):
    corpus = os.path.join(vault, CORPUS_REL)
    if os.path.isdir(corpus):
        shutil.rmtree(corpus)
    os.makedirs(corpus, mode=0o700, exist_ok=True)
    os.chmod(corpus, 0o700)
    copied, skipped_enc, skipped_other = 0, [], 0
    for root, dirs, files in os.walk(vault, followlinks=False):
        # prune skipped dirs in place (also any dot-named dir)
        dirs[:] = [d for d in dirs
                   if d not in SKIP_DIRS and not d.startswith(".")
                   and not os.path.islink(os.path.join(root, d))]
        for name in files:
            src = os.path.join(root, name)
            rel = os.path.relpath(src, vault)
            if name in SKIP_FILES or name.startswith(".") or os.path.islink(src):
                skipped_other += 1
                continue
            if is_encrypted_envelope(src):
                skipped_enc.append(rel)
                continue
            if not is_decodable_text(src):
                skipped_other += 1
                continue
            dst = os.path.join(corpus, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            copied += 1
            # Ledger parity: qmd collections only match **/*.md, so mirror
            # each .cfd as a sibling .cfd.md for indexing. The query script
            # maps hits back to the real .cfd path for verification.
            if name.endswith(".cfd"):
                mirror = dst + ".md"
                shutil.copy2(src, mirror)
                copied += 1
    return corpus, copied, skipped_enc, skipped_other


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
    ap.add_argument("--i-confirm-encrypted-disk", action="store_true",
                    help="assert the disk is encrypted (only if you have "
                         "verified it yourself; detection is attempted first)")
    args = ap.parse_args()

    vault = resolve_vault(args.vault)
    ensure_corpus_gitignored(vault)
    ensure_encrypted_disk(vault, args.i_confirm_encrypted_disk)
    ensure_store_dirs(vault)
    migrate_default_store()

    env = qmd_env(vault)
    corpus, copied, skipped_enc, skipped_other = build_corpus(vault)
    exclude_from_backups(vault)
    print(f"corpus: {corpus} ({copied} files)")

    # idempotent collection registration: drop the old one if present
    # (exact name match: a "confidant-backup" collection must not trigger this)
    lst = run_qmd(["collection", "list"], env, check=False)
    if re.search(rf"(?m)^{re.escape(COLLECTION)} ", lst.stdout):
        run_qmd(["collection", "remove", COLLECTION], env)
        print(f"removed stale '{COLLECTION}' collection")
    run_qmd(["collection", "add", corpus, "--name", COLLECTION], env)
    print(f"registered '{COLLECTION}' collection")

    if skipped_enc:
        print(f"warning: skipped {len(skipped_enc)} encrypted file(s) "
              f"(enc: envelope; decrypt-through-CLI not yet implemented):")
        for rel in skipped_enc[:10]:
            print(f"  {rel}")
        if len(skipped_enc) > 10:
            print(f"  ... and {len(skipped_enc) - 10} more")
    if args.embed:
        print("embedding (first run downloads models)...")
        run_qmd(["embed"], env)
    print("done. query with: bin/qmd-query.py --vault "
          + vault + ' "your question"')


if __name__ == "__main__":
    main()
