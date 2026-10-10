"""Shared helpers for the Confidant integration skills (skills/bin/).

Keep this dependency-light (stdlib only): skills must run anywhere the
agent runs, with no installs.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# IDs
# ---------------------------------------------------------------------------

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ID_RE = re.compile(r"^(p|o|d|i|n|pkg)-[0-9A-HJKMNP-TV-Z]{26}$", re.IGNORECASE)


def format_duration(minutes: int) -> str:
    """Minutes -> spec duration grammar: Nm, Nh, or NhNm (e.g. 90 -> '1h30m')."""
    h, m = divmod(minutes, 60)
    if h and m:
        return f"{h}h{m}m"
    if h:
        return f"{h}h"
    return f"{m}m"


def new_ulid() -> str:
    """Generate a random ULID (Crockford base32, first char 0-7)."""
    ms = int(time.time() * 1000)
    rand = int.from_bytes(secrets.token_bytes(10), "big")
    value = (ms << 80) | rand
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def valid_id(value: str) -> bool:
    """True when value looks like a spec 0.1 record ID (prefix-ULID, any case)."""
    return bool(_ID_RE.match(value))


def valid_date(value: str) -> bool:
    """True when value is a real YYYY-MM-DD calendar date."""
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Vault reading (plaintext scan; the vault is trusted-device-local here)
# ---------------------------------------------------------------------------

_SRC_RE = re.compile(r"(?:^|\s)src:([^\s;\"']+)")


def collect_srcs(vault: str) -> set[str]:
    """Return every `src:` provenance value found in the vault's ledgers."""
    srcs: set[str] = set()
    ledger = os.path.join(vault, "ledger")
    if not os.path.isdir(ledger):
        return srcs
    for root, _dirs, files in os.walk(ledger):
        for name in files:
            if not name.lower().endswith(".cfd"):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        for m in _SRC_RE.finditer(line):
                            srcs.add(m.group(1))
            except OSError:
                continue
    return srcs


def record_exists(vault: str, record_id: str) -> bool:
    """True when a record file/dir for record_id exists in the vault."""
    prefix = record_id.split("-", 1)[0]
    collection = {"p": "people", "o": "orgs", "d": "deals",
                  "i": "interactions", "n": "notes"}.get(prefix)
    if collection is None:
        return False
    base = os.path.join(vault, collection, record_id)
    if os.path.isdir(base) or os.path.isfile(base + ".md"):
        return True
    # notes may live under people/<id>/notes/
    if prefix == "n":
        people = os.path.join(vault, "people")
        if os.path.isdir(people):
            for person in os.listdir(people):
                cand = os.path.join(people, person, "notes", record_id + ".md")
                if os.path.isfile(cand):
                    return True
    return False


def month_file(vault: str, date: str) -> str:
    """Repo-relative ledger file for a date (ledger/YYYY/MM.cfd)."""
    return f"ledger/{date[:4]}/{date[5:7]}.cfd"


# ---------------------------------------------------------------------------
# Secure scratch (plaintext PII lives here until --cleanup deletes it)
# ---------------------------------------------------------------------------

def _secure_makedirs(path: str) -> None:
    """makedirs with mode 0700 (umask-proof: chmod after, like #24)."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def write_file_600(path: str, text: str) -> None:
    """Write text to path with mode 0600 (plaintext PII scratch)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path, 0o600)


def _ensure_proposals_gitignored(vault: str) -> None:
    """Refuse unless <vault>/.confidant/proposals/ is git-ignored.

    Same pattern as #24's corpus check: the proposal set is plaintext
    PII (names, emails, notes, transcripts), and one `git add -A` in a
    vault that doesn't ignore it would commit the whole thing. Skips
    with a note when the vault isn't a git repo or git is absent (no
    commit vector then).
    """
    git = shutil.which("git")
    if git is None:
        print("note: git not found; skipping gitignore check "
              "(nothing to commit the proposals with)", file=sys.stderr)
        return
    rp = subprocess.run([git, "-C", vault, "rev-parse", "--git-dir"],
                        capture_output=True, text=True)
    if rp.returncode != 0:
        print("note: vault is not a git repo; skipping gitignore check",
              file=sys.stderr)
        return
    probe = os.path.join(".confidant", "proposals", ".probe")
    r = subprocess.run([git, "-C", vault, "check-ignore", "-q", probe],
                       capture_output=True)
    if r.returncode != 0:
        sys.exit(
            "error: refusing to write proposal: .confidant/proposals/ is not "
            "git-ignored in this vault\n"
            "The proposal set is plaintext PII (names, emails, notes, "
            "transcripts); one `git add -A` would commit it.\n"
            f"Fix: (cd {vault} && echo '.confidant/' >> .gitignore)\n"
            "then re-run.")
    print("gitignore: .confidant/proposals/ is ignored — ok")


# ---------------------------------------------------------------------------
# Proposal manifests
# ---------------------------------------------------------------------------

def ensure_out_ignored(vault: str, *paths: str) -> None:
    """Refuse unless every custom --out path inside the vault is git-ignored.

    #57: proposers use --out directly, skipping the check-ignore probe that
    proposal_paths() runs on the default location. A manifest, lines file,
    or staged note body landing inside the vault unignored is plaintext PII
    one `git add -A` away from a commit. Paths outside the vault have no
    vault-git commit vector and are left alone. Skips with a note when the
    vault isn't a git repo or git is absent (same as _ensure_proposals_gitignored).
    """
    git = shutil.which("git")
    if git is None:
        print("note: git not found; skipping gitignore check "
              "(nothing to commit the proposals with)", file=sys.stderr)
        return
    rp = subprocess.run([git, "-C", vault, "rev-parse", "--git-dir"],
                        capture_output=True, text=True)
    if rp.returncode != 0:
        print("note: vault is not a git repo; skipping gitignore check",
              file=sys.stderr)
        return
    vault_abs = os.path.realpath(vault)
    for p in paths:
        if not p:
            continue
        target = os.path.realpath(p)
        try:
            inside = os.path.commonpath([vault_abs, target]) == vault_abs
        except ValueError:
            inside = False
        if not inside:
            continue
        rel = os.path.relpath(target, vault_abs)
        r = subprocess.run([git, "-C", vault, "check-ignore", "-q", rel],
                           capture_output=True)
        if r.returncode != 0:
            sys.exit(
                f"error: refusing to write proposal: --out path {p!r} is inside "
                f"the vault but not git-ignored\n"
                "The proposal set is plaintext PII (names, emails, notes, "
                "transcripts); one `git add -A` would commit it.\n"
                f"Fix: add a matching pattern to the vault .gitignore, e.g.\n"
                f"  (cd {vault} && echo '{rel}' >> .gitignore)\n"
                "then re-run, or point --out outside the vault.")

def new_request_id() -> str:
    """Fresh random idempotency key for one proposal.

    A ULID, generated once per proposal run and stored in the manifest.
    Retries reuse the manifest's stored value (never regenerate for the
    same proposal): the CLI's HMAC idempotency keys must not be guessable
    and must be stable across retries, so date-derived digests are out.
    """
    return new_ulid()


def proposal_paths(vault: str, skill: str) -> tuple[str, str]:
    """Default (manifest_path, lines_path) for a proposal.

    Both live under <vault>/.confidant/proposals/ (gitignored scratch —
    the manifest is plaintext PII, deleted after the apply). Refuses
    unless that dir is git-ignored (same check-ignore pattern as #24);
    creates it 0700. The lines file holds the proposed ledger lines, one
    per line, for `confidant import --file`.
    """
    _ensure_proposals_gitignored(vault)
    d = os.path.join(vault, ".confidant", "proposals")
    _secure_makedirs(d)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = os.path.join(d, f"{skill}-{ts}")
    return base + ".json", base + ".cfd"


def proposal_notes_dir(manifest_path: str) -> str:
    """Directory for per-note body files, next to the manifest.

    `<manifest-stem>/notes/` — never /tmp (note bodies are plaintext
    PII). Created 0700; the proposer writes each body 0600 and records
    the path in the manifest, and --cleanup removes the whole proposal
    set (manifest, lines file, note bodies).
    """
    stem = (manifest_path[:-5] if manifest_path.endswith(".json")
            else manifest_path)
    d = os.path.join(stem, "notes")
    _secure_makedirs(d)
    # makedirs modes only the leaf; the stem parent needs 0700 too.
    os.chmod(stem, 0o700)
    return d


def write_lines_file(path: str, by_file: dict[str, list[str]]) -> None:
    """Write the proposed ledger lines as one flat file for `import --file`.

    `import --file` parses every line and routes each to its month file
    itself, so the file is just the lines concatenated (sorted by month
    file for determinism).
    """
    lines: list[str] = []
    for key in sorted(by_file):
        lines.extend(by_file[key])
    write_file_600(path, "".join(line + "\n" for line in lines))


_ENC_RE = re.compile(r"^enc:\s*\S", re.MULTILINE)


def vault_looks_encrypted(vault: str) -> bool:
    """True when any record file carries an `enc:` envelope marker.

    Used to refuse hand-written record files once milestone 2 encryption
    is in play: writing plaintext records by hand post-M2 would commit
    plaintext PII to git. Ledger lines and notes still go through the
    CLI (`import --file`, `note add`), which encrypts on write.
    """
    for root, dirs, files in os.walk(vault):
        # never descend into git or local scratch
        dirs[:] = [d for d in dirs if d not in (".git", ".confidant")]
        for name in files:
            if not name.endswith(".md"):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, encoding="utf-8") as f:
                    head = f.read(4096)
            except OSError:
                continue
            if _ENC_RE.search(head):
                return True
    return False


def write_manifest(path: str | None, manifest: dict) -> None:
    """Write the proposal manifest as JSON (0600; stdout when path is None)."""
    text = json.dumps(manifest, indent=2, sort_keys=True)
    if path:
        write_file_600(path, text + "\n")
    else:
        print(text)


def vault_arg(parser, default_env: str = "CONFIDANT_VAULT"):
    """Add --vault (falling back to $CONFIDANT_VAULT) to an argparse parser."""
    parser.add_argument(
        "--vault", default=os.environ.get(default_env),
        help=f"vault directory (or ${default_env})",
    )
    return parser


def require_vault(args) -> str:
    if not args.vault or not os.path.isfile(os.path.join(args.vault, "confidant.toml")):
        print("error: --vault must point at a vault directory containing confidant.toml",
              file=sys.stderr)
        sys.exit(2)
    return os.path.abspath(args.vault)
