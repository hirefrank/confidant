"""Shared helpers for the Confidant integration skills (skills/bin/).

Keep this dependency-light (stdlib only): skills must run anywhere the
agent runs, with no installs.
"""
from __future__ import annotations

import json
import os
import re
import secrets
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
# Proposal manifests
# ---------------------------------------------------------------------------

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
    the manifest is plaintext PII, deleted after the apply). The lines
    file holds the proposed ledger lines, one per line, for
    `confidant import --file`.
    """
    d = os.path.join(vault, ".confidant", "proposals")
    os.makedirs(d, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = os.path.join(d, f"{skill}-{ts}")
    return base + ".json", base + ".cfd"


def write_lines_file(path: str, by_file: dict[str, list[str]]) -> None:
    """Write the proposed ledger lines as one flat file for `import --file`.

    `import --file` parses every line and routes each to its month file
    itself, so the file is just the lines concatenated (sorted by month
    file for determinism).
    """
    lines: list[str] = []
    for key in sorted(by_file):
        lines.extend(by_file[key])
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


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
    """Write the proposal manifest as JSON (stdout when path is None)."""
    text = json.dumps(manifest, indent=2, sort_keys=True)
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
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
