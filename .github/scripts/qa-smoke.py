#!/usr/bin/env python3
"""End-to-end QA smoke test for the built `confidant` binary.

This is the deterministic half of the QA sweep protocol in
`.agents/skills/qa-sweep/SKILL.md`. It drives the *built* binary against
throwaway vaults under one work directory and asserts the invariants a
sweep cares about, so a nightly run catches the class of defect that unit
tests, clippy and CI can all pass over:

  - a refused write leaves no directories behind (git-invisible) and the
    vault still passes `check` (#604);
  - the agent read path never gains `operator_only` and never leaks a
    `no-ai` person, while `--for-operator` does (`find` / `context`);
  - the pack lifecycle no-ops cleanly (`unchanged`), repairs a stale lock
    hash, and rolls back a refused change;
  - writes encrypt on an encrypted vault and stay plaintext only on a
    vault that declares the opt-out.

Everything is fake data and throwaway keys (ADR-14): the script generates
its own age device key and Ed25519 operator seed in-process, points `HOME`
at a throwaway config dir, and never touches a real vault or keychain.

The binary must be built with `--all-features` (the CI job does): the
encrypted steps need the `test-overrides` feature so the operator seed can
arrive via `CONFIDANT_TEST_OPERATOR_KEY` and no real keychain is touched.

A `--workdir` is wiped before a run, so the script refuses to delete a
directory it did not create: it drops a `.qa-smoke` marker when it makes a
work directory, and on a later run it refuses an existing non-empty
directory that does not carry that marker (`--workdir ~` or `--workdir .`
is therefore safe). Run with `--self-test` to exercise that refusal
against a fixture tree, mirroring `check-crate-paths.py --self-test`.

Usage:
  python3 .github/scripts/qa-smoke.py --cli target/debug/confidant
  python3 .github/scripts/qa-smoke.py --cli target/debug/confidant \
      --workdir /tmp/opencode/my-sweep
  python3 .github/scripts/qa-smoke.py --self-test

Exit 0 and a `qa smoke passed: N steps` line on success; exit 1 with the
failing step named and its captured output on failure.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

# Fixed fake identifiers and dates. The dates are pinned so the smoke never
# depends on the wall clock (a "today" date writes ledger/2026/11.cfd from
# 2026-11-01 and turns a green run red on the month rollover, #585).
PERSON = "p-01J9Z3K4QF0000000000000001"  # "Ada Example", paid
NO_AI_PERSON = "p-01J9Z3K4QG0000000000000002"  # "Cam Sample", no-ai
PACKAGE = "pkg-01J9Z3K4QF0000000000000000"
VAULT_ID = "01J9Z3K4QF0000000000000000"
SESSION_DATE = "2026-10-13"
ALIAS_DATE = "2026-10-13"
TOUCH_DATE = "2026-10-15"
PACK_DIR = REPO / "testdata" / "packs" / "coaching-ext"

# Marker the script drops in a work directory it created. A `--workdir` is
# wiped before a run, so an existing non-empty directory without this marker
# is refused rather than deleted (`--workdir ~` must not wipe a home dir).
MARKER = ".qa-smoke"


class SmokeFailure(Exception):
    """A step failed; carries the step name and the captured output."""

    def __init__(self, step: str, detail: str) -> None:
        super().__init__(f"{step}: {detail}")
        self.step = step
        self.detail = detail


# ---------------------------------------------------------------------------
# Throwaway age key generation (ADR-14: CI never holds vault keys).
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_convertbits(data: bytes, frombits: int, tobits: int) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def age_secret_key() -> str:
    """A fresh throwaway age x25519 identity, e.g. `AGE-SECRET-KEY-1…`.

    Implemented in pure Python so the smoke needs no `age-keygen` install
    (the crypto tests get theirs from a Rust dev-dependency).
    """
    raw = os.urandom(32)
    hrp = "age-secret-key-"
    data = _bech32_convertbits(raw, 8, 5)
    values = _bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]
    polymod = _bech32_polymod(values) ^ 1
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    encoded = "".join(_BECH32_CHARSET[d] for d in data + checksum)
    return (hrp + "1" + encoded).upper()


# ---------------------------------------------------------------------------
# Step runner
# ---------------------------------------------------------------------------


class Smoke:
    """Runs the smoke steps and keeps a summary of what ran."""

    def __init__(self, cli: Path, root: Path) -> None:
        self.cli = str(cli)
        self.root = root
        self.vaults = root / "vaults"
        self.scratch = root / "scratch"
        self.home = root / "home"
        for path in (self.vaults, self.scratch, self.home):
            path.mkdir(parents=True, exist_ok=True)

        self.device_key = age_secret_key()
        self.operator_hex = os.urandom(32).hex()
        # A throwaway git identity, written into the throwaway HOME *and* named
        # explicitly via GIT_CONFIG_GLOBAL. Without this the smoke passes on a
        # developer machine (git falls back to the real user's config) and fails
        # on a runner, which has no identity: the first write is refused with
        # "git user.name is not configured". XDG_CONFIG_HOME is cleared in
        # env() for the same reason (#623, the #560 lesson).
        (self.home / ".gitconfig").write_text(
            "[user]\n\tname = QA Smoke\n\temail = qa-smoke@example.invalid\n"
        )
        self.steps: list[str] = []
        self.step_count = 0

    # -- environment --------------------------------------------------------

    def env(self) -> dict[str, str]:
        """A hermetic environment: throwaway HOME, keys and git identity."""
        e = dict(os.environ)
        e.pop("CONFIDANT_VAULT", None)
        # The throwaway HOME must be the *only* place git can find config:
        # XDG_CONFIG_HOME would otherwise still point at the real user's
        # ~/.config/git/config, and GIT_CONFIG_GLOBAL makes the throwaway file
        # the global config explicitly rather than by HOME inference (#623).
        e.pop("XDG_CONFIG_HOME", None)
        e.update(
            {
                "HOME": str(self.home),
                "GIT_CONFIG_GLOBAL": str(self.home / ".gitconfig"),
                "CONFIDANT_KEYCHAIN": "off",
                "CONFIDANT_DEVICE_KEY": self.device_key,
                "CONFIDANT_TEST_OPERATOR_KEY": self.operator_hex,
                "GIT_AUTHOR_NAME": "QA Smoke",
                "GIT_AUTHOR_EMAIL": "qa-smoke@example.invalid",
                "GIT_COMMITTER_NAME": "QA Smoke",
                "GIT_COMMITTER_EMAIL": "qa-smoke@example.invalid",
                "GIT_CONFIG_NOSYSTEM": "1",
                "TZ": "UTC",
            }
        )
        return e

    # -- process helpers ----------------------------------------------------

    def run(
        self,
        args: list[str],
        stdin: str | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.cli, *args],
            input=stdin,
            text=True,
            capture_output=True,
            env=env or self.env(),
        )

    def git(self, vault: Path, args: list[str]) -> None:
        proc = subprocess.run(
            ["git", "-C", str(vault), *args],
            text=True,
            capture_output=True,
            env=self.env(),
        )
        if proc.returncode != 0:
            raise SmokeFailure(
                "git",
                f"git {' '.join(args)} failed in {vault}:\n{proc.stderr}",
            )

    def ok(self, step: str, condition: bool, detail: str) -> None:
        if not condition:
            raise SmokeFailure(step, detail)

    def mark(self, step: str) -> None:
        self.step_count += 1
        self.steps.append(step)
        print(f"  [ ok ] {step}", flush=True)

    def cli_ok(
        self, step: str, args: list[str], stdin: str | None = None
    ) -> dict:
        """Run the CLI expecting exit 0 and JSON on stdout; return the JSON."""
        proc = self.run(args, stdin=stdin)
        if proc.returncode != 0:
            raise SmokeFailure(
                step,
                f"expected exit 0, got {proc.returncode}\n"
                f"    args: {' '.join(args)}\n"
                f"    stdout: {proc.stdout.strip()}\n"
                f"    stderr: {proc.stderr.strip()}",
            )
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as err:
            raise SmokeFailure(
                step,
                f"stdout was not JSON ({err})\n"
                f"    args: {' '.join(args)}\n"
                f"    stdout: {proc.stdout.strip()}\n"
                f"    stderr: {proc.stderr.strip()}",
            ) from err

    def cli_fail(
        self,
        step: str,
        args: list[str],
        code: str | None = None,
        stdin: str | None = None,
    ) -> dict:
        """Run the CLI expecting a non-zero exit; assert the error code."""
        proc = self.run(args, stdin=stdin)
        if proc.returncode == 0:
            raise SmokeFailure(
                step,
                f"expected a refusal, got exit 0\n"
                f"    args: {' '.join(args)}\n"
                f"    stdout: {proc.stdout.strip()}",
            )
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError as err:
            raise SmokeFailure(
                step,
                f"refusal stdout was not JSON ({err})\n"
                f"    args: {' '.join(args)}\n"
                f"    stdout: {proc.stdout.strip()}\n"
                f"    stderr: {proc.stderr.strip()}",
            ) from err
        if code is not None:
            got = report.get("error", {}).get("code")
            if got != code:
                raise SmokeFailure(
                    step,
                    f"expected error code {code}, got {got}\n"
                    f"    args: {' '.join(args)}\n"
                    f"    stdout: {proc.stdout.strip()}",
                )
        return report

    # -- vault helpers ------------------------------------------------------

    def make_plaintext_vault(self, name: str, packs: list[str]) -> Path:
        """A git-backed vault declaring the plaintext write opt-out."""
        vault = self.vaults / name
        if vault.exists():
            shutil.rmtree(vault)
        vault.mkdir(parents=True)
        pack_list = ", ".join(f'"{p}"' for p in packs)
        (vault / "confidant.toml").write_text(
            f'spec = "0.1"\npacks = [{pack_list}]\nvault_id = "{VAULT_ID}"\n'
            '\n[crypto]\nmode = "plaintext"\n'
        )
        self.git(vault, ["init", "-q"])
        self.git(vault, ["add", "-A"])
        self.git(vault, ["commit", "-qm", "init"])
        return vault

    def write_person(self, record_id: str, name: str, no_ai: bool = False) -> None:
        body = "---\n" f"id: {record_id}\n" "type: person\n" f'name: "{name}"\n'
        if no_ai:
            body += "no-ai: true\n"
        body += "---\n\nFake bio.\n"
        path = self.scratch / f"{record_id}.md"
        path.write_text(body)

    def seed_open_line(self, vault: Path, no_ai_touch: bool = True) -> None:
        """Seed the package `open` line a session needs (coaching@0.1).

        `no_ai_touch` also seeds a `touch` line naming the no-ai person, the
        operator-only ledger hit the read-path checks assert on. The
        encrypted vault is single-person, so it seeds the open line alone.
        """
        ledger = vault / "ledger" / "2026" / "10.cfd"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        text = f"2026-10-01 open {PERSON} package {PACKAGE} 4 sessions\n"
        if no_ai_touch:
            text += f"{TOUCH_DATE} touch {NO_AI_PERSON} meal\n"
        ledger.write_text(text)
        self.git(vault, ["add", "-A"])
        self.git(vault, ["commit", "-qm", "seed ledger"])

    def check_clean(self, step: str, vault: Path) -> None:
        report = self.cli_ok(
            step, ["check", "--json", "--no-input", "--vault", str(vault)]
        )
        self.ok(
            step,
            report.get("ok") is True and report.get("findings") == [],
            f"check not clean: {json.dumps(report)}",
        )

    def assert_clean_tree(self, step: str, vault: Path) -> None:
        proc = subprocess.run(
            ["git", "-C", str(vault), "status", "--porcelain"],
            text=True,
            capture_output=True,
            env=self.env(),
        )
        self.ok(
            step,
            proc.stdout.strip() == "",
            f"working tree is not clean: {proc.stdout!r}",
        )


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def plaintext_vault_steps(smoke: Smoke) -> None:
    """Write pipeline, read-path privacy, and the refused-write invariant."""
    vault = smoke.make_plaintext_vault("plaintext", ["coaching@0.1"])

    smoke.write_person(PERSON, "Ada Example")
    smoke.write_person(NO_AI_PERSON, "Cam Sample", no_ai=True)

    step = "record add (plaintext)"
    for record_id in (PERSON, NO_AI_PERSON):
        smoke.cli_ok(
            step,
            [
                "record",
                "add",
                "--file",
                str(smoke.scratch / f"{record_id}.md"),
                "--json",
                "--no-input",
                "--vault",
                str(vault),
            ],
        )
    # Plaintext vault: the record must NOT be an envelope.
    profile = (vault / "people" / PERSON / "profile.md").read_text()
    smoke.ok(step, "enc:" not in profile, "plaintext vault wrote an envelope")
    smoke.ok(step, "Ada Example" in profile, "plaintext record lost its name")
    smoke.mark(step)

    smoke.seed_open_line(vault)

    step = "note add (plaintext)"
    note_body = smoke.scratch / "note.md"
    note_body.write_text("Follow up on the launch.\n")
    report = smoke.cli_ok(
        step,
        [
            "note",
            "add",
            "--person",
            PERSON,
            "--body-file",
            str(note_body),
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    smoke.ok(step, str(report.get("id", "")).startswith("n-"), f"bad note id: {report}")
    smoke.mark(step)

    step = "log session (plaintext)"
    report = smoke.cli_ok(
        step,
        [
            "log",
            "session",
            PERSON,
            "60m",
            "paid",
            "--date",
            SESSION_DATE,
            "--note",
            "Fake session note.",
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    smoke.ok(step, report.get("command") == "log-session", f"bad command: {report}")
    smoke.mark(step)

    smoke.check_clean("check --json (plaintext)", vault)
    smoke.mark("check --json (plaintext)")

    # Read-path privacy: the agent path must hide the no-ai person and the
    # ledger line naming them; the operator path must show the line with the
    # `operator_only` marker, and the agent JSON must never carry that key.
    step = "find agent hides no-ai"
    report = smoke.cli_ok(
        step,
        ["find", "Cam Sample", "--json", "--no-input", "--vault", str(vault)],
    )
    smoke.ok(step, report.get("matches") == [], f"agent find leaked no-ai: {report}")
    smoke.mark(step)

    step = "find operator marks operator_only"
    report = smoke.cli_ok(
        step,
        ["find", TOUCH_DATE, "--for-operator", "--json", "--no-input", "--vault", str(vault)],
    )
    ledger_hits = [m for m in report.get("matches", []) if str(m.get("path", "")).startswith("ledger/")]
    smoke.ok(step, bool(ledger_hits), f"operator find missed the ledger line: {report}")
    smoke.ok(
        step,
        all(m.get("operator_only") is True for m in ledger_hits),
        f"operator-only ledger hit lost its marker: {ledger_hits}",
    )
    agent = smoke.cli_ok(
        step,
        ["find", TOUCH_DATE, "--json", "--no-input", "--vault", str(vault)],
    )
    smoke.ok(step, agent.get("matches") == [], "agent find leaked the no-ai ledger line")
    smoke.mark(step)

    step = "find agent JSON has no operator_only"
    report = smoke.cli_ok(
        step,
        ["find", "Ada", "--json", "--no-input", "--vault", str(vault)],
    )
    smoke.ok(step, bool(report.get("matches")), f"agent find found nothing: {report}")
    smoke.ok(
        step,
        all("operator_only" not in m for m in report["matches"]),
        "agent JSON gained an operator_only key",
    )
    smoke.mark(step)

    step = "context no-ai (agent vs operator)"
    agent = smoke.cli_ok(
        step,
        ["context", NO_AI_PERSON, "--json", "--no-input", "--vault", str(vault)],
    )
    smoke.ok(
        step,
        agent["person"]["no_ai"] is True
        and agent["person"]["name"] is None
        and agent.get("notes") == []
        and "for_operator" not in agent,
        f"agent context leaked a no-ai person: {agent}",
    )
    operator = smoke.cli_ok(
        step,
        [
            "context",
            NO_AI_PERSON,
            "--for-operator",
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    smoke.ok(
        step,
        operator["person"]["name"] == "Cam Sample" and operator.get("for_operator") is True,
        f"operator context did not surface the no-ai person: {operator}",
    )
    smoke.mark(step)

    refused_write_step(smoke, vault)


def refused_write_step(smoke: Smoke, vault: Path) -> None:
    """#604: a refused `record add` must leave no directory behind and the
    vault must still pass `check`.

    The payload shares a ULID with an existing interaction under a different
    prefix, so the write creates `people/p-…/` and the post-check refuses it
    with `E_DUPLICATE_ULID`. Left behind, the empty directory makes the next
    `check` fail `E_FRONTMATTER` — and git never sees it.
    """
    step = "refused write leaves no directories"
    shared = "01J9Z3K4QK0000000000000000"
    interaction_id = f"i-{shared}"
    interaction_dir = vault / "interactions" / interaction_id
    interaction_dir.mkdir(parents=True)
    (interaction_dir / "interaction.md").write_text(
        "---\n"
        f"id: {interaction_id}\n"
        "type: interaction\n"
        "name: Call\n"
        f"person: {PERSON}\n"
        "date: 2026-10-06\n"
        "---\n\nFake call.\n"
    )
    smoke.git(vault, ["add", "-A"])
    smoke.git(vault, ["commit", "-qm", "interaction fixture"])

    new_person = f"p-{shared}"
    payload = smoke.scratch / "duplicate.md"
    payload.write_text(
        "---\n"
        f"id: {new_person}\n"
        "type: person\n"
        'name: "Dana Example"\n'
        "---\n\nFake bio.\n"
    )

    report = smoke.cli_fail(
        step,
        [
            "record",
            "add",
            "--file",
            str(payload),
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    codes = [f.get("code") for f in report.get("findings", [])]
    smoke.ok(step, "E_DUPLICATE_ULID" in codes, f"expected E_DUPLICATE_ULID, got {codes}")
    smoke.ok(
        step,
        not (vault / "people" / new_person).exists(),
        "the refused write left its record directory behind",
    )
    smoke.assert_clean_tree(step, vault)

    check = smoke.cli_ok(
        step, ["check", "--json", "--no-input", "--vault", str(vault)]
    )
    check_codes = [f.get("code") for f in check.get("findings", [])]
    smoke.ok(
        step,
        check.get("ok") is True and "E_FRONTMATTER" not in check_codes,
        f"the vault is unhealthy after the refusal: {check}",
    )
    smoke.mark(step)


def encrypted_vault_steps(smoke: Smoke) -> None:
    """Init, keys, encrypted writes, and the alias stdin round-trip."""
    vault = smoke.vaults / "encrypted"
    if vault.exists():
        shutil.rmtree(vault)

    step = "init (encrypted)"
    report = smoke.cli_ok(
        step,
        [
            "init",
            "--create",
            "--packs",
            "coaching@0.1",
            "--no-input",
            "--json",
            "--vault",
            str(vault),
        ],
    )
    smoke.ok(step, report.get("ok") is True, f"init failed: {report}")
    smoke.ok(step, (vault / "keys").is_dir(), "init did not create the keys/ tree")
    smoke.ok(
        step,
        (smoke.home / ".config" / "confidant" / "trust.toml").is_file(),
        "init did not write the trust anchor",
    )
    smoke.mark(step)

    step = "keys init-client (encrypted)"
    smoke.cli_ok(
        step,
        ["keys", "init-client", PERSON, "--json", "--no-input", "--vault", str(vault)],
    )
    smoke.mark(step)

    smoke.write_person(PERSON, "Ada Example")

    step = "record add (encrypted)"
    smoke.cli_ok(
        step,
        [
            "record",
            "add",
            "--file",
            str(smoke.scratch / f"{PERSON}.md"),
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    profile = (vault / "people" / PERSON / "profile.md").read_text()
    smoke.ok(step, "\nenc:" in f"\n{profile}", f"encrypted vault wrote plaintext: {profile[:120]}")
    smoke.ok(step, "Ada Example" not in profile, "encrypted profile leaked its plaintext name")
    smoke.mark(step)

    smoke.seed_open_line(vault, no_ai_touch=False)

    step = "note add (encrypted)"
    note_body = smoke.scratch / "enc-note.md"
    note_body.write_text("Follow up on the launch.\n")
    smoke.cli_ok(
        step,
        [
            "note",
            "add",
            "--person",
            PERSON,
            "--body-file",
            str(note_body),
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    smoke.mark(step)

    step = "log session (encrypted)"
    smoke.cli_ok(
        step,
        [
            "log",
            "session",
            PERSON,
            "60m",
            "paid",
            "--date",
            SESSION_DATE,
            "--note",
            "Fake session note.",
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    smoke.mark(step)

    step = "alias add + resolve (stdin)"
    value_file = smoke.scratch / "alias-email.txt"
    value_file.write_text(" Ada@Example.com \n")
    added = smoke.cli_ok(
        step,
        [
            "alias",
            "add",
            PERSON,
            "email",
            "--value-file",
            str(value_file),
            "--date",
            ALIAS_DATE,
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    smoke.ok(step, added.get("command") == "alias-add", f"bad alias add: {added}")
    smoke.ok(step, str(added.get("hmac", "")).startswith("hmac:"), f"no hmac: {added}")
    smoke.ok(
        step,
        "Ada@Example.com" not in json.dumps(added),
        "the alias value leaked into alias-add output",
    )
    resolved = smoke.cli_ok(
        step,
        ["alias", "resolve", "email", "--json", "--no-input", "--vault", str(vault)],
        stdin="ada@example.com",
    )
    smoke.ok(
        step,
        resolved.get("matched_by") == "alias" and resolved["person"]["id"] == PERSON,
        f"alias resolve failed: {resolved}",
    )
    smoke.ok(
        step,
        "ada@example.com" not in json.dumps(resolved),
        "the alias value leaked into alias-resolve output",
    )
    smoke.mark(step)

    smoke.check_clean("check --json (encrypted)", vault)
    smoke.mark("check --json (encrypted)")


def plaintext_init_refusal_step(smoke: Smoke) -> None:
    """Spec 3: `init` must refuse a vault that declares `mode = "plaintext"`."""
    step = "init refuses a plaintext declaration"
    vault = smoke.make_plaintext_vault("plaintext-init", [])
    smoke.cli_fail(
        step,
        ["init", "--no-input", "--json", "--vault", str(vault)],
        code="E_CONFIG",
    )
    smoke.ok(
        step,
        not (vault / "keys").exists(),
        "a refused init left a keys/ tree behind",
    )
    smoke.mark(step)


def pack_lifecycle_steps(smoke: Smoke) -> None:
    """Install, no-op update, stale-pin repair, and remove."""
    vault = smoke.make_plaintext_vault("packs", [])
    pack_dir = str(PACK_DIR)

    step = "pack add --from-dir"
    report = smoke.cli_ok(
        step,
        [
            "pack",
            "add",
            "--from-dir",
            pack_dir,
            "--yes",
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    smoke.ok(step, report["pack"]["name"] == "coaching-ext", f"bad pack add: {report}")
    smoke.ok(
        step,
        (vault / "packs" / "coaching-ext@0.1" / "manifest.toml").is_file(),
        "pack was not vendored",
    )
    smoke.check_clean("check --json (pack added)", vault)
    smoke.mark(step)

    step = "pack verify"
    verify = subprocess.run(
        [smoke.cli, "pack", "verify", "--vault", str(vault)],
        text=True,
        capture_output=True,
        env=smoke.env(),
    )
    smoke.ok(step, verify.returncode == 0, f"pack verify failed: {verify.stderr}")
    smoke.mark(step)

    step = "pack update no-op is unchanged"
    report = smoke.cli_ok(
        step,
        [
            "pack",
            "update",
            "coaching-ext",
            "--from-dir",
            pack_dir,
            "--yes",
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    smoke.ok(step, report.get("unchanged") is True, f"no-op update was not unchanged: {report}")
    smoke.ok(step, report.get("error") is None, f"no-op update returned an error: {report}")
    smoke.assert_clean_tree(step, vault)
    smoke.mark(step)

    step = "pack update repairs a stale lock hash"
    lock_path = vault / "confidant.lock"
    good_lock = lock_path.read_text()
    match = re.search(r'sha256:([0-9a-f]{64})', good_lock)
    smoke.ok(step, match is not None, f"no lock hash found: {good_lock}")
    good_hash = match.group(1)
    stale_hash = "0" * 64 if good_hash[0] != "0" else "1" * 64
    lock_path.write_text(good_lock.replace(good_hash, stale_hash))
    smoke.git(vault, ["add", "confidant.lock"])
    smoke.git(vault, ["commit", "-qm", "plant stale pin"])
    # The stale pin is an error-severity finding, so `check` exits non-zero.
    check = smoke.cli_fail(step, ["check", "--json", "--no-input", "--vault", str(vault)])
    smoke.ok(
        step,
        any(f.get("code") == "E_PACK_HASH" for f in check.get("findings", [])),
        f"the stale pin was not flagged: {check}",
    )
    report = smoke.cli_ok(
        step,
        [
            "pack",
            "update",
            "coaching-ext",
            "--from-dir",
            pack_dir,
            "--yes",
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    smoke.ok(step, report.get("unchanged") is None, f"a stale pin is not a no-op: {report}")
    smoke.ok(
        step,
        report.get("files") == ["confidant.lock"],
        f"the repair touched more than the lock: {report}",
    )
    smoke.ok(
        step,
        lock_path.read_text() == good_lock,
        "the repair did not restore the good lock hash",
    )
    smoke.assert_clean_tree(step, vault)
    smoke.check_clean("check --json (lock repaired)", vault)
    smoke.mark(step)

    step = "pack remove"
    report = smoke.cli_ok(
        step,
        [
            "pack",
            "remove",
            "coaching-ext",
            "--yes",
            "--json",
            "--no-input",
            "--vault",
            str(vault),
        ],
    )
    smoke.ok(
        step,
        report.get("removed") == ["coaching-ext@0.1"],
        f"pack remove did not remove the pack: {report}",
    )
    smoke.ok(
        step,
        not (vault / "packs" / "coaching-ext@0.1").exists(),
        "pack remove left the vendored tree behind",
    )
    smoke.check_clean("check --json (pack removed)", vault)
    smoke.mark(step)


# ---------------------------------------------------------------------------
# Work directory safety
# ---------------------------------------------------------------------------


class WorkdirRefused(Exception):
    """A `--workdir` was refused because the smoke did not create it."""


def resolve_workdir(raw: str | None) -> tuple[Path, bool]:
    """Return `(root, temporary)` for the run's vaults.

    `raw is None` uses a fresh temp dir (deleted at the end). An explicit
    `--workdir` is wiped first, so it is only accepted when it does not
    exist, is empty, or carries the `.qa-smoke` marker this script wrote on
    an earlier run. Anything else is refused — never deleted — so
    `--workdir ~` or `--workdir .` cannot destroy real data.
    """
    if raw is None:
        root = Path(tempfile.mkdtemp(prefix="confidant-qa-smoke-"))
        (root / MARKER).write_text("qa smoke work directory\n")
        return root, True

    root = Path(raw).expanduser()
    if root.is_symlink():
        raise WorkdirRefused(f"{root} is a symbolic link; refusing to follow it")
    if root.exists() and not root.is_dir():
        raise WorkdirRefused(
            f"{root} exists and is not a directory; refusing to overwrite it"
        )
    if root.is_dir():
        entries = {entry.name for entry in root.iterdir()}
        if entries and MARKER not in entries:
            raise WorkdirRefused(
                f"{root} is not empty and does not carry the {MARKER} marker, "
                f"so the smoke did not create it"
            )
        shutil.rmtree(root)
    root.mkdir(parents=True)
    (root / MARKER).write_text("qa smoke work directory\n")
    return root, False


def self_test() -> int:
    """Exercise the `--workdir` refusal against a fixture tree."""
    failures = 0

    def check(label: str, path: Path, expect_refusal: bool) -> None:
        nonlocal failures
        try:
            root, temporary = resolve_workdir(str(path))
        except WorkdirRefused as err:
            got, detail = True, str(err)
        else:
            got, detail = False, str(root)
            if temporary:
                shutil.rmtree(root, ignore_errors=True)
        ok = got == expect_refusal
        if not ok:
            failures += 1
        print(f"  [{'ok' if ok else 'MISMATCH'}] {label}")
        if not ok:
            print(f"      detail: {detail}")

    with tempfile.TemporaryDirectory() as td:
        base = Path(td)

        unmarked = base / "unmarked"
        unmarked.mkdir()
        (unmarked / "important.txt").write_text("keep me\n")
        check(
            "a non-empty dir without the marker is refused",
            unmarked,
            True,
        )

        marked = base / "marked"
        marked.mkdir()
        (marked / MARKER).write_text("qa smoke work directory\n")
        (marked / "leftover").write_text("stale\n")
        check("a non-empty dir with the marker is accepted and wiped", marked, False)
        if marked.exists() and (marked / "leftover").exists():
            failures += 1
            print("  [MISMATCH] the marked dir was not wiped")

        empty = base / "empty"
        empty.mkdir()
        check("an empty dir is accepted", empty, False)

        absent = base / "absent"
        check("an absent dir is created", absent, False)

        a_file = base / "a-file"
        a_file.write_text("not a dir\n")
        check("a path that is a file is refused", a_file, True)

        link = base / "link"
        try:
            link.symlink_to(base / "absent", target_is_directory=True)
        except OSError:
            pass  # symlinks unavailable (e.g. a restricted runner): skip
        else:
            check("a symlinked path is refused", link, True)

    if failures:
        print(f"self-test FAILED ({failures} mismatch(es))")
        return 1
    print("self-test passed")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cli",
        default=os.environ.get("CONFIDANT_BIN", "target/debug/confidant"),
        help="path to the built confidant binary (default: target/debug/confidant)",
    )
    parser.add_argument(
        "--workdir",
        default=None,
        help="directory for the throwaway vaults (default: a fresh temp dir)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="exercise the --workdir refusal against a fixture tree and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    cli = Path(args.cli)
    if not cli.is_absolute():
        cli = (REPO / cli).resolve()
    if not cli.is_file():
        print(f"qa smoke FAILED: CLI not found at {cli}", file=sys.stderr)
        return 1

    if not PACK_DIR.is_dir():
        print(f"qa smoke FAILED: fixture pack missing at {PACK_DIR}", file=sys.stderr)
        return 1

    try:
        root, temporary = resolve_workdir(args.workdir)
    except WorkdirRefused as err:
        print(f"qa smoke FAILED: refusing --workdir: {err}", file=sys.stderr)
        print(
            f"Pass a fresh path, an empty directory, or a directory the smoke "
            f"created (carrying {MARKER}).",
            file=sys.stderr,
        )
        return 1

    print(f"qa smoke: {cli}")
    print(f"qa smoke: workdir {root}")
    smoke = Smoke(cli, root)

    try:
        plaintext_vault_steps(smoke)
        # Before the encrypted init writes a trust anchor: the plaintext
        # refusal is masked by "anchor already exists" once one does.
        plaintext_init_refusal_step(smoke)
        encrypted_vault_steps(smoke)
        pack_lifecycle_steps(smoke)
    except SmokeFailure as err:
        print(f"\nqa smoke FAILED at step: {err.step}", file=sys.stderr)
        print(err.detail, file=sys.stderr)
        print(f"\n{smoke.step_count} step(s) passed before the failure:", file=sys.stderr)
        for name in smoke.steps:
            print(f"  - {name}", file=sys.stderr)
        return 1
    finally:
        if temporary:
            shutil.rmtree(root, ignore_errors=True)

    print(f"\nqa smoke passed: {smoke.step_count} steps")
    for name in smoke.steps:
        print(f"  - {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
