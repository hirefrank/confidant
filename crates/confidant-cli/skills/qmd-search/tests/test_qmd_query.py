#!/usr/bin/env python3
"""Focused tests for qmd-query.py's allowlist verification (issue #538).

The script is driven without QMD: a fake `qmd` on PATH prints canned hits,
and a wrapper `confidant` on PATH logs every spawn, so the tests can assert
both clearance behavior and the one-CLI-call contract (#538 replaced one
`confidant find` per hit file with a single `confidant allowlist`).

Run from the repo root:

    python3 crates/confidant-cli/skills/qmd-search/tests/test_qmd_query.py \
        --cli target/debug/confidant

`--cli` defaults to $CONFIDANT_CLI, then `target/debug/confidant`; the suite
skips (with a message) when no built CLI is found. Fake data only — the
notes added here are the demo vault's style of obviously fake content.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
SKILL_DIR = TESTS_DIR.parent
REPO_ROOT = TESTS_DIR.parents[4]
QUERY = SKILL_DIR / "bin" / "qmd-query.py"
INDEX = SKILL_DIR / "bin" / "qmd-index.py"
DEMO = REPO_ROOT / "examples" / "demo-vault"

PERSON = "p-01M3TC5H00MPJG000000000101"
NO_AI_PERSON = "p-01M3TC5H00MPJG001248000002"
CJK_ID = "n-01M3TC5H00MPJG00CJK0000001"
SHORT_ID = "n-01M3TC5H00MPJG00N0TE000002"
# The fixture's no-ai person: cleared_files never contains these paths.
NO_AI_NOTE = (f"people/{NO_AI_PERSON}/notes/"
              "n-01M3TC5H000068T0000000000C.md")
# Cleared unscoped; owned by the implicit personal pack (a `touch` line
# references it).
LINKED_NOTE = f"people/{PERSON}/notes/n-01M3TC5H00MPJG002NAM000005.md"
# Cleared unscoped, but unattributed: out of scope for a `--packs` ceiling.
UNATTRIBUTED_NOTE = f"people/{PERSON}/notes/n-01M3TC5H00MPJG0036CR000006.md"

CJK_NOTE = f"people/{PERSON}/notes/{CJK_ID}.md"
SHORT_NOTE = f"people/{PERSON}/notes/{SHORT_ID}.md"

CJK_BODY = "山田さんと面談。日本語だけのメモ。"
SHORT_BODY = "OK? #12 — done."
LEDGER_REL = "ledger/2026/11.cfd"
# A small file: reindex writes the cleared line at the same position.
LEDGER_CORPUS_LINE = 1
LEDGER_VAULT_LINE = 1

# The retired probe rule (qmd-query.py before #538): a >= 24-char ASCII run.
OLD_PROBE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9'’\- ]{8,}")

FAKE_QMD = '''#!/usr/bin/env python3
"""Fake qmd: `status` reports no vectors, everything else prints canned hits."""
import os
import sys

if len(sys.argv) > 1 and sys.argv[1] == "status":
    print("Vectors: 0 embedded")
    sys.exit(0)
with open(os.environ["FAKE_QMD_HITS"], encoding="utf-8") as f:
    print(f.read())
'''

CONFIDANT_WRAPPER = '''#!/bin/sh
# Log one line per spawn, then run the real CLI.
printf '%s\\n' "$*" >> "$CONFIDANT_SPAWN_LOG"
exec {cli} "$@"
'''


def resolve_cli():
    argv = sys.argv
    if "--cli" in argv:
        return Path(argv[argv.index("--cli") + 1]).resolve()
    if os.environ.get("CONFIDANT_CLI"):
        return Path(os.environ["CONFIDANT_CLI"]).resolve()
    return (REPO_ROOT / "target" / "debug" / "confidant").resolve()


def write_exec(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def add_person(vault, person_id, name, extra=""):
    path = vault / "people" / person_id / "profile.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"---\nid: {person_id}\ntype: person\nname: {name}\n{extra}---\n\nFake person.\n",
        encoding="utf-8",
    )


def add_note(vault, note_id, body, person=PERSON):
    path = vault / "people" / person / "notes" / f"{note_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"---\nid: {note_id}\ntype: note\nperson: {person}\n"
        f"date: 2026-10-01\nsession: 2026-10-01\n---\n\n{body}\n",
        encoding="utf-8",
    )


def hit(rel, line, snippet, score=1.0):
    """One qmd --json hit for a vault-relative path."""
    uri = rel + ".md" if rel.endswith(".cfd") else rel
    return {"file": f"qmd://confidant/{uri}", "line": line,
            "score": score, "snippet": snippet}


class QmdQueryTest(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        if not QUERY.is_file():
            raise unittest.SkipTest(f"skill script not found: {QUERY}")
        if shutil.which("git") is None:
            raise unittest.SkipTest("git is required (reindex probes the gitignore)")
        cls.cli = resolve_cli()
        if not cls.cli.is_file():
            raise unittest.SkipTest(
                f"no built confidant at {cls.cli}; build it or pass --cli PATH")

        cls.tmp = tempfile.TemporaryDirectory(prefix="qmd-query-538-")
        cls.root = Path(cls.tmp.name)
        cls.vault = cls.root / "vault"
        shutil.copytree(DEMO, cls.vault)
        add_person(cls.vault, NO_AI_PERSON, "Cam Sample", "no-ai: true\n")
        add_note(cls.vault, CJK_ID, CJK_BODY)
        add_note(cls.vault, SHORT_ID, SHORT_BODY)
        add_note(cls.vault, "n-01M3TC5H00MPJG002NAM000005", "Kickofftoken. Dana wants a vault that agents can write.")
        add_note(cls.vault, "n-01M3TC5H00MPJG0036CR000006", "Followuptoken. Balance assertions caught a duplicate.")
        add_note(cls.vault, "n-01M3TC5H000068T0000000000C", "Cam asked that notes never go to a model provider.", person=NO_AI_PERSON)
        (cls.vault / "ledger/2026/11.cfd").write_text(
            f"2026-11-01 touch {PERSON} meeting note:n-01M3TC5H00MPJG002NAM000005\n",
            encoding="utf-8",
        )
        (cls.vault / ".gitignore").write_text(".confidant/\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=cls.vault, check=True)
        # Build the real corpus: the ledger alignment reads the file reindex
        # writes, so the test exercises the shipped corpus layout.
        r = subprocess.run(
            [str(cls.cli), "reindex", "--json", "--no-input",
             "--vault", str(cls.vault)],
            capture_output=True, text=True)
        if r.returncode != 0:
            raise AssertionError(f"reindex failed: {r.stdout}{r.stderr}")

        cls.bin = cls.root / "bin"
        cls.bin.mkdir()
        write_exec(cls.bin / "qmd", FAKE_QMD)
        write_exec(cls.bin / "confidant",
                   CONFIDANT_WRAPPER.format(cli=shlex.quote(str(cls.cli))))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def query(self, hits, query="anything", packs=None, with_qmd=True):
        """Run qmd-query.py; return (returncode, parsed stdout, spawn log)."""
        hits_file = self.root / "hits.json"
        hits_file.write_text(json.dumps(hits), encoding="utf-8")
        spawn_log = self.root / "spawns.log"
        spawn_log.write_text("", encoding="utf-8")
        bindir = self.bin if with_qmd else self.root / "no-qmd"
        if with_qmd:
            path = f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"
        else:
            # A minimal PATH without qmd, so the fallback is deterministic
            # even on a developer machine that has QMD installed.
            bindir.mkdir(exist_ok=True)
            shutil.copy2(self.bin / "confidant", bindir / "confidant")
            path = os.pathsep.join([str(bindir), os.path.dirname(sys.executable),
                                    "/usr/bin", "/bin"])
        env = dict(os.environ, PATH=path, FAKE_QMD_HITS=str(hits_file),
                   CONFIDANT_SPAWN_LOG=str(spawn_log))
        argv = [sys.executable, str(QUERY), "--vault", str(self.vault)]
        if packs:
            argv += ["--packs", packs]
        argv.append(query)
        p = subprocess.run(argv, capture_output=True, text=True, env=env)
        data = json.loads(p.stdout) if p.stdout.strip() else None
        spawns = spawn_log.read_text(encoding="utf-8").splitlines()
        if not with_qmd:  # determinism guard: a stray qmd must not hide the fallback
            if shutil.which("qmd", path=env["PATH"]) is not None:
                self.skipTest("a real qmd is on PATH; cannot test the fallback")
        return p, data, spawns

    def paths(self, data):
        return [m["path"] for m in data["matches"]]

    def test_cjk_short_and_ledger_hits_are_not_dropped(self):
        """#538: cleared CJK/short notes and a shifted ledger line come back."""
        for text in (CJK_BODY, SHORT_BODY):
            probes = [r for r in OLD_PROBE_RE.findall(text) if len(r.strip(" -'’")) >= 24]
            self.assertEqual(probes, [], f"the old probe rule would not be empty: {text!r}")
        p, data, spawns = self.query([
            hit(CJK_NOTE, 5, CJK_BODY, score=0.9),
            hit(SHORT_NOTE, 5, SHORT_BODY, score=0.8),
            hit(NO_AI_NOTE, 5, "Cam asked that notes never go to a model provider.", score=0.7),
            hit(LEDGER_REL, LEDGER_CORPUS_LINE,
                f"2026-11-01 touch {PERSON} meeting note:n-01M3TC5H00MPJG002NAM000005",
                score=0.6),
        ])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(CJK_NOTE, self.paths(data), "cleared CJK note was dropped")
        self.assertIn(SHORT_NOTE, self.paths(data), "cleared short note was dropped")
        self.assertNotIn(NO_AI_NOTE, self.paths(data), "a no-ai hit was returned")
        by_path = {m["path"]: m for m in data["matches"]}
        cjk = by_path[CJK_NOTE]
        self.assertEqual(cjk["id"], CJK_ID)
        self.assertIn(CJK_BODY, cjk["excerpt"])
        self.assertEqual(by_path[SHORT_NOTE]["id"], SHORT_ID)
        # The ledger hit reports the vault line, not the corpus line.
        ledger = by_path[LEDGER_REL]
        self.assertEqual(ledger["line"], LEDGER_VAULT_LINE)
        self.assertEqual(ledger["id"], PERSON)
        self.assertIn("touch", ledger["excerpt"])
        self.assertEqual(data["dropped_uncleared"], 1)
        # #538: one vault load per query, not one per hit file.
        self.assertEqual(len(spawns), 1, spawns)
        self.assertIn("allowlist --json", spawns[0])

    def test_uncleared_ledger_line_is_dropped(self):
        """A stale/corpus-only ledger line resolves to nothing: fail closed."""
        p, data, spawns = self.query([
            hit(LEDGER_REL, 999, "2026-10-09 stage d-01M3TC5H00MPJG00248G000004 proposal"),
        ])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(data["matches"], [])
        self.assertEqual(data["dropped_uncleared"], 1)
        self.assertEqual(len(spawns), 1)

    def test_scope_drops_out_of_scope_ledger_and_note_hits(self):
        """`--packs` scopes the one allowlist call: out-of-scope hits drop."""
        p, data, _ = self.query([
            hit(LINKED_NOTE, 5, "Kickofftoken. Dana wants a vault that agents can write.", score=0.9),
            hit(UNATTRIBUTED_NOTE, 6, "Followuptoken. Balance assertions caught a duplicate.", score=0.8),
            hit(LEDGER_REL, 1, f"2026-11-01 touch {PERSON} meeting", score=0.7),
        ], packs="personal@0.2")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.paths(data), [LINKED_NOTE, LEDGER_REL])
        self.assertEqual(data["dropped_uncleared"], 1)

    def test_fallback_when_qmd_is_missing(self):
        """No qmd: plain `find` fallback and the JSON contract are unchanged."""
        p, data, spawns = self.query([], query="Kickoff", with_qmd=False)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(data["mode"], "find-fallback")
        self.assertEqual(data["dropped_uncleared"], 0)
        self.assertTrue(data["matches"])
        self.assertEqual(data["matches"][0]["via"], "find")
        self.assertEqual(data["matches"][0]["path"], LINKED_NOTE)
        self.assertEqual(len(spawns), 1, spawns)
        self.assertIn("find Kickoff", spawns[0])


def load_index_module():
    """Import bin/qmd-index.py (a hyphenated filename) as a module."""
    spec = importlib.util.spec_from_file_location("qmd_index", INDEX)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class QmdIndexEncryptedDiskTest(unittest.TestCase):
    """#540: the encrypted-disk gate honours a persisted confirmation.

    The gate is device policy, so the tests drive
    `encrypted_disk_confirmation` with detection patched instead of building
    a corpus: the env var and the user-config key both satisfy it, neither
    (with no detection) refuses, and detection is reported ahead of any
    operator assertion.
    """

    home_keys = ("CONFIDANT_ASSUME_ENCRYPTED_DISK", "HOME")

    def setUp(self):
        self.index = load_index_module()
        self._saved = {k: os.environ.get(k) for k in self.home_keys}
        self._detected = self.index.encrypted_disk_detected
        os.environ.pop("CONFIDANT_ASSUME_ENCRYPTED_DISK", None)
        self.tmp = tempfile.TemporaryDirectory(prefix="qmd-index-540-")
        self.home = Path(self.tmp.name)
        os.environ["HOME"] = str(self.home)

    def tearDown(self):
        self.index.encrypted_disk_detected = self._detected
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tmp.cleanup()

    def detect(self, value):
        self.index.encrypted_disk_detected = lambda vault: value

    def write_user_config(self, text):
        cfg = self.home / ".config" / "confidant"
        cfg.mkdir(parents=True, exist_ok=True)
        (cfg / "config.toml").write_text(text, encoding="utf-8")

    def test_env_confirmation_satisfies_gate(self):
        self.detect(None)  # no detection possible (cloud VM / container)
        os.environ["CONFIDANT_ASSUME_ENCRYPTED_DISK"] = "1"
        self.assertEqual(
            self.index.encrypted_disk_confirmation("/vault", False),
            "asserted via CONFIDANT_ASSUME_ENCRYPTED_DISK")

    def test_user_config_confirmation_satisfies_gate(self):
        self.detect(None)
        self.write_user_config("[qmd]\nassume_encrypted_disk = true\n")
        mechanism = self.index.encrypted_disk_confirmation("/vault", False)
        self.assertIn("config.toml", mechanism)
        self.assertIn("assume_encrypted_disk", mechanism)

    def test_without_confirmation_it_refuses(self):
        self.detect(False)  # definitively not detected, no assertion
        with self.assertRaises(SystemExit):
            self.index.ensure_encrypted_disk("/vault", False)

    def test_detection_preferred_over_assertions(self):
        self.detect(True)
        os.environ["CONFIDANT_ASSUME_ENCRYPTED_DISK"] = "1"
        self.write_user_config("[qmd]\nassume_encrypted_disk = true\n")
        self.assertEqual(
            self.index.encrypted_disk_confirmation("/vault", True),
            "detected (FileVault/dm-crypt)")

    def test_mechanism_is_printed_to_stderr(self):
        self.detect(None)
        os.environ["CONFIDANT_ASSUME_ENCRYPTED_DISK"] = "true"
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.index.ensure_encrypted_disk("/vault", False)
        self.assertIn("CONFIDANT_ASSUME_ENCRYPTED_DISK", err.getvalue())

    def test_flag_alone_still_satisfies_gate(self):
        self.detect(None)
        self.assertEqual(
            self.index.encrypted_disk_confirmation("/vault", True),
            "asserted via --i-confirm-encrypted-disk")


class FakeTtyStdin(io.StringIO):
    """stdin with isatty() True, so the #723 election prompt runs."""

    def isatty(self):
        return True


class FakePipeStdin(io.StringIO):
    """stdin with isatty() False, so the #723 election never prompts."""

    def isatty(self):
        return False


class QmdIndexDiskElectionTest(unittest.TestCase):
    """#723: the disk election happens once, at setup, and persists.

    No new key is invented: the election writes the existing #540
    `[qmd] assume_encrypted_disk` key. The interactive prompt runs only
    on a TTY; anything else keeps the old refusal.
    """

    def setUp(self):
        self.index = load_index_module()
        self._saved_home = os.environ.get("HOME")
        self._saved_stdin = sys.stdin
        self._detected = self.index.encrypted_disk_detected
        os.environ.pop("CONFIDANT_ASSUME_ENCRYPTED_DISK", None)
        self.tmp = tempfile.TemporaryDirectory(prefix="qmd-index-723-")
        self.home = Path(self.tmp.name)
        os.environ["HOME"] = str(self.home)

    def tearDown(self):
        self.index.encrypted_disk_detected = self._detected
        sys.stdin = self._saved_stdin
        if self._saved_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._saved_home
        self.tmp.cleanup()

    def user_config(self):
        cfg = self.home / ".config" / "confidant" / "config.toml"
        return cfg.read_text(encoding="utf-8") if cfg.is_file() else None

    def test_persist_preserves_other_keys_and_comments(self):
        cfg = self.home / ".config" / "confidant"
        cfg.mkdir(parents=True, exist_ok=True)
        (cfg / "config.toml").write_text(
            "# Preflight choice (issue #722).\n"
            "[qmd]\noffline = true\n",
            encoding="utf-8")
        self.index.persist_encrypted_disk_assumption()
        text = self.user_config()
        self.assertIn("offline = true", text)
        self.assertIn("# Preflight choice", text)
        self.assertIn("assume_encrypted_disk = true", text)
        # Idempotent: a second persist replaces, never duplicates.
        self.index.persist_encrypted_disk_assumption()
        self.assertEqual(self.user_config().count("assume_encrypted_disk"), 1)

    def test_persist_creates_qmd_section(self):
        self.index.persist_encrypted_disk_assumption()
        self.assertEqual(
            self.index.assume_from_user_config(), True)

    def test_election_assert_persists_and_proceeds(self):
        self.index.encrypted_disk_detected = lambda vault: None
        sys.stdin = FakeTtyStdin("a\n")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.index.ensure_encrypted_disk("/vault", False)
        self.assertIn("asserted by operator at setup", err.getvalue())
        self.assertIn("assume_encrypted_disk = true", self.user_config())

    def test_election_decline_keeps_qmd_off(self):
        self.index.encrypted_disk_detected = lambda vault: None
        sys.stdin = FakeTtyStdin("d\n")
        with self.assertRaises(SystemExit) as caught:
            with contextlib.redirect_stderr(io.StringIO()):
                self.index.ensure_encrypted_disk("/vault", False)
        self.assertIn("stays off", str(caught.exception.code))
        self.assertIsNone(self.user_config())

    def test_election_eof_refuses_without_assuming(self):
        self.index.encrypted_disk_detected = lambda vault: None
        sys.stdin = FakeTtyStdin("")
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                self.index.ensure_encrypted_disk("/vault", False)
        self.assertIsNone(self.user_config())

    def test_election_reprompts_then_asserts(self):
        self.index.encrypted_disk_detected = lambda vault: None
        sys.stdin = FakeTtyStdin("maybe\na\n")
        with contextlib.redirect_stderr(io.StringIO()):
            self.index.ensure_encrypted_disk("/vault", False)
        self.assertIn("assume_encrypted_disk = true", self.user_config())

    def test_non_tty_keeps_the_old_refusal(self):
        self.index.encrypted_disk_detected = lambda vault: None
        sys.stdin = FakePipeStdin("")
        with self.assertRaises(SystemExit) as caught:
            with contextlib.redirect_stderr(io.StringIO()):
                self.index.ensure_encrypted_disk("/vault", False)
        self.assertIn("could not confirm", str(caught.exception.code))
        self.assertIsNone(self.user_config())


if __name__ == "__main__":
    # Strip our own --cli flag; leave any unittest flags (-v, -k, …) alone.
    argv, rest, i = [sys.argv[0]], sys.argv[1:], 0
    while i < len(rest):
        if rest[i] == "--cli":
            i += 2
            continue
        argv.append(rest[i])
        i += 1
    unittest.main(argv=argv, verbosity=2)
