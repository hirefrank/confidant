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
DEMO = REPO_ROOT / "examples" / "demo-vault"

PERSON = "p-01M3TC5H00MPJG000000000000"
CJK_ID = "n-01M3TC5H00MPJG00CJK0000001"
SHORT_ID = "n-01M3TC5H00MPJG00N0TE000002"
# The demo vault's no-ai person: cleared_files never contains these paths.
NO_AI_NOTE = ("people/p-01M3TC5H00MPJG001248000002/notes/"
              "n-01M3TC5H000068T0000000000C.md")
# Cleared unscoped; owned by coaching (referenced by a ledger line).
COACHING_NOTE = f"people/{PERSON}/notes/n-01M3TC5H00MPJG002NAM000005.md"
# Cleared unscoped, but unattributed: out of scope for --packs coaching.
UNATTRIBUTED_NOTE = f"people/{PERSON}/notes/n-01M3TC5H00MPJG0036CR000006.md"

CJK_NOTE = f"people/{PERSON}/notes/{CJK_ID}.md"
SHORT_NOTE = f"people/{PERSON}/notes/{SHORT_ID}.md"

CJK_BODY = "山田さんと面談。日本語だけのメモ。"
SHORT_BODY = "OK? #12 — done."
LEDGER_REL = "ledger/2026/10.cfd"
# reindex writes only cleared ledger lines into the corpus, in order, so the
# corpus line is not the vault line: corpus line 8 is vault line 10.
LEDGER_CORPUS_LINE = 8
LEDGER_VAULT_LINE = 10

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


def add_note(vault, note_id, body):
    path = vault / "people" / PERSON / "notes" / f"{note_id}.md"
    path.write_text(
        f"---\nid: {note_id}\ntype: note\nperson: {PERSON}\n"
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
        add_note(cls.vault, CJK_ID, CJK_BODY)
        add_note(cls.vault, SHORT_ID, SHORT_BODY)
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
                "2026-10-08 balance p-01M3TC5H00MPJG000000000000 sessions_remaining 4",
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
        self.assertIn("sessions_remaining 4", ledger["excerpt"])
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
            hit(COACHING_NOTE, 5, "Kickoff. Ada wants a vault that agents can write.", score=0.9),
            hit(UNATTRIBUTED_NOTE, 6, "Follow-up. Balance assertions caught a duplicate.", score=0.8),
            # Corpus line 1 is the unattributed ledger comment: cleared
            # unscoped, out of scope for coaching.
            hit(LEDGER_REL, 1, "; Demo ledger. FAKE data only.", score=0.7),
        ], packs="coaching@0.1")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.paths(data), [COACHING_NOTE])
        self.assertEqual(data["dropped_uncleared"], 2)

    def test_fallback_when_qmd_is_missing(self):
        """No qmd: plain `find` fallback and the JSON contract are unchanged."""
        p, data, spawns = self.query([], query="Kickoff", with_qmd=False)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(data["mode"], "find-fallback")
        self.assertEqual(data["dropped_uncleared"], 0)
        self.assertTrue(data["matches"])
        self.assertEqual(data["matches"][0]["via"], "find")
        self.assertEqual(data["matches"][0]["path"], COACHING_NOTE)
        self.assertEqual(len(spawns), 1, spawns)
        self.assertIn("find Kickoff", spawns[0])


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
