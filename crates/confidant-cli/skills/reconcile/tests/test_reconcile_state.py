#!/usr/bin/env python3
"""Tests for the reconcile skill's SKILL.md and local state helper.

Run from the repo root:

    python3 crates/confidant-cli/skills/reconcile/tests/test_reconcile_state.py

The helper reads the vault only through `confidant allowlist --json` (the
§12 cleared set), so this suite uses a fake CLI that prints a canned cleared
set. No real vault or built binary is needed. Fake data only.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
SKILL_DIR = TESTS_DIR.parent
SCRIPT = SKILL_DIR / "bin" / "reconcile-state.py"
SKILL_MD = SKILL_DIR / "SKILL.md"

PERSON = "p-01M3TC5H00MPJG000000000101"
OTHER = "p-01M3TC5H00MPJG000000000102"
THIRD = "p-01M3TC5H00MPJG000000000103"
FOURTH = "p-01M3TC5H00MPJG000000000104"
HIDDEN = "p-01M3TC5H00MPJG001248000002"

# Built by concatenation so this test file, which is itself embedded in the
# binary's skills tree, does not carry the literal operator-only names that
# embedded.rs's #559 drift test forbids.
FORBIDDEN = ("record" + " list", "--for" + "-operator", "for" + "_operator")

# A stand-in for `confidant allowlist --json`: the helper only needs the
# cleared record paths, and the ids are what the state must filter against.
FAKE_CLI = '''#!/usr/bin/env python3
import json, os, sys
# Optional: prove `plan` detaches candidate stdin. A wrapper that reads
# stdin must not eat the JSON the parent is about to parse.
if os.environ.get("FAKE_CLI_READ_STDIN") == "1":
    sys.stdin.read()
ids = [i for i in os.environ.get("FAKE_CLEARED", "").split(",") if i]
if os.environ.get("FAKE_CLI_OK", "1") != "1":
    sys.exit("fake confidant failure")
paths = ["people/%s/profile.md" % i for i in ids]
print(json.dumps({"ok": True, "cleared_files": paths}))
'''


def make_vault(root: Path, gitignored: bool = True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    vault = root / "vault"
    vault.mkdir(exist_ok=True)
    (vault / "confidant.toml").write_text('spec = "0.2"\n', encoding="utf-8")
    if shutil.which("git"):
        subprocess.run(
            ["git", "-C", str(vault), "init", "-q"],
            check=True,
            capture_output=True,
        )
    if gitignored:
        (vault / ".gitignore").write_text(".confidant/\n", encoding="utf-8")
    return vault


def state_path(vault: Path) -> Path:
    return vault / ".confidant" / "reconcile-state.json"


class SkillTextTests(unittest.TestCase):
    def test_front_matter_is_well_formed(self):
        text = SKILL_MD.read_text(encoding="utf-8")
        match = re.match(r"\A---\n(.*?)\n---\n", text, re.DOTALL)
        self.assertIsNotNone(match, "SKILL.md has no closing front-matter fence")
        front = match.group(1)
        name = re.search(r'^name:\s*"([^"]+)"\s*$', front, re.MULTILINE)
        desc = re.search(r'^description:\s*"([^"]+)"\s*$', front, re.MULTILINE)
        self.assertIsNotNone(name, "front matter has no quoted name")
        self.assertIsNotNone(desc, "front matter has no quoted description")
        self.assertEqual(name.group(1), SKILL_DIR.name)
        self.assertGreater(len(desc.group(1)), 40)
        body = text[match.end():]
        self.assertTrue(body.lstrip().startswith("# "), "body has no heading")

    def test_skill_never_names_the_operator_roster_or_flag(self):
        # Mirrors embedded.rs's #559 drift test for the whole skill tree.
        for path in SKILL_DIR.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.suffix in (".pyc", ".pyo"):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for needle in FORBIDDEN:
                self.assertNotIn(needle, text, f"{path} mentions {needle!r}")

    def test_skill_documents_the_show_unverified_key(self):
        text = SKILL_MD.read_text(encoding="utf-8")
        self.assertIn("`show --json`", text)
        self.assertIn("`unverified`", text)
        # The stale name was the bug: `show` never emitted it, and treating
        # it as a `show` key dropped loose ends from the candidate set.
        self.assertNotIn("`open_unverified` id from `show", text)
        self.assertIn("`open_unverified`", text)


class StateHelperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.vault = make_vault(self.root)
        self.state = state_path(self.vault)
        self.fake_cli = self.root / "fake-confidant"
        self.fake_cli.write_text(FAKE_CLI, encoding="utf-8")
        self.fake_cli.chmod(0o755)
        self.cleared = [PERSON, OTHER, THIRD, FOURTH]

    def tearDown(self):
        self.tmp.cleanup()

    def helper(
        self, *args, stdin=None, cleared=None, vault=None, cli_ok=True,
        read_stdin=False,
    ):
        cmd = [
            sys.executable,
            str(SCRIPT),
            "--vault",
            str(vault or self.vault),
            "--cli",
            str(self.fake_cli),
        ]
        cmd.extend(args)
        env = dict(os.environ)
        env["FAKE_CLEARED"] = ",".join(
            self.cleared if cleared is None else cleared
        )
        env["FAKE_CLI_OK"] = "1" if cli_ok else "0"
        env["FAKE_CLI_READ_STDIN"] = "1" if read_stdin else "0"
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            input=stdin,
            env=env,
        )

    def show(self, cleared=None):
        out = self.helper("show", "--json", cleared=cleared)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def seed_state(self, records=None, unverified=None):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "1",
            "updated": "2026-11-07",
            "records": records or {},
            "unverified": unverified or {},
            "runs": [],
        }
        self.state.write_text(json.dumps(payload), encoding="utf-8")

    def test_show_with_no_state_is_empty(self):
        data = self.show()
        self.assertEqual(data["schema_version"], "1")
        self.assertEqual(data["records"], {})
        self.assertEqual(data["unverified"], {})
        self.assertEqual(data["runs"], [])
        self.assertEqual(data["hidden_uncleared"], 0)
        self.assertFalse(self.state.exists())

    def test_mark_verified_round_trip_and_permissions(self):
        out = self.helper("mark-verified", PERSON, "--date", "2026-11-07")
        self.assertEqual(out.returncode, 0, out.stderr)
        data = self.show()
        self.assertEqual(
            data["records"][PERSON], {"last_verified": "2026-11-07"}
        )
        if os.name == "posix":
            self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.state.parent.stat().st_mode & 0o777, 0o700)

    def test_rejects_non_opaque_ids(self):
        for bad in (
            "Robin Example",
            "robin@example.test",
            "p-01m3tc5h00mpjg000000000101",
            "p-01M3TC5H00MPJG000000000101 ",
            "note-01M3TC5H00MPJG0000000001",
            "",
        ):
            out = self.helper("mark-verified", bad, "--date", "2026-11-07")
            self.assertNotEqual(out.returncode, 0, f"{bad!r} was accepted")
        self.assertFalse(self.state.exists(), "a rejected id still wrote state")

    def test_unverified_then_verified_clears(self):
        out = self.helper(
            "mark-unverified",
            PERSON,
            "--reason",
            "no-answer",
            "--date",
            "2026-11-01",
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        data = self.show()
        self.assertEqual(
            data["unverified"][PERSON],
            {"since": "2026-11-01", "reason": "no-answer"},
        )
        out = self.helper("mark-verified", PERSON, "--date", "2026-11-07")
        self.assertEqual(out.returncode, 0, out.stderr)
        data = self.show()
        self.assertNotIn(PERSON, data["unverified"])
        self.assertEqual(
            data["records"][PERSON], {"last_verified": "2026-11-07"}
        )

    def test_unverified_keeps_first_since_date(self):
        self.helper(
            "mark-unverified",
            PERSON,
            "--reason",
            "no-answer",
            "--date",
            "2026-11-01",
        )
        self.helper(
            "mark-unverified",
            PERSON,
            "--reason",
            "operator-declined",
            "--date",
            "2026-11-07",
        )
        data = self.show()
        self.assertEqual(
            data["unverified"][PERSON],
            {"since": "2026-11-01", "reason": "operator-declined"},
        )

    def test_plan_orders_changed_never_checked_stalest(self):
        self.helper("mark-verified", PERSON, "--date", "2026-01-01")
        self.helper("mark-verified", OTHER, "--date", "2026-10-01")
        self.helper(
            "mark-unverified",
            FOURTH,
            "--reason",
            "conflict",
            "--date",
            "2026-11-01",
        )
        payload = {
            "records": [
                {"id": OTHER, "dates": ["2026-03"]},
                {"id": PERSON, "dates": ["2026-09-10"]},
                {"id": THIRD, "dates": ["2026-10"]},
            ]
        }
        out = self.helper("plan", stdin=json.dumps(payload))
        self.assertEqual(out.returncode, 0, out.stderr)
        data = json.loads(out.stdout)
        groups = {g["priority"]: g["records"] for g in data["groups"]}
        self.assertEqual(
            [g["priority"] for g in data["groups"]],
            ["changed", "never-checked", "stalest"],
        )
        self.assertEqual([r["id"] for r in groups["changed"]], [PERSON])
        self.assertEqual([r["id"] for r in groups["never-checked"]], [THIRD])
        self.assertEqual([r["id"] for r in groups["stalest"]], [OTHER])
        self.assertEqual(
            data["open_unverified"],
            [{"id": FOURTH, "since": "2026-11-01", "reason": "conflict"}],
        )
        self.assertEqual(data["skipped_uncleared"], 0)

    def test_plan_reads_candidates_even_when_cli_reads_stdin(self):
        # Finding 3: `plan` calls the cleared-set CLI before reading the
        # candidate JSON from its own stdin. The child must not inherit that
        # pipe; a wrapper that reads stdin would otherwise eat the candidates
        # and the plan would silently come back empty.
        payload = {"records": [{"id": PERSON, "dates": ["2026-10-01"]}]}
        out = self.helper(
            "plan", stdin=json.dumps(payload), read_stdin=True
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        data = json.loads(out.stdout)
        listed = [
            record["id"]
            for group in data["groups"]
            for record in group["records"]
        ]
        self.assertEqual(listed, [PERSON])
        self.assertEqual(data["skipped_uncleared"], 0)

    def test_plan_keeps_open_unverified_even_when_listed(self):
        # Finding 1: an unverified id that is also a candidate must not
        # vanish from `open_unverified`, or the cap could skip it.
        self.helper("mark-unverified", PERSON, "--reason", "no-answer")
        payload = {"records": [{"id": PERSON, "dates": []}]}
        out = self.helper("plan", stdin=json.dumps(payload))
        self.assertEqual(out.returncode, 0, out.stderr)
        data = json.loads(out.stdout)
        self.assertEqual(len(data["open_unverified"]), 1)
        self.assertEqual(data["open_unverified"][0]["id"], PERSON)
        self.assertEqual(data["open_unverified"][0]["reason"], "no-answer")

    def test_plan_month_only_dates_compare_conservatively(self):
        self.helper("mark-verified", PERSON, "--date", "2026-03-31")
        self.helper("mark-verified", OTHER, "--date", "2026-02-28")
        payload = {
            "records": [
                {"id": PERSON, "dates": ["2026-03"]},
                {"id": OTHER, "dates": ["2026-03"]},
            ]
        }
        out = self.helper("plan", stdin=json.dumps(payload))
        self.assertEqual(out.returncode, 0, out.stderr)
        data = json.loads(out.stdout)
        groups = {g["priority"]: g["records"] for g in data["groups"]}
        self.assertEqual([r["id"] for r in groups["changed"]], [OTHER])
        self.assertEqual([r["id"] for r in groups["stalest"]], [PERSON])

    def test_plan_rejects_bad_input(self):
        for payload in (
            '"not an object"',
            '{"records": [{"id": "Robin Example"}]}',
            '{"records": [{"id": "%s", "dates": ["2026-13-01"]}]}' % PERSON,
            '{"records": [{"id": "%s"}, {"id": "%s"}]}' % (PERSON, PERSON),
        ):
            out = self.helper("plan", stdin=payload)
            self.assertNotEqual(out.returncode, 0, payload)

    def test_no_ai_id_cannot_enter_the_state_file(self):
        # Finding 2: a no-ai id is absent from the cleared set, and that —
        # not an E_NOT_FOUND from `context` — is the fail-closed signal.
        out = self.helper("mark-verified", HIDDEN, "--date", "2026-11-07")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("cleared set", out.stderr)
        self.assertFalse(self.state.exists(), "an uncleared id wrote state")

    def test_plan_drops_uncleared_candidates_and_never_names_them(self):
        payload = {
            "records": [
                {"id": HIDDEN, "dates": ["2026-10-01"]},
                {"id": PERSON, "dates": ["2026-10-01"]},
            ]
        }
        out = self.helper("plan", stdin=json.dumps(payload))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn(HIDDEN, out.stdout)
        data = json.loads(out.stdout)
        self.assertEqual(data["skipped_uncleared"], 1)
        listed = [
            record["id"]
            for group in data["groups"]
            for record in group["records"]
        ]
        self.assertEqual(listed, [PERSON])

    def test_show_hides_uncleared_state_entries(self):
        # A record can become no-ai after being verified; `show` must not
        # put its id back into agent-facing output, and `prune` must remove
        # it from the local state.
        self.seed_state(records={HIDDEN: {"last_verified": "2026-10-01"}})
        data = self.show()
        self.assertNotIn(HIDDEN, json.dumps(data))
        self.assertEqual(data["hidden_uncleared"], 1)
        self.assertEqual(data["records"], {})

        out = self.helper("prune")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn(HIDDEN, out.stdout)
        self.assertEqual(self.show()["hidden_uncleared"], 0)

    def test_show_and_mark_fail_closed_without_the_cleared_set(self):
        self.seed_state(records={PERSON: {"last_verified": "2026-10-01"}})
        out = self.helper("show", "--json", cli_ok=False)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("cleared set", out.stderr)
        out = self.helper("mark-verified", PERSON, "--date", "2026-11-07",
                       cli_ok=False)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("cleared set", out.stderr)

    def test_rejects_invalid_or_unknown_state(self):
        self.state.parent.mkdir(parents=True)
        for text in ("not json", '{"schema_version": "9"}'):
            self.state.write_text(text, encoding="utf-8")
            out = self.helper("mark-verified", PERSON, "--date", "2026-11-07")
            self.assertNotEqual(out.returncode, 0, text)
            self.assertIn("move it aside", out.stderr)

    def test_refuses_when_confidant_dir_is_not_gitignored(self):
        if not shutil.which("git"):
            self.skipTest("git not installed")
        vault = make_vault(self.root / "nogit", gitignored=False)
        out = self.helper("mark-verified", PERSON, "--date", "2026-11-07",
                       vault=vault)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("git-ignored", out.stderr)
        self.assertFalse(state_path(vault).exists())

    def test_record_run_keeps_last_thirty(self):
        start = datetime.date(2026, 1, 1)
        for offset in range(35):
            day = (start + datetime.timedelta(days=offset)).isoformat()
            out = self.helper(
                "record-run",
                "--checked",
                "1",
                "--proposed",
                "0",
                "--applied",
                "0",
                "--skipped",
                "1",
                "--date",
                day,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
        runs = self.show()["runs"]
        self.assertEqual(len(runs), 30)
        self.assertEqual(
            runs[0]["date"], (start + datetime.timedelta(days=5)).isoformat()
        )
        self.assertEqual(runs[-1]["date"], "2026-02-04")

    def test_record_run_rejects_impossible_counts(self):
        for args in (
            ["--checked", "-1"],
            ["--checked", "2", "--proposed", "1", "--applied", "2"],
            ["--checked", "1", "--skipped", "2"],
        ):
            out = self.helper("record-run", *args, "--date", "2026-11-07")
            self.assertNotEqual(out.returncode, 0, args)

    def test_forget_and_clear_are_no_ops_when_absent(self):
        for args in (("forget", PERSON), ("clear-unverified", PERSON)):
            out = self.helper(*args)
            self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
