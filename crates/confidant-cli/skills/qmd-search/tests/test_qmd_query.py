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
import time
import unittest
import unittest.mock
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


def load_module(name, path):
    """Import a hyphenated skill script as a module."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class QmdQueryConfigTest(unittest.TestCase):
    """#722: qmd-query.py honors the persisted preflight choices.

    No CLI needed: these are pure module-level tests, so they run even
    when the suite skips the QmdQueryTest class for want of a binary.
    """

    def setUp(self):
        self.query = load_module("qmd_query", QUERY)
        self._saved_home = os.environ.get("HOME")
        self.tmp = tempfile.TemporaryDirectory(prefix="qmd-query-722-")
        os.environ["HOME"] = self.tmp.name

    def tearDown(self):
        if self._saved_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._saved_home
        self.tmp.cleanup()

    def write_user_config(self, text):
        cfg = Path(self.tmp.name) / ".config" / "confidant"
        cfg.mkdir(parents=True, exist_ok=True)
        (cfg / "config.toml").write_text(text, encoding="utf-8")

    def test_explicit_mode_wins_over_config(self):
        self.assertEqual(self.query.resolve_mode("vector", {"default_mode": "bm25"}),
                         "vector")

    def test_config_default_mode_used_when_no_flag(self):
        self.assertEqual(self.query.resolve_mode(None, {"default_mode": "vector"}),
                         "vector")

    def test_invalid_config_mode_falls_back_to_bm25(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            mode = self.query.resolve_mode(None, {"default_mode": "sideways"})
        self.assertEqual(mode, "bm25")
        self.assertIn("sideways", err.getvalue())

    def test_no_config_means_bm25(self):
        self.assertEqual(self.query.resolve_mode(None, {}), "bm25")

    def test_read_qmd_config_round_trips(self):
        self.write_user_config("[qmd]\noffline = true\ndefault_mode = \"vector\"\n")
        config = self.query.read_qmd_config()
        self.assertTrue(self.query._truthy(config.get("offline", "")))
        self.assertEqual(config.get("default_mode"), "vector")

    def test_read_qmd_config_fail_closed(self):
        self.write_user_config("[qmd]\noffline = true\n[broken\n")
        self.assertEqual(self.query.read_qmd_config(), {})

    def test_runtime_env_sets_offline_from_config(self):
        env = self.query.qmd_runtime_env("/vault", {"offline": True})
        self.assertEqual(env.get("HF_HUB_OFFLINE"), "1")
        self.assertIn("INDEX_PATH", env)

    def test_runtime_env_explicit_shell_wins(self):
        with unittest.mock.patch.dict(os.environ, {"HF_HUB_OFFLINE": "0"}):
            env = self.query.qmd_runtime_env("/vault", {"offline": True})
        self.assertEqual(env.get("HF_HUB_OFFLINE"), "0")

    def test_timeout_hint_names_the_hub_and_the_fix(self):
        self.assertIn("Hugging Face", self.query.TIMEOUT_HINT)
        self.assertIn("HF_HUB_OFFLINE=1", self.query.TIMEOUT_HINT)
        self.assertIn("one possible cause", self.query.TIMEOUT_HINT)

    def test_timeout_hint_conditioned_on_offline(self):
        # Offline already forced: the hub cannot be the cause, and the
        # hint must say so instead of suggesting the no-op fix.
        hint = self.query.timeout_hint({"HF_HUB_OFFLINE": "1"})
        self.assertIn("not the cause", hint)
        self.assertNotIn("Hugging Face", hint)
        self.assertEqual(self.query.timeout_hint({}),
                         self.query.TIMEOUT_HINT)

    def test_timeout_fallback_json_carries_conditioned_hint(self):
        # In-process main() with qmd patched to time out: the fallback
        # JSON must carry fallback_hint, conditioned on the env.
        vault = Path(self.tmp.name) / "vault"
        vault.mkdir()
        (vault / "confidant.toml").write_text("", encoding="utf-8")
        (vault / ".confidant" / "qmd-corpus").mkdir(parents=True)
        find_envelope = {"ok": True, "matches": [
            {"path": "people/p-01M3TC5H00MPJG000000000101/profile.md"}]}

        def fake_run(cmd, **kwargs):
            if "find" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout=json.dumps(find_envelope), stderr="")
            raise subprocess.TimeoutExpired(cmd, 180)

        for env_offline, want in ((None, self.query.TIMEOUT_HINT),
                                  ("1", self.query.TIMEOUT_HINT_OFFLINE)):
            argv = ["qmd-query.py", "--vault", str(vault),
                    "--mode", "bm25", "hello"]
            # "" is falsy: deterministic "not offline" regardless of
            # the ambient environment.
            env_patch = {"HF_HUB_OFFLINE": env_offline or ""}
            out = io.StringIO()
            with unittest.mock.patch.object(sys, "argv", argv), \
                    unittest.mock.patch.object(
                        shutil, "which", return_value="/fake/bin"), \
                    unittest.mock.patch.object(
                        subprocess, "run", side_effect=fake_run), \
                    unittest.mock.patch.dict(os.environ, env_patch), \
                    contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = self.query.main()
            self.assertEqual(code, 0)
            data = json.loads(out.getvalue())
            self.assertEqual(data["mode"], "find-fallback")
            self.assertEqual(data["fallback_hint"], want)


class QmdPreflightTest(unittest.TestCase):
    """#722: qmd-preflight.py reports spec, hub, smoke, recommendation."""

    def setUp(self):
        self.preflight = load_module(
            "qmd_preflight", SKILL_DIR / "bin" / "qmd-preflight.py")
        self._saved_home = os.environ.get("HOME")
        self.tmp = tempfile.TemporaryDirectory(prefix="qmd-preflight-722-")
        self.root = Path(self.tmp.name)
        os.environ["HOME"] = str(self.root)

    def tearDown(self):
        if self._saved_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._saved_home
        self.tmp.cleanup()

    def test_host_spec_shape(self):
        vault = self.root / "vault"
        vault.mkdir()
        spec = self.preflight.host_spec(str(vault))
        self.assertIsInstance(spec["cpus"], int)
        self.assertGreater(spec["cpus"], 0)
        self.assertIsInstance(spec["disk_free_gb"], float)
        self.assertEqual(spec["model_footprint_gb"], 2.5)

    def test_hub_probe_reachable_local_server(self):
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/"
            result = self.preflight.probe_model_hub(url, timeout=5)
        finally:
            server.shutdown()
            server.server_close()
        self.assertTrue(result["reachable"])
        self.assertIn("200", result["detail"])

    def test_hub_probe_unreachable_is_fast_not_hanging(self):
        import socket
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        start = time.time()
        result = self.preflight.probe_model_hub(
            f"http://127.0.0.1:{port}/", timeout=5)
        self.assertFalse(result["reachable"])
        self.assertLess(time.time() - start, 5)

    def test_config_edit_preserves_other_keys_and_comments(self):
        cfg = self.root / ".config" / "confidant"
        cfg.mkdir(parents=True, exist_ok=True)
        (cfg / "config.toml").write_text(
            "# Operator election (see issue #723).\n"
            "[qmd]\nassume_encrypted_disk = true\n",
            encoding="utf-8")
        self.preflight.set_qmd_config_value(str(self.root), "default_mode",
                                            '"vector"')
        self.preflight.set_qmd_config_value(str(self.root), "offline", "true")
        text = (cfg / "config.toml").read_text(encoding="utf-8")
        self.assertIn("assume_encrypted_disk = true", text)
        self.assertIn("# Operator election", text)
        self.assertIn('default_mode = "vector"', text)
        self.assertIn("offline = true", text)
        # Idempotent: a second write replaces, never duplicates.
        self.preflight.set_qmd_config_value(str(self.root), "offline", "true")
        text = (cfg / "config.toml").read_text(encoding="utf-8")
        self.assertEqual(text.count("offline = true"), 1)

    def test_config_edit_creates_qmd_section(self):
        self.preflight.set_qmd_config_value(str(self.root), "offline", "true")
        config = self.preflight.read_qmd_config(str(self.root))
        self.assertTrue(self.preflight._truthy(config.get("offline", "")))

    def test_recommendation_prefers_hybrid_within_budget(self):
        results = {
            "hybrid": {"status": "ok", "seconds": 6.3},
            "vector": {"status": "ok", "seconds": 2.0},
            "bm25": {"status": "ok", "seconds": 0.5},
        }
        self.assertEqual(self.preflight.recommend_default_mode(results, 60),
                         "hybrid")

    def test_recommendation_skips_over_budget_modes(self):
        results = {
            "hybrid": {"status": "ok", "seconds": 90.0},
            "vector": {"status": "ok", "seconds": 5.0},
            "bm25": {"status": "ok", "seconds": 0.5},
        }
        self.assertEqual(self.preflight.recommend_default_mode(results, 60),
                         "vector")

    def test_recommendation_none_when_nothing_ran(self):
        results = {m: {"status": "skipped", "seconds": None}
                   for m in ("hybrid", "vector", "bm25")}
        self.assertIsNone(self.preflight.recommend_default_mode(results, 60))

    def test_smoke_with_stub_query_script(self):
        # A zero-hit answer is ok-empty, not ok: it proves timing, not
        # a usable mode, and is never recommended.
        stub = self.root / "stub-query.py"
        stub.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "mode = sys.argv[sys.argv.index('--mode') + 1]\n"
            "print(json.dumps({'mode': mode, 'matches': []}))\n",
            encoding="utf-8")
        results = self.preflight.run_smoke(
            str(stub), "/vault", "preflight", timeout=30, env=dict(os.environ),
            qmd_present=True, corpus_present=True)
        for mode in ("hybrid", "vector", "bm25"):
            self.assertEqual(results[mode]["status"], "ok-empty", results[mode])
            self.assertEqual(results[mode]["matches"], 0)
        self.assertIsNone(
            self.preflight.recommend_default_mode(results, 60))
        self.assertFalse(self.preflight.cache_complete(results))

    def test_smoke_hit_bearing_ok_reports_cold_and_warm(self):
        # A hit-bearing stub is run twice (cold, then warm); the warm
        # run is canonical and both timings are reported.
        stub = self.root / "stub-hits.py"
        stub.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "mode = sys.argv[sys.argv.index('--mode') + 1]\n"
            "print(json.dumps({'mode': mode, "
            "'matches': [{'path': 'x.md', 'score': 1.0}]}))\n",
            encoding="utf-8")
        calls = []
        results = self.preflight.run_smoke(
            str(stub), "/vault", "preflight", timeout=30, env=dict(os.environ),
            qmd_present=True, corpus_present=True,
            progress=lambda m, ph, r: calls.append((m, ph)))
        for mode in ("hybrid", "vector", "bm25"):
            self.assertEqual(results[mode]["status"], "ok", results[mode])
            self.assertEqual(results[mode]["matches"], 1)
            self.assertEqual(results[mode]["cold"]["status"], "ok")
            self.assertEqual(results[mode]["warm"]["status"], "ok")
            self.assertIsNotNone(results[mode]["seconds"])
        # Two runs per mode (cold + warm), each announced on progress.
        self.assertEqual(len(calls), 12)
        self.assertEqual(
            self.preflight.recommend_default_mode(results, 60), "hybrid")
        self.assertTrue(self.preflight.cache_complete(results))

    def test_smoke_timeout_failure_fallback_classification(self):
        # Timeout: the stub sleeps past the timeout (killed, not hung).
        sleepy = self.root / "stub-sleep.py"
        sleepy.write_text(
            "#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n",
            encoding="utf-8")
        results = self.preflight.run_smoke(
            str(sleepy), "/vault", "preflight", timeout=1,
            env=dict(os.environ), qmd_present=True, corpus_present=True)
        for mode in ("hybrid", "vector", "bm25"):
            self.assertEqual(results[mode]["status"], "timeout", results[mode])
            self.assertEqual(results[mode]["warm"]["status"], "not-measured")
        # A timeout proves nothing about the cache: offline must NOT
        # be recommended on hub-reachable + timeout evidence alone.
        hub = {"reachable": True, "skipped": False}
        self.assertFalse(
            self.preflight.offline_recommended_for(hub, results))
        # Failure: nonzero exit. Fallback: find-fallback envelope.
        failing = self.root / "stub-fail.py"
        failing.write_text(
            "#!/usr/bin/env python3\nimport sys\n"
            "print('boom', file=sys.stderr)\nsys.exit(3)\n",
            encoding="utf-8")
        results = self.preflight.run_smoke(
            str(failing), "/vault", "preflight", timeout=30,
            env=dict(os.environ), qmd_present=True, corpus_present=True)
        for mode in ("hybrid", "vector", "bm25"):
            self.assertEqual(results[mode]["status"], "failed", results[mode])
            self.assertIn("boom", results[mode]["reason"])
        fallback_stub = self.root / "stub-fallback.py"
        fallback_stub.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "print(json.dumps({'mode': 'find-fallback', "
            "'fallback': 'qmd missing', 'matches': []}))\n",
            encoding="utf-8")
        results = self.preflight.run_smoke(
            str(fallback_stub), "/vault", "preflight", timeout=30,
            env=dict(os.environ), qmd_present=True, corpus_present=True)
        for mode in ("hybrid", "vector", "bm25"):
            self.assertEqual(results[mode]["status"], "fallback", results[mode])
        self.assertFalse(
            self.preflight.offline_recommended_for(hub, results))

    def test_smoke_skips_when_qmd_missing(self):
        results = self.preflight.run_smoke(
            "/nonexistent/qmd-query.py", "/vault", "preflight", timeout=30,
            env=dict(os.environ), qmd_present=False, corpus_present=True)
        for mode in ("hybrid", "vector", "bm25"):
            self.assertEqual(results[mode]["status"], "skipped")
            self.assertIn("not installed", results[mode]["reason"])

    def test_hub_probe_stalling_server_times_out(self):
        # A stalling hub (connection accepted, never answered — the slow
        # proxy case) must hit the probe timeout, not hang preflight.
        import socket
        import threading
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def hold():
            try:
                conn, _ = listener.accept()
                time.sleep(30)
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=hold, daemon=True)
        thread.start()
        try:
            start = time.time()
            result = self.preflight.probe_model_hub(
                f"http://127.0.0.1:{port}/", timeout=2)
            elapsed = time.time() - start
        finally:
            listener.close()
        self.assertFalse(result["reachable"])
        self.assertLess(elapsed, 8)
        self.assertIn("timed out", result["detail"])

    def test_hub_probe_proxy_error_not_reachable(self):
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(502)
                self.end_headers()
                self.wfile.write(b"Bad Gateway")

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/"
            result = self.preflight.probe_model_hub(url, timeout=5)
        finally:
            server.shutdown()
            server.server_close()
        self.assertFalse(result["reachable"])
        self.assertIn("502", result["detail"])

    def test_hub_probe_skipped_when_offline_forced(self):
        result = self.preflight.probe_model_hub(
            "http://127.0.0.1:1/", timeout=5, offline_forced=True)
        self.assertFalse(result["reachable"])
        self.assertTrue(result["skipped"])
        self.assertIn("HF_HUB_OFFLINE", result["detail"])

    def test_hub_url_prefers_flag_then_hf_endpoint(self):
        with unittest.mock.patch.dict(
                os.environ, {"HF_ENDPOINT": "https://endpoint.example"}):
            self.assertEqual(
                self.preflight.resolve_hub_url(None),
                "https://endpoint.example")
            self.assertEqual(
                self.preflight.resolve_hub_url("https://flag.example"),
                "https://flag.example")
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HF_ENDPOINT", None)
            self.assertEqual(self.preflight.resolve_hub_url(None),
                             self.preflight.DEFAULT_HUB_URL)

    def test_spec_warnings_compare_thresholds(self):
        low = {"cpus": 1, "ram_gb": 1.0, "disk_free_gb": 1.0,
               "model_cache_free_gb": 10.0}
        warnings = self.preflight.spec_warnings(low)
        self.assertTrue(any("CPU" in w for w in warnings), warnings)
        self.assertTrue(any("RAM" in w for w in warnings), warnings)
        self.assertTrue(any("LOW DISK" in w for w in warnings), warnings)
        field = {"cpus": 2, "ram_gb": 8.0, "disk_free_gb": 10.0,
                 "model_cache_free_gb": 10.0}
        self.assertEqual(self.preflight.spec_warnings(field), [])
        unknown = {"cpus": None, "ram_gb": None, "disk_free_gb": None,
                   "model_cache_free_gb": None}
        warnings = self.preflight.spec_warnings(unknown)
        self.assertEqual(len(warnings), 3)
        self.assertTrue(all("unknown" in w for w in warnings), warnings)

    def test_tradeoff_note_surfaces_runner_up(self):
        # The fastest hit-bearing mode is the runner-up: bm25 here.
        results = {
            "hybrid": {"status": "ok", "seconds": 59.0},
            "vector": {"status": "ok", "seconds": 2.0},
            "bm25": {"status": "ok", "seconds": 0.5},
        }
        note = self.preflight.tradeoff_note(results, "hybrid")
        self.assertIsNotNone(note)
        self.assertIn("bm25", note)
        self.assertIn("0.5", note)
        # With bm25 out, the runner-up is vector (#722's own example:
        # hybrid ~40s warm, vector recommended).
        results["bm25"] = {"status": "skipped", "seconds": None}
        results["hybrid"] = {"status": "ok", "seconds": 40.0}
        note = self.preflight.tradeoff_note(results, "hybrid")
        self.assertIsNotNone(note)
        self.assertIn("vector", note)
        self.assertIn("2.0", note)
        close = {
            "hybrid": {"status": "ok", "seconds": 0.9},
            "vector": {"status": "ok", "seconds": 2.0},
            "bm25": {"status": "ok", "seconds": 0.5},
        }
        self.assertIsNone(self.preflight.tradeoff_note(close, "hybrid"))

    # --persist end-to-end through main() (offline/hub/config together).

    def _fake_vault(self):
        vault = self.root / "vault"
        vault.mkdir(exist_ok=True)
        (vault / "confidant.toml").write_text("", encoding="utf-8")
        (vault / ".confidant" / "qmd-corpus").mkdir(parents=True)
        return vault

    def _fake_qmd_on_path(self):
        bindir = self.root / "bin"
        bindir.mkdir(exist_ok=True)
        write_exec(bindir / "qmd", "#!/bin/sh\nexit 0\n")
        return bindir

    def _stub(self, name, matches):
        stub = self.root / name
        stub.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "mode = sys.argv[sys.argv.index('--mode') + 1]\n"
            f"print(json.dumps({{'mode': mode, 'matches': {matches!r}}}))\n",
            encoding="utf-8")
        return stub

    def _closed_port_url(self):
        import socket
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return f"http://127.0.0.1:{port}/"

    def _run_main(self, vault, stub, hub_url, extra=()):
        bindir = self._fake_qmd_on_path()
        # main(argv) passes argv straight to parse_args: no prog name.
        argv = ["--vault", str(vault),
                "--query-script", str(stub), "--hub-url", hub_url,
                "--json", *extra]
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch.dict(
                os.environ, {"PATH": f"{bindir}{os.pathsep}"
                             f"{os.environ.get('PATH', '')}"}), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = self.preflight.main(argv)
        self.assertEqual(code, 0, err.getvalue())
        return json.loads(out.getvalue())

    def test_persist_sets_recommendation_and_offline(self):
        vault = self._fake_vault()
        stub = self._stub("stub-hits2.py", [{"path": "x.md", "score": 1.0}])
        report = self._run_main(vault, stub, self._closed_port_url(),
                                extra=("--persist",))
        self.assertEqual(report["recommended_mode"], "hybrid")
        self.assertTrue(report["offline_recommended"])
        self.assertTrue(report["embeddings_present"])
        self.assertEqual(report["persisted"]["default_mode"], "hybrid")
        self.assertTrue(report["persisted"]["offline"])
        cfg = (self.root / ".config" / "confidant" / "config.toml")
        text = cfg.read_text(encoding="utf-8")
        self.assertIn('default_mode = "hybrid"', text)
        self.assertIn("offline = true", text)

    def test_persist_clears_stale_preflight_keys(self):
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            hub_url = f"http://127.0.0.1:{server.server_address[1]}/"
            vault = self._fake_vault()
            cfg = self.root / ".config" / "confidant"
            cfg.mkdir(parents=True, exist_ok=True)
            (cfg / "config.toml").write_text(
                "[qmd]\ndefault_mode = \"vector\"\n"
                "default_mode_source = \"preflight\"\n"
                "offline = true\noffline_source = \"preflight\"\n",
                encoding="utf-8")
            stub = self._stub("stub-empty2.py", [])
            report = self._run_main(vault, stub, hub_url,
                                    extra=("--persist",))
            self.assertIsNone(report["recommended_mode"])
            self.assertFalse(report["offline_recommended"])
            self.assertEqual(report["persisted"]["default_mode_cleared"],
                             "vector")
            self.assertTrue(report["persisted"]["offline_cleared"])
            text = (cfg / "config.toml").read_text(encoding="utf-8")
            self.assertNotIn("default_mode", text)
            self.assertNotIn("offline", text)
        finally:
            server.shutdown()
            server.server_close()

    def test_persist_leaves_hand_set_values_alone(self):
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            hub_url = f"http://127.0.0.1:{server.server_address[1]}/"
            vault = self._fake_vault()
            cfg = self.root / ".config" / "confidant"
            cfg.mkdir(parents=True, exist_ok=True)
            (cfg / "config.toml").write_text(
                "[qmd]\ndefault_mode = \"bm25\"\noffline = true\n",
                encoding="utf-8")
            stub = self._stub("stub-empty3.py", [])
            report = self._run_main(vault, stub, hub_url,
                                    extra=("--persist",))
            self.assertEqual(report["persisted"]["default_mode_left"],
                             "bm25")
            self.assertTrue(report["persisted"]["offline_left"])
            text = (cfg / "config.toml").read_text(encoding="utf-8")
            self.assertIn('default_mode = "bm25"', text)
            self.assertIn("offline = true", text)
        finally:
            server.shutdown()
            server.server_close()

    def test_persist_without_home_fails_before_smoke(self):
        vault = self._fake_vault()
        counter = self.root / "smoke-calls.txt"
        stub = self.root / "stub-count.py"
        stub.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            f"open({str(counter)!r}, 'a').write('x')\n"
            "mode = sys.argv[sys.argv.index('--mode') + 1]\n"
            "print(json.dumps({'mode': mode, 'matches': []}))\n",
            encoding="utf-8")
        bindir = self._fake_qmd_on_path()
        argv = ["--vault", str(vault),
                "--query-script", str(stub),
                "--hub-url", self._closed_port_url(), "--persist"]
        with unittest.mock.patch.dict(os.environ, {
                "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"}):
            os.environ.pop("HOME", None)
            with self.assertRaises(SystemExit):
                self.preflight.main(argv)
        self.assertFalse(counter.exists(),
                         "smoke ran despite --persist having no HOME")


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
