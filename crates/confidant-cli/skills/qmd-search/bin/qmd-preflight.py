#!/usr/bin/env python3
"""Preflight a host for QMD search (issue #722).

Usage: qmd-preflight.py [--vault PATH] [--persist] [--json]

Reports, in order:

1. Spec check: cores, RAM, free disk at the vault, against the layer's
   real needs (model footprint ~2.5 GB disk once everything lands;
   field data, 0.7.0: a 2-vCPU / 8 GB slice ran BM25 and vector fine).
   CPU-only inference is assumed when no GPU is detected.
2. Model-hub reachability: the 0.7.0 field failure was NOT compute — a
   cold hybrid/vector query spent 3m01s with 0.76s user CPU waiting on
   a Hugging Face hub check through an egress proxy, then silently fell
   back. The probe below makes one short-timeout request to the hub and
   says whether the host can reach it. When the probe fails (or the
   models are already cached, so no hub call is ever needed), offline
   mode is recommended: `qmd-query.py` then runs qmd with
   `HF_HUB_OFFLINE=1`, and `--persist` records that choice.
3. Timed smoke query per mode (bm25 / vector / hybrid) on the freshly
   built corpus, reporting actual seconds and flagging modes over the
   budget (default 60s). Modes are skipped, not failed, when qmd or the
   corpus is missing or embeddings are not built yet.
4. A recommended default mode for this host, recorded where the query
   wrapper honors it: `--persist` writes `[qmd] default_mode` (and
   `[qmd] offline`, when recommended) to `~/.config/confidant/config.toml`,
   preserving every other key in the file. `qmd-query.py` reads both.

This script never builds anything and never phones home beyond the one
hub probe: smoke queries run through `qmd-query.py` (same allowlist
filtering, same `find` fallback reporting) with the offline decision
from step 2 applied, so a hanging hub cannot turn the smoke test itself
into a 3-minute silent fallback.

Exit code is 0 whenever the report completes, even when the verdict is
"no mode recommended" — the report is the deliverable, not a gate.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

COLLECTION = "confidant"
CORPUS_REL = os.path.join(".confidant", "qmd-corpus")
STORE_REL = os.path.join(".confidant", "qmd")
USER_CONFIG_REL = os.path.join(".config", "confidant", "config.toml")
TRUTHY = ("1", "true", "yes", "on")

# Planning figure from #722: ~1.6 GB landed in 0.7.0 (embed 319 MB + 1.7B
# query-expansion 1.2 GB) with the 0.6B reranker still to download.
MODEL_FOOTPRINT_GB = 2.5
MODES = ("hybrid", "vector", "bm25")
DEFAULT_BUDGET_S = 60
DEFAULT_QUERY_TIMEOUT_S = 180  # mirrors qmd-query.py's qmd timeout
DEFAULT_HUB_URL = "https://huggingface.co"
DEFAULT_HUB_TIMEOUT_S = 10


def resolve_vault(explicit):
    vault = explicit or os.environ.get("CONFIDANT_VAULT")
    if not vault:
        sys.exit("error: no vault: pass --vault or set CONFIDANT_VAULT")
    vault = os.path.abspath(os.path.expanduser(vault))
    if not os.path.isfile(os.path.join(vault, "confidant.toml")):
        sys.exit(f"error: {vault} does not look like a vault (no confidant.toml)")
    return vault


def total_ram_bytes():
    """Total RAM, or None when it cannot be determined on this host."""
    if sys.platform == "linux":
        try:
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1]) * 1024
        except (OSError, ValueError):
            return None
    elif sys.platform == "darwin":
        try:
            p = subprocess.run(["sysctl", "-n", "hw.memsize"],
                               capture_output=True, text=True, timeout=10)
            if p.returncode == 0:
                return int(p.stdout.strip())
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return None
    return None


def detect_gpu():
    """First GPU name from nvidia-smi, or None when none is detected."""
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi is None:
        return None
    try:
        p = subprocess.run([nvidia_smi, "--query-gpu=name",
                            "--format=csv,noheader"],
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    name = (p.stdout or "").strip().splitlines()
    return name[0].strip() if p.returncode == 0 and name else None


def host_spec(vault):
    """Cores, RAM, free disk at the vault, and GPU detection."""
    disk_path = os.path.join(vault, STORE_REL)
    try:
        usage = shutil.disk_usage(disk_path if os.path.isdir(disk_path) else vault)
        free_gb = usage.free / (1024 ** 3)
    except OSError:
        free_gb = None
    ram = total_ram_bytes()
    return {
        "cpus": os.cpu_count(),
        "ram_gb": round(ram / (1024 ** 3), 1) if ram is not None else None,
        "disk_free_gb": round(free_gb, 1) if free_gb is not None else None,
        "disk_path": disk_path,
        "gpu": detect_gpu(),
        "model_footprint_gb": MODEL_FOOTPRINT_GB,
    }


def probe_model_hub(url, timeout):
    """One short-timeout hub request. Never hangs: the probe IS the budget.

    Returns {reachable, seconds, detail}. An HTTP error response still
    proves reachability (the host talked to the hub); a timeout or
    connection error does not.
    """
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read(1)
        return {"reachable": True,
                "seconds": round(time.monotonic() - start, 2),
                "detail": f"HTTP {resp.status}"}
    except urllib.error.HTTPError as e:
        return {"reachable": True,
                "seconds": round(time.monotonic() - start, 2),
                "detail": f"HTTP {e.code}"}
    except (TimeoutError, urllib.error.URLError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, TimeoutError) or "timed out" in str(reason).lower():
            detail = f"timed out after {timeout}s"
        else:
            detail = f"{type(reason).__name__}: {reason}" if reason else str(e)
        return {"reachable": False,
                "seconds": round(time.monotonic() - start, 2),
                "detail": detail}
    except (OSError, ValueError) as e:
        return {"reachable": False,
                "seconds": round(time.monotonic() - start, 2),
                "detail": f"{type(e).__name__}: {e}"}


def _truthy(value):
    return str(value).strip().lower() in TRUTHY


def read_qmd_config(home=None):
    """The [qmd] table from the user config, or {} when absent/unreadable.

    Fail closed: a missing file, invalid TOML, or a non-table [qmd] is
    not a configuration — callers fall back to defaults.
    """
    home = home or os.environ.get("HOME")
    if not home:
        return {}
    try:
        import tomllib
    except ImportError:
        return {}
    try:
        with open(os.path.join(home, USER_CONFIG_REL), "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    qmd = data.get("qmd")
    return dict(qmd) if isinstance(qmd, dict) else {}


def set_qmd_config_value(home, key, value_repr):
    """Set one key in the [qmd] table, preserving everything else.

    Text edit, not a TOML round-trip: comments and unrelated keys (e.g.
    the #723 disk-election key) survive byte-for-byte. Creates the
    [qmd] section when absent. Returns the config path written.
    """
    home = home or os.environ.get("HOME")
    if not home:
        raise OSError("no HOME: cannot locate the user config")
    path = os.path.join(home, USER_CONFIG_REL)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        text = ""
    lines = text.splitlines()
    section_re = re.compile(r"^\s*\[qmd\]\s*(#.*)?$")
    header_re = re.compile(r"^\s*\[[^\]]+\]\s*(#.*)?$")
    key_re = re.compile(rf"^\s*{re.escape(key)}\s*=")
    section_at = next((i for i, ln in enumerate(lines) if section_re.match(ln)),
                      None)
    if section_at is None:
        if lines and lines[-1] != "":
            lines.append("")
        lines.append("[qmd]")
        lines.append(f"{key} = {value_repr}")
    else:
        end = len(lines)
        for i in range(section_at + 1, len(lines)):
            if header_re.match(lines[i]):
                end = i
                break
        key_at = next((i for i in range(section_at + 1, end)
                       if key_re.match(lines[i])), None)
        if key_at is not None:
            lines[key_at] = f"{key} = {value_repr}"
        else:
            lines.insert(section_at + 1, f"{key} = {value_repr}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


def recommend_default_mode(results, budget):
    """First preferred mode that ran within budget, else first that ran.

    Preference order is hybrid > vector > bm25 (quality first); a mode
    that only ran over budget is still better than no mode, but it is
    never preferred over a mode within budget. None when nothing ran.
    """
    for mode in MODES:
        r = results.get(mode, {})
        if r.get("status") == "ok" and r.get("seconds") is not None \
                and r["seconds"] <= budget:
            return mode
    for mode in MODES:
        if results.get(mode, {}).get("status") == "ok":
            return mode
    return None


def run_smoke(query_script, vault, query, timeout, env,
              qmd_present, corpus_present):
    """One timed qmd-query.py run per mode; skips are reported, not failed."""
    results = {}
    for mode in MODES:
        if not qmd_present:
            results[mode] = {"status": "skipped", "reason": "qmd not installed",
                             "seconds": None, "matches": None}
            continue
        if not corpus_present:
            results[mode] = {"status": "skipped",
                             "reason": "corpus missing (run qmd-index.py)",
                             "seconds": None, "matches": None}
            continue
        start = time.monotonic()
        try:
            p = subprocess.run([sys.executable, query_script,
                                "--vault", vault, "--mode", mode, query],
                               capture_output=True, text=True,
                               timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            results[mode] = {"status": "timeout",
                             "reason": f"no answer within {timeout}s",
                             "seconds": round(time.monotonic() - start, 2),
                             "matches": None}
            continue
        except OSError as e:
            results[mode] = {"status": "failed", "reason": str(e),
                             "seconds": round(time.monotonic() - start, 2),
                             "matches": None}
            continue
        elapsed = round(time.monotonic() - start, 2)
        try:
            data = json.loads(p.stdout) if p.stdout.strip() else None
        except json.JSONDecodeError:
            data = None
        if p.returncode != 0 and "needs embeddings" in (p.stderr or ""):
            results[mode] = {"status": "skipped",
                             "reason": "no embeddings (run qmd-index.py --embed)",
                             "seconds": elapsed, "matches": None}
        elif p.returncode == 0 and isinstance(data, dict) \
                and data.get("mode") == mode:
            matches = data.get("matches")
            results[mode] = {"status": "ok", "reason": "",
                             "seconds": elapsed,
                             "matches": len(matches) if isinstance(matches, list)
                             else None}
        elif p.returncode == 0 and isinstance(data, dict) \
                and data.get("mode") == "find-fallback":
            results[mode] = {"status": "fallback",
                             "reason": data.get("fallback", "qmd unavailable"),
                             "seconds": elapsed, "matches": None}
        else:
            detail = (p.stderr or "").strip().splitlines()
            results[mode] = {"status": "failed",
                             "reason": detail[-1] if detail else
                             f"exit {p.returncode}",
                             "seconds": elapsed, "matches": None}
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=None)
    ap.add_argument("--query", default="preflight smoke test",
                    help="query text for the per-mode smoke runs (timing "
                         "only; the hits are not evaluated)")
    ap.add_argument("--query-timeout", type=int,
                    default=DEFAULT_QUERY_TIMEOUT_S,
                    help="per-mode smoke timeout in seconds "
                         f"(default {DEFAULT_QUERY_TIMEOUT_S})")
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET_S,
                    help="seconds a mode must answer within to be "
                         f"recommended (default {DEFAULT_BUDGET_S})")
    ap.add_argument("--hub-url", default=DEFAULT_HUB_URL)
    ap.add_argument("--hub-timeout", type=int, default=DEFAULT_HUB_TIMEOUT_S,
                    help="seconds the hub probe may take "
                         f"(default {DEFAULT_HUB_TIMEOUT_S})")
    ap.add_argument("--persist", action="store_true",
                    help="write the recommendation ([qmd] default_mode, and "
                         "[qmd] offline when recommended) to the user config")
    ap.add_argument("--json", action="store_true",
                    help="print the report as JSON instead of text")
    ap.add_argument("--query-script", default=None,
                    help="qmd-query.py path (default: the sibling script; "
                         "tests point it at a stub)")
    args = ap.parse_args()

    vault = resolve_vault(args.vault)
    home = os.environ.get("HOME")
    spec = host_spec(vault)
    config = read_qmd_config(home)
    hub = probe_model_hub(args.hub_url, args.hub_timeout)

    # Smoke env: the hub probe already answered the reachability question,
    # so a failing probe must not turn the smoke runs into another
    # 3-minute wait — run them offline, exactly as qmd-query.py would
    # with [qmd] offline persisted.
    smoke_env = dict(os.environ)
    offline_configured = _truthy(config.get("offline", ""))
    offline_for_smoke = offline_configured or not hub["reachable"]
    if offline_for_smoke and "HF_HUB_OFFLINE" not in smoke_env:
        smoke_env["HF_HUB_OFFLINE"] = "1"

    qmd_present = shutil.which("qmd") is not None
    corpus_present = os.path.isdir(os.path.join(vault, CORPUS_REL))
    query_script = args.query_script or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "qmd-query.py")
    results = run_smoke(query_script, vault, args.query, args.query_timeout,
                        smoke_env, qmd_present, corpus_present)

    # Embeddings are present when a vector/hybrid run got past the
    # embeddings gate (ran, timed out, or failed for another reason).
    # Cached models never need the hub again, so that alone recommends
    # offline mode — the phone-home per query is pure liability then.
    embeddings_present = any(
        results[m]["status"] in ("ok", "timeout", "failed", "fallback")
        for m in ("vector", "hybrid"))
    offline_recommended = (not hub["reachable"]) or offline_configured \
        or embeddings_present
    recommendation = recommend_default_mode(results, args.budget)

    persisted = {}
    if args.persist:
        if recommendation is not None:
            set_qmd_config_value(home, "default_mode",
                                 json.dumps(recommendation))
            persisted["default_mode"] = recommendation
        if offline_recommended:
            set_qmd_config_value(home, "offline", "true")
            persisted["offline"] = True

    report = {
        "vault": vault,
        "spec": spec,
        "hub": hub,
        "offline_for_smoke": offline_for_smoke,
        "offline_recommended": offline_recommended,
        "embeddings_present": embeddings_present,
        "modes": results,
        "budget_s": args.budget,
        "recommended_mode": recommendation,
        "persisted": persisted,
    }
    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"qmd preflight: {vault}")
    cpus = spec["cpus"] if spec["cpus"] is not None else "?"
    ram = f"{spec['ram_gb']} GB" if spec["ram_gb"] is not None else "unknown"
    disk = (f"{spec['disk_free_gb']} GB free"
            if spec["disk_free_gb"] is not None else "unknown free disk")
    disk_ok = spec["disk_free_gb"] is None or \
        spec["disk_free_gb"] >= MODEL_FOOTPRINT_GB
    print(f"  spec: {cpus} CPUs, {ram} RAM, {disk} "
          f"(model footprint ~{MODEL_FOOTPRINT_GB} GB) "
          f"— {'ok' if disk_ok else 'LOW DISK'}")
    gpu = spec["gpu"] or "none detected — CPU-only inference"
    print(f"  gpu: {gpu}")
    print(f"  model hub ({args.hub_url}): "
          f"{'reachable' if hub['reachable'] else 'UNREACHABLE'} "
          f"in {hub['seconds']}s ({hub['detail']})")
    if offline_for_smoke:
        print("  smoke runs use HF_HUB_OFFLINE=1 "
              "(hub unreachable or offline already configured)")
    for mode in MODES:
        r = results[mode]
        if r["status"] == "ok":
            over = " — OVER BUDGET" if r["seconds"] > args.budget else ""
            print(f"  {mode}: ok in {r['seconds']}s "
                  f"({r['matches']} matches){over}")
        elif r["status"] == "skipped":
            print(f"  {mode}: skipped ({r['reason']})")
        else:
            print(f"  {mode}: {r['status']} in {r['seconds']}s ({r['reason']})")
    if recommendation is not None:
        print(f"  recommended default mode: {recommendation}")
    else:
        print("  recommended default mode: none (no mode ran; "
              "search falls back to `confidant find`)")
    if offline_recommended:
        print("  offline mode recommended: persist with --persist "
              "(or set [qmd] offline = true)")
    if args.persist:
        print(f"  persisted: {persisted or 'nothing to persist'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
