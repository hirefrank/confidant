#!/usr/bin/env python3
"""Preflight a host for QMD search (issue #722).

Usage: qmd-preflight.py [--vault PATH] [--persist] [--json]

Reports, in order:

1. Spec check: cores, RAM, free disk at the vault AND at the model
   cache (they may be different filesystems), against the layer's real
   needs (model footprint ~2.5 GB disk once everything lands; field
   data, 0.7.0: a 2-vCPU / 8 GB slice ran BM25 and vector fine — hosts
   below that floor get an explicit warning, not a silent pass).
   CPU-only inference is assumed when no NVIDIA GPU is detected
   (Apple Silicon / AMD GPUs are not probed; see `detect_gpu`).
2. Model-hub reachability: the 0.7.0 field failure was NOT compute — a
   cold hybrid/vector query spent 3m01s with 0.76s user CPU waiting on
   a Hugging Face hub check through an egress proxy, then silently fell
   back. The probe below makes one short-timeout request to the
   configured hub endpoint (`--hub-url`, else `HF_ENDPOINT`, else
   huggingface.co) and says whether the host can reach it. A 4xx/5xx
   response (e.g. a proxy's 502) does NOT count as reachable: the host
   talked to a proxy, not to a usable hub. The probe is skipped
   entirely when `HF_HUB_OFFLINE` is already forced in the shell.
   When the probe fails, or when a hybrid smoke run proves the
   heaviest models are already cached (see below), offline mode is
   recommended: `qmd-query.py` then runs qmd with `HF_HUB_OFFLINE=1`,
   and `--persist` records that choice.
3. Timed smoke query per mode (bm25 / vector / hybrid) on the freshly
   built corpus, reporting cold AND warm seconds separately: the first
   run per mode may pay a model download, so a mode that ran `ok` is
   run a second time and the recommendation is derived from the warm
   run, never from a single cold sample. If the warm run fails or
   times out, the mode is downgraded to that warm failure — the cold
   sample is never reused as the mode's result, so no recommendation
   or --persist can derive from it. Modes are skipped, not
   failed, when qmd or the corpus is missing or embeddings are not
   built yet. A run that answers with zero hits is reported distinctly
   as `ok-empty`, never as proof of anything: it is not recommended
   and does not count toward cache-completeness. Only a hit-bearing
   `ok` proves a mode's models are cached — a `timeout`, `failed`, or
   `fallback` run proves nothing of the kind (the original #722 failure
   IS a hybrid timeout, and treating it as "cached" would persist
   offline mode and break the very download that would fix it).
   Progress lines go to stderr as each run starts/finishes, so a slow
   preflight is never a silent wait: worst case is 6 x the per-mode
   timeout (cold + warm per mode) plus the hub probe — at the default
   180s per-mode timeout that is ~18 minutes plus the probe, so pass
   --query-timeout to bound it (the 60s recommendation budget is a
   separate, unchanged figure).
4. A recommended default mode for this host, recorded where the query
   wrapper honors it: `--persist` writes `[qmd] default_mode` (and
   `[qmd] offline`, when recommended) to the VAULT-LOCAL preflight
   file, `<vault>/.confidant/qmd-preflight.toml` — local and gitignored
   like the corpus and the QMD store. A recommendation measured on one
   vault must not leak into another vault on the same host, which is
   what the old global-only persist did. `qmd-query.py` reads the
   per-vault value first and falls back to the global user config
   (`~/.config/confidant/config.toml`, `[qmd]` table) for vaults with
   no per-vault file, so single-vault setups keep working unchanged
   and a global value set by hand is still honored. The global file
   is NOT touched by `--persist`: its values remain as fallback, and
   clearing a global value from a per-vault run could clobber a
   fallback another vault still relies on. `--persist` also clears
   a stale preflight-written `offline` when the hub has recovered,
   and says so explicitly. A `default_mode` change needs an explicit,
   user-supplied `--query` (#778 fix round): the default smoke query
   ("preflight smoke test") can return hits through the semantic
   modes even though the literal phrase appears nowhere, so a run
   without an explicit query — and the chained `qmd-index` run,
   which passes `--chained` — never writes `default_mode`, whatever
   the probe returns; it updates `offline` only and reports any
   persisted value as kept. Only a fresh hit-bearing recommendation
   from an explicit-`--query` run replaces a persisted mode, and
   an empty explicit-query probe keeps it: an empty probe is not
   evidence against the old mode.
   Values not marked as preflight-written are left alone and
   reported. (The global file keeps its own older
   scheme — provenance markers plus the one-time
   `preflight_legacy_migrated` stamp — for values an old `--persist`
   wrote there; those values are read-only fallback now and are never
   rewritten by a per-vault run.)

This script never builds anything and never phones home beyond the one
hub probe: smoke queries run through `qmd-query.py` (same allowlist
filtering, same `find` fallback reporting) with the offline decision
from step 2 applied, so a hanging hub cannot turn the smoke test itself
into a 3-minute silent fallback.

Exit code is 0 whenever the report completes, even when the verdict is
"no mode recommended" — the report is the deliverable, not a gate.
Automation MUST NOT chain on the exit code (`preflight && next-step`):
read the report (or `--json`) instead — a LOW DISK / unreachable-hub /
no-mode-recommended outcome still exits 0.
"""
import argparse
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

COLLECTION = "confidant"
CORPUS_REL = os.path.join(".confidant", "qmd-corpus")
STORE_REL = os.path.join(".confidant", "qmd")
USER_CONFIG_REL = os.path.join(".config", "confidant", "config.toml")
TRUTHY = ("1", "true", "yes", "on")
FALSEY = ("0", "false", "no", "off")

# Planning figure from #722: ~1.6 GB landed in 0.7.0 (embed 319 MB + 1.7B
# query-expansion 1.2 GB) with the 0.6B reranker still to download.
MODEL_FOOTPRINT_GB = 2.5
# Field-proven floor from #722 (a 2-vCPU / 8 GB slice ran BM25 and vector
# fine). Hosts below it get warnings; these are not pass/fail gates —
# the report, not a verdict bit, is the deliverable.
MIN_CPUS = 2
MIN_RAM_GB = 8
MODES = ("hybrid", "vector", "bm25")
DEFAULT_BUDGET_S = 60
DEFAULT_QUERY_TIMEOUT_S = 180  # mirrors qmd-query.py's qmd timeout
# Smoke query when --query is not supplied. The literal phrase
# appears in no vault, but vector/hybrid semantic search can still
# return neighbours for it — so a default-query run is a measurement
# only and must never write default_mode (see persist_preflight).
DEFAULT_QUERY = "preflight smoke test"
DEFAULT_HUB_URL = "https://huggingface.co"
DEFAULT_HUB_TIMEOUT_S = 10
# Provenance markers --persist writes next to the keys it owns, so a
# later --persist run can tell its own stale values apart from values
# the operator set by hand (which it must not clobber).
SOURCE_SUFFIX = "_source"
SOURCE_VALUE = "preflight"
# NOTE: the old global persist scheme also had a one-time
# `preflight_legacy_migrated` stamp (see the module docstring). New
# runs never write it — the global file is read-only fallback now —
# so no constant is kept for it.


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
    """First NVIDIA GPU name from nvidia-smi, or None.

    NVIDIA-only by design: Apple Silicon / AMD GPUs are NOT probed, so
    None means "no NVIDIA GPU detected", never "this host has no usable
    GPU". Callers must word it that way.
    """
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


def model_cache_path():
    """Where downloaded models land (HF_HOME, else the XDG cache default).

    The disk verdict must consider this filesystem too: the vault store
    and the model cache can live on different disks, and a verdict
    measured only at the vault can be on the wrong filesystem.
    """
    hf_home = os.environ.get("HF_HOME")
    if hf_home:
        return os.path.abspath(os.path.expanduser(hf_home))
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = xdg if xdg else os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "huggingface")


def _free_gb(path):
    try:
        usage = shutil.disk_usage(path if os.path.isdir(path) else
                                  os.path.dirname(path) or path)
        return round(usage.free / (1024 ** 3), 1)
    except OSError:
        return None


def host_spec(vault):
    """Cores, RAM, free disk at the vault and the model cache, GPU probe."""
    disk_path = os.path.join(vault, STORE_REL)
    cache_path = model_cache_path()
    free_gb = _free_gb(disk_path if os.path.isdir(disk_path) else vault)
    cache_free_gb = _free_gb(cache_path)
    ram = total_ram_bytes()
    return {
        "cpus": os.cpu_count(),
        "ram_gb": round(ram / (1024 ** 3), 1) if ram is not None else None,
        "disk_free_gb": free_gb,
        "disk_path": disk_path,
        "model_cache_path": cache_path,
        "model_cache_free_gb": cache_free_gb,
        "gpu": detect_gpu(),
        "gpu_detector": "nvidia-smi",
        "model_footprint_gb": MODEL_FOOTPRINT_GB,
    }


def spec_warnings(spec):
    """Explicit threshold comparisons (or an explicit 'unknown').

    A 1-CPU / 1 GB host must not get the same verdict shape as the
    field host: every dimension is either compared to a threshold or
    flagged as unmeasurable. Disk uses the tightest known figure across
    the vault store and the model cache (either may be unmeasurable).
    """
    warnings = []
    if spec["cpus"] is None:
        warnings.append("CPU count unknown: cannot compare to the "
                        f"{MIN_CPUS}-vCPU field floor")
    elif spec["cpus"] < MIN_CPUS:
        warnings.append(f"only {spec['cpus']} CPU(s): below the "
                        f"{MIN_CPUS}-vCPU field host that ran BM25/vector fine")
    if spec["ram_gb"] is None:
        warnings.append("RAM unknown: cannot compare to the "
                        f"{MIN_RAM_GB} GB field floor or judge headroom "
                        "for the largest model")
    elif spec["ram_gb"] < MIN_RAM_GB:
        warnings.append(f"only {spec['ram_gb']} GB RAM: below the "
                        f"{MIN_RAM_GB} GB field host")
    figures = [f for f in (spec["disk_free_gb"],
                           spec["model_cache_free_gb"]) if f is not None]
    if not figures:
        warnings.append("free disk unknown at both the vault store and "
                        "the model cache: cannot compare to the "
                        f"~{MODEL_FOOTPRINT_GB} GB model footprint")
    elif min(figures) < MODEL_FOOTPRINT_GB:
        vault_txt = (f"{spec['disk_free_gb']} GB" if
                     spec["disk_free_gb"] is not None else "unknown")
        cache_txt = (f"{spec['model_cache_free_gb']} GB" if
                     spec["model_cache_free_gb"] is not None else "unknown")
        warnings.append(f"LOW DISK: tightest free-disk figure is "
                        f"{min(figures)} GB (vault store {vault_txt}, "
                        f"model cache {cache_txt}) vs the "
                        f"~{MODEL_FOOTPRINT_GB} GB model footprint")
    return warnings


def resolve_hub_url(explicit):
    """--hub-url wins, else HF_ENDPOINT, else the default hub root."""
    if explicit:
        return explicit
    return os.environ.get("HF_ENDPOINT") or DEFAULT_HUB_URL


def probe_model_hub(url, timeout, offline_forced=False):
    """One short-timeout hub request. Never hangs: the probe IS the budget.

    Returns {reachable, skipped, seconds, detail}. Only a 2xx/3xx
    response counts as reachable: a proxy answering 403/502 quickly
    proves the host talked to a proxy, not to a usable hub. The probe
    fetches the endpoint root only — it does not prove a specific
    model/CDN path. When offline is already forced in the shell the
    probe is skipped outright (no phone-home when the operator already
    decided), reported as skipped, not as unreachable.
    """
    if offline_forced:
        return {"reachable": False, "skipped": True, "seconds": 0.0,
                "detail": "skipped: HF_HUB_OFFLINE is set in the shell"}
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read(1)
        return {"reachable": True, "skipped": False,
                "seconds": round(time.monotonic() - start, 2),
                "detail": f"HTTP {resp.status}"}
    except urllib.error.HTTPError as e:
        # A gateway/proxy error is not hub reachability: models cannot
        # be downloaded through it.
        return {"reachable": False, "skipped": False,
                "seconds": round(time.monotonic() - start, 2),
                "detail": f"HTTP {e.code} (hub not usable through this response)"}
    except (TimeoutError, urllib.error.URLError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, TimeoutError) or "timed out" in str(reason).lower():
            detail = f"timed out after {timeout}s"
        else:
            detail = f"{type(reason).__name__}: {reason}" if reason else str(e)
        return {"reachable": False, "skipped": False,
                "seconds": round(time.monotonic() - start, 2),
                "detail": detail}
    except (OSError, ValueError) as e:
        return {"reachable": False, "skipped": False,
                "seconds": round(time.monotonic() - start, 2),
                "detail": f"{type(e).__name__}: {e}"}


def _load_query_module():
    """Load the sibling qmd-query.py as a module, or None if absent.

    qmd-query.py is the single source of truth for the [qmd] config
    helpers: preflight used to carry its own copies, which drifted.
    A lone copy of this script (sibling missing) falls back to local
    implementations below rather than failing outright.
    """
    sibling = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "qmd-query.py")
    if not os.path.isfile(sibling):
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "qmd_query_sibling", sibling)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except (OSError, ImportError):
        return None


_QUERY_MODULE = _load_query_module()


def _truthy(value):
    if _QUERY_MODULE is not None:
        return _QUERY_MODULE._truthy(value)
    return str(value).strip().lower() in TRUTHY


def read_qmd_config(home=None):
    """The [qmd] table from the user config, or {} when absent/unreadable.

    Fail closed: a missing file, invalid TOML, or a non-table [qmd] is
    not a configuration — callers fall back to defaults. Delegates to
    qmd-query.py's implementation when the sibling is present.
    """
    if _QUERY_MODULE is not None:
        return _QUERY_MODULE.read_qmd_config(home)
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


def write_config_atomic(path, text):
    """Replace `path` with `text` atomically.

    The query wrapper reads this file on every run, so a crash, a full disk,
    or an interrupt mid-write must not leave it truncated or half-written
    (#795 review). Write a sibling temp file in the same directory (so
    `os.replace` stays on one filesystem and is atomic), fsync it, then
    rename over the target; on any failure the temp file is removed and the
    original config is untouched. Returns the path written.
    """
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=parent, prefix=".qmd-config-",
                suffix=".tmp", delete=False) as f:
            tmp = f.name
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp is not None:
            try:
                os.remove(tmp)
            except OSError:
                pass
    return path


def set_qmd_config_value(home, key, value_repr):
    """Set one key in the [qmd] table, preserving everything else.

    Text edit, not a TOML round-trip: comments and unrelated keys (e.g.
    the #722 preflight keys an older run wrote) survive byte-for-byte.
    Creates the [qmd] section when absent, and writes atomically through
    write_config_atomic. Returns the config path written.
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
    write_config_atomic(path, "\n".join(lines) + "\n")
    return path


def remove_qmd_config_value(home, key):
    """Remove one key from the [qmd] table; True when something was removed.

    Text edit like set_qmd_config_value: comments and unrelated keys
    survive. Removing the last key leaves an empty [qmd] section rather
    than rewriting the file's structure.
    """
    home = home or os.environ.get("HOME")
    if not home:
        raise OSError("no HOME: cannot locate the user config")
    path = os.path.join(home, USER_CONFIG_REL)
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return False
    lines = text.splitlines()
    section_re = re.compile(r"^\s*\[qmd\]\s*(#.*)?$")
    header_re = re.compile(r"^\s*\[[^\]]+\]\s*(#.*)?$")
    key_re = re.compile(rf"^\s*{re.escape(key)}\s*=")
    section_at = next((i for i, ln in enumerate(lines) if section_re.match(ln)),
                      None)
    if section_at is None:
        return False
    end = len(lines)
    for i in range(section_at + 1, len(lines)):
        if header_re.match(lines[i]):
            end = i
            break
    key_at = next((i for i in range(section_at + 1, end)
                   if key_re.match(lines[i])), None)
    if key_at is None:
        return False
    del lines[key_at]
    write_config_atomic(path, "\n".join(lines) + "\n")
    return True


def vault_preflight_path(vault):
    """The vault-local preflight file for this vault."""
    if _QUERY_MODULE is not None:
        return _QUERY_MODULE.vault_preflight_path(vault)
    return os.path.join(vault, ".confidant", "qmd-preflight.toml")


def read_vault_qmd_config(vault):
    """The [qmd] table from the vault-local preflight file, or {}.

    Delegates to qmd-query.py's implementation when the sibling is
    present (single source of truth, as with read_qmd_config).
    """
    if _QUERY_MODULE is not None:
        return _QUERY_MODULE.read_vault_qmd_config(vault)
    try:
        import tomllib
    except ImportError:
        return {}
    try:
        with open(vault_preflight_path(vault), "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    qmd = data.get("qmd")
    return dict(qmd) if isinstance(qmd, dict) else {}


def resolve_offline(vault_config, global_config):
    """The persisted offline choice: per-vault wins, global is fallback.

    Delegates to qmd-query.py's implementation when the sibling is
    present (single source of truth, as with read_qmd_config).
    Returns (offline_bool, source) with source "vault", "global", or
    "none".
    """
    if _QUERY_MODULE is not None:
        return _QUERY_MODULE.resolve_offline(vault_config, global_config)
    for label, config in (("vault", vault_config), ("global", global_config)):
        value = config.get("offline", "")
        if value in ("", None):
            continue
        token = str(value).strip().lower()
        if token in TRUTHY:
            return True, label
        if token in FALSEY:
            return False, label
        print(f"note: ignoring invalid {label} [qmd] offline {value!r} "
              f"(want true or false)", file=sys.stderr)
    return False, "none"


def set_vault_qmd_config_value(vault, key, value_repr):
    """Set one key in the vault-local [qmd] table, preserving the rest.

    Text edit like set_qmd_config_value: comments and unrelated keys
    survive byte-for-byte. Creates the .confidant dir and the [qmd]
    section when absent. Returns the config path written.
    """
    path = vault_preflight_path(vault)
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
    write_config_atomic(path, "\n".join(lines) + "\n")
    # Verify the write round-trips (#773 S3): a text edit can "succeed"
    # while leaving the file unparseable (a garbage line elsewhere), so
    # the value would silently never take effect. Re-read and confirm the
    # key parses back to exactly what was written; otherwise the caller
    # reports a persist failure, not a false success.
    parsed = read_vault_qmd_config(vault)
    if json.dumps(parsed.get(key)) != value_repr:
        raise OSError(f"persisted {key}={value_repr} in {path} but it did "
                      "not read back; the vault-local qmd-preflight.toml "
                      "is unreadable or invalid — fix it by hand and retry")
    return path


def remove_vault_qmd_config_value(vault, key):
    """Remove one key from the vault-local [qmd] table; True if removed.

    Text edit like remove_qmd_config_value. A missing file or a
    missing key is not an error: it returns False.
    """
    path = vault_preflight_path(vault)
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return False
    lines = text.splitlines()
    section_re = re.compile(r"^\s*\[qmd\]\s*(#.*)?$")
    header_re = re.compile(r"^\s*\[[^\]]+\]\s*(#.*)?$")
    key_re = re.compile(rf"^\s*{re.escape(key)}\s*=")
    section_at = next((i for i, ln in enumerate(lines) if section_re.match(ln)),
                      None)
    if section_at is None:
        return False
    end = len(lines)
    for i in range(section_at + 1, len(lines)):
        if header_re.match(lines[i]):
            end = i
            break
    key_at = next((i for i in range(section_at + 1, end)
                   if key_re.match(lines[i])), None)
    if key_at is None:
        return False
    del lines[key_at]
    write_config_atomic(path, "\n".join(lines) + "\n")
    return True


def persist_preflight(vault, recommendation, offline_recommended,
                      allow_default_mode=True):
    """Write the preflight recommendation to the vault-local file.

    Per-vault (issue #722 remainder): the file is
    `<vault>/.confidant/qmd-preflight.toml`, never the global user
    config — the global file's [qmd] values remain as fallback for
    vaults with no per-vault file and are never rewritten here.
    A marked `offline` the fresh evidence no longer supports is cleared
    and reported distinctly; unmarked (hand-set) values are left
    alone and reported. A persisted `default_mode` is NEVER cleared
    when the probe yields no hit-bearing mode (#778): an empty probe
    is absence of evidence about the old mode, not evidence against
    it — the value is kept and reported as kept, whether marked or
    hand-set. Only a fresh hit-bearing recommendation replaces it,
    and only when `allow_default_mode` is true: a chained run
    (`--chained`) or a run without an explicit `--query` never
    writes `default_mode`, whatever the probe returns — the default
    query can hit through the semantic modes, so its hits are not
    a user-chosen measurement. Such a run still updates `offline`
    and reports any persisted mode as kept. The vault-local file
    is new, so it has no legacy-migration branch: every value it
    carries was either written with a marker by this function or
    added by hand.
    Returns the persisted dict (including the path written).
    """
    persisted = {}
    config = read_vault_qmd_config(vault)
    if recommendation is not None and allow_default_mode:
        set_vault_qmd_config_value(vault, "default_mode",
                                   json.dumps(recommendation))
        set_vault_qmd_config_value(vault, "default_mode" + SOURCE_SUFFIX,
                                   json.dumps(SOURCE_VALUE))
        persisted["default_mode"] = recommendation
    elif "default_mode" in config:
        # #778: this run does not replace the persisted mode — either
        # no hit-bearing mode ran, so the probe says nothing about
        # it (an empty probe is not evidence against it), or mode
        # writing is not allowed on this run (chained / no explicit
        # --query) and a hit-bearing probe must not overwrite the
        # settled mode. Keep the value, marked or hand-set, and
        # report it as kept.
        persisted["default_mode_kept"] = config["default_mode"]
    if offline_recommended:
        set_vault_qmd_config_value(vault, "offline", "true")
        set_vault_qmd_config_value(vault, "offline" + SOURCE_SUFFIX,
                                   json.dumps(SOURCE_VALUE))
        persisted["offline"] = True
    elif _truthy(config.get("offline", "")):
        if config.get("offline" + SOURCE_SUFFIX) == SOURCE_VALUE:
            remove_vault_qmd_config_value(vault, "offline")
            remove_vault_qmd_config_value(vault, "offline" + SOURCE_SUFFIX)
            persisted["offline_cleared"] = True
        else:
            persisted["offline_left"] = True
    persisted["path"] = vault_preflight_path(vault)
    return persisted


def recommend_default_mode(results, budget):
    """First preferred hit-bearing mode within budget, else first that ran.

    Preference order is hybrid > vector > bm25 (quality first); a mode
    that only ran over budget is still better than no mode, but it is
    never preferred over a mode within budget. Only status "ok" counts:
    "ok-empty" (zero hits) is not a recommendation — a corpus that
    answers nothing has not demonstrated a usable mode — and neither
    do timeout/failed/fallback runs. Seconds are the warm run's when a
    warm run exists (see run_smoke). None when no hit-bearing mode ran.
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


def cache_complete(results):
    """True only when a hybrid run proved the heaviest models are cached.

    Hybrid needs the embedding model AND the reranker, so a hit-bearing
    hybrid `ok` is the strictest cache proof available. A vector `ok`
    proves only the embedding model; a hybrid timeout proves nothing —
    it is exactly the cold-download case offline mode would then break.
    """
    return results.get("hybrid", {}).get("status") == "ok"


def offline_recommended_for(hub, results):
    """Fresh-evidence offline decision: hub unusable, or cache complete.

    Deliberately NOT "or offline was already configured": a prior
    choice is not fresh evidence, and counting it would make a stale
    offline=true self-perpetuating. main() keeps a pre-existing
    offline=true in place (it never clears a value it did not write
    without the provenance marker) — this function only answers what
    today's evidence recommends.
    """
    return (not hub["reachable"]) or cache_complete(results)


def tradeoff_note(results, recommendation):
    """Runner-up timing note, or None when there is no tradeoff to show.

    A hybrid answering in 59s is not obviously better than a vector
    answering in 2s just because the budget is 60s: surface the fastest
    hit-bearing mode's timing whenever the recommendation is more than
    twice as slow as it, so the operator sees the cost of quality.
    """
    if recommendation is None:
        return None
    rec_seconds = results.get(recommendation, {}).get("seconds")
    if rec_seconds is None:
        return None
    fastest = None
    for mode in MODES:
        r = results.get(mode, {})
        if r.get("status") == "ok" and r.get("seconds") is not None:
            if fastest is None or r["seconds"] < fastest[1]:
                fastest = (mode, r["seconds"])
    if fastest is None or fastest[0] == recommendation:
        return None
    if rec_seconds > 2 * fastest[1]:
        return (f"tradeoff: {recommendation} ({rec_seconds}s) is more "
                f"than twice as slow as {fastest[0]} ({fastest[1]}s) — "
                "consider the faster mode for interactive use, or a "
                "tighter --budget")
    return None


def _kill_process_group(proc):
    """SIGKILL the whole process group of a smoke child (issue #775).

    Smoke children run with start_new_session, so the child is its own
    group leader and the group holds exactly the wrapper plus whatever
    it spawned (its qmd child, and anything qmd spawned). The old
    subprocess.run timeout killed only the wrapper process: the qmd
    child survived as an orphan burning CPU for 9-12+ minutes after
    its smoke run timed out. Killing the group is what reaps it.
    A child that already exited is not an error. Off POSIX there is
    no process group to kill, so this falls back to killing the child
    alone (native Windows is unsupported anyway — WSL2 only).
    """
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    else:
        try:
            proc.kill()
        except OSError:
            pass


def _reap_smoke_child(proc):
    """Kill the smoke child's group and reap it, closing its pipes.

    Shared by the timeout path and the interruption path in
    `_run_one_smoke`: either way the child may still be running with
    a live qmd grandchild, and leaving it behind recreates the #775
    orphan. The group kill is best-effort (a child that already
    exited is not an error); the wait reaps the child so it cannot
    linger as a zombie; closing the pipe ends (which `communicate`
    never returned, having raised) keeps the run from leaking file
    descriptors. This helper must not raise: callers in the
    exception paths re-raise the original exception.
    """
    _kill_process_group(proc)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    finally:
        # The pipes were never consumed (communicate raised before
        # returning them): close our ends, or the run leaks file
        # descriptors and trips ResourceWarnings in the test suite.
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except (OSError, ValueError):
                pass
        if proc.stderr is not None:
            try:
                proc.stderr.close()
            except (OSError, ValueError):
                pass


def _run_one_smoke(query_script, vault, query, timeout, env, mode):
    """One timed qmd-query.py run; classifies its outcome precisely.

    Statuses: "ok" (hit-bearing), "ok-empty" (answered, zero hits —
    distinct from ok: it proves timing, not a usable mode), "skipped",
    "timeout", "failed", "fallback". Only "ok" ever feeds a
    recommendation or a cache-completeness claim.

    The run uses Popen (not subprocess.run) so that on timeout it can
    kill the child's whole process group (#775): the wrapper spawns
    qmd in its own group (qmd-query.py deliberately never calls
    start_new_session for the qmd child), so a group kill reaps the
    wrapper and its qmd child together. subprocess.run's timeout
    killed only the wrapper and leaked the qmd child as an orphan.
    The same group kill runs on interruption: the wrapper's new
    session puts it outside the terminal's foreground process group,
    so Ctrl-C reaches only preflight and `KeyboardInterrupt` (or
    `SystemExit`, or any other exception) out of `communicate` must
    still reap the group before propagating, or an ordinary cancel
    recreates the orphan.
    """
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            [sys.executable, query_script,
             "--vault", vault, "--mode", mode, query],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=env, start_new_session=(os.name == "posix"))
    except OSError as e:
        return {"status": "failed", "reason": str(e),
                "seconds": round(time.monotonic() - start, 2),
                "matches": None}
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _reap_smoke_child(proc)
        return {"status": "timeout",
                "reason": f"no answer within {timeout}s",
                "seconds": round(time.monotonic() - start, 2),
                "matches": None}
    except BaseException:
        # KeyboardInterrupt, SystemExit, or any unexpected exception:
        # the child is still alive in its own session, outside the
        # terminal's foreground process group, so only this cleanup
        # reaps it. Re-raise the original exception afterwards.
        _reap_smoke_child(proc)
        raise
    elapsed = round(time.monotonic() - start, 2)
    try:
        data = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError:
        data = None
    if proc.returncode != 0 and "needs embeddings" in (stderr or ""):
        return {"status": "skipped",
                "reason": "no embeddings (run qmd-index.py --embed)",
                "seconds": elapsed, "matches": None}
    if proc.returncode == 0 and isinstance(data, dict) \
            and data.get("mode") == mode:
        matches = data.get("matches")
        count = len(matches) if isinstance(matches, list) else None
        if count == 0:
            return {"status": "ok-empty",
                    "reason": "answered with zero hits — pass --query "
                              "with a term known to hit the corpus for a "
                              "hit-bearing measurement",
                    "seconds": elapsed, "matches": 0}
        return {"status": "ok", "reason": "", "seconds": elapsed,
                "matches": count}
    if proc.returncode == 0 and isinstance(data, dict) \
            and data.get("mode") == "find-fallback":
        return {"status": "fallback",
                "reason": data.get("fallback", "qmd unavailable"),
                "seconds": elapsed, "matches": None}
    detail = (stderr or "").strip().splitlines()
    return {"status": "failed",
            "reason": detail[-1] if detail else f"exit {proc.returncode}",
            "seconds": elapsed, "matches": None}


def run_smoke(query_script, vault, query, timeout, env,
              qmd_present, corpus_present, progress=None):
    """Cold + warm timed runs per mode; skips are reported, not failed.

    The first run per mode is the cold run: it may pay a model
    download, so its timing is exactly the misleading sample #722
    warns about. A mode whose cold run is "ok" (or "ok-empty") is run
    a second time and the warm run becomes the mode's canonical result
    — recommendations and cache claims derive from warm runs, never
    from a single cold sample. If the warm run fails, times out, or
    falls back, the mode is downgraded to that warm failure (its cold
    entry is kept for diagnosis, but the cold sample is never reused
    as the result): the mode is not recommended, proves no cache, and
    a --persist run writes no default_mode for it. A mode whose cold
    run timed out, failed, or fell back gets no warm rerun (there is
    no recommendation to protect, and a second cold download would
    just repeat the wait); its warm entry records that it was not
    measured. `progress`, when given, is called as
    progress(mode, phase, result) after each run so a slow preflight
    is never silent.
    """
    results = {}
    for mode in MODES:
        if not qmd_present:
            skip = {"status": "skipped", "reason": "qmd not installed",
                    "seconds": None, "matches": None}
            results[mode] = dict(skip, cold=dict(skip), warm=dict(skip))
            continue
        if not corpus_present:
            skip = {"status": "skipped",
                    "reason": "corpus missing (run qmd-index.py)",
                    "seconds": None, "matches": None}
            results[mode] = dict(skip, cold=dict(skip), warm=dict(skip))
            continue
        if progress is not None:
            progress(mode, "cold-start", None)
        cold = _run_one_smoke(query_script, vault, query, timeout, env, mode)
        if progress is not None:
            progress(mode, "cold-finish", cold)
        if cold["status"] in ("ok", "ok-empty"):
            if progress is not None:
                progress(mode, "warm-start", None)
            warm = _run_one_smoke(query_script, vault, query, timeout,
                                  env, mode)
            if progress is not None:
                progress(mode, "warm-finish", warm)
            # The warm run is ALWAYS canonical here — including when
            # it failed: reusing `cold` on a warm failure would let a
            # recommendation/--persist derive from a single cold sample
            # (round-2 N1). The cold entry is kept for diagnosis only.
            results[mode] = dict(warm, cold=cold, warm=warm)
        else:
            warm = {"status": "not-measured",
                    "reason": "cold run did not complete ok; warm timing "
                              "not measured (no recommendation derives "
                              "from this mode)",
                    "seconds": None, "matches": None}
            results[mode] = dict(cold, cold=cold, warm=warm)
    return results


def _progress_printer(mode, phase, result):
    """stderr progress for smoke runs: a slow preflight is never silent."""
    if phase.endswith("start"):
        print(f"  smoke {mode} {phase.split('-')[0]} run starting…",
              file=sys.stderr)
    else:
        seconds = result["seconds"] if result else None
        print(f"  smoke {mode} {phase.split('-')[0]} run: "
              f"{result['status']} in {seconds}s",
              file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=None)
    ap.add_argument("--query", default=None,
                    help="query text for the per-mode smoke runs "
                         f"(default {DEFAULT_QUERY!r}); a zero-hit "
                         "answer is reported as ok-empty, not "
                         "recommended — pass a term known to hit the "
                         "corpus for a hit-bearing measurement. A "
                         "default_mode change under --persist needs "
                         "an explicit --query: the semantic modes can "
                         "return neighbours for the default query "
                         "even when the literal phrase is absent, so "
                         "a run without one never writes default_mode")
    ap.add_argument("--query-timeout", type=int,
                    default=DEFAULT_QUERY_TIMEOUT_S,
                    help="per-mode smoke timeout in seconds "
                         f"(default {DEFAULT_QUERY_TIMEOUT_S})")
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET_S,
                    help="seconds a mode must answer within to be "
                         f"recommended (default {DEFAULT_BUDGET_S})")
    ap.add_argument("--hub-url", default=None,
                    help="hub endpoint to probe (default: $HF_ENDPOINT, "
                         "else https://huggingface.co)")
    ap.add_argument("--hub-timeout", type=int, default=DEFAULT_HUB_TIMEOUT_S,
                    help="seconds the hub probe may take "
                         f"(default {DEFAULT_HUB_TIMEOUT_S})")
    ap.add_argument("--persist", action="store_true",
                    help="write the recommendation ([qmd] default_mode, and "
                         "[qmd] offline when recommended) to the "
                         "vault-local per-vault file "
                         "(<vault>/.confidant/qmd-preflight.toml), never "
                         "the global user config; also clears a stale "
                         "preflight-written offline the fresh evidence no "
                         "longer supports, and never clears a persisted "
                         "default_mode when no hit-bearing mode ran. A "
                         "default_mode change needs an explicit "
                         "--query: a chained run (--chained) or a run "
                         "with the default query updates offline only "
                         "and never changes a persisted default_mode")
    ap.add_argument("--chained", action="store_true",
                    help="chained qmd-index.py run: with --persist, "
                         "update [qmd] offline only and never write "
                         "default_mode, whatever the probe returns "
                         "(qmd-index.py passes this; a default_mode "
                         "change needs an explicit --query run instead)")
    ap.add_argument("--json", action="store_true",
                    help="print the report as JSON instead of text")
    ap.add_argument("--query-script", default=None,
                    help="qmd-query.py path (default: the sibling script; "
                         "tests point it at a stub)")
    args = ap.parse_args(argv)

    vault = resolve_vault(args.vault)
    home = os.environ.get("HOME")
    # Per-vault persist needs no HOME (the file lives under the vault),
    # so there is no --persist-without-HOME failure any more: the old
    # early exit existed only because persist wrote the global user
    # config. A missing HOME just means no global fallback is read
    # (read_qmd_config fails closed to {}).
    spec = host_spec(vault)
    config = read_qmd_config(home)
    vault_config = read_vault_qmd_config(vault)
    hub_url = resolve_hub_url(args.hub_url)
    offline_forced = _truthy(os.environ.get("HF_HUB_OFFLINE", ""))
    hub = probe_model_hub(hub_url, args.hub_timeout,
                          offline_forced=offline_forced)

    # Smoke env: the hub probe already answered the reachability question,
    # so a failing probe must not turn the smoke runs into another
    # 3-minute wait — run them offline, exactly as qmd-query.py would
    # with [qmd] offline persisted.
    smoke_env = dict(os.environ)
    # Resolved offline for the smoke runs: per-vault wins, global is
    # fallback (same rule the query wrapper honors).
    offline_configured, offline_source = resolve_offline(vault_config, config)
    offline_for_smoke = offline_configured or not hub["reachable"]
    if offline_for_smoke and "HF_HUB_OFFLINE" not in smoke_env:
        smoke_env["HF_HUB_OFFLINE"] = "1"

    qmd_present = shutil.which("qmd") is not None
    corpus_present = os.path.isdir(os.path.join(vault, CORPUS_REL))
    query_script = args.query_script or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "qmd-query.py")
    # A default_mode change needs an explicit, user-supplied query:
    # the default query can hit through the semantic modes, so a
    # run without one — and any --chained run — is a measurement
    # only and must never write a mode (#778 fix round). The
    # recommendation is still computed and reported either way.
    query_text = args.query if args.query is not None else DEFAULT_QUERY
    allow_default_mode = args.query is not None and not args.chained
    results = run_smoke(query_script, vault, query_text, args.query_timeout,
                        smoke_env, qmd_present, corpus_present,
                        progress=_progress_printer)

    # Cache-completeness is PROOF, not vibes: only a hit-bearing hybrid
    # ok shows the embedding model and the reranker are both cached. A
    # timeout/failed/fallback run — the #722 failure itself — proves
    # nothing and must never persist offline mode. The JSON field is
    # named for what it is (hybrid cache proof), not for embeddings in
    # general: a vector-ok / hybrid-failed host HAS embeddings, but
    # this field is false for it (round-2 N5).
    hybrid_cache_complete = cache_complete(results)
    offline_recommended = offline_recommended_for(hub, results)
    recommendation = recommend_default_mode(results, args.budget)
    note = tradeoff_note(results, recommendation)

    persisted = {}
    persist_error = None
    if args.persist:
        # Per-vault persist (issue #722 remainder): persist_preflight
        # writes only the vault-local file. The global user config is
        # read-only fallback now and is never rewritten here — the old
        # global persist block (including its one-time legacy-migration
        # stamp) is gone by design, not by accident: values an old
        # --persist wrote globally are still honored as fallback, and
        # clearing them from a per-vault run could clobber a fallback
        # another vault still relies on.
        try:
            persisted = persist_preflight(
                vault, recommendation, offline_recommended,
                allow_default_mode=allow_default_mode)
        except OSError as e:
            # Report the failure with the report, not a traceback: the
            # diagnosis is still delivered even when the write failed.
            persist_error = str(e)
            persisted["error"] = persist_error

    warnings = list(spec_warnings(spec))
    if not hub["reachable"] and not hub.get("skipped"):
        warnings.append(f"model hub unreachable ({hub['detail']}): "
                        "first queries may pay a hub wait or fall back")
    if recommendation is None:
        warnings.append("no hit-bearing mode ran: no default mode "
                        "recommended; search falls back to "
                        "`confidant find` until the corpus/embeddings "
                        "are built (qmd-index.py)")
    if note is not None:
        warnings.append(note)

    report = {
        "vault": vault,
        "spec": spec,
        "spec_warnings": warnings,
        "hub": hub,
        "hub_url": hub_url,
        "offline_for_smoke": offline_for_smoke,
        "offline_configured": offline_configured,
        "offline_configured_source": offline_source,
        "vault_preflight_path": vault_preflight_path(vault),
        "offline_recommended": offline_recommended,
        "hybrid_cache_complete": hybrid_cache_complete,
        "modes": results,
        "budget_s": args.budget,
        "recommended_mode": recommendation,
        "tradeoff_note": note,
        "warnings": warnings,
        "persisted": persisted,
    }
    if args.json:
        print(json.dumps(report, indent=2))
        if persist_error is not None:
            print(f"error: persist failed: {persist_error}", file=sys.stderr)
        return 0

    print(f"qmd preflight: {vault}")
    cpus = spec["cpus"] if spec["cpus"] is not None else "?"
    ram = f"{spec['ram_gb']} GB" if spec["ram_gb"] is not None else "unknown"
    disk = (f"{spec['disk_free_gb']} GB free at the vault store"
            if spec["disk_free_gb"] is not None else "unknown free disk")
    cache_disk = (f"{spec['model_cache_free_gb']} GB free at the model "
                  f"cache ({spec['model_cache_path']})"
                  if spec["model_cache_free_gb"] is not None
                  else "unknown free disk at the model cache")
    print(f"  spec: {cpus} CPUs, {ram} RAM, {disk}; {cache_disk} "
          f"(model footprint ~{MODEL_FOOTPRINT_GB} GB)")
    gpu = spec["gpu"] or ("no NVIDIA GPU detected (Apple Silicon / AMD "
                          "GPUs are not probed) — assuming CPU-only "
                          "inference")
    print(f"  gpu: {gpu}")
    if hub.get("skipped"):
        print(f"  model hub ({hub_url}): probe SKIPPED ({hub['detail']})")
    else:
        print(f"  model hub ({hub_url}): "
              f"{'reachable' if hub['reachable'] else 'UNREACHABLE'} "
              f"in {hub['seconds']}s ({hub['detail']})")
    if offline_for_smoke:
        print("  smoke runs use HF_HUB_OFFLINE=1 "
              "(hub unreachable, probe skipped, or offline already configured)")
    for mode in MODES:
        r = results[mode]
        cold = r.get("cold", {})
        warm = r.get("warm", {})
        cold_txt = (f"cold {cold.get('seconds')}s" if cold.get("seconds")
                    is not None else f"cold {cold.get('status')}")
        warm_txt = (f"warm {warm.get('seconds')}s" if warm.get("seconds")
                    is not None else f"warm {warm.get('status')}")
        if r["status"] == "ok":
            over = " — OVER BUDGET" if r["seconds"] > args.budget else ""
            print(f"  {mode}: ok in {r['seconds']}s "
                  f"({r['matches']} matches; {cold_txt}, {warm_txt}){over}")
        elif r["status"] == "ok-empty":
            print(f"  {mode}: ok-empty in {r['seconds']}s (zero hits; "
                  f"{cold_txt}, {warm_txt}) — not recommended")
        elif r["status"] == "skipped":
            print(f"  {mode}: skipped ({r['reason']})")
        elif cold.get("status") in ("ok", "ok-empty") and warm.get("status") \
                not in ("ok", "ok-empty", "not-measured"):
            # Warm failure after a cold ok: say so loudly — the cold
            # sample was NOT reused, and this mode is not recommended.
            print(f"  {mode}: {r['status']} on the warm run in "
                  f"{r['seconds']}s ({r['reason']}; cold was "
                  f"{cold['status']} in {cold['seconds']}s) — not "
                  "recommended; the cold sample is not reused")
        else:
            print(f"  {mode}: {r['status']} in {r['seconds']}s "
                  f"({r['reason']}; {warm_txt})")
    if recommendation is not None:
        print(f"  recommended default mode: {recommendation} "
              f"(warm run; cold cost shown above)")
    else:
        print("  recommended default mode: none (no hit-bearing mode ran; "
              "search falls back to `confidant find`)")
    if note is not None:
        print(f"  {note}")
    if offline_recommended:
        print("  offline mode recommended: persist with --persist "
              "(or set [qmd] offline = true)")
    if args.persist and persist_error is None:
        print(f"  persisted: {persisted or 'nothing to persist'}")
        # "path" alone means nothing needed writing or clearing — only
        # name the file when an actual persist action happened.
        if any(k != "path" for k in persisted):
            print(f"  persisted to: {persisted['path']} (per-vault; the "
                  "global [qmd] config is left untouched and remains "
                  "the fallback for vaults with no per-vault file)")
        if "default_mode_kept" in persisted:
            print(f"  note: kept persisted default_mode "
                  f"({persisted['default_mode_kept']!r}) in the "
                  "vault-local file — this run did not replace it "
                  "(#778: only an explicit --query run replaces a "
                  "persisted mode)")
        if "offline_cleared" in persisted:
            print("  note: cleared stale preflight-written offline = true "
                  "from the vault-local file — fresh evidence no longer "
                  "supports it")
        if "offline_left" in persisted:
            print("  note: a [qmd] offline value set by hand in the "
                  "vault-local file (not marked as preflight-written) "
                  "was left alone despite fresh evidence; edit it "
                  "yourself if it is stale")
    if persist_error is not None:
        print(f"  error: persist failed: {persist_error}")
    if warnings:
        print("  warnings:")
        for w in warnings:
            print(f"    - {w}")
    print("  note: exit 0 is not a gate — read this report (or --json) "
          "before the next setup step")
    return 0


if __name__ == "__main__":
    sys.exit(main())
