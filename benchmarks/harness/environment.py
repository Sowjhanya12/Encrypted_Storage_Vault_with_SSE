"""
benchmarks/harness/environment.py -- captures the machine and library
context every measurement in this phase depends on.

A benchmark number without its environment is not a result, it is a
rumour: "index build takes 40 ms" means nothing until it says on what
CPU, at what Python version, against which `cryptography` build, and
with which Argon2id cost parameters. This module collects that record
automatically at the start of every run so it cannot drift from the
numbers or be filled in from memory afterwards.

Two deliberate decisions:

* **Nothing identifying is collected.** No hostname, no username, no
  home directory, no MAC or serial number, no absolute paths outside
  the project. The report is meant to be handed to an examiner; it
  needs the shape of the machine, not the identity of its owner.

* **Every optional lookup degrades instead of failing.** `psutil` is
  not a hard dependency, and a missing library version records as
  `None` rather than aborting a 20-minute run. A field that could not
  be determined reads as "unknown" in the report -- which is honest --
  rather than being quietly omitted, which would not be.
"""

from __future__ import annotations

import importlib.metadata
import os
import platform
import sqlite3
import sys
import time
from datetime import datetime, timezone
from typing import Optional

from .timing import timer_resolution

# Libraries whose version can change a measured number. `argon2` is
# argon2-cffi; `cryptography` carries the OpenSSL build that actually
# executes AES-GCM, which is the single biggest external influence on
# the throughput numbers in suite B2.
_TRACKED_LIBRARIES = {
    # import name -> distribution name on PyPI
    "cryptography": "cryptography",
    "argon2": "argon2-cffi",
    "flask": "Flask",
    "requests": "requests",
    "numpy": "numpy",
    "matplotlib": "matplotlib",
}


def _library_version(module_name: str, distribution_name: str) -> "Optional[str]":
    """Version of an installed library, preferring package metadata.

    `importlib.metadata` is asked first because a module's
    `__version__` attribute is an informal convention that libraries
    are actively dropping -- Flask 3.2 removes it, and reading it
    emits a DeprecationWarning today. Metadata is the authoritative
    answer and works for libraries that never exposed `__version__`.
    The attribute is kept only as a fallback, and a library that is
    genuinely absent records as None rather than aborting the run.
    """
    try:
        return importlib.metadata.version(distribution_name)
    except importlib.metadata.PackageNotFoundError:
        pass
    except Exception:
        pass
    try:
        module = __import__(module_name)
    except Exception:
        return None
    return getattr(module, "__version__", "unknown")


def _openssl_version() -> "Optional[str]":
    """The OpenSSL build backing `cryptography` -- the code that
    actually performs AES-GCM, and therefore what suite B2's
    throughput is really a measurement of."""
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        return backend.openssl_version_text()
    except Exception:
        return None


def _memory_and_cores() -> dict:
    """Physical core count and total RAM, via psutil when available.

    Both matter here for a specific reason: Argon2id is configured
    with `parallelism=4` and `memory_cost=64 MiB`, so a machine with
    fewer than 4 usable cores, or one under memory pressure, produces
    a materially different unlock time -- and the reader needs to see
    that from the report rather than infer it.
    """
    info = {
        "logical_cores": os.cpu_count(),
        "physical_cores": None,
        "total_ram_bytes": None,
        "available_ram_bytes": None,
        "psutil_available": False,
    }
    try:
        import psutil
    except Exception:
        return info
    info["psutil_available"] = True
    try:
        info["physical_cores"] = psutil.cpu_count(logical=False)
        vm = psutil.virtual_memory()
        info["total_ram_bytes"] = int(vm.total)
        info["available_ram_bytes"] = int(vm.available)
    except Exception:
        pass
    return info


def _argon2_production_parameters() -> dict:
    """The Argon2id cost parameters the application actually ships
    with, read from client/keymgmt.py rather than restated here.

    Read-only, and restated in the report next to the unlock timings
    because those timings are meaningless without them. Audit finding
    M1 is the reason this is captured explicitly: the parameters are
    NOT persisted in the vault's `meta` table, so a vault carries no
    record of what derived its keys -- the benchmark record is
    currently the only place they are written down alongside a
    measurement.
    """
    try:
        from client import keymgmt
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    return {
        "available": True,
        "time_cost": keymgmt.ARGON2_TIME_COST,
        "memory_cost_kib": keymgmt.ARGON2_MEMORY_COST_KIB,
        "parallelism": keymgmt.ARGON2_PARALLELISM,
        "salt_size_bytes": keymgmt.SALT_SIZE,
        "persisted_in_vault_meta": False,  # audit M1 -- open at Phase 7
    }


def capture() -> dict:
    """One JSON-serialisable snapshot of everything that could explain
    a difference between two runs of this suite."""
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "timezone_offset_seconds": -time.timezone,
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor() or None,
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_compiler": platform.python_compiler(),
        "python_64bit": sys.maxsize > 2**32,
        "sqlite_version": sqlite3.sqlite_version,
        "openssl_version": _openssl_version(),
        "libraries": {name: _library_version(name, dist) for name, dist in _TRACKED_LIBRARIES.items()},
        "hardware": _memory_and_cores(),
        "argon2_production_parameters": _argon2_production_parameters(),
        "timer": {
            "clock": "time.perf_counter_ns",
            "resolution_seconds": timer_resolution(),
        },
        "privacy_note": (
            "No hostname, username, or absolute filesystem path outside the "
            "project is recorded -- this snapshot describes the machine's "
            "shape, not its owner."
        ),
    }


def one_line_summary(env: dict) -> str:
    """A compact human-readable line for console output and chart
    captions, so every figure carries its own provenance."""
    hw = env.get("hardware", {})
    cores = hw.get("logical_cores")
    ram = hw.get("total_ram_bytes")
    ram_gib = f"{ram / 1073741824:.1f} GiB" if ram else "RAM unknown"
    return (
        f"{env.get('system')} {env.get('machine')} - "
        f"{cores} logical core(s), {ram_gib} - "
        f"Python {env.get('python_version')} "
        f"({env.get('python_implementation')})"
    )
