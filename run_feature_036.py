#!/usr/bin/env python
"""One-shot runner for feature 036 (`error_class`) + the seven improvements.

Run it with::

    uv run python run_feature_036.py

It does two things:

  1. Runs every feature-036 test module via pytest and reports the result.
  2. Prints a short LIVE demo of each improvement working end to end, so you
     can eyeball the behavior, not just a green bar.

Exit code is 0 only if the test suite passes.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent

TEST_MODULES = [
    "tests/darnit/sieve/test_error_class_classification.py",
    "tests/darnit/sieve/test_error_class_cel_preservation.py",
    "tests/darnit/sieve/test_error_class_improvements.py",
    "tests/darnit/test_error_class_happy_path.py",
    "tests/darnit_baseline/test_error_class_output_surfaces.py",
]


def _rule(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def run_tests() -> int:
    _rule("1. TEST SUITE  (pytest)")
    proc = subprocess.run(
        ["uv", "run", "pytest", *TEST_MODULES, "-q"],
        cwd=REPO_ROOT,
    )
    return proc.returncode


def _proc(returncode: int, stdout: str = "", stderr: str = "") -> MagicMock:
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


def demo() -> None:
    from darnit.context.auto_detect import _get_remote_url
    from darnit.core.error_class import ERROR_CLASSES, log_environmental_failure
    from darnit.sieve import mcp_pool as mcp_pool_mod
    from darnit.sieve.builtin_handlers import (
        _classify_exec_failure,
        _classify_mcp_exception,
        exec_handler,
    )
    from darnit.sieve.handler_registry import HandlerContext, HandlerResultStatus
    from darnit.tools.audit import format_results_markdown

    ctx = HandlerContext(local_path=str(REPO_ROOT), control_id="DEMO-01.01")

    _rule("2. LIVE DEMO")
    print(f"\nKnown error classes: {sorted(ERROR_CLASSES)}")

    # --- #1 full-stderr classification -------------------------------------
    print("\n[#1] rate-limit signal buried past the 2000-char evidence cap:")
    stderr = ("noise\n" * 400) + "gh: API rate limit exceeded for user ID 1."
    with patch(
        "darnit.sieve.builtin_handlers.subprocess.run",
        return_value=_proc(1, stderr=stderr),
    ):
        r = exec_handler({"handler": "exec", "command": ["gh", "api", "/x"]}, ctx)
    print(f"     stderr length={len(stderr)}  ->  error_class={r.error_class!r}")
    print(f"     evidence stderr truncated to {len(r.evidence['stderr'])} chars")

    # --- #2 conservative unclassified --------------------------------------
    print("\n[#2] gh patterns classify; anything else stays unclassified:")
    for line in (
        "gh: Bad credentials (HTTP 401)",
        "You have exceeded a secondary rate limit.",
        "fatal: not a git repository",  # non-gh -> None (was 'network')
    ):
        print(f"     {line!r:52} -> {_classify_exec_failure(line)!r}")

    # --- #5 shared hub, one format -----------------------------------------
    print("\n[#5] every site logs through one hub (typed error_class):")
    hub_log = logging.getLogger("darnit.demo.hub")
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("     WARN | %(message)s"))
    hub_log.addHandler(handler)
    hub_log.setLevel(logging.WARNING)
    hub_log.propagate = False
    log_environmental_failure(hub_log, "auth", "token expired", subject="OSPS-AC-02: exec")
    log_environmental_failure(hub_log, "timeout", "call exceeded 60s", subject="OSPS-BR-01: mcp")

    # --- #4 auto-detect network arm ----------------------------------------
    print("\n[#4] context auto-detect routes its git failures through the hub:")
    from darnit.context import auto_detect as _ad

    ad_handler = logging.StreamHandler(sys.stdout)
    ad_handler.setFormatter(logging.Formatter("     WARN | %(message)s"))
    ad_handler.setLevel(logging.WARNING)
    _ad.logger.addHandler(ad_handler)  # the module's own logger, whatever its name
    _ad.logger.setLevel(logging.WARNING)
    with patch(
        "darnit.context.auto_detect.subprocess.run", side_effect=OSError("disk gone")
    ):
        _get_remote_url("origin", str(REPO_ROOT))
    _ad.logger.removeHandler(ad_handler)

    # --- #6 MCP exception table --------------------------------------------
    print("\n[#6] MCP exception -> (status, error_class) table:")
    for name in (
        "McpToolTimeout",
        "McpServerBinaryMissing",
        "McpServerVerificationFailed",
        "McpToolResponseNotJson",
    ):
        exc = getattr(mcp_pool_mod, name)("boom")
        status, ec, _ = _classify_mcp_exception(exc, optional=True)
        print(f"     {name:32} -> status={status.value:12} error_class={ec!r}")
    req_status, _, req_msg = _classify_mcp_exception(
        mcp_pool_mod.McpServerBinaryMissing("gone"), optional=False
    )
    print(f"     McpServerBinaryMissing (required) -> status={req_status.value}")

    # --- end-to-end: markdown triage (the whole point) ----------------------
    print("\n[E2E] markdown report distinguishes 'fix the runner' from 'fix the repo':")
    md = format_results_markdown(
        owner="o",
        repo="r",
        results=[
            {
                "id": "OSPS-LE-02.02",
                "status": "FAIL",
                "details": "Command exited with unexpected code 1",
                "level": 1,
                "error_class": "auth",
            },
            {
                "id": "OSPS-QA-04.01",
                "status": "FAIL",
                "details": "Pattern not found in any file",
                "level": 1,
            },
        ],
        summary={"PASS": 0, "FAIL": 2, "WARN": 0, "N/A": 0, "ERROR": 0, "total": 2},
        compliance={1: False},
        level=1,
    )
    for ln in md.splitlines():
        if "OSPS-LE-02.02" in ln or "OSPS-QA-04.01" in ln:
            print(f"     {ln.strip()}")
    _ = HandlerResultStatus  # keep import meaningful for readers


def main() -> int:
    rc = run_tests()
    try:
        demo()
    except Exception as exc:  # demo is best-effort; never mask a test failure
        print(f"\n(demo skipped: {type(exc).__name__}: {exc})")

    _rule("RESULT")
    if rc == 0:
        print("All feature-036 tests passed.")
    else:
        print(f"Tests FAILED (pytest exit code {rc}).")
    return rc


if __name__ == "__main__":
    sys.exit(main())
