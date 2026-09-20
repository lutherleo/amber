"""Capture the pre-feature output baseline for feature 036 SC-002 (task T001a).

Runs an audit against an all-deterministic fixture repo (two file-existence
controls, no network) and writes markdown / JSON / SARIF outputs to
tests/darnit/fixtures/error_class_baseline/.

MUST be run against unmodified `main` code. T027 diffs post-feature output
against these files; generating them from post-feature code would be circular.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[0]
# Resolve the actual repo root by walking up to the dir containing pyproject.toml
_p = Path.cwd()
while _p != _p.parent and not (_p / "pyproject.toml").exists():
    _p = _p.parent
REPO_ROOT = _p

OUT_DIR = REPO_ROOT / "tests" / "darnit" / "fixtures" / "error_class_baseline"

# The two purely-deterministic controls the parity corpus already uses:
# README presence and LICENSE presence. No network, no LLM.
DETERMINISTIC_CONTROL_IDS = ["OSPS-DO-01.01", "OSPS-LE-03.01"]

FIXTURE_SRC = REPO_ROOT / "tests" / "darnit" / "parity" / "fixtures" / "mixed_repo"


def build_fixture(dest: Path) -> None:
    """Copy the mixed_repo fixture into a git repo at a stable path.

    A stable path matters: several formatters embed the repo path, so the
    baseline has to be reproducible. We use a fixed directory name under
    the system tempdir rather than a random mkdtemp suffix.
    """
    import shutil

    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(FIXTURE_SRC, dest)
    # Drop the parity harness config so it isn't mistaken for repo content.
    (dest / "parity.toml").unlink(missing_ok=True)

    subprocess.run(["git", "init", "-q"], cwd=dest, check=True)
    subprocess.run(
        ["git", "config", "user.email", "baseline@example.com"], cwd=dest, check=True
    )
    subprocess.run(["git", "config", "user.name", "Baseline"], cwd=dest, check=True)
    subprocess.run(["git", "add", "-A"], cwd=dest, check=True)
    # #7 portability: inherit the real environment (so git.exe is found on
    # Windows) and only *pin* the dates for determinism, instead of replacing
    # PATH with a POSIX-only value that breaks the commit off-Linux.
    commit_env = {
        **os.environ,
        "GIT_COMMITTER_DATE": "2020-01-01T00:00:00Z",
        "GIT_AUTHOR_DATE": "2020-01-01T00:00:00Z",
    }
    subprocess.run(
        ["git", "commit", "-q", "-m", "baseline fixture"],
        cwd=dest,
        check=True,
        env=commit_env,
    )


def scrub(text: str, fixture: Path) -> str:
    """Normalize machine- and run-varying fields out of formatter output.

    Made OS-independent (#7). The committed baseline is a single artifact
    that must match capture output on Linux, macOS, AND Windows, so scrub
    erases every OS-varying representation of the fixture path:

    * The raw OS path (markdown / plain text: ``C:\\...`` or ``/tmp/...``).
    * Its JSON-escaped form (``json.dumps`` doubles Windows backslashes,
      which is exactly why the pre-#7 single ``str.replace`` silently missed
      ``found_file`` on Windows and let a machine path leak into the
      committed baseline).
    * Its forward-slash (``as_posix``) form.

    It then collapses whatever separator follows the placeholder to a single
    ``/`` so ``<FIXTURE>\\x`` (json), ``<FIXTURE>\\x`` (raw win) and
    ``<FIXTURE>/x`` (posix) all normalize to ``<FIXTURE>/x``.

    Other, non-path variance, neither related to this feature:

    * ``format_results_markdown``'s ``Generated At:`` wall-clock stamp
      (run-dependent). Genuine Tier 1 determinism gap; out of scope for
      feature 036, flagged on issue #418.
    * ``pass_history[].duration_ms`` (load-dependent).
    """
    import re

    fixture_str = str(fixture)
    for variant in (
        fixture_str.replace("\\", "\\\\"),  # JSON-escaped Windows path (do first)
        fixture_str,  # raw OS path (markdown, POSIX)
        fixture.as_posix(),  # forward-slash form
    ):
        text = text.replace(variant, "<FIXTURE>")
    # Collapse the trailing separator so the placeholder path is OS-independent.
    text = text.replace("<FIXTURE>\\\\", "<FIXTURE>/")  # JSON-escaped backslash sep
    text = text.replace("<FIXTURE>\\", "<FIXTURE>/")  # raw backslash sep

    text = re.sub(
        r"\*\*Generated At:\*\* \S+",
        "**Generated At:** <SCRUBBED-TIMESTAMP>",
        text,
    )
    text = re.sub(r'"duration_ms": \d+', '"duration_ms": "<SCRUBBED-DURATION>"', text)
    return text


def main() -> int:
    # #7: both the fixture dir and the output dir are overridable via env so
    # the regression test can run capture into a tmp dir and diff against the
    # committed files WITHOUT overwriting them. The pre-#7 script always wrote
    # in place to the committed OUT_DIR -- a destructive side effect that
    # corrupted the committed baseline the first time it ran on Windows.
    out_dir = Path(os.environ.get("DARNIT_036_BASELINE_OUT", str(OUT_DIR)))
    fixture = Path(
        os.environ.get(
            "DARNIT_036_FIXTURE_DIR",
            str(Path(tempfile.gettempdir()) / "darnit-036-baseline-fixture"),
        )
    )
    build_fixture(fixture)

    from darnit.config.control_loader import load_controls_from_effective
    from darnit.config.merger import load_effective_config_by_name
    from darnit.filtering.filters import filter_controls
    from darnit.tools.audit import (
        calculate_compliance,
        format_results_markdown,
        run_sieve_audit,
    )

    config = load_effective_config_by_name("openssf-baseline", repo_path=fixture)
    all_controls = load_controls_from_effective(config)
    controls = filter_controls(
        all_controls, {}, set(DETERMINISTIC_CONTROL_IDS), None
    )
    print(f"filtered to {len(controls)} controls: {[c.control_id for c in controls]}")

    results, summary = run_sieve_audit(
        owner="baseline-owner",
        repo="baseline-repo",
        local_path=str(fixture),
        default_branch="main",
        level=1,
        controls=controls,
        apply_user_config=False,
        stop_on_llm=True,
    )

    # Sort for stability -- run_sieve_audit's ordering follows the registry.
    results = sorted(results, key=lambda r: r["id"])

    out_dir.mkdir(parents=True, exist_ok=True)

    # --- markdown ---
    compliance = calculate_compliance(results, level=1)
    md = format_results_markdown(
        owner="baseline-owner",
        repo="baseline-repo",
        results=results,
        summary=summary,
        compliance=compliance,
        level=1,
        local_path=str(fixture),
        framework_name="openssf-baseline",
    )
    md = scrub(md, fixture)
    (out_dir / "baseline.md").write_text(md, encoding="utf-8")

    # --- JSON (the CheckResult wire shape, which is what error_class lands in) ---
    scrubbed = json.loads(scrub(json.dumps(results), fixture))
    (out_dir / "baseline.json").write_text(
        json.dumps(scrubbed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # --- SARIF ---
    from darnit_baseline.formatters.sarif import result_to_sarif_result

    sarif_results = [
        result_to_sarif_result(r, rule_index=i, repo="baseline-repo", local_path=str(fixture))
        for i, r in enumerate(results)
    ]
    sarif_scrubbed = json.loads(scrub(json.dumps(sarif_results), fixture))
    (out_dir / "baseline.sarif").write_text(
        json.dumps(sarif_scrubbed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(f"wrote baseline to {out_dir}")
    for f in sorted(out_dir.iterdir()):
        print(f"  {f.name}: {f.stat().st_size} bytes")
    print(f"\ncontrols captured: {[r['id'] for r in results]}")
    print(f"summary: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
