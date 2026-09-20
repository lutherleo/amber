"""Amber capture-completeness eval — how good is the capture, measured against ground truth.

The Orion-NodeGoat analog for reproducibility: for each research example whose expected dependencies
are known, score whether the capture actually recorded them (recall), caught the native libraries the
Python import system can't see, verified its own digest, and bound the run to a commit — plus a
verdict-accuracy check (identical captures reproduce; a mutated one does not). Runs offline against the
committed fixtures, so it is a durable regression on capture quality.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .analysis import compare as cmp
from .ingest import witness as ing
from .models import CaptureRecord

# Expected core dependencies per example (a subset that MUST be captured). expect_native_libs=True
# means the run links a native BLAS/etc. the Python import system does not see.
GROUND_TRUTH: dict[str, dict[str, Any]] = {
    "lorenz": {"deps": {"numpy", "scipy"}, "expect_native_libs": True},
    "sir": {"deps": {"numpy", "scipy"}, "expect_native_libs": True},
    "sklearn_wine": {"deps": {"numpy", "scipy", "scikit-learn"}, "expect_native_libs": True},
    "pysindy": {"deps": {"pysindy", "numpy", "scipy"}, "expect_native_libs": True},
}

_REPRODUCED = {"BIT_FOR_BIT", "REPRODUCED_WITH_DRIFT", "SEMANTICALLY_REPRODUCED"}


@dataclass
class Completeness:
    example: str
    deps_recall: float
    missing_deps: list[str]
    native_libs_ok: bool
    digest_verified: bool
    commit_bound: bool
    hardware_captured: bool
    score: float


def capture_completeness(rec: CaptureRecord, gt: dict[str, Any]) -> Completeness:
    used = {d.get("name") for d in rec.python_env.used_distributions}
    missing = sorted(gt["deps"] - used)
    recall = 1.0 - len(missing) / len(gt["deps"]) if gt["deps"] else 1.0
    native = [s for s in (rec.ebpf_file_access or {}).get("shared_objects", [])
              if not s.get("in_python_modules")]
    native_ok = (not gt.get("expect_native_libs")) or bool(native)
    digest = rec.python_env.digest_verified is True
    commit = rec.repo.commit_matches_python_env is True
    hardware = bool(rec.hardware) and "cpu" in (rec.hardware or {})
    checks = [recall, float(native_ok), float(digest), float(commit), float(hardware)]
    return Completeness(example="", deps_recall=recall, missing_deps=missing, native_libs_ok=native_ok,
                        digest_verified=digest, commit_bound=commit, hardware_captured=hardware,
                        score=sum(checks) / len(checks))


def _load_fixture(root: Path, name: str) -> CaptureRecord:
    d = root / name / "fixtures"
    return ing.load(d / "bundle.redacted.json", d / "amber-pylibs.redacted.json")


def _verdict_case(rec: CaptureRecord) -> tuple[bool, bool]:
    """(identical→reproduced, mutated→not-reproduced): the two labels the verdict must get right."""
    same = cmp.compare(rec, rec).level in _REPRODUCED
    other = copy.deepcopy(rec)
    # change every produced file's digest (identical environment) -> must be NOT_REPRODUCED
    for fd in other.folder_stasis.added + other.folder_stasis.changed:
        fd.sha256 = "sha256:deadbeef"
    diff = cmp.compare(rec, other).level == "NOT_REPRODUCED"
    return same, diff


@dataclass
class EvalReport:
    completeness: list[Completeness] = field(default_factory=list)
    verdict_correct: int = 0
    verdict_total: int = 0

    @property
    def completeness_score(self) -> float:
        return (sum(c.score for c in self.completeness) / len(self.completeness)
                if self.completeness else 0.0)

    @property
    def verdict_accuracy(self) -> float:
        return self.verdict_correct / self.verdict_total if self.verdict_total else 0.0


def evaluate_corpus(root: str | Path, ground_truth: dict[str, dict] | None = None) -> EvalReport:
    root = Path(root)
    gt = ground_truth or GROUND_TRUTH
    report = EvalReport()
    for name, spec in gt.items():
        rec = _load_fixture(root, name)
        comp = capture_completeness(rec, spec)
        comp.example = name
        report.completeness.append(comp)
        same, diff = _verdict_case(rec)
        report.verdict_correct += int(same) + int(diff)
        report.verdict_total += 2
    return report


def render(report: EvalReport) -> str:
    L = ["=" * 78, "AMBER CAPTURE-COMPLETENESS EVAL", "=" * 78,
         f"{'example':<14} {'recall':>7} {'native':>7} {'digest':>7} {'commit':>7} {'hw':>4} {'score':>7}",
         "-" * 78]
    for c in report.completeness:
        L.append(f"{c.example:<14} {c.deps_recall:>7.0%} {'✓' if c.native_libs_ok else '✗':>7} "
                 f"{'✓' if c.digest_verified else '✗':>7} {'✓' if c.commit_bound else '✗':>7} "
                 f"{'✓' if c.hardware_captured else '✗':>4} {c.score:>7.0%}")
        if c.missing_deps:
            L.append(f"    missing deps: {', '.join(c.missing_deps)}")
    L.append("-" * 78)
    L.append(f"completeness score: {report.completeness_score:.0%}   "
             f"verdict accuracy: {report.verdict_accuracy:.0%} "
             f"({report.verdict_correct}/{report.verdict_total})")
    L.append("=" * 78)
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    import argparse

    default_root = Path(__file__).resolve().parents[2] / "examples" / "research"
    p = argparse.ArgumentParser(prog="amber-eval",
                                description="Score Amber capture completeness against ground truth.")
    p.add_argument("root", nargs="?", default=str(default_root),
                   help="research examples dir (default: this package's examples/research)")
    p.add_argument("--min-score", type=float, default=0.9, help="fail below this completeness score")
    args = p.parse_args(argv)

    report = evaluate_corpus(args.root)
    print(render(report))
    ok = report.completeness_score >= args.min_score and report.verdict_accuracy == 1.0
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
