"""Evidence tests: ingest REAL captured bundles from real research examples.

The fixtures under ``packages/darnit-reproducibility/examples/research/<name>/fixtures/`` are actual
Amber captures of the Lorenz (SciPy), SIR (SciPy) and scikit-learn experiments, redacted for privacy
(env-var values, home paths, hostname/username) but with the attestor structure, file digests,
installed distributions, loaded library objects and git commit preserved. Ingesting them here proves
the pipeline works on real third-party scientific code — token-free, no witness needed. Regenerate
with ``examples/research/capture_research.sh``.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from darnit_reproducibility.ingest import witness as ing

_ROOT = Path(__file__).resolve().parents[2]
_RESEARCH = _ROOT / "packages" / "darnit-reproducibility" / "examples" / "research"

# (example dir, distribution that MUST have been captured)
CASES = [
    ("lorenz", "scipy"),
    ("sir", "scipy"),
    ("sklearn_wine", "scikit-learn"),
    ("pysindy", "pysindy"),  # downloaded external research package
]


def _fixture(name: str) -> tuple[Path, Path]:
    d = _RESEARCH / name / "fixtures"
    return d / "bundle.redacted.json", d / "amber-pylibs.redacted.json"


@pytest.mark.parametrize("name,dist", CASES)
def test_research_capture_ingests(name: str, dist: str) -> None:
    bundle, pylibs = _fixture(name)
    assert bundle.is_file(), f"missing fixture {bundle} — run capture_research.sh"
    rec = ing.load(bundle, pylibs)

    # a real Witness collection with the core attestors
    assert "attestation-collection" in (rec.collection_type or "")
    assert {"environment", "git", "material", "product", "command-run"} <= set(rec.attestor_types)
    assert rec.command.exitcode == 0

    # the experiment ran as first-party code, bound to a commit the git attestor agrees with
    assert rec.python_env.captured is True
    assert any(m.module == "__main__" for m in rec.python_env.first_party)
    assert rec.repo.commit_matches_python_env is True

    # the scientific dependency was captured as an installed distribution
    dist_names = {d.get("name") for d in rec.python_env.distributions}
    assert dist in dist_names, f"{dist} not among captured distributions: {sorted(dist_names)}"

    # and its library objects were actually loaded and hashed
    assert rec.python_env.third_party, "no third-party modules captured"
    assert all(m.sha256 for m in rec.python_env.third_party[:20])

    # the python-env attestation's own digest matches what the product attestor recorded
    assert rec.python_env.digest_verified is True

    # hardware/numerical + deep trace were captured (M3/M4)
    assert rec.hardware is not None and "cpu" in rec.hardware
    assert rec.numerical is not None
    assert rec.ebpf_file_access is not None
    assert rec.ebpf_file_access.get("shared_objects"), "no native shared objects in deep trace"


@pytest.mark.parametrize("name,_dist", CASES)
def test_capture_report_records_reproducibility(name: str, _dist: str) -> None:
    report = _RESEARCH / name / "CAPTURE_REPORT.txt"
    assert report.is_file()
    text = report.read_text()
    assert "AMBER CAPTURE REPORT" in text
    # capture_research.sh appends the digest it verified bit-for-bit across two independent runs
    assert "reproducible_result_sha256:" in text
    # the committed report must not leak the capturing machine
    assert "lutherleo" not in text and "/home/" not in text
