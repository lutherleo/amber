"""Token-free tests for the make-sense layer: SBOM, OSV vuln check, custom-vs-distributed."""
from __future__ import annotations

from darnit_reproducibility.analysis import provenance, sbom, vuln
from darnit_reproducibility.models import CaptureRecord, PyModule, PythonEnv, RepoInfo


def _rec() -> CaptureRecord:
    return CaptureRecord(
        python_env=PythonEnv(
            captured=True, version="3.12.3",
            used_distributions=[{"name": "numpy", "version": "1.26.4"},
                                {"name": "scipy", "version": "1.13.1"}],
            third_party=[PyModule("numpy", "/x/site-packages/numpy/__init__.py",
                                  "sha256:GOOD", "third_party", "numpy")],
        ),
        repo=RepoInfo(detected=True, commit="abc123", remotes={"origin": "https://example/repo"}),
    )


# ── SBOM ───────────────────────────────────────────────────────────────────────

def test_sbom_components_and_purls() -> None:
    bom = sbom.to_cyclonedx(_rec())
    assert bom["bomFormat"] == "CycloneDX"
    names = {c["name"] for c in bom["components"]}
    assert {"numpy", "scipy"} <= names
    numpy = next(c for c in bom["components"] if c["name"] == "numpy")
    assert numpy["purl"] == "pkg:pypi/numpy@1.26.4"


# ── OSV vuln check ─────────────────────────────────────────────────────────────

def test_vuln_flags_vulnerable() -> None:
    def fake_post(url: str, body: dict) -> dict:
        results = [{"vulns": [{"id": "GHSA-xxxx"}]} if q["package"]["name"] == "scipy" else {}
                   for q in body["queries"]]
        return {"results": results}

    rep = vuln.report(_rec(), post=fake_post)
    assert rep["status"] == "vulnerable"
    assert rep["vulnerable"][0]["package"] == "scipy"
    assert "GHSA-xxxx" in rep["vulnerable"][0]["vuln_ids"]


def test_vuln_clean() -> None:
    rep = vuln.report(_rec(), post=lambda u, b: {"results": [{} for _ in b["queries"]]})
    assert rep["status"] == "clean"


def test_vuln_unknown_on_network_error() -> None:
    def boom(u: str, b: dict) -> dict:
        raise RuntimeError("network down")

    rep = vuln.report(_rec(), post=boom)
    assert rep["status"] == "unknown"


# ── custom-vs-distributed ──────────────────────────────────────────────────────

def test_provenance_stock_when_hashes_match() -> None:
    record = {"numpy/__init__.py": "sha256:GOOD"}
    rows = provenance.classify(_rec(), record_fetcher=lambda n, v: record)
    numpy = next(r for r in rows if r["distribution"] == "numpy")
    assert numpy["status"] == "stock" and numpy["checked"] == 1


def test_provenance_patched_when_hash_differs() -> None:
    record = {"numpy/__init__.py": "sha256:DIFFERENT"}
    rows = provenance.classify(_rec(), record_fetcher=lambda n, v: record)
    numpy = next(r for r in rows if r["distribution"] == "numpy")
    assert numpy["status"] == "patched"
    assert numpy["mismatched"] == ["numpy/__init__.py"]


def test_provenance_unknown_without_record() -> None:
    rows = provenance.classify(_rec(), record_fetcher=lambda n, v: None)
    numpy = next(r for r in rows if r["distribution"] == "numpy")
    assert numpy["status"] == "unknown"
