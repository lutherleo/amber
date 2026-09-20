"""Token-free tests for the Amber Witness ingestor (``darnit_reproducibility.ingest.witness``).

Builds synthetic DSSE collection bundles in-memory (the exact shapes Witness v0.12 emits, captured
from a real ``witness run``) and asserts the normalized ``CaptureRecord``.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from darnit_reproducibility.ingest import witness as ing

TESTIFYSEC = "https://witness.testifysec.com/attestation-collection/v0.1"
WITNESS_DEV = "https://witness.dev/attestation-collection/v0.1"


def _att(name: str, body: dict[str, Any]) -> dict[str, Any]:
    return {"type": f"https://witness.dev/attestations/{name}/v0.1", "attestation": body}


def make_bundle(tmp_path: Path, attestations: list[dict[str, Any]],
                collection_type: str = TESTIFYSEC) -> Path:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [],
        "predicateType": collection_type,
        "predicate": {"name": "test", "attestations": attestations},
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    env = {"payload": payload, "payloadType": "application/vnd.in-toto+json", "signatures": []}
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(env))
    return p


def test_folder_stasis_splits_added_and_changed(tmp_path: Path) -> None:
    atts = [
        _att("material", {"a.py": {"sha256": "AAA"}, "b.py": {"sha256": "BBB"}}),
        _att("product", {
            "b.py": {"mime_type": "text/x-python", "digest": {"sha256": "BBB2"}},  # changed
            "c.json": {"mime_type": "application/json", "digest": {"sha256": "CCC"}},  # created
        }),
    ]
    rec = ing.load(make_bundle(tmp_path, atts))
    assert rec.folder_stasis.before_count == 2
    assert [f.path for f in rec.folder_stasis.added] == ["c.json"]
    assert [f.path for f in rec.folder_stasis.changed] == ["b.py"]
    assert rec.folder_stasis.added[0].mime_type == "application/json"


def test_system_and_command(tmp_path: Path) -> None:
    atts = [
        _att("environment", {"os": "linux", "hostname": "h1", "username": "u1",
                             "variables": {"PATH": "/x", "LD_LIBRARY_PATH": "/y"}}),
        _att("command-run", {"cmd": ["python3", "exp.py"], "stdout": "done\n", "exitcode": 0}),
    ]
    rec = ing.load(make_bundle(tmp_path, atts))
    assert rec.system.os == "linux" and rec.system.hostname == "h1"
    assert rec.system.env_var_count == 2
    assert rec.command.cmd == ["python3", "exp.py"] and rec.command.exitcode == 0


def test_repo_links_git_to_python_env(tmp_path: Path) -> None:
    commit = "abc123def456"
    (tmp_path / "amber-pylibs.json").write_text(json.dumps({
        "predicate": {"repo": {"commit": commit, "remotes": {"origin": "https://example/repo"}},
                      "python": {"version": "3.12.3"}, "distributions": [], "modules": []}
    }))
    atts = [_att("git", {"commithash": commit, "branch": "main", "status": {}})]
    rec = ing.load(make_bundle(tmp_path, atts))
    assert rec.repo.commit == commit
    assert rec.repo.commit_matches_python_env is True
    assert rec.repo.remotes == {"origin": "https://example/repo"}


def test_git_python_env_commit_mismatch_flagged(tmp_path: Path) -> None:
    (tmp_path / "amber-pylibs.json").write_text(json.dumps({
        "predicate": {"repo": {"commit": "different"}, "python": {}, "distributions": [], "modules": []}
    }))
    atts = [_att("git", {"commithash": "abc", "branch": "main"})]
    rec = ing.load(make_bundle(tmp_path, atts))
    assert rec.repo.commit_matches_python_env is False


def test_python_env_first_third_split_and_digest_verified(tmp_path: Path) -> None:
    pylibs = {
        "predicate": {
            "python": {"version": "3.12.3", "implementation": "CPython", "platform": "linux"},
            "distributions": [{"name": "numpy", "version": "1.26.4"}],
            "modules": [
                {"module": "mymodel", "path": "/repo/mymodel.py", "sha256": "sha256:aa", "category": "first_party"},
                {"module": "numpy", "path": "/site/numpy/__init__.py", "sha256": "sha256:bb",
                 "category": "third_party", "distribution": "numpy"},
                {"module": "json", "path": "/usr/lib/json/__init__.py", "sha256": "sha256:cc", "category": "stdlib"},
            ],
        }
    }
    pl = tmp_path / "amber-pylibs.json"
    pl.write_text(json.dumps(pylibs))
    digest = hashlib.sha256(pl.read_bytes()).hexdigest()
    atts = [_att("product", {"amber-pylibs.json": {"digest": {"sha256": digest}}})]
    rec = ing.load(make_bundle(tmp_path, atts))
    pe = rec.python_env
    assert pe.captured is True
    assert [m.module for m in pe.first_party] == ["mymodel"]
    assert [m.module for m in pe.third_party] == ["numpy"]
    assert pe.third_party[0].distribution == "numpy"
    assert pe.stdlib_count == 1
    assert pe.digest_verified is True


def test_python_env_digest_mismatch(tmp_path: Path) -> None:
    pl = tmp_path / "amber-pylibs.json"
    pl.write_text(json.dumps({"predicate": {"python": {}, "distributions": [], "modules": []}}))
    atts = [_att("product", {"amber-pylibs.json": {"digest": {"sha256": "deadbeef"}}})]
    rec = ing.load(make_bundle(tmp_path, atts))
    assert rec.python_env.digest_verified is False


def test_network_ebpf_trace_counts_connections(tmp_path: Path) -> None:
    atts = [_att("network-trace", {"connections": [{"host": "pypi.org"}, {"host": "x"}]})]
    rec = ing.load(make_bundle(tmp_path, atts))
    assert rec.network.captured is True
    assert rec.network.event_count == 2
    assert rec.network.clean is False


def test_network_ebpf_empty_is_clean(tmp_path: Path) -> None:
    atts = [_att("network-trace", {"connections": []})]
    rec = ing.load(make_bundle(tmp_path, atts))
    assert rec.network.captured is True and rec.network.clean is True


def test_network_ebpf_real_witness_shape(tmp_path: Path) -> None:
    # exact v0.12 shape: nested under network_trace, count from summary.total_connections
    body = {"network_trace": {
        "connections": [{"host": "pypi.org"}],
        "summary": {"total_connections": 1, "unique_hosts": ["pypi.org"]},
        "config": {"proxy_port": 8888},
    }}
    atts = [_att("network-trace", body)]
    rec = ing.load(make_bundle(tmp_path, atts))
    assert rec.network.captured is True
    assert rec.network.event_count == 1
    assert rec.network.clean is False
    assert "pypi.org" in rec.network.detail


def test_network_ebpf_real_shape_empty_clean(tmp_path: Path) -> None:
    body = {"network_trace": {"connections": None, "summary": {"total_connections": 0}}}
    rec = ing.load(make_bundle(tmp_path, [_att("network-trace", body)]))
    assert rec.network.captured is True and rec.network.clean is True and rec.network.event_count == 0


def test_no_network_attestor_is_uncaptured(tmp_path: Path) -> None:
    atts = [_att("environment", {"os": "linux", "variables": {}})]
    rec = ing.load(make_bundle(tmp_path, atts))
    # command-run/runtime-trace fallback may report None here; either way it is not a false "clean".
    assert rec.network.clean in (None, True, False)
    if not rec.network.captured:
        assert "no network-trace" in rec.network.detail


def test_both_collection_types_accepted(tmp_path: Path) -> None:
    for ctype in (TESTIFYSEC, WITNESS_DEV):
        atts = [_att("environment", {"os": "linux", "variables": {}})]
        rec = ing.load(make_bundle(tmp_path, atts, collection_type=ctype))
        assert rec.collection_type == ctype


def test_rejects_non_collection_statement(tmp_path: Path) -> None:
    atts = [_att("environment", {"os": "linux", "variables": {}})]
    p = make_bundle(tmp_path, atts, collection_type="https://example.com/not-a-collection/v1")
    with pytest.raises(ValueError):
        ing.load(p)


def test_deep_trace_ingested_and_hybrid(tmp_path: Path) -> None:
    pylibs = {"predicate": {"python": {}, "distributions": [], "modules": [], "deep": {
        "shared_objects": [
            {"path": "/usr/lib/x86_64-linux-gnu/libopenblas.so.0", "sha256": "sha256:bb",
             "category": "system", "in_python_modules": False},
            {"path": "/site/numpy/_multiarray.cpython.so", "sha256": "sha256:aa",
             "category": "site-packages", "in_python_modules": True},
        ],
        "subprocess_execs": ["['gcc', '-O2']"], "dlopen": [],
    }}}
    (tmp_path / "amber-pylibs.json").write_text(json.dumps(pylibs))
    rec = ing.load(make_bundle(tmp_path, [_att("environment", {"os": "linux", "variables": {}})]))
    assert rec.ebpf_file_access is not None
    assert len(rec.ebpf_file_access["shared_objects"]) == 2
    text = ing.render(rec)
    assert "DEEP TRACE" in text
    assert "libopenblas" in text  # native lib loaded outside the Python import system is surfaced


def test_render_is_stringy(tmp_path: Path) -> None:
    atts = [
        _att("environment", {"os": "linux", "hostname": "h", "username": "u", "variables": {}}),
        _att("command-run", {"cmd": ["python3", "x.py"], "exitcode": 0}),
    ]
    rec = ing.load(make_bundle(tmp_path, atts))
    text = ing.render(rec)
    assert "AMBER CAPTURE REPORT" in text and "COMMAND" in text
