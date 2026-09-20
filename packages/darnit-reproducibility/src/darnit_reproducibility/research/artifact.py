"""Portable amber research artifact: pack a locked project so future work can build on it.

An artifact is a ``.tar.gz`` of the project workspace plus a top-level
``manifest.json`` describing the paper, claims, verdict summary and contents. A new
project seeds itself from one via ``amber research begin --from <artifact>`` (which
unpacks it into a fresh workspace).
"""
from __future__ import annotations

import json
import tarfile
import time
from pathlib import Path
from typing import Any

from .graph import ResearchGraph
from .run import DEFAULT_ROOT, load_manifest, workspace_dir


def _verdict_summary(graph: ResearchGraph) -> list[dict[str, Any]]:
    return [
        {"kind": v.get("kind"), "level": v.get("level"), "metric": v.get("metric"),
         "summary": v.get("summary")}
        for v in graph.nodes("Verdict")
    ]


def pack(project: str, out_path: str | Path, *, root: str | Path = DEFAULT_ROOT) -> Path:
    """Pack a project workspace into a portable artifact tarball."""
    ws = workspace_dir(project, root)
    if not ws.exists():
        raise FileNotFoundError(f"no such project workspace: {ws}")
    graph_path = ws / "graph-research.json"
    graph = ResearchGraph.load(graph_path) if graph_path.exists() else ResearchGraph(project)

    manifest = {
        "artifact_version": 1,
        "project": project,
        "packed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_manifest": load_manifest(project, root),
        "verdicts": _verdict_summary(graph),
        "graph_meta": graph.to_dict()["meta"],
    }

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Write the artifact manifest into the workspace so it travels inside the tar too.
    (ws / "amber-artifact.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with tarfile.open(out_path, "w:gz") as tar:
        tar.add(ws, arcname=project)
    return out_path


def read_manifest(artifact_path: str | Path) -> dict[str, Any]:
    """Read the artifact's manifest without fully unpacking it."""
    with tarfile.open(artifact_path, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("amber-artifact.json"):
                f = tar.extractfile(member)
                if f is not None:
                    return json.loads(f.read().decode("utf-8"))
    return {}


def unpack(artifact_path: str | Path, *, root: str | Path = DEFAULT_ROOT) -> Path:
    """Unpack a portable artifact into ``<root>/<project>/`` and return that path."""
    manifest = read_manifest(artifact_path)
    project = manifest.get("project")
    dest_root = Path(root)
    dest_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(artifact_path, "r:gz") as tar:
        _safe_extract(tar, dest_root)
        if not project:
            # Fall back to the single top-level dir in the archive.
            tops = {m.name.split("/", 1)[0] for m in tar.getmembers()}
            project = next(iter(tops)) if len(tops) == 1 else "imported"
    return dest_root / project


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract guarding against path traversal (no absolute paths, no ``..`` escapes)."""
    dest = dest.resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest)):
            raise ValueError(f"unsafe path in artifact: {member.name!r}")
    # members validated against dest above; `filter="data"` is the safe extractor
    # (drops absolute paths / traversal / special files) and future-proofs 3.14+.
    tar.extractall(dest, filter="data")  # noqa: S202
