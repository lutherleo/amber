"""Normalized capture model — the single record the Witness ingestor produces from a bundle.

One ``CaptureRecord`` is Amber's answer to "what happened during this run": system info, folder
state before/after, the git repo it came from, the Python library objects it loaded (first-party vs
third-party), and the eBPF network trace. It is the hand-off point between capture (this package's
``capture/`` harness) and everything downstream (reporting now; analysis/generation later).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SystemInfo:
    os: str | None = None
    hostname: str | None = None
    username: str | None = None
    env_var_count: int = 0
    env_vars: dict[str, str] = field(default_factory=dict)


@dataclass
class FileDigest:
    path: str
    sha256: str | None = None
    mime_type: str | None = None


@dataclass
class FolderStasis:
    """Folder "stasis": the working-tree snapshot before the command (material) vs the files it
    created/changed (product). Witness product records only changed/created files, so removals are
    not observable here."""
    before_count: int = 0
    added: list[FileDigest] = field(default_factory=list)
    changed: list[FileDigest] = field(default_factory=list)


@dataclass
class PyModule:
    module: str
    path: str
    sha256: str | None = None
    category: str = "third_party"
    distribution: str | None = None


@dataclass
class PythonEnv:
    captured: bool = False
    version: str | None = None
    implementation: str | None = None
    platform: str | None = None
    distributions: list[dict[str, Any]] = field(default_factory=list)
    used_distributions: list[dict[str, Any]] = field(default_factory=list)
    first_party: list[PyModule] = field(default_factory=list)
    third_party: list[PyModule] = field(default_factory=list)
    stdlib_count: int = 0
    digest_verified: bool | None = None  # amber-pylibs.json hash == product attestor's digest?


@dataclass
class RepoInfo:
    detected: bool = False
    commit: str | None = None
    branch: str | None = None
    remotes: dict[str, str] = field(default_factory=dict)
    dirty: bool | None = None
    commit_matches_python_env: bool | None = None  # git attestor commit == python-env repo commit


@dataclass
class CommandRun:
    cmd: list[str] = field(default_factory=list)
    exitcode: int | None = None
    stdout_excerpt: str | None = None


@dataclass
class NetworkTrace:
    captured: bool = False
    clean: bool | None = None
    event_count: int = 0
    detail: str = ""


@dataclass
class CaptureRecord:
    collection_type: str | None = None
    attestor_types: list[str] = field(default_factory=list)
    system: SystemInfo = field(default_factory=SystemInfo)
    repo: RepoInfo = field(default_factory=RepoInfo)
    command: CommandRun = field(default_factory=CommandRun)
    folder_stasis: FolderStasis = field(default_factory=FolderStasis)
    python_env: PythonEnv = field(default_factory=PythonEnv)
    network: NetworkTrace = field(default_factory=NetworkTrace)
    # Hardware (cpu/simd, memory, gpu) and numerical settings (thread caps, hash seed, locale, tz,
    # BLAS) — the drivers of numerical non-reproducibility. Kept as dicts (shape in capture.pyprobe).
    hardware: dict[str, Any] | None = None
    numerical: dict[str, Any] | None = None
    # Typed placeholder for the deferred custom eBPF process/file tracer (hybrid python-capture):
    # once a runtime-trace file-access attestor lands, its normalized reads/writes go here and are
    # cross-checked against python_env. None = not captured in this bundle.
    ebpf_file_access: dict[str, Any] | None = None


# ── Track 1: reproducibility verdict (compare two captures) ────────────────────────────────────

@dataclass
class ArtifactComparison:
    name: str
    original_sha256: str | None
    reproduction_sha256: str | None
    match: bool
    semantic_match: bool | None = None  # digests differ but values are equal within tolerance


@dataclass
class VersionDrift:
    name: str
    original: str | None
    reproduction: str | None


@dataclass
class EnvDiff:
    python_version: tuple[str | None, str | None] = (None, None)
    platform: tuple[str | None, str | None] = (None, None)
    version_drift: list[VersionDrift] = field(default_factory=list)  # same dep, different version
    missing: list[str] = field(default_factory=list)                 # used originally, absent in repro
    added: list[str] = field(default_factory=list)                   # new in repro
    identical: bool = False


@dataclass
class ReproducibilityVerdict:
    """The outcome of comparing an original capture with a reproduction attempt.

    ``level`` is the headline: BIT_FOR_BIT (all outputs identical), REPRODUCED_WITH_DRIFT (outputs
    identical despite environment differences), NOT_REPRODUCED (outputs differ — ``discrepancies``
    ranks the likely causes), or INCONCLUSIVE (nothing comparable)."""
    level: str = "INCONCLUSIVE"
    bit_for_bit: bool = False
    reproduction_rate: float = 0.0
    artifacts: list[ArtifactComparison] = field(default_factory=list)
    env: EnvDiff = field(default_factory=EnvDiff)
    discrepancies: list[str] = field(default_factory=list)
    summary: str = ""


@dataclass
class GeneratedEnvironment:
    target: str                                  # "docker", "requirements", ...
    files: dict[str, str] = field(default_factory=dict)   # filename -> contents
    notes: list[str] = field(default_factory=list)
