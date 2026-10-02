"""Per-project container shell (Layer 2). Run-model = the ``amber`` CLI.

Each research project gets its own container; the experiment + ``amber capture``
run **inside** it (Linux -> witness's eBPF/`/proc` collectors work, which they
cannot on a Windows/macOS host). This mirrors ``packaging/container/entrypoint.sh``:
the container's job is to run the amber CLI, nothing more.

Layer 1 does not exercise this module; it is the seam Layer 2 fills. Functions
shell out to ``docker`` and fail with a clear message when Docker is unavailable,
so nothing here silently pretends a run happened.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

# A minimal image whose entrypoint model is the amber CLI. Mirrors
# packaging/container/Dockerfile's stance (venv + non-root) but adds witness.
DEFAULT_DOCKERFILE = """\
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates \\
    && rm -rf /var/lib/apt/lists/*
# witness (in-toto) — the capture backend amber wraps.
ARG WITNESS_VERSION=0.12.0
RUN curl -sSfL https://github.com/in-toto/witness/releases/download/v${WITNESS_VERSION}/witness_${WITNESS_VERSION}_linux_amd64.tar.gz \\
    | tar -xz -C /usr/local/bin witness
RUN pip install --no-cache-dir darnit-reproducibility
WORKDIR /work
ENTRYPOINT ["amber"]
CMD ["--help"]
"""


class DockerUnavailable(RuntimeError):
    """Docker is not installed or not reachable."""


def _require_docker() -> str:
    docker = shutil.which("docker")
    if not docker:
        raise DockerUnavailable("docker not found on PATH; the per-project container needs Docker")
    return docker


def build_default_image(
    tag: str,
    build_dir: str | Path,
    *,
    dockerfile: str | None = None,
    build_args: dict[str, str] | None = None,
) -> str:
    """Write a Dockerfile into ``build_dir`` and build the image. Returns the image tag.

    ``dockerfile`` overrides :data:`DEFAULT_DOCKERFILE` (e.g. a project that needs a
    language toolchain or a vendored ``witness`` binary ``COPY``'d from the build
    context instead of downloaded). ``build_args`` are passed as ``--build-arg``.
    When ``dockerfile`` is given, the caller is responsible for placing any files it
    ``COPY``s into ``build_dir`` first.
    """
    docker = _require_docker()
    build_dir = Path(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    (build_dir / "Dockerfile").write_text(dockerfile or DEFAULT_DOCKERFILE, encoding="utf-8")
    argv = [docker, "build", "-t", tag]
    for k, v in (build_args or {}).items():
        argv += ["--build-arg", f"{k}={v}"]
    argv += [str(build_dir)]
    subprocess.run(argv, check=True)
    return tag


def run_capture_in_container(
    image: str,
    workspace: str | Path,
    experiment_cmd: list[str],
    *,
    step: str = "run",
    bundle_name: str = "bundle.json",
    capture_args: list[str] | None = None,
    docker_args: list[str] | None = None,
) -> Path:
    """Run ``amber capture -- <experiment_cmd>`` inside the project container.

    The workspace is bind-mounted at ``/work``; the signed bundle lands there. The
    container's run-model is exactly the amber CLI, so host and container behave the
    same. Returns the host path to the produced bundle.

    ``capture_args`` are extra flags for ``amber capture`` (e.g. ``["--no-ebpf"]`` so
    the capture does not need a privileged container). ``docker_args`` are extra
    ``docker run`` flags (e.g. extra ``-v`` mounts or ``--network``).
    """
    docker = _require_docker()
    ws = Path(workspace).resolve()
    ws.mkdir(parents=True, exist_ok=True)
    # as_posix() so a Windows source (C:\...) is written C:/... — the form Docker
    # Desktop accepts in a -v spec regardless of host shell.
    argv = [
        docker, "run", "--rm",
        "-v", f"{ws.as_posix()}:/work",
        *(docker_args or []),
        image,
        "capture", "--step", step, "-o", f"/work/{bundle_name}",
        *(capture_args or []),
        "--",
        *experiment_cmd,
    ]
    subprocess.run(argv, check=True)
    return ws / bundle_name
