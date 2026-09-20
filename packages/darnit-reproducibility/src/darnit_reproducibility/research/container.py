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


def build_default_image(tag: str, build_dir: str | Path) -> str:
    """Write the default Dockerfile and build the image. Returns the image tag."""
    docker = _require_docker()
    build_dir = Path(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    (build_dir / "Dockerfile").write_text(DEFAULT_DOCKERFILE, encoding="utf-8")
    subprocess.run([docker, "build", "-t", tag, str(build_dir)], check=True)
    return tag


def run_capture_in_container(
    image: str,
    workspace: str | Path,
    experiment_cmd: list[str],
    *,
    step: str = "run",
    bundle_name: str = "bundle.json",
) -> Path:
    """Run ``amber capture -- <experiment_cmd>`` inside the project container.

    The workspace is bind-mounted at ``/work``; the signed bundle lands there. The
    container's run-model is exactly the amber CLI, so host and container behave the
    same. Returns the host path to the produced bundle.
    """
    docker = _require_docker()
    ws = Path(workspace).resolve()
    ws.mkdir(parents=True, exist_ok=True)
    argv = [
        docker, "run", "--rm",
        "-v", f"{ws}:/work",
        image,
        "capture", "--step", step, "-o", f"/work/{bundle_name}", "--",
        *experiment_cmd,
    ]
    subprocess.run(argv, check=True)
    return ws / bundle_name
