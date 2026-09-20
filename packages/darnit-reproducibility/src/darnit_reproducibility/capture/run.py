"""Amber capture harness: wrap a command with ``witness run`` + the introspective Python attestor.

Produces a signed in-toto **collection** bundle capturing, for one command execution:

- **system info**      — Witness ``environment`` attestor (OS, hostname, user, env vars)
- **folder stasis**    — Witness ``material`` (digests before) + ``product`` (changed/created after)
- **repo connection**  — Witness ``git`` attestor + our python-env attestor's first-party linkage
- **python objects**   — our ``pyprobe`` attestor (loaded modules + hashes, first/third-party), auto
                         -injected via a ``sitecustomize`` shim on ``PYTHONPATH`` (no edit to the code)
- **eBPF kernel trace**— Witness experimental ``network-trace`` attestor + ``--trace`` process trace

The eBPF attestors need CAP_BPF, so by default the harness re-invokes ``witness`` under ``sudo``
(preserving the capture env). ``--no-ebpf`` drops the experimental attestors and runs unprivileged.

CLI:
    python -m darnit_reproducibility.capture.run --step demo -o bundle.json -- python experiment.py
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Confirmed against witness v0.12.0 (`witness attestors list -e`). `material`, `product`,
# `command-run` are always-run and need not be listed. `network-trace` is experimental.
_BASE_ATTESTORS = ["environment", "git", "lockfiles"]
_EBPF_ATTESTORS = ["network-trace"]


def _find_witness(explicit: str | None) -> str:
    """Locate the witness binary: explicit path, then PATH, then ~/.local/bin."""
    if explicit:
        return explicit
    found = shutil.which("witness")
    if found:
        return found
    fallback = Path.home() / ".local" / "bin" / "witness"
    if fallback.is_file():
        return str(fallback)
    raise FileNotFoundError(
        "witness binary not found (install it, or pass --witness /path/to/witness)."
    )


def _shim_dir(dest: Path) -> Path:
    """Materialize the transparent-capture shim: ``sitecustomize.py`` (auto-run at interpreter
    startup) + a bare-importable ``pyprobe.py``, both copied from this package."""
    here = Path(__file__).resolve().parent
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(here / "_sitecustomize.py", dest / "sitecustomize.py")
    shutil.copy2(here / "pyprobe.py", dest / "pyprobe.py")
    return dest


# Sigstore public-good keyless signing (works unattended in CI via the provider's OIDC token; opens a
# browser interactively). Verifiable by witness_attestation._verify_bundle against the OIDC identity.
_FULCIO_FLAGS = [
    "--signer-fulcio-url", "https://fulcio.sigstore.dev",
    "--signer-fulcio-oidc-issuer", "https://oauth2.sigstore.dev/auth",
    "--signer-fulcio-oidc-client-id", "sigstore",
]


def _ensure_signer(args: argparse.Namespace, workdir: Path) -> list[str]:
    """Return witness signer flags: explicit flags win; ``--sign`` selects Sigstore keyless; otherwise
    mint an ephemeral ed25519 file key so a local capture signs without Fulcio/OIDC. (Local bundles are
    parsed by digest downstream; the signature is only needed to *verify* provenance.)"""
    if args.signer_flags:
        return list(args.signer_flags)
    if getattr(args, "sign", False):
        return list(_FULCIO_FLAGS)
    key = workdir / "amber-ephemeral-key.pem"
    if not key.exists():
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-outform", "PEM", "-out", str(key)],
            check=True, capture_output=True,
        )
    return ["-k", str(key)]


def build_command(args: argparse.Namespace, shim: Path, pylibs_out: Path,
                  repo_root: Path, witness: str, signer: list[str]) -> tuple[list[str], dict[str, str]]:
    """Assemble the (argv, env) for the capture. Pure — unit-testable without running anything."""
    attestors = list(_BASE_ATTESTORS)
    if not args.no_ebpf:
        attestors += _EBPF_ATTESTORS

    witness_argv = [witness, "run", "--step", args.step, "-o", str(args.outfile)]
    if not args.no_ebpf:
        witness_argv += ["--experimental", "--trace"]
    for a in attestors:
        witness_argv += ["-a", a]
    witness_argv += signer
    witness_argv += ["--", *args.command]

    # The capture env the traced interpreter must see (the shim + where to write python-env).
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(shim), *filter(None, [env.get("PYTHONPATH")])])
    env["AMBER_PYLIBS_OUT"] = str(pylibs_out)
    env["AMBER_REPO_ROOT"] = str(repo_root)
    env["AMBER_SHIM_DIR"] = str(shim)

    if args.no_ebpf:
        return witness_argv, env
    # eBPF attestors need root; preserve the capture env explicitly through sudo.
    keep = ("PYTHONPATH", "AMBER_PYLIBS_OUT", "AMBER_REPO_ROOT", "AMBER_SHIM_DIR")
    sudo_argv = ["sudo", "env", *(f"{k}={env[k]}" for k in keep), *witness_argv]
    return sudo_argv, env


def run(args: argparse.Namespace) -> int:
    witness = _find_witness(args.witness)
    repo_root = Path(args.repo_root).resolve() if args.repo_root else Path.cwd()
    workdir = Path(args.outfile).resolve().parent
    pylibs_out = workdir / "amber-pylibs.json"

    with tempfile.TemporaryDirectory(prefix="amber_shim_") as tmp:
        shim = _shim_dir(Path(tmp))
        signer = _ensure_signer(args, workdir)
        argv, env = build_command(args, shim, pylibs_out, repo_root, witness, signer)
        print("amber capture:", " ".join(argv), file=sys.stderr)
        proc = subprocess.run(argv, env=env)

    ok_bundle = Path(args.outfile).is_file()
    ok_pylibs = pylibs_out.is_file()
    print(f"amber capture: exit={proc.returncode} bundle={'ok' if ok_bundle else 'MISSING'} "
          f"pylibs={'ok' if ok_pylibs else 'MISSING'}", file=sys.stderr)
    if ok_bundle:
        print(str(args.outfile))
    return proc.returncode


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="amber-capture",
        description="Capture a command's provenance with witness + the python-env attestor.",
    )
    p.add_argument("--step", default="amber-capture", help="witness step name")
    p.add_argument("-o", "--outfile", default="bundle.json", help="output signed bundle path")
    p.add_argument("--repo-root", default=None, help="first-party boundary (default: cwd)")
    p.add_argument("--witness", default=None, help="path to the witness binary")
    p.add_argument("--no-ebpf", action="store_true",
                   help="drop experimental eBPF attestors and run unprivileged (no sudo)")
    p.add_argument("--sign", action="store_true",
                   help="sign keyless via Sigstore/Fulcio (CI OIDC) instead of an ephemeral key")
    p.add_argument("--signer-flags", nargs=argparse.REMAINDER, default=None,
                   help="explicit witness signer flags (default: mint an ephemeral ed25519 key)")
    p.add_argument("command", nargs=argparse.REMAINDER,
                   help="the command to run, after `--`")
    args = p.parse_args(argv)

    if not args.command:
        p.error("no command given; put it after `--`, e.g. `-- python experiment.py`")
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
