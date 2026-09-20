"""``amber`` — the Amber capture/verify command line (part of darnit-reproducibility).

A single entry point over the capture → ingest → generate → verify pipeline. Each subcommand delegates
to its module's ``main`` so the CLI stays a thin dispatcher:

    amber capture  --step run -o bundle.json -- python experiment.py   # run + capture provenance
    amber ingest   bundle.json                                         # normalized capture report
    amber generate bundle.json --target docker --out-dir env/          # reproducible environment
    amber verify   original.json reproduction.json                     # reproducibility verdict

(darnit's core CLI has no plugin-subcommand hook and the framework must not import implementations, so
Amber ships its own ``amber`` script rather than a ``darnit repro`` subcommand.)
"""
from __future__ import annotations

import sys

_USAGE = """amber — reproducible-research provenance capture

usage: amber <command> [options]

commands:
  capture     run a command and capture its provenance (witness + python-env attestor)
  ingest      parse a capture bundle and print the capture report
  generate    generate a reproducible environment (Dockerfile / requirements) from a capture
  verify      compare two captures and print a reproducibility verdict
  sbom        emit a CycloneDX SBOM of the used distributions
  vulns       cross-check the used dependencies against OSV.dev
  provenance  detect locally-patched (vs stock PyPI) library builds
  eval        score capture completeness against ground truth (dev/CI)

run `amber <command> -h` for command options.
"""


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(_USAGE)
        return 0 if argv[:1] in (["-h"], ["--help"], ["help"]) else 2

    cmd, rest = argv[0], argv[1:]
    if cmd == "capture":
        from .capture.run import main as run
        return run(rest)
    if cmd == "ingest":
        from .ingest.witness import main as run
        return run(rest)
    if cmd == "generate":
        from .generate.environment import main as run
        return run(rest)
    if cmd == "verify":
        from .analysis.compare import main as run
        return run(rest)
    if cmd == "sbom":
        from .analysis.sbom import main as run
        return run(rest)
    if cmd == "vulns":
        from .analysis.vuln import main as run
        return run(rest)
    if cmd == "provenance":
        from .analysis.provenance import main as run
        return run(rest)
    if cmd == "eval":
        from .evaluation import main as run
        return run(rest)

    sys.stderr.write(f"amber: unknown command {cmd!r}\n\n{_USAGE}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
