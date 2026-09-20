"""Amber capture front-end: produce Witness/in-toto provenance for a traced run.

This subpackage is the *capture* half of Amber (the PDF's "Problem 1"): wrap a command with
`witness run` to record system info, folder state, the git repo, and (via Witness's eBPF
network-trace attestor) network activity, plus an introspective Python attestor that records the
library objects actually loaded and links them back to the source repo.

Modules:
- ``pyprobe``          — introspective Python-environment attestor (distributions + loaded modules
                         + hashes, first-party vs third-party, git-bound). Emits a self-describing
                         ``python-env`` predicate JSON.
- ``_sitecustomize``   — a startup shim injected via ``PYTHONPATH`` so ``pyprobe`` runs at process
                         exit with no edit to the experiment (Amber's transparency goal).
- ``run``              — the ``witness run`` wrapper / CLI (added once the witness attestor set is
                         confirmed).
"""
