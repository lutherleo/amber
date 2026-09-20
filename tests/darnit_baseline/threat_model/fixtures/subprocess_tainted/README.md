# Fixture: subprocess_tainted

Python file containing a `subprocess.run(..., shell=True)` call whose command
argument is built from `request.query_params` — a real command-injection
pattern. Used by discovery tests to verify:

1. Tree-sitter alone produces a subprocess `CandidateFinding` at the call site.
2. Opengrep (when available) produces a taint finding with a data-flow trace
   from the request source to the subprocess sink.
