# Fixture: large_repo_shallow

Generated (not checked in) directory of synthetic Python files used to exercise
the handler's shallow-mode behavior (>500 in-scope files after exclusions).

Generate via:

    uv run python tests/darnit_baseline/threat_model/fixtures/scripts/generate_large_repo.py

The script produces simple `def f<N>(): pass` stubs. Not meaningful as source
code — only the file count matters. Do not commit the generated files.
