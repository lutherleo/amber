# Quickstart: Developing & Verifying the Threat Model Rewrite

This is a short developer runbook for working on the threat model rewrite in branch `010-threat-model-ast`.

## Prerequisites

```bash
# Development deps (already in the workspace)
uv sync --all-extras

# Optional but required for full test coverage: Opengrep
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
# Or: skip this and run tests without the opengrep integration paths
which opengrep || which semgrep
```

## Dependency additions to `packages/darnit-baseline/pyproject.toml`

```toml
[project]
dependencies = [
    "darnit>=0.1.0",
    "tree-sitter>=0.25",
    "tree-sitter-language-pack>=1.5",
]

[tool.hatch.build.targets.wheel.force-include]
"templates" = "darnit_baseline/templates"
"src/darnit_baseline/threat_model/opengrep_rules" = "darnit_baseline/threat_model/opengrep_rules"
```

Run `uv sync` after editing `pyproject.toml`.

## Sanity-check tree-sitter integration

```python
# Minimal smoke test — run from repo root with `uv run python`
import tree_sitter as ts
from tree_sitter_language_pack import get_language, get_parser

src = b'''
@app.get("/users/{id}")
def get_user(id: int):
    return db.fetch(id)
'''

parser = get_parser("python")
tree = parser.parse(src)

query = ts.Query(get_language("python"), """
(decorated_definition
  (decorator
    (call
      function: (attribute
        object: (identifier) @app
        attribute: (identifier) @method)))
  definition: (function_definition
    name: (identifier) @func_name))
""")

cursor = ts.QueryCursor(query)
for _idx, caps in cursor.matches(tree.root_node):
    print(f"{caps['app'][0].text.decode()}.{caps['method'][0].text.decode()} -> {caps['func_name'][0].text.decode()}")
# Expected: app.get -> get_user
```

If this prints `app.get -> get_user`, tree-sitter is wired up correctly.

## Running the handler locally

Once `discovery.py`, `parsing.py`, and the supporting modules are in place:

```python
# From repo root
from pathlib import Path
from darnit.sieve.handler_registry import HandlerContext
from darnit_baseline.threat_model.remediation import generate_threat_model_handler

ctx = HandlerContext(
    owner="kusari-oss",
    repo="darnit",
    local_path=str(Path.cwd()),
    project_context={},
    gathered_evidence={},
    control_id="OSPS-SA-03.02",
    logger=None,  # uses get_logger internally
)

config = {
    "path": "THREAT_MODEL.md",
    "overwrite": True,  # so repeated runs overwrite
    "max_findings": 50,
}

result = generate_threat_model_handler(config, ctx)
print(result.status, result.message)
print(result.evidence["file_scan_stats"])
print(result.evidence.get("trimmed_overflow"))
```

## Running the full compliance flow (dogfood)

This is the end-to-end verification path the spec's SC-001 depends on:

```bash
# Ensure the MCP server is running the latest code — kill stale darnit processes
ps aux | grep 'darnit serve' | grep -v grep
# Kill any stale pids manually, then restart via the normal serve path.
```

Inside a Claude Code session (or any MCP client):

```text
Call audit_openssf_baseline(local_path="<repo-root>")
  → observe OSPS-SA-03.02 status (expect FAIL before any threat model exists)

Call remediate_audit_findings(local_path="<repo-root>", dry_run=true)
  → confirm the dry-run plan lists OSPS-SA-03.02 under "Would apply"

Call remediate_audit_findings(local_path="<repo-root>", dry_run=false, auto_commit=true)
  → expect THREAT_MODEL.md to be written
  → inspect evidence: file_scan_stats, trimmed_overflow, opengrep_available

Open THREAT_MODEL.md
  → verify all 9 required sections are present (see contracts/output-format-contract.md)
  → verify no phantom postgresql finding from gpg.ssh.allowedSignersFile
  → verify no PII finding from email=data.get("email", "") in metadata parsing
  → verify real findings: subprocess calls in sieve handlers, MCP tool decorators

Call audit_openssf_baseline(local_path="<repo-root>")
  → observe OSPS-SA-03.02 status (expect PASS now)
```

## Running the new test suite

```bash
# Unit tests for parsing and queries
uv run pytest tests/darnit_baseline/threat_model/test_parsing.py -v

# File walk and exclusion tests
uv run pytest tests/darnit_baseline/threat_model/test_file_discovery.py -v

# Discovery end-to-end on fixture repos
uv run pytest tests/darnit_baseline/threat_model/test_discovery.py -v

# Opengrep runner with mocked subprocess
uv run pytest tests/darnit_baseline/threat_model/test_opengrep_runner.py -v

# Ranking + cap + overflow accounting
uv run pytest tests/darnit_baseline/threat_model/test_ranking.py -v

# Handler contract preservation
uv run pytest tests/darnit_baseline/threat_model/test_handler.py -v

# Markdown/SARIF/JSON output shape
uv run pytest tests/darnit_baseline/threat_model/test_generators.py -v

# All threat_model tests
uv run pytest tests/darnit_baseline/threat_model/ -v
```

## Regression tests for known false positives

The false-positive fixtures live under `tests/darnit_baseline/threat_model/fixtures/red_herrings/`. Each test case is one file + one assertion that nothing was discovered in it.

```bash
uv run pytest tests/darnit_baseline/threat_model/test_discovery.py::test_red_herrings -v
```

Expected: no findings from any red-herring file.

## Shallow-mode verification

The `large_repo_shallow/` fixture is generated by a script (not checked in) to avoid bloating the repo:

```bash
uv run python tests/darnit_baseline/threat_model/fixtures/scripts/generate_large_repo.py
uv run pytest tests/darnit_baseline/threat_model/test_discovery.py::test_shallow_mode -v
```

Expected:
- `file_scan_stats["shallow_mode"] == True`
- `file_scan_stats["in_scope_files"] > 500`
- Draft contains `## Limitations` mentioning shallow mode
- Draft does NOT contain `## Attack Chains` (or contains it with a "skipped in shallow mode" note)

## Opengrep-absent verification

```bash
# Temporarily hide opengrep/semgrep from PATH
env PATH="/usr/bin:/bin" uv run pytest tests/darnit_baseline/threat_model/test_handler.py::test_degrades_when_opengrep_absent -v
```

Expected: handler still returns PASS, `evidence["opengrep_available"] == False`, draft Limitations section mentions the degradation.

## Lint & spec sync

```bash
uv run ruff check .
uv run python scripts/validate_sync.py --verbose
uv run python scripts/generate_docs.py && git diff docs/generated/
```

All must pass before commit.

## Manual QA procedures (for subjective success criteria)

Two success criteria require human judgment and cannot be fully automated. These procedures exist so the verification evidence is reproducible across sessions.

### SC-003: Finding-to-code correspondence spot check

After generating a draft against a real repository:

1. Enumerate all findings across all STRIDE categories in the draft.
2. Randomly select 10 findings (use `random.sample(findings, 10)` or equivalent).
3. For each selected finding, open the referenced file at the referenced line number.
4. Ask: "Does the code at this location plausibly exhibit the threat the finding describes?"
5. Record pass/fail per finding with a one-sentence justification.
6. SC-003 is satisfied when all 10 spot-checks pass.

### SC-008: False-positive stripping measurement

After running the full `/darnit-comply` skill:

1. Count the findings Claude removes or marks as false positives during the verification pass.
2. Compare against the count from a pre-rewrite run against the same repository (recorded in the PR description or a prior commit message).
3. SC-008 is satisfied when the new-pipeline count is strictly less than the old-pipeline count.

If no pre-rewrite baseline exists for the target repository, record the new-pipeline number as the baseline for future comparisons and note in the PR that the criterion is informational-only for this run.

## Commit gates

Before any commit on this branch:

1. `uv run ruff check .` — zero errors
2. `uv run pytest tests/ --ignore=tests/integration/ -q` — all pass
3. `uv run python scripts/validate_sync.py --verbose` — spec-sync check passes
4. Dogfood check: run the full audit→remediate→audit flow against darnit itself and confirm the generated `THREAT_MODEL.md` is free of the known false positives (SC-001) and contains the known true positives
5. Rebase from upstream: `git fetch upstream && git rebase upstream/main`
