# Contract: Opengrep Runner

The interface between the rest of the threat model pipeline and the `opengrep` (or `semgrep`) CLI binary. Lives in `opengrep_runner.py`.

## Public interface

```python
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

@dataclass(frozen=True)
class OpengrepResult:
    available: bool
    findings: list[dict[str, Any]]
    rule_errors: list[dict[str, Any]]
    degraded_reason: str | None
    binary_used: str | None            # "opengrep" | "semgrep" | None
    version: str | None                # captured from --version at detection time
    scan_duration_s: float | None

def run_opengrep(
    target: Path,
    rules_dir: Path,
    timeout_s: int = 120,
) -> OpengrepResult: ...
```

## Behavioral contract

### Detection

1. Check `shutil.which("opengrep")` first.
2. If missing, check `shutil.which("semgrep")`.
3. If both missing, return `OpengrepResult(available=False, findings=[], rule_errors=[], degraded_reason="opengrep/semgrep binary not installed", binary_used=None, version=None, scan_duration_s=None)` immediately. Do not attempt to invoke anything.

### Invocation

When a binary is found, invoke:

```python
subprocess.run(
    [
        binary,
        "scan",
        "--json",
        "--quiet",
        "--disable-version-check",
        "--metrics=off",
        "--timeout", "10",                # per-rule-per-file seconds
        "--timeout-threshold", "3",       # max timeouts per file before skipping
        "--config", str(rules_dir),
        str(target),
    ],
    capture_output=True,
    text=True,
    timeout=timeout_s,
    env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
)
```

The `--quiet`, `--disable-version-check`, and `--metrics=off` flags are **required**. They guarantee clean JSON on stdout and no network calls.

### Exit code handling

| Exit code | Meaning | Handler response |
|-----------|---------|------------------|
| 0 | Success, no findings, or findings present without `--error` flag | Parse stdout; still check `errors[]` |
| 1 | Findings present with `--error` (we don't set this flag) | Parse stdout; this case shouldn't arise in our invocation |
| 2 | Rule/input errors, fatal scan failure | `degraded_reason = "opengrep exit 2: <stderr[:500]>"`; return with empty findings |
| 7 | Invalid config file | `degraded_reason = "opengrep config error: <stderr>"`; return with empty findings |
| anything else | Unknown failure | `degraded_reason = f"opengrep exit {code}: <stderr[:500]>"`; return with empty findings |

### Stdout parsing

On a successful exit:
1. `json.loads(proc.stdout)` — if this raises, set `degraded_reason = f"malformed JSON from opengrep: {e}"` and return with empty findings.
2. Extract `findings = data.get("results", [])`.
3. Extract `rule_errors = data.get("errors", [])`.
4. **Always inspect `rule_errors` even on exit 0.** If non-empty, set `degraded_reason = f"{len(rule_errors)} rule schema errors; see logs"` and log each error via `darnit.core.logging` at WARN level. Still return the `findings` that were successfully produced.

This is the single most important invariant of this contract. Silently accepting exit 0 without checking `errors[]` is how broken rules go undetected.

### Timeout handling

When `subprocess.TimeoutExpired` fires:
- Kill the process (Python does this automatically after the exception)
- Return `OpengrepResult(available=True, ..., degraded_reason=f"opengrep timed out after {timeout_s}s", ...)`
- Do not retry.

### Rule directory resolution

The caller (the handler) resolves the rule directory via `importlib.resources`:

```python
from importlib.resources import files, as_file

with as_file(files("darnit_baseline.threat_model").joinpath("opengrep_rules")) as rules_path:
    result = run_opengrep(target=repo_root, rules_dir=rules_path)
```

This handles both editable installs (where files are on disk) and zipped wheels (where `as_file` materializes them to a temp directory for the duration of the `with` block).

## Finding shape (normalized from Opengrep JSON)

Each entry in `OpengrepResult.findings` is the raw dict from Opengrep's `results[]` array. Downstream code in `discovery.py` is responsible for mapping these into `CandidateFinding` objects. The runner does not transform the shape.

Relevant fields the runner consumer depends on:
- `check_id` → becomes `CandidateFinding.query_id`
- `path` → file portion of `Location`
- `start.line`, `start.col`, `end.line`, `end.col` → `Location`
- `extra.message` → can seed `CandidateFinding.title`
- `extra.severity` → mapped to `CandidateFinding.severity`
- `extra.metadata` → rule-declared category, used for STRIDE mapping
- `extra.dataflow_trace` (taint mode only) → becomes `DataFlowTrace`

## What this contract is NOT

- The runner is **not** responsible for STRIDE categorization. It returns raw Opengrep findings.
- The runner is **not** responsible for ranking or capping findings. That is `ranking.py`'s job downstream.
- The runner does **not** write any files. It is a pure function (modulo subprocess state).
- The runner does **not** retry or cache. Every call is a fresh subprocess invocation.

## Failure-mode examples

| Situation | `available` | `findings` | `rule_errors` | `degraded_reason` |
|-----------|-------------|------------|---------------|-------------------|
| Binary not installed | `False` | `[]` | `[]` | `"opengrep/semgrep binary not installed"` |
| Binary installed, all rules OK, 5 findings | `True` | `[...5 entries...]` | `[]` | `None` |
| Binary installed, 1 broken rule, still produced 3 findings from other rules | `True` | `[...3 entries...]` | `[{...schema error...}]` | `"1 rule schema errors; see logs"` |
| Subprocess timeout | `True` | `[]` | `[]` | `"opengrep timed out after 120s"` |
| Rules dir missing | `True` | `[]` | `[]` | `"opengrep config error: ..."` |
| Malformed JSON on stdout | `True` | `[]` | `[]` | `"malformed JSON from opengrep: ..."` |
