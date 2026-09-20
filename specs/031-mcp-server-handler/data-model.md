# Phase 1 Data Model: mcp handler

## Purpose

Enumerate every new type, its fields, its constraints, and its lifecycle. The vocabulary here is what the plan phase locks in for the reader contract, the tasks decomposition, and future reconciliation-style diffs.

## New types

### `McpServerConfig` (Pydantic model in `framework_schema.py`)

An allowlist entry declaring one MCP server darnit may spawn.

| Field | Type | Default | Constraint |
|-------|------|---------|------------|
| `command` | `list[str]` | required (no default) | Non-empty. First element is the executable name (resolved via PATH) or an absolute path; subsequent elements are argv. |
| `env` | `dict[str, str]` | `{}` | Values MAY contain `$VAR` placeholders. `$VAR` is resolved against darnit's parent `os.environ` at spawn time; unset variables substitute as empty string (matching `exec` handler behavior). |
| `trusted_publisher` | `str \| None` | `None` | When set, MUST be a GitHub identity URL (`https://github.com/<owner>` or `https://github.com/<owner>/<repo>`) or an OIDC identity string. Verified against a Sigstore sidecar (`<binary>.sigstore` or `<binary>.sigstore.json`) at spawn time; verification failure produces ERROR without spawning. |
| `optional` | `bool` | `True` | When `True`, absence of the binary produces INCONCLUSIVE. When `False`, absence produces FAIL. |
| `install_hint` | `str` | `""` | Free-form. Surfaces in the INCONCLUSIVE/FAIL message when the binary is missing. Recommend one line, imperative form (`Install with: brew install scorecard-mcp`). |

Merge precedence: `.baseline.toml` block wins over framework TOML block of the same name (spec FR-016).

### `FrameworkConfig.mcp_servers` (new field on existing model)

```python
mcp_servers: dict[str, McpServerConfig] = Field(default_factory=dict)
```

Key is the operator-chosen server name (referenced by controls as `server = "<name>"`). Empty dict is the pre-feature default; any framework or `.baseline.toml` without an `[mcp_servers]` section behaves identically to before this feature.

### `PooledSession` (runtime dataclass in `mcp_pool.py`)

```python
@dataclass
class PooledSession:
    server_name: str
    config: McpServerConfig
    session: ClientSession | None       # None while broken
    trust_label: Literal["sigstore-verified", "operator-trusted-path"]
    spawn_ts: datetime
    broken: bool = False
```

Lifecycle: `FRESH` → `USED` on first call → `TEARDOWN` on audit end. Any call that raises (crash, timeout, MCP-level error other than tool-side isError) transitions to `BROKEN`; a subsequent reference to the same server name triggers exactly one respawn attempt. A double-broken session produces INCONCLUSIVE/FAIL without further respawn attempts, per FR-012.

Pool holds one `PooledSession` per server name. Uniqueness by `server_name` within the pool's audit run.

### `McpInvocationRecord` (evidence-dict shape)

Not a distinct type in code — this is the shape darnit writes into a control's evidence dict per invocation, mirrored here so the reader contract and future maintainers can point at one definition.

```python
{
    "server": "scorecard",
    "tool": "get_repo_score",
    "args_after_substitution": {"repo_url": "github.com/octo/hello"},
    "raw_response": {"score": 8.5, "date": "2026-08-01", ...},  # or omitted if error
    "error": "tool raise_error: reason 'x'",                      # or omitted if success
    "trust_label": "sigstore-verified",  # or "operator-trusted-path"
    "elapsed_ms": 812,
}
```

## Existing types touched

### `SieveOrchestrator` (in `orchestrator.py`)

Add:

```python
self._mcp_pool: dict[str, PooledSession] = {}   # cleared in reset_caches()
```

Modify `reset_caches()`:

```python
def reset_caches(self) -> None:
    self._shared_cache.clear()
    self._dependency_results.clear()
    self._mcp_pool.clear()  # NEW
```

Modify `verify_batch()` to wrap its per-control loop in a `try/finally` that tears down all live pool sessions before returning.

Modify `_dispatch_handler_invocations` (or the equivalent dispatch site inside `verify_batch`) to emit `f"[{idx}/{total}] {control_spec.control_id} dispatching_mcp {invocation.server}.{invocation.tool}"` on the `darnit.harness` logger at INFO level **before** invoking a handler where `invocation.handler == "mcp"`. The counter `(idx, total)` is threaded from `verify_batch`'s enumeration loop. The handler function itself stays log-free at its dispatch site because a caller-observed side effect belongs to the caller (matches feature 026's `dispatching_llm` pattern; see spec FR-019).

### `HandlerContext` (in `handler_registry.py`)

Add:

```python
mcp_pool: McpPool | None = None   # assigned by the orchestrator's
                                   # dispatch site alongside shared_cache
                                   # and dependency_results when the
                                   # invocation is an mcp handler; None
                                   # for every other handler kind.
```

Handler function reads `context.mcp_pool` to obtain the pool. A `None` value at handler-invocation time indicates a plumbing bug and MUST resolve the pass ERROR rather than crash. Default value preserves every existing call site.

No signature changes on any public callable.

## Constants introduced

- `MCP_DEFAULT_TIMEOUT_SECONDS = 60` in `builtin_handlers.py`, referenced by `mcp_handler`.
- `MCP_ENV_SAFE_KEYS = ("PATH", "HOME", "LANG", "SSL_CERT_FILE")` and `MCP_ENV_SAFE_PREFIXES = ("LC_", "XDG_")` in `mcp_pool.py`, referenced by the spawn helper.
- `MCP_PROGRESS_VERB = "dispatching_mcp"` in `mcp_pool.py` (or the handler module), referenced by the progress-log line.

## Trust-label state machine

```
                 sigstore verify passes            spawn succeeds
      ---[trusted_publisher set]---> [SIGSTORE-VERIFIED] -----------> PooledSession
     /
[McpServerConfig]                                                            
     \                                                              spawn succeeds
      ---[trusted_publisher unset]---> [OPERATOR-TRUSTED-PATH] ---------> PooledSession
```

`sigstore verify fails` → no spawn, no session, ERROR on all controls that would use this server for the current audit.

`binary absent + optional=true` → INCONCLUSIVE.
`binary absent + optional=false` → FAIL.

The trust label is opaque to authority resolution — both paths produce `dispositive` results (spec FR-010; observation-based). The label appears only in the evidence record for auditors and downstream attestation.

## Non-model concerns

Everything else about this feature (CEL binding, arg substitution, timeout enforcement) reuses machinery that already exists in the sieve. No new pydantic models, no new dataclasses, no schema migrations beyond the two additions above.
