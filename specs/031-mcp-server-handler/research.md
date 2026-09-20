# Phase 0 Research: mcp handler for calling external MCP servers

## Decision 1: MCP client-side API surface

**Decision**: Use `mcp.client.stdio.stdio_client` + `mcp.ClientSession.call_tool` from the `mcp>=1.23,<2` package, wrapped behind a thin adapter in `packages/darnit/src/darnit/sieve/mcp_pool.py` so a future HTTP-transport follow-up can add a parallel adapter without touching the handler.

**Rationale**:
- The `mcp` package is already declared as a darnit-core runtime dep (from feature 025's `FastMCP` server-side use). Its client-side entry points ship in the same wheel and require no extra installation.
- `mcp.client.stdio.stdio_client(StdioServerParameters(command=[...], args=[...], env={...}))` returns an async context manager yielding `(read_stream, write_stream)`. `mcp.ClientSession(read_stream, write_stream)` wraps those into a session with `initialize()`, `list_tools()`, `call_tool(name, arguments)`, and `close()`. This is the documented, stable surface across all 1.x releases.
- `session.call_tool(name, arguments)` returns a `CallToolResult` object with `.content: list[TextContent | ImageContent | ...]` and `.isError: bool`. For v0, we require and consume text content whose payload is JSON-parseable (this matches how every current MCP server we care about, including Scorecard MCP's design, returns results).
- Isolating the adapter behind `mcp_pool.py` means the handler code sees an object with a `call_tool(name, args, *, timeout: float) -> dict[str, Any]` signature. That single-method interface is a natural seam for the HTTP-transport follow-up: a new adapter satisfies the same interface, and the pool picks it based on a future `transport = "http"` field.

**Alternatives considered**:
- **Direct JSON-RPC-over-pipes**: rejected. Reimplements what the SDK already does (framing, request/response correlation, initialization handshake) and reintroduces the maintenance burden the SDK exists to remove.
- **Subprocess + wait_for on `session.call_tool` in every handler call**: kept as the actual mechanism, but wrapped behind the pool's `call_tool` so timeout enforcement is centralized (matches spec FR-002 60s default).

## Decision 2: Pool lifecycle boundary

**Decision**: The pool is owned by `SieveOrchestrator` as `_mcp_pool: dict[str, PooledSession]`, cleared in the existing `reset_caches()` method, and torn down in a `try/finally` around `verify_batch()`'s per-control loop so any exit path (success, failure, exception, external interrupt) tears down before the method returns.

**Rationale**:
- The orchestrator already owns two audit-run-scoped caches (`_shared_cache`, `_dependency_results`) with the exact same lifetime as an MCP server pool. Reusing the same lifecycle hook is the shortest correct path.
- `verify_batch()` is the single entry point for a full audit run — every consumer of the sieve (agent graph, `HarnessRun` driver, MCP tool wrapper `audit_openssf_baseline`, CLI `cmd_run`) calls into `verify_batch()`. Adding teardown there covers every caller.
- `try/finally` around the per-control loop guarantees teardown fires on the exception path too (spec FR-013, no orphaned subprocesses).
- Broken sessions are invalidated at their per-call catch site; the next reference to the same server sees `broken=True` and triggers exactly one respawn (spec FR-012). A double-broken session goes to a permanent "unusable this audit" state without further respawn.

**Alternatives considered**:
- **Audit-level context-manager wrapping the whole run**: rejected. Requires threading a new lifetime object through every `verify_batch()` caller (four call sites). The orchestrator-owned pool needs zero external plumbing.
- **Per-control pool (spawn/teardown per call)**: rejected — spec FR-011 explicitly requires spawn-lazy-per-audit with reuse.

## Decision 3: Environment safe-set implementation

**Decision**: The child process env is constructed as:

```python
_SAFE_KEY_PREDICATE = lambda k: (
    k in {"PATH", "HOME", "LANG", "SSL_CERT_FILE"}
    or k.startswith("LC_")
    or k.startswith("XDG_")
)

child_env = {k: v for k, v in os.environ.items() if _SAFE_KEY_PREDICATE(k)}
for tk, tv in server_config.env.items():
    child_env[tk] = _substitute(tv)  # $VAR from os.environ, empty string if unset
```

**Rationale**:
- The predicate is spelled out with the exact key set from spec FR-005 (2026-08-16 clarification). Any future expansion of the safe-set touches this one line.
- `LC_*` and `XDG_*` are prefix predicates because their key namespace is open-ended (`LC_ALL`, `LC_CTYPE`, `LC_MESSAGES`, ..., `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_RUNTIME_DIR`, ...). Matching by prefix is the natural shape.
- `$VAR` substitution inside the TOML `env` values mirrors how `exec` handler substitutes `$OWNER`/`$REPO`/`$BRANCH`/`$PATH` in `command`; consistent semantics reduce control-author surprise.
- An unset substituted var becomes empty string (not KeyError) to match `exec`'s behavior. The MCP server, not darnit, is responsible for treating "no token" as an error condition if it needs one.
- Cross-platform: on Windows, add `SYSTEMROOT` and `SYSTEMDRIVE` to the safe-set at the platform-guard level. Deferred to plan-implementation phase; called out here so it does not get overlooked.

**Alternatives considered**:
- **Pass full parent env**: rejected. Reintroduces the leak the safe-set exists to prevent.
- **Empty env plus TOML block only**: rejected. Breaks most real MCP servers (which need PATH to find helper binaries, HOME for config).

## Decision 4: Sigstore verification path

**Decision**: `mcp_trust.verify(binary_path, trusted_publisher)` looks for a `.sigstore` or `.sigstore.json` sidecar next to the binary, calls `sigstore.verify.Verifier.production().verify_dsse(bundle, policy)` where `policy = AllOf([OIDCIssuer("https://token.actions.githubusercontent.com"), GitHubWorkflowRepository(trusted_publisher.removeprefix("https://github.com/"))])`. Returns `True` on success, `False` on any failure (missing sidecar, malformed bundle, verification error). Failure is loud in the caller: the caller resolves the affected control ERROR with the specific reason surfaced in evidence.

**Rationale**:
- The `sigstore` package is already declared under `darnit-core[attestation]` and used by the existing plugin-wheel verification path in `packages/darnit/src/darnit/core/plugin.py`. Reusing the same `Verifier.production()` + policy composition means one trust-root, one code path.
- The sidecar approach matches how GoReleaser's Sigstore step produces attestations for binary releases (e.g., cosign attach + a `.sig` and `.sigstore` bundle deposited next to the binary). It's the most common on-disk shape for CLI tools that publish signed releases.
- Failure at any point (missing sidecar, HTTP unreachable while contacting Rekor, mismatched identity) returns `False`; the caller produces ERROR with the specific reason. Constitution II: never a silent PASS from a verification failure.
- Sidecar-based verification does not require a network round-trip *at audit time* if the sidecar contains the full offline-verifiable bundle. Recent sigstore Python versions default to bundle format which does support offline verification for most cases; the fallback that hits Rekor is deferred to `sigstore.verify` internals and only fires when the bundle is old-shape.

**Alternatives considered**:
- **Fetch attestation from Rekor at audit time using the binary's SHA-256**: rejected for v0. Adds a network round-trip that Constitution II says can't silently be required for a compliance check. Attaching a sidecar to the binary makes the trust story auditable at install time, not audit time.
- **In-process verification with a fixed embedded trust root**: rejected. Duplicates the `sigstore` package's trust-root management, defeating the reason we depend on it.

## Decision 5: Mock MCP server design for the integration test

**Decision**: A small Python module at `tests/darnit/sieve/fixtures/mock_mcp_server/__init__.py` implementing a real MCP server using `mcp.server.Server`. Ships with a `__main__.py` for `python -m tests.darnit.sieve.fixtures.mock_mcp_server` invocation. Exposes four tools:

- `echo(text: str) -> {"text": str}` — trivially exercises the round-trip.
- `get_score(repo_url: str) -> {"score": float}` — returns a canned score parameterizable by env var so different test cases hit different values.
- `raise_error(reason: str) -> raises` — deliberately returns `isError=True` so ERROR-path tests are exercised.
- `sleep_forever() -> hangs indefinitely` — for timeout-path tests.

Spawn/teardown/tool-call events are logged to a file named by env var `DARNIT_MOCK_MCP_COUNTER_FILE`. The test fixture creates a fresh path per test; the mock appends one line per event; the test reads it back for assertions.

**Rationale**:
- Using the real `mcp` package's server primitives (rather than hand-rolling JSON-RPC) means the mock exercises the exact wire protocol darnit's client-side code uses. If the SDK's framing changes, both sides update together.
- File-based event counting is the simplest way to observe a subprocess's lifecycle from a test that cannot use in-process introspection (the subprocess is a separate process).
- Four tools cover the four load-bearing behavior paths: success (echo, get_score), server-side error (raise_error), timeout (sleep_forever). No fifth tool needed; edge cases beyond these compose from these primitives.
- Placing the mock under `tests/darnit/sieve/fixtures/` keeps it clearly test-scoped and out of production packaging.

**Alternatives considered**:
- **Third-party MCP mock library**: nothing usable exists at this feature's estimated implementation date; the `mcp` SDK's own server primitives are the right level.
- **Reuse the `scorecard-mcp` binary as the test fixture**: rejected — it's an external, still-stabilizing project. The spec explicitly defers the reference integration to a follow-up feature.
- **Multi-process mock**: rejected. One mock per test is a distinct file-counter path; simpler than a shared multi-instance mock.

## Deferred / out of scope for this feature

- HTTP or SSE MCP transports (deferred per spec Assumptions).
- Parallel invocation of the same server across parallel controls (deferred; v0 is serial).
- Cross-audit caching of tool results.
- `darnit install-mcp <server>` install-helper subcommand.
- Sandbox tooling beyond env-curation (tracked in issue #375).
- `exec`-handler env-curation retrofit — a separate feature could apply the same predicate to `exec` calls; not in scope here.
