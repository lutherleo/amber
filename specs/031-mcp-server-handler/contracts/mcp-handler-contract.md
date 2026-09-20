# Reader Contract: `mcp` handler

## Scope

The public control-author-facing surface of the `mcp` handler, its allowlist declaration, its evidence shape, its progress-log line, and its exhaustive failure-mode table. This is the file a future reconciliation-style feature will diff against to detect breaking changes.

## TOML pass surface

Inside a `[[controls.<id>.passes]]` block:

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `handler` | string | required | Value MUST be `"mcp"`. |
| `server` | string | required | References an `[mcp_servers.<name>]` allowlist entry by name. Unknown name resolves the pass ERROR without spawning. |
| `tool` | string | required | The MCP tool name to invoke on the server. |
| `args` | table | required | Arguments passed to the tool. Values may contain `$OWNER`, `$REPO`, `$BRANCH`, `$PATH` substitution tokens; the handler performs substitution before dispatch, symmetric with `exec` handler. |
| `expr` | string | optional | CEL truth expression evaluated against `result.*` (the tool's response). If omitted, the presence of a non-error response is treated as PASS. Same evaluation model as `exec`'s `expr`. |
| `timeout` | integer (seconds) | optional | Per-call timeout. Defaults to `60` (spec FR-002, clarified 2026-08-16). Timeout expiration resolves the affected pass ERROR. |
| `authority` | string | optional | Standard sieve authority override. May tighten (dispositive → suggestive) but not loosen. Default: `dispositive` (from the handler's registered `default_authority`). |

## TOML allowlist surface

Top-level `[mcp_servers.<name>]` block, either in `.baseline.toml` or a framework TOML:

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `command` | list of strings | required | argv-style. First element is the executable (resolved via PATH) or an absolute path. |
| `env` | table of string→string | optional | Extra env vars for the child process. Values may contain `$VAR` placeholders; darnit substitutes from its own `os.environ` at spawn time (empty string when unset). |
| `trusted_publisher` | string | optional | GitHub identity URL (`https://github.com/<owner>` or `.../<owner>/<repo>`) or OIDC identity. When present, darnit verifies the binary's Sigstore sidecar (`<binary>.sigstore` or `.sigstore.json`) against this publisher before spawning. |
| `optional` | bool | optional | Defaults to `true`. When `true`, absence of the binary produces INCONCLUSIVE. When `false`, absence produces FAIL. |
| `install_hint` | string | optional | One-line hint surfaced in the INCONCLUSIVE/FAIL message when the binary is missing (e.g., `"Install with: brew install scorecard-mcp"`). |

Merge precedence: `.baseline.toml` block wins over framework TOML block of the same name.

## Child process environment

At spawn time, the child process env is constructed as:

```
child_env = {
    k: os.environ[k] for k in os.environ
    if k in {"PATH", "HOME", "LANG", "SSL_CERT_FILE"}
    or k.startswith("LC_")
    or k.startswith("XDG_")
} | {
    tk: substitute($VARS_from_os_environ)(tv)
    for tk, tv in server_config.env.items()
}
```

No other operator-shell env variable is visible to the child. Notably absent by default: `AWS_*`, `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, any user-set variable not in the safe-set. An operator who needs one of these in the child MUST name it in the TOML `env` block explicitly.

## CEL binding

The tool's response is bound in CEL as `result.*`. Example:

```toml
expr = 'result.score >= 7.0 && result.date > "2026-01-01"'
```

The response must be JSON-parseable text content in the `CallToolResult`. Non-JSON responses (image content, binary blobs) resolve the pass ERROR with a "non-JSON response" reason.

## Evidence shape (`McpInvocationRecord`)

Every invocation writes one record into the control's `evidence["mcp_calls"]` list:

```json
{
    "server": "scorecard",
    "tool": "get_repo_score",
    "args_after_substitution": {"repo_url": "github.com/octo/hello"},
    "raw_response": {"score": 8.5, "date": "2026-08-01"},
    "trust_label": "sigstore-verified",
    "elapsed_ms": 812
}
```

On error, `raw_response` is omitted and `error` is set:

```json
{
    "server": "scorecard",
    "tool": "get_repo_score",
    "args_after_substitution": {"repo_url": "github.com/octo/hello"},
    "error": "tool timeout after 60s",
    "trust_label": "sigstore-verified",
    "elapsed_ms": 60003
}
```

`trust_label` is one of `"sigstore-verified"` (successful Sigstore verification against `trusted_publisher`) or `"operator-trusted-path"` (spawned based on allowlist entry alone, no verification attempted).

## Progress-log shape

At tool dispatch, exactly one INFO log line on the `darnit.harness` logger:

```
[{n}/{m}] {control_id} dispatching_mcp {server}.{tool}
```

Where `{n}/{m}` is the standard sieve control-progress counter (matching feature 026's `[N/M]` format), `{control_id}` is the current control being resolved, `{server}` is the allowlist key, `{tool}` is the tool name. No corresponding "returned" line; the terminal `resolved_pass` / `resolved_fail` / `resolved_error` / `resolved_inconclusive` line for the control conveys completion.

## Failure-mode table

Every failure path and its resulting control status:

| Failure mode | Control status | Evidence reason |
|--------------|----------------|-----------------|
| Referenced `server` not in `[mcp_servers.*]` allowlist | ERROR | `unknown MCP server: <name>` |
| Binary from `command` not on PATH (`optional = true`) | INCONCLUSIVE | `MCP server binary not found: <cmd>. <install_hint>` |
| Binary from `command` not on PATH (`optional = false`) | FAIL | `Required MCP server binary not found: <cmd>. <install_hint>` |
| `trusted_publisher` set, no sidecar or verification fails | ERROR | `Sigstore verification failed for <cmd>: <specific reason>` |
| Spawn succeeded but MCP handshake failed or timed out | INCONCLUSIVE (or FAIL if `optional=false`) | `MCP handshake failed: <reason>` |
| Handshake succeeded, tool invocation timed out | ERROR | `MCP tool call timed out after <N>s` |
| Handshake succeeded, tool returned `isError=True` | ERROR | `MCP tool error: <server-supplied message>` |
| Handshake succeeded, tool returned non-JSON content | ERROR | `MCP tool response not JSON-parseable` |
| Session crashed mid-audit, respawn attempted, respawn succeeded | (call retries against fresh session) | (evidence records the respawn) |
| Session crashed mid-audit, respawn attempted, respawn failed | INCONCLUSIVE (or FAIL if `optional=false`) | `MCP server session broken and respawn failed: <reason>` |
| Audit exits (success, fail, exception, interrupt) with active session | (control status unchanged) | Session is terminated before darnit process exits. No orphan. |

## Backward compatibility

This feature is a strict addition. Every framework TOML and `.baseline.toml` that parsed successfully before this feature MUST continue to parse successfully after it. Zero existing controls change behavior. The `[mcp_servers]` schema section is optional; absence is the pre-feature state.

## Non-goals for v0

The following are deferred and are NOT part of this contract:

- HTTP or SSE transport. Only stdio is supported.
- Parallel invocation of the same server (v0 is serial).
- Cross-audit result caching.
- `darnit install-mcp <server>` install-helper subcommand.
- Sandbox tooling beyond env-curation (tracked in issue #375).
- Retrofit of the env-safe-set to the existing `exec` handler (separate feature).

Any control author who assumes a deferred feature is available should get a clear error (e.g., an `mcp_servers.<name>` block with a hypothetical `transport = "http"` field would fail schema validation, not silently no-op).
