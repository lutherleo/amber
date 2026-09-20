# Quickstart: `mcp` handler

Two worked examples. First is the control-author perspective (writing a new control that consults an external MCP server). Second is the operator perspective (adding a new server to a fleet's `.baseline.toml`).

## Example 1: Control author writes a pass that consults an external MCP server

Assume there's an MCP server called `scorecard-mcp` that exposes a `get_repo_score(repo_url) -> {"score": float, ...}` tool. Your framework TOML declares the allowlist entry in one place and references it from any number of controls.

### Framework TOML

```toml
[mcp_servers.scorecard]
command = ["scorecard-mcp"]
env = { GITHUB_TOKEN = "$GITHUB_TOKEN" }        # substituted from operator's shell at spawn time
trusted_publisher = "https://github.com/uwu-tools"   # optional; when set, sidecar-verified
optional = true                                  # binary absent -> INCONCLUSIVE, not FAIL
install_hint = "Install with: brew install scorecard-mcp"

[controls."OSPS-VM-01.01"]
name = "OpenSSFScorecardOverallScore"
level = 1
domain = "VM"
description = "Repository's OpenSSF Scorecard aggregate score is at least 7.0."

[[controls."OSPS-VM-01.01".passes]]
handler = "mcp"
server = "scorecard"
tool = "get_repo_score"
args = { repo_url = "github.com/$OWNER/$REPO" }
expr = 'result.score >= 7.0'
timeout = 120           # override the 60s default; a real Scorecard scan may take longer
```

### What happens at audit time

1. `darnit audit` (or the MCP tool wrapper, or the harness) starts a `verify_batch` run.
2. The first control that references `server = "scorecard"` triggers spawn: darnit resolves `scorecard-mcp` on PATH, verifies its Sigstore sidecar against `https://github.com/uwu-tools`, constructs the child env as (curated safe-set) + (`GITHUB_TOKEN` from operator's shell), spawns the subprocess, performs the MCP `initialize` handshake, and caches the session in the pool.
3. Darnit emits one INFO line on `darnit.harness`:
   ```
   [3/62] OSPS-VM-01.01 dispatching_mcp scorecard.get_repo_score
   ```
4. `session.call_tool("get_repo_score", {"repo_url": "github.com/octo/hello"})` runs with 120s timeout.
5. Result comes back as `{"score": 8.5, "date": "2026-08-01"}`.
6. CEL evaluates `result.score >= 7.0` → `True` → pass resolves PASS.
7. Evidence record for this control's `mcp_calls` list captures the whole exchange with `trust_label = "sigstore-verified"` and `elapsed_ms = 812`.
8. Subsequent controls that reference `server = "scorecard"` reuse the same session — no re-spawn, no re-handshake.
9. At audit end, `verify_batch`'s `finally` block terminates the session before returning. No orphaned subprocess.

### What if the operator hasn't installed `scorecard-mcp`?

The absent-binary path produces one INFO line and one INCONCLUSIVE result per affected control:

```
[3/62] OSPS-VM-01.01 dispatching_mcp scorecard.get_repo_score
[3/62] OSPS-VM-01.01 resolved_inconclusive
```

The evidence record for the control names the missing binary and includes the `install_hint`:

```
MCP server binary not found: scorecard-mcp. Install with: brew install scorecard-mcp
```

## Example 2: Operator adds a new MCP-backed capability without editing plugin code

Your fleet already runs `darnit audit` against your repos. You want to enrich the audit with a new external tool that exposes an MCP interface. No plugin code, no framework fork.

Add one block to `.baseline.toml`:

```toml
extends = "openssf-baseline"

[mcp_servers.internal_policy]
command = ["/opt/company/policy-mcp"]
env = { COMPANY_POLICY_TOKEN = "$COMPANY_POLICY_TOKEN" }
optional = false      # required for our fleet; missing binary is FAIL, not INCONCLUSIVE
install_hint = "See internal wiki page: https://wiki.company.io/policy-mcp"
```

Then any control in the extended framework, or in an override you write, can reference `server = "internal_policy"`. If you also want to add controls without forking the framework, you'll typically place them in a small extension package; that's an existing darnit-plugin-composition workflow (feature 013), not something this feature introduces.

## Failure-mode diagnostics quick reference

When a control's `mcp`-backed pass resolves to something unexpected, the evidence record tells you why. Reading the evidence for the affected control's `mcp_calls[0]`:

| Symptom in evidence | What it means | Fix |
|---------------------|---------------|-----|
| `unknown MCP server: <name>` | Control's `server = "<name>"` has no matching `[mcp_servers.<name>]` block. | Add the block to `.baseline.toml` or the framework TOML. |
| `MCP server binary not found: <cmd>. <hint>` | Binary is not on PATH. | Install per the hint. |
| `Required MCP server binary not found` (FAIL) | Same as above, but `optional = false` promoted absence to FAIL. | Install, or set `optional = true` if this control class can tolerate absence. |
| `Sigstore verification failed for <cmd>: <reason>` | `trusted_publisher` was set and the binary's sidecar didn't verify. | Verify the binary's provenance manually. Do NOT remove `trusted_publisher` without understanding why verification failed. |
| `MCP handshake failed: <reason>` | Server binary spawned but its initialization handshake failed or timed out. | Check server-side logs; the binary may be a wrong version or misconfigured. |
| `MCP tool call timed out after <N>s` | Tool didn't respond within `timeout`. | Raise the per-pass `timeout`, or investigate why the server is slow. |
| `MCP tool error: <server-supplied message>` | Server explicitly returned `isError=True`. | The message is the tool's own; read it. |
| `MCP tool response not JSON-parseable` | Tool returned non-text or non-JSON content. | Report to the MCP server's authors; darnit v0 requires JSON responses. |
| `MCP server session broken and respawn failed: <reason>` | Session crashed mid-audit and could not respawn. | Same as handshake-failure diagnosis for the respawn attempt. |

## Non-goals for v0 (what you can't do yet)

The following are known-deferred:

- **HTTP or SSE transport**: only stdio is supported. `command = ["python", "server.py"]` works; connecting to `https://mcp.company.io/tool` does not.
- **Parallel calls to the same server**: v0 runs controls serially. If your MCP server can handle concurrent calls, that capability is not yet used.
- **Cross-audit result caching**: every audit spawns fresh sessions. If your MCP tool is expensive and its output is stable across a day, you may want to add a separate cache layer above darnit for now.
- **`darnit install-mcp <server>`**: no install-helper subcommand exists. Operators install MCP-server binaries the same way they install any other CLI tool.
- **Stronger sandboxing**: env-curation is the sandbox in v0. See issue #375 for the exploration on `nono.sh` / bubblewrap / nsjail / landlock integration for real subprocess isolation.

## Where to look next

- Contract: `contracts/mcp-handler-contract.md` — exhaustive field, log, and failure-mode table.
- Data model: `data-model.md` — the schema types this feature adds.
- Research decisions: `research.md` — why the pool lives on the orchestrator, why sidecar-based Sigstore verify, etc.
- Follow-up sandboxing: [darnitdevorg/darnit#375](https://github.com/darnitdevorg/darnit/issues/375).
