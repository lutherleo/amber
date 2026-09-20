# Feature Specification: mcp handler for calling external MCP servers as observation sources

**Feature Branch**: `031-mcp-server-handler`

**Created**: 2026-08-16

**Status**: Draft

**Input**: User description: "Add mcp handler to darnit's sieve so TOML controls can call external MCP servers as observation sources, with spawn-lazy-per-audit lifecycle and allowlist-required plus optional Sigstore trust. Motivating reference server: uwu-tools/scorecard-mcp. v0 ships the machinery + mock-server integration test only; real Scorecard-backed controls land in a follow-up feature once uwu-tools/scorecard-mcp stabilizes its tool surface."

## Clarifications

### Session 2026-08-16

- Q: Child process environment inheritance → A: Curated safe-set (PATH, HOME, LANG, LC_*, SSL_CERT_FILE, XDG_*) plus TOML `env` block. Stronger sandbox tech (e.g., seccomp/landlock/nsjail-style isolation) is a follow-up feature, tracked separately.
- Q: Default per-call timeout → A: 60 seconds. Control authors doing longer-running work opt in with `timeout = <seconds>` on the pass.
- Q: Progress-line observability for MCP calls → A: One INFO line per call at dispatch, using a `dispatching_mcp` phase verb symmetric with feature 026's `dispatching_llm`.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Control author writes an OSPS control that consults an external MCP server (Priority: P1)

A control author writes a compliance control whose most authoritative signal is not observable from the local repo alone. They want to consult a tool that already exposes an MCP interface (OpenSSF Scorecard, a proprietary policy engine, an internal SBOM validator) and use its answer as evidence for the control's PASS/FAIL decision. They declare the tool call in the same flat TOML shape they use for `exec` and `api_call`. The audit runs, the tool answers, the control resolves.

**Why this priority**: This is the whole reason the feature exists. Without a working control-author flow, the machinery has no consumer. Every other user story presupposes this one works.

**Independent Test**: Author a small OpenSSF-style TOML control whose only pass is `handler = "mcp"` against a mock MCP server that returns `{"score": 8.0}`. Run the audit against a test repo. The control's status equals PASS; the evidence dict contains `result.score = 8.0`; the CEL `expr` was evaluated against the mock's response.

**Acceptance Scenarios**:

1. **Given** an `.baseline.toml` that declares `[mcp_servers.mock]` pointing at a mock MCP server binary on the operator's PATH, **When** an audit runs a control whose pass is `{ handler = "mcp", server = "mock", tool = "get_score", args = {...}, expr = 'result.score >= 7.0' }`, **Then** the control resolves against the mock's response with the CEL `expr` evaluated over `result.*` and the mock's raw response captured in the control's evidence.
2. **Given** the same audit invocation, **When** three separate controls in the same audit each call the `mock` server (possibly for different tools), **Then** the mock server is spawned exactly once for that audit run and reused across all three calls.
3. **Given** the same audit invocation, **When** the audit finishes (success, failure, or interrupted mid-run), **Then** the mock server subprocess is terminated cleanly before the darnit process exits; no orphaned processes remain.

---

### User Story 2 - Operator adds a new MCP-backed capability to their audit (Priority: P2)

A fleet operator wants to enrich their audits with a new external tool that exposes an MCP interface. They add one block to their `.baseline.toml` describing how to spawn the server. Controls in their framework TOML can now reference the new server by name. No plugin code, no framework fork, no additional darnit installation step beyond making the MCP-server binary available on PATH.

**Why this priority**: Operator ergonomics is what makes the feature adoptable beyond the reference integration. If adding a new server requires a plugin author to write Python glue, the machinery loses most of its value. This story asserts the pure-configuration path works.

**Independent Test**: On a fresh checkout with no plugin changes, add a `[mcp_servers.newthing]` block to `.baseline.toml`, place the corresponding binary on PATH, author a control that references it, run the audit, observe the control resolve.

**Acceptance Scenarios**:

1. **Given** an operator adds a `[mcp_servers.newthing]` block to `.baseline.toml` with a `command` field naming a binary they installed, **When** the audit starts, **Then** darnit reads that block from the effective framework configuration alongside all other framework TOML.
2. **Given** the operator's TOML block includes `env = { API_TOKEN = "$SOME_ENV_VAR" }`, **When** the server is spawned, **Then** the child process's environment contains (a) the curated safe-set `PATH`, `HOME`, `LANG`, `LC_*`, `SSL_CERT_FILE`, `XDG_*` inherited from darnit's own process, PLUS (b) `API_TOKEN` set to the value of `$SOME_ENV_VAR` from the operator's shell environment at audit-invocation time. NO other operator-shell env variables leak through by default (clarified 2026-08-16); the child does NOT receive credentials-style vars from the parent shell such as `AWS_*`, `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, or arbitrary user-set variables unless the TOML block names them explicitly.
3. **Given** no framework or `.baseline.toml` block declares an `[mcp_servers.<name>]`, **When** a control's pass references `server = "<name>"`, **Then** the control resolves as ERROR with an evidence field naming the missing server and pointing at the operator's configuration; the audit does not crash or silently swallow the control.

---

### User Story 3 - Trust boundary is respected regardless of the operator's PATH state (Priority: P2)

A malicious or accidentally-installed binary on the operator's PATH must not be able to run under darnit's identity as an MCP server. The `[mcp_servers.<name>]` block is the allowlist; without an entry, darnit does not spawn. When the block includes a `trusted_publisher`, darnit verifies the binary's Sigstore attestation before spawning and refuses to trust the output on verification failure.

**Why this priority**: Constitution II bites hard here. A silent PASS from an unverified server contradicts the entire compliance posture darnit exists to enforce. This story is P2 not because it is less important than US1 (it is not) but because the P1 machinery does not compile without an allowlist enforcement path, so this property is exercised even in the reference test path.

**Independent Test**: Two shell tests. (a) Try to reference a server not declared in `[mcp_servers.*]` from a control; observe ERROR without a subprocess spawn. (b) Declare a server with `trusted_publisher = "https://github.com/example"` pointing at a binary whose Sigstore attestation does not match; observe ERROR with a verification-failed message; the binary's output MUST NOT contribute to any control's evidence.

**Acceptance Scenarios**:

1. **Given** an `.baseline.toml` with NO `[mcp_servers.rogue]` block, **When** a control's pass declares `server = "rogue"`, **Then** darnit records an ERROR result naming the missing allowlist entry; the audit does NOT spawn any subprocess.
2. **Given** `[mcp_servers.pinned].trusted_publisher = "https://github.com/example"` and a `pinned-server` binary on PATH whose Sigstore attestation cannot be verified against that publisher, **When** the audit reaches a control that uses `server = "pinned"`, **Then** darnit records an ERROR with the verification failure reason; the audit does NOT trust the binary's output as evidence.
3. **Given** the same block but the binary's Sigstore attestation DOES verify against `https://github.com/example`, **When** the audit runs, **Then** the server is spawned once for the audit run and its tool responses are used as evidence, and verification success is recorded in the run's evidence.
4. **Given** `[mcp_servers.<name>]` with NO `trusted_publisher` field, **When** the audit runs, **Then** the server is spawned based on the allowlist entry alone, no Sigstore verification is attempted, and this is documented as "operator-trusted PATH" in the run's evidence.

---

### User Story 4 - Missing binary is a knowable, non-fatal outcome by default (Priority: P3)

A control author writes a control that consults an external MCP server. Some operators install that server; some do not. When the server is absent, the audit does not crash and does not silently PASS. The control's status is INCONCLUSIVE with a clear message telling the operator what to install.

**Why this priority**: Real-world audits run across heterogeneous fleets. A single "install this binary" gate that stops every run is worse than a control that reports "I could not check this because you did not install the tool." P3 because US3 covers the security-critical absence case (rogue reference), while this story covers the ergonomics of the common-case absence (tool not installed).

**Independent Test**: Configure a control that uses `[mcp_servers.absent]` where the binary is not on PATH. Run the audit. Observe the control resolves INCONCLUSIVE (not PASS, not ERROR) with a message identifying which binary was expected. Then set `[mcp_servers.absent].optional = false` in `.baseline.toml`, re-run, observe the same absence now produces FAIL.

**Acceptance Scenarios**:

1. **Given** `[mcp_servers.absent].command = ["absentbin"]` and no `absentbin` on PATH, **When** the audit reaches a control that uses `server = "absent"`, **Then** the control resolves INCONCLUSIVE with a message naming `absentbin` and hinting at how to install it (per the operator's TOML block or a default hint).
2. **Given** the same conditions plus `[mcp_servers.absent].optional = false` in the operator's `.baseline.toml`, **When** the audit runs, **Then** the same absence produces FAIL for every control that references the server.
3. **Given** the server is present and spawns cleanly, but a specific tool call raises an MCP-level error (unknown tool, malformed args, tool-side crash), **When** the audit reaches the affected control, **Then** that individual control resolves ERROR with the MCP error message in evidence; other controls that use the same server continue to function.

### Edge Cases

- **Server crashes mid-audit**: the pooled session becomes unusable. Subsequent controls that reference the same server MUST attempt exactly one respawn; if respawn fails, they resolve INCONCLUSIVE (or FAIL if `optional = false`). Do not retry indefinitely.
- **Server hangs (no response within the handler's timeout)**: the individual call times out, that control resolves ERROR, the session is discarded; the next control that references the same server triggers a fresh spawn.
- **Same server name declared in both `.baseline.toml` and a framework TOML**: `.baseline.toml` wins (operator override supersedes framework default), symmetric with how darnit already merges `.baseline.toml` over framework TOMLs.
- **Server spawns but MCP handshake fails or times out**: the session is not cached; the control resolves INCONCLUSIVE (or FAIL if `optional = false`) with a message identifying the handshake failure. Do NOT retry the same broken server for other controls in the same audit; log once and record consistently.
- **Argument substitution (`$OWNER`, `$REPO`, `$BRANCH`, `$PATH`) inside `args`**: MUST behave identically to how `exec` handler substitutes them today. No new substitution surface introduced by this feature.
- **A control that legitimately expects a numeric-zero or empty-list result**: `expr` distinguishes "server returned {}" from "server did not respond" so an empty response does not silently look like a PASS or FAIL depending on which one the operator wanted. Evidence records both the raw response and the CEL truth value.
- **Audit interrupted (Ctrl+C, timeout, harness cancel)**: pooled sessions MUST be terminated before darnit exits. No zombie subprocesses under any exit path.
- **HTTP or SSE transport for the MCP server**: out of scope for this feature; only stdio transport is supported. A control that references an HTTP-only server MUST produce ERROR with a "stdio-only" reason, not a silent hang.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: A new sieve handler named `mcp` MUST be available for control authors to reference from framework TOML alongside `exec`, `api_call`, `file_exists`, and the other existing built-in handlers.
- **FR-002**: The `mcp` handler MUST accept, at minimum, `server` (allowlist name), `tool` (tool to invoke), and `args` (dict of arguments to pass to the tool) from its TOML config block. It MUST accept `expr` (CEL truth expression evaluated against the tool response) with the same semantics as `exec`. It MUST accept an optional `timeout` (per-call, in seconds) that defaults to **60 seconds** when unspecified on the pass (clarified 2026-08-16). A control author whose tool legitimately takes longer (repository clone, deep static analysis) opts in with an explicit larger `timeout` value.
- **FR-003**: The result of a tool invocation MUST be exposed to CEL as `result.*`, symmetric with how `exec` exposes `output.*`, so a control author familiar with `exec` needs no additional CEL knowledge.
- **FR-004**: The handler MUST perform `$OWNER`, `$REPO`, `$BRANCH`, and `$PATH` variable substitution inside `args` values before dispatching the tool call, matching the `exec` handler's substitution behavior.
- **FR-005**: An allowlist entry for a server MUST take the form `[mcp_servers.<name>]` in `.baseline.toml` or a framework TOML, with at minimum a `command` field listing the executable and arguments used to spawn the server. Optional fields MUST include `env`, `trusted_publisher`, `optional`, and `install_hint`. When darnit spawns the server, the child process's environment MUST be constructed as the union of (a) a fixed curated safe-set inherited from darnit's own process (`PATH`, `HOME`, `LANG`, `LC_*`, `SSL_CERT_FILE`, `XDG_*`) and (b) the operator's `env` block. Any other variable from darnit's parent shell MUST NOT be visible to the child (clarified 2026-08-16).
- **FR-006**: A control's pass MUST resolve as ERROR with a message identifying the missing allowlist entry when the referenced server has no `[mcp_servers.<name>]` block; the audit MUST NOT spawn any subprocess as a result of that reference.
- **FR-007**: When `[mcp_servers.<name>].trusted_publisher` is set, darnit MUST verify the server binary's Sigstore attestation against that publisher before treating the binary's output as evidence; verification failure MUST resolve as ERROR (never PASS) and MUST NOT contribute the binary's output to any control's evidence.
- **FR-008**: When `[mcp_servers.<name>].trusted_publisher` is unset, darnit MAY spawn the binary based on the allowlist entry alone; the resulting evidence MUST be labelled "operator-trusted PATH" or equivalent so downstream consumers (attestation, report) can distinguish operator-trust from cryptographic verification.
- **FR-009**: When the named binary is not found on the operator's PATH (or at the absolute path specified in `command`), the affected control MUST resolve INCONCLUSIVE by default, with a message naming the missing binary and including the operator's `install_hint` if set. The `[mcp_servers.<name>].optional = false` field MUST promote absence to FAIL.
- **FR-010**: The `mcp` handler ships under RFC-0001 Stage 1 authority semantics as an observation-based handler; its default authority MUST be `dispositive`. TOML-level authority overrides on individual passes MUST behave identically to how they work for `exec` today (cannot loosen a handler default).
- **FR-011**: Server sessions MUST be pooled across the lifetime of a single audit run: the first control that references a given server triggers the spawn and MCP handshake; subsequent controls in the same audit that reference the same server reuse the same session; sessions are torn down when the audit ends. Session pooling MUST NOT cross audit boundaries.
- **FR-012**: A pooled session that becomes unusable mid-audit (server crashed, socket closed, handshake failure) MUST be invalidated so that the next control's reference to the same server triggers a single respawn attempt; darnit MUST NOT retry the spawn indefinitely on repeated failures within one audit run.
- **FR-013**: On any audit exit path (success, failure, exception, external interrupt), all pooled MCP server subprocesses MUST be terminated before the darnit process exits. No orphaned processes.
- **FR-014**: A tool invocation that returns an MCP-level error (unknown tool, malformed args, or server-side error response) MUST resolve the affected control as ERROR for that call only; other controls in the same audit that reference the same server or the same tool MUST NOT be affected.
- **FR-015**: Transport for v0 MUST be stdio only. A server declared with a transport specification other than stdio (if the schema grows to support one) MUST produce a clear ERROR ("transport not supported") rather than a silent hang.
- **FR-016**: When the same `[mcp_servers.<name>]` block is declared in both `.baseline.toml` and a framework TOML, the `.baseline.toml` block MUST take precedence, symmetric with existing darnit config-merge semantics.
- **FR-017**: The feature MUST NOT introduce a new runtime dependency to any darnit product package. The MCP client library `mcp>=1.23,<2` is already a runtime dependency; no additional dependency is required.
- **FR-018**: Every tool invocation MUST record in the control's evidence: the server name, the tool name, the arguments the tool was called with (after `$` substitution), the raw JSON response (or the error), the trust label (Sigstore-verified vs operator-trusted PATH), and the elapsed time.
- **FR-019**: At the moment the sieve orchestrator is about to dispatch an MCP tool call (a pass whose `handler = "mcp"`), the orchestrator MUST emit one INFO log line on the `darnit.harness` logger using the `[N/M] <control_id> dispatching_mcp <server>.<tool>` shape (clarified 2026-08-16). Emission from the orchestrator (not the handler) matches feature 026's `dispatching_llm` pattern, where the driver iterating controls is the only entity that knows N and M. No corresponding "call returned" line is emitted; the terminal `resolved_*` line for the control conveys completion.

### Key Entities *(include if feature involves data)*

- **MCP server allowlist entry** (`[mcp_servers.<name>]`): the operator's or framework author's declaration of a server darnit may spawn. Fields: `command` (required), `env`, `trusted_publisher`, `optional`, `install_hint`. Identity is the block name; uniqueness within the effective merged framework configuration.
- **Pooled session**: the runtime state representing one spawned MCP server subprocess plus its client-side session for the current audit. Ephemeral to the audit run. Distinguishable by (audit id, server name); a fresh audit starts fresh sessions.
- **Tool invocation record**: a per-call record entered into the affected control's evidence, capturing every input, output, and trust label. Persists into the audit's evidence log the same way `exec` output persists today.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A control author familiar with `exec` handler can author a working `mcp`-backed pass by writing at most one additional TOML block (the `[mcp_servers.<name>]` allowlist) and using the same CEL and substitution syntax they already know for `exec`.
- **SC-002**: For a hypothetical audit that runs 20 controls all backed by the same MCP server, the server MUST be spawned exactly once and terminated exactly once. This measurable property (spawns == 1, terminations == 1) is verifiable from a mock server that counts its own lifecycle events.
- **SC-003**: An operator who removes a server from their PATH (or never installs it) sees INCONCLUSIVE results with actionable install-hint messages on affected controls, and no ERROR or crash of the audit as a whole, on the very first audit run after the removal.
- **SC-004**: A malicious binary swapped onto PATH under a server name whose allowlist entry declares `trusted_publisher` MUST NOT successfully contribute any evidence to the audit. Result on the affected controls MUST be ERROR with the Sigstore verification failure reason, verifiable by re-running the audit after the swap.
- **SC-005**: A control author who reads the feature's docs plus one worked example can add a new `[mcp_servers.<name>]` block for an arbitrary MCP server they know about in under 15 minutes, without reading any Python source.

## Assumptions

- The MCP server producer's own lifecycle guarantees are outside darnit's scope. If the server itself makes non-idempotent state changes on a `tools/list` handshake, that is the server's design bug and darnit does not compensate for it. Darnit's own contract is: single spawn per audit, single handshake per spawn, teardown at audit end.
- Sigstore verification uses the same underlying machinery as darnit's existing plugin-wheel Sigstore path (`.baseline.toml [plugins] allow_unsigned` etc.). No new verification transport, no new trust root. If the operator's environment cannot reach Sigstore's transparency log, `trusted_publisher`-configured servers MUST resolve as ERROR (server unusable) rather than fall through to allowlist-only trust.
- The reference MCP server (`uwu-tools/scorecard-mcp`) is out of scope for this feature. This feature ships the mechanism plus a mock-server-backed integration test; the Scorecard-backed control TOML lands in a follow-up feature once the reference server's tool surface stabilizes.
- HTTP and SSE transports are out of scope. Only stdio is supported in v0. A follow-up feature can add HTTP once the operational story (URLs, TLS trust, cross-network dispatch policy) is scoped.
- Concurrent tool calls against the same server are NOT supported in v0. Controls are dispatched serially; if the future orchestrator adds parallel control execution, a follow-up feature addresses per-server concurrency (e.g., per-server locks or connection multiplexing).
- Cross-audit caching of tool results is NOT supported in v0. Every audit spawns fresh sessions. A follow-up feature can add a cache once the invalidation story is scoped (e.g., "invalidate when the target repo's HEAD SHA changes").
- The feature does not introduce a `darnit install-mcp <server>` install-helper subcommand. Making the binary available is the operator's responsibility; the feature only provides `install_hint` messages to the operator when a control fails because the binary is absent.
- Existing scorecard normalizer (`packages/darnit/src/darnit/locate/normalizer.py`) is neither replaced nor extended by this feature. Whether a future Scorecard-backed control routes its raw JSON through that normalizer is decided in the follow-up Scorecard integration feature, not here.
- Stronger sandboxing (seccomp filters, landlock, nsjail-style process isolation, per-server cgroups) is deliberately out of scope for v0. The env-curation posture chosen in the 2026-08-16 clarification is a first line of defense; harder isolation belongs in a follow-up issue that can evaluate the whole sandbox-tool market against darnit's cross-platform requirements.
