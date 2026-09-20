# Darnit Framework - Architecture Research Brief

## Context

We're designing **Darnit**, a security/compliance checking framework that runs as MCP (Model Context Protocol) servers. It will support multiple security standards:

- **OSPS** (OpenSSF Baseline) - 61 security controls across 3 maturity levels
- **SLSA** (Supply-chain Levels for Software Artifacts) - Build provenance and supply chain security
- **OpenSSF Scorecard** - Automated security health metrics
- **Custom/Proprietary standards** - Internal organizational policies

The framework needs to:
1. Support both open source and proprietary plugins/checks
2. Share configuration via a `project.toml` file
3. Potentially allow the AI to help with ambiguous decisions (e.g., overlapping controls)
4. Provide unified reporting (SARIF, Markdown, JSON)

## What is MCP?

MCP (Model Context Protocol) is Anthropic's open protocol for connecting AI assistants to external tools and data sources. Key characteristics:

- **Server-based**: Each MCP server is a separate process that exposes "tools" (functions the AI can call)
- **Tool invocation**: The AI sees tool descriptions and can call them with parameters
- **No inter-MCP communication**: MCPs cannot directly call each other; the AI orchestrates between them
- **Configuration**: Users configure MCP servers in their AI client (Claude Desktop, VS Code, etc.)

Example MCP tool:
```python
@mcp.tool()
def audit_security(repo_path: str, level: int = 3) -> str:
    """Run security audit on a repository."""
    # ... implementation
    return "Audit results..."
```

## The Architectural Question

We're debating between these approaches:

### Option A: Single MCP with Plugin System

```
┌─────────────────────────────────────────────┐
│            darnit MCP Server                │
│  ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐  │
│  │ OSPS  │ │ SLSA  │ │Score- │ │ Acme  │  │
│  │plugin │ │plugin │ │ card  │ │plugin │  │
│  └───────┘ └───────┘ └───────┘ └───────┘  │
│         (all in-process plugins)           │
└─────────────────────────────────────────────┘
                    │
                    ▼
                 AI Agent
```

- One MCP server loads all standards as Python plugins
- Shared state, config parsing, caching
- ~30-50 tools exposed to AI
- Proprietary plugins installed from private PyPI

### Option B: Multiple Specialized MCPs

```
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│ darnit   │ │  slsa    │ │scorecard │ │  acme    │
│ -osps    │ │  -mcp    │ │  -mcp    │ │  -mcp    │
│  MCP     │ │          │ │          │ │(private) │
└──────────┘ └──────────┘ └──────────┘ └──────────┘
     │            │            │            │
     └────────────┴────────────┴────────────┘
                       │
                       ▼
                   AI Agent
                (orchestrates)
```

- Each standard is its own MCP server (separate process)
- AI calls tools across multiple MCPs
- Each MCP has 5-10 focused tools
- Each can have specialized system prompts/expertise
- No shared state (each parses config independently)

### Option C: Core MCP + Specialist MCPs

```
┌─────────────────────────────────────────────┐
│           darnit-core MCP                   │
│  • Config management (project.toml)         │
│  • Shared cache                             │
│  • Result aggregation                       │
│  • Consultation/decision protocol           │
└─────────────────────────────────────────────┘
        │
        │ (file-based or IPC)
        │
┌───────┴───────┬───────────────┬─────────────┐
│               │               │             │
▼               ▼               ▼             ▼
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│  osps    │ │  slsa    │ │scorecard │ │  acme    │
│ -expert  │ │ -expert  │ │ -expert  │ │ -expert  │
│  MCP     │ │  MCP     │ │  MCP     │ │  MCP     │
└──────────┘ └──────────┘ └──────────┘ └──────────┘
```

- Core MCP handles shared concerns
- Specialist MCPs are domain experts
- Communicate via shared files or simple IPC
- Each specialist has deep, focused expertise

## Research Questions

Please research and provide guidance on:

### 1. MCP Best Practices

- Are there established patterns for multi-MCP architectures?
- How do existing MCP ecosystems handle related tools? (e.g., filesystem + git + GitHub MCPs)
- What's the recommended number of tools per MCP for optimal AI performance?
- Are there examples of MCP "plugin" systems?

### 2. AI Tool Selection Performance

- Does AI tool selection degrade with many tools (30-50+)?
- Do specialized, focused tools lead to better AI decision-making?
- Is there research on "cognitive load" for AI agents with large tool sets?
- How does tool description quality affect selection accuracy?

### 3. Parallel Execution

- Can AI agents effectively parallelize calls to multiple MCPs?
- What's the latency overhead of multiple MCP connections vs. one?
- Are there benefits to having independent MCPs that can run concurrently?

### 4. State Sharing Patterns

- How do multi-MCP setups handle shared state (config files, caches)?
- Are there patterns for "coordinator" MCPs that manage other MCPs?
- How do you avoid duplicate work across MCPs (e.g., both checking branch protection)?

### 5. Enterprise/Security Considerations

- How should proprietary/licensed MCPs be isolated from open source ones?
- Are there security benefits to process isolation between MCPs?
- How do enterprises typically deploy multiple related MCPs?

### 6. Similar Systems

- How do other plugin-based security tools handle this? (e.g., ESLint, Semgrep, tfsec)
- Are there examples of "meta-tools" that orchestrate other security scanners?
- How does the OpenSSF Scorecard architecture work (it aggregates multiple checks)?

## Trade-off Summary

| Factor | Single MCP | Multiple MCPs |
|--------|------------|---------------|
| User setup complexity | Lower | Higher |
| Shared state/caching | Natural | Requires coordination |
| Tool selection clarity | Harder (many tools) | Easier (focused tools) |
| Process isolation | None | Full |
| Proprietary integration | In-process | Separate process |
| Parallel execution | Thread-level | Process-level |
| Fault isolation | None | Full |
| Release independence | Coupled | Independent |
| Cross-standard deduplication | Easy | Hard |

## What We're Trying to Decide

1. Should we build one MCP with a plugin system, or multiple specialized MCPs?

2. If multiple MCPs, should there be a "core" MCP that coordinates, or let the AI orchestrate?

3. How do we handle:
   - Shared configuration (`project.toml`)
   - Cross-standard overlap (OSPS and SLSA both check similar things)
   - Unified reporting (combining results from multiple standards)
   - Proprietary plugins that need isolation

4. What architecture will:
   - Scale to 5-10 standards
   - Support both OSS and proprietary checks
   - Provide the best AI user experience
   - Be maintainable long-term

## Additional Context

- Primary AI client will be Claude (via Claude Desktop or Claude Code)
- We want the AI to be able to help with ambiguous decisions (e.g., "these two controls overlap, what should I do?")
- Configuration is in `project.toml` (TOML format)
- Output formats needed: SARIF (for GitHub Code Scanning), Markdown, JSON
- Some checks require GitHub API access, some are local file analysis only

## Deliverable Requested

Please provide:
1. Research findings on the questions above
2. Recommendation on which architecture to pursue
3. Any alternative approaches we haven't considered
4. Risks or pitfalls to watch out for
5. Examples of similar systems that have solved this well

---

*This brief was prepared for architectural review. The Darnit framework is in early design phase.*
