# Contract: Draft Output Format

The structure of the Markdown draft the handler writes to `THREAT_MODEL.md`. This contract exists because the existing `darnit-remediate` skill instructs the calling agent to review generated files with the assumption that certain sections exist. Breaking this contract would break the skill's review flow without the skill being updated.

## Markdown draft — required top-level sections

Every draft **MUST** contain these sections in this order. Section headers **MUST** use `##` (level 2) so the calling agent can parse them from the document:

1. `# Threat Model Report` (level 1 title)
2. `## Executive Summary`
3. `## Asset Inventory`
4. `## Data Flow Diagram`
5. `## STRIDE Threats`
6. `## Attack Chains` (optional in shallow mode)
7. `## Recommendations Summary`
8. `## Verification Prompts` (the instruction block for the calling agent)
9. `## Limitations`

### Section content contracts

#### `## Executive Summary`

**Required elements**:
- Date, repository path, detected frameworks list
- Risk distribution table (Critical / High / Medium / Low / Info counts)
- One-sentence summary of the risk posture

**Must not contain**: prose that asserts severity without underlying findings backing it.

#### `## Asset Inventory`

**Required elements**:
- Subsection `### Entry Points` with a list or table of discovered `EntryPoint` assets (file:line, kind, framework, route if applicable)
- Subsection `### Data Stores` with a list or table of discovered `DataStore` assets (technology, location, import evidence)
- Subsection `### Authentication Mechanisms` with discovered auth decorators/middleware

**Empty-case content**: When a category has no assets, the subsection MUST still exist with text like `No HTTP route handlers detected.`

**Empty-inventory diagnostic** *(added 2026-04-12)*: When the Entry Points subsection is empty AND `FileScanStats.in_scope_files > 50`, the subsection MUST include a diagnostic warning: `⚠️ No entry points detected in a repository with N source files. This likely indicates missing query coverage for the project's framework or registration pattern. Review the Limitations section.` This prevents users from mistaking a detection gap for a clean bill of health.

#### `## Data Flow Diagram`

**Required elements**:
- A Mermaid `flowchart LR` code block showing external actors → entry points → data stores
- When the call graph is too large (>50 nodes), render a simplified version with a note
- In shallow mode, the DFD may be omitted; if so, include a note under this heading explaining why

#### `## STRIDE Threats`

**Required elements**:
- Six subsections: `### Spoofing`, `### Tampering`, `### Repudiation`, `### Information Disclosure`, `### Denial of Service`, `### Elevation of Privilege`
- Each subsection lists the `CandidateFinding`s belonging to that category, up to the top-N cap
- Each finding rendering **MUST** include:
  - A heading like `#### TM-<CATEGORY>-<NNN>: <title>`
  - Severity and confidence ("Risk Score: 0.85 (HIGH)")
  - The file path and line number
  - A fenced code block with the ±N line `code_snippet`, with `>>>` prefix on the marker line
  - When a data-flow trace is present: a second fenced block labeled "Data Flow"
  - The source of the finding (tree-sitter query id or Opengrep rule id)
- Empty categories MUST still exist with a one-line "No threats identified." note

#### `## Attack Chains`

**Optional in shallow mode.** When present:
- A list of detected multi-finding chains (findings that share an asset and span multiple STRIDE categories)
- Each chain rendered as a numbered path from source to impact
- If no chains: "No compound attack paths identified."

#### `## Recommendations Summary`

**Required elements**:
- "Immediate actions" subsection listing Critical/High findings
- "Short-term actions" subsection listing Medium findings
- Ranked by severity × confidence

#### `## Verification Prompts`

**Required elements**: A block of instructions the calling agent reads to drive its verification pass. Must include:
- "For each finding above, read the embedded code snippet. If the code does not actually exhibit the described threat, remove the finding entirely from the committed file."
- "After removing false positives, refine remaining narratives with project-specific details."
- "Preserve the STRIDE category headings even when their content changes."
- "Commit the reviewed file using the `darnit-remediate` skill's normal commit step."
- An HTML comment marker: `<!-- darnit:verification-prompt-block -->` wrapping the block for unambiguous detection by tests and the skill.

This replaces the existing `_build_verification_section` in `tools.py`. The new version refers to the new finding shape but preserves the instructional intent.

#### `## Limitations`

**Required elements**:
- Languages scanned, files scanned count, excluded directory count (from `FileScanStats`)
- Whether Opengrep was available (from `opengrep_available`)
- Whether shallow mode was used (from `FileScanStats.shallow_mode`) and what analyses were reduced or skipped
- Per-category trimmed-overflow counts (from `TrimmedOverflow`)
- A boilerplate note that this is a threat-modeling aid, not an exhaustive vulnerability scan

## SARIF output

SARIF 2.1.0 document. Each `CandidateFinding` becomes one `result` entry with:
- `ruleId` = `query_id`
- `level` = `"error"` / `"warning"` / `"note"` from severity thresholds (≥7 → error, 4–6 → warning, ≤3 → note)
- `message.text` = the finding `title`
- `locations[0].physicalLocation.artifactLocation.uri` = `primary_location.file`
- `locations[0].physicalLocation.region.startLine` / `startColumn` / `endLine` / `endColumn`
- `locations[0].physicalLocation.contextRegion.snippet.text` = joined `code_snippet.lines`
- `properties.dataFlowTrace` = serialized `DataFlowTrace` when present
- `properties.source` = `FindingSource` string

The SARIF `tool.driver.rules` array lists every query id used, with short descriptions.

## JSON output

Serialized form of the full in-memory model: `FileScanStats`, lists of `EntryPoint`, `DataStore`, `CandidateFinding`, `TrimmedOverflow`. Pretty-printed with 2-space indent. Used by consumers that want programmatic access without re-parsing the Markdown.

## Structural invariants

- All three output formats (Markdown, SARIF, JSON) describe the **same finding set**. If a finding is trimmed by the top-N cap, it is absent from all three.
- Findings in the Markdown draft appear in ranked order (highest severity × confidence first) within each STRIDE category.
- Line numbers are 1-indexed across all formats.
- File paths are repository-relative with forward slashes.
- The `<!-- darnit:verification-prompt-block -->` marker is present exactly once in every successful Markdown draft.
