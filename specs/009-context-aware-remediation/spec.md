# Feature Specification: Context-Aware Remediation

**Feature Branch**: `009-context-aware-remediation`  
**Created**: 2026-04-05  
**Status**: Draft  
**Input**: Revamp darnit-baseline remediation to generate context-aware compliance files that use real project data instead of generic templates, with optional LLM enhancement for complex documents.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Remediation Produces Ready-to-Merge Docs (Priority: P1)

A maintainer runs `remediate_audit_findings` on their Python monorepo. The generated SUPPORT.md links to the actual Getting Started guide found in the repo, TEST-REQUIREMENTS.md contains `uv run pytest` (detected from pyproject.toml and CI workflows), and DEPENDENCIES.md names Dependabot specifically (detected from `.github/dependabot.yml`). The maintainer reviews the PR and merges without manual edits.

**Why this priority**: The #1 complaint from dogfooding — generated files feel like boilerplate and always need manual enhancement. Fixing this eliminates the most visible quality gap.

**Acceptance Scenarios**:

1. **Given** a Python project with `pyproject.toml` and `uv.lock`, **When** remediation generates TEST-REQUIREMENTS.md, **Then** the file contains `uv run pytest` (not `make test`).
2. **Given** a Go project with `go.mod`, **When** remediation generates TEST-REQUIREMENTS.md, **Then** the file contains `go test ./...`.
3. **Given** a repo with `.github/dependabot.yml`, **When** remediation generates DEPENDENCIES.md, **Then** it names "Dependabot" specifically (not "Dependabot or Renovate").
4. **Given** a repo with `.github/workflows/ci.yml` containing `golangci-lint`, **When** remediation generates a SAST policy doc, **Then** it names the specific linter.
5. **Given** a repo with CONTRIBUTING.md that mentions "governed by Kusari, Inc", **When** remediation generates GOVERNANCE.md, **Then** it includes that governance context.
6. **Given** a repo with CODE_OF_CONDUCT.md, **When** remediation generates any community doc (CONTRIBUTING, GOVERNANCE, SUPPORT), **Then** it links to the code of conduct.

---

### User Story 2 - Real Directory Structure in ARCHITECTURE.md (Priority: P1)

A maintainer runs remediation and the generated ARCHITECTURE.md contains the actual top-level directories and one level of subdirectories — e.g., `packages/darnit/`, `packages/darnit-baseline/` — not fake paths like `src/core/`, `src/api/`.

**Acceptance Scenarios**:

1. **Given** a repo with `packages/darnit/` and `packages/darnit-baseline/`, **When** remediation generates ARCHITECTURE.md, **Then** the components table lists these actual directories (not `src/core/`).
2. **Given** a repo with `cmd/`, `pkg/`, `internal/` directories, **When** remediation generates ARCHITECTURE.md, **Then** it lists those Go-conventional paths.
3. **Given** a repo with only a flat structure (no subdirectories), **When** remediation generates ARCHITECTURE.md, **Then** it lists top-level source files or notes the flat structure.

---

### User Story 3 - CI Workflow Awareness for Policy Docs (Priority: P2)

When remediation creates policy documents (SAST policy, SCA policy, release verification), it cross-references `.github/workflows/` to name specific tools.

**Acceptance Scenarios**:

1. **Given** a repo with `.github/workflows/sast.yml` using `github/codeql-action`, **When** remediation generates SAST policy, **Then** it names "CodeQL" as the SAST tool.
2. **Given** a repo with no CI workflows, **When** remediation generates policy docs, **Then** it uses sensible defaults and notes that CI integration is recommended.
3. **Given** a repo where the remediation itself creates new CI workflows (sast.yml, sca.yml, sbom.yml), **When** policy docs reference CI tools, **Then** the docs name the tools from the newly-created workflows via the `${var|default}` fallback syntax.

---

### User Story 4 - Cross-Reference Existing Docs (Priority: P2)

When remediation creates new documentation files, it scans existing docs and links to them where relevant.

**Acceptance Scenarios**:

1. **Given** a repo with a README linking to `https://docs.example.com`, **When** remediation generates SUPPORT.md, **Then** SUPPORT.md includes a link to that documentation site.
2. **Given** a repo with CONTRIBUTING.md, CODE_OF_CONDUCT.md, and SECURITY.md, **When** remediation generates GOVERNANCE.md, **Then** it links to all three.

---

### User Story 5 - LLM Enhancement for Complex Documents (Priority: P3)

For documents that benefit from deeper analysis — ARCHITECTURE.md component descriptions, threat model refinement — the MCP tool offers an optional LLM enhancement pass triggered via `enhance_with_llm=True`.

---

### User Story 6 - Deterministic Files Need No Enhancement (Priority: P1)

Files that can be fully generated from project context — LICENSE, .gitignore, CI workflow YAMLs, CODEOWNERS — are created correctly in one pass with no LLM involvement.

---

### User Story 7 - Single Source of Truth for Project Metadata (Priority: P1)

When remediation generates multiple files that need the same piece of data (maintainer list, security contact, governance model), exactly ONE file is the canonical source and all others reference it. If the maintainer list changes, only one file needs updating.

**Why this priority**: Dogfooding revealed that maintainer names, security contacts, and governance details get embedded in 3-5 generated files each. This creates a maintenance burden and drift risk — if a maintainer is added to CODEOWNERS but not GOVERNANCE.md, the docs are inconsistent.

**Acceptance Scenarios**:

1. **Given** confirmed maintainers `["@alice", "@bob"]`, **When** remediation generates CODEOWNERS, MAINTAINERS.md, and GOVERNANCE.md, **Then** CODEOWNERS and MAINTAINERS.md contain the names, but GOVERNANCE.md says "See [MAINTAINERS.md](MAINTAINERS.md) for the current list."
2. **Given** a confirmed security contact `security@kusari.dev`, **When** remediation generates SECURITY.md and SECURITY-ASSESSMENT.md, **Then** SECURITY.md contains the contact, but SECURITY-ASSESSMENT.md says "See [SECURITY.md](../SECURITY.md) for reporting instructions."
3. **Given** remediation generates GOVERNANCE.md and CONTRIBUTING.md, **When** both reference governance details, **Then** CONTRIBUTING.md says "See [GOVERNANCE.md](GOVERNANCE.md)" rather than embedding governance details.
4. **Given** a repo where the user later updates MAINTAINERS.md with a new maintainer, **When** they re-run the audit, **Then** no other generated file is stale — because they all reference MAINTAINERS.md.

**Canonical Source Mapping**:

| Data | Canonical File | All others should reference it |
|------|---------------|-------------------------------|
| Maintainer list | CODEOWNERS + MAINTAINERS.md | GOVERNANCE.md, SECURITY-ASSESSMENT.md, etc. |
| Security contact | SECURITY.md | SECURITY-ASSESSMENT.md, SUPPORT.md, etc. |
| Governance model | GOVERNANCE.md | CONTRIBUTING.md, etc. |
| License | LICENSE | README.md, etc. |

Note: CODEOWNERS and MAINTAINERS.md both contain the actual names because they serve different purposes — CODEOWNERS drives GitHub review assignment (machine-readable), MAINTAINERS.md is the human-readable canonical list.

---

### User Story 8 - Auto-Fix Workflow Permissions (Priority: P2)

When the audit finds GitHub Actions workflows missing a top-level `permissions:` block (OSPS-AC-04.01), remediation automatically adds `permissions: {}` to each affected workflow. This is safe because `permissions: {}` is the most restrictive default — individual jobs already declare their own permissions.

**Acceptance Scenarios**:

1. **Given** a workflow with job-level permissions but no top-level `permissions:`, **When** remediation runs, **Then** `permissions: {}` is added at the workflow level and job-level permissions are untouched.
2. **Given** a workflow that already has `permissions:` at the top level, **When** remediation runs, **Then** the file is not modified (idempotent).
3. **Given** a workflow with no permissions at any level, **When** remediation runs, **Then** `permissions: {}` is added at the top level.

---

### Edge Cases

- No recognizable language -> Fall back to generic templates with a note suggesting manual customization.
- Uncommon CI actions -> Extract action names as-is; don't try to map every action.
- Docs contradict each other (e.g., README says MIT, pyproject.toml says Apache-2.0) -> Flag the inconsistency.
- No `.github/workflows/` -> Generate policy docs with recommended tools, noting CI should be set up.
- Sensitive information in existing files -> Never copy into generated files. Use generic references.
- Multi-language repos -> Include commands for all detected languages.
- Canonical source file doesn't exist yet -> Generate both in the correct order.
- Remediation creates CI workflows AND policy docs in same run -> Templates use `${var|default}` fallback for sibling knowledge.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: MUST scan repo for existing docs and cross-reference in generated files.
- **FR-002**: MUST detect all project languages and include idiomatic commands for each.
- **FR-003**: MUST scan `.github/workflows/` for specific tools and name them in policy docs.
- **FR-004**: MUST scan actual directory structure and use real paths in ARCHITECTURE.md.
- **FR-005**: MUST identify dependency update tool and name it specifically.
- **FR-006**: MUST extract doc links from README.md and include in SUPPORT.md.
- **FR-007**: Deterministic files MUST be generated without LLM involvement.
- **FR-008**: MUST support optional LLM enhancement via `enhance_with_llm` parameter.
- **FR-009**: Without LLM, files MUST still contain real project data — never fake placeholders.
- **FR-010**: Template system MUST support `${scan.*}` namespace for repo-scanned variables.
- **FR-011**: MUST extract and incorporate context from existing docs.
- **FR-012**: MUST NOT copy sensitive values into generated files.
- **FR-013**: MUST flag inconsistencies between project files.
- **FR-014**: MUST gracefully fall back to generic templates when no scan data available.
- **FR-015**: Generated files MUST NOT duplicate project metadata that has a canonical source in another file. Each piece of data MUST have exactly one canonical file, all others MUST reference it.
- **FR-016**: Templates MUST use `${context.security_contact}` for security contact, not hardcoded patterns.
- **FR-017**: Policy templates MUST have built-in fallback knowledge via `${var|default}` syntax for tools installed by sibling workflow templates (chicken-and-egg).
- **FR-018**: MUST support auto-fixing workflows missing top-level `permissions:` by injecting `permissions: {}` (safe, idempotent, only restricts).

### Key Entities

- **RepoScanContext**: Collected context from scanning a repository.
- **CanonicalSourceMap**: Mapping from data type to its canonical file.
- **SiblingTemplateKnowledge**: Mapping from policy templates to tools their sibling workflow templates install.

## Success Criteria *(mandatory)*

- **SC-001**: Zero placeholder/TODO comments for discoverable information.
- **SC-002**: ARCHITECTURE.md contains only real directory paths.
- **SC-003**: Policy docs name specific tools — zero generic references when detectable.
- **SC-004**: Community docs link to all relevant existing docs.
- **SC-005**: Language-idiomatic commands in 100% of generated docs.
- **SC-006**: Deterministic file generation completes without LLM calls.
- **SC-007**: 80%+ of deterministic files mergeable without manual edits.
- **SC-008**: Repos with no detectable language still receive valid docs.
- **SC-009**: No metadata embedded beyond its canonical file(s). Verified by: grep for `${context.maintainers}` in templates — only in codeowners_template and maintainers_template.
- **SC-010**: OSPS-AC-04.01 auto-remediated. Zero false modifications to workflows that already have top-level permissions.

## Clarifications

### Session 2026-04-05

- Q: How does the user trigger LLM enhancement? -> A: `enhance_with_llm=True` on `remediate_audit_findings`.
- Q: Multi-language repos? -> A: Include all detected languages.
- Q: Non-GitHub CI? -> A: GitHub Actions only for now.
- Q: Why not embed maintainer names everywhere? -> A: Drift risk. Single canonical source + references keeps docs consistent.
- Q: Why auto-fix workflow permissions? -> A: `permissions: {}` only restricts. Jobs already declare their own. Safe and idempotent.
- Q: Chicken-and-egg with CI tool detection? -> A: `${var|default}` syntax — sast_policy_template has `${scan.ci_sast_tools|CodeQL}` fallback.

## Assumptions

- `${scan.*}` namespace extends existing template system without breaking it.
- Language detection from manifest files is reliable enough.
- CI workflows follow standard GitHub Actions YAML structure.
- `RemediationExecutor` supports pre-rendering scan phase.
- Adding `permissions: {}` is always safe when jobs already declare their own permissions.
