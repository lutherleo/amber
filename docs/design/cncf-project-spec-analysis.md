# CNCF .project Spec Analysis for OpenSSF Baseline

**Date**: 2025-12-19
**Status**: Design Analysis
**Context**: Evaluating migration from `project.toml` to CNCF `.project` specification

---

## Executive Summary

The CNCF `.project` specification (PR #116, merged 2025-12-16) provides a standardized repository structure for CNCF projects. This document analyzes compatibility with OpenSSF Baseline compliance requirements and identifies gaps that should be addressed with the CNCF team.

---

## 1. Current project.toml Schema (baseline-mcp)

### Structure Overview

```toml
schema_version = "0.1"

[project]
name = "project-name"
type = "software|specification|documentation|infrastructure|data"
description = "..."

[project.controls]
"OSPS-XX-YY.ZZ" = { status = "n/a", reason = "..." }

[security]
policy = "SECURITY.md"
threat_model = { path = "docs/THREAT_MODEL.md" }
advisories = { url = "https://..." }

[governance]
maintainers = "MAINTAINERS.md"
contributing = "CONTRIBUTING.md"
code_of_conduct = "CODE_OF_CONDUCT.md"
codeowners = "CODEOWNERS"
governance_doc = "GOVERNANCE.md"

[legal]
license = "LICENSE"
contributor_agreement = { type = "dco", url = "..." }

[artifacts]
sbom = { path = "sbom.json", format = "cyclonedx" }
signing = { enabled = true, method = "sigstore" }
provenance = { path = ".attestations/" }

[quality]
changelog = "CHANGELOG.md"

[documentation]
readme = "README.md"
support = "SUPPORT.md"
architecture = "docs/ARCHITECTURE.md"
api = "docs/API.md"

[dependencies]
lockfile = "package-lock.json"
manifest = "package.json"

[testing]
docs = "docs/TESTING.md"

[releases]
docs = "docs/RELEASING.md"

[ci]
provider = "github"
[ci.github]
workflows = [".github/workflows/ci.yml"]
dependabot = ".github/dependabot.yml"
```

### Key Features

1. **Resource References**: Flexible path/url/repo/section/n-a reference types
2. **Control Overrides**: Per-control N/A status with reasoning
3. **Project Type Exclusions**: Automatic control exclusion by project type
4. **CI/CD Discovery**: GitHub Actions workflow analysis
5. **Metadata Expansion**: format, type, enabled, method attributes

---

## 2. CNCF .project Spec Schema

### Structure Overview (from types.go)

```go
type Project struct {
    Name              string
    Description       string
    SchemaVersion     string
    Type              string
    MaturityLog       []MaturityEntry      // CNCF-specific
    Repositories      []string
    Social            map[string]string    // twitter, slack, youtube, etc.
    Artwork           string
    Website           string
    MailingLists      []string
    Audits            []Audit
    Security          *SecurityConfig
    Governance        *GovernanceConfig
    Legal             *LegalConfig
    Documentation     *DocumentationConfig
}

type SecurityConfig struct {
    Policy      *PathRef
    ThreatModel *PathRef
    Contact     string    // email
}

type GovernanceConfig struct {
    Contributing  *PathRef
    Codeowners    *PathRef
    GovernanceDoc *PathRef
    GitVoteConfig *PathRef
}

type LegalConfig struct {
    License *PathRef
}

type DocumentationConfig struct {
    Readme       *PathRef
    Support      *PathRef
    Architecture *PathRef
    API          *PathRef
}

type PathRef struct {
    Path string
}

type MaturityEntry struct {
    Phase string     // sandbox, incubating, graduated
    Date  time.Time
    Issue string     // link to maturity issue
}

type Audit struct {
    Date time.Time
    Type string
    URL  string
}
```

### Current Validations

- Required: `name`, `description`, `maturity_log[]`, `repositories[]`
- URL validation for all URL fields
- Email validation for security contact
- Non-empty path validation for optional sections
- SHA256 content drift detection

---

## 3. Capability Comparison Matrix

| Capability | project.toml | .project spec | Gap Analysis |
|------------|--------------|---------------|--------------|
| **Basic Metadata** |
| Project name | ✅ | ✅ | Equivalent |
| Description | ✅ | ✅ | Equivalent |
| Project type | ✅ (5 types) | ✅ | Need to align type values |
| Schema version | ✅ | ✅ | Equivalent |
| **Security** |
| Security policy path | ✅ | ✅ | Equivalent |
| Threat model path | ✅ | ✅ | Equivalent |
| Security contact | ❌ | ✅ (email) | **Add to baseline** |
| Security advisories URL | ✅ | ❌ | **Request addition** |
| **Governance** |
| CONTRIBUTING path | ✅ | ✅ | Equivalent |
| CODEOWNERS path | ✅ | ✅ | Equivalent |
| GOVERNANCE doc path | ✅ | ✅ | Equivalent |
| MAINTAINERS path | ✅ | ❌ | **Request addition** |
| CODE_OF_CONDUCT path | ✅ | ❌ | **Request addition** |
| GitVote config | ❌ | ✅ | Consider adding |
| **Legal** |
| License path | ✅ | ✅ | Equivalent |
| DCO/CLA type | ✅ | ❌ | **Request addition** |
| Contributor agreement URL | ✅ | ❌ | **Request addition** |
| **Documentation** |
| README path | ✅ | ✅ | Equivalent |
| SUPPORT path | ✅ | ✅ | Equivalent |
| Architecture docs | ✅ | ✅ | Equivalent |
| API docs | ✅ | ✅ | Equivalent |
| CHANGELOG path | ✅ | ❌ | **Request addition** |
| **Artifacts & Build** |
| SBOM path + format | ✅ | ❌ | **Request addition** |
| Signing config | ✅ | ❌ | **Request addition** |
| Provenance path | ✅ | ❌ | **Request addition** |
| **Dependencies** |
| Lockfile path | ✅ | ❌ | **Request addition** |
| Manifest path | ✅ | ❌ | Lower priority |
| **Testing** |
| Test docs path | ✅ | ❌ | Lower priority |
| **Releases** |
| Release docs path | ✅ | ❌ | Lower priority |
| **CI/CD** |
| Provider | ✅ | ❌ | **Request addition** |
| Workflow paths | ✅ | ❌ | **Request addition** |
| Dependabot config | ✅ | ❌ | **Request addition** |
| **Control Management** |
| Per-control N/A status | ✅ | ❌ | **Critical gap** |
| N/A reasoning | ✅ | ❌ | **Critical gap** |
| **CNCF-Specific** |
| Maturity log | ❌ | ✅ | CNCF-specific, N/A |
| Repositories list | partial | ✅ | Consider adding |
| Social links | ❌ | ✅ | Nice-to-have |
| Website | ❌ | ✅ | Nice-to-have |
| Mailing lists | ❌ | ✅ | Nice-to-have |
| Artwork | ❌ | ✅ | CNCF-specific |
| Audits array | ❌ | ✅ | **Useful for compliance** |
| **Reference Types** |
| Simple path string | ✅ | ✅ | Equivalent |
| URL reference | ✅ | ❌ | **Request addition** |
| Cross-repo reference | ✅ | ❌ | **Request addition** |
| Section reference | ✅ | ❌ | Nice-to-have |
| N/A status + reason | ✅ | ❌ | **Critical for compliance** |
| Format metadata | ✅ | ❌ | Useful for SBOM |
| Enabled boolean | ✅ | ❌ | Useful for signing |

---

## 4. Gap Analysis for OpenSSF Baseline Compliance

### Critical Gaps (Must Request)

These are essential for OpenSSF Baseline compliance checking:

#### 4.1 Control Override Mechanism
**Gap**: No way to mark controls as N/A with reasoning
**Use Case**: Projects that legitimately don't need certain controls (e.g., specifications don't need SBOM)
**Proposed Addition**:
```yaml
controls:
  OSPS-BR-02.01:
    status: n/a
    reason: "Specification project - no distributable artifacts"
```

#### 4.2 MAINTAINERS Reference
**Gap**: No `governance.maintainers` field
**Use Case**: OSPS-GV-01.01 requires documented project maintainers
**Proposed Addition**: `governance.maintainers` with PathRef

#### 4.3 CODE_OF_CONDUCT Reference
**Gap**: No `governance.code_of_conduct` field
**Use Case**: OSPS-GV-01.02 requires code of conduct
**Proposed Addition**: `governance.code_of_conduct` with PathRef

#### 4.4 CHANGELOG Reference
**Gap**: No changelog documentation reference
**Use Case**: OSPS-DO-01.01 requires changelog
**Proposed Addition**: `documentation.changelog` or `quality.changelog` with PathRef

#### 4.5 Security Advisories
**Gap**: No security advisories URL
**Use Case**: OSPS-VM-02.01 requires advisories publishing mechanism
**Proposed Addition**: `security.advisories` (URL or path)

### High Priority Gaps (Should Request)

#### 4.6 Artifacts Section
**Gap**: No artifacts/build output references
**Use Case**: OSPS-BR-02 (SBOM), OSPS-BR-03 (signing/provenance)
**Proposed Addition**:
```yaml
artifacts:
  sbom:
    path: "sbom.json"
    format: "cyclonedx|spdx"
  signing:
    enabled: true
    method: "sigstore"
  provenance:
    path: ".attestations/"
```

#### 4.7 Contributor Agreement
**Gap**: No DCO/CLA configuration
**Use Case**: OSPS-LE-01.01 requires contributor licensing
**Proposed Addition**:
```yaml
legal:
  license:
    path: "LICENSE"
  contributor_agreement:
    type: "dco|cla"
    url: "https://..."  # optional
```

#### 4.8 CI/CD Section
**Gap**: No CI/CD configuration references
**Use Case**: Multiple controls check for CI/CD presence and configuration
**Proposed Addition**:
```yaml
ci:
  provider: "github|gitlab|jenkins|..."
  workflows:
    - ".github/workflows/ci.yml"
  dependency_scanning: ".github/dependabot.yml"
```

### Medium Priority Gaps (Nice to Have)

#### 4.9 URL and Cross-Repo References
**Gap**: PathRef only supports simple paths
**Use Case**: Resources hosted externally or in other repos
**Proposed Addition**:
```yaml
# Expand PathRef to ResourceRef:
security:
  policy:
    path: "SECURITY.md"  # local
  # OR
  advisories:
    url: "https://github.com/org/repo/security/advisories"
  # OR
  common_policy:
    repo: "org/.github"
    path: "SECURITY.md"
    ref: "main"
```

#### 4.10 Dependencies Section
**Gap**: No dependency management references
**Use Case**: OSPS-VM-05 controls check dependency management
**Proposed Addition**:
```yaml
dependencies:
  lockfile: "package-lock.json"
  manifest: "package.json"
```

---

## 5. What We Can Use Today

The following .project fields align well with current needs:

| .project Field | Maps To | Baseline Control |
|----------------|---------|------------------|
| `name` | project.name | General |
| `description` | project.description | General |
| `type` | project.type | Type exclusions |
| `security.policy` | security.policy | OSPS-DO-02.01 |
| `security.threat_model` | security.threat_model | OSPS-SA-03.02 |
| `security.contact` | (new) | OSPS-VM-01.01 |
| `governance.contributing` | governance.contributing | OSPS-DO-01.02 |
| `governance.codeowners` | governance.codeowners | OSPS-GV-01.01 |
| `governance.governance_doc` | governance.governance_doc | OSPS-GV-01.02 |
| `legal.license` | legal.license | OSPS-LI-01.01 |
| `documentation.readme` | documentation.readme | OSPS-DO-01.03 |
| `documentation.support` | documentation.support | OSPS-DO-03.01 |
| `documentation.architecture` | documentation.architecture | Documentation |
| `documentation.api` | documentation.api | Documentation |
| `audits[]` | (new - useful!) | OSPS-SA-02.01 |

### Bonus: Audits Array

The `.project` audits array is actually useful for compliance:
```yaml
audits:
  - date: 2024-01-15
    type: "security"
    url: "https://..."
  - date: 2024-06-01
    type: "performance"
    url: "https://..."
```

This could help verify OSPS-SA-02.01 (security audit requirements).

---

## 6. Implementation Strategy

### Approach: Native .project.yaml with Extension Schema

Clean implementation using CNCF `.project.yaml` as the base with `x-openssf-baseline`
extension for Baseline-specific fields not yet in the standard.

### 6.1 Complete Schema Design

```yaml
# =============================================================================
# CNCF .project Standard Fields
# =============================================================================
name: "my-project"
description: "A project description"
schema_version: "1.0"
type: "software"  # software|specification|documentation|infrastructure|data

# CNCF maturity tracking (required for CNCF projects)
maturity_log:
  - phase: "sandbox"
    date: 2024-01-15
    issue: "https://github.com/cncf/toc/issues/123"

# Repository references
repositories:
  - "https://github.com/org/repo"
  - "https://github.com/org/repo-docs"

# Project presence
website: "https://project.io"
artwork: "https://github.com/cncf/artwork/tree/main/projects/myproject"

# Community channels
social:
  twitter: "https://twitter.com/myproject"
  slack: "https://slack.cncf.io"
  youtube: "https://youtube.com/@myproject"

mailing_lists:
  - "dev@myproject.io"
  - "users@myproject.io"

# Security documentation
security:
  policy:
    path: "SECURITY.md"
  threat_model:
    path: "docs/THREAT_MODEL.md"
  contact: "security@myproject.io"

# Governance documentation
governance:
  contributing:
    path: "CONTRIBUTING.md"
  codeowners:
    path: "CODEOWNERS"
  governance_doc:
    path: "GOVERNANCE.md"
  gitvote_config:
    path: ".gitvote.yml"

# Legal
legal:
  license:
    path: "LICENSE"

# Documentation
documentation:
  readme:
    path: "README.md"
  support:
    path: "SUPPORT.md"
  architecture:
    path: "docs/ARCHITECTURE.md"
  api:
    path: "docs/API.md"

# Security audits (useful for compliance!)
audits:
  - date: 2024-06-15
    type: "security"
    url: "https://example.com/audit-report.pdf"

# =============================================================================
# OpenSSF Baseline Extension (x-openssf-baseline)
# =============================================================================
x-openssf-baseline:
  # Extension schema version
  version: "1.0"

  # Target OSPS specification version
  osps_version: "v2025.10.10"

  # Control overrides - mark controls as N/A with reasoning
  controls:
    OSPS-BR-02.01:
      status: n/a
      reason: "Specification project - no distributable artifacts"
    OSPS-BR-03.01:
      status: n/a
      reason: "Specification project - no releases to sign"

  # Fields missing from CNCF spec (to be upstreamed)
  governance:
    maintainers:
      path: "MAINTAINERS.md"
    code_of_conduct:
      path: "CODE_OF_CONDUCT.md"

  quality:
    changelog:
      path: "CHANGELOG.md"

  # Build artifacts
  artifacts:
    sbom:
      path: "sbom.json"
      format: "cyclonedx"  # cyclonedx|spdx
    signing:
      enabled: true
      method: "sigstore"
    provenance:
      path: ".attestations/"
      format: "slsa"

  # Contributor licensing
  legal:
    contributor_agreement:
      type: "dco"  # dco|cla|none
      url: "https://developercertificate.org/"

  # Security advisories
  security:
    advisories:
      url: "https://github.com/org/repo/security/advisories"

  # Dependency management
  dependencies:
    lockfile: "uv.lock"
    manifest: "pyproject.toml"

  # CI/CD configuration
  ci:
    provider: "github"
    workflows:
      - ".github/workflows/ci.yml"
      - ".github/workflows/release.yml"
    dependency_scanning: ".github/dependabot.yml"
    security_scanning:
      - ".github/workflows/codeql.yml"
```

### 6.2 Field Resolution Logic

When checking controls, fields resolve in this order:

1. **Standard .project fields** (if available)
2. **Extension fields** (`x-openssf-baseline.*`)
3. **Auto-discovery** (scan filesystem for common locations)

```python
def get_security_policy(config: ProjectConfig) -> Optional[str]:
    """Get security policy path with fallback chain."""
    # 1. Standard field
    if config.security and config.security.policy:
        return config.security.policy.path

    # 2. Extension field (not needed for this - it's in standard)

    # 3. Auto-discovery
    for path in ["SECURITY.md", ".github/SECURITY.md"]:
        if os.path.exists(os.path.join(config.local_path, path)):
            return path

    return None

def get_maintainers(config: ProjectConfig) -> Optional[str]:
    """Get maintainers path - requires extension until upstreamed."""
    # 1. Not in standard spec

    # 2. Extension field
    ext = config.extensions.get("x-openssf-baseline", {})
    if gov := ext.get("governance", {}):
        if maintainers := gov.get("maintainers"):
            return maintainers.get("path")

    # 3. Auto-discovery
    for path in ["MAINTAINERS.md", "MAINTAINERS"]:
        if os.path.exists(os.path.join(config.local_path, path)):
            return path

    return None
```

### 6.3 Upstream Strategy

Track which extension fields should be proposed upstream:

| Extension Field | Priority | Upstream Status |
|-----------------|----------|-----------------|
| `governance.maintainers` | P1 | Propose immediately |
| `governance.code_of_conduct` | P1 | Propose immediately |
| `quality.changelog` | P1 | Propose immediately |
| `security.advisories` | P1 | Propose immediately |
| `artifacts.*` | P2 | Propose after P1 |
| `legal.contributor_agreement` | P2 | Propose after P1 |
| `ci.*` | P3 | Lower priority |
| `dependencies.*` | P3 | Lower priority |
| `controls.*` | Special | Keep as extension |

**Note**: Control overrides (`controls.*`) should likely remain as an extension
since they're specific to compliance checking tools, not general project metadata.

---

## 7. Implementation Plan

### 7.1 Files to Modify

```
packages/darnit/src/darnit/config/
├── models.py          # Replace ProjectConfig with new YAML-based model
├── loader.py          # Replace TOML loading with YAML loading
├── discovery.py       # Update to work with new model
└── schema.py          # NEW: Pydantic models for .project.yaml

packages/darnit-baseline/src/darnit_baseline/config/
└── mappings.py        # Update control mappings for new field paths
```

### 7.2 New Data Models (schema.py)

```python
"""Pydantic models for CNCF .project.yaml schema."""

from datetime import date
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, HttpUrl, EmailStr


class PathRef(BaseModel):
    """Reference to a file path."""
    path: str


class MaturityEntry(BaseModel):
    """CNCF maturity phase entry."""
    phase: str  # sandbox, incubating, graduated
    date: date
    issue: HttpUrl


class Audit(BaseModel):
    """Security or compliance audit record."""
    date: date
    type: str  # security, performance, compliance
    url: HttpUrl


class SecurityConfig(BaseModel):
    """Security documentation references."""
    policy: Optional[PathRef] = None
    threat_model: Optional[PathRef] = None
    contact: Optional[EmailStr] = None


class GovernanceConfig(BaseModel):
    """Governance documentation references."""
    contributing: Optional[PathRef] = None
    codeowners: Optional[PathRef] = None
    governance_doc: Optional[PathRef] = None
    gitvote_config: Optional[PathRef] = None


class LegalConfig(BaseModel):
    """Legal documentation references."""
    license: Optional[PathRef] = None


class DocumentationConfig(BaseModel):
    """Project documentation references."""
    readme: Optional[PathRef] = None
    support: Optional[PathRef] = None
    architecture: Optional[PathRef] = None
    api: Optional[PathRef] = None


# =============================================================================
# OpenSSF Baseline Extension Models
# =============================================================================

class ControlOverride(BaseModel):
    """Override status for a specific control."""
    status: str  # n/a, enabled, disabled
    reason: Optional[str] = None


class ArtifactConfig(BaseModel):
    """Build artifact configuration."""
    path: Optional[str] = None
    format: Optional[str] = None  # cyclonedx, spdx, slsa
    enabled: Optional[bool] = None
    method: Optional[str] = None  # sigstore


class ContributorAgreement(BaseModel):
    """Contributor licensing configuration."""
    type: str  # dco, cla, none
    url: Optional[HttpUrl] = None


class CIConfig(BaseModel):
    """CI/CD configuration references."""
    provider: Optional[str] = None  # github, gitlab, jenkins
    workflows: List[str] = Field(default_factory=list)
    dependency_scanning: Optional[str] = None
    security_scanning: List[str] = Field(default_factory=list)


class BaselineExtension(BaseModel):
    """OpenSSF Baseline extension schema (x-openssf-baseline)."""
    version: str = "1.0"
    osps_version: Optional[str] = None

    # Control overrides
    controls: Dict[str, ControlOverride] = Field(default_factory=dict)

    # Extended governance (not in CNCF spec yet)
    governance: Optional[Dict[str, PathRef]] = None  # maintainers, code_of_conduct

    # Quality tracking
    quality: Optional[Dict[str, PathRef]] = None  # changelog

    # Build artifacts
    artifacts: Optional[Dict[str, ArtifactConfig]] = None  # sbom, signing, provenance

    # Extended legal
    legal: Optional[Dict[str, Any]] = None  # contributor_agreement

    # Extended security
    security: Optional[Dict[str, Any]] = None  # advisories

    # Dependencies
    dependencies: Optional[Dict[str, str]] = None  # lockfile, manifest

    # CI/CD
    ci: Optional[CIConfig] = None


# =============================================================================
# Main Project Config
# =============================================================================

class ProjectConfig(BaseModel):
    """
    Complete .project.yaml configuration.

    Combines CNCF standard fields with OpenSSF Baseline extension.
    """
    # Core metadata (CNCF standard)
    name: str
    description: str
    schema_version: str = "1.0"
    type: str = "software"

    # CNCF-specific
    maturity_log: List[MaturityEntry] = Field(default_factory=list)
    repositories: List[HttpUrl] = Field(default_factory=list)
    website: Optional[HttpUrl] = None
    artwork: Optional[HttpUrl] = None
    social: Dict[str, HttpUrl] = Field(default_factory=dict)
    mailing_lists: List[str] = Field(default_factory=list)

    # Documentation sections (CNCF standard)
    security: Optional[SecurityConfig] = None
    governance: Optional[GovernanceConfig] = None
    legal: Optional[LegalConfig] = None
    documentation: Optional[DocumentationConfig] = None
    audits: List[Audit] = Field(default_factory=list)

    # OpenSSF Baseline extension
    x_openssf_baseline: Optional[BaselineExtension] = Field(
        default=None,
        alias="x-openssf-baseline"
    )

    # Internal tracking
    config_path: Optional[str] = Field(default=None, exclude=True)
    local_path: Optional[str] = Field(default=None, exclude=True)

    class Config:
        populate_by_name = True  # Allow both alias and field name

    # ==========================================================================
    # Convenience accessors with fallback chain
    # ==========================================================================

    def get_path(self, section: str, field: str) -> Optional[str]:
        """Get a path reference with extension fallback."""
        # Try standard section first
        std_section = getattr(self, section, None)
        if std_section:
            ref = getattr(std_section, field, None)
            if ref and hasattr(ref, 'path'):
                return ref.path

        # Try extension
        if self.x_openssf_baseline:
            ext_section = getattr(self.x_openssf_baseline, section, None)
            if isinstance(ext_section, dict) and field in ext_section:
                ref = ext_section[field]
                if isinstance(ref, dict):
                    return ref.get('path')
                elif hasattr(ref, 'path'):
                    return ref.path

        return None

    def is_control_applicable(self, control_id: str) -> tuple[bool, Optional[str]]:
        """Check if control is applicable (not overridden as N/A)."""
        if not self.x_openssf_baseline:
            return True, None

        override = self.x_openssf_baseline.controls.get(control_id)
        if override and override.status == "n/a":
            return False, override.reason

        return True, None
```

### 7.3 Updated Loader (loader.py)

```python
"""Configuration loading for .project.yaml files."""

import os
from typing import Optional
import yaml

from darnit.config.schema import ProjectConfig, BaselineExtension
from darnit.core.logging import get_logger

logger = get_logger("config.loader")

# Config locations in priority order
CONFIG_LOCATIONS = [
    ".project.yaml",
    ".project.yml",
    ".project/project.yaml",
    ".project/project.yml",
]


def load_project_config(local_path: str) -> Optional[ProjectConfig]:
    """
    Load .project.yaml from the given path.
    Returns None if no config file exists.
    """
    config_path = None
    for location in CONFIG_LOCATIONS:
        full_path = os.path.join(local_path, location)
        if os.path.exists(full_path):
            config_path = full_path
            break

    if not config_path:
        return None

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if not data:
            return None

        config = ProjectConfig.model_validate(data)
        config.config_path = config_path
        config.local_path = local_path
        return config

    except (IOError, OSError, yaml.YAMLError) as e:
        logger.warning(f"Failed to load {config_path}: {e}")
        return None
    except Exception as e:
        logger.warning(f"Invalid config in {config_path}: {e}")
        return None


def save_project_config(config: ProjectConfig, local_path: str) -> str:
    """Save project configuration to .project.yaml."""
    config_path = config.config_path or os.path.join(local_path, ".project.yaml")

    # Export with alias (x-openssf-baseline not x_openssf_baseline)
    data = config.model_dump(by_alias=True, exclude_none=True)

    with open(config_path, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    return config_path


def init_project_config(
    local_path: str,
    name: Optional[str] = None,
    project_type: str = "software"
) -> ProjectConfig:
    """Initialize a new .project.yaml with discovered values."""
    from darnit.config.discovery import discover_project_name

    return ProjectConfig(
        name=name or discover_project_name(local_path) or "unnamed",
        description="",
        type=project_type,
        local_path=local_path,
        x_openssf_baseline=BaselineExtension(version="1.0")
    )
```

### 7.4 Migration Checklist

- [ ] Create `schema.py` with Pydantic models
- [ ] Update `loader.py` for YAML loading
- [ ] Update `discovery.py` to work with new model
- [ ] Update `mappings.py` control → field mappings
- [ ] Update all control checks to use new accessors
- [ ] Update remediation tools to generate .project.yaml
- [ ] Update MCP tool handlers
- [ ] Add migration command for any existing project.toml files
- [ ] Update documentation and examples
- [ ] Add JSON Schema export for editor validation

### 7.5 Dependencies

Add to `pyproject.toml`:
```toml
dependencies = [
    "pydantic>=2.0",
    "pyyaml>=6.0",
    # Remove tomli/tomllib dependency
]
```

---

## 8. Recommendations for CNCF Team

### Priority 1: Critical for Compliance

| Field | Justification |
|-------|---------------|
| `governance.maintainers` | OSPS-GV-01.01 requires documented maintainers |
| `governance.code_of_conduct` | OSPS-GV-01.02 requires code of conduct |
| `documentation.changelog` or `quality.changelog` | OSPS-DO-01.01 requires changelog |
| `security.advisories` | OSPS-VM-02.01 requires advisories mechanism |

### Priority 2: High Value for Supply Chain Security

| Field | Justification |
|-------|---------------|
| `artifacts.sbom` | OSPS-BR-02.01 - SBOM with format metadata |
| `artifacts.signing` | OSPS-BR-03.01 - Release signing config |
| `artifacts.provenance` | OSPS-BR-03.02 - Provenance attestations |
| `legal.contributor_agreement` | OSPS-LE-01.01 - DCO/CLA tracking |

### Priority 3: Nice to Have

| Field | Justification |
|-------|---------------|
| `ci.provider` | CI/CD platform identification |
| `ci.dependency_scanning` | Dependabot/Renovate config location |
| `dependencies.lockfile` | Package lockfile location |
| URL references in PathRef | External resource support |

### Proposed PR for CNCF

```yaml
# Proposed additions to .project schema

governance:
  # Existing
  contributing: { path: "CONTRIBUTING.md" }
  codeowners: { path: "CODEOWNERS" }
  governance_doc: { path: "GOVERNANCE.md" }
  # NEW
  maintainers: { path: "MAINTAINERS.md" }
  code_of_conduct: { path: "CODE_OF_CONDUCT.md" }

documentation:
  # Existing
  readme: { path: "README.md" }
  support: { path: "SUPPORT.md" }
  # NEW
  changelog: { path: "CHANGELOG.md" }

security:
  # Existing
  policy: { path: "SECURITY.md" }
  threat_model: { path: "docs/THREAT_MODEL.md" }
  contact: "security@example.com"
  # NEW
  advisories: "https://github.com/org/repo/security/advisories"

legal:
  # Existing
  license: { path: "LICENSE" }
  # NEW
  contributor_agreement:
    type: "dco"  # dco|cla|none
    url: "https://developercertificate.org/"
```

---

## 9. Appendix: Control to Field Mapping

| OSPS Control | Required Field | .project Status |
|--------------|----------------|-----------------|
| OSPS-AC-01.01 | (API check) | N/A |
| OSPS-AC-02.01 | (API check) | N/A |
| OSPS-AC-03.01 | (API check) | N/A |
| OSPS-DO-01.01 | documentation.changelog | **Missing** |
| OSPS-DO-01.02 | governance.contributing | ✅ Available |
| OSPS-DO-01.03 | documentation.readme | ✅ Available |
| OSPS-DO-02.01 | security.policy | ✅ Available |
| OSPS-DO-03.01 | documentation.support | ✅ Available |
| OSPS-GV-01.01 | governance.maintainers | **Missing** |
| OSPS-GV-01.02 | governance.code_of_conduct | **Missing** |
| OSPS-LI-01.01 | legal.license | ✅ Available |
| OSPS-LE-01.01 | legal.contributor_agreement | **Missing** |
| OSPS-SA-02.01 | audits[] | ✅ Available |
| OSPS-SA-03.02 | security.threat_model | ✅ Available |
| OSPS-VM-01.01 | security.contact | ✅ Available |
| OSPS-VM-02.01 | security.advisories | **Missing** |
| OSPS-BR-02.01 | artifacts.sbom | **Missing** |
| OSPS-BR-03.01 | artifacts.signing | **Missing** |
| OSPS-BR-03.02 | artifacts.provenance | **Missing** |
