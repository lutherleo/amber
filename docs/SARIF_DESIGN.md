# SARIF Output Design for OpenSSF Baseline Audits

This document specifies the design for SARIF (Static Analysis Results Interchange Format) output from the OpenSSF Baseline MCP server, enabling integration with GitHub Code Scanning and other SARIF-compatible tools.

## Overview

SARIF 2.1.0 is an OASIS standard format for static analysis results. Implementing proper SARIF output enables:

- GitHub Code Scanning integration with alert tracking
- IDE integration (VS Code, JetBrains)
- CI/CD pipeline integration
- Unified security dashboard visibility

## Current State

The existing SARIF implementation (`main.py:308-331`) is minimal:

```python
sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "openssf-baseline-audit",
                "version": "0.1.0",
                "informationUri": "https://baseline.openssf.org/"
            }
        },
        "results": [
            {
                "ruleId": r["id"],
                "level": "error" if r["status"] == "FAIL" else "warning",
                "message": {"text": r.get("details", "")},
            }
            for r in audit_result.all_results
        ]
    }]
}
```

### Gap Analysis

| Element | Current | Required | Impact |
|---------|---------|----------|--------|
| Rules array | ❌ Missing | ✅ Full rule definitions | No filtering in GitHub UI |
| Locations | ❌ Missing | ✅ File paths, line numbers | Alerts not linked to code |
| Fingerprints | ❌ Missing | ✅ Alert deduplication | Duplicate alerts on re-scan |
| Security severity | ❌ Missing | ✅ 0.1-10.0 score | No severity sorting |
| Tags | ❌ Missing | ✅ Categorization | No domain filtering |
| Help text | ❌ Missing | ✅ Remediation guidance | No fix guidance in UI |

## SARIF 2.1.0 Specification Requirements

Based on the [OASIS SARIF 2.1.0 Standard](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) and [GitHub Code Scanning requirements](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning):

### Required Structure

```
SARIF File
├── $schema: JSON schema URL
├── version: "2.1.0"
└── runs[]: Array of analysis runs
    ├── tool.driver: Tool information
    │   ├── name: Tool identifier
    │   ├── version: Semantic version
    │   ├── informationUri: Documentation URL
    │   └── rules[]: Rule definitions
    ├── results[]: Analysis findings
    └── invocations[]: Execution metadata
```

### GitHub Code Scanning Limits

| Limit | Value |
|-------|-------|
| Runs per file | 20 |
| Results per run | 25,000 (displays top 5,000) |
| Rules per run | 25,000 |
| Locations per result | 1,000 (displays 100) |
| File size (gzip) | 10 MB |

## Proposed SARIF Structure

### Complete Example

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "openssf-baseline-audit",
        "version": "0.1.0",
        "informationUri": "https://baseline.openssf.org/",
        "rules": [
          {
            "id": "OSPS-AC-01.01",
            "name": "MFARequired",
            "shortDescription": {
              "text": "MFA required for repository access"
            },
            "fullDescription": {
              "text": "All project contributors with elevated permissions MUST use MFA for authentication"
            },
            "helpUri": "https://baseline.openssf.org/versions/2025-10-10#OSPS-AC-01.01",
            "help": {
              "text": "Enable MFA for all organization members with write access or higher.",
              "markdown": "Enable MFA for all organization members with write access or higher.\n\n**Remediation:**\n1. Go to Organization Settings → Security\n2. Enable 'Require two-factor authentication'"
            },
            "defaultConfiguration": {
              "level": "error"
            },
            "properties": {
              "tags": ["security", "access-control", "authentication", "OSPS-Level-1"],
              "precision": "high",
              "problem.severity": "error",
              "security-severity": "8.0"
            }
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "OSPS-AC-01.01",
        "ruleIndex": 0,
        "level": "error",
        "message": {
          "text": "MFA is not enabled for all organization members with elevated permissions"
        },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {
              "uri": ".github/settings.yml",
              "uriBaseId": "%SRCROOT%"
            },
            "region": {
              "startLine": 1,
              "startColumn": 1
            }
          }
        }],
        "partialFingerprints": {
          "primaryLocationLineHash": "abc123def456"
        },
        "fixes": [{
          "description": {
            "text": "Enable organization MFA requirement"
          }
        }]
      }
    ],
    "invocations": [{
      "executionSuccessful": true,
      "endTimeUtc": "2024-01-15T10:30:00Z"
    }],
    "properties": {
      "owner": "example-org",
      "repo": "example-repo",
      "level": 3,
      "compliance": {
        "level1": true,
        "level2": false,
        "level3": false
      },
      "summary": {
        "pass": 53,
        "fail": 2,
        "warn": 0,
        "na": 7,
        "error": 0,
        "total": 62
      }
    }
  }]
}
```

## Design Decisions

### 1. Rule Definitions

Each of the 61 OSPS controls maps to a SARIF rule:

| SARIF Property | Source |
|----------------|--------|
| `id` | Control ID (e.g., `OSPS-AC-01.01`) |
| `name` | PascalCase derived from control title |
| `shortDescription.text` | Control title |
| `fullDescription.text` | Control requirement text |
| `helpUri` | `https://baseline.openssf.org/versions/2025-10-10#<id>` |
| `help.markdown` | Remediation guidance |
| `defaultConfiguration.level` | Based on typical failure severity |
| `properties.tags` | Domain code + level + keywords |
| `properties.security-severity` | Numeric score (see below) |

### 2. Security Severity Mapping

SARIF security-severity uses a 0.1-10.0 scale. Mapping by OSPS level:

| OSPS Level | Severity Range | Rationale |
|------------|----------------|-----------|
| Level 1 | 8.0 - 10.0 | Critical security hygiene |
| Level 2 | 5.0 - 7.9 | Enhanced security controls |
| Level 3 | 2.0 - 4.9 | Advanced security practices |

Status-based adjustment:
- **FAIL**: Full severity value
- **WARN**: Severity × 0.7
- **N/A**: Excluded from results (or severity 0)

### 3. SARIF Level Mapping

| Check Status | SARIF Level | Display |
|--------------|-------------|---------|
| FAIL | `error` | 🔴 Error |
| WARN | `warning` | 🟡 Warning |
| PASS | `note` | ℹ️ Note (if included) |
| N/A | `none` | Excluded by default |
| ERROR | `error` | 🔴 Error |

### 4. Location Mapping

Controls map to specific file locations for code linking:

| Control Domain | Location Pattern | Example |
|----------------|------------------|---------|
| AC (Access Control) | `.github/settings.yml` | Branch protection |
| BR (Build & Release) | `.github/workflows/*.yml` | CI/CD workflows |
| DO (Documentation) | `SECURITY.md`, `README.md` | Security policy |
| GV (Governance) | `LICENSE`, `CODEOWNERS` | Project governance |
| LE (Legal) | `LICENSE` | License file |
| QA (Quality) | `.github/workflows/*.yml` | Test workflows |
| SA (Security Analysis) | `.github/workflows/*.yml` | Security scanning |
| VM (Vulnerability) | `SECURITY.md` | Vuln disclosure |

Default fallback: Repository root (line 1, column 1)

### 5. Fingerprinting Strategy

Fingerprints enable alert persistence across scans:

```python
import hashlib

def generate_fingerprint(control_id: str, repo: str, status: str) -> str:
    """Generate stable fingerprint for alert deduplication."""
    content = f"{control_id}:{repo}:{status}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]
```

### 6. Tags Structure

Each rule includes tags for filtering:

```json
"properties": {
  "tags": [
    "security",           // Always included
    "access-control",     // Domain-specific
    "authentication",     // Control-specific keywords
    "OSPS-Level-1"        // Maturity level
  ]
}
```

Domain tag mapping:
| Domain | Tags |
|--------|------|
| AC | `access-control`, `authentication`, `authorization` |
| BR | `build`, `release`, `ci-cd`, `supply-chain` |
| DO | `documentation`, `security-policy` |
| GV | `governance`, `maintainership` |
| LE | `legal`, `licensing` |
| QA | `quality`, `testing`, `code-review` |
| SA | `security-analysis`, `scanning`, `sast` |
| VM | `vulnerability`, `disclosure`, `patching` |

## Implementation Architecture

### Module Structure

```
baseline_mcp/
└── formatters/
    ├── __init__.py
    ├── sarif.py           # SARIF generation
    ├── markdown.py        # Markdown formatting (existing)
    └── rules_catalog.py   # OSPS rules metadata
```

### Core Interface

```python
# baseline_mcp/formatters/sarif.py

from typing import Dict, Any, List, Optional
from baseline_mcp.core.models import AuditResult

def generate_sarif_audit(
    audit_result: AuditResult,
    include_passing: bool = False,
    include_na: bool = False
) -> Dict[str, Any]:
    """
    Generate SARIF 2.1.0 output for baseline audit.

    Args:
        audit_result: Complete audit result
        include_passing: Include PASS results (default: False)
        include_na: Include N/A results (default: False)

    Returns:
        SARIF-formatted dictionary
    """
    pass

def build_sarif_rules(
    controls: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Build rules array for OSPS controls.

    Args:
        controls: Specific control IDs to include (default: all)

    Returns:
        List of SARIF rule objects
    """
    pass

def result_to_sarif_result(
    result: Dict[str, Any],
    rule_index: int,
    local_path: str
) -> Dict[str, Any]:
    """
    Convert check result to SARIF result format.

    Args:
        result: Check result dictionary
        rule_index: Index in rules array
        local_path: Repository path for location resolution

    Returns:
        SARIF result object
    """
    pass

def get_location_for_control(
    control_id: str,
    local_path: str
) -> Dict[str, Any]:
    """
    Determine file location for control result.

    Args:
        control_id: OSPS control ID
        local_path: Repository path

    Returns:
        SARIF physicalLocation object
    """
    pass
```

### Rules Catalog Structure

```python
# baseline_mcp/formatters/rules_catalog.py

from typing import Dict, Any

OSPS_RULES: Dict[str, Dict[str, Any]] = {
    "OSPS-AC-01.01": {
        "name": "MFARequired",
        "domain": "AC",
        "level": 1,
        "short": "MFA required for repository access",
        "full": "All project contributors with elevated permissions MUST use multi-factor authentication (MFA) for authentication.",
        "help_md": """Enable MFA for all organization members with write access or higher.

**Remediation:**
1. Go to Organization Settings → Security
2. Enable 'Require two-factor authentication for everyone'
3. Set a grace period for existing members to enable MFA

**References:**
- [GitHub MFA Documentation](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa)
""",
        "security_severity": 9.0,
        "tags": ["security", "access-control", "authentication", "mfa"],
        "location_hint": ".github/settings.yml",
        "default_level": "error"
    },
    # ... 60 more controls
}

def get_rule(control_id: str) -> Dict[str, Any]:
    """Get rule metadata for a control ID."""
    return OSPS_RULES.get(control_id, {})

def get_all_rules() -> Dict[str, Dict[str, Any]]:
    """Get all rule definitions."""
    return OSPS_RULES
```

## Integration Points

### GitHub Code Scanning

Upload via GitHub CLI:
```bash
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -X POST \
  -H "Accept: application/vnd.github+json" \
  -f sarif="$(cat audit.sarif | base64)"
```

Upload via GitHub Actions:
```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: audit.sarif
```

### MCP Tool Integration

```python
@mcp.tool()
def audit_openssf_baseline(
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    local_path: str = ".",
    level: int = 3,
    output_format: str = "markdown",  # markdown, json, sarif
    sarif_include_passing: bool = False,
    sarif_include_na: bool = False
) -> str:
    """Run OpenSSF Baseline audit with SARIF output support."""
    # ... existing audit logic ...

    if output_format == "sarif":
        from baseline_mcp.formatters.sarif import generate_sarif_audit
        sarif = generate_sarif_audit(
            audit_result,
            include_passing=sarif_include_passing,
            include_na=sarif_include_na
        )
        return json.dumps(sarif, indent=2)
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `include_passing` | bool | False | Include PASS results in output |
| `include_na` | bool | False | Include N/A results in output |
| `include_rules` | bool | True | Include full rules array |
| `pretty_print` | bool | True | Format JSON with indentation |

## Trade-offs Analysis

| Approach | Pros | Cons |
|----------|------|------|
| **Full rules catalog** | Complete GitHub integration, proper filtering | 61 static rules to maintain |
| **Dynamic rules only** | Simpler, only relevant rules | Less GitHub filtering capability |
| **Include passing** | Complete audit picture | More noise, larger file |
| **Failures only** | Clean actionable output | Missing context |

**Recommendation**: Full rules catalog with failures/warnings by default, configurable inclusion of passing/NA results.

## References

- [SARIF 2.1.0 OASIS Standard](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub SARIF Support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
- [SARIF Web Tools](https://sarifweb.azurewebsites.net/)
- [OpenSSF Baseline Specification](https://baseline.openssf.org/versions/2025-10-10)

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2024-11-30 | Initial design document |
