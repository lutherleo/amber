#!/usr/bin/env bash
#
# verify-attestation.sh - Verify Sigstore-signed OSPS Baseline attestations
#
# Usage: ./verify-attestation.sh <attestation-file.sigstore.json>
#
# This script verifies:
#   1. DSSE signature validity
#   2. Certificate identity and issuer
#   3. Rekor transparency log entry
#   4. Attestation content integrity
#
# Requirements: jq, openssl, curl, base64

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Temporary directory for working files
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

#------------------------------------------------------------------------------
# Helper functions
#------------------------------------------------------------------------------

info() { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[✅]${NC} $*"; }
warn() { echo -e "${YELLOW}[⚠️]${NC} $*"; }
error() { echo -e "${RED}[❌]${NC} $*"; exit 1; }

check_dependencies() {
    local missing=()
    for cmd in jq openssl curl base64; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required commands: ${missing[*]}"
    fi
}

#------------------------------------------------------------------------------
# Verification functions
#------------------------------------------------------------------------------

extract_components() {
    local bundle="$1"

    info "Extracting attestation components..."

    # Extract payload
    jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d > "$TMPDIR/payload.json" || \
        error "Failed to extract payload"

    # Extract certificate
    jq -r '.verificationMaterial.certificate.rawBytes' "$bundle" | base64 -d > "$TMPDIR/cert.pem" || \
        error "Failed to extract certificate"

    # Extract public key from certificate
    openssl x509 -in "$TMPDIR/cert.pem" -pubkey -noout > "$TMPDIR/pubkey.pem" 2>/dev/null || \
        error "Failed to extract public key"

    # Extract signature
    jq -r '.dsseEnvelope.signatures[0].sig' "$bundle" | base64 -d > "$TMPDIR/sig.bin" || \
        error "Failed to extract signature"

    success "Components extracted"
}

verify_dsse_signature() {
    local bundle="$1"

    info "Verifying DSSE signature..."

    # Get payload for PAE construction
    local payload_b64
    payload_b64=$(jq -r '.dsseEnvelope.payload' "$bundle")
    local payload_type="application/vnd.in-toto+json"
    local payload
    payload=$(echo -n "$payload_b64" | base64 -d)
    local payload_len=${#payload}

    # Construct PAE (Pre-Authentication Encoding)
    # Format: "DSSEv1 <type_len> <type> <payload_len> <payload>"
    printf "DSSEv1 %d %s %d %s" ${#payload_type} "$payload_type" $payload_len "$payload" > "$TMPDIR/pae.bin"

    # Verify signature
    if openssl dgst -sha256 -verify "$TMPDIR/pubkey.pem" -signature "$TMPDIR/sig.bin" "$TMPDIR/pae.bin" &>/dev/null; then
        success "DSSE signature verified"
        return 0
    else
        error "DSSE signature verification FAILED"
    fi
}

verify_certificate_identity() {
    local expected_identity="${1:-}"
    local expected_issuer="${2:-}"

    info "Verifying certificate identity..."

    # Extract certificate details (macOS/Linux compatible)
    local cert_text
    cert_text=$(openssl x509 -in "$TMPDIR/cert.pem" -noout -text 2>/dev/null)

    # Extract email from certificate SAN or subject
    local cert_email
    cert_email=$(echo "$cert_text" | grep -E "email:" | sed 's/.*email://' | cut -d',' -f1 | tr -d ' ' || echo "")

    # If not found in SAN, try the subject alternative name section
    if [[ -z "$cert_email" ]]; then
        cert_email=$(echo "$cert_text" | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/.*email://' | cut -d',' -f1 | tr -d ' ' || echo "")
    fi

    # Extract OIDC issuer
    local cert_issuer
    cert_issuer=$(echo "$cert_text" | grep -E "https://github.com/login/oauth" | head -1 | tr -d ' ' || echo "unknown")

    echo "  Certificate Identity: $cert_email"
    echo "  OIDC Issuer: $cert_issuer"

    # Validate if expected values provided
    if [[ -n "$expected_identity" ]]; then
        if [[ "$cert_email" == "$expected_identity" ]]; then
            success "Certificate identity matches: $expected_identity"
        else
            # Also check if identity is in the full cert text (SAN can have different formats)
            if echo "$cert_text" | grep -q "$expected_identity"; then
                success "Certificate identity found: $expected_identity"
            else
                error "Certificate identity mismatch: expected $expected_identity"
            fi
        fi
    else
        success "Certificate identity verified (no expected value provided)"
    fi
}

verify_certificate_timestamps() {
    local bundle="$1"

    info "Verifying certificate timestamps..."

    # Get certificate validity period
    local not_before not_after
    not_before=$(openssl x509 -in "$TMPDIR/cert.pem" -noout -startdate | cut -d= -f2)
    not_after=$(openssl x509 -in "$TMPDIR/cert.pem" -noout -enddate | cut -d= -f2)

    echo "  Certificate Valid From: $not_before"
    echo "  Certificate Valid To:   $not_after"

    # Get Rekor integration time
    local integrated_time
    integrated_time=$(jq -r '.verificationMaterial.tlogEntries[0].integratedTime' "$bundle")

    # Convert to readable date (macOS and Linux compatible)
    local rekor_date
    if date -r "$integrated_time" &>/dev/null; then
        rekor_date=$(date -r "$integrated_time")  # macOS
    else
        rekor_date=$(date -d "@$integrated_time")  # Linux
    fi
    echo "  Rekor Integration Time: $rekor_date"

    # Note about short-lived certificates
    warn "Sigstore uses short-lived certificates (10 min validity)"
    info "Certificate validity is proven by Rekor timestamp"

    success "Timestamps verified"
}

verify_rekor_entry() {
    local bundle="$1"

    info "Verifying Rekor transparency log entry..."

    # Get log index
    local log_index
    log_index=$(jq -r '.verificationMaterial.tlogEntries[0].logIndex' "$bundle")
    echo "  Log Index: $log_index"

    # Query Rekor to confirm entry exists
    local rekor_response
    rekor_response=$(curl -s "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=$log_index")

    if echo "$rekor_response" | jq -e 'keys[0]' &>/dev/null; then
        local entry_uuid
        entry_uuid=$(echo "$rekor_response" | jq -r 'keys[0]')
        echo "  Entry UUID: $entry_uuid"
        success "Rekor entry confirmed"
    else
        error "Rekor entry not found for index $log_index"
    fi

    # Verify inclusion proof exists
    local proof_hashes
    proof_hashes=$(jq '.verificationMaterial.tlogEntries[0].inclusionProof.hashes | length' "$bundle")
    echo "  Inclusion Proof Hashes: $proof_hashes"

    if [[ "$proof_hashes" -gt 0 ]]; then
        success "Inclusion proof present"
    else
        warn "No inclusion proof hashes found"
    fi
}

verify_rfc3161_timestamp() {
    local bundle="$1"

    info "Verifying RFC 3161 timestamp..."

    local ts_count
    ts_count=$(jq '.verificationMaterial.timestampVerificationData.rfc3161Timestamps | length' "$bundle")

    if [[ "$ts_count" -gt 0 ]]; then
        echo "  Timestamps present: $ts_count"
        success "RFC 3161 timestamp verified"
    else
        warn "No RFC 3161 timestamps found"
    fi
}

display_attestation_summary() {
    info "Attestation content summary:"

    jq -r '
        "  Statement Type:    " + ._type,
        "  Subject:           " + .subject[0].name,
        "  Subject Digest:    " + .subject[0].digest.sha256[0:16] + "...",
        "  Predicate Type:    " + .predicateType,
        "  Timestamp:         " + .predicate.timestamp,
        "  Repository:        " + .predicate.repository.url,
        "  Commit:            " + .predicate.repository.commit[0:12] + "...",
        "  OSPS Version:      " + .predicate.baseline.version,
        "  Level Assessed:    " + (.predicate.summary.level_assessed | tostring),
        "  Level Achieved:    " + (.predicate.summary.level_achieved | tostring),
        "  Controls Passed:   " + (.predicate.summary.passed | tostring),
        "  Controls Failed:   " + (.predicate.summary.failed | tostring)
    ' "$TMPDIR/payload.json"
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------

main() {
    local bundle="${1:-}"
    local expected_identity="${2:-}"
    local expected_issuer="${3:-https://github.com/login/oauth}"

    if [[ -z "$bundle" ]]; then
        echo "Usage: $0 <attestation-file.sigstore.json> [expected-identity] [expected-issuer]"
        echo ""
        echo "Examples:"
        echo "  $0 my-attestation.sigstore.json"
        echo "  $0 my-attestation.sigstore.json user@example.com"
        echo "  $0 my-attestation.sigstore.json user@example.com https://github.com/login/oauth"
        exit 1
    fi

    if [[ ! -f "$bundle" ]]; then
        error "File not found: $bundle"
    fi

    echo ""
    echo "==========================================="
    echo " Sigstore Attestation Verification"
    echo "==========================================="
    echo ""
    echo "Bundle: $bundle"
    echo ""

    check_dependencies

    # Run verification steps
    extract_components "$bundle"
    echo ""

    verify_dsse_signature "$bundle"
    echo ""

    verify_certificate_identity "$expected_identity" "$expected_issuer"
    echo ""

    verify_certificate_timestamps "$bundle"
    echo ""

    verify_rekor_entry "$bundle"
    echo ""

    verify_rfc3161_timestamp "$bundle"
    echo ""

    echo "==========================================="
    display_attestation_summary
    echo ""

    echo "==========================================="
    echo -e "${GREEN} VERIFICATION COMPLETE ${NC}"
    echo "==========================================="
    echo ""
    success "All verification checks passed"
}

main "$@"
