"""Sigstore sidecar verification for MCP server binaries.

Isolated so the sandboxing follow-up (issue #375) can extend the pre-spawn
hooks (bubblewrap, nono.sh, landlock, nsjail) without touching the pool's
session cache or the handler.

Verification model: an operator declares ``trusted_publisher`` in a
``[mcp_servers.<name>]`` block; the pool looks for
``<binary>.sigstore`` or ``<binary>.sigstore.json`` next to the resolved
binary path and verifies it against a GitHub-workflow identity policy
derived from ``trusted_publisher``. Failure returns a ``(False, reason)``
tuple; the pool maps that to :class:`McpServerVerificationFailed`, which
the handler resolves ERROR. There is NO code path from verification failure
to PASS.

Bundle shapes supported:

1. Direct-artifact signatures (``cosign sign-blob`` output, GitHub
   Actions' Sigstore action against a binary artifact). Verification
   uses :func:`sigstore.verify.Verifier.verify_artifact` with the
   binary's precomputed SHA-256, which binds the signature to the
   bytes on disk.
2. DSSE-wrapped in-toto attestations (the GoReleaser / SLSA shape).
   Verification uses :func:`Verifier.verify_dsse` and then checks that
   at least one ``subject[].digest.sha256`` in the returned statement
   equals the binary's SHA-256. Without this second check, any valid
   bundle from the trusted publisher's workflow would pass regardless
   of which binary sat beside it.

Direct-artifact is tried first because it is the cheaper and more
directly bound shape; DSSE fallback runs only when the bundle is not a
direct signature. Both paths reject a bundle whose subject digest does
not match the on-disk binary.

Alternatives considered:

* Fetching a transparency-log attestation by SHA-256 at spawn time was
  rejected because Constitution II ("conservative-by-default") forbids
  silently requiring network I/O during an audit.
* Chaining verification into the plugin-signing surface was rejected
  because MCP server binaries are external tools, not darnit plugins;
  the two trust domains are different.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def verify(binary_path: Path, trusted_publisher: str) -> tuple[bool, str]:
    """Verify a Sigstore sidecar next to ``binary_path``.

    Args:
        binary_path: The resolved path of the MCP server binary.
        trusted_publisher: Either a full GitHub identity URL
            (``https://github.com/<owner>[/<repo>]``) or a bare
            ``<owner>`` / ``<owner>/<repo>`` string.

    Returns:
        ``(True, reason)`` if verification succeeds against a policy
        derived from ``trusted_publisher`` AND the bundle is bound to
        the on-disk binary bytes; ``(False, reason)`` on any failure --
        missing sidecar, malformed bundle, unbound signature, sigstore
        SDK not installed, or policy mismatch. The pool never sees an
        exception from this function.
    """
    sidecar = _find_sidecar(binary_path)
    if sidecar is None:
        return False, (
            f"no Sigstore sidecar found next to {binary_path} "
            f"(looked for .sigstore and .sigstore.json)"
        )

    try:
        from sigstore._utils import HashAlgorithm  # type: ignore[import-not-found]
        from sigstore.hashes import Hashed  # type: ignore[import-not-found]
        from sigstore.models import Bundle  # type: ignore[import-not-found]
        from sigstore.verify import Verifier  # type: ignore[import-not-found]
        from sigstore.verify.policy import (  # type: ignore[import-not-found]
            GitHubWorkflowRepository,
        )
    except ImportError:
        return False, (
            "sigstore not installed -- install darnit-core[attestation] "
            "to enable trusted_publisher verification"
        )

    try:
        bundle = Bundle.from_json(sidecar.read_bytes())
    except Exception as err:  # noqa: BLE001 - sigstore raises assorted subclasses
        return False, f"Sigstore verification failed: could not parse bundle: {err}"

    repo_ref = _extract_repo_ref(trusted_publisher)
    if repo_ref is None:
        return False, (
            f"Sigstore verification failed: trusted_publisher "
            f"{trusted_publisher!r} does not name a GitHub owner/repo"
        )

    try:
        binary_bytes = binary_path.read_bytes()
    except OSError as err:
        return False, f"Sigstore verification failed: cannot read {binary_path}: {err}"
    binary_sha256 = hashlib.sha256(binary_bytes).digest()
    binary_sha256_hex = binary_sha256.hex()

    try:
        policy = GitHubWorkflowRepository(repo_ref)
        verifier = Verifier.production()
    except Exception as err:  # noqa: BLE001
        return False, f"Sigstore verification failed: {err}"

    # Path A: direct-artifact signature. verify_artifact binds the
    # signature to the SHA-256 digest we hand it, so a substituted
    # binary produces a mismatch here rather than a false accept.
    hashed = Hashed(algorithm=HashAlgorithm.SHA2_256, digest=binary_sha256)
    try:
        verifier.verify_artifact(hashed, bundle, policy)
        return True, (
            f"verified against {trusted_publisher} "
            f"(direct-artifact signature; sha256={binary_sha256_hex[:16]}...)"
        )
    except Exception as artifact_err:  # noqa: BLE001 - fall through to DSSE
        artifact_reason = str(artifact_err)

    # Path B: DSSE-wrapped attestation. verify_dsse returns the payload;
    # we still have to check that the attested subject is our binary.
    try:
        payload_type, payload = verifier.verify_dsse(bundle, policy)
    except Exception as dsse_err:  # noqa: BLE001
        return False, (
            f"Sigstore verification failed for both paths: "
            f"direct-artifact ({artifact_reason}); "
            f"DSSE ({dsse_err})"
        )

    if payload_type != "application/vnd.in-toto+json":
        return False, (
            f"Sigstore verification failed: DSSE payload type "
            f"{payload_type!r} is not an in-toto statement"
        )

    try:
        statement = json.loads(payload)
    except json.JSONDecodeError as err:
        return False, (
            f"Sigstore verification failed: in-toto statement not JSON: {err}"
        )

    subjects = statement.get("subject") or []
    if not isinstance(subjects, list) or not subjects:
        return False, (
            "Sigstore verification failed: in-toto statement declares no "
            "subject; cannot bind attestation to this binary"
        )

    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        digest_map = subject.get("digest")
        if not isinstance(digest_map, dict):
            continue
        candidate = digest_map.get("sha256")
        if isinstance(candidate, str) and candidate.lower() == binary_sha256_hex:
            return True, (
                f"verified against {trusted_publisher} "
                f"(DSSE in-toto attestation; sha256={binary_sha256_hex[:16]}...)"
            )

    return False, (
        "Sigstore verification failed: DSSE attestation is valid but no "
        f"subject.digest.sha256 matches the on-disk binary "
        f"(binary sha256={binary_sha256_hex[:16]}...); attestation may "
        "cover a different artifact"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_sidecar(binary_path: Path) -> Path | None:
    for suffix in (".sigstore", ".sigstore.json"):
        candidate = binary_path.with_name(binary_path.name + suffix)
        if candidate.exists():
            return candidate
    return None


def _extract_repo_ref(trusted_publisher: str) -> str | None:
    """Extract the ``owner/repo`` reference from a ``trusted_publisher`` value.

    Accepts:

    * ``https://github.com/<owner>``
    * ``https://github.com/<owner>/<repo>``
    * ``<owner>`` (bare)
    * ``<owner>/<repo>`` (bare)

    Returns ``owner/repo`` when a repo is present; ``owner/`` is invalid for
    :class:`GitHubWorkflowRepository`, so an owner-only value returns
    ``None`` and the caller reports the failure.
    """
    stripped = trusted_publisher.strip()
    for prefix in ("https://github.com/", "http://github.com/"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix) :]
            break
    stripped = stripped.strip("/")
    parts = stripped.split("/", 1)
    if len(parts) == 2 and parts[0] and parts[1]:
        return f"{parts[0]}/{parts[1]}"
    return None


__all__ = ["verify"]
