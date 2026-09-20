"""Environmental failure classification.

Feature 036. See specs/036-tier2-error-class/contracts/error-class.md.

When a sieve pass cannot run to completion -- the network is unreachable,
the auth token expired, a subprocess timed out, a required binary is
missing -- the resulting verdict is not the same kind of thing as a
verdict produced by a check that ran cleanly and found the repository
non-compliant. Both gate the audit identically (WARN counts as FAIL for
compliance math, per Constitution Principle II), but they demand
different operator responses: fix the environment vs fix the repo.

``error_class`` names the environmental cause so the two are
distinguishable in reports, logs, and attestations. Every value below
means "the check could not run to completion." None of them means "the
check ran and the repository does not comply" -- that stays a bare
FAIL/WARN with no ``error_class``.

=============  ===============================================================
Value          Meaning
=============  ===============================================================
network        Host unreachable, DNS failure, TLS error, or MCP server
               unusable. NOTE: an unrecognized non-zero subprocess exit is
               NOT forced into this bucket -- see ``classify_exec_failure``,
               which returns ``None`` rather than guess ``network`` for a
               non-GitHub failure, so a genuine repo finding with an
               undeclared exit code is never mislabelled as an environment
               problem.
auth           HTTP 401, bad credentials, expired token, "requires
               authentication", or MCP plugin signature-verification failure.
timeout        Subprocess exceeded its ``timeout`` budget, or an MCP tool
               call exceeded ``MCP_DEFAULT_TIMEOUT_SECONDS``.
rate_limit     GitHub primary or secondary rate limit, or abuse-detection
               throttle.
not_found      A required binary or MCP server executable is absent from
               PATH.
crashed        A handler raised an unexpected exception, or an MCP tool
               returned unparseable output. The handler did not complete
               cleanly.
=============  ===============================================================

Two names are exported because ``typing.Literal`` is erased at runtime
and enforces nothing on its own. ``ErrorClass`` gives static-analysis
coverage; ``ERROR_CLASSES`` is what ``HandlerResult.__post_init__``
checks membership against, and is therefore the mechanism that actually
delivers the rejection guarantee (FR-002a). Adding a value means editing
both.

Deliberate divergence from :mod:`darnit.core.authority`: that module
pairs its ``Authority`` Literal with ``_TERMINAL_AUTHORITIES`` for a
*fail-safe* -- ``is_terminal_authority()`` returns False for unknown
strings, so an unknown authority can never conclude a control. That
works because authority has a conservative default ("cannot conclude").
An unknown ``error_class`` has no equivalent safe default: it is neither
"the check failed" nor "the check could not run." Rejection is the only
conservative option, so this module's frozenset backs a raise rather
than a degrade.
"""

from __future__ import annotations

import logging
from typing import Literal

ErrorClass = Literal[
    "network",
    "auth",
    "timeout",
    "rate_limit",
    "not_found",
    "crashed",
]

# Runtime-checkable companion to ``ErrorClass``. See module docstring for
# why both exist.
ERROR_CLASSES: frozenset[ErrorClass] = frozenset(
    (
        "network",
        "auth",
        "timeout",
        "rate_limit",
        "not_found",
        "crashed",
    )
)


def log_environmental_failure(
    logger: logging.Logger,
    error_class: ErrorClass,
    message: str,
    *,
    subject: str | None = None,
) -> None:
    """Emit the one canonical WARN line for an environmental failure.

    Single formatting + logging site for all four classification producers
    (exec / mcp / orchestrator crash-catch / context auto-detect). Two
    reasons this is centralized rather than open-coded per site:

    * Uniform shape. Every environmental failure logs the same way, so an
      operator (or a log scraper) sees one grammar, not three.
    * Static safety. ``error_class`` is a typed :data:`ErrorClass` argument,
      so a typo at any call site is a type error -- previously the
      context-auto-detect site interpolated a *bare string* into the log
      message, bypassing the ``ERROR_CLASSES`` frozenset entirely. The
      runtime membership check below backstops that for good measure.

    WARN, not DEBUG: a degraded audit must be visible at the default log
    level -- an operator should not have to raise verbosity to discover
    that half their checks never reached the network.
    """
    if error_class not in ERROR_CLASSES:  # backstop; mirrors HandlerResult guard
        raise ValueError(
            f"error_class={error_class!r} is not a known ErrorClass; "
            f"expected one of {sorted(ERROR_CLASSES)}"
        )
    prefix = f"{subject}: " if subject else ""
    logger.warning("%scould not complete (error_class=%s): %s", prefix, error_class, message)


__all__ = ["ERROR_CLASSES", "ErrorClass", "log_environmental_failure"]
