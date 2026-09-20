"""Feature 036 hardening: the seven improvements built on top of the base feature.

Each test class maps to one improvement so a failure points straight at the
change that regressed:

  #1  exec classifies from the FULL stderr, not the 2000-char-truncated copy.
  #2  an unrecognized non-``gh`` failure is left UNCLASSIFIED, not guessed
      as ``network`` (also asserted in test_error_class_classification.py).
  #3  the orchestrator's ``last_error_class`` fall-through is typed and
      carries the last environmental class into the manual WARN.
  #4  context auto-detect logs through the typed hub (its `network` arm).
  #5  the shared ``log_environmental_failure`` hub: one format, typed guard.
  #6  the MCP exception->(status, error_class) table, incl. required-server
      FAIL and the unknown-exception safety net.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from darnit.core.error_class import ERROR_CLASSES, log_environmental_failure
from darnit.sieve.builtin_handlers import (
    _classify_exec_failure,
    _classify_mcp_exception,
    exec_handler,
)
from darnit.sieve.handler_registry import (
    HandlerContext,
    HandlerResult,
    HandlerResultStatus,
)


def _ctx(local_path: Path) -> HandlerContext:
    return HandlerContext(
        local_path=str(local_path),
        owner="o",
        repo="r",
        default_branch="main",
        control_id="TEST-01.01",
    )


def _proc(returncode: int, stdout: str = "", stderr: str = "") -> MagicMock:
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


class TestImprovement1FullStderrClassification:
    """#1: a signal past the 2000-char evidence truncation still classifies."""

    @pytest.mark.unit
    def test_rate_limit_beyond_truncation_boundary_is_still_classified(
        self, tmp_path: Path
    ) -> None:
        # Bury the rate-limit line well past the 2000-char evidence cap.
        noisy = "warning: retrying\n" * 300  # >> 2000 chars
        stderr = noisy + "gh: API rate limit exceeded for user ID 1."
        assert len(noisy) > 2000

        with patch(
            "darnit.sieve.builtin_handlers.subprocess.run",
            return_value=_proc(1, stderr=stderr),
        ):
            result = exec_handler(
                {"handler": "exec", "command": ["gh", "api", "/x"]},
                _ctx(tmp_path),
            )

        assert result.error_class == "rate_limit", (
            "classification must read the full stderr, not the truncated "
            "evidence copy"
        )
        # The evidence copy is still truncated -- only the classification input changed.
        assert len(result.evidence["stderr"]) == 2000


class TestImprovement2ConservativeUnclassified:
    """#2: unrecognized cause -> None, but known gh patterns still classify."""

    @pytest.mark.unit
    def test_unrecognized_returns_none(self) -> None:
        assert _classify_exec_failure("fatal: not a git repository") is None

    @pytest.mark.unit
    def test_known_gh_patterns_still_classify(self) -> None:
        assert _classify_exec_failure("gh: Bad credentials (HTTP 401)") == "auth"
        assert _classify_exec_failure("API rate limit exceeded") == "rate_limit"

    @pytest.mark.unit
    def test_unclassified_exec_still_warns_without_a_class(
        self, tmp_path: Path, caplog
    ) -> None:
        """An undeclared exit is still surfaced at WARN, just with no label."""
        with caplog.at_level(logging.WARNING):
            with patch(
                "darnit.sieve.builtin_handlers.subprocess.run",
                return_value=_proc(3, stderr="mysterious tool failure"),
            ):
                result = exec_handler(
                    {"handler": "exec", "command": ["some-tool"]}, _ctx(tmp_path)
                )
        assert result.error_class is None
        assert result.status == HandlerResultStatus.INCONCLUSIVE
        warns = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert warns, "an undeclared exit should still be visible at WARN"
        assert "unclassified" in " ".join(r.getMessage() for r in warns)


class TestImprovement3LastErrorClassFallthrough:
    """#3: the manual WARN fall-through carries the last environmental class.

    Two passes: pass 1 is environmental (timeout, INCONCLUSIVE), pass 2 is a
    manual placeholder (INCONCLUSIVE, no class). FR-009a has no resolving
    pass here, so the final WARN falls back to the last classified pass.
    """

    @pytest.mark.unit
    def test_timeout_on_first_pass_survives_to_manual_warn(self) -> None:
        from darnit.config.framework_schema import HandlerInvocation
        from darnit.core.plugin import ControlSpec
        from darnit.sieve.handler_registry import get_sieve_handler_registry
        from darnit.sieve.models import CheckContext
        from darnit.sieve.orchestrator import SieveOrchestrator

        def env_timeout(config, ctx):
            return HandlerResult(
                status=HandlerResultStatus.INCONCLUSIVE,
                message="simulated network timeout",
                error_class="timeout",
            )

        registry = get_sieve_handler_registry()
        registry.register(
            "env_timeout_036", "deterministic", env_timeout, default_authority="dispositive"
        )

        control = ControlSpec(
            control_id="TEST-DEGRADED.01",
            name="Degraded",
            description="first pass times out, then manual",
            level=1,
            domain="TEST",
            metadata={
                "handler_invocations": [
                    HandlerInvocation(handler="env_timeout_036"),
                    HandlerInvocation(handler="manual"),
                ]
            },
        )
        context = CheckContext(
            owner="o",
            repo="r",
            local_path="/tmp/x",
            default_branch="main",
            control_id="TEST-DEGRADED.01",
            project_context={},
        )

        result = SieveOrchestrator(stop_on_llm=True)._dispatch_handler_invocations(
            control, context
        )
        assert result is not None
        assert result.status == "WARN"
        assert result.error_class == "timeout", (
            "a degraded audit's manual WARN must explain WHY it could not "
            "verify -- the last environmental class, not a bare WARN"
        )


class TestImprovement4AutoDetectNetworkThroughHub:
    """#4: the auto-detect `network` arm logs a typed, hub-formatted line."""

    @pytest.mark.unit
    def test_generic_git_error_logs_network(self, tmp_path: Path, caplog) -> None:
        from darnit.context.auto_detect import _get_remote_url

        with caplog.at_level(logging.WARNING):
            with patch(
                "darnit.context.auto_detect.subprocess.run",
                side_effect=OSError("disk gone"),
            ):
                assert _get_remote_url("origin", str(tmp_path)) is None

        joined = " ".join(
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        )
        assert "network" in joined
        assert "origin" in joined
        assert "context.platform" in joined


class TestImprovement5SharedHub:
    """#5: one canonical formatter, statically-typed error_class, runtime guard."""

    @pytest.mark.unit
    def test_hub_rejects_unknown_error_class(self) -> None:
        with pytest.raises(ValueError, match="not a known ErrorClass"):
            log_environmental_failure(
                logging.getLogger("t"), "bogus", "msg"  # type: ignore[arg-type]
            )

    @pytest.mark.unit
    @pytest.mark.parametrize("value", sorted(ERROR_CLASSES))
    def test_hub_emits_uniform_warn_line(self, value: str, caplog) -> None:
        with caplog.at_level(logging.WARNING):
            log_environmental_failure(
                logging.getLogger("darnit.test"),
                value,  # type: ignore[arg-type]
                "something went wrong",
                subject="CTRL-1: exec",
            )
        rec = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(rec) == 1
        msg = rec[0].getMessage()
        assert f"error_class={value}" in msg
        assert "CTRL-1: exec" in msg
        assert "something went wrong" in msg


class TestImprovement6McpExceptionTable:
    """#6: the MCP exception mapping as a single auditable table."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        ("exc_name", "expected_class"),
        [
            ("McpToolTimeout", "timeout"),
            ("McpServerHandshakeFailed", "network"),
            ("McpServerBinaryMissing", "not_found"),
            ("McpServerVerificationFailed", "auth"),
            ("McpServerUnusable", "network"),
            ("McpToolError", "crashed"),
            ("McpToolResponseNotJson", "crashed"),
            ("UnknownMcpServer", "not_found"),
        ],
    )
    def test_each_exception_maps_to_expected_class(
        self, exc_name: str, expected_class: str
    ) -> None:
        from darnit.sieve import mcp_pool as mcp_pool_mod

        exc = getattr(mcp_pool_mod, exc_name)("boom")
        _status, error_class, _msg = _classify_mcp_exception(exc, optional=True)
        assert error_class == expected_class

    @pytest.mark.unit
    def test_optional_binary_missing_is_inconclusive_required_is_fail(self) -> None:
        from darnit.sieve import mcp_pool as mcp_pool_mod

        err = mcp_pool_mod.McpServerBinaryMissing("gone")
        opt_status, _c, _m = _classify_mcp_exception(err, optional=True)
        req_status, _c2, req_msg = _classify_mcp_exception(err, optional=False)
        assert opt_status == HandlerResultStatus.INCONCLUSIVE
        assert req_status == HandlerResultStatus.FAIL
        assert "Required MCP server binary not found" in req_msg

    @pytest.mark.unit
    def test_unknown_exception_is_the_crashed_safety_net(self) -> None:
        status, error_class, msg = _classify_mcp_exception(
            RuntimeError("surprise"), optional=True
        )
        assert status == HandlerResultStatus.ERROR
        assert error_class == "crashed"
        assert "surprise" in msg
