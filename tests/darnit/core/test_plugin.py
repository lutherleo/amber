"""Tests for darnit.core.plugin module."""

from pathlib import Path

import pytest

from darnit.core.plugin import ComplianceImplementation, ControlSpec


class FullyCompliantImplementation:
    """Minimal implementation satisfying the compliance protocol."""

    name = "test-framework"
    display_name = "Test Framework"
    version = "0.1.0"
    spec_version = "TEST v1"

    def get_all_controls(self) -> list[ControlSpec]:
        return [
            ControlSpec(
                control_id="TEST-01",
                name="Test control",
                description="A test control",
                level=1,
                domain="TEST",
                metadata={},
            )
        ]

    def get_controls_by_level(self, level: int) -> list[ControlSpec]:
        return [
            control for control in self.get_all_controls() if control.level == level
        ]

    def get_rules_catalog(self) -> dict[str, str]:
        return {"version": self.spec_version}

    def get_remediation_registry(self) -> dict[str, str]:
        return {"test": "handler"}

    def get_framework_config_path(self) -> Path | None:
        return Path("/tmp/framework.toml")

    def register_controls(self) -> None:
        return None


class MissingRegisterControlsImplementation:
    """Deliberately incomplete implementation for protocol checks."""

    name = "broken-framework"
    display_name = "Broken Framework"
    version = "0.1.0"
    spec_version = "TEST v1"

    def get_all_controls(self) -> list[ControlSpec]:
        return []

    def get_controls_by_level(self, level: int) -> list[ControlSpec]:
        return []

    def get_rules_catalog(self) -> dict[str, str]:
        return {}

    def get_remediation_registry(self) -> dict[str, str]:
        return {}

    def get_framework_config_path(self) -> Path | None:
        return None


class TestControlSpec:
    """Tests for ControlSpec dataclass behavior."""

    @pytest.mark.unit
    def test_construction_stores_all_fields(self):
        """ControlSpec stores provided values and copies level/domain to tags."""
        control = ControlSpec(
            control_id="OSPS-AC-01.01",
            name="Access control policy",
            description="Ensure an access control policy exists",
            level=2,
            domain="AC",
            metadata={"severity": "medium"},
            tags={"source": "tests"},
        )

        assert control.control_id == "OSPS-AC-01.01"
        assert control.name == "Access control policy"
        assert control.description == "Ensure an access control policy exists"
        assert control.level == 2
        assert control.domain == "AC"
        assert control.metadata == {"severity": "medium"}
        assert control.tags == {"source": "tests", "level": 2, "domain": "AC"}

    @pytest.mark.unit
    def test_defaults_allow_none_level_and_domain(self):
        """ControlSpec keeps tags empty when level/domain are not provided."""
        control = ControlSpec(
            control_id="CUSTOM-01",
            name="Custom control",
            description="Framework without levels",
            level=None,
            domain=None,
            metadata={},
        )

        assert control.level is None
        assert control.domain is None
        assert control.metadata == {}
        assert control.tags == {}


class TestComplianceImplementationProtocol:
    """Tests for ComplianceImplementation runtime protocol checks."""

    @pytest.mark.unit
    def test_runtime_check_accepts_complete_implementation(self):
        """A class implementing the full protocol satisfies isinstance()."""
        implementation = FullyCompliantImplementation()

        assert isinstance(implementation, ComplianceImplementation)
        assert implementation.get_framework_config_path() == Path(
            "/tmp/framework.toml"
        )
        assert implementation.get_all_controls()[0].control_id == "TEST-01"

    @pytest.mark.unit
    def test_runtime_check_rejects_missing_required_method(self):
        """A class missing a required protocol method fails isinstance()."""
        implementation = MissingRegisterControlsImplementation()

        assert not isinstance(implementation, ComplianceImplementation)
