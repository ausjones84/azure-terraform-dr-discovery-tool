"""
tests/test_models.py - Unit tests for data models
===================================================
Tests for models.py dataclasses and enumerations.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from models import (
    AzureResource, PrivateEndpointInfo, PrivateDnsConfig,
    DiagnosticSettingInfo, IdentityInfo, RoleAssignmentInfo,
    TerraformMatch, TerraformSearchResult,
    ComparisonResult, ComparisonStatus, RiskLevel, MatchType,
    DriftEntry, DiscoveryReport
)


class TestAzureResource:
    def test_default_values(self):
        res = AzureResource()
        assert res.name == ""
        assert res.resource_type == ""
        assert res.tags == {}
        assert res.private_endpoints == []
        assert res.diagnostic_settings == []
        assert res.role_assignments == []

    def test_with_identity(self):
        identity = IdentityInfo(type="SystemAssigned", principal_id="abc123")
        res = AzureResource(name="test-resource", identity=identity)
        assert res.identity.type == "SystemAssigned"
        assert res.identity.principal_id == "abc123"

    def test_with_private_endpoints(self):
        pe = PrivateEndpointInfo(
            name="pe-test",
            vnet_name="vnet-test",
            subnet_name="subnet-test",
            private_ip_address="10.0.0.5",
        )
        res = AzureResource(name="test-resource", private_endpoints=[pe])
        assert len(res.private_endpoints) == 1
        assert res.private_endpoints[0].private_ip_address == "10.0.0.5"


class TestTerraformMatch:
    def test_confidence_label_high(self):
        match = TerraformMatch(confidence=0.95)
        assert match.confidence_label() == "HIGH"

    def test_confidence_label_medium(self):
        match = TerraformMatch(confidence=0.70)
        assert match.confidence_label() == "MEDIUM"

    def test_confidence_label_low(self):
        match = TerraformMatch(confidence=0.30)
        assert match.confidence_label() == "LOW"


class TestTerraformSearchResult:
    def test_best_confidence_empty(self):
        result = TerraformSearchResult(resource_name="test")
        assert result.best_confidence == 0.0

    def test_best_confidence_with_matches(self):
        result = TerraformSearchResult(
            resource_name="test",
            matches=[
                TerraformMatch(confidence=0.5),
                TerraformMatch(confidence=0.9),
                TerraformMatch(confidence=0.7),
            ]
        )
        assert result.best_confidence == 0.9

    def test_has_resource_definition(self):
        result = TerraformSearchResult(
            resource_name="test",
            matches=[
                TerraformMatch(
                    line_content='resource "azurerm_search_service" "this" {',
                    confidence=0.9
                ),
            ]
        )
        assert result.has_resource_definition is True

    def test_no_resource_definition(self):
        result = TerraformSearchResult(
            resource_name="test",
            matches=[
                TerraformMatch(
                    line_content='  name = "my-search-service"',
                    confidence=0.9
                ),
            ]
        )
        assert result.has_resource_definition is False


class TestComparisonResult:
    def test_to_summary_dict(self):
        res = AzureResource(
            name="test-search",
            resource_type="Microsoft.Search/searchServices",
            resource_group="test-rg",
        )
        cr = ComparisonResult(
            azure_resource=res,
            status=ComparisonStatus.AZURE_ONLY,
            risk_level=RiskLevel.HIGH,
            confidence=0.0,
            recommended_action="Review required",
        )
        summary = cr.to_summary_dict()
        assert summary["resource_name"] == "test-search"
        assert summary["status"] == "azure_only"
        assert summary["risk"] == "high"


class TestDriftParser:
    """Tests for drift parsing logic."""

    def test_drift_entry_creation(self):
        entry = DriftEntry(
            resource_name="test-resource",
            resource_type="Microsoft.Search/searchServices",
            status="azure_only",
            notes="Found in Azure, not in TF"
        )
        assert entry.resource_name == "test-resource"
        assert entry.status == "azure_only"


class TestDiscoveryReport:
    def test_empty_report(self):
        report = DiscoveryReport()
        assert report.azure_resources == []
        assert report.comparison_results == []
        assert report.drift_entries == []
        assert report.key_findings == []
        assert report.next_steps == []

    def test_report_with_data(self):
        res = AzureResource(name="my-search", resource_type="Microsoft.Search/searchServices")
        report = DiscoveryReport(
            service="ai_search",
            resource_name="my-search",
            azure_resources=[res],
        )
        assert report.service == "ai_search"
        assert len(report.azure_resources) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
