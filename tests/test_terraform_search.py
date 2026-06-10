"""
tests/test_terraform_search.py - Unit tests for Terraform search engine
=======================================================================
Tests the TerraformSearchEngine and module availability checks.
"""

import sys
import tempfile
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from terraform_search import TerraformSearchEngine, check_module_availability, get_module_variables
from models import MatchType


@pytest.fixture
def sample_tf_repo(tmp_path):
    """
    Create a temporary Terraform repository with sample files.
    """
    repo_dir = tmp_path / "terraform-scripts" / "edav" / "dev"
    repo_dir.mkdir(parents=True)

    # Create a sample main.tf with search service reference
    (repo_dir / "main.tf").write_text(
        'resource "azurerm_search_service" "edav_search" {\n'
        '  name                = "edav-dev-aisearch-eastus-internal"\n'
        '  resource_group_name = "ocio-edav-dev-rg"\n'
        '  location            = "eastus"\n'
        '  sku                 = "standard"\n'
        '}',
        encoding="utf-8"
    )

    # Create a module reference file
    mod_dir = tmp_path / "terraform-scripts" / "modules"
    mod_dir.mkdir(parents=True)
    (mod_dir / "search.tf").write_text(
        'module "ai_search_service" {\n'
        '  source = "../../../../terraform-modules/ai_search_service"\n'
        '}',
        encoding="utf-8"
    )

    return str(tmp_path / "terraform-scripts")


@pytest.fixture
def sample_module_repo(tmp_path):
    """
    Create a temporary module repository.
    """
    mod_dir = tmp_path / "terraform-modules" / "ai_search_service"
    mod_dir.mkdir(parents=True)

    (mod_dir / "main.tf").write_text(
        'resource "azurerm_search_service" "this" {\n'
        '  name = var.name\n'
        '}',
        encoding="utf-8"
    )
    (mod_dir / "variables.tf").write_text(
        'variable "name" {\n'
        '  description = "The name of the search service"\n'
        '  type        = string\n'
        '}',
        encoding="utf-8"
    )

    return str(tmp_path / "terraform-modules")


class TestTerraformSearchEngine:
    def test_exact_name_match(self, sample_tf_repo):
        engine = TerraformSearchEngine(repo_roots=[sample_tf_repo])
        result = engine.search_resource(
            resource_name="edav-dev-aisearch-eastus-internal",
        )
        exact_matches = [
            m for m in result.matches
            if m.match_type == MatchType.EXACT_NAME
        ]
        assert len(exact_matches) > 0, "Expected exact name match"

    def test_resource_type_match(self, sample_tf_repo):
        engine = TerraformSearchEngine(repo_roots=[sample_tf_repo])
        result = engine.search_resource(
            resource_name="edav-dev-aisearch-eastus-internal",
            resource_type="Microsoft.Search/searchServices",
        )
        type_matches = [
            m for m in result.matches
            if m.match_type == MatchType.RESOURCE_TYPE
        ]
        assert len(type_matches) > 0, "Expected resource type match"

    def test_module_name_match(self, sample_tf_repo):
        engine = TerraformSearchEngine(repo_roots=[sample_tf_repo])
        result = engine.search_resource(
            resource_name="edav-dev-aisearch-eastus-internal",
            resource_type="Microsoft.Search/searchServices",
        )
        module_matches = [
            m for m in result.matches
            if m.match_type == MatchType.MODULE_NAME
        ]
        assert len(module_matches) > 0, "Expected module name match"

    def test_has_resource_definition(self, sample_tf_repo):
        engine = TerraformSearchEngine(repo_roots=[sample_tf_repo])
        result = engine.search_resource(
            resource_name="edav-dev-aisearch-eastus-internal",
            resource_type="Microsoft.Search/searchServices",
        )
        assert result.has_resource_definition is True

    def test_empty_repo(self, tmp_path):
        engine = TerraformSearchEngine(repo_roots=[str(tmp_path)])
        result = engine.search_resource(resource_name="nonexistent-resource")
        assert len(result.matches) == 0
        assert result.best_confidence == 0.0

    def test_nonexistent_repo_path(self):
        engine = TerraformSearchEngine(
            repo_roots=["/nonexistent/path/terraform-scripts"]
        )
        result = engine.search_resource(resource_name="any-resource")
        assert len(result.matches) == 0


class TestModuleAvailability:
    def test_module_found(self, sample_module_repo):
        result = check_module_availability(
            module_roots=[sample_module_repo],
            module_names=["ai_search_service"],
        )
        assert result["ai_search_service"] is not None
        assert "ai_search_service" in result["ai_search_service"]

    def test_module_not_found(self, sample_module_repo):
        result = check_module_availability(
            module_roots=[sample_module_repo],
            module_names=["nonexistent_module"],
        )
        assert result["nonexistent_module"] is None


class TestGetModuleVariables:
    def test_parse_variables(self, sample_module_repo):
        mod_path = os.path.join(sample_module_repo, "ai_search_service")
        variables = get_module_variables(mod_path)
        assert "name" in variables
        assert variables["name"]["description"] == "The name of the search service"
        assert variables["name"]["type"] == "string"

    def test_no_variables_file(self, tmp_path):
        variables = get_module_variables(str(tmp_path))
        assert variables == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
