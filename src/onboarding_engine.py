"""
onboarding_engine.py - Terraform Onboarding Risk Engine
========================================================
Evaluates terraform_onboarding_candidate resources and produces:
  - Risk scoring with detailed evidence-based notes
  - Terraform import command generation (output only, never executed)
  - Structured OnboardingRecommendation objects
  - OwnershipValidation objects for all comparison results

SAFETY:
  Import commands are EXAMPLES ONLY. This engine NEVER executes them.
  No Terraform, no Azure, no filesystem changes are made here.
"""

import logging
from typing import Optional, List

from models import (
    AzureResource, ComparisonResult, ComparisonStatus, RiskLevel,
    OwnershipStatus, DeploymentSource, OwnershipValidation,
    OnboardingRecommendation,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Resource type -> Terraform resource type mapping
# ---------------------------------------------------------------------------

_RESOURCE_TYPE_MAP = {
    "searchservices":                   "azurerm_search_service",
    "search/searchservices":            "azurerm_search_service",
    "privateendpoints":                 "azurerm_private_endpoint",
    "network/privateendpoints":         "azurerm_private_endpoint",
    "diagnosticsettings":               "azurerm_monitor_diagnostic_setting",
    "insights/diagnosticsettings":      "azurerm_monitor_diagnostic_setting",
    "roleassignments":                  "azurerm_role_assignment",
    "authorization/roleassignments":    "azurerm_role_assignment",
    "accounts":                         "azurerm_cognitive_account",
    "cognitiveservices/accounts":       "azurerm_cognitive_account",
    "workspaces":                       "azurerm_machine_learning_workspace",
    "storageaccounts":                  "azurerm_storage_account",
    "storage/storageaccounts":          "azurerm_storage_account",
    "vaults":                           "azurerm_key_vault",
    "keyvault/vaults":                  "azurerm_key_vault",
}


# ---------------------------------------------------------------------------
# Import Command Generator
# ---------------------------------------------------------------------------

class ImportCommandGenerator:
    """
    Generates example terraform import commands.
    OUTPUT ONLY. Never executes. Never modifies state.
    """

    IMPORT_HEADER = [
        "#!/bin/bash",
        "# ===================================================================",
        "# TERRAFORM IMPORT COMMANDS - OUTPUT ONLY, NEVER EXECUTED BY TOOL",
        "# ===================================================================",
        "# Before running:",
        "#   1. terraform init",
        "#   2. Verify resource addresses match your module structure",
        "#   3. terraform plan -generate-config-out=generated.tf (TF 1.5+)",
        "#   4. Run import commands one at a time",
        "#   5. terraform plan MUST return:",
        "#        Plan: 0 to add, 0 to change, 0 to destroy",
        "#   6. DO NOT apply until plan is reviewed and approved",
        "# ===================================================================",
        "",
    ]

    def _resolve_tf_resource_type(self, resource: AzureResource) -> str:
        rtype = (resource.resource_type or "").lower()
        for key, tf_type in _RESOURCE_TYPE_MAP.items():
            if key in rtype:
                return tf_type
        segments = rtype.split("/")
        return "azurerm_" + segments[-1] if segments else "azurerm_unknown"

    def generate_for_resource(self, resource: AzureResource, module_name: str) -> List[str]:
        lines = list(self.IMPORT_HEADER)
        tf_type = self._resolve_tf_resource_type(resource)

        lines.append("# Resource: " + resource.name)
        lines.append("# Type:     " + resource.resource_type)
        lines.append("# RG:       " + resource.resource_group)
        lines.append("")

        lines.append("# Step 1: Import the primary resource")
        lines.append("# terraform import \")
        lines.append("#   module." + module_name + "." + tf_type + ".this \")
        lines.append("#   " + resource.resource_id)
        lines.append("")

        if resource.private_endpoints:
            lines.append("# Step 2: Import private endpoints")
            for i, pe in enumerate(resource.private_endpoints):
                lines.append("# terraform import \")
                lines.append("#   module." + module_name + ".azurerm_private_endpoint.pe[" + str(i) + "] \")
                lines.append("#   " + pe.resource_id)
            lines.append("")

        if resource.diagnostic_settings:
            lines.append("# Step 3: Import diagnostic settings")
            for i, ds in enumerate(resource.diagnostic_settings):
                lines.append("# terraform import \")
                lines.append("#   module." + module_name + ".azurerm_monitor_diagnostic_setting.diag[" + str(i) + "] \")
                lines.append("#   " + ds.resource_id)
            lines.append("")

        if resource.role_assignments:
            lines.append("# Step 4: Import role assignments")
            for i, ra in enumerate(resource.role_assignments):
                lines.append("# terraform import \")
                lines.append("#   module." + module_name + ".azurerm_role_assignment.rbac[" + str(i) + "] \")
                lines.append("#   " + ra.scope)
            lines.append("")

        lines.append("# After all imports:")
        lines.append("# terraform show   <- verify state")
        lines.append("# terraform plan   <- MUST return: Plan: 0 to add, 0 to change, 0 to destroy")
        lines.append("# DO NOT apply until plan is reviewed and approved.")
        return lines

    def generate_as_string(self, resource: AzureResource, module_name: str) -> str:
        return "\n".join(self.generate_for_resource(resource, module_name)) + "\n"


# ---------------------------------------------------------------------------
# Ownership Validator
# ---------------------------------------------------------------------------

class OwnershipValidator:
    """Determines OwnershipStatus and DeploymentSource for a ComparisonResult."""

    def validate(self, cr: ComparisonResult, env_path: str = "edav/dev") -> OwnershipValidation:
        ov = OwnershipValidation()
        resource = cr.azure_resource
        tf_result = cr.terraform_result

        ov.resource_exists_in_azure = resource is not None
        ov.module_exists_in_repo = bool(tf_result and tf_result.has_module_reference)
        ov.deployment_definition_found = bool(tf_result and tf_result.has_resource_definition)
        ov.created_outside_terraform = (
            ov.resource_exists_in_azure and not ov.deployment_definition_found
        )

        if cr.status == ComparisonStatus.TERRAFORM_MANAGED:
            ov.ownership_status = OwnershipStatus.TERRAFORM_MANAGED
        elif cr.status == ComparisonStatus.TERRAFORM_ONBOARDING_CANDIDATE:
            ov.ownership_status = OwnershipStatus.CREATED_OUTSIDE_TERRAFORM
            ov.is_onboarding_candidate = True
            ov.import_required = True
            ov.plan_validation_required = True
        elif cr.status in (ComparisonStatus.AZURE_ONLY, ComparisonStatus.MODULE_AVAILABLE):
            ov.ownership_status = OwnershipStatus.AZURE_ONLY
        else:
            ov.ownership_status = OwnershipStatus.UNKNOWN

        if ov.deployment_definition_found:
            ov.deployment_source = DeploymentSource.TERRAFORM_SCRIPTS
        elif ov.is_onboarding_candidate:
            ov.deployment_source = DeploymentSource.MANUAL_DEPLOYMENT
        else:
            ov.deployment_source = DeploymentSource.UNKNOWN

        if resource:
            svc = _guess_module_name(resource.resource_type)
            ov.suggested_deployment_path = "terraform-scripts/" + env_path + "/" + svc

        return ov


# ---------------------------------------------------------------------------
# Onboarding Risk Engine
# ---------------------------------------------------------------------------

class OnboardingRiskEngine:
    """
    Computes risk score and builds OnboardingRecommendation for onboarding candidates.

    Risk levels:
      HIGH     - default for all onboarding candidates
      CRITICAL - PE + diagnostics + RBAC all present (full import required)
    """

    _IMPORT_GEN = ImportCommandGenerator()

    def score(self, resource: AzureResource, module_name: str) -> tuple:
        """Returns (RiskLevel, List[str])."""
        risk = RiskLevel.HIGH
        notes = ["Existing resource - created outside Terraform"]

        if resource.private_endpoints:
            notes.append("Existing private endpoint(s): " + str(len(resource.private_endpoints)))
        if resource.diagnostic_settings:
            notes.append("Existing diagnostic setting(s): " + str(len(resource.diagnostic_settings)))
        if resource.role_assignments:
            notes.append("Existing RBAC assignment(s): " + str(len(resource.role_assignments)))

        has_pe   = bool(resource.private_endpoints)
        has_diag = bool(resource.diagnostic_settings)
        has_rbac = bool(resource.role_assignments)
        if has_pe and has_diag and has_rbac:
            risk = RiskLevel.CRITICAL
            notes.append("CRITICAL: PE + diagnostics + RBAC all present - import all before apply")

        return risk, notes

    def build_recommendation(self, resource: AzureResource, module_name: str, env_path: str = "edav/dev") -> OnboardingRecommendation:
        risk, risk_notes = self.score(resource, module_name)
        deployment_path = "terraform-scripts/" + env_path + "/" + module_name

        actions = [
            "Create deployment definition under: " + deployment_path,
            "  - Create " + deployment_path + "/main.tf (module block)",
            "  - Create " + deployment_path + "/variables.tf",
            "Match Azure configuration exactly (SKU, location, tags, PE, diagnostics, RBAC)",
            "Run: terraform init",
            "Run import commands from import_commands.sh for ALL sub-resources",
            "Run: terraform plan",
            "Validate plan returns: Plan: 0 to add, 0 to change, 0 to destroy",
            "Submit PR for review",
            "Apply ONLY after approval",
        ]

        warning_lines = [
            "WARNING: Terraform onboarding required.",
            "This resource was created outside Terraform.",
            "Import existing resources BEFORE first apply.",
            "Plan MUST return: Plan: 0 to add, 0 to change, 0 to destroy.",
            "DO NOT apply unless the plan is reviewed and approved.",
        ]

        import_cmds = self._IMPORT_GEN.generate_for_resource(resource, module_name)

        return OnboardingRecommendation(
            resource_name=resource.name,
            resource_type=resource.resource_type,
            terraform_module=module_name,
            deployment_path=deployment_path,
            required_actions=actions,
            plan_validation_target="Plan: 0 to add, 0 to change, 0 to destroy",
            import_commands=import_cmds,
            risk_level=risk,
            risk_notes=risk_notes,
            warning_text="\n".join(warning_lines),
        )

    def enrich_comparison_result(self, cr: ComparisonResult, env_path: str = "edav/dev") -> ComparisonResult:
        """Add OnboardingRecommendation and OwnershipValidation to an onboarding candidate."""
        if cr.status != ComparisonStatus.TERRAFORM_ONBOARDING_CANDIDATE or not cr.azure_resource:
            return cr

        module_name = _guess_module_name(cr.azure_resource.resource_type)
        rec = self.build_recommendation(cr.azure_resource, module_name, env_path)
        cr.onboarding_recommendation = rec
        cr.risk_level = rec.risk_level
        cr.risk_notes = list(cr.risk_notes) + rec.risk_notes
        cr.ownership = OwnershipValidator().validate(cr, env_path)
        cr.recommended_action = (
            "TERRAFORM ONBOARDING REQUIRED. "
            "Create deployment definition at " + rec.deployment_path + ". "
            "Import all sub-resources before apply. "
            "Plan must return: Plan: 0 to add, 0 to change, 0 to destroy."
        )
        return cr


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enrich_all_results(results: list, env_path: str = "edav/dev") -> list:
    """
    Enrich all ComparisonResults with OwnershipValidation.
    For TERRAFORM_ONBOARDING_CANDIDATE results, attach OnboardingRecommendation too.
    Call after classify_resource() on all resources.
    """
    engine = OnboardingRiskEngine()
    validator = OwnershipValidator()
    enriched = []
    for cr in results:
        if cr.status == ComparisonStatus.TERRAFORM_ONBOARDING_CANDIDATE:
            cr = engine.enrich_comparison_result(cr, env_path)
        else:
            if cr.ownership is None:
                cr.ownership = validator.validate(cr, env_path)
        enriched.append(cr)
    return enriched


def _guess_module_name(resource_type: str) -> str:
    """Derive a module name from Azure resource type string."""
    rtype = (resource_type or "").lower()
    if "search" in rtype:         return "ai_search_service"
    if "openai" in rtype:         return "azure_openai"
    if "cognitive" in rtype:      return "azure_openai"
    if "machinelearning" in rtype: return "ai_foundry"
    if "privateendpoints" in rtype: return "private_endpoint"
    if "diagnosticsettings" in rtype: return "diagnostic_setting"
    if "roleassignments" in rtype: return "rbac"
    if "storage" in rtype:        return "storage_account"
    if "keyvault" in rtype or "vaults" in rtype: return "key_vault"
    segments = rtype.split("/")
    return segments[-1] if segments else "unknown_module"
