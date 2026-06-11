"""
models.py - Data models for Azure Terraform DR Discovery Tool
=============================================================
Defines dataclasses for all discovered Azure resources,
Terraform matches, comparison results, and report findings.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ComparisonStatus(str, Enum):
    """Classification of Azure resource vs Terraform alignment."""
    TERRAFORM_MANAGED            = "terraform_managed"
    AZURE_ONLY                   = "azure_only"
    TF_ONLY                      = "tf_only"
    POSSIBLE_MATCH               = "possible_match"
    MODULE_AVAILABLE             = "module_available_but_not_instantiated"
    TERRAFORM_ONBOARDING_CANDIDATE = "terraform_onboarding_candidate"
    UNKNOWN                      = "unknown"
    #
    # terraform_onboarding_candidate definition:
    #   - Resource EXISTS in Azure
    #   - Reusable Terraform MODULE exists in terraform-modules
    #   - No deployment DEFINITION exists in terraform-scripts
    #   - Resource was CREATED OUTSIDE Terraform (no state, no import record)
    # This is distinct from:
    #   terraform_managed: has deployment definition AND state
    #   azure_only:        no module and no deployment definition
    #   module_available:  partial match, no confirmed external-creation context


class RiskLevel(str, Enum):
    """Risk scoring for DR findings."""
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class MatchType(str, Enum):
    """Types of Terraform search matches."""
    EXACT_NAME    = "exact_name"
    PARTIAL_NAME  = "partial_name"
    RESOURCE_GROUP = "resource_group"
    RESOURCE_TYPE = "resource_type"
    MODULE_NAME   = "module_name"
    VNET_NAME     = "vnet_name"
    SUBNET_NAME   = "subnet_name"
    PE_NAME       = "pe_name"
    NIC_NAME      = "nic_name"


class OwnershipStatus(str, Enum):
    """How the resource is owned / managed."""
    TERRAFORM_MANAGED        = "Terraform Managed"
    AZURE_ONLY               = "Azure Only"
    CREATED_OUTSIDE_TERRAFORM = "Created Outside Terraform"
    UNKNOWN                  = "Unknown"


class DeploymentSource(str, Enum):
    """Where the resource deployment definition lives, if known."""
    TERRAFORM_SCRIPTS = "terraform-scripts"
    ALTERNATE_REPO    = "alternate repo"
    MANUAL_DEPLOYMENT = "manual deployment"
    UNKNOWN           = "unknown"


# ---------------------------------------------------------------------------
# Private Endpoint models
# ---------------------------------------------------------------------------

@dataclass
class PrivateDnsConfig:
    """DNS configuration for a private endpoint."""
    fqdn: Optional[str] = None
    private_ip: Optional[str] = None
    zone_name: Optional[str] = None


@dataclass
class PrivateEndpointInfo:
    """Full details of a private endpoint connection."""
    name: str = ""
    resource_id: str = ""
    resource_group: str = ""
    location: str = ""
    subscription_id: str = ""
    provisioning_state: str = ""
    connection_name: str = ""
    connection_state: str = ""
    connection_description: str = ""
    private_link_service_id: str = ""
    group_ids: List[str] = field(default_factory=list)
    vnet_name: str = ""
    subnet_name: str = ""
    subnet_id: str = ""
    private_ip_address: str = ""
    nic_name: str = ""
    nic_id: str = ""
    dns_configs: List[PrivateDnsConfig] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Diagnostic Settings model
# ---------------------------------------------------------------------------

@dataclass
class DiagnosticSettingInfo:
    """Diagnostic setting attached to a resource."""
    name: str = ""
    resource_id: str = ""
    log_analytics_workspace_id: str = ""
    log_analytics_workspace_name: str = ""
    storage_account_id: str = ""
    event_hub_name: str = ""
    log_categories: List[str] = field(default_factory=list)
    metric_categories: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Identity model
# ---------------------------------------------------------------------------

@dataclass
class IdentityInfo:
    """Managed identity information."""
    type: str = "None"
    principal_id: str = ""
    tenant_id: str = ""
    user_assigned_identities: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# RBAC model
# ---------------------------------------------------------------------------

@dataclass
class RoleAssignmentInfo:
    """Role assignment on a resource."""
    role_definition_name: str = ""
    role_definition_id: str = ""
    principal_id: str = ""
    principal_type: str = ""
    scope: str = ""


# ---------------------------------------------------------------------------
# Ownership Validation model (new)
# ---------------------------------------------------------------------------

@dataclass
class OwnershipValidation:
    """
    Ownership and deployment-source information for a resource.
    Populated by classify_resource() based on discovery evidence.
    """
    ownership_status: OwnershipStatus = OwnershipStatus.UNKNOWN
    deployment_source: DeploymentSource = DeploymentSource.UNKNOWN

    # Evidence flags that drive classification
    resource_exists_in_azure: bool = False
    module_exists_in_repo: bool = False
    deployment_definition_found: bool = False
    created_outside_terraform: bool = False  # True when Azure-only + module exists

    # Onboarding candidate details
    is_onboarding_candidate: bool = False
    suggested_deployment_path: str = ""  # e.g. terraform-scripts/edav/dev/ai_search_service
    import_required: bool = False
    plan_validation_required: bool = False

    # Additional notes (populated by risk engine)
    notes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Terraform Onboarding Recommendation model (new)
# ---------------------------------------------------------------------------

@dataclass
class OnboardingRecommendation:
    """
    Full Terraform onboarding recommendation for a single resource.
    Generated by OnboardingEngine for terraform_onboarding_candidate resources.
    """
    resource_name: str = ""
    resource_type: str = ""
    terraform_module: str = ""

    # Recommended deployment path in terraform-scripts
    # e.g. terraform-scripts/edav/dev/ai_search_service
    deployment_path: str = ""

    # Ordered list of required actions
    required_actions: List[str] = field(default_factory=list)

    # Validation target: plan must return this before any apply
    plan_validation_target: str = "Plan: 0 to add, 0 to change, 0 to destroy"

    # Import commands (output only, never executed)
    import_commands: List[str] = field(default_factory=list)

    # Risk level for this onboarding operation
    risk_level: RiskLevel = RiskLevel.HIGH
    risk_notes: List[str] = field(default_factory=list)

    # Human-readable warning block
    warning_text: str = ""


# ---------------------------------------------------------------------------
# Core Azure Resource model
# ---------------------------------------------------------------------------

@dataclass
class AzureResource:
    """Represents a discovered Azure resource with all collected metadata."""
    name: str = ""
    resource_type: str = ""
    resource_id: str = ""
    resource_group: str = ""
    subscription_id: str = ""
    location: str = ""
    sku_name: str = ""
    sku_tier: str = ""
    sku_capacity: Optional[int] = None
    tags: Dict[str, str] = field(default_factory=dict)
    identity: Optional[IdentityInfo] = None
    public_network_access: str = ""
    custom_subdomain: str = ""
    private_endpoints: List[PrivateEndpointInfo] = field(default_factory=list)
    diagnostic_settings: List[DiagnosticSettingInfo] = field(default_factory=list)
    role_assignments: List[RoleAssignmentInfo] = field(default_factory=list)
    extras: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Terraform search result models
# ---------------------------------------------------------------------------

@dataclass
class TerraformMatch:
    """A single match found in a Terraform file."""
    file_path: str = ""
    line_number: int = 0
    line_content: str = ""
    match_type: MatchType = MatchType.EXACT_NAME
    matched_value: str = ""
    confidence: float = 0.0

    def confidence_label(self) -> str:
        if self.confidence >= 0.9: return "HIGH"
        elif self.confidence >= 0.6: return "MEDIUM"
        return "LOW"


@dataclass
class TerraformSearchResult:
    """Aggregated search results for a single Azure resource."""
    resource_name: str = ""
    resource_group: str = ""
    matches: List[TerraformMatch] = field(default_factory=list)

    @property
    def best_confidence(self) -> float:
        if not self.matches: return 0.0
        return max(m.confidence for m in self.matches)

    @property
    def has_resource_definition(self) -> bool:
        return any("azurerm_" in m.line_content for m in self.matches)

    @property
    def has_module_reference(self) -> bool:
        return any(
            'module "' in m.line_content or "source" in m.line_content
            for m in self.matches
        )


# ---------------------------------------------------------------------------
# Drift / comparison models
# ---------------------------------------------------------------------------

@dataclass
class DriftEntry:
    """Parsed entry from drift_candidates.csv or drift.csv."""
    resource_name: str = ""
    resource_type: str = ""
    resource_group: str = ""
    subscription_id: str = ""
    status: str = ""
    notes: str = ""
    raw_row: Dict[str, str] = field(default_factory=dict)


@dataclass
class ComparisonResult:
    """Azure resource compared against Terraform findings."""
    azure_resource: Optional[AzureResource] = None
    terraform_result: Optional[TerraformSearchResult] = None
    drift_entry: Optional[DriftEntry] = None

    status: ComparisonStatus = ComparisonStatus.UNKNOWN
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_notes: List[str] = field(default_factory=list)
    recommended_action: str = ""
    confidence: float = 0.0

    # Ownership and deployment source (new)
    ownership: Optional[OwnershipValidation] = None

    # Full onboarding recommendation when status == TERRAFORM_ONBOARDING_CANDIDATE
    onboarding_recommendation: Optional[OnboardingRecommendation] = None

    def to_summary_dict(self) -> Dict[str, Any]:
        name  = self.azure_resource.name if self.azure_resource else "N/A"
        rtype = self.azure_resource.resource_type if self.azure_resource else "N/A"
        rg    = self.azure_resource.resource_group if self.azure_resource else "N/A"
        tf_matches = len(self.terraform_result.matches) if self.terraform_result else 0
        own_status = self.ownership.ownership_status.value if self.ownership else "Unknown"
        dep_source = self.ownership.deployment_source.value if self.ownership else "unknown"
        return {
            "resource_name": name,
            "resource_type": rtype,
            "resource_group": rg,
            "status": self.status.value,
            "ownership_status": own_status,
            "deployment_source": dep_source,
            "risk": self.risk_level.value,
            "tf_matches": tf_matches,
            "confidence": f"{self.confidence:.0%}",
            "recommended_action": self.recommended_action,
        }


# ---------------------------------------------------------------------------
# Full discovery run report
# ---------------------------------------------------------------------------

@dataclass
class DiscoveryReport:
    """Top-level container for a full discovery run."""
    service: str = ""
    resource_name: str = ""
    subscription_id: str = ""
    resource_group: str = ""
    repo_root: str = ""
    module_root: str = ""
    run_timestamp: str = ""

    azure_resources: List[AzureResource] = field(default_factory=list)
    comparison_results: List[ComparisonResult] = field(default_factory=list)
    drift_entries: List[DriftEntry] = field(default_factory=list)

    # Onboarding candidates (subset of comparison_results)
    onboarding_candidates: List[ComparisonResult] = field(default_factory=list)

    summary_status: ComparisonStatus = ComparisonStatus.UNKNOWN
    overall_risk: RiskLevel = RiskLevel.MEDIUM
    key_findings: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)

    ticket_update_text: str = ""
    teams_message_text: str = ""
