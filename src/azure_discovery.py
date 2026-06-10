"""
azure_discovery.py - Azure Resource Discovery Engine
=====================================================
Discovers Azure resources using Azure CLI (subprocess) and/or
Azure SDK. Collects all metadata for DR documentation.

SAFETY: This module is READ-ONLY. It never modifies Azure resources.
"""

import json
import subprocess
import logging
from typing import Optional, List, Dict, Any

from models import (
    AzureResource, PrivateEndpointInfo, PrivateDnsConfig,
    DiagnosticSettingInfo, IdentityInfo, RoleAssignmentInfo
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_az(args: List[str], mask_output: bool = False) -> Optional[Dict]:
    """
    Run an Azure CLI command and return parsed JSON output.

    Args:
        args: List of az CLI arguments (do NOT include 'az' itself).
        mask_output: If True, do not log the raw output (for sensitive calls).

    Returns:
        Parsed JSON dict/list, or None on error.
    """
    cmd = ["az"] + args + ["--output", "json"]
    logger.debug("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            logger.warning("az command failed: %s", result.stderr.strip())
            return None
        if not result.stdout.strip():
            return None
        parsed = json.loads(result.stdout)
        if not mask_output:
            logger.debug("az result: %s", str(parsed)[:200])
        return parsed
    except FileNotFoundError:
        logger.error("Azure CLI (az) not found. Install azure-cli and log in first.")
        raise
    except subprocess.TimeoutExpired:
        logger.error("Azure CLI command timed out: %s", " ".join(cmd))
        return None
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse JSON from az output: %s", exc)
        return None


def _mask_sensitive(value: str) -> str:
    """Mask potentially sensitive values for display."""
    if not value or len(value) < 8:
        return "***"
    return value[:4] + "****" + value[-4:]


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------

def _parse_identity(raw_identity: Optional[Dict]) -> Optional[IdentityInfo]:
    """Parse identity block from Azure resource."""
    if not raw_identity:
        return IdentityInfo(type="None")
    identity_type = raw_identity.get("type", "None")
    principal_id = raw_identity.get("principalId", "")
    tenant_id = raw_identity.get("tenantId", "")
    user_assigned = list((raw_identity.get("userAssignedIdentities") or {}).keys())
    return IdentityInfo(
        type=identity_type,
        principal_id=principal_id,
        tenant_id=tenant_id,
        user_assigned_identities=user_assigned,
    )


# ---------------------------------------------------------------------------
# Private Endpoint discovery
# ---------------------------------------------------------------------------

def discover_private_endpoints_for_resource(
    resource_id: str,
    subscription_id: str,
) -> List[PrivateEndpointInfo]:
    """
    Discover private endpoints connected to a given Azure resource.

    Args:
        resource_id: Full Azure resource ID.
        subscription_id: Subscription ID for the az CLI context.

    Returns:
        List of PrivateEndpointInfo objects.
    """
    endpoints: List[PrivateEndpointInfo] = []

    # List all private endpoints in the subscription, then filter by resource
    all_pe = _run_az([
        "network", "private-endpoint", "list",
        "--subscription", subscription_id,
    ])
    if not all_pe:
        logger.info("No private endpoints found in subscription %s", subscription_id)
        return endpoints

    resource_id_lower = resource_id.lower()

    for pe in all_pe:
        # Check if this PE is connected to our resource
        connections = pe.get("privateLinkServiceConnections") or []
        connections += pe.get("manualPrivateLinkServiceConnections") or []

        for conn in connections:
            linked_id = (conn.get("privateLinkServiceId") or "").lower()
            if resource_id_lower not in linked_id:
                continue

            # Found a matching PE
            pe_info = PrivateEndpointInfo()
            pe_info.name = pe.get("name", "")
            pe_info.resource_id = pe.get("id", "")
            pe_info.resource_group = pe.get("resourceGroup", "")
            pe_info.location = pe.get("location", "")
            pe_info.subscription_id = subscription_id
            pe_info.provisioning_state = pe.get("provisioningState", "")
            pe_info.connection_name = conn.get("name", "")
            conn_state = (conn.get("privateLinkServiceConnectionState") or {})
            pe_info.connection_state = conn_state.get("status", "")
            pe_info.connection_description = conn_state.get("description", "")
            pe_info.private_link_service_id = conn.get("privateLinkServiceId", "")
            pe_info.group_ids = conn.get("groupIds") or []
            pe_info.raw = pe

            # Extract subnet info
            subnet_ref = (pe.get("subnet") or {}).get("id", "")
            if subnet_ref:
                parts = subnet_ref.split("/")
                if "virtualNetworks" in parts:
                    vnet_idx = parts.index("virtualNetworks")
                    pe_info.vnet_name = parts[vnet_idx + 1] if vnet_idx + 1 < len(parts) else ""
                if "subnets" in parts:
                    sub_idx = parts.index("subnets")
                    pe_info.subnet_name = parts[sub_idx + 1] if sub_idx + 1 < len(parts) else ""
                pe_info.subnet_id = subnet_ref

            # Extract NIC info
            nics = pe.get("networkInterfaces") or []
            if nics:
                nic_id = nics[0].get("id", "")
                pe_info.nic_id = nic_id
                pe_info.nic_name = nic_id.split("/")[-1] if nic_id else ""
                # Fetch NIC details for private IP
                nic_detail = _get_nic_details(nic_id, subscription_id)
                if nic_detail:
                    ip_configs = nic_detail.get("ipConfigurations") or []
                    for ipc in ip_configs:
                        ip = ipc.get("privateIPAddress", "")
                        if ip:
                            pe_info.private_ip_address = ip
                            break

            # DNS configs
            dns_cfgs = pe.get("customDnsConfigs") or []
            for dns in dns_cfgs:
                pe_info.dns_configs.append(PrivateDnsConfig(
                    fqdn=dns.get("fqdn", ""),
                    private_ip=dns.get("ipAddresses", [""])[0] if dns.get("ipAddresses") else "",
                ))

            endpoints.append(pe_info)

    return endpoints


def _get_nic_details(nic_id: str, subscription_id: str) -> Optional[Dict]:
    """Fetch NIC details to get private IP address."""
    if not nic_id:
        return None
    parts = nic_id.split("/")
    if "resourceGroups" not in parts or "networkInterfaces" not in parts:
        return None
    rg_idx = parts.index("resourceGroups")
    nic_idx = parts.index("networkInterfaces")
    rg = parts[rg_idx + 1]
    nic_name = parts[nic_idx + 1]
    return _run_az([
        "network", "nic", "show",
        "--name", nic_name,
        "--resource-group", rg,
        "--subscription", subscription_id,
    ])


# ---------------------------------------------------------------------------
# Diagnostic Settings
# ---------------------------------------------------------------------------

def discover_diagnostic_settings(
    resource_id: str,
    subscription_id: str,
) -> List[DiagnosticSettingInfo]:
    """Discover diagnostic settings for a resource."""
    settings: List[DiagnosticSettingInfo] = []
    raw = _run_az([
        "monitor", "diagnostic-settings", "list",
        "--resource", resource_id,
        "--subscription", subscription_id,
    ])
    if not raw:
        return settings
    items = raw if isinstance(raw, list) else raw.get("value", [])
    for item in items:
        ds = DiagnosticSettingInfo()
        ds.name = item.get("name", "")
        ds.resource_id = item.get("id", "")
        la_id = item.get("workspaceId", "") or item.get("logAnalyticsDestinationType", "")
        ds.log_analytics_workspace_id = la_id
        if la_id:
            ds.log_analytics_workspace_name = la_id.split("/")[-1]
        ds.storage_account_id = item.get("storageAccountId", "")
        ds.event_hub_name = item.get("eventHubName", "")
        ds.log_categories = [
            log.get("category", "") for log in (item.get("logs") or [])
            if log.get("enabled", False)
        ]
        ds.metric_categories = [
            m.get("category", "") for m in (item.get("metrics") or [])
            if m.get("enabled", False)
        ]
        ds.raw = item
        settings.append(ds)
    return settings


# ---------------------------------------------------------------------------
# Role Assignments
# ---------------------------------------------------------------------------

def discover_role_assignments(
    resource_id: str,
    subscription_id: str,
) -> List[RoleAssignmentInfo]:
    """Discover RBAC role assignments scoped to a resource."""
    assignments: List[RoleAssignmentInfo] = []
    raw = _run_az([
        "role", "assignment", "list",
        "--scope", resource_id,
        "--subscription", subscription_id,
        "--include-inherited",
    ])
    if not raw:
        return assignments
    for item in raw:
        ra = RoleAssignmentInfo(
            role_definition_name=item.get("roleDefinitionName", ""),
            role_definition_id=item.get("roleDefinitionId", ""),
            principal_id=item.get("principalId", ""),
            principal_type=item.get("principalType", ""),
            scope=item.get("scope", ""),
        )
        assignments.append(ra)
    return assignments


# ---------------------------------------------------------------------------
# AI Search discovery
# ---------------------------------------------------------------------------

def discover_ai_search(
    subscription_id: str,
    resource_group: Optional[str] = None,
    resource_name: Optional[str] = None,
) -> List[AzureResource]:
    """
    Discover Azure AI Search (Microsoft.Search/searchServices) resources.

    Args:
        subscription_id: Azure subscription ID.
        resource_group: Optional resource group filter.
        resource_name: Optional specific resource name.

    Returns:
        List of AzureResource objects for each AI Search service found.
    """
    resources: List[AzureResource] = []

    if resource_name and resource_group:
        raw_list = _run_az([
            "search", "service", "show",
            "--name", resource_name,
            "--resource-group", resource_group,
            "--subscription", subscription_id,
        ])
        raw_list = [raw_list] if raw_list else []
    elif resource_group:
        raw_list = _run_az([
            "search", "service", "list",
            "--resource-group", resource_group,
            "--subscription", subscription_id,
        ]) or []
    else:
        raw_list = _run_az([
            "resource", "list",
            "--resource-type", "Microsoft.Search/searchServices",
            "--subscription", subscription_id,
        ]) or []

    for raw in raw_list:
        res = AzureResource()
        res.name = raw.get("name", "")
        res.resource_type = "Microsoft.Search/searchServices"
        res.resource_id = raw.get("id", "")
        res.resource_group = raw.get("resourceGroup", "")
        res.subscription_id = subscription_id
        res.location = raw.get("location", "")
        sku = raw.get("sku") or {}
        res.sku_name = sku.get("name", "")
        res.tags = raw.get("tags") or {}
        res.identity = _parse_identity(raw.get("identity"))
        props = raw.get("properties") or {}
        res.public_network_access = props.get("publicNetworkAccess", "")
        res.extras = {
            "hosting_mode": props.get("hostingMode", ""),
            "replica_count": props.get("replicaCount"),
            "partition_count": props.get("partitionCount"),
            "status": props.get("status", ""),
            "status_details": props.get("statusDetails", ""),
        }
        res.raw = raw

        # Collect additional details
        res.private_endpoints = discover_private_endpoints_for_resource(
            res.resource_id, subscription_id
        )
        res.diagnostic_settings = discover_diagnostic_settings(
            res.resource_id, subscription_id
        )
        res.role_assignments = discover_role_assignments(
            res.resource_id, subscription_id
        )
        resources.append(res)

    return resources


# ---------------------------------------------------------------------------
# OpenAI / Cognitive Services discovery
# ---------------------------------------------------------------------------

def discover_openai(
    subscription_id: str,
    resource_group: Optional[str] = None,
    resource_name: Optional[str] = None,
) -> List[AzureResource]:
    """
    Discover Azure OpenAI / Cognitive Services resources.
    Resource type: Microsoft.CognitiveServices/accounts
    """
    resources: List[AzureResource] = []
    args = [
        "resource", "list",
        "--resource-type", "Microsoft.CognitiveServices/accounts",
        "--subscription", subscription_id,
    ]
    if resource_group:
        args += ["--resource-group", resource_group]

    raw_list = _run_az(args) or []

    # Filter by name if provided
    if resource_name:
        raw_list = [r for r in raw_list if r.get("name", "").lower() == resource_name.lower()]

    for raw in raw_list:
        res = AzureResource()
        res.name = raw.get("name", "")
        res.resource_type = raw.get("type", "Microsoft.CognitiveServices/accounts")
        res.resource_id = raw.get("id", "")
        res.resource_group = raw.get("resourceGroup", "")
        res.subscription_id = subscription_id
        res.location = raw.get("location", "")
        sku = raw.get("sku") or {}
        res.sku_name = sku.get("name", "")
        res.sku_tier = sku.get("tier", "")
        res.tags = raw.get("tags") or {}
        res.identity = _parse_identity(raw.get("identity"))

        # Get full details for properties
        detail = _run_az([
            "cognitiveservices", "account", "show",
            "--name", res.name,
            "--resource-group", res.resource_group,
            "--subscription", subscription_id,
        ])
        if detail:
            props = detail.get("properties") or {}
            res.public_network_access = props.get("publicNetworkAccess", "")
            res.custom_subdomain = props.get("customSubDomainName", "")
            kind = detail.get("kind", "")
            res.extras = {
                "kind": kind,
                "endpoint": props.get("endpoint", ""),
                "provisioning_state": props.get("provisioningState", ""),
                "restore": props.get("restore", False),
            }
            res.raw = detail
        else:
            res.raw = raw

        res.private_endpoints = discover_private_endpoints_for_resource(
            res.resource_id, subscription_id
        )
        res.diagnostic_settings = discover_diagnostic_settings(
            res.resource_id, subscription_id
        )
        res.role_assignments = discover_role_assignments(
            res.resource_id, subscription_id
        )
        resources.append(res)

    return resources


# ---------------------------------------------------------------------------
# AI Foundry / AI Services discovery
# ---------------------------------------------------------------------------

def discover_ai_foundry(
    subscription_id: str,
    resource_group: Optional[str] = None,
    resource_name: Optional[str] = None,
) -> List[AzureResource]:
    """
    Discover Azure AI Foundry / AI Services resources.
    These share the CognitiveServices resource type with kind=AIServices.
    """
    all_cog = discover_openai(subscription_id, resource_group, resource_name)
    # AI Foundry resources have kind = AIServices or AzureAI.*
    return [
        r for r in all_cog
        if r.extras.get("kind", "").startswith("AI") or
           r.extras.get("kind", "") == "AIServices"
    ]


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

SERVICE_DISPATCHERS = {
    "ai_search": discover_ai_search,
    "openai": discover_openai,
    "ai_foundry": discover_ai_foundry,
}


def discover_resources(
    service: str,
    subscription_id: str,
    resource_group: Optional[str] = None,
    resource_name: Optional[str] = None,
) -> List[AzureResource]:
    """
    Entry point for resource discovery.

    Args:
        service: Service type key (ai_search, openai, ai_foundry).
        subscription_id: Azure subscription ID.
        resource_group: Optional resource group filter.
        resource_name: Optional resource name filter.

    Returns:
        List of discovered AzureResource objects.
    """
    dispatcher = SERVICE_DISPATCHERS.get(service)
    if not dispatcher:
        supported = ", ".join(SERVICE_DISPATCHERS.keys())
        raise ValueError(
            f"Unsupported service '{service}'. Supported: {supported}"
        )
    logger.info(
        "Discovering %s resources in subscription %s", service, subscription_id
    )
    return dispatcher(subscription_id, resource_group, resource_name)
