"""
terraform_search.py - Terraform Repository Search Engine
=========================================================
Searches local Terraform repositories for resources, modules,
and patterns that match discovered Azure resources.

SAFETY: Read-only file scanning. Does not execute Terraform.
"""

import os
import re
import logging
from pathlib import Path
from typing import List, Optional, Dict, Tuple

from models import TerraformMatch, TerraformSearchResult, MatchType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Terraform resource type mappings
# ---------------------------------------------------------------------------

RESOURCE_TYPE_MAP: Dict[str, List[str]] = {
    "Microsoft.Search/searchServices": [
        "azurerm_search_service",
    ],
    "Microsoft.CognitiveServices/accounts": [
        "azurerm_cognitive_account",
        "azurerm_ai_services",
    ],
    "Microsoft.Network/privateEndpoints": [
        "azurerm_private_endpoint",
    ],
    "Microsoft.Network/networkInterfaces": [
        "azurerm_network_interface",
    ],
    "Microsoft.Network/virtualNetworks": [
        "azurerm_virtual_network",
    ],
    "Microsoft.Network/virtualNetworks/subnets": [
        "azurerm_subnet",
    ],
    "Microsoft.OperationalInsights/workspaces": [
        "azurerm_log_analytics_workspace",
    ],
    "Microsoft.Insights/diagnosticSettings": [
        "azurerm_monitor_diagnostic_setting",
    ],
    "Microsoft.Authorization/roleAssignments": [
        "azurerm_role_assignment",
    ],
}

MODULE_NAME_MAP: Dict[str, List[str]] = {
    "Microsoft.Search/searchServices": [
        "ai_search_service",
        "search_service",
        "cognitive_search",
    ],
    "Microsoft.CognitiveServices/accounts": [
        "ai_foundry",
        "ai_foundry_deployment",
        "ai_foundry_project",
        "cognitive_account",
        "openai",
        "ai_services",
    ],
}

# File extensions to search
TF_EXTENSIONS = {".tf", ".tfvars", ".hcl"}

# Patterns that indicate a resource definition vs just a reference
RESOURCE_DEFINITION_PATTERNS = [
    r'resource\s+"[^"]+\s+"[^"]+"\s*\{',
    r'module\s+"[^"]+"\s*\{',
]


# ---------------------------------------------------------------------------
# Core search engine
# ---------------------------------------------------------------------------

class TerraformSearchEngine:
    """
    Searches Terraform repositories for references to Azure resources.

    Supports searching by:
    - Resource name (exact and partial)
    - Resource group name
    - VNet / Subnet names
    - Private endpoint names
    - NIC names
    - Terraform resource types
    - Module names
    """

    def __init__(self, repo_roots: List[str], module_roots: List[str] = None):
        """
        Args:
            repo_roots: Paths to Terraform script repositories.
            module_roots: Paths to Terraform module repositories.
        """
        self.repo_roots = [Path(r) for r in repo_roots if r]
        self.module_roots = [Path(m) for m in (module_roots or []) if m]
        self._file_cache: Dict[str, List[str]] = {}

    def _get_tf_files(self) -> List[Path]:
        """Walk all repo and module roots to find Terraform files."""
        tf_files: List[Path] = []
        all_roots = self.repo_roots + self.module_roots
        for root in all_roots:
            if not root.exists():
                logger.warning("Repository path does not exist: %s", root)
                continue
            for path in root.rglob("*"):
                if path.suffix in TF_EXTENSIONS and path.is_file():
                    tf_files.append(path)
        logger.debug("Found %d Terraform files across %d roots", len(tf_files), len(all_roots))
        return tf_files

    def _read_file(self, path: Path) -> List[str]:
        """Read and cache file lines."""
        key = str(path)
        if key not in self._file_cache:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    self._file_cache[key] = f.readlines()
            except OSError as exc:
                logger.warning("Cannot read %s: %s", path, exc)
                self._file_cache[key] = []
        return self._file_cache[key]

    def _search_pattern(
        self,
        files: List[Path],
        pattern: str,
        match_type: MatchType,
        confidence: float,
        flags: int = re.IGNORECASE,
    ) -> List[TerraformMatch]:
        """Search all files for a regex pattern."""
        matches: List[TerraformMatch] = []
        compiled = re.compile(pattern, flags)
        for path in files:
            lines = self._read_file(path)
            for lineno, line in enumerate(lines, start=1):
                if compiled.search(line):
                    matches.append(TerraformMatch(
                        file_path=str(path),
                        line_number=lineno,
                        line_content=line.rstrip(),
                        match_type=match_type,
                        matched_value=pattern,
                        confidence=confidence,
                    ))
        return matches

    def search_resource(
        self,
        resource_name: str,
        resource_type: str = "",
        resource_group: str = "",
        vnet_names: List[str] = None,
        subnet_names: List[str] = None,
        pe_names: List[str] = None,
        nic_names: List[str] = None,
    ) -> TerraformSearchResult:
        """
        Search Terraform repos for a specific Azure resource.

        Args:
            resource_name: Azure resource name (exact).
            resource_type: Azure resource type (e.g. Microsoft.Search/searchServices).
            resource_group: Resource group name.
            vnet_names: List of associated VNet names.
            subnet_names: List of associated subnet names.
            pe_names: List of associated private endpoint names.
            nic_names: List of associated NIC names.

        Returns:
            TerraformSearchResult with all matches.
        """
        result = TerraformSearchResult(
            resource_name=resource_name,
            resource_group=resource_group,
        )
        tf_files = self._get_tf_files()

        # 1. Exact resource name match
        result.matches.extend(self._search_pattern(
            tf_files,
            r'\b' + re.escape(resource_name) + r'\b',
            MatchType.EXACT_NAME,
            0.95,
        ))

        # 2. Partial name match (for abbreviated names)
        if len(resource_name) > 6:
            # Try the first significant segment (e.g. 'edav-dev' from 'edav-dev-aisearch-eastus')
            parts = resource_name.split("-")
            if len(parts) >= 3:
                partial = "-".join(parts[:3])
                result.matches.extend(self._search_pattern(
                    tf_files,
                    re.escape(partial),
                    MatchType.PARTIAL_NAME,
                    0.60,
                ))

        # 3. Resource group name
        if resource_group:
            result.matches.extend(self._search_pattern(
                tf_files,
                r'\b' + re.escape(resource_group) + r'\b',
                MatchType.RESOURCE_GROUP,
                0.50,
            ))

        # 4. Terraform resource types for this Azure resource type
        tf_types = RESOURCE_TYPE_MAP.get(resource_type, [])
        for tf_type in tf_types:
            result.matches.extend(self._search_pattern(
                tf_files,
                r'resource\s+"' + re.escape(tf_type) + r'"',
                MatchType.RESOURCE_TYPE,
                0.70,
            ))

        # 5. Module names
        module_names = MODULE_NAME_MAP.get(resource_type, [])
        for mod_name in module_names:
            result.matches.extend(self._search_pattern(
                tf_files,
                r'(module\s+"[^"]*' + re.escape(mod_name) + r'|source\s*=\s*"[^"]*' + re.escape(mod_name) + r')',
                MatchType.MODULE_NAME,
                0.65,
            ))

        # 6. VNet names
        for vnet in (vnet_names or []):
            if vnet:
                result.matches.extend(self._search_pattern(
                    tf_files,
                    re.escape(vnet),
                    MatchType.VNET_NAME,
                    0.55,
                ))

        # 7. Subnet names
        for subnet in (subnet_names or []):
            if subnet:
                result.matches.extend(self._search_pattern(
                    tf_files,
                    re.escape(subnet),
                    MatchType.SUBNET_NAME,
                    0.55,
                ))

        # 8. Private endpoint names
        for pe in (pe_names or []):
            if pe:
                result.matches.extend(self._search_pattern(
                    tf_files,
                    r'\b' + re.escape(pe) + r'\b',
                    MatchType.PE_NAME,
                    0.80,
                ))

        # 9. NIC names
        for nic in (nic_names or []):
            if nic:
                result.matches.extend(self._search_pattern(
                    tf_files,
                    re.escape(nic),
                    MatchType.NIC_NAME,
                    0.75,
                ))

        # Deduplicate: remove exact same file+line combos
        seen = set()
        unique_matches = []
        for m in result.matches:
            key = (m.file_path, m.line_number)
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)
        result.matches = sorted(
            unique_matches,
            key=lambda x: (-x.confidence, x.file_path, x.line_number),
        )
        logger.info(
            "Search for '%s' found %d matches", resource_name, len(result.matches)
        )
        return result


# ---------------------------------------------------------------------------
# Module availability checker
# ---------------------------------------------------------------------------

def check_module_availability(
    module_roots: List[str],
    module_names: List[str],
) -> Dict[str, Optional[str]]:
    """
    Check if specific module directories exist in the module roots.

    Returns:
        Dict mapping module name -> path (str) if found, None if not.
    """
    result = {}
    for mod_name in module_names:
        found_path = None
        for root in module_roots:
            candidate = Path(root) / mod_name
            if candidate.is_dir():
                found_path = str(candidate)
                break
        result[mod_name] = found_path
    return result


def get_module_variables(module_path: str) -> Dict[str, Dict]:
    """
    Parse variables from a Terraform module's variables.tf file.

    Returns:
        Dict mapping variable name -> {description, type, default}.
    """
    variables = {}
    var_file = Path(module_path) / "variables.tf"
    if not var_file.exists():
        return variables

    try:
        content = var_file.read_text(encoding="utf-8")
        # Simple regex-based parser (not full HCL parser)
        var_blocks = re.finditer(
            r'variable\s+"([^"]+)"\s*\{([^}]+)\}',
            content,
            re.DOTALL,
        )
        for match in var_blocks:
            var_name = match.group(1)
            block = match.group(2)
            desc_match = re.search(r'description\s*=\s*"([^"]*)"', block)
            type_match = re.search(r'type\s*=\s*(\S+)', block)
            default_match = re.search(r'default\s*=\s*(.+)', block)
            variables[var_name] = {
                "description": desc_match.group(1) if desc_match else "",
                "type": type_match.group(1) if type_match else "any",
                "default": default_match.group(1).strip() if default_match else None,
            }
    except OSError as exc:
        logger.warning("Cannot read variables.tf from %s: %s", module_path, exc)

    return variables
