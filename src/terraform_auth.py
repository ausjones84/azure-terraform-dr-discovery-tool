"""
terraform_auth.py - Terraform & Azure Service Principal Auth Validator
=======================================================================
Validates Terraform authentication configuration for the Azure provider.
Supports Service Principal, Managed Identity, and Azure CLI auth methods.

SAFETY:
- NEVER logs, stores, or transmits credentials, secrets, or tokens.
- Only checks PRESENCE of environment variables, not their values.
- Does not run terraform init/plan/apply.
- Read-only environment inspection only.
"""

import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

logger = logging.getLogger(__name__)
console = Console()

# ARM environment variable names (checked for presence only)
SP_REQUIRED_VARS = ["ARM_CLIENT_ID", "ARM_CLIENT_SECRET", "ARM_TENANT_ID", "ARM_SUBSCRIPTION_ID"]
SP_OPTIONAL_VARS = ["ARM_ENVIRONMENT", "ARM_METADATA_HOST", "ARM_PARTNER_ID"]
MSI_VARS = ["ARM_USE_MSI", "ARM_MSI_ENDPOINT"]
CLI_VARS = ["ARM_USE_CLI", "ARM_USE_AZUREAD"]
OIDC_VARS = ["ARM_USE_OIDC", "ARM_OIDC_TOKEN", "ARM_OIDC_TOKEN_FILE_PATH"]


@dataclass
class TerraformEnvReport:
    """Report of Terraform ARM environment variable status."""
    auth_method: str = "none"  # sp / msi / cli / oidc / none
    arm_client_id_present: bool = False
    arm_client_secret_present: bool = False
    arm_tenant_id_present: bool = False
    arm_subscription_id_present: bool = False
    arm_use_msi: bool = False
    arm_use_cli: bool = False
    arm_use_azuread: bool = False
    arm_use_oidc: bool = False
    arm_oidc_configured: bool = False
    backend_type: str = ""
    backend_resource_group: str = ""
    backend_storage_account: str = ""
    backend_container: str = ""
    backend_key: str = ""
    is_ready: bool = False
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


def _az_cli_available() -> bool:
    """Check if az CLI is available."""
    try:
        r = subprocess.run(["az", "--version"], capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _running_in_pipeline() -> bool:
    """Detect common CI/CD pipeline environment variables."""
    pipeline_vars = ["TF_BUILD", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI"]
    return any(os.environ.get(v) for v in pipeline_vars)


def _mask(value: str) -> str:
    """Mask sensitive value - display only first/last 4 chars."""
    if not value or len(value) < 8:
        return "***"
    return value[:4] + "****" + value[-4:]


def inspect_arm_environment() -> TerraformEnvReport:
    """
    Inspect ARM environment variables for Terraform authentication.
    Checks PRESENCE ONLY - values are never read or logged.
    """
    report = TerraformEnvReport()
    report.arm_client_id_present = bool(os.environ.get("ARM_CLIENT_ID"))
    report.arm_client_secret_present = bool(os.environ.get("ARM_CLIENT_SECRET"))
    report.arm_tenant_id_present = bool(os.environ.get("ARM_TENANT_ID"))
    report.arm_subscription_id_present = bool(os.environ.get("ARM_SUBSCRIPTION_ID"))
    report.arm_use_msi = os.environ.get("ARM_USE_MSI", "").lower() in ("1", "true", "yes")
    report.arm_use_cli = os.environ.get("ARM_USE_CLI", "").lower() in ("1", "true", "yes")
    report.arm_use_azuread = os.environ.get("ARM_USE_AZUREAD", "").lower() in ("1", "true", "yes")
    report.arm_use_oidc = os.environ.get("ARM_USE_OIDC", "").lower() in ("1", "true", "yes")
    report.arm_oidc_configured = report.arm_use_oidc and (
        bool(os.environ.get("ARM_OIDC_TOKEN"))
        or bool(os.environ.get("ARM_OIDC_TOKEN_FILE_PATH"))
        or bool(os.environ.get("ARM_OIDC_REQUEST_URL"))
    )

    sp_complete = (
        report.arm_client_id_present and report.arm_client_secret_present
        and report.arm_tenant_id_present and report.arm_subscription_id_present
    )

    if sp_complete:
        report.auth_method = "sp"
        report.is_ready = True
    elif report.arm_use_msi:
        report.auth_method = "msi"
        report.is_ready = True
    elif report.arm_use_oidc and report.arm_oidc_configured:
        report.auth_method = "oidc"
        report.is_ready = True
    elif report.arm_use_cli or _az_cli_available():
        report.auth_method = "cli"
        report.is_ready = True
    else:
        report.auth_method = "none"
        report.is_ready = False

    if report.arm_client_id_present and not report.arm_client_secret_present:
        report.warnings.append("ARM_CLIENT_ID is set but ARM_CLIENT_SECRET is missing.")
    if report.arm_client_secret_present and not report.arm_client_id_present:
        report.warnings.append("ARM_CLIENT_SECRET is set but ARM_CLIENT_ID is missing.")
    if (report.arm_client_id_present or report.arm_client_secret_present) and not report.arm_tenant_id_present:
        report.warnings.append("ARM_TENANT_ID is not set - required for SP auth.")
    if not report.arm_subscription_id_present:
        report.warnings.append("ARM_SUBSCRIPTION_ID is not set. AzureRM provider requires this.")
    if report.arm_use_oidc and not report.arm_oidc_configured:
        report.warnings.append("ARM_USE_OIDC is set but OIDC token/URL not configured.")
    if not report.is_ready:
        report.errors.append(
            "No Terraform auth method configured. Options:\n"
            "  SP:  set ARM_CLIENT_ID, ARM_CLIENT_SECRET, ARM_TENANT_ID, ARM_SUBSCRIPTION_ID\n"
            "  CLI: set ARM_USE_CLI=true and run az login\n"
            "  MSI: set ARM_USE_MSI=true (Azure-hosted infra only)\n"
            "  See scripts/setup_auth.sh for templates."
        )
    if report.auth_method == "cli":
        report.recommendations.append("CLI auth is for local/dev only. Use SP or OIDC for pipelines.")
    if report.auth_method == "sp" and not _running_in_pipeline():
        report.recommendations.append("Ensure ARM_CLIENT_SECRET is set via vault/keychain, NOT hardcoded.")
    return report


def check_terraform_binary() -> Dict[str, str]:
    """Check if terraform binary is available and get version."""
    info = {"available": "false", "version": "not installed", "path": ""}
    try:
        result = subprocess.run(
            ["terraform", "version", "-json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            import json
            data = json.loads(result.stdout)
            info["available"] = "true"
            info["version"] = data.get("terraform_version", "")
        else:
            result2 = subprocess.run(["terraform", "version"], capture_output=True, text=True, timeout=10)
            if result2.returncode == 0:
                info["available"] = "true"
                lines = result2.stdout.strip().splitlines()
                info["version"] = lines[0] if lines else ""
    except FileNotFoundError:
        pass
    except Exception:
        pass
    try:
        which = subprocess.run(["which", "terraform"], capture_output=True, text=True, timeout=5)
        if which.returncode == 0:
            info["path"] = which.stdout.strip()
    except Exception:
        pass
    return info


def inspect_backend_config(repo_root: str) -> Dict[str, str]:
    """
    Parse Terraform backend config from repo directory.
    Extracts non-secret keys only (resource_group, storage_account, container, key).
    """
    import re
    backend_info: Dict[str, str] = {}
    search_files = ["backend.tf", "backend.hcl", "terraform.tf", "providers.tf", "main.tf"]
    root = Path(repo_root)
    for fname in search_files:
        fpath = root / fname
        if not fpath.exists():
            continue
        try:
            text = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if "azurerm" in text and "backend" in text:
            backend_info["type"] = "azurerm"
            for key in ["resource_group_name", "storage_account_name", "container_name", "key"]:
                match = re.search(rf'{key}\s*=\s*["\']([^"\' ]+)["\']', text)
                if match:
                    backend_info[key] = match.group(1)
            break
    return backend_info


def print_terraform_auth_report(report: TerraformEnvReport, tf_info: Dict[str, str]):
    """Print Terraform auth status as a rich table."""
    table = Table(
        title="[bold]Terraform Authentication Status[/bold]",
        box=box.ROUNDED,
        header_style="bold white on dark_blue",
        show_header=True,
    )
    table.add_column("Check", style="bold", width=35)
    table.add_column("Status", width=55)

    def ok(msg): return f"[green]PASS[/green]  {msg}"
    def warn(msg): return f"[yellow]WARN[/yellow]  {msg}"
    def fail(msg): return f"[red]FAIL[/red]  {msg}"

    tf_avail = tf_info.get("available") == "true"
    table.add_row(
        "Terraform binary",
        ok(f"terraform {tf_info.get('version')} at {tf_info.get('path')}")
        if tf_avail else warn("terraform not found - install from terraform.io")
    )
    method_labels = {
        "sp": "Service Principal (ARM_CLIENT_ID/SECRET/TENANT/SUBSCRIPTION)",
        "msi": "Managed Identity (ARM_USE_MSI=true)",
        "cli": "Azure CLI (ARM_USE_CLI or az available)",
        "oidc": "OIDC / Federated Identity (ARM_USE_OIDC)",
        "none": "NONE - not configured",
    }
    table.add_row(
        "Auth method",
        ok(method_labels.get(report.auth_method, report.auth_method)) if report.is_ready
        else fail(method_labels.get(report.auth_method, report.auth_method))
    )
    table.add_row("ARM_CLIENT_ID", ok("Set") if report.arm_client_id_present else warn("Not set"))
    table.add_row("ARM_CLIENT_SECRET", ok("Set (value masked)") if report.arm_client_secret_present else warn("Not set"))
    table.add_row("ARM_TENANT_ID", ok("Set") if report.arm_tenant_id_present else warn("Not set"))
    table.add_row("ARM_SUBSCRIPTION_ID", ok("Set") if report.arm_subscription_id_present else warn("Not set - required"))
    table.add_row("ARM_USE_MSI", ok("Enabled") if report.arm_use_msi else "[dim]Not set[/dim]")
    table.add_row("ARM_USE_CLI", ok("Enabled") if report.arm_use_cli else "[dim]Not set[/dim]")
    table.add_row("ARM_USE_OIDC", ok("Enabled + configured") if report.arm_oidc_configured else ("[yellow]Set but not configured[/yellow]" if report.arm_use_oidc else "[dim]Not set[/dim]"))
    table.add_row("Pipeline detected", ok("Yes - use SP/OIDC auth") if _running_in_pipeline() else "[dim]Local/dev environment[/dim]")
    console.print(table)

    if report.warnings:
        console.print("[yellow]Warnings:[/yellow]")
        for w in report.warnings:
            console.print(f"  [yellow]~[/yellow] {w}")
    if report.errors:
        console.print("[red]Errors:[/red]")
        for e in report.errors:
            console.print(f"  [red]![/red] {e}")
    if report.recommendations:
        console.print("[cyan]Recommendations:[/cyan]")
        for r in report.recommendations:
            console.print(f"  [cyan]>[/cyan] {r}")


def run_terraform_auth_check(repo_root: Optional[str] = None, fail_on_missing: bool = False) -> bool:
    """Run full Terraform auth check and print report."""
    console.print("[bold]Checking Terraform authentication...[/bold]")
    report = inspect_arm_environment()
    tf_info = check_terraform_binary()
    if repo_root:
        backend = inspect_backend_config(repo_root)
        if backend.get("type"):
            report.backend_type = backend.get("type", "")
            report.backend_resource_group = backend.get("resource_group_name", "")
            report.backend_storage_account = backend.get("storage_account_name", "")
            report.backend_container = backend.get("container_name", "")
            report.backend_key = backend.get("key", "")
    print_terraform_auth_report(report, tf_info)
    console.print()
    if fail_on_missing and not report.is_ready:
        return False
    return True


if __name__ == "__main__":
    import sys
    repo = sys.argv[1] if len(sys.argv) > 1 else None
    result = run_terraform_auth_check(repo_root=repo)
    sys.exit(0 if result else 1)
