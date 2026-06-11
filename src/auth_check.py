"""
auth_check.py - Azure Authentication & Login Verification
==========================================================
Verifies Azure CLI login status, subscription access, and required
permissions before running any discovery commands.

SAFETY:
- READ-ONLY checks only. Never modifies Azure resources.
- Never stores or logs credentials, tokens, or secrets.
- Requires explicit user action to authenticate (never auto-logins).
- Privileged operations (subscription switch) require confirmation.
"""

import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional, List, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

logger = logging.getLogger(__name__)
console = Console()


# ---------------------------------------------------------------------------
# Auth result models
# ---------------------------------------------------------------------------

@dataclass
class AzureAuthStatus:
    """Result of an Azure authentication check."""
    is_logged_in: bool = False
    account_name: str = ""
    account_type: str = ""           # user / servicePrincipal / managedIdentity
    tenant_id: str = ""
    current_subscription_id: str = ""
    current_subscription_name: str = ""
    target_subscription_accessible: bool = False
    target_subscription_name: str = ""
    has_required_permissions: bool = False
    missing_permissions: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class TerraformAuthStatus:
    """Result of a Terraform/Azure backend auth check."""
    arm_client_id_set: bool = False
    arm_client_secret_set: bool = False   # presence check ONLY — value never logged
    arm_tenant_id_set: bool = False
    arm_subscription_id_set: bool = False
    use_msi: bool = False                  # Managed Identity auth
    use_cli: bool = False                  # Azure CLI auth (dev mode)
    backend_config_detected: bool = False
    backend_type: str = ""
    is_complete: bool = False
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_az(args: List[str]) -> Optional[Dict]:
    """Run an Azure CLI command silently and return parsed JSON."""
    cmd = ["az"] + args + ["--output", "json"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.debug("az %s failed: %s", " ".join(args[:3]), result.stderr.strip()[:100])
            return None
        if not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except FileNotFoundError:
        return None
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def _az_available() -> bool:
    """Check if Azure CLI is installed and on the PATH."""
    try:
        result = subprocess.run(
            ["az", "--version"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _mask(value: str) -> str:
    """Mask a sensitive value for safe display."""
    if not value or len(value) < 8:
        return "***"
    return value[:4] + "****" + value[-4:]


# ---------------------------------------------------------------------------
# Azure CLI auth check
# ---------------------------------------------------------------------------

def check_azure_auth(target_subscription_id: Optional[str] = None) -> AzureAuthStatus:
    """
    Check Azure CLI authentication status.

    Verifies:
    - Azure CLI is installed
    - User is logged in
    - Target subscription is accessible
    - Basic read permissions exist (resource list)

    Args:
        target_subscription_id: Subscription ID the tool will operate against.

    Returns:
        AzureAuthStatus with full auth status details.
    """
    status = AzureAuthStatus()

    # Check az CLI is available
    if not _az_available():
        status.errors.append(
            "Azure CLI (az) is not installed or not on PATH. "
            "Install from: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli"
        )
        return status

    # Check signed-in account
    account = _run_az(["account", "show"])
    if not account:
        status.errors.append(
            "Not logged in to Azure CLI. Run: az login"
        )
        return status

    status.is_logged_in = True
    status.account_name = account.get("user", {}).get("name", "")
    status.account_type = account.get("user", {}).get("type", "user")
    status.tenant_id = account.get("tenantId", "")
    status.current_subscription_id = account.get("id", "")
    status.current_subscription_name = account.get("name", "")

    # Check target subscription accessibility
    if target_subscription_id:
        subs_raw = _run_az(["account", "list"])
        accessible_ids = [
            s.get("id", "").lower() for s in (subs_raw or [])
        ]
        target_lower = target_subscription_id.lower()

        if target_lower in accessible_ids:
            status.target_subscription_accessible = True
            # Find subscription name
            for s in (subs_raw or []):
                if s.get("id", "").lower() == target_lower:
                    status.target_subscription_name = s.get("name", "")
                    break

            # Warn if not the active subscription
            if status.current_subscription_id.lower() != target_lower:
                status.warnings.append(
                    f"Target subscription ({_mask(target_subscription_id)}) is not the "
                    "currently active subscription. The tool will specify --subscription "
                    "on each az command, but consider running: "
                    f"az account set --subscription {target_subscription_id}"
                )
        else:
            status.target_subscription_accessible = False
            status.errors.append(
                f"Target subscription {_mask(target_subscription_id)} is not accessible. "
                "Check subscription ID or request access. "
                "Run: az account list --output table"
            )
    else:
        # No target subscription specified — use current
        status.target_subscription_accessible = True
        status.target_subscription_name = status.current_subscription_name

    # Permission check: try a basic read operation
    if status.target_subscription_accessible:
        check_sub = target_subscription_id or status.current_subscription_id
        test_read = _run_az([
            "resource", "list",
            "--subscription", check_sub,
            "--resource-type", "Microsoft.Search/searchServices",
            "--query", "[].name",
        ])
        if test_read is None:
            status.missing_permissions.append(
                "Read access to Microsoft.Search/searchServices — "
                "check RBAC: Reader role on subscription or resource group"
            )
            status.warnings.append(
                "Limited permissions detected. Some discovery steps may fail."
            )
        else:
            status.has_required_permissions = True

    return status


# ---------------------------------------------------------------------------
# Terraform backend / ARM env var check
# ---------------------------------------------------------------------------

def check_terraform_auth(repo_root: Optional[str] = None) -> TerraformAuthStatus:
    """
    Check Terraform authentication setup.

    Checks:
    - ARM_* environment variables are set (presence only, never values)
    - Whether MSI or CLI auth is configured
    - Backend config files in the repo root

    Args:
        repo_root: Optional path to terraform scripts repo for backend detection.

    Returns:
        TerraformAuthStatus with full status details.
    """
    status = TerraformAuthStatus()

    # Check ARM environment variables (presence only — NEVER log values)
    arm_client_id = os.environ.get("ARM_CLIENT_ID", "")
    arm_client_secret = os.environ.get("ARM_CLIENT_SECRET", "")
    arm_tenant_id = os.environ.get("ARM_TENANT_ID", "")
    arm_sub_id = os.environ.get("ARM_SUBSCRIPTION_ID", "")
    arm_use_msi = os.environ.get("ARM_USE_MSI", "").lower() in ("1", "true", "yes")
    arm_use_cli = os.environ.get("ARM_USE_CLI", "").lower() in ("1", "true", "yes")

    status.arm_client_id_set = bool(arm_client_id)
    status.arm_client_secret_set = bool(arm_client_secret)  # presence only
    status.arm_tenant_id_set = bool(arm_tenant_id)
    status.arm_subscription_id_set = bool(arm_sub_id)
    status.use_msi = arm_use_msi
    status.use_cli = arm_use_cli

    # Determine if auth is complete
    has_sp_auth = (
        status.arm_client_id_set
        and status.arm_client_secret_set
        and status.arm_tenant_id_set
        and status.arm_subscription_id_set
    )
    has_msi_auth = arm_use_msi
    has_cli_auth = arm_use_cli or _az_available()  # CLI available = can use CLI auth

    status.is_complete = has_sp_auth or has_msi_auth or has_cli_auth

    # Warnings for partial configs
    if status.arm_client_id_set and not status.arm_client_secret_set:
        status.warnings.append(
            "ARM_CLIENT_ID is set but ARM_CLIENT_SECRET is missing. "
            "Service principal auth will fail."
        )
    if status.arm_client_secret_set and not status.arm_client_id_set:
        status.warnings.append(
            "ARM_CLIENT_SECRET is set but ARM_CLIENT_ID is missing."
        )
    if (status.arm_client_id_set or status.arm_client_secret_set) and not status.arm_tenant_id_set:
        status.warnings.append(
            "ARM_TENANT_ID is not set. Required for service principal auth."
        )
    if not status.arm_subscription_id_set:
        status.warnings.append(
            "ARM_SUBSCRIPTION_ID is not set. "
            "Terraform will need this for provider configuration."
        )

    if not status.is_complete:
        status.errors.append(
            "No complete Terraform auth method detected. "
            "Options: (1) Set ARM_CLIENT_ID/SECRET/TENANT_ID/SUBSCRIPTION_ID for SP auth, "
            "(2) Set ARM_USE_MSI=true for managed identity, "
            "(3) Set ARM_USE_CLI=true to use Azure CLI auth (dev/local use)."
        )

    # Detect backend config
    if repo_root:
        from pathlib import Path
        backend_files = [
            "backend.tf", "backend.hcl", "providers.tf",
            "terraform.tf", "_backend.tf",
        ]
        for fname in backend_files:
            fpath = Path(repo_root) / fname
            if fpath.exists():
                status.backend_config_detected = True
                try:
                    text = fpath.read_text(encoding="utf-8", errors="ignore").lower()
                    if "azurerm" in text:
                        status.backend_type = "azurerm"
                    elif "s3" in text:
                        status.backend_type = "s3"
                    elif "gcs" in text:
                        status.backend_type = "gcs"
                    elif "local" in text:
                        status.backend_type = "local"
                    else:
                        status.backend_type = "unknown"
                except Exception:
                    status.backend_type = "unknown"
                break

    return status


# ---------------------------------------------------------------------------
# Rich terminal output
# ---------------------------------------------------------------------------

def print_auth_status(az_status: AzureAuthStatus, tf_status: TerraformAuthStatus):
    """Print a rich terminal table of authentication status."""
    table = Table(
        title="[bold]Authentication Pre-flight Check[/bold]",
        box=box.ROUNDED,
        header_style="bold white on dark_blue",
        show_header=True,
    )
    table.add_column("Check", style="bold", width=35)
    table.add_column("Status", width=50)

    def ok(msg): return f"[green]PASS[/green]  {msg}"
    def warn(msg): return f"[yellow]WARN[/yellow]  {msg}"
    def fail(msg): return f"[red]FAIL[/red]  {msg}"

    # Azure checks
    table.add_row("Azure CLI installed", ok("az found") if _az_available() else fail("az not found"))
    table.add_row(
        "Azure CLI login",
        ok(f"Signed in as {az_status.account_name} ({az_status.account_type})")
        if az_status.is_logged_in else fail("Not logged in — run: az login")
    )
    table.add_row(
        "Target subscription",
        ok(f"Accessible: {az_status.target_subscription_name or az_status.current_subscription_name}")
        if az_status.target_subscription_accessible else fail("Not accessible")
    )
    table.add_row(
        "Read permissions",
        ok("Basic read verified") if az_status.has_required_permissions
        else warn("Limited permissions — some steps may fail")
    )

    # Terraform checks
    tf_auth_method = ""
    if tf_status.use_msi:
        tf_auth_method = "Managed Identity (ARM_USE_MSI)"
    elif tf_status.arm_client_id_set and tf_status.arm_client_secret_set:
        tf_auth_method = f"Service Principal (ARM_CLIENT_ID: {_mask(os.environ.get('ARM_CLIENT_ID', ''))})"
    elif tf_status.use_cli:
        tf_auth_method = "Azure CLI (ARM_USE_CLI)"
    elif _az_available():
        tf_auth_method = "Azure CLI (implicit — az available)"

    table.add_row(
        "Terraform ARM auth",
        ok(tf_auth_method) if tf_status.is_complete else fail("No complete TF auth method")
    )
    table.add_row(
        "ARM_SUBSCRIPTION_ID",
        ok("Set") if tf_status.arm_subscription_id_set else warn("Not set — required for TF provider")
    )
    table.add_row(
        "Terraform backend",
        ok(f"Detected: {tf_status.backend_type}") if tf_status.backend_config_detected
        else warn("No backend config found in repo root")
    )

    console.print(table)

    # Print warnings
    all_warnings = az_status.warnings + tf_status.warnings
    if all_warnings:
        console.print("[yellow]Auth Warnings:[/yellow]")
        for w in all_warnings:
            console.print(f"  [yellow]~[/yellow] {w}")

    # Print errors
    all_errors = az_status.errors + tf_status.errors
    if all_errors:
        console.print("[red]Auth Errors:[/red]")
        for e in all_errors:
            console.print(f"  [red]![/red] {e}")


# ---------------------------------------------------------------------------
# Pre-flight guard
# ---------------------------------------------------------------------------

def require_azure_auth(
    subscription_id: Optional[str] = None,
    repo_root: Optional[str] = None,
    check_terraform: bool = False,
    allow_missing_tf_auth: bool = True,
) -> bool:
    """
    Run pre-flight auth checks. Print results. Optionally abort if checks fail.

    Args:
        subscription_id: Target subscription to validate access for.
        repo_root: Terraform repo root for backend detection.
        check_terraform: Whether to check Terraform ARM env vars.
        allow_missing_tf_auth: If False, abort when TF auth is incomplete.

    Returns:
        True if auth is sufficient to proceed. False if critical checks failed.
    """
    console.print("[bold]Running authentication pre-flight checks...[/bold]")
    console.print()

    az_status = check_azure_auth(subscription_id)
    tf_status = check_terraform_auth(repo_root) if check_terraform else TerraformAuthStatus(is_complete=True)

    print_auth_status(az_status, tf_status)
    console.print()

    # Abort conditions
    if not az_status.is_logged_in:
        console.print(Panel(
            "[bold red]CRITICAL: Not logged in to Azure CLI.[/bold red]\n"
            "Run the following command and re-run the tool:\n"
            "  [bold]az login[/bold]\n"
            "For service principal login:\n"
            "  [bold]az login --service-principal -u <CLIENT_ID> -p <CLIENT_SECRET> --tenant <TENANT_ID>[/bold]",
            title="Authentication Required",
            border_style="red",
        ))
        return False

    if not az_status.target_subscription_accessible:
        console.print(Panel(
            "[bold red]CRITICAL: Target subscription is not accessible.[/bold red]\n"
            "Verify the subscription ID and your access. Commands to check:\n"
            "  [bold]az account list --output table[/bold]\n"
            "  [bold]az account set --subscription <SUBSCRIPTION_ID>[/bold]",
            title="Subscription Access Required",
            border_style="red",
        ))
        return False

    if check_terraform and not tf_status.is_complete and not allow_missing_tf_auth:
        console.print(Panel(
            "[bold red]Terraform auth is not configured.[/bold red]\n"
            "Set ARM environment variables or use ARM_USE_CLI=true.\n"
            "See scripts/setup_auth.sh for a helper template.",
            title="Terraform Auth Required",
            border_style="red",
        ))
        return False

    console.print("[bold green]Auth pre-flight: PASSED[/bold green]")
    return True


# ---------------------------------------------------------------------------
# Subscription switch helper
# ---------------------------------------------------------------------------

def prompt_subscription_switch(target_subscription_id: str) -> bool:
    """
    Prompt the user to switch active subscription.

    IMPORTANT: This only switches the az CLI context, not Azure itself.
    No Azure resources are modified.

    Args:
        target_subscription_id: Subscription ID to switch to.

    Returns:
        True if switch succeeded, False otherwise.
    """
    console.print(
        f"[yellow]Active subscription differs from target.[/yellow]\n"
        f"Target: [bold]{_mask(target_subscription_id)}[/bold]\n"
        "Switch active subscription? This only affects your local az CLI context."
    )
    confirm = input("Switch subscription? [y/N]: ").strip().lower()
    if confirm != "y":
        console.print("[dim]Subscription not switched. Tool will pass --subscription on each command.[/dim]")
        return False

    result = subprocess.run(
        ["az", "account", "set", "--subscription", target_subscription_id],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        console.print(f"[green]Switched active subscription to {_mask(target_subscription_id)}[/green]")
        return True
    else:
        console.print(f"[red]Failed to switch subscription: {result.stderr.strip()}[/red]")
        return False
