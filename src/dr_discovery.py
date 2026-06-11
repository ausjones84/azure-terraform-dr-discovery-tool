#!/usr/bin/env python3
"""
dr_discovery.py - Azure Terraform DR Discovery Tool - Main CLI
==============================================================
Entry point for the Azure DR Discovery Tool.

Usage:
python dr_discovery.py --service ai_search \
--resource-name edav-dev-aisearch-eastus-internal \
--subscription b6085d96-6bb5-4e70-890c-e026d0cb1d1a \
--repo-root ./terraform-scripts \
--module-root ./terraform-modules \
--output ./reports

python dr_discovery.py --service openai \
--resource-group ocio-edav-dev-high-openaieast-rg \
--repo-root ./terraform-scripts \
--output ./reports

python dr_discovery.py --service ai_search \
--resource-name edav-dev-aisearch-eastus-internal \
--generate-stub --output ./generated

# Skip auth pre-flight (not recommended):
python dr_discovery.py --service ai_search --subscription <SUB_ID> --skip-auth-check

# Run auth check only:
python dr_discovery.py --auth-check

SAFETY:
Default mode is READ-ONLY. No Azure or Terraform changes are made.
--generate-stub ONLY creates draft files. It never runs terraform apply.
Authentication pre-flight runs by default to verify access before discovery.
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.text import Text
from rich import box

# Add src directory to path if running from repo root
src_dir = Path(__file__).parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from models import (
    DiscoveryReport, ComparisonResult, ComparisonStatus, RiskLevel,
    OwnershipValidation, OwnershipStatus, DeploymentSource,
)
from onboarding_engine import enrich_all_results
from azure_discovery import discover_resources
from terraform_search import TerraformSearchEngine, check_module_availability
from drift_parser import find_drift_files, parse_drift_file, match_drift_to_resource
from report_writer import write_all_reports
from stub_generator import generate_stub
from auth_check import require_azure_auth, check_azure_auth
from terraform_auth import run_terraform_auth_check

console = Console()
logger = logging.getLogger(__name__)

BANNER = """
[bold blue]Azure Terraform DR Discovery Tool[/bold blue]
[dim]Read-only discovery. No infrastructure changes made.[/dim]
"""


def classify_resource(
    azure_resource,
    tf_result,
    drift_entry=None,
) -> ComparisonResult:
    """
    Classify a resource's Terraform management status based on evidence.
    """
    cr = ComparisonResult(
        azure_resource=azure_resource,
        terraform_result=tf_result,
        drift_entry=drift_entry,
    )
    if tf_result and tf_result.matches:
        best = tf_result.best_confidence
        has_resource_def = tf_result.has_resource_definition
        has_module = tf_result.has_module_reference
        if best >= 0.9 and has_resource_def:
            cr.status = ComparisonStatus.TERRAFORM_MANAGED
            cr.confidence = best
        elif has_module and not has_resource_def:
            cr.status = ComparisonStatus.MODULE_AVAILABLE
            cr.confidence = 0.6
        elif best >= 0.6:
            cr.status = ComparisonStatus.POSSIBLE_MATCH
            cr.confidence = best
        else:
            cr.status = ComparisonStatus.AZURE_ONLY
            cr.confidence = 0.3
    else:
        cr.status = ComparisonStatus.AZURE_ONLY
        cr.confidence = 0.0

    if drift_entry and drift_entry.status:
        status_map = {
            "terraform_managed": ComparisonStatus.TERRAFORM_MANAGED,
            "azure_only": ComparisonStatus.AZURE_ONLY,
            "possible_match": ComparisonStatus.POSSIBLE_MATCH,
            "unknown": ComparisonStatus.UNKNOWN,
        }
        mapped = status_map.get(drift_entry.status.lower())
        if mapped:
            cr.status = mapped

    risk_notes = []
    risk = RiskLevel.LOW
    if cr.status == ComparisonStatus.AZURE_ONLY:
        risk = RiskLevel.HIGH
        risk_notes.append("Resource exists in Azure but no Terraform definition found")
    if azure_resource:
        if (azure_resource.public_network_access or "").lower() == "enabled":
            if risk.value in ("low", "medium"):
                risk = RiskLevel.MEDIUM
            risk_notes.append("WARNING: Public network access is ENABLED")
        for pe in azure_resource.private_endpoints:
            if pe.connection_state and pe.connection_state.lower() != "approved":
                if risk.value == "low":
                    risk = RiskLevel.MEDIUM
                risk_notes.append(
                    f"Private endpoint {pe.name} connection state: {pe.connection_state}"
                )
            if not pe.private_ip_address:
                risk_notes.append(f"WARNING: Private endpoint {pe.name} has no private IP address")
        if azure_resource.identity and azure_resource.identity.type == "None":
            risk_notes.append("No managed identity configured")
        if not azure_resource.diagnostic_settings:
            risk_notes.append("No diagnostic settings configured")
    action_map = {
        ComparisonStatus.TERRAFORM_MANAGED: (
            "Validate Terraform state matches Azure. Run terraform plan to check for drift."
        ),
        ComparisonStatus.AZURE_ONLY: (
            "Resource is not managed by Terraform. Confirm with team whether Terraform "
            "import is needed. Use --generate-stub to create a draft module deployment."
        ),
        ComparisonStatus.MODULE_AVAILABLE: (
            "Module exists but no deployment found. Create deployment definition "
            "referencing the existing module. Consider --generate-stub."
        ),
        ComparisonStatus.TERRAFORM_ONBOARDING_CANDIDATE: (
            "TERRAFORM ONBOARDING REQUIRED. Resource exists in Azure, module exists in repo, "
            "but no deployment definition found. Resource was created outside Terraform. "
            "Generate deployment definition, import existing resources, run plan, "
            "validate Plan: 0 to add, 0 to change, 0 to destroy before any apply."
        ),
        ComparisonStatus.POSSIBLE_MATCH: (
            "Possible Terraform match found. Review matched files to confirm."
        ),
        ComparisonStatus.UNKNOWN: (
            "Unable to determine status. Manual review required."
        ),
    }
    cr.recommended_action = action_map.get(cr.status, "Manual review required.")
    cr.risk_level = risk
    cr.risk_notes = risk_notes
    return cr


def print_banner():
    console.print(Panel.fit(BANNER, border_style="blue"))


def print_summary_table(report: DiscoveryReport):
    table = Table(
        title="[bold]Discovery Summary[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on blue",
    )
    table.add_column("Field", style="bold", width=25)
    table.add_column("Value", width=55)
    table.add_row("Service", report.service)
    table.add_row("Resource Name", report.resource_name or "-")
    table.add_row("Subscription", report.subscription_id or "-")
    table.add_row("Resource Group", report.resource_group or "-")
    table.add_row("Resources Found", str(len(report.azure_resources)))
    table.add_row("Comparison Results", str(len(report.comparison_results)))
    table.add_row("Drift Entries", str(len(report.drift_entries)))
    status_color = {
        ComparisonStatus.TERRAFORM_MANAGED: "green",
        ComparisonStatus.AZURE_ONLY: "red",
        ComparisonStatus.POSSIBLE_MATCH: "yellow",
        ComparisonStatus.MODULE_AVAILABLE: "cyan",
        ComparisonStatus.TERRAFORM_ONBOARDING_CANDIDATE: "bold magenta",
        ComparisonStatus.UNKNOWN: "dim",
    }.get(report.summary_status, "white")
    table.add_row(
        "Overall Status",
        Text(report.summary_status.value if report.summary_status else "-", style=status_color)
    )
    risk_color = {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "bold red",
    }.get(report.overall_risk, "white")
    table.add_row(
        "Overall Risk",
        Text(report.overall_risk.value if report.overall_risk else "-", style=risk_color)
    )
    console.print(table)


def print_comparison_results(results: List[ComparisonResult]):
    if not results:
        console.print("[yellow]No comparison results to display.[/yellow]")
        return
    table = Table(
        title="[bold]Terraform Comparison Results[/bold]",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold white on dark_blue",
    )
    table.add_column("Resource", style="bold", min_width=30)
    table.add_column("Status", min_width=25)
    table.add_column("Risk", min_width=10)
    table.add_column("TF Matches", justify="center")
    table.add_column("Confidence", justify="center")
    for cr in results:
        name = cr.azure_resource.name if cr.azure_resource else "N/A"
        status_color = {
            ComparisonStatus.TERRAFORM_MANAGED: "green",
            ComparisonStatus.AZURE_ONLY: "red",
            ComparisonStatus.POSSIBLE_MATCH: "yellow",
            ComparisonStatus.MODULE_AVAILABLE: "cyan",
            ComparisonStatus.TERRAFORM_ONBOARDING_CANDIDATE: "bold magenta",
        }.get(cr.status, "white")
        risk_color = {
            RiskLevel.LOW: "green",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "red",
            RiskLevel.CRITICAL: "bold red",
        }.get(cr.risk_level, "white")
        matches = len(cr.terraform_result.matches) if cr.terraform_result else 0
        table.add_row(
            name,
            Text(cr.status.value, style=status_color),
            Text(cr.risk_level.value, style=risk_color),
            str(matches),
            f"{cr.confidence:.0%}",
        )
    console.print(table)


def print_risk_warnings(results: List[ComparisonResult]):
    has_warnings = any(cr.risk_notes for cr in results)
    if not has_warnings:
        return
    console.print("[bold red]Risk Warnings:[/bold red]")
    for cr in results:
        if cr.risk_notes:
            name = cr.azure_resource.name if cr.azure_resource else "N/A"
            for note in cr.risk_notes:
                if "WARNING" in note.upper() or cr.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                    console.print(f"  [red]![/red] [{name}] {note}")
                else:
                    console.print(f"  [yellow]~[/yellow] [{name}] {note}")


def print_next_steps(report: DiscoveryReport):
    if report.next_steps:
        console.print("[bold]Recommended Next Steps:[/bold]")
        for i, step in enumerate(report.next_steps, start=1):
            console.print(f"  [cyan]{i}.[/cyan] {step}")


def load_config(config_path: str) -> dict:
    """Load optional YAML config file."""
    path = Path(config_path)
    if not path.exists():
        logger.warning("Config file not found: %s", config_path)
        return {}
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as exc:
        logger.warning("Failed to load config %s: %s", config_path, exc)
        return {}


def run_discovery(
    service: str,
    subscription_id: str,
    resource_name: Optional[str],
    resource_group: Optional[str],
    repo_roots: List[str],
    module_roots: List[str],
    output_dir: str,
    generate_stub_mode: bool = False,
    env_path: str = "edav/dev",
    templates_dir: Optional[str] = None,
    skip_auth_check: bool = False,
) -> DiscoveryReport:
    """
    Core discovery workflow.

    Steps:
    0. Auth pre-flight check (Azure login + subscription access)
    1. Print safety banner
    2. Discover Azure resources
    3. Search Terraform repositories
    4. Parse drift files
    5. Classify comparison results
    6. Build report
    7. Write reports
    8. (Optional) Generate Terraform stubs
    """
    print_banner()
    mode_label = "[red]STUB GENERATION[/red]" if generate_stub_mode else "[green]READ-ONLY DISCOVERY[/green]"
    console.print(f"[bold]Mode:[/bold] {mode_label}")
    console.print()

    # -----------------------------------------------------------------------
    # Step 0: Authentication Pre-flight
    # -----------------------------------------------------------------------
    if not skip_auth_check:
        auth_ok = require_azure_auth(
            subscription_id=subscription_id,
            repo_root=repo_roots[0] if repo_roots else None,
            check_terraform=False,  # TF auth only needed for apply, which we never do
            allow_missing_tf_auth=True,
        )
        if not auth_ok:
            console.print()
            console.print("[bold red]Authentication pre-flight failed. Aborting discovery.[/bold red]")
            console.print("[dim]Fix the auth issues above and re-run. Use --skip-auth-check to bypass (not recommended).[/dim]")
            sys.exit(1)
        console.print()
    else:
        console.print("[yellow]WARNING: Auth pre-flight check skipped (--skip-auth-check). Use with caution.[/yellow]")
        console.print()

    report = DiscoveryReport(
        service=service,
        resource_name=resource_name or "",
        subscription_id=subscription_id,
        resource_group=resource_group or "",
        repo_root=", ".join(repo_roots),
        module_root=", ".join(module_roots),
        run_timestamp=datetime.now().isoformat(timespec="seconds"),
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=True,
    ) as progress:

        task1 = progress.add_task("[cyan]Discovering Azure resources...", total=None)
        try:
            report.azure_resources = discover_resources(
                service=service,
                subscription_id=subscription_id,
                resource_group=resource_group,
                resource_name=resource_name,
            )
            progress.update(task1, description=f"[green]Found {len(report.azure_resources)} resource(s)")
        except Exception as exc:
            console.print(f"[red]Azure discovery failed: {exc}[/red]")
            logger.exception("Azure discovery error")
            report.azure_resources = []
        progress.stop_task(task1)

        if not report.azure_resources:
            console.print("[yellow]No Azure resources found. Check your subscription/resource-group/name filters.[/yellow]")

        task2 = progress.add_task("[cyan]Searching Terraform repositories...", total=None)
        engine = TerraformSearchEngine(repo_roots=repo_roots, module_roots=module_roots)
        tf_results = []
        for res in report.azure_resources:
            pe_names = [pe.name for pe in res.private_endpoints]
            vnet_names = list({pe.vnet_name for pe in res.private_endpoints if pe.vnet_name})
            subnet_names = list({pe.subnet_name for pe in res.private_endpoints if pe.subnet_name})
            nic_names = [pe.nic_name for pe in res.private_endpoints if pe.nic_name]
            tf_result = engine.search_resource(
                resource_name=res.name,
                resource_type=res.resource_type,
                resource_group=res.resource_group,
                vnet_names=vnet_names,
                subnet_names=subnet_names,
                pe_names=pe_names,
                nic_names=nic_names,
            )
            tf_results.append(tf_result)
        progress.update(task2, description="[green]Terraform search complete")
        progress.stop_task(task2)

        task3 = progress.add_task("[cyan]Scanning for drift files...", total=None)
        all_search_roots = repo_roots + module_roots
        drift_files = find_drift_files(all_search_roots)
        for df in drift_files:
            entries = parse_drift_file(df)
            report.drift_entries.extend(entries)
        progress.update(task3, description=f"[green]Found {len(report.drift_entries)} drift entries")
        progress.stop_task(task3)

        task4 = progress.add_task("[cyan]Comparing Azure vs Terraform...", total=None)
        for res, tf_result in zip(report.azure_resources, tf_results):
            drift_entry = match_drift_to_resource(
                report.drift_entries, res.name, res.resource_group, res.resource_type,
            )
            cr = classify_resource(res, tf_result, drift_entry)
            report.comparison_results.append(cr)
        progress.update(task4, description="[green]Comparison complete")
        progress.stop_task(task4)

        if report.comparison_results:
            statuses = [cr.status for cr in report.comparison_results]
            risks = [cr.risk_level for cr in report.comparison_results]
            if any(s == ComparisonStatus.TERRAFORM_MANAGED for s in statuses):
                report.summary_status = ComparisonStatus.TERRAFORM_MANAGED
            elif any(s == ComparisonStatus.POSSIBLE_MATCH for s in statuses):
                report.summary_status = ComparisonStatus.POSSIBLE_MATCH
            elif any(s == ComparisonStatus.MODULE_AVAILABLE for s in statuses):
                report.summary_status = ComparisonStatus.MODULE_AVAILABLE
            else:
                report.summary_status = ComparisonStatus.AZURE_ONLY
            risk_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]
            for risk in risk_order:
                if risk in risks:
                    report.overall_risk = risk
                    break
            else:
                report.overall_risk = RiskLevel.LOW
        else:
            report.summary_status = ComparisonStatus.UNKNOWN
            report.overall_risk = RiskLevel.MEDIUM

    report.key_findings = _build_key_findings(report)
    report.next_steps = _build_next_steps(report)
    print_summary_table(report)
    print_comparison_results(report.comparison_results)
    print_risk_warnings(report.comparison_results)
    print_next_steps(report)

    console.print()
    console.print(f"[bold]Writing reports to:[/bold] {output_dir}")
    tmpl_dir = templates_dir or str(Path(__file__).parent.parent / "templates")
    written = write_all_reports(report, output_dir, tmpl_dir)
    for fmt, path in written.items():
        console.print(f"  [green]checkmark[/green] {fmt.upper()}: {path}")

    if generate_stub_mode:
        console.print()
        console.print("[bold yellow]STUB GENERATION MODE[/bold yellow]")
        console.print("[dim]Generating draft Terraform stubs. Review all TODO values before use.[/dim]")
        generated = generate_stub(
            service=service,
            report=report,
            output_dir=output_dir,
            module_root=module_roots[0] if module_roots else ".",
            templates_dir=tmpl_dir,
            env_path=env_path,
        )
        for gen_path in generated:
            console.print(f"  [yellow]STUB[/yellow] {gen_path}")

    console.print()
    console.print("[bold green]Discovery complete.[/bold green]")
    return report


def _build_key_findings(report: DiscoveryReport) -> List[str]:
    findings = []
    for cr in report.comparison_results:
        name = cr.azure_resource.name if cr.azure_resource else "unknown"
        if cr.status == ComparisonStatus.AZURE_ONLY:
            findings.append(f"{name}: Azure resource found but NO active Terraform deployment definition located")
        elif cr.status == ComparisonStatus.TERRAFORM_MANAGED:
            findings.append(f"{name}: Likely managed by Terraform (confidence: {cr.confidence:.0%})")
        elif cr.status == ComparisonStatus.MODULE_AVAILABLE:
            findings.append(f"{name}: Terraform module exists but no deployment definition found")
        for note in cr.risk_notes:
            findings.append(f"{name}: {note}")
    return findings


def _build_next_steps(report: DiscoveryReport) -> List[str]:
    steps = []
    has_azure_only = any(cr.status == ComparisonStatus.AZURE_ONLY for cr in report.comparison_results)
    has_module = any(cr.status == ComparisonStatus.MODULE_AVAILABLE for cr in report.comparison_results)
    has_tf = any(cr.status == ComparisonStatus.TERRAFORM_MANAGED for cr in report.comparison_results)
    has_public = any(
        (cr.azure_resource.public_network_access or "").lower() == "enabled"
        for cr in report.comparison_results if cr.azure_resource
    )
    if has_azure_only:
        steps.append("Confirm with the team whether this resource is managed in another repo or branch")
        steps.append("If Terraform management is required, use --generate-stub to create a draft module deployment, then review carefully before any apply")
        steps.append("Add terraform import commands BEFORE first terraform apply to avoid recreation")
    if has_module:
        steps.append("Module is available. Create deployment definition instantiating the module")
    if has_tf:
        steps.append("Run terraform plan to detect any drift between Azure state and Terraform code")
    if has_public:
        steps.append("REVIEW: Public network access is enabled on one or more resources. Confirm this is intentional.")
    if not steps:
        steps.append("Review reports and confirm all resource configurations are correct")
    steps.append("Update the Azure DevOps ticket with the findings using the ticket draft")
    steps.append("Share Teams message with resource owner for confirmation before any changes")
    return steps


@click.command()
@click.option("--service", "-s", required=False, default=None,
    type=click.Choice(["ai_search", "openai", "ai_foundry"], case_sensitive=False),
    help="Service type to discover.")
@click.option("--resource-name", "-n", default=None, help="Azure resource name filter.")
@click.option("--resource-group", "-g", default=None, help="Azure resource group filter.")
@click.option("--subscription", "-sub", default=None, help="Azure subscription ID.")
@click.option("--repo-root", "-r", multiple=True, default=["./terraform-scripts"], show_default=True)
@click.option("--module-root", "-m", multiple=True, default=["./terraform-modules"], show_default=True)
@click.option("--output", "-o", default="./reports", show_default=True)
@click.option("--generate-stub", is_flag=True, default=False,
    help="[EXPLICIT] Generate Terraform stub files. NOT run by default.")
@click.option("--env-path", default="edav/dev", show_default=True)
@click.option("--config", "-c", default=None)
@click.option("--templates-dir", default=None)
@click.option("--verbose", "-v", is_flag=True, default=False)
@click.option("--skip-auth-check", is_flag=True, default=False,
    help="Skip Azure auth pre-flight check. Not recommended.")
@click.option("--auth-check", is_flag=True, default=False,
    help="Run auth check only without performing discovery.")
@click.option("--check-tf-auth", is_flag=True, default=False,
    help="Include Terraform ARM auth status in pre-flight check.")
def main(
    service, resource_name, resource_group, subscription,
    repo_root, module_root, output, generate_stub, env_path,
    config, templates_dir, verbose, skip_auth_check, auth_check, check_tf_auth,
):
    """
    Azure Terraform DR Discovery Tool

    Discovers Azure resources, searches Terraform repositories,
    compares Azure vs Terraform, and generates DR findings reports.

    Default mode is READ-ONLY. Use --generate-stub explicitly to create
    draft Terraform stubs (no apply is ever performed).

    Authentication pre-flight runs by default. Use --skip-auth-check to bypass.
    Run --auth-check to verify authentication without performing discovery.
    """
    log_level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Auth-check-only mode
    if auth_check:
        from auth_check import check_azure_auth, print_auth_status, TerraformAuthStatus
        console.print(Panel.fit(BANNER, border_style="blue"))
        console.print("[bold]Authentication Check Mode[/bold]")
        console.print()
        az_status = check_azure_auth(subscription)
        tf_status = TerraformAuthStatus()
        if check_tf_auth:
            from terraform_auth import inspect_arm_environment
            tf_env = inspect_arm_environment()
            tf_status.arm_client_id_set = tf_env.arm_client_id_present
            tf_status.arm_client_secret_set = tf_env.arm_client_secret_present
            tf_status.arm_tenant_id_set = tf_env.arm_tenant_id_present
            tf_status.arm_subscription_id_set = tf_env.arm_subscription_id_present
            tf_status.use_msi = tf_env.arm_use_msi
            tf_status.use_cli = tf_env.arm_use_cli
            tf_status.is_complete = tf_env.is_ready
        from auth_check import print_auth_status
        print_auth_status(az_status, tf_status)
        if check_tf_auth:
            run_terraform_auth_check()
        sys.exit(0)

    # Require service for actual discovery
    if not service:
        console.print("[red]Error: --service is required for discovery. Use --auth-check to check auth only.[/red]")
        sys.exit(1)

    cfg = load_config(config) if config else {}
    resolved_subscription = subscription or cfg.get("subscription_id")
    resolved_resource_name = resource_name or cfg.get("resource_name")
    resolved_resource_group = resource_group or cfg.get("resource_group")
    resolved_repo_roots = list(repo_root) or cfg.get("repo_roots", [])
    resolved_module_roots = list(module_root) or cfg.get("module_roots", [])
    resolved_output = output or cfg.get("output_dir", "./reports")
    resolved_templates = templates_dir or cfg.get("templates_dir")

    if not resolved_subscription:
        console.print("[red]Error: --subscription is required.[/red]")
        sys.exit(1)

    run_discovery(
        service=service,
        subscription_id=resolved_subscription,
        resource_name=resolved_resource_name,
        resource_group=resolved_resource_group,
        repo_roots=resolved_repo_roots,
        module_roots=resolved_module_roots,
        output_dir=resolved_output,
        generate_stub_mode=generate_stub,
        env_path=env_path,
        templates_dir=resolved_templates,
        skip_auth_check=skip_auth_check,
    )


if __name__ == "__main__":
    main()
