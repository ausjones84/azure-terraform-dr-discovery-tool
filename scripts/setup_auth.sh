#!/usr/bin/env bash
# =============================================================================
# setup_auth.sh - Azure & Terraform Authentication Setup Helper
# =============================================================================
# PURPOSE:
#   Provides templates for configuring Azure CLI and Terraform ARM environment
#   variables needed by the DR Discovery Tool.
#
# SAFETY:
#   - NEVER hardcode secrets, passwords, or keys in this file.
#   - NEVER commit this file with real values filled in.
#   - Use Azure Key Vault, environment-specific vaults, or CI/CD secret stores.
#   - This file is a TEMPLATE only. Fill values at runtime.
#
# USAGE:
#   source scripts/setup_auth.sh           # Load into current shell
#   bash scripts/setup_auth.sh --check     # Run auth check only
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# OPTION 1: Azure CLI Login (recommended for local/dev use)
# ---------------------------------------------------------------------------
# Uncomment and run the appropriate line for your scenario:

# Interactive browser login:
# az login

# Service principal login (for scripts/pipelines):
# az login --service-principal \
#   --username "${ARM_CLIENT_ID}" \
#   --password "${ARM_CLIENT_SECRET}" \
#   --tenant "${ARM_TENANT_ID}"

# Managed Identity login (Azure VMs, AKS, Azure DevOps agents):
# az login --identity

# ---------------------------------------------------------------------------
# OPTION 2: Set Active Subscription
# ---------------------------------------------------------------------------
# After login, set the target subscription:
# az account set --subscription "${ARM_SUBSCRIPTION_ID}"

# Verify current account and subscription:
# az account show --output table
# az account list --output table

# ---------------------------------------------------------------------------
# OPTION 3: Terraform ARM Environment Variables
# ---------------------------------------------------------------------------
# Set these for Terraform AzureRM provider authentication.
# IMPORTANT: Load values from a secure vault - NEVER hardcode here.
#
# --- Service Principal (SP) Auth ---
# export ARM_CLIENT_ID=""            # App registration client/application ID
# export ARM_CLIENT_SECRET=""        # SP secret - load from vault ONLY
# export ARM_TENANT_ID=""            # Azure AD tenant ID
# export ARM_SUBSCRIPTION_ID=""      # Target subscription ID

# --- Azure CLI Auth (local dev only) ---
# export ARM_USE_CLI=true
# (ARM_SUBSCRIPTION_ID still recommended)

# --- Managed Identity Auth (Azure-hosted infra only) ---
# export ARM_USE_MSI=true
# export ARM_SUBSCRIPTION_ID=""      # Required even with MSI

# --- OIDC / Federated Identity (GitHub Actions / Azure DevOps) ---
# export ARM_USE_OIDC=true
# export ARM_CLIENT_ID=""            # App registration with federated credential
# export ARM_TENANT_ID=""
# export ARM_SUBSCRIPTION_ID=""
# (Token injected by pipeline - no ARM_CLIENT_SECRET needed)

# ---------------------------------------------------------------------------
# OPTION 4: Load from Azure Key Vault (recommended for non-pipeline use)
# ---------------------------------------------------------------------------
# Example: load SP secret from Key Vault at runtime
# export ARM_CLIENT_SECRET=$(az keyvault secret show \
#   --vault-name "your-keyvault-name" \
#   --name "terraform-sp-secret" \
#   --query "value" --output tsv)

# ---------------------------------------------------------------------------
# Auth check function
# ---------------------------------------------------------------------------
check_auth() {
    echo "=== Azure CLI Auth Check ==="
    if ! command -v az &>/dev/null; then
        echo "ERROR: Azure CLI not found. Install from https://learn.microsoft.com/en-us/cli/azure/install-azure-cli"
        return 1
    fi

    local account
    account=$(az account show --output json 2>/dev/null) || {
        echo "ERROR: Not logged in to Azure CLI. Run: az login"
        return 1
    }

    local name sub_id sub_name
    name=$(echo "${account}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['user']['name'])" 2>/dev/null || echo "unknown")
    sub_id=$(echo "${account}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['id'])" 2>/dev/null || echo "unknown")
    sub_name=$(echo "${account}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['name'])" 2>/dev/null || echo "unknown")

    echo "  Logged in as:    ${name}"
    echo "  Subscription ID: ${sub_id:0:8}****${sub_id: -4}"
    echo "  Subscription:    ${sub_name}"
    echo ""

    echo "=== Terraform ARM Env Check ==="
    # Check presence only - never print values
    local missing=0
    for var in ARM_CLIENT_ID ARM_CLIENT_SECRET ARM_TENANT_ID ARM_SUBSCRIPTION_ID; do
        if [[ -n "${!var:-}" ]]; then
            echo "  [SET]   ${var}"
        else
            echo "  [MISS]  ${var}"
        fi
    done

    for var in ARM_USE_MSI ARM_USE_CLI ARM_USE_OIDC; do
        if [[ -n "${!var:-}" ]]; then
            echo "  [SET]   ${var}=${!var}"
        fi
    done

    echo ""
    echo "=== Terraform Binary ==="
    if command -v terraform &>/dev/null; then
        echo "  Found: $(terraform version -no-color 2>/dev/null | head -1)"
    else
        echo "  WARNING: terraform not found. Install from https://developer.hashicorp.com/terraform/install"
    fi
    echo ""
    echo "Auth check complete."
}

# Run Python auth checker if available
run_python_check() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local python_check="${script_dir}/../src/auth_check.py"
    local tf_check="${script_dir}/../src/terraform_auth.py"

    if command -v python3 &>/dev/null && [[ -f "${python_check}" ]]; then
        echo "Running Python auth check..."
        python3 "${python_check}"
    fi

    if command -v python3 &>/dev/null && [[ -f "${tf_check}" ]]; then
        echo "Running Terraform auth check..."
        python3 "${tf_check}"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--check" ]]; then
    check_auth
    run_python_check
    exit 0
fi

# If sourced (not run directly), just define functions
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    echo "Auth helper functions loaded. Run check_auth to verify authentication."
fi
