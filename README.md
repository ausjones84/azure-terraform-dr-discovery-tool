# Azure Terraform DR Discovery Tool

> **A Python-based tool for Azure Disaster Recovery documentation and Terraform validation.**
> Default mode is fully **READ-ONLY**. No Azure resources or Terraform code are ever modified unless explicitly requested.

---

## Purpose

This tool helps Platform/Cloud engineers:

- **Discover** Azure resources (AI Search, OpenAI, AI Foundry, Private Endpoints, Networking)
- **Inspect** private endpoint configuration, network settings, diagnostic settings, identity, and tags
- **Search** local Terraform repositories for matching resource definitions and modules
- **Compare** Azure live state vs Terraform code to classify resources
- **Generate** clean findings reports for Azure DevOps tickets
- **Draft** ticket update text and Teams messages ready to send
- **Create** safe Terraform stub files (only when explicitly requested with `--generate-stub`)

---

## Supported Services

| Service | Azure Resource Type | Terraform Resource |
|---------|--------------------|--------------------||
| AI Search | `Microsoft.Search/searchServices` | `azurerm_search_service` |
| Azure OpenAI / Cognitive Services | `Microsoft.CognitiveServices/accounts` | `azurerm_cognitive_account` |
| AI Foundry / AI Services | `Microsoft.CognitiveServices/accounts` (kind=AIServices) | `azurerm_cognitive_account` |
| Private Endpoints | `Microsoft.Network/privateEndpoints` | `azurerm_private_endpoint` |
| Network Interfaces | `Microsoft.Network/networkInterfaces` | `azurerm_network_interface` |
| VNets / Subnets | `Microsoft.Network/virtualNetworks` | `azurerm_virtual_network` |
| Log Analytics | `Microsoft.OperationalInsights/workspaces` | `azurerm_log_analytics_workspace` |
| Diagnostic Settings | `Microsoft.Insights/diagnosticSettings` | `azurerm_monitor_diagnostic_setting` |
| Role Assignments | `Microsoft.Authorization/roleAssignments` | `azurerm_role_assignment` |

---

## Safety Rules

| Rule | Detail |
|------|--------|
| **Default read-only** | Discovery and reporting never touch Azure or Terraform |
| **No apply** | `terraform apply` and `terraform destroy` are never run |
| **No Azure mutations** | No `az resource create/update/delete` commands |
| **No secrets exposed** | API keys and tokens are masked in all output |
| **Stub mode explicit** | `--generate-stub` must be passed explicitly; it only creates draft files |
| **Import warnings** | Clear warning is always shown when a resource must be imported before apply |
| **Subnet IP warnings** | Warning shown when subnet available IP count is 0 |

---

## Setup

### Prerequisites

- Python 3.9+
- Azure CLI (`az`) installed and logged in
- Access to your Terraform repositories (local checkout)

### Installation

```bash
# Clone the repo
git clone https://github.com/ausjones84/azure-terraform-dr-discovery-tool.git
cd azure-terraform-dr-discovery-tool

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

### Azure Login

```bash
# Login to Azure CLI
az login

# Set default subscription (optional)
az account set --subscription <subscription-id>

# Verify access
az account show
```

---

## Usage

### Discover AI Search resources

```bash
python src/dr_discovery.py \
  --service ai_search \
  --resource-name edav-dev-aisearch-eastus-internal \
  --subscription b6085d96-6bb5-4e70-890c-e026d0cb1d1a \
  --repo-root ./terraform-scripts \
  --module-root ./terraform-modules \
  --output ./reports
```

### Discover OpenAI / Cognitive Services by resource group

```bash
python src/dr_discovery.py \
  --service openai \
  --resource-group ocio-edav-dev-high-openaieast-rg \
  --subscription b6085d96-6bb5-4e70-890c-e026d0cb1d1a \
  --repo-root ./terraform-scripts \
  --module-root ./terraform-modules \
  --output ./reports
```

### Generate a Terraform stub (explicit mode only)

```bash
python src/dr_discovery.py \
  --service ai_search \
  --resource-name edav-dev-aisearch-eastus-internal \
  --subscription b6085d96-6bb5-4e70-890c-e026d0cb1d1a \
  --repo-root ./terraform-scripts \
  --module-root ./terraform-modules \
  --generate-stub \
  --env-path edav/dev \
  --output ./generated
```

### Use a config file

```bash
# Copy and customize the sample config
cp examples/sample_config.yaml my_config.yaml
# Edit my_config.yaml with your values

python src/dr_discovery.py \
  --service ai_search \
  --config my_config.yaml
```

### Verbose debug output

```bash
python src/dr_discovery.py --service ai_search --subscription <sub> -v
```

---

## Output Reports

Reports are written to the `--output` directory in three formats:

| Format | Description |
|--------|-------------|
| `.xlsx` | Multi-sheet Excel workbook |
| `.md` | Markdown report |
| `.json` | Full structured JSON |

### Excel Sheets

1. **Summary** - Run metadata, counts, overall status and risk
2. **Azure Resources** - All discovered resources with properties
3. **Private Endpoints** - Full PE configuration with connection state
4. **Networking** - VNet, Subnet, IP, NIC, DNS details
5. **Terraform Matches** - All TF file matches with confidence scores
6. **Drift Findings** - Parsed drift CSV entries
7. **Risks** - Classified risks with color coding
8. **Recommended Next Steps** - Actionable items
9. **Ticket Update Draft** - Ready-to-paste Azure DevOps ticket text

---

## Comparison Status Classifications

| Status | Meaning |
|--------|---------|
| `terraform_managed` | Exact resource name found in TF with a resource definition block |
| `azure_only` | Resource exists in Azure but no TF match found |
| `tf_only` | TF resource found but not matched to Azure discovery |
| `possible_match` | Some TF matches found but not high-confidence |
| `module_available_but_not_instantiated` | Module exists but no deployment definition found |
| `unknown` | Cannot determine status |

---

## Terraform Stub Generator

Run **only** with `--generate-stub`.

For AI Search, generates:
```
<output>/<env-path>/ai_search_service/
  main.tf          # Module block with known values pre-filled
  variables.tf     # Variables with TODO comments for unknowns
  import_commands.sh  # Example import commands (NEVER auto-run)
```

**Generated stubs include:**
- Pre-filled values from Azure discovery (name, location, SKU, tags, identity type)
- `# TODO` comments for values needing confirmation (log analytics, groups, private IP)
- Import command examples (not executed)
- Safety warning header

**`terraform apply` is NEVER run by this tool.**

---

## Drift File Support

The tool automatically searches for `drift.csv` and `drift_candidates.csv` files in your repo roots.

Expected columns (flexible naming):
- `resource_name` / `name` / `resource`
- `resource_type` / `type` (optional)
- `resource_group` / `rg` (optional)
- `subscription_id` (optional)
- `status` / `drift_status` (optional)
- `notes` / `comments` (optional)

---

## Using Reports for Azure DevOps Tickets

1. Run the tool against your target resource
2. Open the generated `.xlsx` report
3. Navigate to the **Ticket Update Draft** sheet
4. Copy the ticket update text into your Azure DevOps work item
5. Optionally use the Teams message draft to notify the resource owner
6. Review the **Risks** and **Recommended Next Steps** sheets
7. Add the `.xlsx` as an attachment to the ticket

---

## Extending for Other DR Tickets

To add a new service type:

1. **Add discovery function** in `src/azure_discovery.py`
   - Follow the pattern of `discover_ai_search()` or `discover_openai()`
   - Add your function to `SERVICE_DISPATCHERS`

2. **Add Terraform resource type mappings** in `src/terraform_search.py`
   - Update `RESOURCE_TYPE_MAP` and `MODULE_NAME_MAP`

3. **Add stub generator** in `src/stub_generator.py`
   - Add a `generate_<service>_stub()` method
   - Add it to the `generate_stub()` dispatcher

4. **Add templates** in `templates/`
   - `terraform_<service>_main.tf.j2`
   - `terraform_<service>_variables.tf.j2`

5. **Register the service** in the `--service` CLI option in `src/dr_discovery.py`

---

## Repository Structure

```
azure-terraform-dr-discovery-tool/
├── README.md
├── requirements.txt
├── .gitignore
├── src/
│   ├── dr_discovery.py          # CLI entry point
│   ├── azure_discovery.py       # Azure resource discovery (read-only)
│   ├── terraform_search.py      # Terraform repo search engine
│   ├── drift_parser.py          # Drift CSV parser
│   ├── report_writer.py         # Excel/Markdown/JSON report generator
│   ├── stub_generator.py        # Terraform stub generator (explicit only)
│   └── models.py                # Data models (dataclasses + enums)
├── templates/
│   ├── ticket_update.md.j2      # Azure DevOps ticket update template
│   ├── teams_message.md.j2      # Teams message template
│   ├── terraform_ai_search_main.tf.j2
│   └── terraform_ai_search_variables.tf.j2
├── examples/
│   └── sample_config.yaml       # Sample YAML config file
├── reports/                     # Output directory for reports
├── generated/                   # Output directory for stubs
└── tests/
    ├── test_models.py
    └── test_terraform_search.py
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

> **This tool is for discovery and documentation only. It never modifies Azure resources or Terraform code unless explicitly requested via `--generate-stub`. All Terraform stubs are drafts requiring human review before use.**


---

## Terraform Onboarding Workflow

Use this workflow when a resource is classified as `terraform_onboarding_candidate`:
a resource that **exists in Azure**, has a **reusable Terraform module** available,
but has **no deployment definition in terraform-scripts** and was **created outside Terraform**.

```
Azure Resource Exists
       |
       v
Terraform Module Exists (in terraform-modules)
       |
       v
Deployment Definition Missing (not in terraform-scripts)
       |
       v
Generate Deployment Definition
  terraform-scripts/<env>/<module>/main.tf
  terraform-scripts/<env>/<module>/variables.tf
  terraform-scripts/<env>/<module>/import_commands.sh
       |
       v
Import Existing Resources
  Run: bash import_commands.sh
  (review commands BEFORE running)
       |
       v
Terraform Plan
  Run: terraform plan
       |
       v
Validate Zero Drift
  Plan: 0 to add, 0 to change, 0 to destroy
  (STOP if plan shows any add/change/destroy until resolved)
       |
       v
Submit PR
       |
       v
Approval (required)
       |
       v
Apply (only after approval)
```

### Resource Classifications

| Status | Definition |
|--------|-----------|
| `terraform_managed` | Resource exists in Azure AND deployment definition found in terraform-scripts |
| `azure_only` | Resource exists in Azure, no module and no deployment definition found |
| `terraform_onboarding_candidate` | Resource exists in Azure + module exists + NO deployment definition + created outside Terraform |
| `module_available_but_not_instantiated` | Module reference found in repo but no active deployment definition |
| `tf_only` | Deployment definition found in Terraform but resource not found in Azure |

### Ownership Validation Fields

Every resource in the report now includes:

| Field | Values |
|-------|--------|
| Ownership Status | Terraform Managed, Azure Only, Created Outside Terraform, Unknown |
| Deployment Source | terraform-scripts, alternate repo, manual deployment, unknown |

### Terraform Onboarding Risk Scoring

| Risk Level | Criteria |
|-----------|---------|
| HIGH | Resource exists + created outside Terraform (all onboarding candidates start here) |
| CRITICAL | PE + diagnostic settings + RBAC all present — import all sub-resources before apply |

### Example: AI Search Onboarding

```
Resource: edav-dev-aisearch-eastus-internal

Recommendation:
  Create deployment definition under:
  terraform-scripts/edav/dev/ai_search_service

Required Actions:
  1. Create module block in main.tf
  2. Match Azure configuration exactly (SKU, location, tags, PE, diagnostics, RBAC)
  3. Run: terraform init
  4. Run import commands from import_commands.sh
  5. Run: terraform plan
  6. Validate: Plan: 0 to add, 0 to change, 0 to destroy
  7. Submit PR for review
  8. Apply ONLY after approval

WARNING: Import resources before apply.
         Plan must zero out before approval.
```

### Terraform Import Commands (Output Only)

The tool generates example import commands for:
- `azurerm_search_service`
- `azurerm_private_endpoint`
- `azurerm_monitor_diagnostic_setting`
- `azurerm_role_assignment`

**These commands are NEVER executed by the tool.** They are output to
`import_commands.sh` for human review. Run them manually only after reviewing
the deployment definition and running `terraform init`.

### Excel Report: Terraform_Onboarding Sheet

The Excel report now includes a **Terraform_Onboarding** sheet with these columns:

| Column | Description |
|--------|-------------|
| Resource Name | Azure resource name |
| Resource Type | Full Azure resource type |
| Terraform Module | Module name in terraform-modules |
| Deployment Path | Suggested path in terraform-scripts |
| Ownership Status | Terraform Managed / Azure Only / Created Outside Terraform |
| Deployment Source | terraform-scripts / alternate repo / manual deployment |
| Import Required | Yes / No |
| Risk Level | low / medium / high / critical |
| Recommended Action | Step-by-step onboarding action |
| Plan Validation Required | Yes / No |
| Import Commands Preview | First 5 lines of import_commands.sh |
