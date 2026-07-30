# Sentinel Analyzer

A shift-left policy governance utility designed to validate Sentinel code layout/unit tests locally, and simulate policy blast radius against live Terraform Enterprise (TFE / HCP Terraform) workspaces before merging code to production.

## 📁 Repository Layout
*   `scripts/sentinel_analyzer.py`: Unified Python engine handling both local validation (`sentinel fmt`/`test`) and remote TFE workspace impact analysis.
*   `scripts/Taskfile.yml`: Task runner orchestration framework.

---

## ⚙️ Prerequisites

*   **Python 3.10+**
*   **HashiCorp Sentinel CLI** (installed and available in `$PATH`)
*   **Task CLI** (`go-task` / `task`)

### Environment Variables
Set your TFE authentication token before running impact analysis:

```powershell
# PowerShell:
$env:TFE_TOKEN="your-tfe-user-or-team-token"
$env:TFE_ORG="WoolworthsCorpTest"

# Bash / Zsh:
export TFE_TOKEN="your-tfe-user-or-team-token"
export TFE_ORG="WoolworthsCorp"

```

---

## 🚀 Quick Execution

Run tasks directly from your working IaC directory (e.g. `terraform/kiran_azure/`) by pointing to the script's `Taskfile.yml`:

### 1. Full Pipeline (Validation + Blast Radius Impact Analysis)

```powershell
task -t scripts/Taskfile.yml analyze

```

### 2. Validate Code Only (Formatting & Unit Tests)

```powershell
task -t scripts/Taskfile.yml validate POLICY="odessa_tenants/azure/networking/azure-gr-loadbalancer-deny-policies.sentinel"

```

### 3. Run Blast Radius Impact Analysis Only

```powershell
task -t scripts/Taskfile.yml impact POLICY="odessa_tenants/azure/networking/azure-gr-loadbalancer-deny-policies.sentinel"

```

```
