# Sentinel Analyzer

A shift-left policy governance utility designed to validate Sentinel code layout/unit tests locally, and simulate policy blast radius against live Terraform Enterprise (TFE / HCP Terraform) workspaces before merging code to production.

## 📁 Repository Layout
*   `scripts/sentinel_validator.py`: Handles local policy formatting (`sentinel fmt`) and unit test suite verification (`sentinel test`).
*   `scripts/sentinel_impact_analyzer.py`: Evaluates target policies against active TFE workspace state histories to generate blast radius scorecards.
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
$env:TFE_ORG="WoolworthsCorp"

# Bash / Zsh:
export TFE_TOKEN="your-tfe-user-or-team-token"
export TFE_ORG="WoolworthsCorp"

```

---


## 🔒 Execution Modes: Dry-Run vs. Live Mode

| Execution Mode | Command Flag | Behavior & Impact |
| --- | --- | --- |
| **Dry-Run Mode** *(Default)* | `DRY_RUN=true` | 🟢 **100% Safe.** Evaluates state snapshots and cached plans. Creates **zero** remote TFE plan jobs and causes no API storms. |
| **Live Mode** | `DRY_RUN=false` | ⚠️ **Live Execution.** Sends POST requests to TFE to generate new speculative plans for workspaces without fresh plan history. |

---

## 🚀 Execution Commands

Run tasks directly from your working IaC directory (e.g., `terraform/kiran_azure/`) by referencing the script's `Taskfile.yml`:

### 1. Execute Local Code Validation Only (`fmt` + `test`)

```powershell
task -t scripts/Taskfile.yml validate POLICY="odessa_tenants/azure/networking/azure-gr-loadbalancer-deny-policies.sentinel"

```

### 2. Run Impact Analysis (Safe Default: Dry-Run)

```powershell
task -t scripts/Taskfile.yml impact POLICY="odessa_tenants/azure/networking/azure-gr-loadbalancer-deny-policies.sentinel"

```

### 3. Run Impact Analysis in Live Mode (Triggers TFE Speculative Plans)

```powershell
task -t scripts/Taskfile.yml impact DRY_RUN=false POLICY="odessa_tenants/azure/networking/azure-gr-loadbalancer-deny-policies.sentinel"

```

### 4. Execute Full Pipeline (Validation + Impact Analysis)

```powershell
# Safe Dry-Run Full Pipeline:
task -t scripts/Taskfile.yml analyze:all

# Live Execution Full Pipeline:
task -t scripts/Taskfile.yml analyze:all DRY_RUN=false

```

---

## 📥 Pull Utility into Local Workspace

To pull the `scripts` folder directly into your target Terraform workspace without creating a nested `.git` repository, open CMD or PowerShell in your IaC directory and run:

```cmd
curl.exe -sL [https://github.com/mliao-wowcorp/sentinel-analyzer/archive/refs/heads/main.tar.gz](https://github.com/mliao-wowcorp/sentinel-analyzer/archive/refs/heads/main.tar.gz) | tar -xz --strip-components=1 scripts

```

```

```