# Sentinel Analyzer

A shift-left policy governance utility designed to validate Sentinel code layout/unit tests, and simulate policy blast radius against live Terraform Enterprise (TFE / HCP Terraform) workspaces before merging code to production.

## 📁 Repository Layout
.
├── .github/
│   └── workflows/
│       ├── sentinel-impact-analysis.yml     # GHA Workflow: Blast Radius Analyzer (PR & Manual)
│       ├── sentinel-validation-report.yml   # GHA Workflow: Code Style & Unit Test Gate (PR & Manual)
│       └── scripts/
│           ├── report-results.sh             # Compiles markdown validation summary & posts PR sticky comments
│           ├── run-validation.sh             # Executes sentinel fmt -check & sentinel test -verbose
│           └── speculative_analyzer.py       # Parallel TFE state/plan impact simulator
├── scripts/
│   ├── sentinel_validator.py                # Local Python validator for formatting and unit tests
│   ├── sentinel_impact_analyzer.py         # Local Python TFE workspace impact analyzer
│   └── Taskfile.yml                         # Task runner orchestration framework
└── README.md
```

---

## 🤖 GitHub Actions (GHA) Automation Pipelines

The repository includes two automated GitHub Actions workflows that run as shift-left governance gates during Pull Requests or manual dispatches.

### 1. Sentinel Validation Gate (`sentinel-validation-report.yml`)

Executes strict code layout checks (`sentinel fmt -check`) and unit test assertions (`sentinel test -verbose`) against all modified policy files.

* **Triggers**:
  * **Pull Request**: Automatically triggers when `.sentinel` files under `odessa_tenants/` are changed, opened, or synchronized.
  * **Workflow Dispatch**: Manual UI execution with custom `target_scope` inputs.
* **Execution Flow**:
  1. Identifies modified `.sentinel` policies via `git diff`.
  2. Runs `scripts/run-validation.sh` to check formatting and execute unit test suites in `test/` subdirectories.
  3. Executes `scripts/report-results.sh` to compile a status matrix and post/update a **sticky comment dashboard** on the Pull Request.
  4. Archives `pr_comment.md` as a workflow artifact.
* **Gating**: Non-zero exit codes block the PR from merging if formatting or test suite assertions fail.

### 2. Sentinel Blast Radius Analyzer (`sentinel-impact-analysis.yml`)

Simulates the real-world impact of modified policies across all active Terraform Enterprise workspaces in the organization before code is merged.

* **Triggers**:
  * **Pull Request**: Automatically triggers when `.sentinel` files under `odessa_tenants/` are modified.
  * **Workflow Dispatch**: Manual UI execution allowing custom `target_scope` targets and `dry_run` toggles.
* **Execution Flow**:
  1. Detects modified policies or ingests user-defined target paths.
  2. Spawns parallel thread pools via `speculative_analyzer.py` to query TFE workspace state histories and speculative plans.
  3. Evaluates target policies using local Sentinel execution engines against live TFE infrastructure topologies.
  4. Aggregates results into Markdown (`blast_radius_report.md`) and HTML reports (`intermediate_*.html`).
  5. Posts or updates an interactive **Production Impact Analysis Radar** scorecard comment directly on the PR.
  6. Archives HTML and Markdown reports as 7-day workflow artifacts.

---

### 🔑 Required Repository Secrets & Variables

To enable the GHA workflows, configure the following secrets and variables in your GitHub Repository settings:

| Type | Name | Description |
| :--- | :--- | :--- |
| **Secret** | `TFE_ORG_TOKEN` | TFE / HCP Terraform API token with read access to organization workspaces and states. |
| **Secret** | `GITHUB_TOKEN` | Built-in GitHub token used by `gh api` to post/update sticky comments on PRs. |
| **Variable** | `TFE_ORG` | Name of your TFE organization (e.g., `WoolworthsCorp`). |
| **Variable** | `DRY_RUN` | *(Optional)* Default Dry-Run flag (`true` or `false`). |

---

### 🎛️ Manual Pipeline Execution (`workflow_dispatch`)

You can trigger either pipeline manually from the GitHub **Actions** tab:

1. Select **Sentinel Blast Radius Analyzer** or **Sentinel Validation Report**.
2. Click **Run workflow**.
3. Provide the `target_scope` parameter:
   * **Single Policy**: `odessa_tenants/azure/networking/azure-gr-loadbalancer-deny-policies.sentinel`
   * **Subfolder Domain**: `odessa_tenants/azure/networking`
   * **Entire Suite**: `odessa_tenants` or `all`
4. Choose **Dry Run Mode** (`true` for safe state snapshot evaluation; `false` to trigger remote speculative plan runs in TFE).

---

## ⚙️ Local CLI Prerequisites

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

To pull the `scripts` folder directly into your target Terraform workspace without creating a nested `.git` repository, open PowerShell or CMD in your IaC directory and run:

```powershell
# PowerShell:
gh repo clone mliao-wowcorp/sentinel-analyzer temp_repo; Move-Item -Path temp_repo\scripts -Destination .\ -Force; Remove-Item -Recurse -Force temp_repo

# CMD / Windows Command Prompt:
gh repo clone mliao-wowcorp/sentinel-analyzer temp_repo && xcopy /E /I /Y temp_repo\scripts scripts && rmdir /S /Q temp_repo


```

```

```