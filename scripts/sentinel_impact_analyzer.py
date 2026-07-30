import sys
import os
import re
import time
import json
import subprocess
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Color definitions
C_GREEN  = "\033[1;32m"
C_RED    = "\033[1;31m"
C_YELLOW = "\033[1;33m"
C_CYAN   = "\033[36m"
C_RESET  = "\033[0m"

WORKSPACE_REGEX = re.compile(r"^iac-([a-z0-9]{3})-(prod|uat|test|dev|stg)-(azure|gcp)$", re.IGNORECASE)
ENV_PRIORITY = {"prod": 1, "stg": 2, "uat": 3, "test": 4, "dev": 5}

def make_tfe_request(url, token, method="GET", payload=None):
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, method=method)
            req.add_header("Authorization", f"Bearer {token}")
            req.add_header("Content-Type", "application/vnd.api+json")
            if payload:
                req.data = json.dumps(payload).encode('utf-8')
            
            with urllib.request.urlopen(req, timeout=20) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 3:
                time.sleep(3 * (attempt + 1))
                continue
            raise e
        except Exception as e:
            if attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            raise RuntimeError(f"[-] API Failure at endpoint: {url}") from e

def build_pseudo_plan(state_json):
    pseudo_plan = {
        "format_version": "0.2",
        "terraform_version": "1.0.0",
        "resource_changes": {}
    }
    for res in state_json.get("resources", []):
        if res.get("mode") == "data":
            continue
        
        res_type = res.get("type")
        res_name = res.get("name")
        module = res.get("module", "")
        address = f"{module}.{res_type}.{res_name}" if module else f"{res_type}.{res_name}"
            
        for instance in res.get("instances", []):
            attrs = instance.get("attributes", {})
            change_obj = {
                "address": address,
                "mode": "managed",
                "type": res_type,
                "name": res_name,
                "change": {"actions": ["no-op"], "before": attrs, "after": attrs}
            }
            if module:
                change_obj["module_address"] = module
            pseudo_plan["resource_changes"][address] = change_obj
    return pseudo_plan

def process_single_workspace(ws_name, ws_info, tfe_org, tfe_token, policy_path, targeted_resource_types, dry_run):
    result_record = {
        "workspace": ws_name,
        "env": "unknown",
        "status": "EXCLUDED",
        "details": "",
        "evaluation_source": "CACHE"
    }
    
    match = WORKSPACE_REGEX.match(ws_name)
    if not match:
        result_record["details"] = "Excluded nomenclature scope."
        return result_record
        
    env = match.group(2).lower()
    result_record["env"] = env
    
    try:
        ws_id = ws_info["id"]
        resources_in_state = ws_info["resource_count"]
        has_state_history = ws_info["has_state"]
        
        if has_state_history and resources_in_state == 0:
            result_record["status"] = "INACTIVE"
            result_record["details"] = "Ghost Asset: Workspace manages 0 live resources in cloud state."
            return result_record
        
        plan_payload = None
        has_recent_error = False

        # 1. Attempt to fetch recent plan
        runs_url = f"https://app.terraform.io/api/v2/workspaces/{ws_id}/runs?page%5Bsize%5D=10"
        try:
            runs_data = make_tfe_request(runs_url, tfe_token)
            if runs_data.get('data'):
                latest_status = runs_data['data'][0]['attributes']['status']
                if latest_status in ["errored", "plan_errors"]:
                    has_recent_error = True
                
                for run in runs_data['data']:
                    run_status = run['attributes']['status']
                    if run_status not in ["errored", "plan_errors", "pending", "planning", "canceled", "discarded"]:
                        plan_rel = run['relationships'].get('plan', {}).get('data')
                        if plan_rel:
                            try:
                                plan_url = f"https://app.terraform.io/api/v2/plans/{plan_rel['id']}/json-output"
                                tmp_payload = make_tfe_request(plan_url, tfe_token)
                                if tmp_payload:
                                    plan_payload = tmp_payload
                                    result_record["evaluation_source"] = "LIVE_PLAN"
                                    break
                            except Exception:
                                plan_payload = None
        except Exception:
            plan_payload = None

        # 2. Trigger Live Plan if DRY_RUN is False and no recent plan exists
        if not plan_payload and not has_recent_error and not dry_run:
            run_trigger_url = "https://app.terraform.io/api/v2/runs"
            trigger_payload = {
                "data": {
                    "type": "runs",
                    "attributes": {"plan-only": True, "message": "Automated Sentinel Verification"},
                    "relationships": {"workspace": {"data": {"type": "workspaces", "id": ws_id}}}
                }
            }
            try:
                triggered_run = make_tfe_request(run_trigger_url, tfe_token, method="POST", payload=trigger_payload)
                new_run_id = triggered_run['data']['id']
                
                timeout = 120  
                start_time = time.time()
                while time.time() - start_time < timeout:
                    time.sleep(10)
                    check_run_url = f"https://app.terraform.io/api/v2/runs/{new_run_id}"
                    run_status_data = make_tfe_request(check_run_url, tfe_token)
                    current_status = run_status_data['data']['attributes']['status']
                    plan_rel = run_status_data['data']['relationships'].get('plan', {}).get('data')
                    
                    if plan_rel and plan_rel.get('id') and current_status not in ["pending", "planning"]:
                        new_plan_id = plan_rel['id']
                        new_plan_url = f"https://app.terraform.io/api/v2/plans/{new_plan_id}/json-output"
                        plan_payload = make_tfe_request(new_plan_url, tfe_token)
                        result_record["evaluation_source"] = "LIVE_PLAN"
                        break
                    elif current_status in ["errored", "canceled", "rejected"]:
                        break
            except Exception:
                plan_payload = None

        # 3. Fallback to state version if plan payload unavailable
        if not plan_payload and resources_in_state > 0 and has_state_history:
            try:
                state_url = f"https://app.terraform.io/api/v2/workspaces/{ws_id}/current-state-version"
                state_data = make_tfe_request(state_url, tfe_token)
                if state_data and state_data.get('data'):
                    download_url = state_data['data']['attributes'].get('hosted-state-download-url')
                    if download_url:
                        raw_state_json = make_tfe_request(download_url, tfe_token)
                        plan_payload = build_pseudo_plan(raw_state_json)
                        result_record["evaluation_source"] = "STATE"
            except Exception:
                plan_payload = None

        if not plan_payload:
            result_record["status"] = "UNSTABLE"
            result_record["details"] = "Unable to fetch state or plan metrics baseline profiles."
            return result_record

        # Check for targeted resource types
        changes_map = plan_payload.get("resource_changes", {})
        changes_iterator = changes_map.values() if isinstance(changes_map, dict) else changes_map
        has_targeted_resources = any(change.get("type") in targeted_resource_types for change in changes_iterator)

        if not has_targeted_resources:
            result_record["status"] = "EXCLUDED"
            result_record["details"] = "Infrastructure topology does not contain matching targeted resource types."
            return result_record

        cfg_file = f"config_{ws_id}.json"
        config_payload = {
            "mock": {
                "tfplan/v2": {"data": plan_payload},
                "tfrun": {"data": {"id": "run-local-analysis-mock", "workspace": {"name": ws_name}}},
                "tfconfig/v2": {"data": {"resources": {}}},
                "tfstate/v2": {"data": {"resources": {}}}
            }
        }
        with open(cfg_file, "w") as f:
            json.dump(config_payload, f)
            
        run_sim = subprocess.run(["sentinel", "apply", "-trace", "-config", cfg_file, policy_path], capture_output=True, text=True)

        if os.path.exists(cfg_file):
            os.remove(cfg_file)
            
        if run_sim.returncode == 0:
            result_record["status"] = "PASS"
            result_record["details"] = "Compatible: Rule passes perfectly against active configuration."
        else:
            result_record["status"] = "BLOCKED"
            result_record["details"] = f"Violation Detected:\n{run_sim.stdout.strip()[:300]}"

    except Exception as e:
        result_record["status"] = "UNSTABLE"
        result_record["details"] = f"Processing Exception: {str(e)[:100]}"
        
    return result_record

def generate_html_report(results, policy_base, timestamp, script_dir):
    count_pass = sum(1 for r in results if r["status"] == "PASS")
    count_blocked = sum(1 for r in results if r["status"] == "BLOCKED")
    count_excluded = sum(1 for r in results if r["status"] == "EXCLUDED")
    
    status_text = "PASSED" if count_blocked == 0 else "VIOLATION DETECTED"
    status_color = "#28a745" if count_blocked == 0 else "#dc3545"

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Sentinel Blast Radius Impact Analysis Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f8f9fa; color: #333; }}
        .card {{ background: white; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .badge {{ display: inline-block; padding: 6px 12px; font-weight: bold; border-radius: 4px; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background-color: #f1f3f5; font-weight: 600; }}
        .badge-pass {{ background-color: #28a745; }}
        .badge-blocked {{ background-color: #dc3545; }}
        .badge-excluded {{ background-color: #6c757d; }}
        .badge-env {{ background-color: #0078d4; color: white; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
        .details-box {{ font-family: monospace; font-size: 0.85em; background: #f8f9fa; padding: 8px; border-radius: 4px; border-left: 3px solid #6c757d; white-space: pre-wrap; }}
    </style>
</head>
<body>
    <div class="card">
        <h2>🛡️ Sentinel Blast Radius Impact Analysis Summary</h2>
        <p><strong>Target Policy:</strong> <code>{policy_base}</code></p>
        <p><strong>Timestamp:</strong> {timestamp}</p>
        <p><strong>Status:</strong> <span class="badge" style="background: {status_color}">{status_text}</span></p>
        <p><strong>Workspaces Evaluated:</strong> Total: {len(results)} | Clean: {count_pass} | Blocked: {count_blocked} | Out of Scope: {count_excluded}</p>
    </div>
    <div class="card">
        <h3>Evaluated Workspace Matrix</h3>
        <table>
            <tr><th>Status</th><th>Env</th><th>Target Workspace Scope</th><th>Data Source</th><th>Diagnostic Context</th></tr>
    """

    for r in results:
        if r["status"] == "EXCLUDED":
            continue
        badge_cls = "badge-pass" if r["status"] == "PASS" else "badge-blocked" if r["status"] == "BLOCKED" else "badge-excluded"
        
        html += f"""
            <tr>
                <td><span class="badge {badge_cls}">{r['status']}</span></td>
                <td><span class="badge-env">{r['env'].upper()}</span></td>
                <td><strong>{r['workspace']}</strong></td>
                <td><code>{r['evaluation_source']}</code></td>
                <td><div class="details-box">{r['details']}</div></td>
            </tr>
        """

    html += """
        </table>
    </div>
</body>
</html>
    """
    
    html_file = os.path.join(script_dir, f"sentinel_impact_report_{timestamp}.html")
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html)
    return html_file

def main():
    if len(sys.argv) < 2:
        print(f"{C_RED}[-] Usage: python sentinel_impact_analyzer.py <policy_path>{C_RESET}")
        sys.exit(1)

    policy_path = sys.argv[1]
    policy_base = os.path.basename(policy_path)
    script_dir = os.path.dirname(os.path.abspath(__file__))

    tfe_token = os.getenv("TFE_TOKEN")
    tfe_org = os.getenv("TFE_ORG", "WoolworthsCorp")
    dry_run = os.getenv("DRY_RUN", "true").lower() == "true"

    print(f"\n{C_CYAN}========================================================================{C_RESET}")
    print(f"{C_CYAN}🚀 STAGE 2: TFE WORKSPACE BLAST RADIUS IMPACT ANALYSIS ({policy_base}){C_RESET}")
    print(f"{C_CYAN}========================================================================{C_RESET}")

    if dry_run:
        print(f"{C_YELLOW}⚠️  [LOG ALERT] RUNNING IN ENVIRONMENT DRY RUN SAMPLE MODE. NO LIVE REMOTE PLANS WILL BE CREATED.{C_RESET}")

    if not tfe_token:
        print(f"{C_RED}[-] Error: Environment variable 'TFE_TOKEN' is missing.{C_RESET}")
        sys.exit(1)

    if not os.path.exists(policy_path):
        print(f"{C_RED}[-] Error: Policy file '{policy_path}' not found.{C_RESET}")
        sys.exit(1)

    with open(policy_path, 'r') as f:
        content = f.read()

    resources = re.findall(r'\.find_resources\([\'"]([^\'"]+)[\'"]\)', content)
    if not resources:
        print(f"{C_YELLOW}[!] No resource constraints (.find_resources) declared in policy. Exiting.{C_RESET}")
        sys.exit(0)

    targeted_resource_types = set(resources)
    print(f"{C_GREEN}[+] Target resource types detected: {targeted_resource_types}{C_RESET}")

    target_platform = "azure" if "azure-" in policy_base else "gcp" if "gcp-" in policy_base else "unknown"
    candidate_workspaces = {}

    print(f"{C_CYAN}[*] Querying TFE workspaces matching platform suffix '*-{target_platform}'...{C_RESET}")
    page_number = 1
    while True:
        list_url = f"https://app.terraform.io/api/v2/organizations/{tfe_org}/workspaces?page%5Bnumber%5D={page_number}&page%5Bsize%5D=100"
        ws_page = make_tfe_request(list_url, tfe_token)
        if not ws_page.get('data'):
            break
            
        for item in ws_page['data']:
            ws_name = item['attributes']['name']
            res_count = item['attributes'].get('resource-count', 0)
            ws_id = item['id']
            state_rel = item['relationships'].get('current-state-version', {}).get('data')
            
            if WORKSPACE_REGEX.match(ws_name) and ws_name.lower().endswith(f"-{target_platform}"):
                if res_count > 0:
                    candidate_workspaces[ws_name] = {
                        "id": ws_id,
                        "resource_count": res_count,
                        "has_state": state_rel is not None
                    }
                    
        if len(ws_page['data']) < 100:
            break
        page_number += 1

    print(f"{C_GREEN}[+] Discovered {len(candidate_workspaces)} candidate workspaces. Running parallel simulations...{C_RESET}")

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(process_single_workspace, ws, info, tfe_org, tfe_token, policy_path, targeted_resource_types, dry_run): ws
            for ws, info in candidate_workspaces.items()
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: (ENV_PRIORITY.get(x["env"], 99), x["workspace"]))

    # Save JSON Report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = os.path.join(script_dir, f"sentinel_impact_report_{timestamp}.json")
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Save HTML Report
    html_file = generate_html_report(results, policy_base, timestamp, script_dir)

    print(f"\n{C_GREEN}[+] Impact Analysis JSON report created: {json_file}{C_RESET}")
    print(f"{C_GREEN}[+] Impact Analysis HTML report created: {html_file}{C_RESET}")

    count_blocked = sum(1 for r in results if r["status"] == "BLOCKED")
    if count_blocked > 0:
        print(f"\n{C_RED}[-] Blast Radius Alert: {count_blocked} workspace(s) will be blocked by this policy!{C_RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()