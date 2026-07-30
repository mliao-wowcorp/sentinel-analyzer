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

# Color definitions for Windows Terminal
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

def process_single_workspace(ws_name, ws_info, tfe_org, tfe_token, policy_path, targeted_resource_types):
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
            result_record["details"] = "Workspace manages 0 live resources in cloud state."
            return result_record
        
        plan_payload = None
        if resources_in_state > 0 and has_state_history:
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
            result_record["details"] = "Unable to fetch state metrics baseline profiles."
            return result_record

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

def main():
    if len(sys.argv) < 2:
        print(f"{C_RED}[-] Usage: python sentinel_impact_analyzer.py <policy_path>{C_RESET}")
        sys.exit(1)

    policy_path = sys.argv[1]
    policy_base = os.path.basename(policy_path)
    policy_name = policy_base.replace(".sentinel", "")

    print(f"\n{C_CYAN}========================================================================{C_RESET}")
    print(f"{C_CYAN}🚀 STAGE 2: TFE WORKSPACE BLAST RADIUS IMPACT ANALYSIS ({policy_base}){C_RESET}")
    print(f"{C_CYAN}========================================================================{C_RESET}")

    tfe_token = os.getenv("TFE_TOKEN")
    tfe_org = os.getenv("TFE_ORG", "WoolworthsCorp")

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
            executor.submit(process_single_workspace, ws, info, tfe_org, tfe_token, policy_path, targeted_resource_types): ws
            for ws, info in candidate_workspaces.items()
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: (ENV_PRIORITY.get(x["env"], 99), x["workspace"]))

    # Print Summary Scorecard
    print(f"\n{C_CYAN}========================================================================{C_RESET}")
    print(f"{C_CYAN}📊 BLAST RADIUS IMPACT SCORECARD: {policy_base}{C_RESET}")
    print(f"{C_CYAN}========================================================================{C_RESET}")
    
    count_pass = sum(1 for r in results if r["status"] == "PASS")
    count_blocked = sum(1 for r in results if r["status"] == "BLOCKED")
    count_excluded = sum(1 for r in results if r["status"] == "EXCLUDED")

    for r in results:
        if r["status"] == "EXCLUDED":
            continue
        status_color = C_GREEN if r["status"] == "PASS" else C_RED
        print(f"  [{status_color}{r['status']:<7}{C_RESET}] Workspace: {r['workspace']:<35} Env: {r['env'].upper()}")

    print(f"\n{C_GREEN}Passed Cleanly : {count_pass}{C_RESET}")
    print(f"{C_RED}Blocked/Violated: {count_blocked}{C_RESET}")
    print(f"Outside Scope   : {count_excluded}")
    print(f"{C_CYAN}========================================================================{C_RESET}\n")

    if count_blocked > 0:
        print(f"{C_RED}[-] Blast Radius Alert: {count_blocked} workspace(s) will be blocked by this policy!{C_RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()