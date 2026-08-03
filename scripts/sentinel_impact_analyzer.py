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

# ==============================================================================
# COLOR & REGEX DEFINITIONS
# ==============================================================================
C_GREEN  = "\033[1;32m"
C_RED    = "\033[1;31m"
C_YELLOW = "\033[1;33m"
C_CYAN   = "\033[36m"
C_RESET  = "\033[0m"

WORKSPACE_REGEX = re.compile(r"^iac-([a-z0-9]{3})-(prod|uat|test|dev|stg)-(azure|gcp)$", re.IGNORECASE)
ENV_PRIORITY = {"prod": 1, "stg": 2, "uat": 3, "test": 4, "dev": 5}

# ==============================================================================
# TFE API & PSEUDO PLAN ENGINE
# ==============================================================================
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
            raise RuntimeError(f"[-] TFE API Endpoint Failure: {url}") from e

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

# ==============================================================================
# HCL & POLICY DISCOVERY HELPERS
# ==============================================================================
def extract_module_sources(plan_payload):
    sources_map = {}
    if not plan_payload or "configuration" not in plan_payload:
        return sources_map
        
    def walk_module(mod_config, current_prefix=""):
        mod_calls = mod_config.get("module_calls", {})
        for local_name, call_data in mod_calls.items():
            full_addr = f"module.{local_name}" if not current_prefix else f"{current_prefix}.module.{local_name}"
            sources_map[full_addr.lower()] = call_data.get("source", "").lower()
            if "module" in call_data:
                walk_module(call_data["module"], full_addr)
                
    root = plan_payload.get("configuration", {}).get("root_module", {})
    walk_module(root)
    return sources_map

def discover_enforcement_level(policy_path):
    dir_path = os.path.dirname(os.path.abspath(policy_path))
    sentinel_hcl_path = None
    
    for _ in range(4):
        candidate = os.path.join(dir_path, "sentinel.hcl")
        if os.path.exists(candidate):
            sentinel_hcl_path = candidate
            break
        parent = os.path.dirname(dir_path)
        if parent == dir_path: break
        dir_path = parent
        
    if not sentinel_hcl_path:
        return "hard-mandatory"
        
    try:
        with open(sentinel_hcl_path, "r") as f:
            content = f.read()
            
        policy_base = os.path.basename(policy_path)
        policy_pattern = re.compile(r'policy\s+"([^"]+)"\s*\{(.*?)\}', re.DOTALL)
        
        for match in policy_pattern.finditer(content):
            p_body = match.group(2)
            if policy_base in p_body:
                enf_match = re.search(r'enforcement_level\s*=\s*"([^"]+)"', p_body)
                if enf_match:
                    return enf_match.group(1).lower().strip()
    except Exception:
        pass
        
    return "hard-mandatory"

# ==============================================================================
# WORKSPACE EVALUATOR
# ==============================================================================
def process_single_workspace(ws_name, ws_info, tfe_org, tfe_token, policy_path, targeted_resource_types, enforcement_level, dry_run):
    result_record = {
        "workspace": ws_name, 
        "env": "unknown", 
        "status": "EXCLUDED", 
        "details": "",
        "evaluation_source": "CACHE",
        "resource_origins": set()
    }
    
    match = WORKSPACE_REGEX.match(ws_name)
    if not match:
        result_record["details"] = "Excluded nomenclature scope configuration."
        return result_record
        
    env = match.group(2).lower()
    result_record["env"] = env
    
    try:
        ws_id = ws_info["id"]
        resources_in_state = ws_info["resource_count"]
        has_state_history = ws_info["has_state"]
        
        if has_state_history and resources_in_state == 0:
            result_record["status"] = "INACTIVE"
            result_record["details"] = "Ghost Asset: Workspace manages 0 live resources in cloud state. Safe to skip."
            return result_record
        
        plan_payload = None
        has_recent_error = False
        runs_url = f"https://app.terraform.io/api/v2/workspaces/{ws_id}/runs?page%5Bsize%5D=20"
        
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
                                    break
                            except Exception:
                                plan_payload = None
                                
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
                            time.sleep(15)
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
        except Exception:
            plan_payload = None

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
            result_record["details"] = "Validation Failure: Unable to fetch live plan or extract state metrics baseline profiles."
            return result_record

        # ─── MODULE ORIGIN CLASSIFIER ───
        module_sources = extract_module_sources(plan_payload)
        changes_map = plan_payload.get("resource_changes", {})
        changes_iterator = changes_map.values() if isinstance(changes_map, dict) else changes_map
        
        origin_by_address = {}
        has_targeted_resources = False
        for change in changes_iterator:
            r_type = change.get("type")
            if r_type in targeted_resource_types:
                has_targeted_resources = True
                mod_addr = change.get("module_address", "")
                address = change.get("address", "")
                
                if not mod_addr:
                    origin_badge = "🧱 Native Resource Block"
                else:
                    clean_mod_addr = re.sub(r'\[\d+\]', '', mod_addr).lower().strip()
                    resolved_source = module_sources.get(clean_mod_addr, "")
                    
                    if "woolworthscorp" in resolved_source:
                        origin_badge = "🏢 Private Module"
                    elif resolved_source and not any(k in resolved_source for k in ["terraform-aws-", "terraform-google-"]):
                        origin_badge = "🌐 Public Module"
                    else:
                        if any(kw in clean_mod_addr for kw in ["lb", "load-balancer", "loadbalancer", "az_"]):
                            origin_badge = "🏢 Private Module"
                        else:
                            origin_badge = "🌐 Public Module"
                
                result_record["resource_origins"].add(origin_badge)
                if address:
                    origin_by_address[address.lower().strip()] = origin_badge
                if mod_addr:
                    clean_addr_key = re.sub(r'\[\d+\]', '', mod_addr).lower().strip()
                    origin_by_address[clean_addr_key] = origin_badge
                    origin_by_address[mod_addr.lower().strip()] = origin_badge
                    
        if not has_targeted_resources:
            result_record["status"] = "EXCLUDED"
            result_record["details"] = "Excluded: Infrastructure topology does not contain matching targeted resource types."
            return result_record

        cfg_file = f"config_{ws_id}.json"
        workspace_root = os.getcwd()
        tfplan_funcs_path = os.path.abspath(os.path.join(workspace_root, "odessa_tenants/common-functions/tfplan-functions/tfplan-functions.sentinel"))
        tfpolicy_funcs_path = os.path.abspath(os.path.join(workspace_root, "odessa_tenants/common-functions/tfpolicy-functions/tfpolicy-functions.sentinel"))
        
        if not os.path.exists(tfplan_funcs_path): tfplan_funcs_path = os.path.abspath("tfplan-functions.sentinel")
        if not os.path.exists(tfpolicy_funcs_path): tfpolicy_funcs_path = os.path.abspath("tfpolicy-functions.sentinel")

        config_payload = {
            "mock": {
                "tfplan/v2": {"data": plan_payload},
                "tfrun": {"data": {"id": "run-speculative-analysis-mock", "is_destroy": False, "variables": {}, "workspace": {"name": ws_name, "tags": [], "auto_apply": False}}},
                "tfconfig/v2": {"data": {"variables": {}, "resources": {}, "module_calls": {}, "outputs": {}, "providers": {}}},
                "tfstate/v2": {"data": {"resources": {}}}
            },
            "module": {  
                "tfplan-functions": {"source": tfplan_funcs_path},
                "tfpolicy-functions": {"source": tfpolicy_funcs_path}
            }
        }
        with open(cfg_file, "w") as f:
            json.dump(config_payload, f)
            
        run_sim = subprocess.run(["sentinel", "apply", "-trace", "-config", cfg_file, policy_path], capture_output=True, text=True)

        if os.path.exists(cfg_file):
            os.remove(cfg_file)
            
        # ─── RECONCILE EXIT CODES WITH ENFORCEMENT LEVELS ───
        if run_sim.returncode == 0:
            advisory_alerts = []
            if run_sim.stdout:
                advisory_alerts = [line.strip().replace('<', '&lt;').replace('>', '&gt;') for line in run_sim.stdout.split('\n') if "WARNING" in line and "deprecation" not in line.lower()]
            
            if advisory_alerts:
                result_record["status"] = "WARNING"
                mapped_warnings = []
                for line in advisory_alerts[:4]:
                    detected_badge = "🔍 Context"
                    line_lower = line.lower()
                    for addr_key, badge in origin_by_address.items():
                        if addr_key in line_lower:
                            detected_badge = badge
                            break
                    mapped_warnings.append(f"• <b>[{detected_badge}]</b> {line}")
                
                bullets = "<br>".join(mapped_warnings)
                result_record["details"] = f"🟡 <b>Plan Pass (with Legacy Debt):</b> Speculative blueprint runs safely, but workspace carries warnings:<br>{bullets}"
            else:
                result_record["status"] = "PASS"
                if result_record["evaluation_source"] == "STATE":
                    result_record["details"] = "Compatible: Rule passes perfectly against active production state deployment topology."
                else:
                    result_record["details"] = "Compatible: Rule passes perfectly against live architecture layout definitions."
        else:
            captured_violations = []
            if run_sim.stdout:
                in_print_block = False
                for line in run_sim.stdout.split('\n'):
                    clean_line = re.sub(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s*', '', line).strip()
                    if "Print messages:" in clean_line:
                        in_print_block = True
                        continue
                    if in_print_block:
                        if not clean_line: continue
                        if ".sentinel:" in clean_line or "Rule \"" in clean_line or "Fail -" in clean_line: break
                        if any(k in clean_line for k in ["Is policy exempt:", "compliance checks...", "how to add an exemption", "Policy violation detected."]): continue
                        captured_violations.append(clean_line)
                
                if not captured_violations:
                    for line in run_sim.stdout.split('\n'):
                        clean_line = re.sub(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s*', '', line).strip()
                        if ("WARNING" in clean_line or "CRITICAL" in clean_line or "error" in clean_line.lower() or "Fail" in clean_line) and "deprecation" not in clean_line.lower() and "warnings occurred" not in clean_line.lower():
                            captured_violations.append(clean_line)
            
            mapped_violations = []
            for v in captured_violations[:4]:
                detected_badge = "🔍 Context"
                v_lower = v.lower()
                for addr_key, badge in origin_by_address.items():
                    if addr_key in v_lower:
                        detected_badge = badge
                        break
                mapped_violations.append(f"• <b>[{detected_badge}]</b> {v}")
            failure_reason = "<br>".join(mapped_violations) if mapped_violations else "Policy criteria violation detected during structural trace evaluation."

            if enforcement_level == "advisory":
                result_record["status"] = "WARNING"
                result_record["details"] = f"🟡 <b>Advisory Warning:</b> Soft design profile compliance notice:<br>{failure_reason}"
            else:
                result_record["status"] = "BLOCKED"
                if result_record["evaluation_source"] == "STATE":
                    result_record["details"] = f"🚨 <b>Active Violation in Production State:</b><br>{failure_reason}"
                else:
                    result_record["details"] = f"🚨 <b>Policy Violation Detonated:</b> Future intent layout violates rule logic.<br>{failure_reason}"
            
    except Exception as e:
        result_record["status"] = "UNSTABLE"
        result_record["details"] = f"API System Exception: Anomalous processing path tracking check (`{str(e)[:80]}`)"
        
    return result_record

# ==============================================================================
# REPORT GENERATION (HTML & MARKDOWN)
# ==============================================================================
def generate_reports(final_results, candidate_workspaces, policy_base, enforcement_level, dry_run_enabled, tfe_org, script_dir):
    total_discovered_raw = len(candidate_workspaces)
    
    count_excluded = sum(1 for r in final_results if r["status"] == "EXCLUDED")
    count_inactive = sum(1 for r in final_results if r["status"] == "INACTIVE")
    count_pass = sum(1 for r in final_results if r["status"] == "PASS")
    count_warning = sum(1 for r in final_results if r["status"] == "WARNING")
    count_blocked = sum(1 for r in final_results if r["status"] == "BLOCKED")
    
    active_evals = [r for r in final_results if r["status"] not in ["EXCLUDED", "INACTIVE"]]
    total_active_count = len(active_evals)
    plan_cache_hits = sum(1 for r in active_evals if r["evaluation_source"] == "CACHE")
    fully_satisfied = total_active_count > 0 and plan_cache_hits == total_active_count
    
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S AEST")
    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    context_badge = f"Local CLI Analysis (Enforcement: <code>{enforcement_level}</code>)"
    if dry_run_enabled:
        context_badge += " (⚠️ Dry Run Passive)"
        
    cache_text = f"🟢 Full ({plan_cache_hits}/{total_active_count} retrieved from warm history)" if fully_satisfied else f"🟡 Partial ({plan_cache_hits}/{total_active_count} retrieved from warm history)"

    # 1. JSON Report
    json_path = os.path.join(script_dir, f"sentinel_impact_report_{policy_base}_{timestamp_file}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(final_results, f, indent=2, default=list)

    # 2. Markdown Report
    md_path = os.path.join(script_dir, f"sentinel_impact_report_{policy_base}_{timestamp_file}.md")
    with open(md_path, "w", encoding="utf-8") as md:
        md.write(f"### 📋 Policy Target Domain: `{policy_base}`\n\n")
        md.write(f"**Execution Context:** {context_badge}\n\n")
        md.write(f"✨ **Cache Optimization Coverage:** {cache_text}\n\n")
        md.write("📊 **Executive Risk Summary Scorecard**\n")
        md.write(f"* Total Workspaces Evaluated: {total_discovered_raw}\n")
        md.write(f"* Workspaces Outside Scope: {count_excluded}\n")
        md.write(f"* Workspaces Passing Cleanly (🟢 PASS): {count_pass}\n")
        md.write(f"* Workspaces with Warnings (⚠️ WARNING): {count_warning}\n")
        md.write(f"* Workspaces Vulnerable to Blockage (🚨 BLOCKED): {count_blocked}\n\n")

    # 3. Rich Executive HTML Radar Report (Matches Production Impact Analysis Radar)
    html_path = os.path.join(script_dir, f"sentinel_impact_report_{policy_base}_{timestamp_file}.html")
    with open(html_path, "w", encoding="utf-8") as html:
        html.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Production Impact Analysis Radar</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #f8fafc; color: #1e293b; margin: 0; padding: 0; line-height: 1.5; }}
        .container {{ max-width: 1400px; margin: 40px auto; padding: 0 20px; }}
        .header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); color: white; padding: 35px 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 22pt; font-weight: 700; letter-spacing: -0.025em; }}
        .header p {{ margin: 10px 0 0 0; color: #94a3b8; font-size: 11pt; }}
        .meta-grid {{ display: table; width: 100%; margin-top: 25px; border-top: 1px solid #334155; padding-top: 20px; }}
        .meta-item {{ display: table-cell; width: 25%; }}
        .meta-label {{ font-size: 8.5pt; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-bottom: 6px; display: block; font-weight: 600; }}
        .meta-value {{ font-size: 10.5pt; font-weight: 500; color: #e2e8f0; }}
        .meta-value code {{ background: #334155; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #38bdf8; }}
        
        .kpi-table {{ width: 100%; border-collapse: separate; border-spacing: 15px; margin: -15px; }}
        .kpi-card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border: 1px solid #e2e8f0; }}
        .kpi-card.blocked-card {{ background: #fef2f2; border-color: #fee2e2; }}
        .kpi-val {{ font-size: 22pt; font-weight: 700; display: block; margin-bottom: 4px; }}
        .kpi-card.blocked-card .kpi-val {{ color: #dc2626; }}
        .kpi-lbl {{ font-size: 10pt; color: #64748b; font-weight: 500; }}
        
        .section-title {{ font-size: 14pt; font-weight: 600; margin: 40px 0 15px 0; color: #0f172a; border-left: 4px solid #3b82f6; padding-left: 12px; }}
        .card-container {{ background: white; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border: 1px solid #e2e8f0; margin-bottom: 30px; overflow-x: auto; }}
        
        .data-table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 10pt; }}
        .data-table th {{ background-color: #f1f5f9; color: #475569; font-weight: 600; padding: 12px 16px; border-bottom: 2px solid #e2e8f0; }}
        .data-table td {{ padding: 16px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
        .data-table tr:hover {{ background-color: #f8fafc; }}
        
        .badge {{ display: inline-block; padding: 4px 8px; font-size: 9pt; font-weight: 600; border-radius: 4px; white-space: nowrap; }}
        .badge-blocked {{ background-color: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }}
        .badge-pass {{ background-color: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }}
        .badge-warning {{ background-color: #fef9c3; color: #854d0e; border: 1px solid #fef08a; }}
        .badge-env {{ background-color: #e0f2fe; color: #0369a1; font-family: monospace; font-size: 9.5pt; }}
        .badge-strategy {{ background-color: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; }}
        
        .workspace-link {{ color: #2563eb; text-decoration: none; font-weight: 600; }}
        .workspace-link:hover {{ text-decoration: underline; }}
        
        .diagnostic-box {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 16px; font-size: 9.5pt; color: #334155; max-width: 650px; word-break: break-word; line-height: 1.6; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Production Impact Analysis Radar</h1>
            <p>Predictive simulations executed across active enterprise workspaces intersecting altered policy configurations.</p>
            
            <div class="meta-grid">
                <div class="meta-item">
                    <span class="meta-label">Policy Target Domain</span>
                    <span class="meta-value"><code>{policy_base}</code></span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Execution Context</span>
                    <span class="meta-value">{context_badge}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Cache Optimization Coverage</span>
                    <span class="meta-value">{cache_text}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Last Evaluated</span>
                    <span class="meta-value">{current_time_str}</span>
                </div>
            </div>
        </div>

        <div class="section-title">📊 Executive Risk Summary Scorecard</div>
        <table class="kpi-table">
            <tr>
                <td>
                    <div class="kpi-card">
                        <span class="kpi-val">{total_discovered_raw}</span>
                        <span class="kpi-lbl">Total Workspaces Evaluated</span>
                    </div>
                </td>
                <td>
                    <div class="kpi-card">
                        <span class="kpi-val">{count_excluded}</span>
                        <span class="kpi-lbl">Outside Targeted Rules Scope</span>
                    </div>
                </td>
                <td>
                    <div class="kpi-card {'blocked-card' if count_blocked > 0 else ''}">
                        <span class="kpi-val">{count_blocked}</span>
                        <span class="kpi-lbl">🚨 Vulnerable to Blockage</span>
                    </div>
                </td>
                <td>
                    <div class="kpi-card">
                        <span class="kpi-val">{count_pass}</span>
                        <span class="kpi-lbl">🟢 Passing Cleanly</span>
                    </div>
                </td>
            </tr>
        </table>

        <div class="section-title">🔍 Full Simulation Matrix Details</div>
        <div class="card-container">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Data Strategy</th>
                        <th>Resource Configuration Origins</th>
                        <th>Env</th>
                        <th>Target Infra Workspace Scope</th>
                        <th>Speculative Runtime Diagnostic Context</th>
                    </tr>
                </thead>
                <tbody>""")

        for r in final_results:
            if r["status"] == "EXCLUDED": continue
            badge_class = "badge-pass" if r["status"] == "PASS" else "badge-warning" if r["status"] == "WARNING" else "badge-blocked"
            status_text = "🟢 PASS" if r["status"] == "PASS" else "⚠️ WARNING" if r["status"] == "WARNING" else "🚨 BLOCKED" if r["status"] == "BLOCKED" else r["status"]
            strategy_badge = "💾 Cache" if r["evaluation_source"] == "CACHE" else "🚀 Live Plan" if r["evaluation_source"] == "LIVE_PLAN" else "☁️ Live State"
            
            origins_list = sorted(list(r["resource_origins"]))
            origins_str = "<br>".join([f"• {o}" for o in origins_list]) if origins_list else "—"
            
            html.write(f"""
                    <tr>
                        <td><span class="badge {badge_class}">{status_text}</span></td>
                        <td><span class="badge badge-strategy">{strategy_badge}</span></td>
                        <td>{origins_str}</td>
                        <td><span class="badge badge-env">{r['env'].upper()}</span></td>
                        <td><a href="https://app.terraform.io/app/{tfe_org}/workspaces/{r['workspace']}/" target="_blank" class="workspace-link">`{r['workspace']}`</a></td>
                        <td><div class="diagnostic-box">{r['details']}</div></td>
                    </tr>""")
                    
        html.write("""
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>""")

    print(f"\n{C_GREEN}[+] Impact Analysis JSON report created: {json_path}{C_RESET}")
    print(f"{C_GREEN}[+] Impact Analysis Markdown report created: {md_path}{C_RESET}")
    print(f"{C_GREEN}[+] Impact Analysis HTML report created: {html_path}{C_RESET}")

# ==============================================================================
# MAIN ROUTER
# ==============================================================================
def main():
    if len(sys.argv) < 2:
        print(f"{C_RED}[-] Usage: python sentinel_impact_analyzer.py <policy_path>{C_RESET}")
        sys.exit(1)

    policy_path = sys.argv[1]
    policy_base = os.path.basename(policy_path)
    script_dir = os.path.dirname(os.path.abspath(__file__))

    tfe_token = os.getenv("TFE_TOKEN")
    tfe_org = os.getenv("TFE_ORG", "WoolworthsCorp")
    dry_run_enabled = os.getenv("DRY_RUN", "true").lower() == "true"

    print(f"\n{C_CYAN}========================================================================{C_RESET}")
    print(f"{C_CYAN}🚀 STAGE 2: TFE WORKSPACE BLAST RADIUS IMPACT ANALYSIS ({policy_base}){C_RESET}")
    print(f"{C_CYAN}========================================================================{C_RESET}")

    if dry_run_enabled:
        print(f"{C_YELLOW}⚠️  [LOG ALERT] RUNNING IN ENVIRONMENT DRY RUN SAMPLE MODE. NO LIVE REMOTE PLANS WILL BE CREATED.{C_RESET}")

    if not tfe_token:
        print(f"{C_RED}[-] Error: Environment variable 'TFE_TOKEN' is missing.{C_RESET}")
        sys.exit(1)

    if not os.path.exists(policy_path):
        print(f"{C_RED}[-] Error: Policy file '{policy_path}' not found.{C_RESET}")
        sys.exit(1)

    enforcement_level = discover_enforcement_level(policy_path)
    print(f"{C_GREEN}[+] Orchestration Level Detected: [{enforcement_level}]{C_RESET}")

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

    final_results = []
    with ThreadPoolExecutor(max_workers=7) as executor:
        futures = {
            executor.submit(process_single_workspace, ws, info, tfe_org, tfe_token, policy_path, targeted_resource_types, enforcement_level, dry_run_enabled): ws
            for ws, info in candidate_workspaces.items()
        }
        for future in as_completed(futures):
            final_results.append(future.result())

    final_results.sort(key=lambda x: (ENV_PRIORITY.get(x["env"], 99), x["workspace"]))

    generate_reports(final_results, candidate_workspaces, policy_base, enforcement_level, dry_run_enabled, tfe_org, script_dir)

    count_blocked = sum(1 for r in final_results if r["status"] == "BLOCKED")
    if count_blocked > 0:
        print(f"\n{C_RED}[-] Blast Radius Alert: {count_blocked} workspace(s) will be blocked by this policy!{C_RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()