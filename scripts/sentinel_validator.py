import sys
import os
import json
import subprocess
from datetime import datetime

C_GREEN  = "\033[1;32m"
C_RED    = "\033[1;31m"
C_YELLOW = "\033[1;33m"
C_CYAN   = "\033[36m"
C_RESET  = "\033[0m"

def main():
    if len(sys.argv) < 2:
        print(f"{C_RED}[-] Usage: python sentinel_validator.py <policy_path>{C_RESET}")
        sys.exit(1)

    policy_path = sys.argv[1]
    policy_base = os.path.basename(policy_path)
    policy_dir = os.path.dirname(policy_path) or "."
    policy_name = policy_base.replace(".sentinel", "")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    print(f"\n{C_CYAN}========================================================================{C_RESET}")
    print(f"{C_CYAN}🧪 STAGE 1: SENTINEL CODE VALIDATION & UNIT TESTS ({policy_base}){C_RESET}")
    print(f"{C_CYAN}========================================================================{C_RESET}")

    if not os.path.exists(policy_path):
        print(f"{C_RED}[-] Error: Specified policy file '{policy_path}' does not exist.{C_RESET}")
        sys.exit(1)

    style_status = "PASSED"
    test_status = "PASSED"
    has_errors = False

    # 1. STYLE & FORMATTING CHECK
    print(f"\n{C_CYAN}[1/2] Checking Code Formatting (`sentinel fmt -check`)...{C_RESET}")
    fmt_res = subprocess.run(["sentinel", "fmt", "-check", policy_path], capture_output=True, text=True)
    if fmt_res.returncode != 0:
        print(f"  {C_RED}❌ FAILED Layout Rules: {policy_path}{C_RESET}")
        style_status = "FAILED"
        has_errors = True
    else:
        print(f"  {C_GREEN}✅ PASSED: Formatting aligns with standard Sentinel code style.{C_RESET}")

    # 2. UNIT TEST EXECUTION
    test_dir = os.path.join(policy_dir, "test", policy_name)
    print(f"\n{C_CYAN}[2/2] Running Unit Test Suite (`sentinel test -verbose`)...{C_RESET}")
    
    if os.path.exists(test_dir):
        test_res = subprocess.run(["sentinel", "test", "-verbose", policy_path], capture_output=True, text=True)
        print(test_res.stdout)
        if test_res.returncode != 0:
            print(f"  {C_RED}❌ TEST SUITE FAILED for: {policy_path}{C_RESET}")
            test_status = "FAILED"
            has_errors = True
        else:
            print(f"  {C_GREEN}✅ PASSED: All unit test mock assertions succeeded.{C_RESET}")
    else:
        print(f"  {C_YELLOW}⚠️  SKIPPED: No local test directory found at '{test_dir}'.{C_RESET}")
        test_status = "SKIPPED"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_data = {
        "policy": policy_path,
        "style_check": style_status,
        "unit_tests": test_status,
        "timestamp": timestamp
    }

    # Save JSON Report
    json_file = os.path.join(script_dir, f"sentinel_validation_report_{timestamp}.json")
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Save HTML Report
    status_color = "#dc3545" if has_errors else "#28a745"
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Sentinel Policy Validation Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f8f9fa; color: #333; }}
        .card {{ background: white; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .badge {{ display: inline-block; padding: 6px 12px; font-weight: bold; border-radius: 4px; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background-color: #f1f3f5; }}
        .pass {{ color: #28a745; font-weight: bold; }}
        .fail {{ color: #dc3545; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="card">
        <h2>🛡️ Sentinel Code Validation & Unit Test Report</h2>
        <p><strong>Target Policy:</strong> <code>{policy_path}</code></p>
        <p><strong>Timestamp:</strong> {timestamp}</p>
        <p><strong>Overall Result:</strong> <span class="badge" style="background: {status_color}">{"FAILED" if has_errors else "PASSED"}</span></p>
    </div>
    <div class="card">
        <table>
            <tr><th>Check Type</th><th>Result Status</th></tr>
            <tr><td>Code Style & Layout (<code>sentinel fmt</code>)</td><td class="{'fail' if style_status == 'FAILED' else 'pass'}">{style_status}</td></tr>
            <tr><td>Unit Test Suite (<code>sentinel test</code>)</td><td class="{'fail' if test_status == 'FAILED' else 'pass'}">{test_status}</td></tr>
        </table>
    </div>
</body>
</html>"""

    html_file = os.path.join(script_dir, f"sentinel_validation_report_{timestamp}.html")
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\n{C_GREEN}[+] Validation JSON report saved to: {json_file}{C_RESET}")
    print(f"{C_GREEN}[+] Validation HTML report saved to: {html_file}{C_RESET}")

    if has_errors:
        sys.exit(1)

if __name__ == "__main__":
    main()