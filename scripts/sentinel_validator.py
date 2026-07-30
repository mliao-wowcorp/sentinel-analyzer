import sys
import os
import re
import subprocess
from datetime import datetime

# Windows ANSI Color Setup
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
    
    print(f"\n{C_CYAN}========================================================================{C_RESET}")
    print(f"{C_CYAN}🧪 STAGE 1: SENTINEL CODE VALIDATION & UNIT TESTS ({policy_base}){C_RESET}")
    print(f"{C_CYAN}========================================================================{C_RESET}")

    if not os.path.exists(policy_path):
        print(f"{C_RED}[-] Error: Specified policy file '{policy_path}' does not exist.{C_RESET}")
        sys.exit(1)

    style_status = "🟢 PASS"
    test_status = "🟢 PASS"
    has_errors = False

    # 1. STYLE & FORMATTING CHECK (sentinel fmt -check)
    print(f"\n{C_CYAN}[1/2] Checking Code Formatting (`sentinel fmt -check`)...{C_RESET}")
    fmt_res = subprocess.run(["sentinel", "fmt", "-check", policy_path], capture_output=True, text=True)
    
    if fmt_res.returncode != 0:
        print(f"  {C_RED}❌ FAILED Layout Rules: {policy_path}{C_RESET}")
        print(f"     Run `sentinel fmt {policy_path}` to auto-align code formatting.")
        style_status = "🚨 FAIL"
        has_errors = True
    else:
        print(f"  {C_GREEN}✅ PASSED: Formatting aligns with standard Sentinel code style.{C_RESET}")

    # 2. UNIT TEST EXECUTION (sentinel test -verbose)
    test_dir = os.path.join(policy_dir, "test", policy_name)
    print(f"\n{C_CYAN}[2/2] Running Unit Test Suite (`sentinel test -verbose`)...{C_RESET}")
    
    if os.path.exists(test_dir):
        test_res = subprocess.run(["sentinel", "test", "-verbose", policy_path], capture_output=True, text=True)
        print(test_res.stdout)
        if test_res.stderr:
            print(test_res.stderr)

        if test_res.returncode != 0:
            print(f"  {C_RED}❌ TEST SUITE FAILED for: {policy_path}{C_RESET}")
            test_status = "🚨 FAIL"
            has_errors = True
        else:
            print(f"  {C_GREEN}✅ PASSED: All unit test mock assertions succeeded.{C_RESET}")
    else:
        print(f"  {C_YELLOW}⚠️  SKIPPED: No local test directory found at '{test_dir}'.{C_RESET}")
        test_status = "⚪ SKIPPED"

    # 3. GENERATE MARKDOWN SUMMARY REPORT
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S AEST")
    report_file = f"validation_report_{policy_name}.md"
    
    recommendation = "Template aligns perfectly with standards."
    if style_status == "🚨 FAIL" and test_status == "🚨 FAIL":
        recommendation = "🚨 **Action Required:** Run `sentinel fmt` AND repair broken test assertions."
    elif style_status == "🚨 FAIL":
        recommendation = "⚠️ **Layout Bug:** Run `sentinel fmt` locally to auto-align code formatting rules."
    elif test_status == "🚨 FAIL":
        recommendation = "❌ **Assertion Failure:** Check mock trace outputs to fix broken logic criteria."

    report_md = f"""## 🛡️ Sentinel Governance Validation Radar
_Last Evaluated: {timestamp}_

### 📊 Validation Dashboard Metrics
| Target Policy Domain File | Style & Layout Check | Unit Test Execution | Discovery Context / Actions |
| :--- | :---: | :---: | :--- |
| `{policy_path}` | {style_status} | {test_status} | {recommendation} |
"""
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(report_md)

    print(f"\n{C_GREEN}[+] Validation summary saved to: {report_file}{C_RESET}")

    if has_errors:
        print(f"{C_RED}[-] Validation failed. Please fix style or test assertion errors.{C_RESET}")
        sys.exit(1)
        
    print(f"{C_GREEN}[+] Validation completed successfully.{C_RESET}\n")

if __name__ == "__main__":
    main()