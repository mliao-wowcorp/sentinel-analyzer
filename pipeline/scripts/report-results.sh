#!/bin/bash
set -e

EXIT_CODE="$1"
TARGET="$2"
REPORT_FILE="$3"
REPO_CONTEXT="$4"
PR_NUMBER="$5"

# 1. Clean ANSI colors from raw execution logs safely
sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g" ../raw.log > ../clean.log

# 2. Extract dynamic time metadata in local AEST timezone 
TIMESTAMP=$(TZ="Australia/Sydney" date +"%Y-%m-%d %H:%M:%S AEST")

# 3. Dynamic Identification Vector: Locate all distinct sentinel files evaluated in this run
POLICIES=$(grep -oE "odessa_tenants/[a-zA-Z0-9_\/-]+\.sentinel" ../clean.log | sort -u || true)

# If no specific files were logged, fall back to displaying the raw target path arguments
if [ -z "$POLICIES" ]; then
  POLICIES="$TARGET"
fi

# 4. Compile polished markdown report payload
{
  echo "## 🛡️ Sentinel Governance Validation Radar"
  echo "Automated compliance unit tests and style rules were executed against your modified architecture code layers."
  echo "_Last Evaluated: ${TIMESTAMP}_"
  echo ""
  
  echo "### 📊 Validation Dashboard Metrics"
  echo "| Target Policy Domain File | Style & Layout Check | Unit Test Execution | Discovery Context Context / Actions |"
  echo "| :--- | :---: | :---: | :--- |"
  
  for p in $POLICIES; do
    P_BASE=$(basename "$p")
    
    # Check Style Status for this specific policy file
    STYLE_STATUS="🟢 PASS"
    if grep -q "❌ FAILED Layout Rules:.*$P_BASE" ../clean.log || grep -q "❌ FAILED Layout Rules:.*$p" ../clean.log; then
      STYLE_STATUS="🚨 FAIL"
    fi
    
    # Check Unit Test Status for this specific policy file
    TEST_STATUS="🟢 PASS"
    # Locate the log segment block corresponding to this policy's test runner block group
    if sed -n "/Test Results for:.*$P_BASE/,/::endgroup::/p" ../clean.log | grep -q "❌ TEST SUITE FAILED"; then
      TEST_STATUS="🚨 FAIL"
    elif sed -n "/Test Results for Directory:.*$(dirname "$p")/,/::endgroup::/p" ../clean.log | grep -q "❌ TEST SUITE FAILED"; then
      TEST_STATUS="🚨 FAIL"
    fi
    
    # Formulate Context Recommendations dynamically based on individual row status cells
    CONTEXT="Template aligns perfectly with standards."
    if [ "$STYLE_STATUS" == "🚨 FAIL" ] && [ "$TEST_STATUS" == "🚨 FAIL" ]; then
      CONTEXT="🚨 <b>Action Required:</b> Run \`sentinel fmt\` AND repair broken test assertions."
    elif [ "$STYLE_STATUS" == "🚨 FAIL" ]; then
      CONTEXT="⚠️ <b>Layout Bug:</b> Run \`sentinel fmt $p\` locally to auto-align code formatting rules."
    elif [ "$TEST_STATUS" == "🚨 FAIL" ]; then
      CONTEXT="❌ <b>Assertion Failure:</b> Check mock trace outputs to fix broken logic criteria."
    fi
    
    echo "| \`$p\` | $STYLE_STATUS | $TEST_STATUS | $CONTEXT |"
  done
  
  # Append Shared Common Functions Scan Status as a distinct system summary metric card
  echo ""
  echo "### 📦 Core Shared Foundation Health"
  if grep -q "⚠️  Warning:" ../clean.log; then
    echo "⚠️ **Warning:** Non-standard style variations detected inside global framework helper libraries. Review line-item traces below to clean style definitions."
  else
    echo "🟢 **Passed:** Global shared core framework helper libraries are fully standardized."
  fi
  
  echo -e "\n---\n"
  
  # 5. Collapse heavy log stream outputs into an expandable code element block
  echo "<details>"
  echo "<summary>🔍 Click to expand detailed terminal execution logs</summary>"
  echo ""
  echo "\`\`\`text"
  cat ../clean.log
  echo "\`\`\`"
  echo ""
  echo "</details>"
} > "$REPORT_FILE"

# 💡 NEW DASHBOARD OUTPUT FOR DIRECT CONSOLE VISIBILITY (PR AND MANUAL RUNS)
echo "========================================================================"
echo "📋 SENTINEL STAGE VALIDATION MATRIX LOG OUTPUT"
echo "========================================================================"
if [ -f "$REPORT_FILE" ]; then
  cat "$REPORT_FILE"
else
  echo "⚠️ Validation report file not found."
fi
echo "========================================================================"

# 6. Handle Sticky PR comment logic via safe file-stream redirection (Bypasses ARG_MAX boundaries)
if [ -n "$PR_NUMBER" ] && [ "$PR_NUMBER" != "null" ]; then
  # Unique Target Keyword Hook: "Sentinel Governance Validation Radar"
  COMMENT_ID=$(gh api "repos/${REPO_CONTEXT}/issues/${PR_NUMBER}/comments" \
    --jq '.[] | select(.user.login=="github-actions[bot]" and (.body | contains("Sentinel Governance Validation Radar"))) | .id' | head -n 1)
  
  jq -n --rawfile body "$REPORT_FILE" '{body: $body}' > comment_payload.json
  
  if [ -n "$COMMENT_ID" ]; then
    echo "Updating existing Sentinel Validation dashboard comment (ID: $COMMENT_ID)..."
    gh api -X PATCH "repos/${REPO_CONTEXT}/issues/comments/$COMMENT_ID" --input comment_payload.json > /dev/null
  else
    echo "Posting brand new validation matrix comment card..."
    gh api -X POST "repos/${REPO_CONTEXT}/issues/${PR_NUMBER}/comments" --input comment_payload.json > /dev/null
  fi
  rm -f comment_payload.json
fi