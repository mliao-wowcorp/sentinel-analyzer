#!/bin/bash

# --- Initialization & Normalization ---
cd "$(dirname "$0")/../../.."

TEST_FAILED=0
DOMAIN_ERRORS=0

echo -e "\033[1;35m🚀 INITIALIZING VALIDATION FOR TARGET LIST:\033[0m $@"

# ========================================================================
# --- STAGE 1: STYLE & FORMATTING CHECK ---
# ========================================================================
echo -e "\n\033[1;34m[1/3] STYLE & FORMATTING CHECK\033[0m"

for target in "$@"; do
    if [ "$target" == "all" ]; then
        TARGET_PATH="odessa_tenants"
    else
        CLEAN_PATH=$(echo "$target" | sed 's|^/||' | sed 's|^odessa_tenants/||' | sed 's|/$||')
        TARGET_PATH="odessa_tenants/$CLEAN_PATH"
    fi

    # CASE 1: Single Independent File
    if [ -f "$TARGET_PATH" ]; then
        if ! sentinel fmt -check "$TARGET_PATH" > /dev/null 2>&1; then 
            echo -e "  \033[31m❌ FAILED Layout Rules:\033[0m $TARGET_PATH"
            DOMAIN_ERRORS=$((DOMAIN_ERRORS + 1))
        else
            echo -e "  Status: \033[32m✅ PASSED:\033[0m $(basename "$TARGET_PATH") is clean."
        fi

    # CASE 2: Complete Domain Directory Matrix
    elif [ -d "$TARGET_PATH" ]; then
        echo -e "  🔎 Auditing Directory: $TARGET_PATH"
        FILE_COUNT=0
        DIR_ERRORS=0
        
        while IFS= read -r file; do
            FILE_COUNT=$((FILE_COUNT + 1))
            if ! sentinel fmt -check "$file" > /dev/null 2>&1; then 
                echo -e "    \033[31m❌ FAILED Layout Rules:\033[0m $(basename "$file")"
                DOMAIN_ERRORS=$((DOMAIN_ERRORS + 1))
                DIR_ERRORS=$((DIR_ERRORS + 1))
            fi
        done < <(find "$TARGET_PATH" -type f -name "*.sentinel" ! -name "mock-*.sentinel" ! -path "*/test/*" 2>/dev/null)
        
        # FIX: Explicit visual confirmation when everything passes
        if [ "$DIR_ERRORS" -eq 0 ]; then
            echo -e "    Status: \033[32m✅ PASSED\033[0m (Clean formatting across all $FILE_COUNT discovered files)"
        fi
    fi
done

# ========================================================================
# --- STAGE 2: COMMON FUNCTIONS SCAN ---
# ========================================================================
echo -e "\n\033[1;34m[2/3] COMMON FUNCTIONS SCAN\033[0m"

if [ -d "odessa_tenants/common-functions" ]; then
    WARN_COUNT=0
    while IFS= read -r file; do
        if ! sentinel fmt -check "$file" > /dev/null 2>&1; then
            echo -e "  \033[33m⚠️  Warning:\033[0m $(basename "$file") has style variations."
            WARN_COUNT=$((WARN_COUNT + 1))
        fi
    done < <(find "odessa_tenants/common-functions" -type f -name "*.sentinel" ! -name "mock-*.sentinel" 2>/dev/null)
    
    if [ "$WARN_COUNT" -eq 0 ]; then
        echo -e "  Status: \033[32m✅ PASSED\033[0m (All global framework helper libraries are standardized)"
    fi
else
    echo -e "  Status: \033[90m-- SKIPPED: Shared global common folder not present.\033[0m"
fi

# ========================================================================
# --- STAGE 3: UNIT TEST EXECUTION ---
# ========================================================================
echo -e "\n\033[1;34m[3/3] UNIT TEST EXECUTION\033[0m"

for target in "$@"; do
    if [ "$target" == "all" ]; then
        TARGET_PATH="odessa_tenants"
    else
        CLEAN_PATH=$(echo "$target" | sed 's|^/||' | sed 's|^odessa_tenants/||' | sed 's|/$||')
        TARGET_PATH="odessa_tenants/$CLEAN_PATH"
    fi

    # CASE 1: Single Independent File Testing
    if [ -f "$TARGET_PATH" ]; then
        POLICY_NAME=$(basename "$TARGET_PATH" .sentinel)
        POLICY_DIR=$(dirname "$TARGET_PATH")
        TEST_DIR="$POLICY_DIR/test/$POLICY_NAME"
        
        echo "::group::Test Results for: $TARGET_PATH"
        
        # 🟢 PRESERVED NATIVE UNIT TESTING ENGINE: Runs actual pass/fail rules
        set +e
        sentinel test -verbose "$TARGET_PATH" 2>&1 | sed \
          -e 's/PASS/\x1b[32mPASS\x1b[0m/g' \
          -e 's/FAIL/\x1b[31mFAIL\x1b[0m/g' \
          -e 's/ERROR/\x1b[31mERROR\x1b[0m/g' \
          -e 's/logs:/\x1b[36mlogs:\x1b[0m/g' \
          -e 's/trace:/\x1b[33mtrace:\x1b[0m/g'
        STATUS=${PIPESTATUS[0]}
        set -e
        
        if [ $STATUS -ne 0 ]; then
            echo -e "\n  \033[0;31m❌ TEST SUITE FAILED\033[0m"
            TEST_FAILED=1
        else
            echo -e "\n  \033[0;32m✅ PASSED\033[0m"
        fi
        echo "::endgroup::"

    # CASE 2: Full Directory Matrix Testing
    elif [ -d "$TARGET_PATH" ]; then
        VALID_TEST_DIRS=$(find "$TARGET_PATH" -type f -name "*.sentinel" ! -path "*/test/*" ! -name "mock-*.sentinel" -exec dirname {} \; 2>/dev/null | sort -u)
        
        while IFS= read -r dir; do
            if [ -n "$dir" ] && [ -d "$dir/test" ]; then
                echo "::group::Test Results for Directory: $dir"

                # 🟢 PRESERVED NATIVE UNIT TESTING ENGINE: Runs actual directory pass/fail rules
                set +e
                sentinel test -verbose "$dir" 2>&1 | sed \
                  -e 's/PASS/\x1b[32mPASS\x1b[0m/g' \
                  -e 's/FAIL/\x1b[31mFAIL\x1b[0m/g' \
                  -e 's/ERROR/\x1b[31mERROR\x1b[0m/g' \
                  -e 's/logs:/\x1b[36mlogs:\x1b[0m/g' \
                  -e 's/trace:/\x1b[33mtrace:\x1b[0m/g'
                STATUS=${PIPESTATUS[0]}
                set -e
                
                if [ $STATUS -ne 0 ]; then
                    echo -e "\n  \033[0;31m❌ TEST SUITE FAILED\033[0m"
                    TEST_FAILED=1
                else
                    echo -e "\n  \033[0;32m✅ PASSED\033[0m"
                fi
                echo "::endgroup::"
            fi
        done <<< "$VALID_TEST_DIRS"
    fi
done

# ========================================================================
# --- FINAL SUMMARY GATING ---
# ========================================================================
echo -e "\n\033[1;34m========================================================================\033[0m"
if [ "$DOMAIN_ERRORS" -gt 0 ] || [ "$TEST_FAILED" -eq 1 ]; then
    echo -e "\033[1;31m💥 BUILD FAILED SUMMARY\033[0m"
    [ "$DOMAIN_ERRORS" -gt 0 ] && echo -e "👉 \033[1mSTYLE BUG:\033[0m $DOMAIN_ERRORS file(s) failed layout rules. Run 'sentinel fmt <file>' locally."
    if [ "$TEST_FAILED" -eq 1 ]; then
        echo -e "\n👉 TEST BUG: One or more policy mock assertions failed or mocks are missing."
    fi
    echo -e "\033[1;31m------------------------------------------------------------------------\033[0m"
    exit 1
else
    echo -e "\033[1;32m🎉 BUILD SUCCESSFUL: Fine-grained linear verification stages passed.\033[0m"
    exit 0
fi