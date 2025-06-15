#!/bin/bash

# SIGMA Engine Pre-commit Hook
# Runs essential quality checks before allowing a commit

set -e

echo "🔍 SIGMA Engine Pre-commit Checks"
echo "=============================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track overall success
OVERALL_SUCCESS=true

# Function to run a check and track success
run_check() {
    local check_name="$1"
    local command="$2"
    
    echo -e "${BLUE}🔍 $check_name...${NC}"
    
    if eval "$command" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ $check_name passed${NC}"
        return 0
    else
        echo -e "${RED}❌ $check_name failed${NC}"
        OVERALL_SUCCESS=false
        return 1
    fi
}

# Essential pre-commit checks (fast ones only)

# 1. Code Formatting Check
run_check "Code formatting" "cargo fmt --all -- --check"

# 2. Basic Clippy Check (only errors, not warnings)
run_check "Clippy errors" "cargo clippy --all-targets --all-features -- -D clippy::correctness -D clippy::suspicious"

# 3. Quick compile check
run_check "Compilation" "cargo check --all-targets --all-features"

# 4. Unit tests only (integration tests can be slow)
run_check "Unit tests" "cargo test --lib --quiet"

echo ""

# Summary
if [ "$OVERALL_SUCCESS" = true ]; then
    echo -e "${GREEN}🎉 Pre-commit checks passed!${NC}"
    echo -e "${GREEN}✅ Commit allowed${NC}"
    exit 0
else
    echo -e "${RED}❌ Pre-commit checks failed${NC}"
    echo ""
    echo -e "${YELLOW}💡 Run 'make quality' for detailed output${NC}"
    echo -e "${YELLOW}💡 Run 'cargo fmt' to fix formatting issues${NC}"
    echo -e "${YELLOW}💡 Fix clippy errors before committing${NC}"
    echo ""
    echo -e "${RED}🚫 Commit blocked${NC}"
    exit 1
fi
