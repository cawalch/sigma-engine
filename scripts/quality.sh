#!/bin/bash

# SIGMA Engine Code Quality Check Script
# Runs comprehensive code quality checks including formatting, linting, and documentation

set -e

echo "🔍 SIGMA Engine Code Quality Checks"
echo "================================"
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
    
    echo -e "${BLUE}🔍 Running $check_name...${NC}"
    
    if eval "$command"; then
        echo -e "${GREEN}✅ $check_name passed${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}❌ $check_name failed${NC}"
        echo ""
        OVERALL_SUCCESS=false
        return 1
    fi
}

# 1. Code Formatting Check
run_check "Code Formatting" "cargo fmt --all -- --check"

# 2. Clippy Linting (allow warnings for now, focus on errors)
run_check "Clippy Linting" "cargo clippy --all-targets --all-features -- -D clippy::correctness -D clippy::suspicious -A warnings"

# 3. Unit Tests
run_check "Unit Tests" "cargo test --lib"

# 4. Integration Tests
run_check "Integration Tests" "cargo test --test '*'"

# 5. Documentation Tests
run_check "Documentation Tests" "cargo test --doc"

# 6. Documentation Build
run_check "Documentation Build" "cargo doc --all-features --no-deps"

# 7. Security Audit (if cargo-audit is available)
if command -v cargo-audit >/dev/null 2>&1; then
    run_check "Security Audit" "cargo audit"
else
    echo -e "${YELLOW}⚠️  Skipping security audit (cargo-audit not installed)${NC}"
    echo ""
fi

# 8. Check for TODO/FIXME comments
echo -e "${BLUE}🔍 Checking for TODO/FIXME comments...${NC}"
TODO_COUNT=$(grep -r "TODO\|FIXME" src/ tests/ 2>/dev/null | wc -l || echo "0")
if [ "$TODO_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Found $TODO_COUNT TODO/FIXME comments:${NC}"
    grep -rn "TODO\|FIXME" src/ tests/ 2>/dev/null || true
    echo ""
else
    echo -e "${GREEN}✅ No TODO/FIXME comments found${NC}"
    echo ""
fi

# 9. Check for println! statements in src/ (should use proper logging)
echo -e "${BLUE}🔍 Checking for println! statements in source code...${NC}"
PRINTLN_COUNT=$(grep -r "println!" src/ 2>/dev/null | wc -l || echo "0")
if [ "$PRINTLN_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Found $PRINTLN_COUNT println! statements in src/:${NC}"
    grep -rn "println!" src/ 2>/dev/null || true
    echo -e "${YELLOW}💡 Consider using proper logging instead of println!${NC}"
    echo ""
else
    echo -e "${GREEN}✅ No println! statements found in source code${NC}"
    echo ""
fi

# 10. Check for unwrap() calls (should use proper error handling)
echo -e "${BLUE}🔍 Checking for unwrap() calls in source code...${NC}"
UNWRAP_COUNT=$(grep -r "\.unwrap()" src/ 2>/dev/null | grep -v "test" | wc -l || echo "0")
if [ "$UNWRAP_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Found $UNWRAP_COUNT unwrap() calls in src/:${NC}"
    grep -rn "\.unwrap()" src/ 2>/dev/null | grep -v "test" || true
    echo -e "${YELLOW}💡 Consider using proper error handling instead of unwrap()${NC}"
    echo ""
else
    echo -e "${GREEN}✅ No unwrap() calls found in source code${NC}"
    echo ""
fi

# 11. Check line length (should be under 100 characters)
echo -e "${BLUE}🔍 Checking for long lines (>100 characters)...${NC}"
LONG_LINES=$(find src/ tests/ -name "*.rs" -exec awk 'length($0) > 100 {print FILENAME ":" NR ":" $0}' {} \; 2>/dev/null | wc -l || echo "0")
if [ "$LONG_LINES" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Found $LONG_LINES lines longer than 100 characters${NC}"
    echo -e "${YELLOW}💡 Consider breaking long lines for better readability${NC}"
    echo ""
else
    echo -e "${GREEN}✅ All lines are within 100 character limit${NC}"
    echo ""
fi

# 12. Check for proper module documentation
echo -e "${BLUE}🔍 Checking for module documentation...${NC}"
UNDOCUMENTED_MODULES=0
for file in src/*.rs; do
    if [ -f "$file" ] && [ "$(basename "$file")" != "lib.rs" ]; then
        if ! head -20 "$file" | grep -q "^//!"; then
            echo -e "${YELLOW}⚠️  Module $file missing documentation${NC}"
            UNDOCUMENTED_MODULES=$((UNDOCUMENTED_MODULES + 1))
        fi
    fi
done

if [ "$UNDOCUMENTED_MODULES" -eq 0 ]; then
    echo -e "${GREEN}✅ All modules have documentation${NC}"
else
    echo -e "${YELLOW}💡 Consider adding module-level documentation (//!) to undocumented modules${NC}"
fi
echo ""

# Summary
echo "📊 Quality Check Summary"
echo "======================="

if [ "$OVERALL_SUCCESS" = true ]; then
    echo -e "${GREEN}🎉 All critical quality checks passed!${NC}"
    echo ""
    echo "✅ Code is ready for commit/merge"
    exit 0
else
    echo -e "${RED}❌ Some quality checks failed${NC}"
    echo ""
    echo "🔧 Please fix the issues above before committing"
    exit 1
fi
