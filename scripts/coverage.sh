#!/bin/bash

# SIGMA Engine Code Coverage Script
# Runs cargo-tarpaulin to generate code coverage reports

set -e

echo "🔍 SIGMA Engine Code Coverage Analysis"
echo "=================================="
echo ""

# Check if cargo-tarpaulin is installed
if ! command -v cargo-tarpaulin &> /dev/null; then
    echo "❌ cargo-tarpaulin is not installed"
    echo "📦 Installing cargo-tarpaulin..."
    cargo install cargo-tarpaulin
    echo "✅ cargo-tarpaulin installed successfully"
    echo ""
fi

# Create coverage output directory
COVERAGE_DIR="target/coverage"
mkdir -p "$COVERAGE_DIR"

echo "📊 Running code coverage analysis..."
echo "   Output directory: $COVERAGE_DIR"
echo ""

# Run tarpaulin with comprehensive options
cargo tarpaulin \
    --ignore-tests \
    --out Html \
    --out Xml \
    --out Json \
    --output-dir "$COVERAGE_DIR" \
    --exclude-files "examples/*" \
    --exclude-files "benches/*" \
    --exclude-files "tests/*" \
    --timeout 120

echo ""
echo "📈 Coverage Analysis Complete!"
echo ""

# Check if HTML report was generated
if [ -f "$COVERAGE_DIR/tarpaulin-report.html" ]; then
    echo "📄 Reports generated:"
    echo "   📊 HTML Report: $COVERAGE_DIR/tarpaulin-report.html"
    echo "   📋 XML Report:  $COVERAGE_DIR/cobertura.xml"
    echo "   📝 JSON Report: $COVERAGE_DIR/tarpaulin-report.json"
    echo ""
    
    # Extract coverage percentage from the output
    if [ -f "$COVERAGE_DIR/tarpaulin-report.json" ]; then
        echo "🎯 Coverage Summary:"
        # Use a simple grep approach since jq might not be available
        COVERAGE=$(grep -o '"coverage":[0-9.]*' "$COVERAGE_DIR/tarpaulin-report.json" | cut -d: -f2 | head -1)
        if [ -n "$COVERAGE" ]; then
            echo "   📊 Overall Coverage: ${COVERAGE}%"
            
            # Check if coverage meets target (95%)
            COVERAGE_INT=$(echo "$COVERAGE" | cut -d. -f1)
            if [ "$COVERAGE_INT" -ge 95 ]; then
                echo "   ✅ Coverage target met (≥95%)"
            else
                echo "   ⚠️  Coverage below target (95%)"
                echo "   💡 Consider adding more tests to improve coverage"
            fi
        fi
    fi
    
    echo ""
    echo "🌐 To view the HTML report:"
    echo "   open $COVERAGE_DIR/tarpaulin-report.html"
    
else
    echo "❌ HTML report not found. Check for errors above."
    exit 1
fi

echo ""
echo "✅ Coverage analysis completed successfully!"
