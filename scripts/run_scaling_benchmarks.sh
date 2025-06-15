#!/bin/bash

# SIGMA Engine Rule Scaling Benchmark Runner
# This script runs comprehensive benchmarks to test performance with different numbers of rules

set -e

echo "🚀 SIGMA Engine Rule Scaling Benchmark Suite"
echo "=========================================="
echo ""

# Create output directory
BENCHMARK_DIR="benchmark_results/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BENCHMARK_DIR"

echo "📁 Results will be saved to: $BENCHMARK_DIR"
echo ""

# Function to run a benchmark and save results
run_benchmark() {
    local bench_name=$1
    local description=$2
    
    echo "🔬 Running $description..."
    echo "   Benchmark: $bench_name"
    
    # Run the benchmark and save results
    cargo bench --bench "$bench_name" -- --output-format json > "$BENCHMARK_DIR/${bench_name}_results.json" 2>&1 || {
        echo "   ⚠️  Benchmark failed, running with verbose output..."
        cargo bench --bench "$bench_name" 2>&1 | tee "$BENCHMARK_DIR/${bench_name}_output.txt"
    }
    
    # Also save HTML report if available
    if [ -d "target/criterion" ]; then
        cp -r "target/criterion" "$BENCHMARK_DIR/criterion_reports/"
    fi
    
    echo "   ✅ Completed"
    echo ""
}

# Function to run profiling
run_profiling() {
    echo "🔍 Running profiling analysis..."
    
    # Build in release mode with debug symbols
    cargo build --release --bench rule_scaling
    
    # Find the benchmark binary
    BENCH_BINARY=$(find target/release/deps -name "rule_scaling-*" -type f -executable | head -1)
    
    if [ -n "$BENCH_BINARY" ]; then
        echo "   📊 Found benchmark binary: $BENCH_BINARY"
        
        # Run with different profiling tools based on OS
        if [[ "$OSTYPE" == "darwin"* ]]; then
            echo "   🍎 macOS detected - profiling instructions:"
            echo "      To profile with Instruments:"
            echo "      instruments -t 'Time Profiler' $BENCH_BINARY --bench"
            echo ""
            echo "   🔧 Running basic time measurement..."
            time "$BENCH_BINARY" --bench 2>&1 | tee "$BENCHMARK_DIR/profiling_output.txt"
            
        elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
            echo "   🐧 Linux detected - attempting perf profiling..."
            
            if command -v perf &> /dev/null; then
                echo "      Running perf record..."
                perf record -g "$BENCH_BINARY" --bench 2>&1 | tee "$BENCHMARK_DIR/perf_output.txt"
                
                echo "      Generating perf report..."
                perf report > "$BENCHMARK_DIR/perf_report.txt" 2>&1
            else
                echo "      perf not available, running basic timing..."
                time "$BENCH_BINARY" --bench 2>&1 | tee "$BENCHMARK_DIR/profiling_output.txt"
            fi
        else
            echo "   ⏱️  Running basic timing measurement..."
            time "$BENCH_BINARY" --bench 2>&1 | tee "$BENCHMARK_DIR/profiling_output.txt"
        fi
    else
        echo "   ❌ Could not find benchmark binary"
    fi
    
    echo ""
}

# Function to generate summary report
generate_summary() {
    echo "📋 Generating benchmark summary..."
    
    cat > "$BENCHMARK_DIR/README.md" << EOF
# SIGMA Engine Rule Scaling Benchmark Results

Generated on: $(date)
System: $(uname -a)
Rust version: $(rustc --version)

## Benchmark Overview

This benchmark suite tests the performance of the SIGMA Engine with different numbers of rules,
from small deployments to production-scale scenarios with 2k+ rules.

### Test Scenarios

1. **Simple Rules**: Basic field matching (EventID, LogonType)
2. **Medium Rules**: Multiple selections with contains operations
3. **Complex Rules**: Multiple selections, filters, and complex conditions
4. **Mixed Rules**: Realistic distribution (60% simple, 30% medium, 10% complex)

### Rule Counts Tested

- Small scale: 10, 50, 100 rules
- Medium scale: 500, 1000 rules  
- Large scale: 2000, 5000 rules

### Key Metrics

- **Execution Time**: Time to process events through all rules
- **Primitive Matching**: Time for pattern matching operations
- **Compilation Time**: Time to compile rules to bytecode
- **Memory Usage**: Memory allocation patterns

## Files in this directory

- \`rule_scaling_results.json\`: Raw benchmark data
- \`profiling_output.txt\`: Profiling information
- \`criterion_reports/\`: Detailed HTML reports from Criterion
- \`performance_analysis.md\`: Detailed analysis and recommendations

## Quick Results Summary

EOF

    # Try to extract key metrics from benchmark results
    if [ -f "$BENCHMARK_DIR/rule_scaling_results.json" ]; then
        echo "### Performance Highlights" >> "$BENCHMARK_DIR/README.md"
        echo "" >> "$BENCHMARK_DIR/README.md"
        echo "See detailed results in the JSON files and Criterion HTML reports." >> "$BENCHMARK_DIR/README.md"
    fi

    cat >> "$BENCHMARK_DIR/README.md" << EOF

## Performance Analysis

### Scaling Characteristics

The benchmarks test how performance scales with the number of rules:

1. **Linear Scaling**: Expected for most operations
2. **Primitive Deduplication**: Should reduce overhead with similar rules
3. **Memory Efficiency**: Important for large rule sets
4. **Cache Performance**: Critical for high-throughput scenarios

### Production Recommendations

Based on these results:

- **2k Rules**: Target performance for production deployments
- **Memory Usage**: Monitor allocation patterns
- **Optimization Opportunities**: Identify bottlenecks for improvement

### Next Steps

1. Analyze results for performance bottlenecks
2. Profile specific scenarios showing degradation
3. Implement optimizations for identified issues
4. Re-run benchmarks to measure improvements

EOF

    echo "   ✅ Summary generated: $BENCHMARK_DIR/README.md"
    echo ""
}

# Main execution
echo "🏗️  Building benchmarks..."
cargo build --release --bench rule_scaling

echo ""
echo "🧪 Running benchmark suite..."
echo ""

# Run the main scaling benchmark
run_benchmark "rule_scaling" "Rule Scaling Benchmarks"

# Run profiling if requested
if [ "${1:-}" = "--profile" ]; then
    run_profiling
fi

# Generate summary
generate_summary

echo "🎉 Benchmark suite completed!"
echo ""
echo "📊 Results summary:"
echo "   📁 Directory: $BENCHMARK_DIR"
echo "   📋 Summary: $BENCHMARK_DIR/README.md"

if [ -d "$BENCHMARK_DIR/criterion_reports" ]; then
    echo "   🌐 HTML Reports: $BENCHMARK_DIR/criterion_reports/index.html"
fi

echo ""
echo "🔍 To analyze results:"
echo "   1. Review the summary: cat $BENCHMARK_DIR/README.md"
echo "   2. Open HTML reports in browser"
echo "   3. Examine JSON data for detailed metrics"
echo ""
echo "💡 To run with profiling: $0 --profile"
echo ""
