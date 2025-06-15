#!/bin/bash
# Profiling script for SIGMA Engine benchmarks

set -e

echo "Running flamegraph profiling on SIGMA Engine benchmarks..."

# Create output directory for flamegraphs
mkdir -p target/flamegraphs

# Profile the high EPS simulation benchmark (most representative of real-world usage)
echo "Profiling high_eps_simulation benchmark..."
cargo flamegraph --bench vm_execution --output target/flamegraphs/high_eps_simulation.svg -- --bench high_eps_simulation

# Profile the complex execution benchmark
echo "Profiling complex_execution benchmark..."
cargo flamegraph --bench vm_execution --output target/flamegraphs/complex_execution.svg -- --bench complex_execution

# Profile the deeply nested execution benchmark
echo "Profiling deeply_nested_execution benchmark..."
cargo flamegraph --bench vm_execution --output target/flamegraphs/deeply_nested_execution.svg -- --bench deeply_nested_execution

echo "Flamegraphs generated in target/flamegraphs/"
echo "Open the SVG files in a web browser to view the profiling results."
