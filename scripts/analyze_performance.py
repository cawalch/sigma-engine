#!/usr/bin/env python3
"""
SIGMA Engine Performance Analysis Script

This script analyzes benchmark results to identify performance bottlenecks
and scaling issues with different numbers of rules.
"""

import json
import sys
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import argparse

def parse_criterion_output(file_path: str) -> Dict:
    """Parse Criterion benchmark output."""
    results = {}
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            
        # Extract benchmark results using regex patterns
        # This is a simplified parser - in practice, you'd want more robust parsing
        
        # Look for timing patterns
        time_pattern = r'(\w+(?:_\w+)*)\s+time:\s+\[([0-9.]+)\s+(\w+)\s+([0-9.]+)\s+(\w+)\s+([0-9.]+)\s+(\w+)\]'
        matches = re.findall(time_pattern, content)
        
        for match in matches:
            benchmark_name = match[0]
            lower_bound = float(match[1])
            lower_unit = match[2]
            estimate = float(match[3])
            estimate_unit = match[4]
            upper_bound = float(match[5])
            upper_unit = match[6]
            
            results[benchmark_name] = {
                'estimate': estimate,
                'unit': estimate_unit,
                'lower_bound': lower_bound,
                'upper_bound': upper_bound,
                'confidence_interval': [lower_bound, upper_bound]
            }
            
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        
    return results

def convert_to_nanoseconds(value: float, unit: str) -> float:
    """Convert time value to nanoseconds."""
    conversions = {
        'ns': 1,
        'µs': 1000,
        'us': 1000,  # Alternative microsecond notation
        'ms': 1_000_000,
        's': 1_000_000_000
    }
    return value * conversions.get(unit, 1)

def analyze_scaling(results: Dict) -> Dict:
    """Analyze scaling characteristics from benchmark results."""
    analysis = {
        'scaling_factor': {},
        'performance_degradation': {},
        'bottlenecks': [],
        'recommendations': []
    }
    
    # Group results by benchmark type and rule count
    grouped_results = {}
    for benchmark_name, data in results.items():
        # Extract rule count from benchmark name if present
        rule_count_match = re.search(r'(\d+)', benchmark_name)
        if rule_count_match:
            rule_count = int(rule_count_match.group(1))
            benchmark_type = re.sub(r'_?\d+', '', benchmark_name)
            
            if benchmark_type not in grouped_results:
                grouped_results[benchmark_type] = {}
            
            grouped_results[benchmark_type][rule_count] = data
    
    # Analyze scaling for each benchmark type
    for benchmark_type, rule_data in grouped_results.items():
        if len(rule_data) < 2:
            continue
            
        sorted_counts = sorted(rule_data.keys())
        base_count = sorted_counts[0]
        base_time = convert_to_nanoseconds(
            rule_data[base_count]['estimate'],
            rule_data[base_count]['unit']
        )
        
        scaling_factors = []
        for count in sorted_counts[1:]:
            current_time = convert_to_nanoseconds(
                rule_data[count]['estimate'],
                rule_data[count]['unit']
            )
            
            # Calculate scaling factor (time ratio vs rule count ratio)
            time_ratio = current_time / base_time
            count_ratio = count / base_count
            scaling_factor = time_ratio / count_ratio
            
            scaling_factors.append({
                'rule_count': count,
                'time_ratio': time_ratio,
                'count_ratio': count_ratio,
                'scaling_factor': scaling_factor
            })
        
        analysis['scaling_factor'][benchmark_type] = scaling_factors
        
        # Identify performance degradation
        if scaling_factors:
            worst_scaling = max(scaling_factors, key=lambda x: x['scaling_factor'])
            if worst_scaling['scaling_factor'] > 1.5:  # More than 50% worse than linear
                analysis['performance_degradation'][benchmark_type] = worst_scaling
                analysis['bottlenecks'].append(
                    f"{benchmark_type}: Non-linear scaling detected at {worst_scaling['rule_count']} rules"
                )
    
    return analysis

def generate_recommendations(analysis: Dict) -> List[str]:
    """Generate performance optimization recommendations."""
    recommendations = []
    
    # Check for scaling issues
    for benchmark_type, degradation in analysis['performance_degradation'].items():
        if degradation['scaling_factor'] > 2.0:
            recommendations.append(
                f"🔴 CRITICAL: {benchmark_type} shows severe scaling issues "
                f"(factor: {degradation['scaling_factor']:.2f}). "
                f"Consider algorithmic optimizations."
            )
        elif degradation['scaling_factor'] > 1.5:
            recommendations.append(
                f"🟡 WARNING: {benchmark_type} shows scaling degradation "
                f"(factor: {degradation['scaling_factor']:.2f}). "
                f"Monitor for production impact."
            )
    
    # General recommendations based on rule counts
    if any('2000' in str(data) or '5000' in str(data) for data in analysis['scaling_factor'].values()):
        recommendations.append(
            "📊 Large rule sets (2k+) tested. Consider implementing rule grouping "
            "or hierarchical matching for better performance."
        )
    
    # Memory recommendations
    recommendations.append(
        "💾 Monitor memory usage patterns with large rule sets. "
        "Consider arena allocation for primitive matching."
    )
    
    # Compilation recommendations
    if 'compilation' in str(analysis).lower():
        recommendations.append(
            "⚡ For production deployments, pre-compile rules and cache bytecode "
            "to avoid compilation overhead."
        )
    
    return recommendations

def create_performance_report(results_dir: str) -> str:
    """Create a comprehensive performance analysis report."""
    results_path = Path(results_dir)
    
    # Find benchmark result files
    result_files = list(results_path.glob("*_output.txt")) + list(results_path.glob("*_results.json"))
    
    if not result_files:
        return "No benchmark result files found."
    
    # Parse all results
    all_results = {}
    for file_path in result_files:
        if file_path.suffix == '.txt':
            results = parse_criterion_output(str(file_path))
            all_results.update(results)
    
    # Analyze scaling
    analysis = analyze_scaling(all_results)
    recommendations = generate_recommendations(analysis)
    
    # Generate report
    report = f"""# SIGMA Engine Performance Analysis Report

## Executive Summary

This report analyzes the performance characteristics of the SIGMA Engine
with different numbers of rules, from small deployments to production-scale
scenarios with 2k+ rules.

## Scaling Analysis

### Performance Scaling Factors

"""
    
    for benchmark_type, scaling_data in analysis['scaling_factor'].items():
        report += f"\n#### {benchmark_type}\n\n"
        report += "| Rule Count | Time Ratio | Scaling Factor | Status |\n"
        report += "|------------|------------|----------------|--------|\n"
        
        for data in scaling_data:
            status = "✅ Good" if data['scaling_factor'] <= 1.2 else \
                    "⚠️ Degraded" if data['scaling_factor'] <= 1.5 else \
                    "🔴 Poor"
            
            report += f"| {data['rule_count']} | {data['time_ratio']:.2f}x | {data['scaling_factor']:.2f} | {status} |\n"
    
    # Bottlenecks section
    if analysis['bottlenecks']:
        report += "\n## Identified Bottlenecks\n\n"
        for bottleneck in analysis['bottlenecks']:
            report += f"- {bottleneck}\n"
    
    # Recommendations section
    report += "\n## Optimization Recommendations\n\n"
    for rec in recommendations:
        report += f"- {rec}\n"
    
    # Production readiness assessment
    report += "\n## Production Readiness Assessment\n\n"
    
    critical_issues = len([r for r in recommendations if "🔴 CRITICAL" in r])
    warning_issues = len([r for r in recommendations if "🟡 WARNING" in r])
    
    if critical_issues > 0:
        report += f"❌ **NOT READY**: {critical_issues} critical performance issues identified.\n"
    elif warning_issues > 0:
        report += f"⚠️ **CAUTION**: {warning_issues} performance warnings. Monitor in production.\n"
    else:
        report += "✅ **READY**: No critical performance issues identified.\n"
    
    report += "\n## Next Steps\n\n"
    report += "1. Address critical performance issues before production deployment\n"
    report += "2. Implement recommended optimizations\n"
    report += "3. Set up continuous performance monitoring\n"
    report += "4. Re-run benchmarks after optimizations\n"
    
    return report

def main():
    parser = argparse.ArgumentParser(description='Analyze SIGMA Engine performance benchmarks')
    parser.add_argument('results_dir', help='Directory containing benchmark results')
    parser.add_argument('--output', '-o', help='Output file for analysis report')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.results_dir):
        print(f"Error: Results directory '{args.results_dir}' not found")
        sys.exit(1)
    
    print("🔍 Analyzing benchmark results...")
    report = create_performance_report(args.results_dir)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"📊 Analysis report saved to: {args.output}")
    else:
        print("\n" + "="*60)
        print(report)
        print("="*60)

if __name__ == "__main__":
    main()
