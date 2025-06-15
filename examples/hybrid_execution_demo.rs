//! Demonstration of SIGMA Engine hybrid execution strategies.
//!
//! This example shows how to use different execution methods for
//! optimal performance based on workload characteristics.

use sigma_engine::{compiler::Compiler, ir::ChunkComplexity, vm::DefaultVm};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 SIGMA Engine Hybrid Execution Demo");
    println!("=====================================\n");

    // Create a compiler and VM
    let mut compiler = Compiler::new();
    let mut vm = DefaultVm::new();

    // Example rules with different complexities
    let rules = [
        // Simple rule
        r#"
title: Simple Login Detection
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
"#,
        // Medium complexity rule
        r#"
title: Medium Complexity Rule
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4624
        LogonType: 2
    selection2:
        EventID: 4625
    condition: selection1 or selection2
"#,
        // Complex rule
        r#"
title: Complex Detection Rule
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4624
        LogonType: 2
    selection2:
        EventID: 4625
    selection3:
        EventID: 4648
    filter:
        TargetUserName: SYSTEM
    condition: (selection1 or selection2 or selection3) and not filter
"#,
    ];

    // Compile rules and show complexity classification
    let mut chunks = Vec::new();
    println!("📊 Rule Complexity Analysis:");

    for (i, rule_yaml) in rules.iter().enumerate() {
        match compiler.compile_rule(rule_yaml) {
            Ok(chunk) => {
                let complexity_str = match chunk.complexity {
                    ChunkComplexity::Simple => "Simple",
                    ChunkComplexity::Medium => "Medium",
                    ChunkComplexity::Complex => "Complex",
                };
                println!(
                    "  Rule {}: {} ({} opcodes, {} max stack depth)",
                    i + 1,
                    complexity_str,
                    chunk.opcodes.len(),
                    chunk.max_stack_depth
                );
                chunks.push(chunk);
            }
            Err(e) => println!("  Rule {}: Compilation failed - {}", i + 1, e),
        }
    }

    // Create sample primitive results
    let primitive_results = vec![true, false, true, false, true];

    println!("\n⚡ Execution Strategy Demonstration:");

    // Demonstrate different execution methods
    for (i, chunk) in chunks.iter().enumerate() {
        println!("\n  Rule {} Execution:", i + 1);

        // 1. Standard optimized execution (recommended for general use)
        let start = Instant::now();
        let result1 = vm.execute_optimized(chunk, &primitive_results)?;
        let time1 = start.elapsed();
        println!("    execute_optimized(): {:?} in {:?}", result1, time1);

        // 2. Ultra-fast execution (direct unchecked)
        if chunk.can_execute_unchecked(primitive_results.len(), 64) {
            let start = Instant::now();
            let result2 = vm.execute_ultra_fast(chunk, &primitive_results);
            let time2 = start.elapsed();
            println!("    execute_ultra_fast(): {:?} in {:?}", result2, time2);
        }

        // 3. Adaptive execution (for specialized workloads)
        if chunk.can_execute_unchecked(primitive_results.len(), 64) {
            let start = Instant::now();
            let result3 = vm.execute_adaptive(chunk, &primitive_results);
            let time3 = start.elapsed();
            println!("    execute_adaptive(): {:?} in {:?}", result3, time3);
        }
    }

    // Demonstrate batch execution for large rule sets
    println!("\n📦 Batch Execution Demo:");

    // Create multiple copies to simulate large rule set
    let mut large_rule_set = Vec::new();
    for _ in 0..100 {
        large_rule_set.extend(chunks.iter().cloned());
    }

    println!("  Processing {} rules...", large_rule_set.len());

    // Individual execution
    let start = Instant::now();
    let mut individual_matches = Vec::new();
    for chunk in &large_rule_set {
        if let Some(rule_id) = vm.execute_optimized(chunk, &primitive_results)? {
            individual_matches.push(rule_id);
        }
    }
    let individual_time = start.elapsed();

    // Batch execution
    let start = Instant::now();
    let batch_matches = vm.execute_batch_optimized(&large_rule_set, &primitive_results)?;
    let batch_time = start.elapsed();

    println!(
        "  Individual execution: {} matches in {:?}",
        individual_matches.len(),
        individual_time
    );
    println!(
        "  Batch execution: {} matches in {:?}",
        batch_matches.len(),
        batch_time
    );

    if batch_time < individual_time {
        let improvement = ((individual_time.as_nanos() as f64 - batch_time.as_nanos() as f64)
            / individual_time.as_nanos() as f64)
            * 100.0;
        println!("  Batch improvement: {:.1}%", improvement);
    }

    // Show performance metrics if available
    #[cfg(feature = "metrics")]
    {
        println!("\n📈 Performance Metrics:");
        let metrics = vm.metrics();
        println!("{}", metrics.performance_summary());
    }

    println!("\n✅ Demo completed successfully!");
    println!("\n💡 Recommendations:");
    println!("  • Use execute_optimized() for general purpose execution");
    println!("  • Use execute_batch_optimized() for large rule sets (1000+ rules)");
    println!("  • Use execute_adaptive() only when profiling shows benefit");
    println!("  • Enable 'metrics' feature for performance monitoring");

    Ok(())
}
