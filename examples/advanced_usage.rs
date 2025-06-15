//! Advanced SIGMA Engine Usage Example
//!
//! This example demonstrates advanced features of SIGMA Engine:
//! 1. Field mapping and custom taxonomy
//! 2. Complex SIGMA rules with multiple conditions
//! 3. Value modifiers (endswith, contains, startswith)
//! 4. Primitive deduplication across multiple rules
//! 5. Performance measurement and optimization
//!
//! Run with: `cargo run --example advanced_usage --features examples`

#[cfg(not(feature = "examples"))]
fn main() {
    eprintln!("This example requires the 'examples' feature to be enabled.");
    eprintln!("Run with: cargo run --example advanced_usage --features examples");
    std::process::exit(1);
}

#[cfg(feature = "examples")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use sigma_engine::{Compiler, FieldMapping, Vm};
    use std::time::Instant;

    println!("🚀 SIGMA Engine Advanced Usage Example");
    println!("======================================\n");

    // Set up field mapping for custom taxonomy
    println!("🗺️  Setting up field mapping...");
    let mut field_mapping = FieldMapping::with_taxonomy("custom_edr".to_string());
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());
    field_mapping.add_mapping("ProcessUser".to_string(), "User".to_string());

    let mut compiler = Compiler::with_field_mapping(field_mapping);
    println!("✅ Field mapping configured for custom EDR taxonomy\n");

    // Define multiple complex SIGMA rules
    println!("📋 Defining multiple SIGMA rules...");

    let rule1_yaml = r#"
title: Suspicious PowerShell Execution
id: 11111111-1111-1111-1111-111111111111
status: stable
description: Detects suspicious PowerShell execution patterns
author: SIGMA BVM Example
date: 2025/06/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        EventID: 1
        ProcessImage|endswith: '\powershell.exe'
    selection_cmdline:
        ProcessCommandLine|contains:
            - 'Invoke-Expression'
            - 'DownloadString'
            - 'EncodedCommand'
    filter_admin:
        ProcessUser|startswith: 'SYSTEM'
    condition: selection_process and selection_cmdline and not filter_admin
level: high
"#;

    let rule2_yaml = r#"
title: Suspicious Command Line Tools
id: 22222222-2222-2222-2222-222222222222
status: experimental
description: Detects execution of suspicious command line tools
author: SIGMA BVM Example
date: 2025/06/15
logsource:
    category: process_creation
    product: windows
detection:
    suspicious_tools:
        ProcessImage|endswith:
            - '\whoami.exe'
            - '\net.exe'
            - '\systeminfo.exe'
            - '\tasklist.exe'
    condition: suspicious_tools
level: medium
"#;

    let rule3_yaml = r#"
title: Any Suspicious Process
id: 33333333-3333-3333-3333-333333333333
status: experimental
description: Detects any suspicious reconnaissance process
author: SIGMA BVM Example
date: 2025/06/15
logsource:
    category: process_creation
    product: windows
detection:
    recon1:
        ProcessImage|endswith: '\whoami.exe'
    recon2:
        ProcessImage|endswith: '\systeminfo.exe'
    recon3:
        ProcessImage|endswith: '\net.exe'
    condition: 1 of them
level: high
"#;

    // Compile all rules
    println!("⚙️  Compiling rules...");
    let start_compile = Instant::now();

    let bytecode1 = compiler.compile_rule(rule1_yaml)?;
    let bytecode2 = compiler.compile_rule(rule2_yaml)?;
    let bytecode3 = compiler.compile_rule(rule3_yaml)?;

    let compile_time = start_compile.elapsed();

    println!("✅ All rules compiled successfully!");
    println!("   📊 Compilation Statistics:");
    println!("      • Total Rules: 3");
    println!(
        "      • Total Primitives: {} (deduplicated)",
        compiler.primitive_count()
    );
    println!("      • Compilation Time: {:?}", compile_time);

    // Show primitive deduplication
    println!("\n🔍 Discovered Primitives (deduplicated across rules):");
    for (i, primitive) in compiler.primitives().iter().enumerate() {
        println!(
            "   {}. Field: '{}', Match: '{}', Values: {:?}",
            i, primitive.field, primitive.match_type, primitive.values
        );
    }

    // Create VM with a larger stack and prepare for execution
    println!("\n🖥️  Creating VM with a larger stack and preparing execution...");
    let mut vm = Vm::<64>::new();
    let rules = vec![
        ("Suspicious PowerShell", &bytecode1),
        ("Suspicious Tools", &bytecode2),
        ("Any Recon Tool", &bytecode3),
    ];

    // Test various scenarios
    println!("\n🎯 Testing detection scenarios...\n");

    // Scenario 1: PowerShell with suspicious command
    let primitive_results1 = vec![
        true,  // EventID = 1
        true,  // Image endswith powershell.exe
        true,  // CommandLine contains Invoke-Expression
        false, // User does not start with SYSTEM
        false, // Image does not end with whoami.exe
        false, // Image does not end with net.exe
        false, // Image does not end with systeminfo.exe
        false, // Image does not end with tasklist.exe
    ];
    let primitive_explanation1 = &[
        "0: EventID = 1",
        "1: Image endswith powershell.exe",
        "2: CommandLine contains Invoke-Expression",
        "3: User does not start with SYSTEM",
        "4: Image does not end with whoami.exe",
        "5: Image does not end with net.exe",
        "6: Image does not end with systeminfo.exe",
        "7: Image does not end with tasklist.exe",
    ];
    test_scenario(
        &mut vm,
        &rules,
        &primitive_results1,
        primitive_explanation1,
        "PowerShell with Invoke-Expression",
    )?;

    // Scenario 2: Reconnaissance tools
    let primitive_results2 = vec![
        true,  // EventID = 1
        false, // Image does not end with powershell.exe
        false, // CommandLine does not contain suspicious strings
        false, // User does not start with SYSTEM
        true,  // Image ends with whoami.exe
        false, // Image does not end with net.exe
        true,  // Image ends with systeminfo.exe
        false, // Image does not end with tasklist.exe
    ];
    let primitive_explanation2 = &[
        "0: EventID = 1",
        "1: Image does not end with powershell.exe",
        "2: CommandLine does not contain suspicious strings",
        "3: User does not start with SYSTEM",
        "4: Image ends with whoami.exe",
        "5: Image does not end with net.exe",
        "6: Image ends with systeminfo.exe",
        "7: Image does not end with tasklist.exe",
    ];
    test_scenario(
        &mut vm,
        &rules,
        &primitive_results2,
        primitive_explanation2,
        "Reconnaissance with whoami and systeminfo",
    )?;

    // Scenario 3: Single tool (should trigger rule 2 and rule 3)
    let primitive_results3 = vec![
        true,  // EventID = 1
        false, // Image does not end with powershell.exe
        false, // CommandLine does not contain suspicious strings
        false, // User does not start with SYSTEM
        true,  // Image ends with whoami.exe
        false, // Image does not end with net.exe
        false, // Image does not end with systeminfo.exe
        false, // Image does not end with tasklist.exe
    ];
    let primitive_explanation3 = &[
        "0: EventID = 1",
        "1: Image does not end with powershell.exe",
        "2: CommandLine does not contain suspicious strings",
        "3: User does not start with SYSTEM",
        "4: Image ends with whoami.exe",
        "5: Image does not end with net.exe",
        "6: Image does not end with systeminfo.exe",
        "7: Image does not end with tasklist.exe",
    ];
    test_scenario(
        &mut vm,
        &rules,
        &primitive_results3,
        primitive_explanation3,
        "Single reconnaissance tool",
    )?;

    // Performance measurement
    println!("\n⚡ Performance measurement...");
    let iterations = 100_000;
    let start_perf = Instant::now();

    for _ in 0..iterations {
        for (_, bytecode) in &rules {
            // Use results from scenario 1 for performance test
            vm.execute(bytecode, &primitive_results1)?;
        }
    }

    let perf_time = start_perf.elapsed();
    let total_executions = iterations * rules.len();
    let ns_per_execution = perf_time.as_nanos() / total_executions as u128;

    println!("📈 Performance Results:");
    println!("   • Total Executions: {}", total_executions);
    println!("   • Total Time: {:?}", perf_time);
    println!("   • Average Time per Rule: {} ns", ns_per_execution);
    println!(
        "   • Rules per Second: {:.0}",
        1_000_000_000.0 / ns_per_execution as f64
    );

    println!("\n🏁 Advanced example completed successfully!");
    println!("\n💡 Advanced Features Demonstrated:");
    println!("   • Field mapping and custom taxonomy");
    println!("   • Complex conditions with multiple selections");
    println!("   • Value modifiers (endswith, contains, startswith)");
    println!("   • Primitive deduplication across multiple rules");
    println!("   • Count-based conditions ('1 of them')");
    println!(
        "   • High-performance execution ({}ns per rule)",
        ns_per_execution
    );

    Ok(())
}

#[cfg(not(feature = "examples"))]
fn test_scenario(
    _vm: &mut sigma_engine::Vm<64>,
    _rules: &[(&str, &sigma_engine::BytecodeChunk)],
    _primitive_results: &[bool],
    _primitive_explanation: &[&str],
    _scenario_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    unreachable!("This function should not be called without the examples feature")
}

#[cfg(feature = "examples")]
fn test_scenario(
    vm: &mut sigma_engine::Vm<64>,
    rules: &[(&str, &sigma_engine::BytecodeChunk)],
    primitive_results: &[bool],
    primitive_explanation: &[&str],
    scenario_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📊 Scenario: {}", scenario_name);
    println!("   Primitive Results: {:?}", primitive_results);
    println!("   Primitive Mapping:");
    for explanation_line in primitive_explanation {
        println!("     {}", explanation_line);
    }

    let mut matches = Vec::new();
    for (rule_name, bytecode) in rules {
        if let Some(rule_id) = vm.execute(bytecode, primitive_results)? {
            matches.push((rule_name, rule_id));
        }
    }

    if matches.is_empty() {
        println!("   ❌ No rules matched");
    } else {
        println!("   🎉 Matches:");
        for (rule_name, rule_id) in matches {
            println!("      • {} (ID: {})", rule_name, rule_id);
        }
    }

    Ok(())
}
