//! Basic SIGMA Engine Usage Example
//!
//! This example demonstrates the fundamental usage of SIGMA Engine:
//! 1. Compiling a simple SIGMA rule
//! 2. Creating a VM
//! 3. Executing the rule with mock primitive results
//!
//! Run with: `cargo run --example basic_usage --features examples`

#[cfg(not(feature = "examples"))]
fn main() {
    eprintln!("This example requires the 'examples' feature to be enabled.");
    eprintln!("Run with: cargo run --example basic_usage --features examples");
    std::process::exit(1);
}

#[cfg(feature = "examples")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use sigma_engine::{Compiler, Vm};

    println!("🚀 SIGMA Engine Basic Usage Example");
    println!("===================================\n");

    println!("📝 Step 1: Creating compiler...");
    let mut compiler = Compiler::new();
    println!("✅ Compiler created\n");

    println!("📋 Step 2: Defining SIGMA rule...");
    let rule_yaml = r#"
title: Windows Login Event Detection
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects Windows login events
author: SIGMA Engine Example
date: 2025/06/15
logsource:
    category: authentication
    product: windows
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection
level: medium
"#;

    println!("Rule: Windows Login Event Detection");
    println!("- EventID: 4624 (Windows Logon)");
    println!("- LogonType: 2 (Interactive logon)\n");

    println!("⚙️  Step 3: Compiling rule to bytecode...");
    let bytecode = compiler.compile_rule(rule_yaml)?;

    println!("✅ Rule compiled successfully!");
    println!("   - Rule ID: {}", bytecode.rule_id);
    println!(
        "   - Rule Name: {}",
        bytecode.rule_name.as_deref().unwrap_or("Unknown")
    );
    println!("   - Bytecode Instructions: {}", bytecode.opcodes.len());
    println!("   - Max Stack Depth: {}", bytecode.max_stack_depth);
    println!("   - Primitives Discovered: {}", compiler.primitive_count());

    println!("\n🔍 Discovered Primitives:");
    for (i, primitive) in compiler.primitives().iter().enumerate() {
        println!(
            "   {}. Field: '{}', Match: '{}', Values: {:?}",
            i, primitive.field, primitive.match_type, primitive.values
        );
    }
    println!();

    println!("🖥️  Step 4: Creating virtual machine...");
    let mut vm = Vm::<64>::new();
    println!("✅ VM created (64-element stack)\n");

    println!("🎯 Step 5: Simulating event processing...");

    println!("\n📊 Scenario 1: Windows login event (should match)");
    let primitive_results_match = vec![
        true, // EventID = 4624 ✓
        true, // LogonType = 2 ✓
    ];

    println!("   Primitive Results: {:?}", primitive_results_match);
    match vm.execute(&bytecode, &primitive_results_match)? {
        Some(rule_id) => {
            println!("   🎉 MATCH! Rule {} triggered", rule_id);
            println!(
                "   📝 Rule: {}",
                bytecode.rule_name.as_deref().unwrap_or("Unknown")
            );
        }
        None => println!("   ❌ No match"),
    }

    println!("\n📊 Scenario 2: Different event (should not match)");
    let primitive_results_no_match = vec![
        false, // EventID ≠ 4624 ❌
        true,  // LogonType = 2 ✓
    ];

    println!("   Primitive Results: {:?}", primitive_results_no_match);
    match vm.execute(&bytecode, &primitive_results_no_match)? {
        Some(rule_id) => {
            println!("   🎉 MATCH! Rule {} triggered", rule_id);
        }
        None => println!("   ❌ No match (as expected)"),
    }

    println!("\n📊 Scenario 3: Wrong logon type (should not match)");
    let primitive_results_wrong_type = vec![
        true,  // EventID = 4624 ✓
        false, // LogonType ≠ 2 ❌
    ];

    println!("   Primitive Results: {:?}", primitive_results_wrong_type);
    match vm.execute(&bytecode, &primitive_results_wrong_type)? {
        Some(rule_id) => {
            println!("   🎉 MATCH! Rule {} triggered", rule_id);
        }
        None => println!("   ❌ No match (as expected)"),
    }

    println!("\n🏁 Example completed successfully!");
    println!("\n💡 Key Takeaways:");
    println!("   • SIGMA rules are compiled offline to efficient bytecode");
    println!("   • The VM executes bytecode with primitive match results");
    println!("   • Primitive matching is handled outside the VM");
    println!("   • The same bytecode can be executed multiple times");
    println!("   • Performance: ~4-10ns per rule execution");

    Ok(())
}
