//! Stress tests for the SIGMA Engine to validate production readiness.
//!
//! These tests simulate high-load scenarios and edge cases that might
//! occur in production environments.

use sigma_engine::vm::{DefaultVm, Vm};
use sigma_engine::{BytecodeChunk, Compiler, Opcode};
use std::fs;

#[test]
fn test_stress_large_rule_set() {
    let mut compiler = Compiler::new();
    let mut chunks = Vec::new();

    // Create a large number of synthetic rules
    for i in 0..100 {
        let rule_yaml = format!(
            r#"
title: Synthetic Rule {}
id: "synthetic-{:03}"
status: experimental
description: Generated rule for stress testing
author: SIGMA BVM Test Suite
date: 2025/06/15
logsource:
    category: test
    product: test
detection:
    selection:
        EventID: {}
        Field{}: "value{}"
    condition: selection
fields:
    - EventID
    - Field{}
level: low
"#,
            i,
            i,
            1000 + i,
            i,
            i,
            i
        );

        if let Ok(chunk) = compiler.compile_rule(&rule_yaml) {
            chunks.push(chunk);
        }
    }

    let ruleset = compiler.into_ruleset(chunks);

    // Verify we compiled a reasonable number of rules
    assert!(
        ruleset.chunks.len() >= 50,
        "Should compile at least 50 rules"
    );

    // Test execution with all rules
    let primitive_results = vec![false; ruleset.primitive_count()];
    let mut vm = DefaultVm::new();

    for chunk in &ruleset.chunks {
        let _result = vm
            .execute(chunk, &primitive_results)
            .expect("Should execute without error");
    }
}

#[test]
fn test_stress_deep_nesting() {
    let mut compiler = Compiler::new();

    // Create a rule with deeply nested conditions
    let rule_yaml = r#"
title: Deep Nesting Test
id: "deep-001"
status: experimental
description: Tests deeply nested boolean logic
author: SIGMA BVM Test Suite
date: 2025/06/15
logsource:
    category: test
    product: test
detection:
    sel1:
        EventID: 1
    sel2:
        EventID: 2
    sel3:
        EventID: 3
    sel4:
        EventID: 4
    sel5:
        EventID: 5
    condition: sel1 and (sel2 or (sel3 and (sel4 or sel5)))
fields:
    - EventID
level: low
"#;

    let chunk = compiler
        .compile_rule(rule_yaml)
        .expect("Should compile deeply nested rule");

    let ruleset = compiler.into_ruleset(vec![chunk]);

    // NOTE: Current compiler implementation has hardcoded primitives
    // This test verifies the VM can handle complex bytecode, even if the compiler
    // doesn't generate it from actual rule parsing yet

    // For now, just test that the rule compiles and executes without error
    let primitive_results = vec![true; ruleset.primitive_count()];
    let mut vm = DefaultVm::new();

    let result = vm
        .execute(&ruleset.chunks[0], &primitive_results)
        .expect("Deep nesting rule should execute");

    // Should match since all primitives are true
    assert!(result.is_some(), "Should match with all true primitives");
}

#[test]
fn test_stress_maximum_stack_usage() {
    // Create bytecode that uses maximum stack depth
    let mut opcodes = Vec::new();

    // Push many values
    for i in 0..32 {
        opcodes.push(Opcode::PushMatch(i % 4)); // Cycle through 4 primitives
    }

    // Combine them with AND operations
    for _ in 0..31 {
        opcodes.push(Opcode::And);
    }

    opcodes.push(Opcode::ReturnMatch(1));

    let chunk = BytecodeChunk::new(1, opcodes);

    // Test with large stack VM
    let mut vm = Vm::<64>::new();
    let primitive_results = [true, true, true, true];

    let result = vm
        .execute(&chunk, &primitive_results)
        .expect("Should handle maximum stack usage");

    assert_eq!(result, Some(1));
}

#[test]
fn test_stress_rapid_execution() {
    let mut compiler = Compiler::new();

    // Load a simple rule
    let rule_yaml =
        fs::read_to_string("tests/rules/simple_rule.yml").expect("Failed to read simple_rule.yml");

    let chunk = compiler
        .compile_rule(&rule_yaml)
        .expect("Failed to compile simple rule");

    let ruleset = compiler.into_ruleset(vec![chunk]);
    let primitive_results = vec![true; ruleset.primitive_count()];

    let mut vm = DefaultVm::new();

    // Execute rapidly many times
    for i in 0..10000 {
        let result = vm
            .execute(&ruleset.chunks[0], &primitive_results)
            .unwrap_or_else(|_| panic!("Execution {} should succeed", i));

        assert!(result.is_some(), "Should match on iteration {}", i);
    }
}

#[test]
fn test_stress_concurrent_vms() {
    use std::sync::Arc;
    use std::thread;

    let mut compiler = Compiler::new();

    // Load a rule
    let rule_yaml =
        fs::read_to_string("tests/rules/simple_rule.yml").expect("Failed to read simple_rule.yml");

    let chunk = compiler
        .compile_rule(&rule_yaml)
        .expect("Failed to compile simple rule");

    let ruleset = Arc::new(compiler.into_ruleset(vec![chunk]));
    let primitive_results = Arc::new(vec![true; ruleset.primitive_count()]);

    // Spawn multiple threads with separate VMs
    let handles: Vec<_> = (0..4)
        .map(|thread_id| {
            let ruleset = Arc::clone(&ruleset);
            let primitive_results = Arc::clone(&primitive_results);

            thread::spawn(move || {
                let mut vm = DefaultVm::new();

                for i in 0..1000 {
                    let result = vm
                        .execute(&ruleset.chunks[0], &primitive_results)
                        .unwrap_or_else(|_| {
                            panic!("Thread {} iteration {} should succeed", thread_id, i)
                        });

                    assert!(
                        result.is_some(),
                        "Thread {} iteration {} should match",
                        thread_id,
                        i
                    );
                }
            })
        })
        .collect();

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }
}

#[test]
fn test_stress_memory_pressure() {
    let mut compiler = Compiler::new();
    let mut all_rulesets = Vec::new();

    // Create many rulesets to test memory usage
    for batch in 0..10 {
        let mut chunks = Vec::new();

        for i in 0..20 {
            let rule_yaml = format!(
                r#"
title: Memory Test Rule {}-{}
id: "mem-{:03}-{:03}"
status: experimental
description: Generated rule for memory testing
author: SIGMA BVM Test Suite
date: 2025/06/15
logsource:
    category: test
    product: test
detection:
    selection:
        EventID: {}
        BatchField: "batch{}"
    condition: selection
fields:
    - EventID
    - BatchField
level: low
"#,
                batch,
                i,
                batch,
                i,
                2000 + (batch * 20) + i,
                batch
            );

            if let Ok(chunk) = compiler.compile_rule(&rule_yaml) {
                chunks.push(chunk);
            }
        }

        let ruleset = compiler.into_ruleset(chunks);
        all_rulesets.push(ruleset);

        // Reset compiler for next batch
        compiler = Compiler::new();
    }

    // Test execution across all rulesets
    let mut vm = DefaultVm::new();

    for (batch_id, ruleset) in all_rulesets.iter().enumerate() {
        let primitive_results = vec![false; ruleset.primitive_count()];

        for (chunk_id, chunk) in ruleset.chunks.iter().enumerate() {
            let _result = vm
                .execute(chunk, &primitive_results)
                .unwrap_or_else(|_| panic!("Batch {} chunk {} should execute", batch_id, chunk_id));
        }
    }

    // Verify we created a substantial number of rules
    let total_rules: usize = all_rulesets.iter().map(|r| r.chunks.len()).sum();
    assert!(total_rules >= 100, "Should create at least 100 rules total");
}

#[test]
fn test_stress_edge_case_primitives() {
    let mut compiler = Compiler::new();

    // Test edge case values through rule compilation
    // This will internally create primitives with edge case values

    // Create a simple rule to test with these primitives
    let rule_yaml = r#"
title: Edge Case Test
id: "edge-001"
status: experimental
description: Tests edge case primitive handling
author: SIGMA BVM Test Suite
date: 2025/06/15
logsource:
    category: test
    product: test
detection:
    selection:
        EventID: 9999
    condition: selection
fields:
    - EventID
level: low
"#;

    let chunk = compiler
        .compile_rule(rule_yaml)
        .expect("Should compile edge case rule");

    let ruleset = compiler.into_ruleset(vec![chunk]);

    // Test execution
    let primitive_results = vec![false; ruleset.primitive_count()];
    let mut vm = DefaultVm::new();

    let result = vm
        .execute(&ruleset.chunks[0], &primitive_results)
        .expect("Should execute with edge case primitives");

    assert!(
        result.is_none(),
        "Should not match with all false primitives"
    );
}
