//! Integration tests for the SIGMA compiler.
//!
//! These tests verify that the compiler can correctly parse and compile
//! real SIGMA rules into bytecode.

use sigma_engine::{Compiler, Opcode};
use std::fs;

#[test]
fn test_compile_simple_rule() {
    let mut compiler = Compiler::new();

    // Load and compile a simple rule
    let rule_yaml =
        fs::read_to_string("tests/rules/simple_rule.yml").expect("Failed to read simple_rule.yml");

    let result = compiler.compile_rule(&rule_yaml);
    assert!(
        result.is_ok(),
        "Failed to compile simple rule: {:?}",
        result.err()
    );

    let chunk = result.unwrap();

    // Verify basic properties
    assert_eq!(
        chunk.rule_name,
        Some("Simple Login Event Detection".to_string())
    );
    assert!(!chunk.opcodes.is_empty());
    assert!(chunk.max_stack_depth > 0);

    // Verify the bytecode structure
    // Should have at least PushMatch and ReturnMatch opcodes
    let has_push_match = chunk
        .opcodes
        .iter()
        .any(|op| matches!(op, Opcode::PushMatch(_)));
    let has_return_match = chunk
        .opcodes
        .iter()
        .any(|op| matches!(op, Opcode::ReturnMatch(_)));

    assert!(has_push_match, "Bytecode should contain PushMatch opcode");
    assert!(
        has_return_match,
        "Bytecode should contain ReturnMatch opcode"
    );

    // Verify primitive discovery worked - simple rule has 2 fields (EventID and LogonType)
    assert_eq!(compiler.primitive_count(), 2);
}

#[test]
fn test_compile_complex_rule() {
    let mut compiler = Compiler::new();

    // Load and compile a complex rule
    let rule_yaml = fs::read_to_string("tests/rules/complex_rule.yml")
        .expect("Failed to read complex_rule.yml");

    let result = compiler.compile_rule(&rule_yaml);
    assert!(
        result.is_ok(),
        "Failed to compile complex rule: {:?}",
        result.err()
    );

    let chunk = result.unwrap();

    // Verify basic properties
    assert_eq!(
        chunk.rule_name,
        Some("Complex Process Creation Detection".to_string())
    );
    assert!(!chunk.opcodes.is_empty());
    assert!(chunk.max_stack_depth > 0);

    // Complex rules should discover primitives
    assert!(compiler.primitive_count() > 0);
}

#[test]
fn test_compile_rule_with_not() {
    let mut compiler = Compiler::new();

    // Load and compile a rule with NOT condition
    let rule_yaml =
        fs::read_to_string("tests/rules/with_not.yml").expect("Failed to read with_not.yml");

    let result = compiler.compile_rule(&rule_yaml);
    assert!(
        result.is_ok(),
        "Failed to compile rule with NOT: {:?}",
        result.err()
    );

    let chunk = result.unwrap();

    // Verify basic properties
    assert_eq!(chunk.rule_name, Some("Rule with NOT condition".to_string()));
    assert!(!chunk.opcodes.is_empty());
    assert!(chunk.max_stack_depth > 0);
}

#[test]
fn test_multiple_rules_primitive_deduplication() {
    let mut compiler = Compiler::new();

    // Compile multiple rules to test primitive deduplication
    let simple_rule =
        fs::read_to_string("tests/rules/simple_rule.yml").expect("Failed to read simple_rule.yml");
    let complex_rule = fs::read_to_string("tests/rules/complex_rule.yml")
        .expect("Failed to read complex_rule.yml");

    let _chunk1 = compiler.compile_rule(&simple_rule).unwrap();
    let initial_primitive_count = compiler.primitive_count();

    let _chunk2 = compiler.compile_rule(&complex_rule).unwrap();
    let final_primitive_count = compiler.primitive_count();

    // Should have discovered primitives from both rules
    assert!(final_primitive_count >= initial_primitive_count);

    // Create a compiled ruleset
    let chunks = vec![_chunk1, _chunk2];
    let ruleset = compiler.into_ruleset(chunks);

    assert_eq!(ruleset.chunks.len(), 2);
    assert!(ruleset.primitive_count() > 0);
}

#[test]
fn test_invalid_yaml_handling() {
    let mut compiler = Compiler::new();

    let invalid_yaml = "invalid: yaml: content: [unclosed";
    let result = compiler.compile_rule(invalid_yaml);

    assert!(result.is_err(), "Should fail on invalid YAML");
}
