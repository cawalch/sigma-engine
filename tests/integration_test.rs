//! Integration tests for the SIGMA Engine crate.
//!
//! These tests verify that the overall structure compiles and basic
//! functionality works as expected.

use sigma_engine::vm::DefaultVm;
use sigma_engine::{BytecodeChunk, Compiler, Opcode, Primitive};

#[test]
fn test_crate_structure_compiles() {
    // Test that we can create instances of the main types
    let _compiler = Compiler::new();
    let _vm = DefaultVm::new();

    // Test that we can create IR types
    let _primitive = Primitive::new_static("EventID", "equals", &["4624"], &[]);
    let _chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
}

#[test]
fn test_basic_vm_execution() {
    let mut vm = DefaultVm::new();

    // Create a simple bytecode chunk: push primitive 0, return rule 1
    let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);

    // Test with primitive result = true
    let primitive_results = [true];
    let result = vm.execute(&chunk, &primitive_results).unwrap();
    assert_eq!(result, Some(1));

    // Test with primitive result = false
    let primitive_results = [false];
    let result = vm.execute(&chunk, &primitive_results).unwrap();
    assert_eq!(result, None);
}

#[test]
fn test_compiler_placeholder() {
    let mut compiler = Compiler::new();

    // The compiler should return an error since it's not implemented yet
    let result = compiler.compile_rule("test rule");
    assert!(result.is_err());
}

#[test]
fn test_primitive_equality_and_hashing() {
    use std::collections::HashMap;

    let prim1 = Primitive::new_static("EventID", "equals", &["4624"], &[]);
    let prim2 = Primitive::new_static("EventID", "equals", &["4624"], &[]);
    let prim3 = Primitive::new_static("EventID", "equals", &["4625"], &[]);

    // Test equality
    assert_eq!(prim1, prim2);
    assert_ne!(prim1, prim3);

    // Test that they can be used as HashMap keys
    let mut map = HashMap::new();
    map.insert(prim1.clone(), 0);
    map.insert(prim3.clone(), 1);

    assert_eq!(map.get(&prim2), Some(&0)); // prim2 equals prim1
    assert_eq!(map.len(), 2);
}

#[test]
fn test_bytecode_chunk_stack_depth_calculation() {
    // Test simple expression: A
    let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
    assert_eq!(chunk.max_stack_depth, 1);

    // Test AND expression: A and B
    let chunk = BytecodeChunk::new(
        1,
        vec![
            Opcode::PushMatch(0),
            Opcode::PushMatch(1),
            Opcode::And,
            Opcode::ReturnMatch(1),
        ],
    );
    assert_eq!(chunk.max_stack_depth, 2);

    // Test complex expression: A and (B or C)
    let chunk = BytecodeChunk::new(
        1,
        vec![
            Opcode::PushMatch(0), // A
            Opcode::PushMatch(1), // B
            Opcode::PushMatch(2), // C
            Opcode::Or,           // B or C
            Opcode::And,          // A and (B or C)
            Opcode::ReturnMatch(1),
        ],
    );
    assert_eq!(chunk.max_stack_depth, 3);
}

#[test]
fn test_vm_with_different_stack_sizes() {
    // Test that we can create VMs with different stack sizes
    let mut vm_small = sigma_engine::vm::Vm::<4>::new();
    let mut vm_large = sigma_engine::vm::Vm::<128>::new();

    let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
    let primitive_results = [true];

    // Both should work for simple operations
    let result1 = vm_small.execute(&chunk, &primitive_results).unwrap();
    let result2 = vm_large.execute(&chunk, &primitive_results).unwrap();

    assert_eq!(result1, Some(1));
    assert_eq!(result2, Some(1));
}
