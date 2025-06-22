//! Integration tests for the SIGMA Engine crate.
//!
//! These tests verify that the overall structure compiles and basic
//! functionality works as expected.

use sigma_engine::{Compiler, Primitive};

#[test]
fn test_crate_structure_compiles() {
    // Test that we can create instances of the main types
    let _compiler = Compiler::new();
    // DAG engine is available through SigmaEngine

    // Test that we can create IR types
    let _primitive = Primitive::new_static("EventID", "equals", &["4624"], &[]);
}

#[test]
fn test_basic_dag_execution() {
    // Test basic DAG functionality through SigmaEngine
    // Test that we can create a compiler
    let compiler = Compiler::new();
    let ruleset = compiler.into_ruleset();
    assert_eq!(ruleset.primitive_count(), 0);
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
fn test_compiler_basic_functionality() {
    let compiler = Compiler::new();
    let ruleset = compiler.into_ruleset();

    // Empty compiler should produce empty ruleset
    assert_eq!(ruleset.primitive_count(), 0);
}
