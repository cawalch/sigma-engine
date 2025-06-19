//! Bytecode generation from SIGMA condition ASTs.
//!
//! This module provides functionality to generate efficient bytecode from
//! parsed SIGMA condition expressions for execution by the virtual machine.

use crate::error::{Result, SigmaError};
use crate::ir::{Opcode, PrimitiveId};
use std::collections::HashMap;

use super::parser::ConditionAst;

/// Generate bytecode from a SIGMA condition AST.
pub(crate) fn generate_bytecode(
    ast: &ConditionAst,
    selection_map: &HashMap<String, Vec<PrimitiveId>>,
) -> Result<Vec<Opcode>> {
    let mut opcodes = Vec::new();
    generate_bytecode_recursive(ast, selection_map, &mut opcodes)?;
    Ok(opcodes)
}

/// Recursively generate bytecode from an AST node.
fn generate_bytecode_recursive(
    ast: &ConditionAst,
    selection_map: &HashMap<String, Vec<PrimitiveId>>,
    opcodes: &mut Vec<Opcode>,
) -> Result<()> {
    match ast {
        ConditionAst::Identifier(name) => {
            if let Some(primitive_ids) = selection_map.get(name) {
                if primitive_ids.is_empty() {
                    return Err(SigmaError::CompilationError(format!(
                        "Selection '{}' has no primitives",
                        name
                    )));
                }

                for &primitive_id in primitive_ids {
                    opcodes.push(Opcode::PushMatch(primitive_id));
                }

                for _ in 1..primitive_ids.len() {
                    opcodes.push(Opcode::And);
                }
            } else {
                return Err(SigmaError::CompilationError(format!(
                    "Unknown selection identifier: {}",
                    name
                )));
            }
        }
        ConditionAst::And(left, right) => {
            generate_bytecode_recursive(left, selection_map, opcodes)?;
            generate_bytecode_recursive(right, selection_map, opcodes)?;
            opcodes.push(Opcode::And);
        }
        ConditionAst::Or(left, right) => {
            generate_bytecode_recursive(left, selection_map, opcodes)?;
            generate_bytecode_recursive(right, selection_map, opcodes)?;
            opcodes.push(Opcode::Or);
        }
        ConditionAst::Not(operand) => {
            generate_bytecode_recursive(operand, selection_map, opcodes)?;
            opcodes.push(Opcode::Not);
        }
        ConditionAst::OneOfThem => {
            generate_one_of_them_bytecode(selection_map, opcodes)?;
        }
        ConditionAst::AllOfThem => {
            generate_all_of_them_bytecode(selection_map, opcodes)?;
        }
        ConditionAst::OneOfPattern(pattern) | ConditionAst::AllOfPattern(pattern) => {
            generate_pattern_bytecode(ast, pattern, selection_map, opcodes)?;
        }
        ConditionAst::CountOfPattern(count, pattern) => {
            generate_count_pattern_bytecode(*count, pattern, selection_map, opcodes)?;
        }
    }
    Ok(())
}

fn generate_one_of_them_bytecode(
    selection_map: &HashMap<String, Vec<PrimitiveId>>,
    opcodes: &mut Vec<Opcode>,
) -> Result<()> {
    let mut selection_count = 0;
    for (selection_name, primitive_ids) in selection_map {
        if !selection_name.starts_with('_') && !primitive_ids.is_empty() {
            for &primitive_id in primitive_ids {
                opcodes.push(Opcode::PushMatch(primitive_id));
            }
            for _ in 1..primitive_ids.len() {
                opcodes.push(Opcode::And);
            }
            selection_count += 1;
        }
    }

    for _ in 1..selection_count {
        opcodes.push(Opcode::Or);
    }

    if selection_count == 0 {
        return Err(SigmaError::CompilationError(
            "No valid selections found for 'one of them'".to_string(),
        ));
    }

    Ok(())
}

fn generate_all_of_them_bytecode(
    selection_map: &HashMap<String, Vec<PrimitiveId>>,
    opcodes: &mut Vec<Opcode>,
) -> Result<()> {
    let mut selection_count = 0;
    for (selection_name, primitive_ids) in selection_map {
        if !selection_name.starts_with('_') && !primitive_ids.is_empty() {
            for &primitive_id in primitive_ids {
                opcodes.push(Opcode::PushMatch(primitive_id));
            }
            for _ in 1..primitive_ids.len() {
                opcodes.push(Opcode::And);
            }
            selection_count += 1;
        }
    }

    for _ in 1..selection_count {
        opcodes.push(Opcode::And);
    }

    if selection_count == 0 {
        return Err(SigmaError::CompilationError(
            "No valid selections found for 'all of them'".to_string(),
        ));
    }

    Ok(())
}

fn generate_pattern_bytecode(
    ast: &ConditionAst,
    pattern: &str,
    selection_map: &HashMap<String, Vec<PrimitiveId>>,
    opcodes: &mut Vec<Opcode>,
) -> Result<()> {
    let mut matching_selections = Vec::new();
    let pattern_prefix = pattern.trim_end_matches('*');

    for (selection_name, primitive_ids) in selection_map {
        if selection_name.starts_with(pattern_prefix) && !primitive_ids.is_empty() {
            matching_selections.push(primitive_ids);
        }
    }

    if matching_selections.is_empty() {
        return Err(SigmaError::CompilationError(format!(
            "No selections found matching pattern '{}'",
            pattern
        )));
    }

    for primitive_ids in &matching_selections {
        for &primitive_id in *primitive_ids {
            opcodes.push(Opcode::PushMatch(primitive_id));
        }
        for _ in 1..primitive_ids.len() {
            opcodes.push(Opcode::And);
        }
    }

    let combiner_op = match ast {
        ConditionAst::OneOfPattern(_) => Opcode::Or,
        ConditionAst::AllOfPattern(_) => Opcode::And,
        _ => unreachable!(),
    };

    for _ in 1..matching_selections.len() {
        opcodes.push(combiner_op.clone());
    }

    Ok(())
}

fn generate_count_pattern_bytecode(
    count: u32,
    pattern: &str,
    selection_map: &HashMap<String, Vec<PrimitiveId>>,
    opcodes: &mut Vec<Opcode>,
) -> Result<()> {
    let mut matching_selections = Vec::new();
    let pattern_prefix = pattern.trim_end_matches('*');

    for (selection_name, primitive_ids) in selection_map {
        if selection_name.starts_with(pattern_prefix) && !primitive_ids.is_empty() {
            matching_selections.push(primitive_ids);
        }
    }

    if matching_selections.is_empty() {
        return Err(SigmaError::CompilationError(format!(
            "No selections found matching pattern '{}'",
            pattern
        )));
    }

    generate_count_bytecode(&matching_selections, count, opcodes)
}

/// Generate bytecode for count-based patterns.
fn generate_count_bytecode(
    matching_selections: &[&Vec<PrimitiveId>],
    required_count: u32,
    opcodes: &mut Vec<Opcode>,
) -> Result<()> {
    let num_selections = matching_selections.len();
    let required_count = required_count as usize;

    if required_count == 0 {
        opcodes.push(Opcode::PushMatch(0));
        opcodes.push(Opcode::Not);
        opcodes.push(Opcode::And);
        return Ok(());
    }

    if required_count > num_selections {
        opcodes.push(Opcode::PushMatch(0));
        opcodes.push(Opcode::Not);
        opcodes.push(Opcode::And);
        return Ok(());
    }

    if required_count == 1 {
        for (i, primitive_ids) in matching_selections.iter().enumerate() {
            for &primitive_id in *primitive_ids {
                opcodes.push(Opcode::PushMatch(primitive_id));
            }
            for _ in 1..primitive_ids.len() {
                opcodes.push(Opcode::And);
            }

            if i > 0 {
                opcodes.push(Opcode::Or);
            }
        }
        return Ok(());
    }

    if required_count == num_selections {
        for (i, primitive_ids) in matching_selections.iter().enumerate() {
            for &primitive_id in *primitive_ids {
                opcodes.push(Opcode::PushMatch(primitive_id));
            }
            for _ in 1..primitive_ids.len() {
                opcodes.push(Opcode::And);
            }

            if i > 0 {
                opcodes.push(Opcode::And);
            }
        }
        return Ok(());
    }

    if num_selections <= 8 && required_count <= num_selections {
        generate_combination_bytecode(matching_selections, required_count, opcodes)?;
    } else {
        return Err(SigmaError::CompilationError(format!(
            "Count patterns with {} of {} selections are too complex for current implementation",
            required_count, num_selections
        )));
    }

    Ok(())
}

fn generate_combination_bytecode(
    matching_selections: &[&Vec<PrimitiveId>],
    required_count: usize,
    opcodes: &mut Vec<Opcode>,
) -> Result<()> {
    let num_selections = matching_selections.len();
    let mut combination_count = 0;

    let combinations = generate_combinations(num_selections, required_count);
    for combination in combinations {
        if combination_count > 0 {
            for (i, &selection_idx) in combination.iter().enumerate() {
                let primitive_ids = matching_selections[selection_idx];

                for &primitive_id in primitive_ids {
                    opcodes.push(Opcode::PushMatch(primitive_id));
                }
                for _ in 1..primitive_ids.len() {
                    opcodes.push(Opcode::And);
                }

                if i > 0 {
                    opcodes.push(Opcode::And);
                }
            }

            opcodes.push(Opcode::Or);
        } else {
            for (i, &selection_idx) in combination.iter().enumerate() {
                let primitive_ids = matching_selections[selection_idx];

                for &primitive_id in primitive_ids {
                    opcodes.push(Opcode::PushMatch(primitive_id));
                }
                for _ in 1..primitive_ids.len() {
                    opcodes.push(Opcode::And);
                }

                if i > 0 {
                    opcodes.push(Opcode::And);
                }
            }
        }

        combination_count += 1;
    }

    if combination_count == 0 {
        return Err(SigmaError::CompilationError(
            "No valid combinations found for count pattern".to_string(),
        ));
    }

    Ok(())
}

fn generate_combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    if k == 0 {
        return vec![vec![]];
    }
    if k > n {
        return vec![];
    }
    if k == n {
        return vec![(0..n).collect()];
    }

    let mut result = Vec::new();
    generate_combinations_recursive(n, k, 0, &mut vec![], &mut result);
    result
}

fn generate_combinations_recursive(
    n: usize,
    k: usize,
    start: usize,
    current: &mut Vec<usize>,
    result: &mut Vec<Vec<usize>>,
) {
    if current.len() == k {
        result.push(current.clone());
        return;
    }

    for i in start..n {
        current.push(i);
        generate_combinations_recursive(n, k, i + 1, current, result);
        current.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    fn create_test_selection_map() -> HashMap<String, Vec<PrimitiveId>> {
        let mut map = HashMap::new();
        map.insert("selection1".to_string(), vec![0]);
        map.insert("selection2".to_string(), vec![1]);
        map.insert("selection3".to_string(), vec![2]);
        map
    }

    fn create_empty_selection_map() -> HashMap<String, Vec<PrimitiveId>> {
        HashMap::new()
    }

    #[test]
    fn test_generate_bytecode_identifier() {
        let ast = ConditionAst::Identifier("selection1".to_string());
        let selection_map = create_test_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        assert_eq!(opcodes.len(), 1);
        assert!(matches!(opcodes[0], Opcode::PushMatch(0)));
    }

    #[test]
    fn test_generate_bytecode_identifier_unknown() {
        let ast = ConditionAst::Identifier("unknown_selection".to_string());
        let selection_map = create_test_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Unknown selection identifier"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_generate_bytecode_identifier_empty_primitives() {
        let ast = ConditionAst::Identifier("empty_selection".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("empty_selection".to_string(), vec![]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("has no primitives"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_generate_bytecode_identifier_multiple_primitives() {
        let ast = ConditionAst::Identifier("multi_selection".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("multi_selection".to_string(), vec![0, 1, 2]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Should have 3 PushMatch + 2 And operations
        assert_eq!(opcodes.len(), 5);
        assert!(matches!(opcodes[0], Opcode::PushMatch(0)));
        assert!(matches!(opcodes[1], Opcode::PushMatch(1)));
        assert!(matches!(opcodes[2], Opcode::PushMatch(2)));
        assert!(matches!(opcodes[3], Opcode::And));
        assert!(matches!(opcodes[4], Opcode::And));
    }

    #[test]
    fn test_generate_bytecode_and() {
        let left = ConditionAst::Identifier("selection1".to_string());
        let right = ConditionAst::Identifier("selection2".to_string());
        let ast = ConditionAst::And(Box::new(left), Box::new(right));
        let selection_map = create_test_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        assert_eq!(opcodes.len(), 3);
        assert!(matches!(opcodes[0], Opcode::PushMatch(0)));
        assert!(matches!(opcodes[1], Opcode::PushMatch(1)));
        assert!(matches!(opcodes[2], Opcode::And));
    }

    #[test]
    fn test_generate_bytecode_or() {
        let left = ConditionAst::Identifier("selection1".to_string());
        let right = ConditionAst::Identifier("selection2".to_string());
        let ast = ConditionAst::Or(Box::new(left), Box::new(right));
        let selection_map = create_test_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        assert_eq!(opcodes.len(), 3);
        assert!(matches!(opcodes[0], Opcode::PushMatch(0)));
        assert!(matches!(opcodes[1], Opcode::PushMatch(1)));
        assert!(matches!(opcodes[2], Opcode::Or));
    }

    #[test]
    fn test_generate_bytecode_not() {
        let operand = ConditionAst::Identifier("selection1".to_string());
        let ast = ConditionAst::Not(Box::new(operand));
        let selection_map = create_test_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        assert_eq!(opcodes.len(), 2);
        assert!(matches!(opcodes[0], Opcode::PushMatch(0)));
        assert!(matches!(opcodes[1], Opcode::Not));
    }

    #[test]
    fn test_generate_bytecode_one_of_them() {
        let ast = ConditionAst::OneOfThem;
        let selection_map = create_test_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Should have 3 PushMatch + 2 Or operations
        assert_eq!(opcodes.len(), 5);
        assert!(matches!(opcodes[0], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[1], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[2], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[3], Opcode::Or));
        assert!(matches!(opcodes[4], Opcode::Or));
    }

    #[test]
    fn test_generate_bytecode_one_of_them_empty() {
        let ast = ConditionAst::OneOfThem;
        let selection_map = create_empty_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("No valid selections found for 'one of them'"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_generate_bytecode_all_of_them() {
        let ast = ConditionAst::AllOfThem;
        let selection_map = create_test_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Should have 3 PushMatch + 2 And operations
        assert_eq!(opcodes.len(), 5);
        assert!(matches!(opcodes[0], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[1], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[2], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[3], Opcode::And));
        assert!(matches!(opcodes[4], Opcode::And));
    }

    #[test]
    fn test_generate_bytecode_all_of_them_empty() {
        let ast = ConditionAst::AllOfThem;
        let selection_map = create_empty_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("No valid selections found for 'all of them'"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_generate_bytecode_one_of_pattern() {
        let ast = ConditionAst::OneOfPattern("sel*".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("sel1".to_string(), vec![0]);
        selection_map.insert("sel2".to_string(), vec![1]);
        selection_map.insert("other".to_string(), vec![2]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Should have 2 PushMatch + 1 Or operation (sel1 and sel2 match pattern)
        assert_eq!(opcodes.len(), 3);
        assert!(matches!(opcodes[0], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[1], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[2], Opcode::Or));
    }

    #[test]
    fn test_generate_bytecode_all_of_pattern() {
        let ast = ConditionAst::AllOfPattern("sel*".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("sel1".to_string(), vec![0]);
        selection_map.insert("sel2".to_string(), vec![1]);
        selection_map.insert("other".to_string(), vec![2]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Should have 2 PushMatch + 1 And operation (sel1 and sel2 match pattern)
        assert_eq!(opcodes.len(), 3);
        assert!(matches!(opcodes[0], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[1], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[2], Opcode::And));
    }

    #[test]
    fn test_generate_bytecode_pattern_no_matches() {
        let ast = ConditionAst::OneOfPattern("nomatch*".to_string());
        let selection_map = create_test_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("No selections found matching pattern"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_generate_bytecode_count_of_pattern_zero() {
        let ast = ConditionAst::CountOfPattern(0, "sel*".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("sel1".to_string(), vec![0]);
        selection_map.insert("sel2".to_string(), vec![1]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Count of 0 should generate false condition
        assert_eq!(opcodes.len(), 3);
        assert!(matches!(opcodes[0], Opcode::PushMatch(0)));
        assert!(matches!(opcodes[1], Opcode::Not));
        assert!(matches!(opcodes[2], Opcode::And));
    }

    #[test]
    fn test_generate_bytecode_count_of_pattern_one() {
        let ast = ConditionAst::CountOfPattern(1, "sel*".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("sel1".to_string(), vec![0]);
        selection_map.insert("sel2".to_string(), vec![1]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Count of 1 should generate OR logic
        assert_eq!(opcodes.len(), 3);
        assert!(matches!(opcodes[0], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[1], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[2], Opcode::Or));
    }

    #[test]
    fn test_generate_bytecode_count_of_pattern_all() {
        let ast = ConditionAst::CountOfPattern(2, "sel*".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("sel1".to_string(), vec![0]);
        selection_map.insert("sel2".to_string(), vec![1]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Count equals total should generate AND logic
        assert_eq!(opcodes.len(), 3);
        assert!(matches!(opcodes[0], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[1], Opcode::PushMatch(_)));
        assert!(matches!(opcodes[2], Opcode::And));
    }

    #[test]
    fn test_generate_bytecode_count_of_pattern_impossible() {
        let ast = ConditionAst::CountOfPattern(5, "sel*".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("sel1".to_string(), vec![0]);
        selection_map.insert("sel2".to_string(), vec![1]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Impossible count should generate false condition
        assert_eq!(opcodes.len(), 3);
        assert!(matches!(opcodes[0], Opcode::PushMatch(0)));
        assert!(matches!(opcodes[1], Opcode::Not));
        assert!(matches!(opcodes[2], Opcode::And));
    }

    #[test]
    fn test_generate_bytecode_count_of_pattern_no_matches() {
        let ast = ConditionAst::CountOfPattern(1, "nomatch*".to_string());
        let selection_map = create_test_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("No selections found matching pattern"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_generate_bytecode_count_of_pattern_complex() {
        let ast = ConditionAst::CountOfPattern(2, "sel*".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("sel1".to_string(), vec![0]);
        selection_map.insert("sel2".to_string(), vec![1]);
        selection_map.insert("sel3".to_string(), vec![2]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Should generate combination logic for 2 of 3
        assert!(opcodes.len() > 3);
        assert!(opcodes.iter().any(|op| matches!(op, Opcode::PushMatch(_))));
        assert!(opcodes.iter().any(|op| matches!(op, Opcode::Or)));
    }

    #[test]
    fn test_generate_bytecode_count_too_complex() {
        let ast = ConditionAst::CountOfPattern(5, "sel*".to_string());
        let mut selection_map = HashMap::new();
        // Create 10 selections to exceed complexity limit
        for i in 0..10 {
            selection_map.insert(format!("sel{}", i), vec![i]);
        }

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("too complex for current implementation"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_generate_combinations_basic() {
        let combinations = generate_combinations(3, 2);
        assert_eq!(combinations.len(), 3);
        assert!(combinations.contains(&vec![0, 1]));
        assert!(combinations.contains(&vec![0, 2]));
        assert!(combinations.contains(&vec![1, 2]));
    }

    #[test]
    fn test_generate_combinations_edge_cases() {
        // k = 0
        let combinations = generate_combinations(3, 0);
        assert_eq!(combinations.len(), 1);
        assert_eq!(combinations[0], vec![] as Vec<usize>);

        // k > n
        let combinations = generate_combinations(2, 5);
        assert_eq!(combinations.len(), 0);

        // k = n
        let combinations = generate_combinations(3, 3);
        assert_eq!(combinations.len(), 1);
        assert_eq!(combinations[0], vec![0, 1, 2]);

        // n = 0
        let combinations = generate_combinations(0, 0);
        assert_eq!(combinations.len(), 1);
        assert_eq!(combinations[0], vec![] as Vec<usize>);
    }

    #[test]
    fn test_generate_combinations_single() {
        let combinations = generate_combinations(4, 1);
        assert_eq!(combinations.len(), 4);
        assert!(combinations.contains(&vec![0]));
        assert!(combinations.contains(&vec![1]));
        assert!(combinations.contains(&vec![2]));
        assert!(combinations.contains(&vec![3]));
    }

    #[test]
    fn test_pattern_matching_with_underscore_selections() {
        let ast = ConditionAst::OneOfThem;
        let mut selection_map = HashMap::new();
        selection_map.insert("_internal".to_string(), vec![0]);
        selection_map.insert("selection1".to_string(), vec![1]);
        selection_map.insert("_another_internal".to_string(), vec![2]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Should only include non-underscore selections
        assert_eq!(opcodes.len(), 1);
        assert!(matches!(opcodes[0], Opcode::PushMatch(1)));
    }

    #[test]
    fn test_pattern_matching_with_empty_primitive_lists() {
        let ast = ConditionAst::OneOfThem;
        let mut selection_map = HashMap::new();
        selection_map.insert("selection1".to_string(), vec![]);
        selection_map.insert("selection2".to_string(), vec![1]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Should only include selections with non-empty primitive lists
        assert_eq!(opcodes.len(), 1);
        assert!(matches!(opcodes[0], Opcode::PushMatch(1)));
    }

    #[test]
    fn test_complex_nested_expression() {
        // Test (selection1 and selection2) or not selection3
        let left = ConditionAst::And(
            Box::new(ConditionAst::Identifier("selection1".to_string())),
            Box::new(ConditionAst::Identifier("selection2".to_string())),
        );
        let right = ConditionAst::Not(Box::new(ConditionAst::Identifier("selection3".to_string())));
        let ast = ConditionAst::Or(Box::new(left), Box::new(right));
        let selection_map = create_test_selection_map();

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        assert_eq!(opcodes.len(), 6); // Fixed: should include the final Or
        assert!(matches!(opcodes[0], Opcode::PushMatch(0)));
        assert!(matches!(opcodes[1], Opcode::PushMatch(1)));
        assert!(matches!(opcodes[2], Opcode::And));
        assert!(matches!(opcodes[3], Opcode::PushMatch(2)));
        assert!(matches!(opcodes[4], Opcode::Not));
        assert!(matches!(opcodes[5], Opcode::Or));
    }

    #[test]
    fn test_pattern_with_multiple_primitives_per_selection() {
        let ast = ConditionAst::OneOfPattern("sel*".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("sel1".to_string(), vec![0, 1]);
        selection_map.insert("sel2".to_string(), vec![2, 3, 4]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // sel1: PushMatch(0), PushMatch(1), And
        // sel2: PushMatch(2), PushMatch(3), PushMatch(4), And, And
        // Final: Or
        assert_eq!(opcodes.len(), 9);
    }

    #[test]
    fn test_generate_combination_bytecode_no_combinations() {
        // Test the error case where no valid combinations are found
        // This is a bit tricky to trigger since generate_combinations should always
        // return at least one combination for valid inputs, but we can test the error path
        let matching_selections = vec![];
        let required_count = 1;
        let mut opcodes = Vec::new();

        // This should trigger the "No valid combinations found" error
        // by calling generate_combinations with empty selections
        let combinations = generate_combinations(0, 1);
        assert_eq!(combinations.len(), 0);

        // Test the actual error path in generate_combination_bytecode
        let result =
            generate_combination_bytecode(&matching_selections, required_count, &mut opcodes);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("No valid combinations found for count pattern"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_generate_combinations_edge_case_zero_selections() {
        // Test edge case with zero selections
        let combinations = generate_combinations(0, 0);
        assert_eq!(combinations.len(), 1);
        assert_eq!(combinations[0], vec![] as Vec<usize>);

        let combinations = generate_combinations(0, 1);
        assert_eq!(combinations.len(), 0);
    }

    #[test]
    fn test_count_pattern_with_complex_combinations() {
        // Test a more complex count pattern that exercises the combination logic
        let ast = ConditionAst::CountOfPattern(3, "sel*".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("sel1".to_string(), vec![0]);
        selection_map.insert("sel2".to_string(), vec![1]);
        selection_map.insert("sel3".to_string(), vec![2]);
        selection_map.insert("sel4".to_string(), vec![3]);
        selection_map.insert("sel5".to_string(), vec![4]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Should generate combinations for 3 of 5 selections
        // This should create multiple OR branches for different combinations
        assert!(opcodes.len() > 10); // Should be quite a few opcodes
        assert!(opcodes.iter().any(|op| matches!(op, Opcode::Or)));
        assert!(opcodes.iter().any(|op| matches!(op, Opcode::And)));
    }

    #[test]
    fn test_all_of_them_with_underscore_selections() {
        let ast = ConditionAst::AllOfThem;
        let mut selection_map = HashMap::new();
        selection_map.insert("_internal".to_string(), vec![0]);
        selection_map.insert("selection1".to_string(), vec![1]);
        selection_map.insert("_another".to_string(), vec![2]);
        selection_map.insert("selection2".to_string(), vec![3]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Should only include non-underscore selections (selection1 and selection2)
        assert_eq!(opcodes.len(), 3); // Two PushMatch operations and one And

        // Check that we have the right opcodes (order may vary due to HashMap)
        let push_matches: Vec<_> = opcodes
            .iter()
            .filter_map(|op| match op {
                Opcode::PushMatch(id) => Some(*id),
                _ => None,
            })
            .collect();

        assert_eq!(push_matches.len(), 2);
        assert!(push_matches.contains(&1)); // selection1
        assert!(push_matches.contains(&3)); // selection2
        assert!(matches!(opcodes.last(), Some(Opcode::And))); // Should end with And
    }

    #[test]
    fn test_one_of_them_with_empty_primitives() {
        let ast = ConditionAst::OneOfThem;
        let mut selection_map = HashMap::new();
        selection_map.insert("empty1".to_string(), vec![]);
        selection_map.insert("selection1".to_string(), vec![1]);
        selection_map.insert("empty2".to_string(), vec![]);

        let result = generate_bytecode(&ast, &selection_map);
        assert!(result.is_ok());

        let opcodes = result.unwrap();
        // Should only include selections with non-empty primitives
        assert_eq!(opcodes.len(), 1); // Only PushMatch(1)
        assert!(matches!(opcodes[0], Opcode::PushMatch(1)));
    }
}
