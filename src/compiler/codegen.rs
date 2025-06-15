//! Bytecode generation from SIGMA condition ASTs.
//!
//! This module provides functionality to generate efficient bytecode from
//! parsed SIGMA condition expressions for execution by the virtual machine.

use crate::error::{Result, SigmaError};
use crate::ir::{Opcode, PrimitiveId};
use std::collections::HashMap;

use super::parser::ConditionAst;

/// Generate bytecode from a SIGMA condition AST.
///
/// This function takes a parsed condition AST and generates a sequence of
/// opcodes that can be executed by the SIGMA BVM.
///
/// # Arguments
/// * `ast` - The parsed condition AST
/// * `selection_map` - Mapping from selection names to primitive IDs
///
/// # Returns
/// A vector of opcodes representing the condition logic.
///
/// # Examples
/// ```rust,ignore
/// use sigma_engine::compiler::codegen::generate_bytecode;
/// use sigma_engine::compiler::parser::ConditionAst;
/// use std::collections::HashMap;
///
/// let ast = ConditionAst::Identifier("selection".to_string());
/// let mut selection_map = HashMap::new();
/// selection_map.insert("selection".to_string(), vec![0]);
///
/// let opcodes = generate_bytecode(&ast, &selection_map)?;
/// ```
pub(crate) fn generate_bytecode(
    ast: &ConditionAst,
    selection_map: &HashMap<String, Vec<PrimitiveId>>,
) -> Result<Vec<Opcode>> {
    let mut opcodes = Vec::new();
    generate_bytecode_recursive(ast, selection_map, &mut opcodes)?;
    Ok(opcodes)
}

/// Recursively generate bytecode from an AST node.
///
/// This function implements the core bytecode generation logic, handling
/// all SIGMA condition constructs including basic boolean logic and
/// SIGMA-specific patterns like count expressions.
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

/// Generate bytecode for count-based patterns (e.g., "2 of selection*").
/// This implements counting logic using boolean combinations.
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
