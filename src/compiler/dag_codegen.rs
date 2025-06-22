//! DAG generation from SIGMA condition ASTs.
//!
//! This module provides functionality to generate DAG nodes directly from
//! parsed SIGMA condition expressions, bypassing bytecode generation entirely.

use crate::dag::types::{DagNode, LogicalOp, NodeId, NodeType};
use crate::error::{Result, SigmaError};
use crate::ir::{PrimitiveId, RuleId};
use std::collections::HashMap;

use super::parser::ConditionAst;

/// Context for DAG generation from AST.
pub(crate) struct DagCodegenContext {
    /// Nodes being constructed
    nodes: Vec<DagNode>,
    /// Next available node ID
    next_node_id: NodeId,
    /// Mapping from primitive IDs to their DAG nodes
    primitive_nodes: HashMap<PrimitiveId, NodeId>,
    /// Current rule being compiled
    current_rule_id: RuleId,
}

impl DagCodegenContext {
    /// Create a new DAG codegen context.
    pub fn new(rule_id: RuleId) -> Self {
        Self {
            nodes: Vec::new(),
            next_node_id: 0,
            primitive_nodes: HashMap::new(),
            current_rule_id: rule_id,
        }
    }

    /// Create a new primitive node or reuse existing one.
    fn get_or_create_primitive_node(&mut self, primitive_id: PrimitiveId) -> NodeId {
        if let Some(&existing_node_id) = self.primitive_nodes.get(&primitive_id) {
            return existing_node_id;
        }

        let node_id = self.next_node_id;
        self.next_node_id += 1;

        let node = DagNode::new(node_id, NodeType::Primitive { primitive_id });
        self.nodes.push(node);
        self.primitive_nodes.insert(primitive_id, node_id);

        node_id
    }

    /// Create a new logical node.
    fn create_logical_node(&mut self, operation: LogicalOp) -> NodeId {
        let node_id = self.next_node_id;
        self.next_node_id += 1;

        let node = DagNode::new(node_id, NodeType::Logical { operation });
        self.nodes.push(node);

        node_id
    }

    /// Create a new result node.
    fn create_result_node(&mut self, rule_id: RuleId) -> NodeId {
        let node_id = self.next_node_id;
        self.next_node_id += 1;

        let node = DagNode::new(node_id, NodeType::Result { rule_id });
        self.nodes.push(node);

        node_id
    }

    /// Add a dependency relationship between nodes.
    fn add_dependency(&mut self, dependent_id: NodeId, dependency_id: NodeId) {
        // Add dependency to dependent node
        if let Some(dependent_node) = self.nodes.get_mut(dependent_id as usize) {
            dependent_node.add_dependency(dependency_id);
        }

        // Add dependent to dependency node
        if let Some(dependency_node) = self.nodes.get_mut(dependency_id as usize) {
            dependency_node.add_dependent(dependent_id);
        }
    }

    /// Generate DAG nodes from AST recursively.
    fn generate_dag_recursive(
        &mut self,
        ast: &ConditionAst,
        selection_map: &HashMap<String, Vec<PrimitiveId>>,
    ) -> Result<NodeId> {
        match ast {
            ConditionAst::Identifier(name) => {
                // Look up the selection in the selection map
                let primitive_ids = selection_map.get(name).ok_or_else(|| {
                    SigmaError::CompilationError(format!("Unknown selection: {}", name))
                })?;

                if primitive_ids.is_empty() {
                    return Err(SigmaError::CompilationError(format!(
                        "Empty selection: {}",
                        name
                    )));
                }

                if primitive_ids.len() == 1 {
                    // Single primitive - create or reuse primitive node
                    Ok(self.get_or_create_primitive_node(primitive_ids[0]))
                } else {
                    // Multiple primitives - create OR node for implicit OR behavior
                    let or_node = self.create_logical_node(LogicalOp::Or);
                    for &primitive_id in primitive_ids {
                        let primitive_node = self.get_or_create_primitive_node(primitive_id);
                        self.add_dependency(or_node, primitive_node);
                    }
                    Ok(or_node)
                }
            }
            ConditionAst::And(left, right) => {
                let left_node = self.generate_dag_recursive(left, selection_map)?;
                let right_node = self.generate_dag_recursive(right, selection_map)?;
                let and_node = self.create_logical_node(LogicalOp::And);
                self.add_dependency(and_node, left_node);
                self.add_dependency(and_node, right_node);
                Ok(and_node)
            }
            ConditionAst::Or(left, right) => {
                let left_node = self.generate_dag_recursive(left, selection_map)?;
                let right_node = self.generate_dag_recursive(right, selection_map)?;
                let or_node = self.create_logical_node(LogicalOp::Or);
                self.add_dependency(or_node, left_node);
                self.add_dependency(or_node, right_node);
                Ok(or_node)
            }
            ConditionAst::Not(operand) => {
                let operand_node = self.generate_dag_recursive(operand, selection_map)?;
                let not_node = self.create_logical_node(LogicalOp::Not);
                self.add_dependency(not_node, operand_node);
                Ok(not_node)
            }
            ConditionAst::OneOfThem => {
                // Create OR node for all primitives in all selections
                let or_node = self.create_logical_node(LogicalOp::Or);
                let mut has_primitives = false;

                for primitive_ids in selection_map.values() {
                    for &primitive_id in primitive_ids {
                        let primitive_node = self.get_or_create_primitive_node(primitive_id);
                        self.add_dependency(or_node, primitive_node);
                        has_primitives = true;
                    }
                }

                if !has_primitives {
                    return Err(SigmaError::CompilationError(
                        "No primitives found for 'one of them'".to_string(),
                    ));
                }

                Ok(or_node)
            }
            ConditionAst::AllOfThem => {
                // Create AND node for all primitives in all selections
                let and_node = self.create_logical_node(LogicalOp::And);
                let mut has_primitives = false;

                for primitive_ids in selection_map.values() {
                    for &primitive_id in primitive_ids {
                        let primitive_node = self.get_or_create_primitive_node(primitive_id);
                        self.add_dependency(and_node, primitive_node);
                        has_primitives = true;
                    }
                }

                if !has_primitives {
                    return Err(SigmaError::CompilationError(
                        "No primitives found for 'all of them'".to_string(),
                    ));
                }

                Ok(and_node)
            }
            ConditionAst::OneOfPattern(pattern) => {
                // Find selections matching the pattern and create OR node
                let or_node = self.create_logical_node(LogicalOp::Or);
                let mut has_matches = false;

                for (selection_name, primitive_ids) in selection_map {
                    if selection_name.contains(pattern) {
                        for &primitive_id in primitive_ids {
                            let primitive_node = self.get_or_create_primitive_node(primitive_id);
                            self.add_dependency(or_node, primitive_node);
                            has_matches = true;
                        }
                    }
                }

                if !has_matches {
                    return Err(SigmaError::CompilationError(format!(
                        "No selections found matching pattern: {}",
                        pattern
                    )));
                }

                Ok(or_node)
            }
            ConditionAst::AllOfPattern(pattern) => {
                // Find selections matching the pattern and create AND node
                let and_node = self.create_logical_node(LogicalOp::And);
                let mut has_matches = false;

                for (selection_name, primitive_ids) in selection_map {
                    if selection_name.contains(pattern) {
                        for &primitive_id in primitive_ids {
                            let primitive_node = self.get_or_create_primitive_node(primitive_id);
                            self.add_dependency(and_node, primitive_node);
                            has_matches = true;
                        }
                    }
                }

                if !has_matches {
                    return Err(SigmaError::CompilationError(format!(
                        "No selections found matching pattern: {}",
                        pattern
                    )));
                }

                Ok(and_node)
            }
            ConditionAst::CountOfPattern(_count, pattern) => {
                // For now, treat count patterns as "one of pattern"
                // TODO: Implement proper count logic
                let or_node = self.create_logical_node(LogicalOp::Or);
                let mut has_matches = false;

                for (selection_name, primitive_ids) in selection_map {
                    if selection_name.contains(pattern) {
                        for &primitive_id in primitive_ids {
                            let primitive_node = self.get_or_create_primitive_node(primitive_id);
                            self.add_dependency(or_node, primitive_node);
                            has_matches = true;
                        }
                    }
                }

                if !has_matches {
                    return Err(SigmaError::CompilationError(format!(
                        "No selections found matching pattern: {}",
                        pattern
                    )));
                }

                Ok(or_node)
            }
        }
    }

    /// Finalize DAG generation by creating result node.
    fn finalize(mut self, condition_root: NodeId) -> DagGenerationResult {
        // Create result node and connect it to the condition root
        let result_node = self.create_result_node(self.current_rule_id);
        self.add_dependency(result_node, condition_root);

        DagGenerationResult {
            nodes: self.nodes,
            primitive_nodes: self.primitive_nodes,
            result_node_id: result_node,
            rule_id: self.current_rule_id,
        }
    }
}

/// Result of DAG generation from AST.
pub(crate) struct DagGenerationResult {
    /// Generated DAG nodes
    pub nodes: Vec<DagNode>,
    /// Mapping from primitive IDs to their DAG nodes
    pub primitive_nodes: HashMap<PrimitiveId, NodeId>,
    /// ID of the result node for this rule
    pub result_node_id: NodeId,
    /// Rule ID
    pub rule_id: RuleId,
}

/// Generate DAG nodes from a SIGMA condition AST.
pub(crate) fn generate_dag_from_ast(
    ast: &ConditionAst,
    selection_map: &HashMap<String, Vec<PrimitiveId>>,
    rule_id: RuleId,
) -> Result<DagGenerationResult> {
    let mut context = DagCodegenContext::new(rule_id);
    let condition_root = context.generate_dag_recursive(ast, selection_map)?;
    Ok(context.finalize(condition_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::parser::ConditionAst;
    use std::collections::HashMap;

    fn create_test_selection_map() -> HashMap<String, Vec<PrimitiveId>> {
        let mut map = HashMap::new();
        map.insert("selection1".to_string(), vec![0, 1]);
        map.insert("selection2".to_string(), vec![2]);
        map.insert("web_selection".to_string(), vec![3, 4]);
        map.insert("network_selection".to_string(), vec![5]);
        map
    }

    #[test]
    fn test_dag_codegen_context_creation() {
        let context = DagCodegenContext::new(42);
        assert_eq!(context.current_rule_id, 42);
        assert_eq!(context.next_node_id, 0);
        assert!(context.nodes.is_empty());
        assert!(context.primitive_nodes.is_empty());
    }

    #[test]
    fn test_generate_dag_from_identifier_single_primitive() {
        let ast = ConditionAst::Identifier("selection2".to_string());
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1).unwrap();

        assert_eq!(result.rule_id, 1);
        assert_eq!(result.nodes.len(), 2); // primitive + result node
        assert_eq!(result.primitive_nodes.len(), 1);
        assert!(result.primitive_nodes.contains_key(&2));
    }

    #[test]
    fn test_generate_dag_from_identifier_multiple_primitives() {
        let ast = ConditionAst::Identifier("selection1".to_string());
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1).unwrap();

        assert_eq!(result.rule_id, 1);
        // Should have: 2 primitives + 1 OR node + 1 result node = 4 nodes
        assert_eq!(result.nodes.len(), 4);
        assert_eq!(result.primitive_nodes.len(), 2);
        assert!(result.primitive_nodes.contains_key(&0));
        assert!(result.primitive_nodes.contains_key(&1));
    }

    #[test]
    fn test_generate_dag_from_and_expression() {
        let ast = ConditionAst::And(
            Box::new(ConditionAst::Identifier("selection1".to_string())),
            Box::new(ConditionAst::Identifier("selection2".to_string())),
        );
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1).unwrap();

        assert_eq!(result.rule_id, 1);
        // Should have multiple nodes including AND logic
        assert!(result.nodes.len() > 4);

        // Check that we have the expected primitive nodes
        assert!(result.primitive_nodes.contains_key(&0));
        assert!(result.primitive_nodes.contains_key(&1));
        assert!(result.primitive_nodes.contains_key(&2));
    }

    #[test]
    fn test_generate_dag_from_or_expression() {
        let ast = ConditionAst::Or(
            Box::new(ConditionAst::Identifier("selection1".to_string())),
            Box::new(ConditionAst::Identifier("selection2".to_string())),
        );
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1).unwrap();

        assert_eq!(result.rule_id, 1);
        assert!(result.nodes.len() > 4);

        // Check that we have the expected primitive nodes
        assert!(result.primitive_nodes.contains_key(&0));
        assert!(result.primitive_nodes.contains_key(&1));
        assert!(result.primitive_nodes.contains_key(&2));
    }

    #[test]
    fn test_generate_dag_from_not_expression() {
        let ast = ConditionAst::Not(Box::new(ConditionAst::Identifier("selection2".to_string())));
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1).unwrap();

        assert_eq!(result.rule_id, 1);
        // Should have: primitive + NOT node + result node = 3 nodes
        assert_eq!(result.nodes.len(), 3);
        assert!(result.primitive_nodes.contains_key(&2));
    }

    #[test]
    fn test_generate_dag_from_one_of_them() {
        let ast = ConditionAst::OneOfThem;
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1).unwrap();

        assert_eq!(result.rule_id, 1);
        // Should include all primitives from all selections
        assert!(result.nodes.len() > 6);

        // Should have all primitive IDs
        for i in 0..=5 {
            assert!(result.primitive_nodes.contains_key(&i));
        }
    }

    #[test]
    fn test_generate_dag_from_all_of_them() {
        let ast = ConditionAst::AllOfThem;
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1).unwrap();

        assert_eq!(result.rule_id, 1);
        // Should include all primitives from all selections
        assert!(result.nodes.len() > 6);

        // Should have all primitive IDs
        for i in 0..=5 {
            assert!(result.primitive_nodes.contains_key(&i));
        }
    }

    #[test]
    fn test_generate_dag_from_one_of_pattern() {
        let ast = ConditionAst::OneOfPattern("web".to_string());
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1).unwrap();

        assert_eq!(result.rule_id, 1);
        // Should include primitives from web_selection
        assert!(result.primitive_nodes.contains_key(&3));
        assert!(result.primitive_nodes.contains_key(&4));

        // Should not include other primitives
        assert!(!result.primitive_nodes.contains_key(&0));
        assert!(!result.primitive_nodes.contains_key(&1));
        assert!(!result.primitive_nodes.contains_key(&2));
        assert!(!result.primitive_nodes.contains_key(&5));
    }

    #[test]
    fn test_generate_dag_from_all_of_pattern() {
        let ast = ConditionAst::AllOfPattern("selection".to_string());
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1).unwrap();

        assert_eq!(result.rule_id, 1);
        // Should include all primitives since all selections contain "selection"
        for i in 0..=5 {
            assert!(result.primitive_nodes.contains_key(&i));
        }
    }

    #[test]
    fn test_generate_dag_from_count_of_pattern() {
        let ast = ConditionAst::CountOfPattern(2, "selection".to_string());
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1).unwrap();

        assert_eq!(result.rule_id, 1);
        // For now, count patterns are treated as "one of pattern"
        // Should include all primitives since all selections contain "selection"
        for i in 0..=5 {
            assert!(result.primitive_nodes.contains_key(&i));
        }
    }

    #[test]
    fn test_generate_dag_unknown_selection_error() {
        let ast = ConditionAst::Identifier("unknown_selection".to_string());
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Unknown selection: unknown_selection"));
        } else {
            panic!("Expected CompilationError for unknown selection");
        }
    }

    #[test]
    fn test_generate_dag_empty_selection_error() {
        let ast = ConditionAst::Identifier("empty_selection".to_string());
        let mut selection_map = HashMap::new();
        selection_map.insert("empty_selection".to_string(), Vec::new());

        let result = generate_dag_from_ast(&ast, &selection_map, 1);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Empty selection: empty_selection"));
        } else {
            panic!("Expected CompilationError for empty selection");
        }
    }

    #[test]
    fn test_generate_dag_one_of_them_no_primitives_error() {
        let ast = ConditionAst::OneOfThem;
        let selection_map = HashMap::new();

        let result = generate_dag_from_ast(&ast, &selection_map, 1);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("No primitives found for 'one of them'"));
        } else {
            panic!("Expected CompilationError for no primitives");
        }
    }

    #[test]
    fn test_generate_dag_pattern_no_matches_error() {
        let ast = ConditionAst::OneOfPattern("nonexistent".to_string());
        let selection_map = create_test_selection_map();

        let result = generate_dag_from_ast(&ast, &selection_map, 1);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("No selections found matching pattern: nonexistent"));
        } else {
            panic!("Expected CompilationError for no pattern matches");
        }
    }
}
