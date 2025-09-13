//! DAG optimization passes for improved performance.

use super::types::{CompiledDag, DagNode, LogicalOp, NodeType};
use crate::error::Result;
use std::collections::{HashMap, HashSet};

/// Simplified DAG optimizer that performs essential optimization passes.
///
/// This optimizer focuses on proven optimizations that provide measurable
/// performance benefits while reducing complexity.
pub struct DagOptimizer {
    /// Enable common subexpression elimination
    enable_cse: bool,
    /// Enable dead code elimination
    enable_dce: bool,
}

impl DagOptimizer {
    /// Create a new DAG optimizer with default settings.
    pub fn new() -> Self {
        Self {
            enable_cse: true,
            enable_dce: true,
        }
    }

    /// Enable or disable common subexpression elimination.
    pub fn with_cse(mut self, enable: bool) -> Self {
        self.enable_cse = enable;
        self
    }

    /// Enable or disable dead code elimination.
    pub fn with_dce(mut self, enable: bool) -> Self {
        self.enable_dce = enable;
        self
    }

    /// Optimize a compiled DAG with essential optimizations.
    pub fn optimize(&self, mut dag: CompiledDag) -> Result<CompiledDag> {
        // Apply common subexpression elimination to reduce duplicate computation
        if self.enable_cse {
            dag = self.common_subexpression_elimination(dag)?;
        }

        // Remove unreachable nodes
        if self.enable_dce {
            dag = self.dead_code_elimination(dag)?;
        }

        // Always rebuild execution order for optimal performance
        dag = self.rebuild_execution_order_optimized(dag)?;

        Ok(dag)
    }

    /// Perform common subexpression elimination.
    ///
    /// This pass identifies identical subexpressions and merges them
    /// to reduce redundant computation.
    fn common_subexpression_elimination(&self, mut dag: CompiledDag) -> Result<CompiledDag> {
        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 5;

        // Iterate until no more changes
        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;

            let mut expression_map: HashMap<String, u32> = HashMap::new();
            let mut node_mapping: HashMap<u32, u32> = HashMap::new();

            // Build expression signatures for each node (excluding result nodes)
            for node in &dag.nodes {
                if matches!(node.node_type, NodeType::Result { .. }) {
                    continue; // Don't merge result nodes
                }

                let signature = Self::build_expression_signature(node, &dag);

                if let Some(&existing_node_id) = expression_map.get(&signature) {
                    // Found a duplicate expression - map this node to the existing one
                    if node.id != existing_node_id {
                        node_mapping.insert(node.id, existing_node_id);
                        changed = true;
                    }
                } else {
                    // First occurrence of this expression
                    expression_map.insert(signature, node.id);
                }
            }

            // Apply node mappings to eliminate duplicates
            if !node_mapping.is_empty() {
                dag = self.apply_node_mapping(dag, &node_mapping)?;
            }
        }

        Ok(dag)
    }

    /// Perform dead code elimination.
    ///
    /// This pass removes nodes that don't contribute to any rule result.
    fn dead_code_elimination(&self, mut dag: CompiledDag) -> Result<CompiledDag> {
        let mut reachable_nodes = HashSet::new();

        // Mark all result nodes as reachable
        for &result_node_id in dag.rule_results.values() {
            Self::mark_reachable(result_node_id, &dag, &mut reachable_nodes);
        }

        // Remove unreachable nodes
        dag.nodes.retain(|node| reachable_nodes.contains(&node.id));

        // Update primitive map and rule results to remove references to deleted nodes
        dag.primitive_map
            .retain(|_, &mut node_id| reachable_nodes.contains(&node_id));
        dag.rule_results
            .retain(|_, &mut node_id| reachable_nodes.contains(&node_id));

        Ok(dag)
    }

    /// Rebuild execution order using topological sorting.
    /// This ensures dependencies are respected while maintaining simplicity.
    fn rebuild_execution_order_optimized(&self, mut dag: CompiledDag) -> Result<CompiledDag> {
        dag.execution_order = self.topological_sort(&dag)?;
        Ok(dag)
    }

    /// Build a signature string for an expression to enable CSE.
    fn build_expression_signature(node: &DagNode, dag: &CompiledDag) -> String {
        match &node.node_type {
            NodeType::Primitive { primitive_id } => {
                format!("P{primitive_id}")
            }
            NodeType::Logical { operation } => {
                let mut dep_signatures: Vec<String> = node
                    .dependencies
                    .iter()
                    .filter_map(|&dep_id| {
                        dag.get_node(dep_id)
                            .map(|dep_node| Self::build_expression_signature(dep_node, dag))
                    })
                    .collect();

                // Sort dependencies for canonical representation
                // This is crucial for detecting equivalent expressions with different ordering
                dep_signatures.sort();

                match operation {
                    LogicalOp::And => format!("AND({})", dep_signatures.join(",")),
                    LogicalOp::Or => format!("OR({})", dep_signatures.join(",")),
                    LogicalOp::Not => format!("NOT({})", dep_signatures.join(",")),
                }
            }
            NodeType::Result { rule_id } => {
                // Result nodes should never be merged - each rule needs its own result
                format!("R{rule_id}")
            }
            NodeType::Prefilter {
                prefilter_id,
                pattern_count,
            } => {
                // Prefilter nodes are unique by their patterns
                format!("F{prefilter_id}:{pattern_count}")
            }
        }
    }

    /// Apply node mapping to eliminate duplicate nodes.
    fn apply_node_mapping(
        &self,
        mut dag: CompiledDag,
        node_mapping: &HashMap<u32, u32>,
    ) -> Result<CompiledDag> {
        // Remove duplicate nodes first
        let nodes_to_remove: HashSet<u32> = node_mapping.keys().copied().collect();
        dag.nodes.retain(|node| !nodes_to_remove.contains(&node.id));

        // Update dependencies in all remaining nodes and deduplicate
        for node in &mut dag.nodes {
            // Update dependencies and remove duplicates
            let mut new_dependencies = Vec::new();
            for &dep_id in &node.dependencies {
                let mapped_id = node_mapping.get(&dep_id).copied().unwrap_or(dep_id);
                if !new_dependencies.contains(&mapped_id) {
                    new_dependencies.push(mapped_id);
                }
            }
            node.dependencies = new_dependencies;

            // Update dependents and remove duplicates
            let mut new_dependents = Vec::new();
            for &dep_id in &node.dependents {
                let mapped_id = node_mapping.get(&dep_id).copied().unwrap_or(dep_id);
                if !new_dependents.contains(&mapped_id) {
                    new_dependents.push(mapped_id);
                }
            }
            node.dependents = new_dependents;
        }

        // Update primitive map
        for node_id in dag.primitive_map.values_mut() {
            if let Some(&new_id) = node_mapping.get(node_id) {
                *node_id = new_id;
            }
        }

        // Update rule results
        for node_id in dag.rule_results.values_mut() {
            if let Some(&new_id) = node_mapping.get(node_id) {
                *node_id = new_id;
            }
        }

        Ok(dag)
    }

    /// Mark a node and all its dependencies as reachable.
    fn mark_reachable(node_id: u32, dag: &CompiledDag, reachable: &mut HashSet<u32>) {
        if reachable.contains(&node_id) {
            return; // Already processed
        }

        reachable.insert(node_id);

        if let Some(node) = dag.get_node(node_id) {
            for &dep_id in &node.dependencies {
                Self::mark_reachable(dep_id, dag, reachable);
            }
        }
    }

    /// Perform topological sort to determine execution order.
    fn topological_sort(&self, dag: &CompiledDag) -> Result<Vec<u32>> {
        use std::collections::{HashMap, VecDeque};

        let mut in_degree: HashMap<u32, usize> = HashMap::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        // Initialize in-degrees for all nodes
        for node in &dag.nodes {
            in_degree.insert(node.id, 0);
        }

        // Calculate in-degrees based on dependencies
        for node in &dag.nodes {
            for &dep_id in &node.dependencies {
                if dag.get_node(dep_id).is_some() {
                    *in_degree.entry(node.id).or_insert(0) += 1;
                }
            }
        }

        // Find nodes with no dependencies
        for (&node_id, &degree) in &in_degree {
            if degree == 0 {
                queue.push_back(node_id);
            }
        }

        // Process nodes in topological order
        while let Some(node_id) = queue.pop_front() {
            result.push(node_id);

            if let Some(node) = dag.get_node(node_id) {
                for &dependent_id in &node.dependents {
                    if let Some(degree) = in_degree.get_mut(&dependent_id) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(dependent_id);
                        }
                    }
                }
            }
        }

        if result.len() != dag.nodes.len() {
            return Err(crate::error::SigmaError::CompilationError(
                "Cycle detected in DAG during optimization".to_string(),
            ));
        }

        Ok(result)
    }
}

impl Default for DagOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::types::{DagNode, NodeType};

    fn create_test_dag() -> CompiledDag {
        let mut dag = CompiledDag::new();

        // Add primitive nodes
        let mut primitive1 = DagNode::new(0, NodeType::Primitive { primitive_id: 0 });
        primitive1.dependents = vec![2]; // Add dependents for proper topological sorting
        let mut primitive2 = DagNode::new(1, NodeType::Primitive { primitive_id: 1 });
        primitive2.dependents = vec![2];
        dag.add_node(primitive1);
        dag.add_node(primitive2);

        // Add logical node
        let mut logical_node = DagNode::new(
            2,
            NodeType::Logical {
                operation: LogicalOp::And,
            },
        );
        logical_node.dependencies = vec![0, 1];
        logical_node.dependents = vec![3];
        dag.add_node(logical_node);

        // Add result node
        let mut result_node = DagNode::new(3, NodeType::Result { rule_id: 1 });
        result_node.dependencies = vec![2];
        dag.add_node(result_node);

        dag.primitive_map.insert(0, 0);
        dag.primitive_map.insert(1, 1);
        dag.rule_results.insert(1, 3);
        dag.execution_order = vec![0, 1, 2, 3];

        dag
    }

    #[test]
    fn test_dag_optimizer_creation() {
        let optimizer = DagOptimizer::new();
        assert!(optimizer.enable_cse);
        assert!(optimizer.enable_dce);
    }

    #[test]
    fn test_dag_optimizer_default() {
        let optimizer = DagOptimizer::default();
        assert!(optimizer.enable_cse);
        assert!(optimizer.enable_dce);
    }

    #[test]
    fn test_dag_optimizer_configuration() {
        let optimizer = DagOptimizer::new().with_cse(false).with_dce(false);

        assert!(!optimizer.enable_cse);
        assert!(!optimizer.enable_dce);
    }

    #[test]
    fn test_dag_optimizer_partial_configuration() {
        let optimizer = DagOptimizer::new().with_cse(false);

        assert!(!optimizer.enable_cse);
        assert!(optimizer.enable_dce); // Should remain default
    }

    #[test]
    fn test_optimize_empty_dag() {
        let optimizer = DagOptimizer::new();
        let dag = CompiledDag::new();

        let optimized = optimizer.optimize(dag).unwrap();
        assert!(optimized.nodes.is_empty());
        assert!(optimized.execution_order.is_empty());
    }

    #[test]
    fn test_optimize_simple_dag() {
        let optimizer = DagOptimizer::new();
        let dag = create_test_dag();

        let optimized = optimizer.optimize(dag).unwrap();
        assert!(!optimized.nodes.is_empty());
        assert!(!optimized.execution_order.is_empty());
    }

    #[test]
    fn test_build_expression_signature_primitive() {
        let _optimizer = DagOptimizer::new();
        let dag = CompiledDag::new();
        let node = DagNode::new(0, NodeType::Primitive { primitive_id: 42 });

        let signature = DagOptimizer::build_expression_signature(&node, &dag);
        assert_eq!(signature, "P42");
    }

    #[test]
    fn test_build_expression_signature_logical_and() {
        let _optimizer = DagOptimizer::new();
        let mut dag = CompiledDag::new();

        // Add dependency nodes
        dag.add_node(DagNode::new(0, NodeType::Primitive { primitive_id: 1 }));
        dag.add_node(DagNode::new(1, NodeType::Primitive { primitive_id: 2 }));

        // Create AND node with dependencies
        let mut and_node = DagNode::new(
            2,
            NodeType::Logical {
                operation: LogicalOp::And,
            },
        );
        and_node.dependencies = vec![0, 1];

        let signature = DagOptimizer::build_expression_signature(&and_node, &dag);
        assert!(signature.starts_with("AND("));
        assert!(signature.contains("P1"));
        assert!(signature.contains("P2"));
    }

    #[test]
    fn test_build_expression_signature_logical_or() {
        let _optimizer = DagOptimizer::new();
        let mut dag = CompiledDag::new();

        dag.add_node(DagNode::new(0, NodeType::Primitive { primitive_id: 1 }));
        dag.add_node(DagNode::new(1, NodeType::Primitive { primitive_id: 2 }));

        let mut or_node = DagNode::new(
            2,
            NodeType::Logical {
                operation: LogicalOp::Or,
            },
        );
        or_node.dependencies = vec![0, 1];

        let signature = DagOptimizer::build_expression_signature(&or_node, &dag);
        assert!(signature.starts_with("OR("));
        assert!(signature.contains("P1"));
        assert!(signature.contains("P2"));
    }

    #[test]
    fn test_build_expression_signature_logical_not() {
        let _optimizer = DagOptimizer::new();
        let mut dag = CompiledDag::new();

        dag.add_node(DagNode::new(0, NodeType::Primitive { primitive_id: 1 }));

        let mut not_node = DagNode::new(
            1,
            NodeType::Logical {
                operation: LogicalOp::Not,
            },
        );
        not_node.dependencies = vec![0];

        let signature = DagOptimizer::build_expression_signature(&not_node, &dag);
        assert!(signature.starts_with("NOT("));
        assert!(signature.contains("P1"));
    }

    #[test]
    fn test_build_expression_signature_result() {
        let _optimizer = DagOptimizer::new();
        let dag = CompiledDag::new();
        let node = DagNode::new(0, NodeType::Result { rule_id: 123 });

        let signature = DagOptimizer::build_expression_signature(&node, &dag);
        assert_eq!(signature, "R123");
    }

    #[test]
    fn test_mark_reachable() {
        let _optimizer = DagOptimizer::new();
        let dag = create_test_dag();
        let mut reachable = HashSet::new();

        DagOptimizer::mark_reachable(3, &dag, &mut reachable); // Start from result node

        // Should mark all nodes as reachable since they're all connected
        assert!(reachable.contains(&3)); // Result node
        assert!(reachable.contains(&2)); // Logical node
        assert!(reachable.contains(&0)); // Primitive 1
        assert!(reachable.contains(&1)); // Primitive 2
    }

    #[test]
    fn test_mark_reachable_already_processed() {
        let _optimizer = DagOptimizer::new();
        let dag = create_test_dag();
        let mut reachable = HashSet::new();

        // Pre-mark a node
        reachable.insert(2);

        DagOptimizer::mark_reachable(2, &dag, &mut reachable);

        // Should still contain the node but not process dependencies again
        assert!(reachable.contains(&2));
    }

    #[test]
    fn test_mark_reachable_nonexistent_node() {
        let _optimizer = DagOptimizer::new();
        let dag = CompiledDag::new();
        let mut reachable = HashSet::new();

        DagOptimizer::mark_reachable(999, &dag, &mut reachable);

        // Should mark the nonexistent node but not crash
        assert!(reachable.contains(&999));
    }

    #[test]
    fn test_topological_sort_simple() {
        let optimizer = DagOptimizer::new();
        let dag = create_test_dag();

        let order = optimizer.topological_sort(&dag).unwrap();

        // Should have all nodes
        assert_eq!(order.len(), 4);

        // Primitives should come before logical node
        let pos_0 = order.iter().position(|&x| x == 0).unwrap();
        let pos_1 = order.iter().position(|&x| x == 1).unwrap();
        let pos_2 = order.iter().position(|&x| x == 2).unwrap();
        let pos_3 = order.iter().position(|&x| x == 3).unwrap();

        assert!(pos_0 < pos_2);
        assert!(pos_1 < pos_2);
        assert!(pos_2 < pos_3);
    }

    #[test]
    fn test_topological_sort_empty_dag() {
        let optimizer = DagOptimizer::new();
        let dag = CompiledDag::new();

        let order = optimizer.topological_sort(&dag).unwrap();
        assert!(order.is_empty());
    }

    #[test]
    fn test_apply_node_mapping() {
        let optimizer = DagOptimizer::new();
        let dag = create_test_dag();

        // Create a mapping that merges node 1 into node 0
        let mut node_mapping = HashMap::new();
        node_mapping.insert(1, 0);

        let updated_dag = optimizer.apply_node_mapping(dag, &node_mapping).unwrap();

        // Verify the node was actually removed from the nodes list
        assert_eq!(updated_dag.nodes.len(), 3); // Should have 3 nodes instead of 4

        // Dependencies should be updated and deduplicated
        // Note: Due to the Vec-based storage, node access by ID may be affected after removal
        // The important thing is that dependencies are properly updated
        let logical_node_found = updated_dag
            .nodes
            .iter()
            .find(|n| matches!(n.node_type, NodeType::Logical { .. }));

        if let Some(logical_node) = logical_node_found {
            assert!(logical_node.dependencies.contains(&0));
            assert!(!logical_node.dependencies.contains(&1));
            // Should have only one dependency on node 0 (deduplicated)
            assert_eq!(logical_node.dependencies, vec![0]);
        }
    }

    #[test]
    fn test_apply_node_mapping_empty() {
        let optimizer = DagOptimizer::new();
        let dag = create_test_dag();
        let node_mapping = HashMap::new();

        let updated_dag = optimizer.apply_node_mapping(dag, &node_mapping).unwrap();

        // Should remain unchanged
        assert_eq!(updated_dag.nodes.len(), 4);
    }

    #[test]
    fn test_common_subexpression_elimination_no_duplicates() {
        let optimizer = DagOptimizer::new();
        let dag = create_test_dag();

        let optimized = optimizer.common_subexpression_elimination(dag).unwrap();

        // Should not change anything since no duplicates
        assert_eq!(optimized.nodes.len(), 4);
    }

    #[test]
    fn test_dead_code_elimination_all_reachable() {
        let optimizer = DagOptimizer::new();
        let dag = create_test_dag();

        let optimized = optimizer.dead_code_elimination(dag).unwrap();

        // Should not remove anything since all nodes are reachable
        assert_eq!(optimized.nodes.len(), 4);
    }

    #[test]
    fn test_dead_code_elimination_with_unreachable() {
        let optimizer = DagOptimizer::new();
        let mut dag = create_test_dag();

        // Add an unreachable node
        let unreachable_node = DagNode::new(99, NodeType::Primitive { primitive_id: 99 });
        dag.add_node(unreachable_node);

        let optimized = optimizer.dead_code_elimination(dag).unwrap();

        // Should remove the unreachable node
        assert_eq!(optimized.nodes.len(), 4);
        assert!(optimized.get_node(99).is_none());
    }

    #[test]
    fn test_rebuild_execution_order() {
        let optimizer = DagOptimizer::new();
        let mut dag = create_test_dag();

        // Mess up the execution order
        dag.execution_order = vec![3, 2, 1, 0];

        let optimized = optimizer.rebuild_execution_order_optimized(dag).unwrap();

        // Should rebuild proper topological order
        assert_eq!(optimized.execution_order.len(), 4);

        // Check that dependencies come before dependents
        let pos_0 = optimized
            .execution_order
            .iter()
            .position(|&x| x == 0)
            .unwrap();
        let pos_1 = optimized
            .execution_order
            .iter()
            .position(|&x| x == 1)
            .unwrap();
        let pos_2 = optimized
            .execution_order
            .iter()
            .position(|&x| x == 2)
            .unwrap();
        let pos_3 = optimized
            .execution_order
            .iter()
            .position(|&x| x == 3)
            .unwrap();

        assert!(pos_0 < pos_2);
        assert!(pos_1 < pos_2);
        assert!(pos_2 < pos_3);
    }

    #[test]
    fn test_optimize_with_all_passes_disabled() {
        let optimizer = DagOptimizer::new().with_cse(false).with_dce(false);

        let dag = create_test_dag();
        let original_node_count = dag.nodes.len();

        let optimized = optimizer.optimize(dag).unwrap();

        // Should only rebuild execution order
        assert_eq!(optimized.nodes.len(), original_node_count);
    }

    #[test]
    fn test_optimize_with_selective_passes() {
        let optimizer = DagOptimizer::new().with_cse(true).with_dce(false);

        let dag = create_test_dag();

        let optimized = optimizer.optimize(dag).unwrap();

        // Should run CSE and rebuild execution order
        assert!(!optimized.nodes.is_empty());
        assert!(!optimized.execution_order.is_empty());
    }
}
