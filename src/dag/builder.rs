//! DAG builder for converting IR bytecode to optimized DAG representation.

use super::types::{CompiledDag, DagNode, NodeId, NodeType};
use crate::error::{Result, SigmaError};
use crate::ir::{CompiledRuleset, PrimitiveId, RuleId};
use std::collections::{HashMap, VecDeque};

/// Builder for constructing optimized DAGs from IR bytecode.
pub struct DagBuilder {
    /// Nodes being constructed
    nodes: Vec<DagNode>,

    /// Next available node ID
    next_node_id: NodeId,

    /// Mapping from primitive IDs to their DAG nodes
    primitive_nodes: HashMap<PrimitiveId, NodeId>,

    /// Mapping from rule IDs to their result nodes
    rule_result_nodes: HashMap<RuleId, NodeId>,

    /// Enable optimization passes
    enable_optimization: bool,
}

impl DagBuilder {
    /// Create a new DAG builder.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            next_node_id: 0,
            primitive_nodes: HashMap::new(),
            rule_result_nodes: HashMap::new(),

            enable_optimization: true,
        }
    }

    /// Enable or disable optimization passes.
    pub fn with_optimization(mut self, enable: bool) -> Self {
        self.enable_optimization = enable;
        self
    }

    /// Build DAG from a compiled ruleset.
    pub fn from_ruleset(mut self, ruleset: &CompiledRuleset) -> Self {
        // First pass: Create primitive nodes (shared across rules)
        for &primitive_id in ruleset.primitive_map.values() {
            let node_id = self.create_primitive_node(primitive_id);
            self.primitive_nodes.insert(primitive_id, node_id);
        }

        // Note: DAG nodes are now created directly from YAML compilation
        // No bytecode chunks to convert

        self
    }

    /// Enable optimization passes.
    pub fn optimize(mut self) -> Self {
        if self.enable_optimization {
            self.perform_optimizations();
        }
        self
    }

    /// Build the final compiled DAG.
    pub fn build(self) -> Result<CompiledDag> {
        // Perform topological sort for execution order
        let execution_order = self.topological_sort()?;

        // Validate the DAG structure
        self.validate_dag_structure()?;

        let dag = CompiledDag {
            nodes: self.nodes,
            execution_order,
            primitive_map: self.primitive_nodes,
            rule_results: self.rule_result_nodes,
            result_buffer_size: self.next_node_id as usize,
        };

        // Final validation
        dag.validate()?;

        Ok(dag)
    }

    /// Create a new primitive node.
    fn create_primitive_node(&mut self, primitive_id: PrimitiveId) -> NodeId {
        let node_id = self.next_node_id;
        self.next_node_id += 1;

        let node = DagNode::new(node_id, NodeType::Primitive { primitive_id });
        self.nodes.push(node);

        node_id
    }

    /// Perform optimization passes on the DAG.
    fn perform_optimizations(&mut self) {
        // Apply optimizations using the DagOptimizer
        if let Ok(dag) = self.build_temporary_dag() {
            if let Ok(optimized_dag) = self.apply_dag_optimizations(dag) {
                self.update_from_optimized_dag(optimized_dag);
            }
        }
    }

    /// Build a temporary DAG for optimization.
    fn build_temporary_dag(&self) -> Result<CompiledDag> {
        // Perform topological sort for execution order
        let execution_order = self.topological_sort()?;

        // Validate the DAG structure
        self.validate_dag_structure()?;

        Ok(CompiledDag {
            nodes: self.nodes.clone(),
            execution_order,
            primitive_map: self.primitive_nodes.clone(),
            rule_results: self.rule_result_nodes.clone(),
            result_buffer_size: self.next_node_id as usize,
        })
    }

    /// Apply DAG optimizations using the DagOptimizer.
    fn apply_dag_optimizations(&self, dag: CompiledDag) -> Result<CompiledDag> {
        use super::optimizer::DagOptimizer;

        let optimizer = DagOptimizer::new()
            .with_cse(true)
            .with_dce(true)
            .with_constant_folding(true);

        optimizer.optimize(dag)
    }

    /// Update builder state from optimized DAG.
    fn update_from_optimized_dag(&mut self, optimized_dag: CompiledDag) {
        self.nodes = optimized_dag.nodes;
        self.primitive_nodes = optimized_dag.primitive_map;
        self.rule_result_nodes = optimized_dag.rule_results;

        // Update next_node_id to be safe
        self.next_node_id = self.nodes.iter().map(|n| n.id).max().unwrap_or(0) + 1;
    }

    /// Perform topological sort to determine execution order.
    fn topological_sort(&self) -> Result<Vec<NodeId>> {
        let mut in_degree = vec![0; self.nodes.len()];
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        // Calculate in-degrees
        for node in &self.nodes {
            for &dep_id in &node.dependencies {
                if (dep_id as usize) < in_degree.len() {
                    in_degree[node.id as usize] += 1;
                }
            }
        }

        // Find nodes with no dependencies
        for (node_id, &degree) in in_degree.iter().enumerate() {
            if degree == 0 {
                queue.push_back(node_id as NodeId);
            }
        }

        // Process nodes in topological order
        while let Some(node_id) = queue.pop_front() {
            result.push(node_id);

            if let Some(node) = self.nodes.get(node_id as usize) {
                for &dependent_id in &node.dependents {
                    if (dependent_id as usize) < in_degree.len() {
                        in_degree[dependent_id as usize] -= 1;
                        if in_degree[dependent_id as usize] == 0 {
                            queue.push_back(dependent_id);
                        }
                    }
                }
            }
        }

        if result.len() != self.nodes.len() {
            return Err(SigmaError::CompilationError(
                "Cycle detected in DAG".to_string(),
            ));
        }

        Ok(result)
    }

    /// Validate the DAG structure for correctness.
    fn validate_dag_structure(&self) -> Result<()> {
        // Check that all rule result nodes exist
        for &rule_id in self.rule_result_nodes.keys() {
            if !self.rule_result_nodes.contains_key(&rule_id) {
                return Err(SigmaError::CompilationError(format!(
                    "Missing result node for rule: {}",
                    rule_id
                )));
            }
        }

        // Check that all dependencies are valid
        for node in &self.nodes {
            for &dep_id in &node.dependencies {
                if dep_id as usize >= self.nodes.len() {
                    return Err(SigmaError::CompilationError(format!(
                        "Invalid dependency: {} -> {}",
                        node.id, dep_id
                    )));
                }
            }
        }

        Ok(())
    }
}

impl Default for DagBuilder {
    fn default() -> Self {
        Self::new()
    }
}
