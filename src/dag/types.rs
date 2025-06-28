//! Core DAG types and data structures.

use crate::error::{Result, SigmaError};
use crate::ir::{PrimitiveId, RuleId};
use std::collections::HashMap;

/// Unique identifier for DAG nodes.
pub type NodeId = u32;

/// Logical operations supported in DAG nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogicalOp {
    And,
    Or,
    Not,
}

/// Types of nodes in the DAG execution graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeType {
    /// Leaf node that evaluates a primitive field matching operation.
    Primitive { primitive_id: PrimitiveId },

    /// Internal node that performs logical operations on child node results.
    Logical { operation: LogicalOp },

    /// Terminal node that aggregates results for a specific rule.
    Result { rule_id: RuleId },

    /// Prefilter node that uses AhoCorasick to quickly eliminate non-matching events.
    /// This node is evaluated first and can short-circuit entire rule evaluation.
    Prefilter {
        /// Unique identifier for this prefilter
        prefilter_id: u32,
        /// Number of patterns in the AhoCorasick automaton
        pattern_count: usize,
    },
}

/// A node in the DAG execution graph.
#[derive(Debug, Clone)]
pub struct DagNode {
    /// Unique identifier for this node
    pub id: NodeId,

    /// The type and operation of this node
    pub node_type: NodeType,

    /// Nodes that must be evaluated before this node (inputs)
    pub dependencies: Vec<NodeId>,

    /// Nodes that depend on this node's result (outputs)
    pub dependents: Vec<NodeId>,

    /// Cached evaluation result (None if not yet evaluated)
    pub cached_result: Option<bool>,
}

impl DagNode {
    /// Create a new DAG node.
    pub fn new(id: NodeId, node_type: NodeType) -> Self {
        Self {
            id,
            node_type,
            dependencies: Vec::new(),
            dependents: Vec::new(),
            cached_result: None,
        }
    }

    /// Add a dependency to this node.
    pub fn add_dependency(&mut self, dependency_id: NodeId) {
        if !self.dependencies.contains(&dependency_id) {
            self.dependencies.push(dependency_id);
        }
    }

    /// Add a dependent to this node.
    pub fn add_dependent(&mut self, dependent_id: NodeId) {
        if !self.dependents.contains(&dependent_id) {
            self.dependents.push(dependent_id);
        }
    }

    /// Clear cached result.
    pub fn clear_cache(&mut self) {
        self.cached_result = None;
    }

    /// Check if this node is a leaf node (no dependencies).
    pub fn is_leaf(&self) -> bool {
        self.dependencies.is_empty()
    }

    /// Check if this node is a root node (no dependents).
    pub fn is_root(&self) -> bool {
        self.dependents.is_empty()
    }
}

/// Compiled DAG optimized for high-performance execution.
#[derive(Debug, Clone)]
pub struct CompiledDag {
    /// All nodes in the DAG, indexed by NodeId
    pub nodes: Vec<DagNode>,

    /// Topologically sorted execution order for optimal cache performance
    pub execution_order: Vec<NodeId>,

    /// Mapping from primitive IDs to their corresponding DAG nodes
    pub primitive_map: HashMap<PrimitiveId, NodeId>,

    /// Mapping from rule IDs to their result nodes
    pub rule_results: HashMap<RuleId, NodeId>,

    /// Size of result buffer needed for evaluation
    pub result_buffer_size: usize,
}

impl CompiledDag {
    /// Create a new empty compiled DAG.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            execution_order: Vec::new(),
            primitive_map: HashMap::new(),
            rule_results: HashMap::new(),
            result_buffer_size: 0,
        }
    }

    /// Get a node by its ID.
    pub fn get_node(&self, node_id: NodeId) -> Option<&DagNode> {
        self.nodes.get(node_id as usize)
    }

    /// Get a mutable reference to a node by its ID.
    pub fn get_node_mut(&mut self, node_id: NodeId) -> Option<&mut DagNode> {
        self.nodes.get_mut(node_id as usize)
    }

    /// Add a node to the DAG.
    pub fn add_node(&mut self, node: DagNode) -> NodeId {
        let node_id = node.id;
        self.nodes.push(node);
        self.result_buffer_size = self.nodes.len();
        node_id
    }

    /// Get the number of nodes in the DAG.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Validate the DAG structure for correctness.
    pub fn validate(&self) -> Result<()> {
        // Check that execution order contains all nodes
        if self.execution_order.len() != self.nodes.len() {
            return Err(SigmaError::CompilationError(
                "Execution order length mismatch".to_string(),
            ));
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

        // Check that all rule result nodes exist
        for &result_node_id in self.rule_results.values() {
            if result_node_id as usize >= self.nodes.len() {
                return Err(SigmaError::CompilationError(format!(
                    "Invalid result node: {result_node_id}"
                )));
            }
        }

        Ok(())
    }

    /// Clear all cached results in the DAG.
    pub fn clear_cache(&mut self) {
        for node in &mut self.nodes {
            node.clear_cache();
        }
    }

    /// Get statistics about the DAG structure.
    pub fn statistics(&self) -> DagStatistics {
        DagStatistics::from_dag(self)
    }
}

impl Default for CompiledDag {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about DAG structure and optimization opportunities.
#[derive(Debug, Clone)]
pub struct DagStatistics {
    /// Total number of nodes
    pub total_nodes: usize,

    /// Number of primitive nodes
    pub primitive_nodes: usize,

    /// Number of logical nodes
    pub logical_nodes: usize,

    /// Number of result nodes
    pub result_nodes: usize,

    /// Maximum depth of the DAG
    pub max_depth: usize,

    /// Average fan-out (dependencies per node)
    pub avg_fanout: f64,

    /// Number of shared primitives (used by multiple rules)
    pub shared_primitives: usize,

    /// Estimated memory usage in bytes
    pub estimated_memory_bytes: usize,
}

impl DagStatistics {
    /// Create statistics from a compiled DAG.
    pub fn from_dag(dag: &CompiledDag) -> Self {
        let mut primitive_nodes = 0;
        let mut logical_nodes = 0;
        let mut result_nodes = 0;
        let mut total_dependencies = 0;

        for node in &dag.nodes {
            match &node.node_type {
                NodeType::Primitive { .. } => primitive_nodes += 1,
                NodeType::Logical { .. } => logical_nodes += 1,
                NodeType::Result { .. } => result_nodes += 1,
                NodeType::Prefilter { .. } => {
                    // Count prefilter as a special type of primitive
                    primitive_nodes += 1;
                }
            }
            total_dependencies += node.dependencies.len();
        }

        let avg_fanout = if dag.nodes.is_empty() {
            0.0
        } else {
            total_dependencies as f64 / dag.nodes.len() as f64
        };

        // Calculate maximum depth
        let max_depth = Self::calculate_max_depth(dag);

        // Calculate shared primitives
        let shared_primitives = Self::calculate_shared_primitives(dag);

        // Estimate memory usage (rough calculation)
        let estimated_memory_bytes = dag.nodes.len() * std::mem::size_of::<DagNode>()
            + dag.execution_order.len() * std::mem::size_of::<NodeId>()
            + dag.primitive_map.len()
                * (std::mem::size_of::<PrimitiveId>() + std::mem::size_of::<NodeId>())
            + dag.rule_results.len()
                * (std::mem::size_of::<RuleId>() + std::mem::size_of::<NodeId>());

        Self {
            total_nodes: dag.nodes.len(),
            primitive_nodes,
            logical_nodes,
            result_nodes,
            max_depth,
            avg_fanout,
            shared_primitives,
            estimated_memory_bytes,
        }
    }

    /// Calculate the maximum depth of the DAG.
    fn calculate_max_depth(dag: &CompiledDag) -> usize {
        use std::collections::HashMap;

        if dag.nodes.is_empty() {
            return 0;
        }

        let mut depths: HashMap<NodeId, usize> = HashMap::new();
        let mut max_depth = 0;

        // Calculate depth for each node in execution order
        for &node_id in &dag.execution_order {
            if let Some(node) = dag.get_node(node_id) {
                let node_depth = if node.dependencies.is_empty() {
                    1 // Leaf nodes have depth 1
                } else {
                    // Depth is 1 + max depth of dependencies
                    node.dependencies
                        .iter()
                        .map(|&dep_id| depths.get(&dep_id).copied().unwrap_or(0))
                        .max()
                        .unwrap_or(0)
                        + 1
                };
                depths.insert(node_id, node_depth);
                max_depth = max_depth.max(node_depth);
            }
        }

        max_depth
    }

    /// Calculate the number of shared primitives.
    fn calculate_shared_primitives(dag: &CompiledDag) -> usize {
        use std::collections::HashMap;

        let mut primitive_usage: HashMap<PrimitiveId, usize> = HashMap::new();

        // Count how many times each primitive is used
        for node in &dag.nodes {
            if let NodeType::Primitive { primitive_id } = &node.node_type {
                *primitive_usage.entry(*primitive_id).or_insert(0) += 1;
            }
        }

        // Count primitives used more than once
        primitive_usage.values().filter(|&&count| count > 1).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_dag() -> CompiledDag {
        let mut dag = CompiledDag::new();

        // Add primitive nodes
        let mut primitive1 = DagNode::new(0, NodeType::Primitive { primitive_id: 0 });
        primitive1.add_dependent(2);
        let mut primitive2 = DagNode::new(1, NodeType::Primitive { primitive_id: 1 });
        primitive2.add_dependent(2);
        dag.add_node(primitive1);
        dag.add_node(primitive2);

        // Add logical node
        let mut logical_node = DagNode::new(
            2,
            NodeType::Logical {
                operation: LogicalOp::And,
            },
        );
        logical_node.add_dependency(0);
        logical_node.add_dependency(1);
        logical_node.add_dependent(3);
        dag.add_node(logical_node);

        // Add result node
        let mut result_node = DagNode::new(3, NodeType::Result { rule_id: 1 });
        result_node.add_dependency(2);
        dag.add_node(result_node);

        dag.primitive_map.insert(0, 0);
        dag.primitive_map.insert(1, 1);
        dag.rule_results.insert(1, 3);
        dag.execution_order = vec![0, 1, 2, 3];

        dag
    }

    #[test]
    fn test_logical_op_equality() {
        assert_eq!(LogicalOp::And, LogicalOp::And);
        assert_eq!(LogicalOp::Or, LogicalOp::Or);
        assert_eq!(LogicalOp::Not, LogicalOp::Not);
        assert_ne!(LogicalOp::And, LogicalOp::Or);
        assert_ne!(LogicalOp::Or, LogicalOp::Not);
        assert_ne!(LogicalOp::And, LogicalOp::Not);
    }

    #[test]
    fn test_logical_op_debug() {
        assert_eq!(format!("{:?}", LogicalOp::And), "And");
        assert_eq!(format!("{:?}", LogicalOp::Or), "Or");
        assert_eq!(format!("{:?}", LogicalOp::Not), "Not");
    }

    #[test]
    fn test_logical_op_clone() {
        let op = LogicalOp::And;
        let cloned = op; // LogicalOp implements Copy, so no need to clone
        assert_eq!(op, cloned);
    }

    #[test]
    fn test_node_type_equality() {
        let primitive1 = NodeType::Primitive { primitive_id: 1 };
        let primitive2 = NodeType::Primitive { primitive_id: 1 };
        let primitive3 = NodeType::Primitive { primitive_id: 2 };

        assert_eq!(primitive1, primitive2);
        assert_ne!(primitive1, primitive3);

        let logical1 = NodeType::Logical {
            operation: LogicalOp::And,
        };
        let logical2 = NodeType::Logical {
            operation: LogicalOp::And,
        };
        let logical3 = NodeType::Logical {
            operation: LogicalOp::Or,
        };

        assert_eq!(logical1, logical2);
        assert_ne!(logical1, logical3);

        let result1 = NodeType::Result { rule_id: 1 };
        let result2 = NodeType::Result { rule_id: 1 };
        let result3 = NodeType::Result { rule_id: 2 };

        assert_eq!(result1, result2);
        assert_ne!(result1, result3);

        assert_ne!(primitive1, logical1);
        assert_ne!(logical1, result1);
        assert_ne!(primitive1, result1);

        let prefilter1 = NodeType::Prefilter {
            prefilter_id: 1,
            pattern_count: 5,
        };
        let prefilter2 = NodeType::Prefilter {
            prefilter_id: 1,
            pattern_count: 5,
        };
        let prefilter3 = NodeType::Prefilter {
            prefilter_id: 2,
            pattern_count: 5,
        };

        assert_eq!(prefilter1, prefilter2);
        assert_ne!(prefilter1, prefilter3);
        assert_ne!(prefilter1, primitive1);
    }

    #[test]
    fn test_node_type_debug() {
        let primitive = NodeType::Primitive { primitive_id: 42 };
        let debug_str = format!("{primitive:?}");
        assert!(debug_str.contains("Primitive"));
        assert!(debug_str.contains("42"));

        let logical = NodeType::Logical {
            operation: LogicalOp::And,
        };
        let debug_str = format!("{logical:?}");
        assert!(debug_str.contains("Logical"));
        assert!(debug_str.contains("And"));

        let result = NodeType::Result { rule_id: 123 };
        let debug_str = format!("{result:?}");
        assert!(debug_str.contains("Result"));
        assert!(debug_str.contains("123"));
    }

    #[test]
    fn test_node_type_clone() {
        let primitive = NodeType::Primitive { primitive_id: 1 };
        let cloned = primitive.clone();
        assert_eq!(primitive, cloned);

        let logical = NodeType::Logical {
            operation: LogicalOp::Or,
        };
        let cloned = logical.clone();
        assert_eq!(logical, cloned);

        let result = NodeType::Result { rule_id: 1 };
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    #[test]
    fn test_dag_node_creation() {
        let node = DagNode::new(42, NodeType::Primitive { primitive_id: 1 });
        assert_eq!(node.id, 42);
        assert_eq!(node.node_type, NodeType::Primitive { primitive_id: 1 });
        assert!(node.dependencies.is_empty());
        assert!(node.dependents.is_empty());
        assert_eq!(node.cached_result, None);
    }

    #[test]
    fn test_dag_node_add_dependency() {
        let mut node = DagNode::new(
            1,
            NodeType::Logical {
                operation: LogicalOp::And,
            },
        );

        node.add_dependency(10);
        assert_eq!(node.dependencies, vec![10]);

        node.add_dependency(20);
        assert_eq!(node.dependencies, vec![10, 20]);

        // Adding duplicate should not change anything
        node.add_dependency(10);
        assert_eq!(node.dependencies, vec![10, 20]);
    }

    #[test]
    fn test_dag_node_add_dependent() {
        let mut node = DagNode::new(1, NodeType::Primitive { primitive_id: 1 });

        node.add_dependent(10);
        assert_eq!(node.dependents, vec![10]);

        node.add_dependent(20);
        assert_eq!(node.dependents, vec![10, 20]);

        // Adding duplicate should not change anything
        node.add_dependent(10);
        assert_eq!(node.dependents, vec![10, 20]);
    }

    #[test]
    fn test_dag_node_clear_cache() {
        let mut node = DagNode::new(1, NodeType::Primitive { primitive_id: 1 });

        // Initially no cache
        assert_eq!(node.cached_result, None);

        // Set cache
        node.cached_result = Some(true);
        assert_eq!(node.cached_result, Some(true));

        // Clear cache
        node.clear_cache();
        assert_eq!(node.cached_result, None);
    }

    #[test]
    fn test_dag_node_is_leaf() {
        let mut node = DagNode::new(1, NodeType::Primitive { primitive_id: 1 });

        // Initially is leaf (no dependencies)
        assert!(node.is_leaf());

        // Add dependency
        node.add_dependency(10);
        assert!(!node.is_leaf());

        // Clear dependencies
        node.dependencies.clear();
        assert!(node.is_leaf());
    }

    #[test]
    fn test_dag_node_is_root() {
        let mut node = DagNode::new(1, NodeType::Result { rule_id: 1 });

        // Initially is root (no dependents)
        assert!(node.is_root());

        // Add dependent
        node.add_dependent(10);
        assert!(!node.is_root());

        // Clear dependents
        node.dependents.clear();
        assert!(node.is_root());
    }

    #[test]
    fn test_dag_node_clone() {
        let mut node = DagNode::new(
            1,
            NodeType::Logical {
                operation: LogicalOp::Or,
            },
        );
        node.add_dependency(10);
        node.add_dependent(20);
        node.cached_result = Some(false);

        let cloned = node.clone();
        assert_eq!(cloned.id, node.id);
        assert_eq!(cloned.node_type, node.node_type);
        assert_eq!(cloned.dependencies, node.dependencies);
        assert_eq!(cloned.dependents, node.dependents);
        assert_eq!(cloned.cached_result, node.cached_result);
    }

    #[test]
    fn test_dag_node_debug() {
        let node = DagNode::new(42, NodeType::Primitive { primitive_id: 123 });
        let debug_str = format!("{node:?}");
        assert!(debug_str.contains("42"));
        assert!(debug_str.contains("Primitive"));
        assert!(debug_str.contains("123"));
    }

    #[test]
    fn test_compiled_dag_creation() {
        let dag = CompiledDag::new();
        assert!(dag.nodes.is_empty());
        assert!(dag.execution_order.is_empty());
        assert!(dag.primitive_map.is_empty());
        assert!(dag.rule_results.is_empty());
        assert_eq!(dag.result_buffer_size, 0);
    }

    #[test]
    fn test_compiled_dag_default() {
        let dag = CompiledDag::default();
        assert!(dag.nodes.is_empty());
        assert!(dag.execution_order.is_empty());
        assert!(dag.primitive_map.is_empty());
        assert!(dag.rule_results.is_empty());
        assert_eq!(dag.result_buffer_size, 0);
    }

    #[test]
    fn test_compiled_dag_add_node() {
        let mut dag = CompiledDag::new();
        let node = DagNode::new(42, NodeType::Primitive { primitive_id: 1 });

        let returned_id = dag.add_node(node.clone());
        assert_eq!(returned_id, 42);
        assert_eq!(dag.nodes.len(), 1);
        assert_eq!(dag.result_buffer_size, 1);
        assert_eq!(dag.nodes[0].id, 42);
    }

    #[test]
    fn test_compiled_dag_get_node() {
        let mut dag = CompiledDag::new();
        let node = DagNode::new(0, NodeType::Primitive { primitive_id: 1 });
        dag.add_node(node);

        // Valid node ID
        assert!(dag.get_node(0).is_some());
        assert_eq!(dag.get_node(0).unwrap().id, 0);

        // Invalid node ID
        assert!(dag.get_node(1).is_none());
        assert!(dag.get_node(999).is_none());
    }

    #[test]
    fn test_compiled_dag_get_node_mut() {
        let mut dag = CompiledDag::new();
        let node = DagNode::new(0, NodeType::Primitive { primitive_id: 1 });
        dag.add_node(node);

        // Valid node ID
        assert!(dag.get_node_mut(0).is_some());

        // Modify the node
        if let Some(node) = dag.get_node_mut(0) {
            node.cached_result = Some(true);
        }

        assert_eq!(dag.get_node(0).unwrap().cached_result, Some(true));

        // Invalid node ID
        assert!(dag.get_node_mut(1).is_none());
        assert!(dag.get_node_mut(999).is_none());
    }

    #[test]
    fn test_compiled_dag_node_count() {
        let mut dag = CompiledDag::new();
        assert_eq!(dag.node_count(), 0);

        dag.add_node(DagNode::new(0, NodeType::Primitive { primitive_id: 1 }));
        assert_eq!(dag.node_count(), 1);

        dag.add_node(DagNode::new(
            1,
            NodeType::Logical {
                operation: LogicalOp::And,
            },
        ));
        assert_eq!(dag.node_count(), 2);
    }

    #[test]
    fn test_compiled_dag_validate_success() {
        let dag = create_test_dag();
        assert!(dag.validate().is_ok());
    }

    #[test]
    fn test_compiled_dag_validate_execution_order_mismatch() {
        let mut dag = create_test_dag();
        dag.execution_order.pop(); // Remove one element

        let result = dag.validate();
        assert!(result.is_err());
        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Execution order length mismatch"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_compiled_dag_validate_invalid_dependency() {
        let mut dag = CompiledDag::new();
        let mut node = DagNode::new(
            0,
            NodeType::Logical {
                operation: LogicalOp::And,
            },
        );
        node.add_dependency(999); // Invalid dependency
        dag.add_node(node);
        dag.execution_order.push(0);

        let result = dag.validate();
        assert!(result.is_err());
        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Invalid dependency"));
            assert!(msg.contains("0 -> 999"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_compiled_dag_validate_invalid_result_node() {
        let mut dag = CompiledDag::new();
        dag.add_node(DagNode::new(0, NodeType::Primitive { primitive_id: 1 }));
        dag.rule_results.insert(1, 999); // Invalid result node
        dag.execution_order.push(0);

        let result = dag.validate();
        assert!(result.is_err());
        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Invalid result node"));
            assert!(msg.contains("999"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_compiled_dag_clear_cache() {
        let mut dag = create_test_dag();

        // Set some cached results
        if let Some(node) = dag.get_node_mut(0) {
            node.cached_result = Some(true);
        }
        if let Some(node) = dag.get_node_mut(1) {
            node.cached_result = Some(false);
        }

        // Verify cache is set
        assert_eq!(dag.get_node(0).unwrap().cached_result, Some(true));
        assert_eq!(dag.get_node(1).unwrap().cached_result, Some(false));

        // Clear cache
        dag.clear_cache();

        // Verify cache is cleared
        assert_eq!(dag.get_node(0).unwrap().cached_result, None);
        assert_eq!(dag.get_node(1).unwrap().cached_result, None);
        assert_eq!(dag.get_node(2).unwrap().cached_result, None);
        assert_eq!(dag.get_node(3).unwrap().cached_result, None);
    }

    #[test]
    fn test_compiled_dag_statistics() {
        let dag = create_test_dag();
        let stats = dag.statistics();

        assert_eq!(stats.total_nodes, 4);
        assert_eq!(stats.primitive_nodes, 2);
        assert_eq!(stats.logical_nodes, 1);
        assert_eq!(stats.result_nodes, 1);
        assert!(stats.avg_fanout > 0.0);
        assert!(stats.estimated_memory_bytes > 0);
    }

    #[test]
    fn test_compiled_dag_clone() {
        let dag = create_test_dag();
        let cloned = dag.clone();

        assert_eq!(cloned.nodes.len(), dag.nodes.len());
        assert_eq!(cloned.execution_order, dag.execution_order);
        assert_eq!(cloned.primitive_map, dag.primitive_map);
        assert_eq!(cloned.rule_results, dag.rule_results);
        assert_eq!(cloned.result_buffer_size, dag.result_buffer_size);
    }

    #[test]
    fn test_compiled_dag_debug() {
        let dag = create_test_dag();
        let debug_str = format!("{dag:?}");
        assert!(debug_str.contains("CompiledDag"));
        assert!(debug_str.contains("nodes"));
        assert!(debug_str.contains("execution_order"));
    }

    #[test]
    fn test_dag_statistics_empty_dag() {
        let dag = CompiledDag::new();
        let stats = DagStatistics::from_dag(&dag);

        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.primitive_nodes, 0);
        assert_eq!(stats.logical_nodes, 0);
        assert_eq!(stats.result_nodes, 0);
        assert_eq!(stats.max_depth, 0);
        assert_eq!(stats.avg_fanout, 0.0);
        assert_eq!(stats.shared_primitives, 0);
        // estimated_memory_bytes is usize, so it's always >= 0
        assert!(stats.estimated_memory_bytes < 1_000_000); // Reasonable upper bound
    }

    #[test]
    fn test_dag_statistics_single_node() {
        let mut dag = CompiledDag::new();
        dag.add_node(DagNode::new(0, NodeType::Primitive { primitive_id: 1 }));
        dag.execution_order.push(0);

        let stats = DagStatistics::from_dag(&dag);

        assert_eq!(stats.total_nodes, 1);
        assert_eq!(stats.primitive_nodes, 1);
        assert_eq!(stats.logical_nodes, 0);
        assert_eq!(stats.result_nodes, 0);
        assert_eq!(stats.max_depth, 1);
        assert_eq!(stats.avg_fanout, 0.0);
        assert_eq!(stats.shared_primitives, 0);
    }

    #[test]
    fn test_dag_statistics_complex_dag() {
        let dag = create_test_dag();
        let stats = DagStatistics::from_dag(&dag);

        assert_eq!(stats.total_nodes, 4);
        assert_eq!(stats.primitive_nodes, 2);
        assert_eq!(stats.logical_nodes, 1);
        assert_eq!(stats.result_nodes, 1);
        assert_eq!(stats.max_depth, 3); // primitive -> logical -> result
        assert!(stats.avg_fanout > 0.0);
        assert_eq!(stats.shared_primitives, 0); // No shared primitives in test DAG
    }

    #[test]
    fn test_dag_statistics_shared_primitives() {
        let mut dag = CompiledDag::new();

        // Add multiple nodes using the same primitive
        dag.add_node(DagNode::new(0, NodeType::Primitive { primitive_id: 1 }));
        dag.add_node(DagNode::new(1, NodeType::Primitive { primitive_id: 1 })); // Same primitive
        dag.add_node(DagNode::new(2, NodeType::Primitive { primitive_id: 2 }));
        dag.add_node(DagNode::new(3, NodeType::Primitive { primitive_id: 2 })); // Same primitive
        dag.add_node(DagNode::new(4, NodeType::Primitive { primitive_id: 3 })); // Unique primitive
        dag.execution_order = vec![0, 1, 2, 3, 4];

        let stats = DagStatistics::from_dag(&dag);

        assert_eq!(stats.total_nodes, 5);
        assert_eq!(stats.primitive_nodes, 5);
        assert_eq!(stats.shared_primitives, 2); // Primitives 1 and 2 are shared
    }

    #[test]
    fn test_dag_statistics_debug() {
        let dag = create_test_dag();
        let stats = dag.statistics();
        let debug_str = format!("{stats:?}");

        assert!(debug_str.contains("DagStatistics"));
        assert!(debug_str.contains("total_nodes"));
        assert!(debug_str.contains("primitive_nodes"));
        assert!(debug_str.contains("max_depth"));
    }

    #[test]
    fn test_dag_statistics_clone() {
        let dag = create_test_dag();
        let stats = dag.statistics();
        let cloned = stats.clone();

        assert_eq!(cloned.total_nodes, stats.total_nodes);
        assert_eq!(cloned.primitive_nodes, stats.primitive_nodes);
        assert_eq!(cloned.logical_nodes, stats.logical_nodes);
        assert_eq!(cloned.result_nodes, stats.result_nodes);
        assert_eq!(cloned.max_depth, stats.max_depth);
        assert_eq!(cloned.avg_fanout, stats.avg_fanout);
        assert_eq!(cloned.shared_primitives, stats.shared_primitives);
        assert_eq!(cloned.estimated_memory_bytes, stats.estimated_memory_bytes);
    }
}
