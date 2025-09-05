//! DAG evaluation functionality for high-performance rule execution.

use super::prefilter::LiteralPrefilter;
use super::types::{CompiledDag, LogicalOp, NodeType};
use crate::error::{Result, SigmaError};
use crate::ir::RuleId;
use crate::matcher::{CompiledPrimitive, EventContext};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Result of DAG evaluation.
#[derive(Debug, Clone, Default)]
pub struct DagEvaluationResult {
    /// Matched rule IDs
    pub matched_rules: Vec<RuleId>,
    /// Number of nodes evaluated during execution
    pub nodes_evaluated: usize,
    /// Number of primitive evaluations performed
    pub primitive_evaluations: usize,
}

/// DAG evaluator for executing compiled DAGs against events.
pub struct DagEvaluator {
    /// Reference to the compiled DAG
    dag: Arc<CompiledDag>,
    /// Compiled primitives for field matching
    primitives: HashMap<u32, CompiledPrimitive>,
    /// Evaluation state (reusable across evaluations)
    node_results: HashMap<u32, bool>,
    /// Fast-path evaluation buffer for small DAGs
    fast_results: Vec<bool>,
    /// Performance counters
    nodes_evaluated: usize,
    primitive_evaluations: usize,

    /// Optional prefilter for literal pattern matching
    prefilter: Option<Arc<LiteralPrefilter>>,

    /// Prefilter performance counters
    prefilter_hits: usize,
    prefilter_misses: usize,
}

impl DagEvaluator {
    /// Create a new DAG evaluator with compiled primitives.
    pub fn with_primitives(
        dag: Arc<CompiledDag>,
        primitives: HashMap<u32, CompiledPrimitive>,
    ) -> Self {
        let fast_results = vec![false; dag.nodes.len()];
        Self {
            dag,
            primitives,
            node_results: HashMap::new(),
            fast_results,
            nodes_evaluated: 0,
            primitive_evaluations: 0,
            prefilter: None,
            prefilter_hits: 0,
            prefilter_misses: 0,
        }
    }

    /// Create a new DAG evaluator with prefilter support.
    pub fn with_primitives_and_prefilter(
        dag: Arc<CompiledDag>,
        primitives: HashMap<u32, CompiledPrimitive>,
        prefilter: Option<Arc<LiteralPrefilter>>,
    ) -> Self {
        let fast_results = vec![false; dag.nodes.len()];
        Self {
            dag,
            primitives,
            node_results: HashMap::new(),
            fast_results,
            nodes_evaluated: 0,
            primitive_evaluations: 0,
            prefilter,
            prefilter_hits: 0,
            prefilter_misses: 0,
        }
    }

    /// Evaluate the DAG against an event and return matches.
    pub fn evaluate(&mut self, event: &Value) -> Result<DagEvaluationResult> {
        // Early termination with prefilter if available
        if let Some(ref prefilter) = self.prefilter {
            if !prefilter.matches(event)? {
                self.prefilter_misses += 1;
                // No literal patterns match - skip entire evaluation
                return Ok(DagEvaluationResult {
                    matched_rules: Vec::new(),
                    nodes_evaluated: 1, // Only prefilter was evaluated
                    primitive_evaluations: 0,
                });
            }
            self.prefilter_hits += 1;
        }

        // Choose optimal evaluation strategy based on DAG characteristics
        self.evaluate_with_optimal_strategy(event)
    }

    /// Evaluate the DAG against a raw JSON string with zero-allocation prefiltering.
    ///
    /// This is the most efficient approach for high-throughput scenarios where events
    /// are already JSON strings. Uses raw string prefiltering to achieve 2.4x performance
    /// improvement for non-matching events (95%+ of real-world SOC traffic).
    ///
    /// # Performance Notes
    ///
    /// - Zero allocation prefiltering - searches raw JSON directly with AhoCorasick
    /// - Zero serialization - no JSON parsing until prefilter passes
    /// - Optimal for high selectivity scenarios (>90% event elimination)
    /// - Falls back to standard evaluation for events that pass prefilter
    pub fn evaluate_raw(&mut self, json_str: &str) -> Result<DagEvaluationResult> {
        // Early termination with raw string prefilter if available
        if let Some(ref prefilter) = self.prefilter {
            if !prefilter.matches_raw(json_str)? {
                self.prefilter_misses += 1;
                // No literal patterns match - skip entire evaluation
                return Ok(DagEvaluationResult {
                    matched_rules: Vec::new(),
                    nodes_evaluated: 1, // Only prefilter was evaluated
                    primitive_evaluations: 0,
                });
            }
            self.prefilter_hits += 1;
        }

        // Parse JSON only after prefilter passes (for the ~5-10% that match)
        let event: Value = serde_json::from_str(json_str)
            .map_err(|e| SigmaError::ExecutionError(format!("Invalid JSON: {e}")))?;

        // Continue with standard evaluation path
        // Ultra-fast path for single primitive rules (most common case)
        if self.dag.rule_results.len() == 1 && self.dag.nodes.len() <= 3 {
            return self.evaluate_single_primitive_optimized(&event);
        }

        // Choose optimal evaluation strategy based on DAG characteristics
        self.evaluate_with_optimal_strategy(&event)
    }

    /// Unified evaluation method that chooses optimal strategy based on DAG characteristics.
    fn evaluate_with_optimal_strategy(&mut self, event: &Value) -> Result<DagEvaluationResult> {
        // Ultra-fast path for single primitive rules (most common case)
        if self.dag.rule_results.len() == 1 && self.dag.nodes.len() <= 3 {
            return self.evaluate_single_primitive_optimized(event);
        }

        // Use Vec-based storage for small DAGs to avoid HashMap overhead
        // Threshold of 32 nodes chosen based on benchmarking - see bench_storage_strategy_threshold
        // Benchmarks show consistent performance across sizes 8-64, indicating the threshold is reasonable.
        // Vec storage provides better cache locality for small DAGs, while HashMap storage scales better
        // for larger DAGs due to O(1) lookups vs potential O(n) Vec operations.
        if self.dag.nodes.len() <= 32 {
            self.evaluate_with_vec_storage(event)
        } else {
            self.evaluate_with_hashmap_storage(event)
        }
    }

    /// Ultra-fast evaluation for single primitive rules.
    fn evaluate_single_primitive_optimized(
        &mut self,
        event: &Value,
    ) -> Result<DagEvaluationResult> {
        self.reset();

        let (&rule_id, &result_node_id) = self.dag.rule_results.iter().next().unwrap();

        if let Some(result_node) = self.dag.get_node(result_node_id) {
            if let NodeType::Result { .. } = result_node.node_type {
                if result_node.dependencies.len() == 1 {
                    let primitive_node_id = result_node.dependencies[0];
                    if let Some(primitive_node) = self.dag.get_node(primitive_node_id) {
                        if let NodeType::Primitive { primitive_id } = primitive_node.node_type {
                            self.nodes_evaluated = 2;
                            let result = self.evaluate_primitive(primitive_id, event)?;
                            let matched_rules = if result { vec![rule_id] } else { Vec::new() };

                            return Ok(DagEvaluationResult {
                                matched_rules,
                                nodes_evaluated: self.nodes_evaluated,
                                primitive_evaluations: self.primitive_evaluations,
                            });
                        }
                    }
                }
            }
        }

        // Fallback to standard evaluation
        self.evaluate_with_hashmap_storage(event)
    }

    /// Vec-based evaluation for small DAGs (avoids HashMap overhead).
    fn evaluate_with_vec_storage(&mut self, event: &Value) -> Result<DagEvaluationResult> {
        self.reset();

        // Use intelligent evaluation with early termination
        self.evaluate_with_early_termination_vec(event)
    }

    /// Intelligent evaluation with early termination using Vec storage.
    fn evaluate_with_early_termination_vec(
        &mut self,
        event: &Value,
    ) -> Result<DagEvaluationResult> {
        let execution_order = self.dag.execution_order.clone();
        let mut can_terminate_early = std::collections::HashMap::new();

        for node_id in execution_order {
            // Check if we can skip this node due to early termination
            if self.should_skip_node_vec(node_id, &can_terminate_early) {
                continue;
            }

            let result = self.evaluate_node_with_vec(node_id, event)?;
            if (node_id as usize) < self.fast_results.len() {
                self.fast_results[node_id as usize] = result;
            }
            self.nodes_evaluated += 1;

            // Update early termination state based on this result
            if let Some(node) = self.dag.get_node(node_id) {
                self.update_early_termination_state_fast(node, result, &mut can_terminate_early);
            }
        }

        let mut matched_rules = Vec::new();
        for (&rule_id, &result_node_id) in &self.dag.rule_results {
            if (result_node_id as usize) < self.fast_results.len()
                && self.fast_results[result_node_id as usize]
            {
                matched_rules.push(rule_id);
            }
        }

        Ok(DagEvaluationResult {
            matched_rules,
            nodes_evaluated: self.nodes_evaluated,
            primitive_evaluations: self.primitive_evaluations,
        })
    }

    /// HashMap-based evaluation for larger DAGs.
    fn evaluate_with_hashmap_storage(&mut self, event: &Value) -> Result<DagEvaluationResult> {
        self.reset();

        // Use intelligent evaluation with early termination
        self.evaluate_with_early_termination_hashmap(event)
    }

    /// Intelligent evaluation with early termination for standard path.
    fn evaluate_with_early_termination_hashmap(
        &mut self,
        event: &Value,
    ) -> Result<DagEvaluationResult> {
        let execution_order = self.dag.execution_order.clone();
        let mut can_terminate_early = std::collections::HashMap::new();

        for node_id in execution_order {
            // Check if we can skip this node due to early termination
            if self.should_skip_node_hashmap(node_id, &can_terminate_early) {
                continue;
            }

            let result = self.evaluate_node_with_hashmap(node_id, event)?;
            self.node_results.insert(node_id, result);
            self.nodes_evaluated += 1;

            // Update early termination state based on this result
            if let Some(node) = self.dag.get_node(node_id) {
                self.update_early_termination_state_standard(
                    node,
                    result,
                    &mut can_terminate_early,
                );
            }
        }

        let mut matched_rules = Vec::new();
        for (&rule_id, &result_node_id) in &self.dag.rule_results {
            if let Some(&result) = self.node_results.get(&result_node_id) {
                if result {
                    matched_rules.push(rule_id);
                }
            }
        }

        Ok(DagEvaluationResult {
            matched_rules,
            nodes_evaluated: self.nodes_evaluated,
            primitive_evaluations: self.primitive_evaluations,
        })
    }

    /// Evaluate a single node using HashMap storage.
    fn evaluate_node_with_hashmap(&mut self, node_id: u32, event: &Value) -> Result<bool> {
        let node = self
            .dag
            .get_node(node_id)
            .ok_or_else(|| SigmaError::ExecutionError(format!("Node {node_id} not found")))?
            .clone();

        match &node.node_type {
            NodeType::Primitive { primitive_id } => self.evaluate_primitive(*primitive_id, event),
            NodeType::Logical { operation } => {
                self.evaluate_logical_operation_with_hashmap(*operation, &node.dependencies)
            }
            NodeType::Result { rule_id: _ } => {
                if node.dependencies.len() == 1 {
                    Ok(self
                        .node_results
                        .get(&node.dependencies[0])
                        .copied()
                        .unwrap_or(false))
                } else {
                    Ok(false)
                }
            }
            NodeType::Prefilter { .. } => {
                // Prefilter nodes are handled at the start of evaluation
                // If we reach here, prefilter already passed
                Ok(true)
            }
        }
    }

    /// Evaluate a single node (fast path).
    fn evaluate_node_with_vec(&mut self, node_id: u32, event: &Value) -> Result<bool> {
        let node = self
            .dag
            .get_node(node_id)
            .ok_or_else(|| SigmaError::ExecutionError(format!("Node {node_id} not found")))?
            .clone();

        match &node.node_type {
            NodeType::Primitive { primitive_id } => self.evaluate_primitive(*primitive_id, event),
            NodeType::Logical { operation } => {
                self.evaluate_logical_operation_with_vec(*operation, &node.dependencies)
            }
            NodeType::Result { rule_id: _ } => {
                if node.dependencies.len() == 1 {
                    let dep_id = node.dependencies[0] as usize;
                    if dep_id < self.fast_results.len() {
                        Ok(self.fast_results[dep_id])
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            NodeType::Prefilter { .. } => {
                // Prefilter nodes are handled at the start of evaluation
                // If we reach here, prefilter already passed
                Ok(true)
            }
        }
    }

    /// Evaluate a primitive node against an event.
    fn evaluate_primitive(&mut self, primitive_id: u32, event: &Value) -> Result<bool> {
        self.primitive_evaluations += 1;

        if let Some(primitive) = self.primitives.get(&primitive_id) {
            let context = EventContext::new(event);
            Ok(primitive.matches(&context))
        } else {
            Err(SigmaError::ExecutionError(format!(
                "Primitive {primitive_id} not found"
            )))
        }
    }

    /// Evaluate a logical operation using HashMap storage.
    fn evaluate_logical_operation_with_hashmap(
        &self,
        operation: LogicalOp,
        dependencies: &[u32],
    ) -> Result<bool> {
        match operation {
            LogicalOp::And => {
                for &dep_id in dependencies {
                    if let Some(&result) = self.node_results.get(&dep_id) {
                        if !result {
                            return Ok(false);
                        }
                    } else {
                        return Err(SigmaError::ExecutionError(format!(
                            "Dependency {dep_id} not evaluated"
                        )));
                    }
                }
                Ok(true)
            }
            LogicalOp::Or => {
                for &dep_id in dependencies {
                    if let Some(&result) = self.node_results.get(&dep_id) {
                        if result {
                            return Ok(true);
                        }
                    } else {
                        return Err(SigmaError::ExecutionError(format!(
                            "Dependency {dep_id} not evaluated"
                        )));
                    }
                }
                Ok(false)
            }
            LogicalOp::Not => {
                if dependencies.len() != 1 {
                    return Err(SigmaError::ExecutionError(
                        "NOT operation requires exactly one dependency".to_string(),
                    ));
                }
                if let Some(&result) = self.node_results.get(&dependencies[0]) {
                    Ok(!result)
                } else {
                    Err(SigmaError::ExecutionError(format!(
                        "Dependency {} not evaluated",
                        dependencies[0]
                    )))
                }
            }
        }
    }

    /// Evaluate a logical operation (fast path).
    fn evaluate_logical_operation_with_vec(
        &self,
        operation: LogicalOp,
        dependencies: &[u32],
    ) -> Result<bool> {
        match operation {
            LogicalOp::And => {
                for &dep_id in dependencies {
                    let dep_idx = dep_id as usize;
                    if dep_idx < self.fast_results.len() {
                        if !self.fast_results[dep_idx] {
                            return Ok(false);
                        }
                    } else {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            LogicalOp::Or => {
                for &dep_id in dependencies {
                    let dep_idx = dep_id as usize;
                    if dep_idx < self.fast_results.len() && self.fast_results[dep_idx] {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            LogicalOp::Not => {
                if dependencies.len() != 1 {
                    return Err(SigmaError::ExecutionError(
                        "NOT operation requires exactly one dependency".to_string(),
                    ));
                }
                let dep_idx = dependencies[0] as usize;
                if dep_idx < self.fast_results.len() {
                    Ok(!self.fast_results[dep_idx])
                } else {
                    Ok(true) // Default to true for NOT of missing dependency
                }
            }
        }
    }

    /// Evaluate the DAG using pre-computed primitive results (for VM compatibility).
    pub fn evaluate_with_primitive_results(
        &mut self,
        primitive_results: &[bool],
    ) -> Result<DagEvaluationResult> {
        self.reset();

        // Pre-populate primitive results from the provided array
        for (primitive_id, &result) in primitive_results.iter().enumerate() {
            if let Some(&node_id) = self.dag.primitive_map.get(&(primitive_id as u32)) {
                self.node_results.insert(node_id, result);
                self.primitive_evaluations += 1;
            }
        }

        // Evaluate logical and result nodes in topological order
        let execution_order = self.dag.execution_order.clone();
        for node_id in execution_order {
            if let Some(node) = self.dag.get_node(node_id) {
                match &node.node_type {
                    NodeType::Primitive { .. } => {
                        // Skip - already handled above
                        self.node_results.entry(node_id).or_insert(false);
                    }
                    NodeType::Logical { operation } => {
                        let result = self.evaluate_logical_operation_with_hashmap(
                            *operation,
                            &node.dependencies,
                        )?;
                        self.node_results.insert(node_id, result);
                    }
                    NodeType::Result { rule_id: _ } => {
                        let result = if node.dependencies.len() == 1 {
                            self.node_results
                                .get(&node.dependencies[0])
                                .copied()
                                .unwrap_or(false)
                        } else {
                            false
                        };
                        self.node_results.insert(node_id, result);
                    }
                    NodeType::Prefilter { .. } => {
                        // Skip prefilter nodes - they're handled separately
                        self.node_results.insert(node_id, true);
                    }
                }
                self.nodes_evaluated += 1;
            }
        }

        // Collect matched rules from result nodes
        let mut matched_rules = Vec::new();
        for (&rule_id, &result_node_id) in &self.dag.rule_results {
            if let Some(&result) = self.node_results.get(&result_node_id) {
                if result {
                    matched_rules.push(rule_id);
                }
            }
        }

        Ok(DagEvaluationResult {
            matched_rules,
            nodes_evaluated: self.nodes_evaluated,
            primitive_evaluations: self.primitive_evaluations,
        })
    }

    /// Check if a node should be skipped due to early termination (Vec storage).
    fn should_skip_node_vec(
        &self,
        node_id: u32,
        termination_state: &std::collections::HashMap<u32, bool>,
    ) -> bool {
        if let Some(node) = self.dag.get_node(node_id) {
            // Check if any of this node's dependencies have caused early termination
            for &dep_id in &node.dependencies {
                if let Some(&can_terminate) = termination_state.get(&dep_id) {
                    if can_terminate {
                        // Check if this dependency failure makes this node unnecessary
                        if self.is_node_unnecessary_due_to_dependency_failure(node, dep_id) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a node should be skipped due to early termination (HashMap storage).
    fn should_skip_node_hashmap(
        &self,
        node_id: u32,
        termination_state: &std::collections::HashMap<u32, bool>,
    ) -> bool {
        if let Some(node) = self.dag.get_node(node_id) {
            // Check if any of this node's dependencies have caused early termination
            for &dep_id in &node.dependencies {
                if let Some(&can_terminate) = termination_state.get(&dep_id) {
                    if can_terminate {
                        // Check if this dependency failure makes this node unnecessary
                        if self.is_node_unnecessary_due_to_dependency_failure(node, dep_id) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a node is unnecessary due to a dependency failure.
    fn is_node_unnecessary_due_to_dependency_failure(
        &self,
        node: &super::types::DagNode,
        failed_dep_id: u32,
    ) -> bool {
        match &node.node_type {
            NodeType::Logical {
                operation: LogicalOp::And,
            } => {
                // For AND nodes, if any dependency fails, the whole node fails
                true
            }
            NodeType::Logical {
                operation: LogicalOp::Or,
            } => {
                // For OR nodes, we can only skip if ALL dependencies have failed
                // This is more complex and requires tracking all dependency states
                false // Conservative approach for now
            }
            NodeType::Result { .. } => {
                // Result nodes depend on their single dependency
                node.dependencies.len() == 1 && node.dependencies[0] == failed_dep_id
            }
            _ => false,
        }
    }

    /// Update early termination state based on node evaluation result (fast path).
    fn update_early_termination_state_fast(
        &self,
        node: &super::types::DagNode,
        result: bool,
        termination_state: &mut std::collections::HashMap<u32, bool>,
    ) {
        match &node.node_type {
            NodeType::Primitive { .. } => {
                // Primitive failure can cause early termination for dependent AND nodes
                if !result {
                    termination_state.insert(node.id, true);
                }
            }
            NodeType::Logical { operation } => {
                match operation {
                    LogicalOp::And if !result => {
                        // Failed AND can cause early termination for dependents
                        termination_state.insert(node.id, true);
                    }
                    LogicalOp::Or if result => {
                        // Successful OR can cause early termination for other OR branches
                        // This is more complex and requires careful analysis
                        termination_state.insert(node.id, false);
                    }
                    _ => {
                        // Other cases don't cause early termination
                        termination_state.insert(node.id, false);
                    }
                }
            }
            _ => {
                // Other node types don't cause early termination
                termination_state.insert(node.id, false);
            }
        }
    }

    /// Update early termination state based on node evaluation result (standard path).
    fn update_early_termination_state_standard(
        &self,
        node: &super::types::DagNode,
        result: bool,
        termination_state: &mut std::collections::HashMap<u32, bool>,
    ) {
        match &node.node_type {
            NodeType::Primitive { .. } => {
                // Primitive failure can cause early termination for dependent AND nodes
                if !result {
                    termination_state.insert(node.id, true);
                }
            }
            NodeType::Logical { operation } => {
                match operation {
                    LogicalOp::And if !result => {
                        // Failed AND can cause early termination for dependents
                        termination_state.insert(node.id, true);
                    }
                    LogicalOp::Or if result => {
                        // Successful OR can cause early termination for other OR branches
                        // This is more complex and requires careful analysis
                        termination_state.insert(node.id, false);
                    }
                    _ => {
                        // Other cases don't cause early termination
                        termination_state.insert(node.id, false);
                    }
                }
            }
            _ => {
                // Other node types don't cause early termination
                termination_state.insert(node.id, false);
            }
        }
    }

    /// Reset evaluation state for a new evaluation.
    pub fn reset(&mut self) {
        self.node_results.clear();
        self.fast_results.fill(false);
        self.nodes_evaluated = 0;
        self.primitive_evaluations = 0;
        // Note: Don't reset prefilter counters as they're cumulative stats
    }

    /// Get prefilter performance statistics.
    pub fn prefilter_stats(&self) -> (usize, usize) {
        (self.prefilter_hits, self.prefilter_misses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::types::{DagNode, LogicalOp, NodeType};
    use crate::ir::Primitive;
    use crate::matcher::CompiledPrimitive;
    use serde_json::json;
    use std::collections::HashMap;

    fn create_test_dag() -> CompiledDag {
        // Create a simple DAG: primitive -> result
        let primitive_node = DagNode::new(0, NodeType::Primitive { primitive_id: 0 });
        let result_node = DagNode::new(1, NodeType::Result { rule_id: 1 });

        let mut primitive_map = HashMap::new();
        primitive_map.insert(0, 0);

        let mut rule_results = HashMap::new();
        rule_results.insert(1, 1);

        CompiledDag {
            nodes: vec![primitive_node, result_node],
            execution_order: vec![0, 1],
            primitive_map,
            rule_results,
            result_buffer_size: 2,
        }
    }

    fn create_test_primitives() -> HashMap<u32, CompiledPrimitive> {
        let primitive = Primitive::new(
            "field1".to_string(),
            "equals".to_string(),
            vec!["value1".to_string()],
            Vec::new(),
        );

        let mut primitives = HashMap::new();
        primitives.insert(0, CompiledPrimitive::from_primitive(primitive).unwrap());
        primitives
    }

    #[test]
    fn test_dag_evaluation_result_default() {
        let result = DagEvaluationResult::default();
        assert!(result.matched_rules.is_empty());
        assert_eq!(result.nodes_evaluated, 0);
        assert_eq!(result.primitive_evaluations, 0);
    }

    #[test]
    fn test_dag_evaluator_creation() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let evaluator = DagEvaluator::with_primitives(dag.clone(), primitives);
        assert_eq!(evaluator.fast_results.len(), dag.nodes.len());
        assert_eq!(evaluator.nodes_evaluated, 0);
        assert_eq!(evaluator.primitive_evaluations, 0);
    }

    #[test]
    fn test_dag_evaluator_reset() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Simulate some state
        evaluator.node_results.insert(0, true);
        evaluator.fast_results[0] = true;
        evaluator.nodes_evaluated = 5;
        evaluator.primitive_evaluations = 3;

        // Reset and verify
        evaluator.reset();
        assert!(evaluator.node_results.is_empty());
        assert!(!evaluator.fast_results[0]);
        assert_eq!(evaluator.nodes_evaluated, 0);
        assert_eq!(evaluator.primitive_evaluations, 0);
    }

    #[test]
    fn test_evaluate_primitive_not_found() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new(); // Empty primitives

        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);
        let event = json!({"field1": "value1"});

        let result = evaluator.evaluate_primitive(0, &event);
        assert!(result.is_err());

        if let Err(SigmaError::ExecutionError(msg)) = result {
            assert!(msg.contains("Primitive 0 not found"));
        } else {
            panic!("Expected ExecutionError for missing primitive");
        }
    }

    #[test]
    fn test_evaluate_logical_operation_and_success() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Set up dependencies
        evaluator.node_results.insert(0, true);
        evaluator.node_results.insert(1, true);

        let result = evaluator
            .evaluate_logical_operation_with_hashmap(LogicalOp::And, &[0, 1])
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_logical_operation_and_failure() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Set up dependencies with one false
        evaluator.node_results.insert(0, true);
        evaluator.node_results.insert(1, false);

        let result = evaluator
            .evaluate_logical_operation_with_hashmap(LogicalOp::And, &[0, 1])
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_logical_operation_or_success() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Set up dependencies with one true
        evaluator.node_results.insert(0, false);
        evaluator.node_results.insert(1, true);

        let result = evaluator
            .evaluate_logical_operation_with_hashmap(LogicalOp::Or, &[0, 1])
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_logical_operation_or_failure() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Set up dependencies with both false
        evaluator.node_results.insert(0, false);
        evaluator.node_results.insert(1, false);

        let result = evaluator
            .evaluate_logical_operation_with_hashmap(LogicalOp::Or, &[0, 1])
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_logical_operation_not_success() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Set up dependency
        evaluator.node_results.insert(0, false);

        let result = evaluator
            .evaluate_logical_operation_with_hashmap(LogicalOp::Not, &[0])
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_logical_operation_not_failure() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Set up dependency
        evaluator.node_results.insert(0, true);

        let result = evaluator
            .evaluate_logical_operation_with_hashmap(LogicalOp::Not, &[0])
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_evaluate_logical_operation_not_invalid_dependencies() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let evaluator = DagEvaluator::with_primitives(dag, primitives);

        // NOT with multiple dependencies should fail
        let result = evaluator.evaluate_logical_operation_with_hashmap(LogicalOp::Not, &[0, 1]);
        assert!(result.is_err());

        if let Err(SigmaError::ExecutionError(msg)) = result {
            assert!(msg.contains("NOT operation requires exactly one dependency"));
        } else {
            panic!("Expected ExecutionError for invalid NOT dependencies");
        }
    }

    #[test]
    fn test_evaluate_logical_operation_missing_dependency() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Try to evaluate without setting up dependencies
        let result = evaluator.evaluate_logical_operation_with_hashmap(LogicalOp::And, &[0, 1]);
        assert!(result.is_err());

        if let Err(SigmaError::ExecutionError(msg)) = result {
            assert!(msg.contains("Dependency") && msg.contains("not evaluated"));
        } else {
            panic!("Expected ExecutionError for missing dependency");
        }
    }

    #[test]
    fn test_evaluate_logical_operation_fast_and() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Set up fast results
        evaluator.fast_results[0] = true;
        evaluator.fast_results[1] = true;

        let result = evaluator
            .evaluate_logical_operation_with_vec(LogicalOp::And, &[0, 1])
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_logical_operation_fast_or() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Set up fast results with one true
        evaluator.fast_results[0] = false;
        evaluator.fast_results[1] = true;

        let result = evaluator
            .evaluate_logical_operation_with_vec(LogicalOp::Or, &[0, 1])
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_evaluate_logical_operation_fast_not() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();

        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Set up fast results
        evaluator.fast_results[0] = false;

        let result = evaluator
            .evaluate_logical_operation_with_vec(LogicalOp::Not, &[0])
            .unwrap();
        assert!(result);
    }
}
