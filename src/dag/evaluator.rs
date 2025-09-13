//! Unified DAG evaluation functionality for high-performance rule execution.
//!
//! This module provides a single adaptive evaluator that automatically selects
//! the optimal evaluation strategy based on input characteristics:
//! - Single event evaluation for individual events
//! - Batch processing for multiple events

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

/// Evaluation strategy selection based on input characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationStrategy {
    /// Single event evaluation with HashMap storage
    Single,
    /// Single event evaluation with Vec storage (for small DAGs)
    SingleVec,
    /// Batch processing with memory pools
    Batch,
}

/// Configuration for the unified evaluator.
#[derive(Debug, Clone)]
pub struct EvaluatorConfig {
    /// Threshold for using Vec vs HashMap storage (number of nodes)
    pub vec_storage_threshold: usize,
}

impl Default for EvaluatorConfig {
    fn default() -> Self {
        Self {
            vec_storage_threshold: 32,
        }
    }
}

/// Memory pool for batch processing to minimize allocations.
#[derive(Debug)]
struct BatchMemoryPool {
    /// Primitive results for all events [primitive_id][event_idx] -> bool
    primitive_results: Vec<Vec<bool>>,
    /// Node results for all events [node_id][event_idx] -> bool
    node_results: Vec<Vec<bool>>,
}

impl BatchMemoryPool {
    fn new() -> Self {
        Self {
            primitive_results: Vec::new(),
            node_results: Vec::new(),
        }
    }

    fn resize_for_batch(&mut self, batch_size: usize, node_count: usize, primitive_count: usize) {
        // Resize primitive results
        self.primitive_results.resize(primitive_count, Vec::new());
        for primitive_buffer in &mut self.primitive_results {
            primitive_buffer.resize(batch_size, false);
        }

        // Resize node results
        self.node_results.resize(node_count, Vec::new());
        for node_buffer in &mut self.node_results {
            node_buffer.resize(batch_size, false);
        }
    }

    fn reset(&mut self) {
        // Reset all buffers to false/empty
        for primitive_buffer in &mut self.primitive_results {
            primitive_buffer.fill(false);
        }
        for node_buffer in &mut self.node_results {
            node_buffer.fill(false);
        }
    }
}

/// Unified DAG evaluator that adapts strategy based on input characteristics.
///
/// This evaluator automatically selects the optimal evaluation approach:
/// - Single event evaluation for individual events
/// - Batch processing for multiple events
/// - Parallel processing for large rule sets (when enabled)
///
/// The evaluator maintains internal state and memory pools for efficient
/// reuse across multiple evaluations.
pub struct DagEvaluator {
    /// Reference to the compiled DAG
    dag: Arc<CompiledDag>,
    /// Compiled primitives for field matching
    primitives: HashMap<u32, CompiledPrimitive>,
    /// Configuration for strategy selection
    config: EvaluatorConfig,

    /// Single event evaluation state
    node_results: HashMap<u32, bool>,
    /// Fast-path evaluation buffer for small DAGs
    fast_results: Vec<bool>,

    /// Batch processing memory pool
    batch_pool: BatchMemoryPool,

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
    /// Create a new unified DAG evaluator with compiled primitives.
    pub fn with_primitives(
        dag: Arc<CompiledDag>,
        primitives: HashMap<u32, CompiledPrimitive>,
    ) -> Self {
        Self::with_primitives_and_config(dag, primitives, None, EvaluatorConfig::default())
    }

    /// Create a new DAG evaluator with prefilter support.
    pub fn with_primitives_and_prefilter(
        dag: Arc<CompiledDag>,
        primitives: HashMap<u32, CompiledPrimitive>,
        prefilter: Option<Arc<LiteralPrefilter>>,
    ) -> Self {
        Self::with_primitives_and_config(dag, primitives, prefilter, EvaluatorConfig::default())
    }

    /// Create a new DAG evaluator with custom configuration.
    pub fn with_primitives_and_config(
        dag: Arc<CompiledDag>,
        primitives: HashMap<u32, CompiledPrimitive>,
        prefilter: Option<Arc<LiteralPrefilter>>,
        config: EvaluatorConfig,
    ) -> Self {
        let fast_results = vec![false; dag.nodes.len()];
        Self {
            dag,
            primitives,
            config,
            node_results: HashMap::new(),
            fast_results,
            batch_pool: BatchMemoryPool::new(),
            nodes_evaluated: 0,
            primitive_evaluations: 0,
            prefilter,
            prefilter_hits: 0,
            prefilter_misses: 0,
        }
    }

    /// Select the optimal evaluation strategy based on input characteristics.
    fn select_strategy(&self, event_count: usize) -> EvaluationStrategy {
        // For single events
        if event_count == 1 {
            if self.dag.nodes.len() <= self.config.vec_storage_threshold {
                EvaluationStrategy::SingleVec
            } else {
                EvaluationStrategy::Single
            }
        }
        // For multiple events
        else {
            EvaluationStrategy::Batch
        }
    }

    /// Evaluate the DAG against a single event and return matches.
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

        // Select strategy and evaluate
        let strategy = self.select_strategy(1);
        match strategy {
            EvaluationStrategy::SingleVec => self.evaluate_single_vec(event),
            EvaluationStrategy::Single => self.evaluate_single_hashmap(event),
            _ => unreachable!("Single event should not use batch/parallel strategy"),
        }
    }

    /// Evaluate the DAG against multiple events using batch processing.
    pub fn evaluate_batch(&mut self, events: &[Value]) -> Result<Vec<DagEvaluationResult>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        // Select strategy and evaluate
        let strategy = self.select_strategy(events.len());
        match strategy {
            EvaluationStrategy::Batch => self.evaluate_batch_internal(events),
            _ => {
                // Fallback to single event evaluation for each event
                let mut results = Vec::with_capacity(events.len());
                for event in events {
                    results.push(self.evaluate(event)?);
                }
                Ok(results)
            }
        }
    }

    /// Evaluate the DAG against a raw JSON string with zero-allocation prefiltering.
    pub fn evaluate_raw(&mut self, json_str: &str) -> Result<DagEvaluationResult> {
        // Early termination with prefilter if available
        if let Some(ref prefilter) = self.prefilter {
            if !prefilter.matches_raw(json_str)? {
                self.prefilter_misses += 1;
                return Ok(DagEvaluationResult {
                    matched_rules: Vec::new(),
                    nodes_evaluated: 1,
                    primitive_evaluations: 0,
                });
            }
            self.prefilter_hits += 1;
        }

        // Parse JSON and evaluate normally
        let event: Value = serde_json::from_str(json_str)
            .map_err(|e| SigmaError::ExecutionError(format!("Invalid JSON: {e}")))?;

        self.evaluate(&event)
    }

    /// Reset the evaluator state for reuse.
    pub fn reset(&mut self) {
        self.node_results.clear();
        self.fast_results.fill(false);
        self.batch_pool.reset();
        self.nodes_evaluated = 0;
        self.primitive_evaluations = 0;
    }

    /// Get performance statistics.
    pub fn get_stats(&self) -> (usize, usize, usize, usize) {
        (
            self.nodes_evaluated,
            self.primitive_evaluations,
            self.prefilter_hits,
            self.prefilter_misses,
        )
    }

    /// Check if prefilter is enabled.
    pub fn has_prefilter(&self) -> bool {
        self.prefilter.is_some()
    }

    /// Single event evaluation using Vec storage (for small DAGs).
    fn evaluate_single_vec(&mut self, event: &Value) -> Result<DagEvaluationResult> {
        self.reset();

        let execution_order = self.dag.execution_order.clone();

        for &node_id in &execution_order {
            let node = &self.dag.nodes[node_id as usize];
            self.nodes_evaluated += 1;

            let result = match &node.node_type {
                NodeType::Primitive { primitive_id } => {
                    self.primitive_evaluations += 1;
                    if let Some(primitive) = self.primitives.get(primitive_id) {
                        let context = EventContext::new(event);
                        primitive.matches(&context)
                    } else {
                        false
                    }
                }
                NodeType::Logical { operation } => {
                    self.evaluate_logical_operation_with_vec(*operation, &node.dependencies)?
                }
                NodeType::Result { .. } => {
                    // Result nodes depend on a single logical node
                    if node.dependencies.len() == 1 {
                        self.fast_results[node.dependencies[0] as usize]
                    } else {
                        false
                    }
                }
                _ => false, // Handle other node types
            };

            self.fast_results[node_id as usize] = result;
        }

        // Collect matched rules
        let mut matched_rules = Vec::new();
        for (&rule_id, &result_node_id) in &self.dag.rule_results {
            if self.fast_results[result_node_id as usize] {
                matched_rules.push(rule_id);
            }
        }

        Ok(DagEvaluationResult {
            matched_rules,
            nodes_evaluated: self.nodes_evaluated,
            primitive_evaluations: self.primitive_evaluations,
        })
    }

    /// Single event evaluation using HashMap storage (for larger DAGs).
    fn evaluate_single_hashmap(&mut self, event: &Value) -> Result<DagEvaluationResult> {
        self.reset();

        let execution_order = self.dag.execution_order.clone();

        for &node_id in &execution_order {
            let node = &self.dag.nodes[node_id as usize];
            self.nodes_evaluated += 1;

            let result = match &node.node_type {
                NodeType::Primitive { primitive_id } => {
                    self.primitive_evaluations += 1;
                    if let Some(primitive) = self.primitives.get(primitive_id) {
                        let context = EventContext::new(event);
                        primitive.matches(&context)
                    } else {
                        false
                    }
                }
                NodeType::Logical { operation } => {
                    self.evaluate_logical_operation_with_hashmap(*operation, &node.dependencies)?
                }
                NodeType::Result { .. } => {
                    // Result nodes depend on a single logical node
                    if node.dependencies.len() == 1 {
                        *self
                            .node_results
                            .get(&node.dependencies[0])
                            .unwrap_or(&false)
                    } else {
                        false
                    }
                }
                _ => false, // Handle other node types
            };

            self.node_results.insert(node_id, result);
        }

        // Collect matched rules
        let mut matched_rules = Vec::new();
        for (&rule_id, &result_node_id) in &self.dag.rule_results {
            if self
                .node_results
                .get(&result_node_id)
                .copied()
                .unwrap_or(false)
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

    /// Evaluate logical operation using Vec storage.
    fn evaluate_logical_operation_with_vec(
        &self,
        op: LogicalOp,
        dependencies: &[u32],
    ) -> Result<bool> {
        match op {
            LogicalOp::And => {
                for &dep_id in dependencies {
                    if !self.fast_results[dep_id as usize] {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            LogicalOp::Or => {
                for &dep_id in dependencies {
                    if self.fast_results[dep_id as usize] {
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
                Ok(!self.fast_results[dependencies[0] as usize])
            }
        }
    }

    /// Evaluate logical operation using HashMap storage.
    fn evaluate_logical_operation_with_hashmap(
        &self,
        op: LogicalOp,
        dependencies: &[u32],
    ) -> Result<bool> {
        match op {
            LogicalOp::And => {
                for &dep_id in dependencies {
                    let result = self.node_results.get(&dep_id).copied().ok_or_else(|| {
                        SigmaError::ExecutionError(format!(
                            "Dependency node {dep_id} not evaluated"
                        ))
                    })?;
                    if !result {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            LogicalOp::Or => {
                for &dep_id in dependencies {
                    let result = self.node_results.get(&dep_id).copied().ok_or_else(|| {
                        SigmaError::ExecutionError(format!(
                            "Dependency node {dep_id} not evaluated"
                        ))
                    })?;
                    if result {
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
                let result = self
                    .node_results
                    .get(&dependencies[0])
                    .copied()
                    .ok_or_else(|| {
                        SigmaError::ExecutionError(format!(
                            "Dependency node {} not evaluated",
                            dependencies[0]
                        ))
                    })?;
                Ok(!result)
            }
        }
    }

    /// Batch evaluation implementation with memory pooling.
    fn evaluate_batch_internal(&mut self, events: &[Value]) -> Result<Vec<DagEvaluationResult>> {
        let batch_size = events.len();
        let node_count = self.dag.nodes.len();
        let primitive_count = self.primitives.len();

        // Prepare memory pool
        self.batch_pool
            .resize_for_batch(batch_size, node_count, primitive_count);
        self.batch_pool.reset();
        self.nodes_evaluated = 0;
        self.primitive_evaluations = 0;

        // Phase 1: Evaluate all primitives for all events (vectorized)
        self.evaluate_primitives_batch(events)?;

        // Phase 2: Evaluate logical nodes using cached primitive results
        self.evaluate_logical_batch(events)?;

        // Phase 3: Collect final results for all events
        self.collect_batch_results(events)
    }

    /// Evaluate all primitives for all events in batch.
    fn evaluate_primitives_batch(&mut self, events: &[Value]) -> Result<()> {
        for (primitive_id, &node_id) in &self.dag.primitive_map {
            if let Some(primitive) = self.primitives.get(primitive_id) {
                for (event_idx, event) in events.iter().enumerate() {
                    let context = EventContext::new(event);
                    let result = primitive.matches(&context);
                    self.primitive_evaluations += 1;

                    // Store primitive result
                    if (*primitive_id as usize) < self.batch_pool.primitive_results.len() {
                        self.batch_pool.primitive_results[*primitive_id as usize][event_idx] =
                            result;
                    }

                    // Store node result (primitive nodes map directly)
                    if (node_id as usize) < self.batch_pool.node_results.len() {
                        self.batch_pool.node_results[node_id as usize][event_idx] = result;
                    }
                }
            }
        }
        Ok(())
    }

    /// Evaluate logical nodes for all events using cached primitive results.
    fn evaluate_logical_batch(&mut self, events: &[Value]) -> Result<()> {
        let execution_order = self.dag.execution_order.clone();

        for &node_id in &execution_order {
            let node = &self.dag.nodes[node_id as usize];

            if let NodeType::Logical { operation } = &node.node_type {
                for event_idx in 0..events.len() {
                    let result = self.evaluate_logical_operation_batch(
                        *operation,
                        &node.dependencies,
                        event_idx,
                    )?;

                    if (node_id as usize) < self.batch_pool.node_results.len() {
                        self.batch_pool.node_results[node_id as usize][event_idx] = result;
                    }
                    self.nodes_evaluated += 1;
                }
            }
        }
        Ok(())
    }

    /// Evaluate logical operation for a specific event in batch processing.
    fn evaluate_logical_operation_batch(
        &self,
        op: LogicalOp,
        dependencies: &[u32],
        event_idx: usize,
    ) -> Result<bool> {
        match op {
            LogicalOp::And => {
                for &dep_id in dependencies {
                    if (dep_id as usize) < self.batch_pool.node_results.len()
                        && !self.batch_pool.node_results[dep_id as usize][event_idx]
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            LogicalOp::Or => {
                for &dep_id in dependencies {
                    if (dep_id as usize) < self.batch_pool.node_results.len()
                        && self.batch_pool.node_results[dep_id as usize][event_idx]
                    {
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
                let dep_id = dependencies[0];
                if (dep_id as usize) < self.batch_pool.node_results.len() {
                    Ok(!self.batch_pool.node_results[dep_id as usize][event_idx])
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Collect final results for all events in batch processing.
    fn collect_batch_results(&mut self, events: &[Value]) -> Result<Vec<DagEvaluationResult>> {
        let mut results = Vec::with_capacity(events.len());

        for event_idx in 0..events.len() {
            let mut matched_rules = Vec::new();

            // Check which rules matched for this event
            for (&rule_id, &result_node_id) in &self.dag.rule_results {
                if (result_node_id as usize) < self.batch_pool.node_results.len()
                    && self.batch_pool.node_results[result_node_id as usize][event_idx]
                {
                    matched_rules.push(rule_id);
                }
            }

            results.push(DagEvaluationResult {
                matched_rules,
                nodes_evaluated: self.nodes_evaluated / events.len(), // Average per event
                primitive_evaluations: self.primitive_evaluations / events.len(),
            });
        }

        Ok(results)
    }

    /// Evaluate a single primitive for testing purposes.
    pub fn evaluate_primitive(&mut self, primitive_id: u32, event: &Value) -> Result<bool> {
        if let Some(primitive) = self.primitives.get(&primitive_id) {
            let context = EventContext::new(event);
            Ok(primitive.matches(&context))
        } else {
            Err(SigmaError::ExecutionError(format!(
                "Primitive {primitive_id} not found"
            )))
        }
    }

    /// Get prefilter performance statistics.
    pub fn prefilter_stats(&self) -> (usize, usize) {
        (self.prefilter_hits, self.prefilter_misses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::types::DagNode;
    use crate::ir::Primitive;
    use serde_json::json;

    fn create_test_dag() -> CompiledDag {
        let mut dag = CompiledDag::new();

        // Add primitive node
        let primitive_node = DagNode::new(0, NodeType::Primitive { primitive_id: 0 });
        dag.add_node(primitive_node);

        // Add logical node
        let mut logical_node = DagNode::new(
            1,
            NodeType::Logical {
                operation: LogicalOp::And,
            },
        );
        logical_node.add_dependency(0);
        dag.add_node(logical_node);

        dag.execution_order = vec![0, 1];
        dag.rule_results.insert(1, 1);
        dag.primitive_map.insert(0, 0);
        dag
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
    fn test_evaluator_config_default() {
        let config = EvaluatorConfig::default();
        assert_eq!(config.vec_storage_threshold, 32);
    }

    #[test]
    fn test_strategy_selection() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();
        let evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Single event with small DAG should use SingleVec
        assert_eq!(evaluator.select_strategy(1), EvaluationStrategy::SingleVec);

        // Multiple events should use Batch
        assert_eq!(evaluator.select_strategy(10), EvaluationStrategy::Batch);
    }

    #[test]
    fn test_batch_memory_pool() {
        let mut pool = BatchMemoryPool::new();
        pool.resize_for_batch(10, 5, 3);

        assert_eq!(pool.primitive_results.len(), 3);
        assert_eq!(pool.node_results.len(), 5);

        pool.reset();
        // Verify all buffers are reset
        for primitive_buffer in &pool.primitive_results {
            assert!(primitive_buffer.iter().all(|&x| !x));
        }
    }

    #[test]
    fn test_logical_operations_vec() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();
        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Test AND operation
        evaluator.fast_results[0] = true;
        evaluator.fast_results[1] = true;
        let result = evaluator
            .evaluate_logical_operation_with_vec(LogicalOp::And, &[0, 1])
            .unwrap();
        assert!(result);

        // Test OR operation
        evaluator.fast_results[0] = false;
        evaluator.fast_results[1] = true;
        let result = evaluator
            .evaluate_logical_operation_with_vec(LogicalOp::Or, &[0, 1])
            .unwrap();
        assert!(result);

        // Test NOT operation
        evaluator.fast_results[0] = false;
        let result = evaluator
            .evaluate_logical_operation_with_vec(LogicalOp::Not, &[0])
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_logical_operations_hashmap() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();
        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        // Test AND operation
        evaluator.node_results.insert(0, true);
        evaluator.node_results.insert(1, true);
        let result = evaluator
            .evaluate_logical_operation_with_hashmap(LogicalOp::And, &[0, 1])
            .unwrap();
        assert!(result);

        // Test OR operation
        evaluator.node_results.insert(0, false);
        evaluator.node_results.insert(1, true);
        let result = evaluator
            .evaluate_logical_operation_with_hashmap(LogicalOp::Or, &[0, 1])
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_empty_batch_evaluation() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();
        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        let events = Vec::new();
        let results = evaluator.evaluate_batch(&events).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_single_event_evaluation() {
        let dag = Arc::new(create_test_dag());
        let primitives = create_test_primitives();
        let mut evaluator = DagEvaluator::with_primitives(dag, primitives);

        let event = json!({"field1": "value1"});
        let result = evaluator.evaluate(&event);

        // Should not panic and return a result
        assert!(result.is_ok());
    }
}
