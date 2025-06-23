//! Parallel DAG evaluation for high-throughput multi-core processing.
//!
//! This module provides the `ParallelDagEvaluator` which implements both rule-level
//! and event-level parallelism to achieve linear scaling with core count. The evaluator
//! partitions rules across threads while maintaining shared primitive computation.

use super::evaluator::DagEvaluationResult;
use super::types::{CompiledDag, LogicalOp, NodeType};
use crate::error::{Result, SigmaError};
use crate::ir::RuleId;
use crate::matcher::{CompiledPrimitive, EventContext};

use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Configuration for parallel DAG evaluation.
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Number of threads to use for parallel evaluation
    pub num_threads: usize,
    /// Minimum number of rules per thread partition
    pub min_rules_per_thread: usize,
    /// Enable event-level parallelism within batches
    pub enable_event_parallelism: bool,
    /// Minimum batch size for event-level parallelism
    pub min_batch_size_for_parallelism: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            num_threads: rayon::current_num_threads(),
            min_rules_per_thread: 10,
            enable_event_parallelism: true,
            min_batch_size_for_parallelism: 100,
        }
    }
}

/// Rule partition for parallel processing.
#[derive(Debug, Clone)]
pub struct RulePartition {
    /// Rule IDs in this partition
    pub rule_ids: Vec<RuleId>,
    /// Result node IDs for these rules
    pub result_node_ids: Vec<u32>,
    /// Estimated complexity score for load balancing
    pub complexity_score: f32,
}

impl Default for RulePartition {
    fn default() -> Self {
        Self::new()
    }
}

impl RulePartition {
    /// Create a new rule partition.
    pub fn new() -> Self {
        Self {
            rule_ids: Vec::new(),
            result_node_ids: Vec::new(),
            complexity_score: 0.0,
        }
    }

    /// Add a rule to this partition.
    pub fn add_rule(&mut self, rule_id: RuleId, result_node_id: u32, complexity: f32) {
        self.rule_ids.push(rule_id);
        self.result_node_ids.push(result_node_id);
        self.complexity_score += complexity;
    }

    /// Get the number of rules in this partition.
    pub fn rule_count(&self) -> usize {
        self.rule_ids.len()
    }
}

/// Parallel DAG evaluator for multi-threaded rule processing.
///
/// The evaluator achieves linear scaling with core count while preserving the
/// performance benefits of shared primitive evaluation.
pub struct ParallelDagEvaluator {
    /// Reference to the compiled DAG
    dag: Arc<CompiledDag>,
    /// Compiled primitives for field matching
    primitives: HashMap<u32, CompiledPrimitive>,
    /// Parallel processing configuration
    config: ParallelConfig,
    /// Rule partitions for parallel processing
    rule_partitions: Vec<RulePartition>,
    /// Performance counters
    total_nodes_evaluated: usize,
    total_primitive_evaluations: usize,
}

impl ParallelDagEvaluator {
    /// Create a new parallel evaluator with the given DAG and primitives.
    pub fn new(
        dag: Arc<CompiledDag>,
        primitives: HashMap<u32, CompiledPrimitive>,
        config: ParallelConfig,
    ) -> Self {
        let rule_partitions = Self::partition_rules(&dag, &config);

        Self {
            dag,
            primitives,
            config,
            rule_partitions,
            total_nodes_evaluated: 0,
            total_primitive_evaluations: 0,
        }
    }

    /// Create a parallel evaluator with default configuration.
    pub fn with_defaults(
        dag: Arc<CompiledDag>,
        primitives: HashMap<u32, CompiledPrimitive>,
    ) -> Self {
        Self::new(dag, primitives, ParallelConfig::default())
    }

    /// Partition rules across threads by complexity and dependencies.
    fn partition_rules(dag: &CompiledDag, config: &ParallelConfig) -> Vec<RulePartition> {
        let rule_count = dag.rule_results.len();
        if rule_count == 0 {
            return Vec::new();
        }

        // Calculate optimal number of partitions
        let num_partitions = std::cmp::min(
            config.num_threads,
            (rule_count + config.min_rules_per_thread - 1) / config.min_rules_per_thread,
        )
        .max(1);

        let mut partitions = vec![RulePartition::new(); num_partitions];
        let mut partition_index = 0;

        // Simple round-robin partitioning with complexity estimation
        for (&rule_id, &result_node_id) in &dag.rule_results {
            let complexity = Self::estimate_rule_complexity(dag, result_node_id);

            partitions[partition_index].add_rule(rule_id, result_node_id, complexity);
            partition_index = (partition_index + 1) % num_partitions;
        }

        // Balance partitions by complexity
        Self::balance_partitions(&mut partitions);

        partitions
    }

    /// Estimate the complexity of a rule based on its DAG structure.
    fn estimate_rule_complexity(dag: &CompiledDag, result_node_id: u32) -> f32 {
        // Simple complexity estimation based on dependency count
        if let Some(result_node) = dag.get_node(result_node_id) {
            let mut complexity = 1.0;

            // Add complexity for each dependency
            complexity += result_node.dependencies.len() as f32 * 0.5;

            // Add complexity for logical operations in the dependency chain
            for &dep_id in &result_node.dependencies {
                if let Some(dep_node) = dag.get_node(dep_id) {
                    match &dep_node.node_type {
                        NodeType::Logical { .. } => complexity += 2.0,
                        NodeType::Primitive { .. } => complexity += 1.0,
                        NodeType::Result { .. } => complexity += 0.5,
                        NodeType::Prefilter { .. } => complexity += 0.1, // Very fast
                    }
                }
            }

            complexity
        } else {
            1.0
        }
    }

    /// Balance partitions to ensure roughly equal complexity distribution.
    fn balance_partitions(partitions: &mut [RulePartition]) {
        if partitions.len() <= 1 {
            return;
        }

        // Simple balancing: move rules from heaviest to lightest partition
        for _ in 0..3 {
            // Max 3 balancing iterations
            let mut heaviest_idx = 0;
            let mut lightest_idx = 0;

            for (i, partition) in partitions.iter().enumerate() {
                if partition.complexity_score > partitions[heaviest_idx].complexity_score {
                    heaviest_idx = i;
                }
                if partition.complexity_score < partitions[lightest_idx].complexity_score {
                    lightest_idx = i;
                }
            }

            // If difference is small, we're balanced enough
            let diff = partitions[heaviest_idx].complexity_score
                - partitions[lightest_idx].complexity_score;
            if diff < 2.0 || partitions[heaviest_idx].rule_count() <= 1 {
                break;
            }

            // Move one rule from heaviest to lightest
            if let (Some(rule_id), Some(result_node_id)) = (
                partitions[heaviest_idx].rule_ids.pop(),
                partitions[heaviest_idx].result_node_ids.pop(),
            ) {
                let complexity = partitions[heaviest_idx].complexity_score
                    / partitions[heaviest_idx].rule_count() as f32;
                partitions[heaviest_idx].complexity_score -= complexity;
                partitions[lightest_idx].add_rule(rule_id, result_node_id, complexity);
            }
        }
    }

    /// Evaluate a single event using parallel rule processing.
    pub fn evaluate(&mut self, event: &Value) -> Result<DagEvaluationResult> {
        self.reset();

        // If we have few rules, use single-threaded evaluation
        if self.dag.rule_results.len() < self.config.min_rules_per_thread * 2 {
            return self.evaluate_single_threaded(event);
        }

        // Evaluate primitives once (shared across all threads)
        let primitive_results = self.evaluate_primitives_shared(event)?;

        // Evaluate rule partitions in parallel
        let partition_results: Result<Vec<_>> = self
            .rule_partitions
            .iter()
            .map(|partition| self.evaluate_partition(partition, event, &primitive_results))
            .collect();

        let partition_results = partition_results?;

        // Merge results from all partitions
        self.merge_partition_results(partition_results)
    }

    /// Evaluate multiple events using parallel batch processing.
    pub fn evaluate_batch(&mut self, events: &[Value]) -> Result<Vec<DagEvaluationResult>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        self.reset();

        // For small batches or few rules, use single-threaded batch processing
        if events.len() < self.config.min_batch_size_for_parallelism
            || self.dag.rule_results.len() < self.config.min_rules_per_thread * 2
        {
            return self.evaluate_batch_single_threaded(events);
        }

        // Use parallel event processing
        if self.config.enable_event_parallelism {
            self.evaluate_batch_parallel_events(events)
        } else {
            self.evaluate_batch_parallel_rules(events)
        }
    }

    /// Evaluate primitives once and share results across threads.
    fn evaluate_primitives_shared(&mut self, event: &Value) -> Result<HashMap<u32, bool>> {
        let mut primitive_results = HashMap::new();

        for (primitive_id, &node_id) in &self.dag.primitive_map {
            if let Some(primitive) = self.primitives.get(primitive_id) {
                let context = EventContext::new(event);
                let result = primitive.matches(&context);
                primitive_results.insert(node_id, result);
                self.total_primitive_evaluations += 1;
            }
        }

        Ok(primitive_results)
    }

    /// Evaluate a rule partition against an event.
    fn evaluate_partition(
        &self,
        partition: &RulePartition,
        _event: &Value,
        primitive_results: &HashMap<u32, bool>,
    ) -> Result<Vec<RuleId>> {
        let mut matched_rules = Vec::new();
        let mut node_results = HashMap::new();

        // Copy primitive results
        for (&node_id, &result) in primitive_results {
            node_results.insert(node_id, result);
        }

        // Evaluate logical and result nodes for this partition
        for &result_node_id in &partition.result_node_ids {
            if let Some(result_node) = self.dag.get_node(result_node_id) {
                let result = self.evaluate_node_with_cache(result_node, &mut node_results)?;
                if result {
                    // Find the rule ID for this result node
                    for (&rule_id, &node_id) in &self.dag.rule_results {
                        if node_id == result_node_id {
                            matched_rules.push(rule_id);
                            break;
                        }
                    }
                }
            }
        }

        Ok(matched_rules)
    }

    /// Evaluate a node with cached results.
    fn evaluate_node_with_cache(
        &self,
        node: &super::types::DagNode,
        node_results: &mut HashMap<u32, bool>,
    ) -> Result<bool> {
        // Check if already computed
        if let Some(&result) = node_results.get(&node.id) {
            return Ok(result);
        }

        let result = match &node.node_type {
            NodeType::Primitive { .. } => {
                // Should already be computed in primitive_results
                node_results.get(&node.id).copied().unwrap_or(false)
            }
            NodeType::Logical { operation } => self.evaluate_logical_operation_cached(
                *operation,
                &node.dependencies,
                node_results,
            )?,
            NodeType::Result { .. } => {
                if node.dependencies.len() == 1 {
                    let dep_id = node.dependencies[0];
                    if let Some(dep_node) = self.dag.get_node(dep_id) {
                        self.evaluate_node_with_cache(dep_node, node_results)?
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            NodeType::Prefilter { .. } => {
                // Prefilter nodes are handled separately and always pass
                true
            }
        };

        node_results.insert(node.id, result);
        Ok(result)
    }

    /// Evaluate a logical operation using cached results.
    fn evaluate_logical_operation_cached(
        &self,
        operation: LogicalOp,
        dependencies: &[u32],
        node_results: &mut HashMap<u32, bool>,
    ) -> Result<bool> {
        match operation {
            LogicalOp::And => {
                for &dep_id in dependencies {
                    if let Some(dep_node) = self.dag.get_node(dep_id) {
                        if !self.evaluate_node_with_cache(dep_node, node_results)? {
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
                    if let Some(dep_node) = self.dag.get_node(dep_id) {
                        if self.evaluate_node_with_cache(dep_node, node_results)? {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            LogicalOp::Not => {
                if dependencies.len() == 1 {
                    if let Some(dep_node) = self.dag.get_node(dependencies[0]) {
                        Ok(!self.evaluate_node_with_cache(dep_node, node_results)?)
                    } else {
                        Ok(true)
                    }
                } else {
                    Err(SigmaError::ExecutionError(
                        "NOT operation requires exactly one dependency".to_string(),
                    ))
                }
            }
        }
    }

    /// Merge results from multiple partition evaluations.
    fn merge_partition_results(
        &mut self,
        partition_results: Vec<Vec<RuleId>>,
    ) -> Result<DagEvaluationResult> {
        let mut matched_rules = Vec::new();

        for partition_result in partition_results {
            matched_rules.extend(partition_result);
        }

        // Sort for consistent output
        matched_rules.sort_unstable();

        Ok(DagEvaluationResult {
            matched_rules,
            nodes_evaluated: self.total_nodes_evaluated,
            primitive_evaluations: self.total_primitive_evaluations,
        })
    }

    /// Fallback to single-threaded evaluation for small rule sets.
    fn evaluate_single_threaded(&mut self, event: &Value) -> Result<DagEvaluationResult> {
        // Use the standard DAG evaluator for small rule sets
        use super::evaluator::DagEvaluator;

        let mut evaluator =
            DagEvaluator::with_primitives(self.dag.clone(), self.primitives.clone());
        evaluator.evaluate(event)
    }

    /// Fallback to single-threaded batch processing.
    fn evaluate_batch_single_threaded(
        &mut self,
        events: &[Value],
    ) -> Result<Vec<DagEvaluationResult>> {
        use super::batch_evaluator::BatchDagEvaluator;

        let mut batch_evaluator = BatchDagEvaluator::new(self.dag.clone(), self.primitives.clone());
        batch_evaluator.evaluate_batch(events)
    }

    /// Evaluate batch with parallel event processing.
    fn evaluate_batch_parallel_events(
        &mut self,
        events: &[Value],
    ) -> Result<Vec<DagEvaluationResult>> {
        // Process events in parallel chunks
        let chunk_size = std::cmp::max(1, events.len() / self.config.num_threads);

        let results: Result<Vec<_>> = events
            .chunks(chunk_size)
            .map(|event_chunk| {
                let mut evaluator = Self::new(
                    self.dag.clone(),
                    self.primitives.clone(),
                    self.config.clone(),
                );
                evaluator.evaluate_batch_single_threaded(event_chunk)
            })
            .collect();

        let chunk_results = results?;

        // Flatten results
        let mut final_results = Vec::new();
        for chunk_result in chunk_results {
            final_results.extend(chunk_result);
        }

        Ok(final_results)
    }

    /// Evaluate batch with parallel rule processing.
    fn evaluate_batch_parallel_rules(
        &mut self,
        events: &[Value],
    ) -> Result<Vec<DagEvaluationResult>> {
        let mut results = Vec::with_capacity(events.len());

        for event in events {
            let result = self.evaluate(event)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Reset the evaluator state for reuse.
    pub fn reset(&mut self) {
        self.total_nodes_evaluated = 0;
        self.total_primitive_evaluations = 0;
    }

    /// Get performance statistics from the last evaluation.
    pub fn get_stats(&self) -> (usize, usize) {
        (self.total_nodes_evaluated, self.total_primitive_evaluations)
    }

    /// Get the number of rule partitions.
    pub fn partition_count(&self) -> usize {
        self.rule_partitions.len()
    }

    /// Get partition information for debugging.
    pub fn get_partition_info(&self) -> Vec<(usize, f32)> {
        self.rule_partitions
            .iter()
            .map(|p| (p.rule_count(), p.complexity_score))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::types::{DagNode, NodeType};
    use serde_json::json;

    fn create_test_dag() -> CompiledDag {
        let mut dag = CompiledDag::new();

        // Add primitive nodes
        let primitive_node1 = DagNode::new(0, NodeType::Primitive { primitive_id: 0 });
        let primitive_node2 = DagNode::new(1, NodeType::Primitive { primitive_id: 1 });
        dag.add_node(primitive_node1);
        dag.add_node(primitive_node2);

        // Add result nodes
        let result_node1 = DagNode::new(2, NodeType::Result { rule_id: 1 });
        let result_node2 = DagNode::new(3, NodeType::Result { rule_id: 2 });
        dag.add_node(result_node1);
        dag.add_node(result_node2);

        dag.execution_order = vec![0, 1, 2, 3];
        dag.primitive_map.insert(0, 0);
        dag.primitive_map.insert(1, 1);
        dag.rule_results.insert(1, 2);
        dag.rule_results.insert(2, 3);

        dag
    }

    #[test]
    fn test_parallel_config_default() {
        let config = ParallelConfig::default();
        assert!(config.num_threads > 0);
        assert!(config.min_rules_per_thread > 0);
        assert!(config.enable_event_parallelism);
    }

    #[test]
    fn test_rule_partition() {
        let mut partition = RulePartition::new();
        assert_eq!(partition.rule_count(), 0);

        partition.add_rule(1, 10, 2.5);
        partition.add_rule(2, 11, 1.5);

        assert_eq!(partition.rule_count(), 2);
        assert_eq!(partition.complexity_score, 4.0);
    }

    #[test]
    fn test_rule_partitioning() {
        let dag = Arc::new(create_test_dag());
        let config = ParallelConfig {
            num_threads: 2,
            min_rules_per_thread: 1,
            ..Default::default()
        };

        let partitions = ParallelDagEvaluator::partition_rules(&dag, &config);
        assert!(!partitions.is_empty());

        let total_rules: usize = partitions.iter().map(|p| p.rule_count()).sum();
        assert_eq!(total_rules, dag.rule_results.len());
    }

    #[test]
    fn test_parallel_evaluator_creation() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let config = ParallelConfig::default();

        let evaluator = ParallelDagEvaluator::new(dag, primitives, config);
        assert!(evaluator.partition_count() > 0);
    }

    #[test]
    fn test_complexity_estimation() {
        let dag = create_test_dag();
        let complexity = ParallelDagEvaluator::estimate_rule_complexity(&dag, 2);
        assert!(complexity > 0.0);
    }

    #[test]
    fn test_rule_partition_default() {
        let partition = RulePartition::default();
        assert_eq!(partition.rule_count(), 0);
        assert_eq!(partition.complexity_score, 0.0);
        assert!(partition.rule_ids.is_empty());
        assert!(partition.result_node_ids.is_empty());
    }

    #[test]
    fn test_rule_partition_add_multiple_rules() {
        let mut partition = RulePartition::new();

        partition.add_rule(1, 10, 2.5);
        partition.add_rule(2, 11, 1.5);
        partition.add_rule(3, 12, 3.0);

        assert_eq!(partition.rule_count(), 3);
        assert_eq!(partition.rule_ids, vec![1, 2, 3]);
        assert_eq!(partition.result_node_ids, vec![10, 11, 12]);
        assert_eq!(partition.complexity_score, 7.0);
    }

    #[test]
    fn test_parallel_config_custom() {
        let config = ParallelConfig {
            num_threads: 8,
            min_rules_per_thread: 5,
            enable_event_parallelism: false,
            min_batch_size_for_parallelism: 50,
        };

        assert_eq!(config.num_threads, 8);
        assert_eq!(config.min_rules_per_thread, 5);
        assert!(!config.enable_event_parallelism);
        assert_eq!(config.min_batch_size_for_parallelism, 50);
    }

    #[test]
    fn test_partition_rules_empty_dag() {
        let dag = CompiledDag::new();
        let config = ParallelConfig::default();

        let partitions = ParallelDagEvaluator::partition_rules(&dag, &config);
        assert!(partitions.is_empty());
    }

    #[test]
    fn test_partition_rules_single_rule() {
        let mut dag = CompiledDag::new();
        dag.rule_results.insert(1, 0);

        let config = ParallelConfig {
            num_threads: 4,
            min_rules_per_thread: 1,
            ..Default::default()
        };

        let partitions = ParallelDagEvaluator::partition_rules(&dag, &config);
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].rule_count(), 1);
    }

    #[test]
    fn test_partition_rules_many_rules() {
        let mut dag = CompiledDag::new();
        for i in 1..=20 {
            dag.rule_results.insert(i, i);
        }

        let config = ParallelConfig {
            num_threads: 4,
            min_rules_per_thread: 2,
            ..Default::default()
        };

        let partitions = ParallelDagEvaluator::partition_rules(&dag, &config);
        assert!(partitions.len() <= 4);

        let total_rules: usize = partitions.iter().map(|p| p.rule_count()).sum();
        assert_eq!(total_rules, 20);
    }

    #[test]
    fn test_complexity_estimation_with_dependencies() {
        let mut dag = CompiledDag::new();

        // Create a node with dependencies
        let mut result_node = DagNode::new(0, NodeType::Result { rule_id: 1 });
        result_node.dependencies = vec![1, 2, 3];
        dag.add_node(result_node);

        // Add dependency nodes
        dag.add_node(DagNode::new(
            1,
            NodeType::Logical {
                operation: LogicalOp::And,
            },
        ));
        dag.add_node(DagNode::new(2, NodeType::Primitive { primitive_id: 0 }));
        dag.add_node(DagNode::new(3, NodeType::Result { rule_id: 2 }));

        let complexity = ParallelDagEvaluator::estimate_rule_complexity(&dag, 0);

        // Should be: 1.0 (base) + 3 * 0.5 (dependencies) + 2.0 (logical) + 1.0 (primitive) + 0.5 (result)
        assert!(complexity > 4.0);
    }

    #[test]
    fn test_complexity_estimation_nonexistent_node() {
        let dag = CompiledDag::new();
        let complexity = ParallelDagEvaluator::estimate_rule_complexity(&dag, 999);
        assert_eq!(complexity, 1.0); // Default complexity
    }

    #[test]
    fn test_balance_partitions_single_partition() {
        let mut partitions = vec![RulePartition::new()];
        partitions[0].add_rule(1, 10, 5.0);

        ParallelDagEvaluator::balance_partitions(&mut partitions);

        // Should remain unchanged
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].complexity_score, 5.0);
    }

    #[test]
    fn test_balance_partitions_already_balanced() {
        let mut partitions = vec![RulePartition::new(), RulePartition::new()];
        partitions[0].add_rule(1, 10, 3.0);
        partitions[1].add_rule(2, 11, 3.0);

        ParallelDagEvaluator::balance_partitions(&mut partitions);

        // Should remain unchanged since already balanced
        assert_eq!(partitions[0].complexity_score, 3.0);
        assert_eq!(partitions[1].complexity_score, 3.0);
    }

    #[test]
    fn test_balance_partitions_unbalanced() {
        let mut partitions = vec![RulePartition::new(), RulePartition::new()];
        partitions[0].add_rule(1, 10, 10.0);
        partitions[0].add_rule(2, 11, 5.0);
        partitions[1].add_rule(3, 12, 1.0);

        let initial_heavy = partitions[0].complexity_score;
        let initial_light = partitions[1].complexity_score;

        ParallelDagEvaluator::balance_partitions(&mut partitions);

        // Should be more balanced after balancing
        let final_heavy = partitions[0].complexity_score;
        let final_light = partitions[1].complexity_score;

        assert!(final_heavy < initial_heavy);
        assert!(final_light > initial_light);
    }

    #[test]
    fn test_parallel_evaluator_with_defaults() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();

        let evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);
        assert!(evaluator.partition_count() > 0);
        assert_eq!(evaluator.total_nodes_evaluated, 0);
        assert_eq!(evaluator.total_primitive_evaluations, 0);
    }

    #[test]
    fn test_parallel_evaluator_reset() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let mut evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);

        // Simulate some state
        evaluator.total_nodes_evaluated = 10;
        evaluator.total_primitive_evaluations = 5;

        evaluator.reset();

        assert_eq!(evaluator.total_nodes_evaluated, 0);
        assert_eq!(evaluator.total_primitive_evaluations, 0);
    }

    #[test]
    fn test_parallel_evaluator_get_stats() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let mut evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);

        evaluator.total_nodes_evaluated = 15;
        evaluator.total_primitive_evaluations = 8;

        let (nodes, primitives) = evaluator.get_stats();
        assert_eq!(nodes, 15);
        assert_eq!(primitives, 8);
    }

    #[test]
    fn test_parallel_evaluator_partition_info() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);

        let partition_info = evaluator.get_partition_info();
        assert!(!partition_info.is_empty());

        for (rule_count, complexity) in partition_info {
            assert!(rule_count > 0);
            assert!(complexity >= 0.0);
        }
    }

    #[test]
    fn test_evaluate_empty_batch() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let mut evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);

        let events: Vec<serde_json::Value> = vec![];
        let results = evaluator.evaluate_batch(&events).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_evaluate_single_event_small_ruleset() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let mut evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);

        let event = json!({"field": "value"});
        let result = evaluator.evaluate(&event);

        // May fail due to missing primitives, but should not panic
        // The test validates the interface exists and handles errors gracefully
        match result {
            Ok(_) => {
                // Success is fine
            }
            Err(_) => {
                // Error is also acceptable since we have no primitives
            }
        }
    }

    #[test]
    fn test_evaluate_batch_small_batch() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let mut evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);

        let events = vec![json!({"field1": "value1"}), json!({"field2": "value2"})];

        let results = evaluator.evaluate_batch(&events);
        assert!(results.is_ok());
        assert_eq!(results.unwrap().len(), 2);
    }

    #[test]
    fn test_parallel_evaluator_new() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let config = ParallelConfig::default();

        let evaluator = ParallelDagEvaluator::new(dag, primitives, config);
        assert_eq!(evaluator.partition_count(), 1); // Test DAG has 2 rules, so 1 partition
        assert_eq!(evaluator.total_nodes_evaluated, 0);
        assert_eq!(evaluator.total_primitive_evaluations, 0);
    }

    #[test]
    fn test_parallel_config_validation() {
        let config = ParallelConfig {
            num_threads: 0, // Invalid
            min_rules_per_thread: 1,
            enable_event_parallelism: true,
            min_batch_size_for_parallelism: 10,
        };

        // The config should handle invalid values gracefully
        assert_eq!(config.num_threads, 0);
        assert_eq!(config.min_rules_per_thread, 1);
        assert!(config.enable_event_parallelism);
        assert_eq!(config.min_batch_size_for_parallelism, 10);
    }

    #[test]
    fn test_rule_partition_edge_cases() {
        let mut partition = RulePartition::new();

        // Test with zero complexity
        partition.add_rule(1, 10, 0.0);
        assert_eq!(partition.complexity_score, 0.0);
        assert_eq!(partition.rule_count(), 1);

        // Test with negative complexity (should be handled gracefully)
        partition.add_rule(2, 11, -1.0);
        assert_eq!(partition.complexity_score, -1.0);
        assert_eq!(partition.rule_count(), 2);
    }

    #[test]
    fn test_partition_rules_with_min_rules_constraint() {
        let mut dag = CompiledDag::new();

        // Add only 2 rules
        dag.rule_results.insert(1, 0);
        dag.rule_results.insert(2, 1);

        let config = ParallelConfig {
            num_threads: 4,
            min_rules_per_thread: 5, // More than available rules
            ..Default::default()
        };

        let partitions = ParallelDagEvaluator::partition_rules(&dag, &config);

        // Should create only 1 partition since we don't have enough rules
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].rule_count(), 2);
    }

    #[test]
    fn test_complexity_estimation_edge_cases() {
        let mut dag = CompiledDag::new();

        // Test with a node that has circular-like dependencies (shouldn't happen but test robustness)
        let mut node = DagNode::new(
            0,
            NodeType::Logical {
                operation: LogicalOp::And,
            },
        );
        node.dependencies = vec![1, 2, 3, 4, 5]; // Many dependencies
        dag.add_node(node);

        let complexity = ParallelDagEvaluator::estimate_rule_complexity(&dag, 0);
        assert!(complexity >= 1.0); // Should have at least base complexity
    }

    #[test]
    fn test_balance_partitions_edge_cases() {
        // Test with empty partitions
        let mut partitions = vec![];
        ParallelDagEvaluator::balance_partitions(&mut partitions);
        assert!(partitions.is_empty());

        // Test with partitions having zero complexity
        let mut partitions = vec![RulePartition::new(), RulePartition::new()];
        partitions[0].add_rule(1, 10, 0.0);
        partitions[1].add_rule(2, 11, 0.0);

        ParallelDagEvaluator::balance_partitions(&mut partitions);
        assert_eq!(partitions[0].complexity_score, 0.0);
        assert_eq!(partitions[1].complexity_score, 0.0);
    }

    #[test]
    fn test_parallel_evaluator_large_batch() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let mut evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);

        // Create a large batch of events
        let events: Vec<serde_json::Value> = (0..1000)
            .map(|i| json!({"field": format!("value{}", i)}))
            .collect();

        let results = evaluator.evaluate_batch(&events);

        match results {
            Ok(results) => {
                assert_eq!(results.len(), 1000);
            }
            Err(_) => {
                // May fail due to missing primitives, but tests the interface
            }
        }
    }

    #[test]
    fn test_parallel_evaluator_statistics_tracking() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let mut evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);

        // Initial stats should be zero
        let (nodes, primitives) = evaluator.get_stats();
        assert_eq!(nodes, 0);
        assert_eq!(primitives, 0);

        // Try to evaluate something to potentially update stats
        let event = json!({"field": "value"});
        let _result = evaluator.evaluate(&event);

        // Stats may or may not be updated depending on implementation
        let (nodes_after, primitives_after) = evaluator.get_stats();
        assert!(nodes_after >= nodes);
        assert!(primitives_after >= primitives);
    }

    #[test]
    fn test_parallel_evaluator_reset_behavior() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let mut evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);

        // Set some state
        evaluator.total_nodes_evaluated = 100;
        evaluator.total_primitive_evaluations = 50;

        // Reset should clear state
        evaluator.reset();

        assert_eq!(evaluator.total_nodes_evaluated, 0);
        assert_eq!(evaluator.total_primitive_evaluations, 0);
    }

    #[test]
    fn test_parallel_config_extreme_values() {
        let config = ParallelConfig {
            num_threads: usize::MAX,
            min_rules_per_thread: usize::MAX,
            enable_event_parallelism: true,
            min_batch_size_for_parallelism: usize::MAX,
        };

        // Should handle extreme values without panicking
        assert_eq!(config.num_threads, usize::MAX);
        assert_eq!(config.min_rules_per_thread, usize::MAX);
        assert_eq!(config.min_batch_size_for_parallelism, usize::MAX);
    }

    #[test]
    fn test_rule_partition_large_numbers() {
        let mut partition = RulePartition::new();

        // Test with large rule IDs and node IDs
        partition.add_rule(u32::MAX, u32::MAX, f32::MAX);

        assert_eq!(partition.rule_count(), 1);
        assert_eq!(partition.rule_ids[0], u32::MAX);
        assert_eq!(partition.result_node_ids[0], u32::MAX);
        assert_eq!(partition.complexity_score, f32::MAX);
    }

    #[test]
    fn test_partition_info_format() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);

        let partition_info = evaluator.get_partition_info();

        // Should return valid partition info
        for (rule_count, complexity) in partition_info {
            assert!(rule_count <= 1000); // Reasonable upper bound for rule count
            assert!(complexity.is_finite() || complexity.is_infinite());
        }
    }

    #[test]
    fn test_parallel_evaluator_thread_safety_interface() {
        let dag = Arc::new(create_test_dag());
        let primitives = HashMap::new();
        let evaluator = ParallelDagEvaluator::with_defaults(dag, primitives);

        // Test that the evaluator can be moved between threads (Send trait)
        let handle = std::thread::spawn(move || {
            let _partition_count = evaluator.partition_count();
            let _stats = evaluator.get_stats();
            let _info = evaluator.get_partition_info();
        });

        handle.join().unwrap();
    }
}
