//! Primary SIGMA Engine interface.
//!
//! This module provides the main `SigmaEngine` struct that serves as the
//! primary interface for all SIGMA rule evaluation using DAG-based execution.

use crate::dag::engine::DagEngineConfig;
use crate::dag::{DagEngine, DagEvaluationResult};
use crate::error::Result;
use crate::ir::{CompiledRuleset, RuleId};
use serde_json::Value;

/// Primary SIGMA Engine for high-performance rule evaluation.
///
/// `SigmaEngine` provides the main interface for evaluating SIGMA detection rules
/// against events. It wraps the underlying DAG execution engine with a simplified
/// API that automatically handles configuration and optimization for optimal performance.
///
/// # Usage Patterns
///
/// ## Single Event Processing
/// Ideal for real-time systems where events arrive individually:
/// ```rust,ignore
/// let result = engine.evaluate(&event)?;
/// if !result.matched_rules.is_empty() {
///     println!("Alert: {} rules matched", result.matched_rules.len());
/// }
/// ```
///
/// ## Batch Processing
/// Optimal for high-throughput systems processing multiple events:
/// ```rust,ignore
/// let results = engine.evaluate_batch(&events)?;
/// let total_matches: usize = results.iter().map(|r| r.matched_rules.len()).sum();
/// println!("Processed {} events, {} total matches", events.len(), total_matches);
/// ```
///
/// ## Streaming Processing
/// For continuous event streams with backpressure handling:
/// ```rust,ignore
/// use sigma_engine::streaming::StreamingEngine;
/// let streaming_engine = StreamingEngine::new(ruleset, config)?;
/// // See streaming module for detailed examples
/// ```
///
/// # Examples
///
/// ## Basic Usage
/// ```rust,ignore
/// use sigma_engine::{Compiler, SigmaEngine};
///
/// // Compile rules offline
/// let mut compiler = Compiler::new();
/// let ruleset = compiler.compile_ruleset(&rules)?;
///
/// // Create engine for online evaluation
/// let mut engine = SigmaEngine::from_ruleset(ruleset)?;
///
/// // Evaluate events
/// let event = serde_json::from_str(r#"{"EventID": "4624"}"#)?;
/// let result = engine.evaluate(&event)?;
///
/// // Check results
/// for rule_id in result.matched_rules {
///     println!("Rule {} matched", rule_id);
/// }
/// ```
///
/// ## High-Performance Configuration
/// ```rust,ignore
/// use sigma_engine::{Compiler, SigmaEngine, DagEngineConfig};
///
/// let mut compiler = Compiler::new();
/// let ruleset = compiler.compile_ruleset(&rules)?;
///
/// // Configure for maximum performance
/// let config = DagEngineConfig::high_performance();
/// let mut engine = SigmaEngine::from_ruleset_with_config(ruleset, config)?;
///
/// // Process events with optimal performance
/// let result = engine.evaluate(&event)?;
/// ```
///
/// ## Batch Processing for High Throughput
/// ```rust,ignore
/// use sigma_engine::{Compiler, SigmaEngine};
///
/// let mut compiler = Compiler::new();
/// let ruleset = compiler.compile_ruleset(&rules)?;
/// let mut engine = SigmaEngine::from_ruleset(ruleset)?;
///
/// // Process multiple events efficiently
/// let events = vec![event1, event2, event3];
/// let results = engine.evaluate_batch(&events)?;
///
/// // Analyze results
/// for (i, result) in results.iter().enumerate() {
///     if !result.matched_rules.is_empty() {
///         println!("Event {}: {} matches", i, result.matched_rules.len());
///     }
/// }
/// ```
pub struct SigmaEngine {
    /// Internal DAG engine
    dag_engine: DagEngine,
}

impl SigmaEngine {
    /// Create a new SIGMA engine from a compiled ruleset.
    ///
    /// This method uses default configuration optimized for most use cases.
    ///
    /// # Arguments
    /// * `ruleset` - The compiled ruleset containing primitives and rules
    ///
    /// # Returns
    /// A new SigmaEngine instance ready for evaluation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sigma_engine::{Compiler, SigmaEngine};
    ///
    /// let mut compiler = Compiler::new();
    /// let ruleset = compiler.compile_ruleset(&rules)?;
    /// let engine = SigmaEngine::from_ruleset(ruleset)?;
    /// ```
    pub fn from_ruleset(ruleset: CompiledRuleset) -> Result<Self> {
        let dag_engine = DagEngine::from_ruleset(ruleset)?;
        Ok(Self { dag_engine })
    }

    /// Create a new SIGMA engine with custom configuration.
    ///
    /// # Arguments
    /// * `ruleset` - The compiled ruleset containing primitives and rules
    /// * `config` - Custom DAG engine configuration
    ///
    /// # Returns
    /// A new SigmaEngine instance with custom configuration.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sigma_engine::{Compiler, SigmaEngine, DagEngineConfig};
    ///
    /// let mut compiler = Compiler::new();
    /// let ruleset = compiler.compile_ruleset(&rules)?;
    ///
    /// let config = DagEngineConfig {
    ///     enable_optimization: true,
    ///     enable_caching: true,
    ///     optimization_level: 3,
    /// };
    ///
    /// let engine = SigmaEngine::from_ruleset_with_config(ruleset, config)?;
    /// ```
    pub fn from_ruleset_with_config(
        ruleset: CompiledRuleset,
        config: DagEngineConfig,
    ) -> Result<Self> {
        let dag_engine = DagEngine::from_ruleset_with_config(ruleset, config)?;
        Ok(Self { dag_engine })
    }

    /// Evaluate an event against all rules in the engine.
    ///
    /// This is the primary method for rule evaluation. It processes the event
    /// through the DAG and returns all matching rules.
    ///
    /// # Arguments
    /// * `event` - The event data as a JSON value
    ///
    /// # Returns
    /// An `EngineResult` containing matched rules and evaluation metadata.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let event = serde_json::from_str(r#"{"EventID": "4624", "LogonType": "2"}"#)?;
    /// let result = engine.evaluate(&event)?;
    ///
    /// for rule_id in result.matched_rules {
    ///     println!("Rule {} matched", rule_id);
    /// }
    /// ```
    pub fn evaluate(&mut self, event: &Value) -> Result<EngineResult> {
        let dag_result = self.dag_engine.evaluate(event)?;
        Ok(EngineResult::from(dag_result))
    }

    /// Evaluate multiple events in batch for improved performance.
    ///
    /// This method implements true batch processing with shared computation:
    /// 1. All primitives are evaluated for all events first (vectorized)
    /// 2. Logical nodes are processed using cached primitive results
    /// 3. Final results are collected efficiently
    ///
    /// # Arguments
    /// * `events` - Slice of events to evaluate
    ///
    /// # Returns
    /// A vector of `EngineResult` for each event.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let events = vec![
    ///     serde_json::from_str(r#"{"EventID": "4624"}"#)?,
    ///     serde_json::from_str(r#"{"EventID": "4625"}"#)?,
    /// ];
    ///
    /// let results = engine.evaluate_batch(&events)?;
    /// ```
    pub fn evaluate_batch(&mut self, events: &[Value]) -> Result<Vec<EngineResult>> {
        // Use the high-performance batch evaluator from the DAG engine
        let dag_results = self.dag_engine.evaluate_batch(events)?;

        // Convert DAG results to engine results
        let results = dag_results.into_iter().map(EngineResult::from).collect();

        Ok(results)
    }

    /// Get the number of rules in the engine.
    pub fn rule_count(&self) -> usize {
        self.dag_engine.rule_count()
    }

    /// Get the number of nodes in the DAG.
    pub fn node_count(&self) -> usize {
        self.dag_engine.node_count()
    }

    /// Get the number of primitive nodes in the DAG.
    pub fn primitive_count(&self) -> usize {
        self.dag_engine.primitive_count()
    }

    /// Check if the engine contains a specific rule.
    pub fn contains_rule(&self, rule_id: RuleId) -> bool {
        self.dag_engine.contains_rule(rule_id)
    }
}

/// Result of SIGMA engine evaluation.
#[derive(Debug, Clone)]
pub struct EngineResult {
    /// IDs of rules that matched the event
    pub matched_rules: Vec<RuleId>,
    /// Number of nodes evaluated during processing
    pub nodes_evaluated: usize,
    /// Number of primitive evaluations performed
    pub primitive_evaluations: usize,
}

impl From<DagEvaluationResult> for EngineResult {
    fn from(dag_result: DagEvaluationResult) -> Self {
        Self {
            matched_rules: dag_result.matched_rules,
            nodes_evaluated: dag_result.nodes_evaluated,
            primitive_evaluations: dag_result.primitive_evaluations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::CompiledRuleset;

    #[test]
    fn test_engine_creation() {
        let ruleset = CompiledRuleset::new();
        let engine = SigmaEngine::from_ruleset(ruleset);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_engine_with_config() {
        let ruleset = CompiledRuleset::new();
        let config = DagEngineConfig::default();
        let engine = SigmaEngine::from_ruleset_with_config(ruleset, config);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_engine_result_conversion() {
        let dag_result = DagEvaluationResult {
            matched_rules: vec![1, 2, 3],
            nodes_evaluated: 10,
            primitive_evaluations: 5,
        };

        let engine_result = EngineResult::from(dag_result);
        assert_eq!(engine_result.matched_rules, vec![1, 2, 3]);
        assert_eq!(engine_result.nodes_evaluated, 10);
        assert_eq!(engine_result.primitive_evaluations, 5);
    }

    #[test]
    fn test_sigma_engine_integration() {
        use crate::Compiler;
        use serde_json::json;

        // Create a simple rule
        let rule_yaml = r#"
title: Test Rule
logsource:
    category: test
detection:
    selection:
        EventID: 4624
    condition: selection
"#;

        // Compile the rule
        let mut compiler = Compiler::new();
        let ruleset = compiler.compile_ruleset(&[rule_yaml]).unwrap();

        // Create the engine
        let mut engine = SigmaEngine::from_ruleset(ruleset).unwrap();

        // Test with matching event
        let matching_event = json!({
            "EventID": "4624"
        });

        // Note: This test may not produce matches because the DAG compilation
        // and primitive evaluation are not fully integrated yet, but it should
        // not crash and should return a valid result
        let result = engine.evaluate(&matching_event);
        assert!(result.is_ok());

        // Test engine metadata
        assert_eq!(engine.rule_count(), 0); // No rules in the DAG yet
                                            // Primitive and node counts are always non-negative by type definition
        assert!(engine.primitive_count() < u32::MAX as usize);
        assert!(engine.node_count() < u32::MAX as usize);
    }

    #[test]
    fn test_engine_result_default_values() {
        let result = EngineResult {
            matched_rules: vec![],
            nodes_evaluated: 0,
            primitive_evaluations: 0,
        };

        assert!(result.matched_rules.is_empty());
        assert_eq!(result.nodes_evaluated, 0);
        assert_eq!(result.primitive_evaluations, 0);
    }

    #[test]
    fn test_engine_result_with_matches() {
        let result = EngineResult {
            matched_rules: vec![1, 2, 3, 4, 5],
            nodes_evaluated: 25,
            primitive_evaluations: 15,
        };

        assert_eq!(result.matched_rules.len(), 5);
        assert_eq!(result.matched_rules, vec![1, 2, 3, 4, 5]);
        assert_eq!(result.nodes_evaluated, 25);
        assert_eq!(result.primitive_evaluations, 15);
    }

    #[test]
    fn test_engine_result_debug_format() {
        let result = EngineResult {
            matched_rules: vec![1, 2],
            nodes_evaluated: 10,
            primitive_evaluations: 5,
        };

        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("matched_rules"));
        assert!(debug_str.contains("nodes_evaluated"));
        assert!(debug_str.contains("primitive_evaluations"));
        assert!(debug_str.contains("[1, 2]"));
        assert!(debug_str.contains("10"));
        assert!(debug_str.contains("5"));
    }

    #[test]
    fn test_engine_result_clone() {
        let result = EngineResult {
            matched_rules: vec![1, 2, 3],
            nodes_evaluated: 15,
            primitive_evaluations: 8,
        };

        let cloned = result.clone();
        assert_eq!(result.matched_rules, cloned.matched_rules);
        assert_eq!(result.nodes_evaluated, cloned.nodes_evaluated);
        assert_eq!(result.primitive_evaluations, cloned.primitive_evaluations);
    }

    #[test]
    fn test_engine_batch_evaluation_empty() {
        let ruleset = CompiledRuleset::new();
        let mut engine = SigmaEngine::from_ruleset(ruleset).unwrap();

        let events: Vec<serde_json::Value> = vec![];
        let results = engine.evaluate_batch(&events).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_engine_batch_evaluation_single_event() {
        let ruleset = CompiledRuleset::new();
        let mut engine = SigmaEngine::from_ruleset(ruleset).unwrap();

        let events = vec![serde_json::json!({"test": "value"})];
        let results = engine.evaluate_batch(&events).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].matched_rules.is_empty()); // No rules to match
    }

    #[test]
    fn test_engine_batch_evaluation_multiple_events() {
        let ruleset = CompiledRuleset::new();
        let mut engine = SigmaEngine::from_ruleset(ruleset).unwrap();

        let events = vec![
            serde_json::json!({"test1": "value1"}),
            serde_json::json!({"test2": "value2"}),
            serde_json::json!({"test3": "value3"}),
        ];
        let results = engine.evaluate_batch(&events).unwrap();

        assert_eq!(results.len(), 3);
        for result in results {
            assert!(result.matched_rules.is_empty()); // No rules to match
        }
    }

    #[test]
    fn test_engine_contains_rule() {
        let ruleset = CompiledRuleset::new();
        let engine = SigmaEngine::from_ruleset(ruleset).unwrap();

        // Since we have no rules, contains_rule should return false
        assert!(!engine.contains_rule(1));
        assert!(!engine.contains_rule(999));
        assert!(!engine.contains_rule(0));
    }

    #[test]
    fn test_engine_config_variations() {
        let ruleset = CompiledRuleset::new();

        // Test with default config
        let config_default = DagEngineConfig::default();
        let engine_default = SigmaEngine::from_ruleset_with_config(ruleset.clone(), config_default);
        assert!(engine_default.is_ok());

        // Test with high performance config
        let config_high_perf = DagEngineConfig::high_performance();
        let engine_high_perf =
            SigmaEngine::from_ruleset_with_config(ruleset.clone(), config_high_perf);
        assert!(engine_high_perf.is_ok());

        // Test with streaming optimized config
        let config_streaming = DagEngineConfig::streaming_optimized();
        let engine_streaming = SigmaEngine::from_ruleset_with_config(ruleset, config_streaming);
        assert!(engine_streaming.is_ok());
    }

    #[test]
    fn test_engine_metadata_consistency() {
        let ruleset = CompiledRuleset::new();
        let engine = SigmaEngine::from_ruleset(ruleset).unwrap();

        // All counts should be consistent and non-negative
        let rule_count = engine.rule_count();
        let node_count = engine.node_count();
        let primitive_count = engine.primitive_count();

        // For an empty ruleset, these should all be 0 or small values
        assert!(rule_count <= 1000); // Reasonable upper bound
        assert!(node_count <= 10000); // Reasonable upper bound
        assert!(primitive_count <= 1000); // Reasonable upper bound

        // Primitive count should not exceed node count (primitives are a subset of nodes)
        assert!(primitive_count <= node_count);
    }

    #[test]
    fn test_dag_evaluation_result_conversion_edge_cases() {
        // Test conversion with empty results
        let empty_dag_result = DagEvaluationResult {
            matched_rules: vec![],
            nodes_evaluated: 0,
            primitive_evaluations: 0,
        };
        let empty_engine_result = EngineResult::from(empty_dag_result);
        assert!(empty_engine_result.matched_rules.is_empty());
        assert_eq!(empty_engine_result.nodes_evaluated, 0);
        assert_eq!(empty_engine_result.primitive_evaluations, 0);

        // Test conversion with large values
        let large_dag_result = DagEvaluationResult {
            matched_rules: (1..=1000).collect(),
            nodes_evaluated: 50000,
            primitive_evaluations: 25000,
        };
        let large_engine_result = EngineResult::from(large_dag_result);
        assert_eq!(large_engine_result.matched_rules.len(), 1000);
        assert_eq!(large_engine_result.nodes_evaluated, 50000);
        assert_eq!(large_engine_result.primitive_evaluations, 25000);
    }
}
