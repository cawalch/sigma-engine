//! Primary SIGMA Engine interface.
//!
//! This module provides the main `SigmaEngine` struct that serves as the
//! primary interface for all SIGMA rule evaluation using DAG-based execution.

use crate::dag::engine::{DagEngineBuilder, DagEngineConfig};
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

/// Type alias for the DAG engine builder to provide a consistent API.
pub type SigmaEngineBuilder = DagEngineBuilder;

impl SigmaEngine {
    /// Create a new builder for configuring the SIGMA engine.
    ///
    /// This provides a fluent API for setting up the engine with custom
    /// configurations, compilers, and field mappings.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sigma_engine::SigmaEngine;
    ///
    /// let engine = SigmaEngine::builder()
    ///     .with_optimization_level(3)
    ///     .with_prefilter(true)
    ///     .build(&[rule_yaml])?;
    /// ```
    pub fn builder() -> SigmaEngineBuilder {
        SigmaEngineBuilder::new()
    }
    /// Create a new SIGMA engine from SIGMA rule YAML strings.
    ///
    /// This method compiles the rules directly to a DAG structure with proper
    /// rule result nodes, ensuring that rule matches are correctly detected.
    ///
    /// # Arguments
    /// * `rule_yamls` - Array of SIGMA rule YAML strings
    ///
    /// # Returns
    /// A new SigmaEngine instance ready for evaluation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sigma_engine::SigmaEngine;
    ///
    /// let rule_yaml = r#"
    /// title: Test Rule
    /// detection:
    ///     selection:
    ///         EventID: 4624
    ///     condition: selection
    /// "#;
    ///
    /// let engine = SigmaEngine::from_rules(&[rule_yaml])?;
    /// ```
    pub fn from_rules(rule_yamls: &[&str]) -> Result<Self> {
        Self::from_rules_with_config(rule_yamls, DagEngineConfig::default())
    }

    /// Create a new SIGMA engine from SIGMA rule YAML strings with custom configuration.
    ///
    /// This method compiles the rules directly to a DAG structure with proper
    /// rule result nodes, ensuring that rule matches are correctly detected.
    ///
    /// # Arguments
    /// * `rule_yamls` - Array of SIGMA rule YAML strings
    /// * `config` - Custom DAG engine configuration
    ///
    /// # Returns
    /// A new SigmaEngine instance with custom configuration.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sigma_engine::{SigmaEngine, DagEngineConfig};
    ///
    /// let rule_yaml = r#"
    /// title: Test Rule
    /// detection:
    ///     selection:
    ///         EventID: 4624
    ///     condition: selection
    /// "#;
    ///
    /// let config = DagEngineConfig::high_performance();
    /// let engine = SigmaEngine::from_rules_with_config(&[rule_yaml], config)?;
    /// ```
    pub fn from_rules_with_config(rule_yamls: &[&str], config: DagEngineConfig) -> Result<Self> {
        DagEngine::from_rules_with_config(rule_yamls, config).map(|dag_engine| Self { dag_engine })
    }

    /// Create a new SIGMA engine from SIGMA rule YAML strings with custom compiler and configuration.
    ///
    /// This method allows using a custom compiler with field mapping for proper rule compilation.
    ///
    /// # Arguments
    /// * `rule_yamls` - Array of SIGMA rule YAML strings
    /// * `compiler` - Custom compiler with field mapping
    /// * `config` - Custom DAG engine configuration
    ///
    /// # Returns
    /// A new SigmaEngine instance with custom configuration and field mapping.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sigma_engine::{SigmaEngine, Compiler, FieldMapping, DagEngineConfig};
    ///
    /// let mut field_mapping = FieldMapping::new();
    /// field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    ///
    /// let compiler = Compiler::with_field_mapping(field_mapping);
    /// let config = DagEngineConfig::default();
    /// let engine = SigmaEngine::from_rules_with_compiler(&[rule_yaml], compiler, config)?;
    /// ```
    pub fn from_rules_with_compiler(
        rule_yamls: &[&str],
        compiler: crate::Compiler,
        config: DagEngineConfig,
    ) -> Result<Self> {
        DagEngine::from_rules_with_compiler(rule_yamls, compiler, config)
            .map(|dag_engine| Self { dag_engine })
    }

    /// Create a new SIGMA engine from a compiled ruleset.
    ///
    /// **Note**: This method is deprecated because it doesn't create proper rule result nodes.
    /// Use `from_rules()` instead for correct rule matching behavior.
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
    #[deprecated(note = "Use from_rules() instead for proper rule matching")]
    pub fn from_ruleset(ruleset: CompiledRuleset) -> Result<Self> {
        DagEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default())
            .map(|dag_engine| Self { dag_engine })
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
    ///     optimization_level: 3,
    ///     ..Default::default()
    /// };
    ///
    /// let engine = SigmaEngine::from_ruleset_with_config(ruleset, config)?;
    /// ```
    pub fn from_ruleset_with_config(
        ruleset: CompiledRuleset,
        config: DagEngineConfig,
    ) -> Result<Self> {
        DagEngine::from_ruleset_with_config(ruleset, config).map(|dag_engine| Self { dag_engine })
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
        self.dag_engine.evaluate(event)
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
        self.dag_engine.evaluate_batch(events)
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
///
/// This is a type alias for `DagEvaluationResult` to provide a consistent
/// API while avoiding duplication.
pub type EngineResult = DagEvaluationResult;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::CompiledRuleset;

    #[test]
    fn test_engine_creation() {
        let ruleset = CompiledRuleset::new();
        let engine = SigmaEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default());
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
    fn test_engine_result_type_alias() {
        let engine_result: EngineResult = DagEvaluationResult {
            matched_rules: vec![1, 2, 3],
            nodes_evaluated: 10,
            primitive_evaluations: 5,
        };

        assert_eq!(engine_result.matched_rules, vec![1, 2, 3]);
        assert_eq!(engine_result.nodes_evaluated, 10);
        assert_eq!(engine_result.primitive_evaluations, 5);
    }

    #[test]
    fn test_sigma_engine_integration() {
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

        // Create the engine using the new API that properly compiles DAG
        let mut engine = SigmaEngine::from_rules(&[rule_yaml]).unwrap();

        // Test with matching event
        let matching_event = json!({
            "EventID": "4624"
        });

        let result = engine.evaluate(&matching_event);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.nodes_evaluated > 0);
        // Now we should actually get matches with the proper DAG compilation
        assert!(!result.matched_rules.is_empty(), "Should match rule 0");
        assert_eq!(result.matched_rules, vec![0]);

        // Test with non-matching event
        let non_matching_event = json!({
            "EventID": "1234"
        });

        let result = engine.evaluate(&non_matching_event);
        assert!(result.is_ok());

        let result = result.unwrap();
        // Non-matching events should have empty matched_rules
        assert!(result.matched_rules.is_empty());

        // Test engine metadata
        assert_eq!(engine.rule_count(), 1); // Should have 1 rule now
        assert!(engine.primitive_count() > 0); // Should have primitives
        assert!(engine.node_count() > 0); // Should have nodes
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
        let mut engine =
            SigmaEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default()).unwrap();

        let events: Vec<serde_json::Value> = vec![];
        let results = engine.evaluate_batch(&events).unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_engine_batch_evaluation_single_event() {
        let ruleset = CompiledRuleset::new();
        let mut engine =
            SigmaEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default()).unwrap();

        let events = vec![serde_json::json!({"test": "value"})];
        let results = engine.evaluate_batch(&events).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].matched_rules.is_empty()); // No rules to match
    }

    #[test]
    fn test_engine_batch_evaluation_multiple_events() {
        let ruleset = CompiledRuleset::new();
        let mut engine =
            SigmaEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default()).unwrap();

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
        let engine =
            SigmaEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default()).unwrap();

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
        let engine =
            SigmaEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default()).unwrap();

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
    fn test_sigma_engine_builder() {
        let rule_yaml = r#"
title: Test Rule
detection:
    selection:
        EventID: 4624
    condition: selection
"#;

        // Test basic builder usage
        let engine = SigmaEngine::builder().build(&[rule_yaml]);
        assert!(engine.is_ok());

        // Test builder with configuration
        let engine = SigmaEngine::builder()
            .with_optimization_level(3)
            .with_prefilter(true)
            .build(&[rule_yaml]);
        assert!(engine.is_ok());

        // Test builder chaining
        let engine = SigmaEngine::builder()
            .with_optimization(true)
            .with_parallel_processing(false)
            .build(&[rule_yaml]);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_engine_result_edge_cases() {
        // Test with empty results
        let empty_result: EngineResult = DagEvaluationResult {
            matched_rules: vec![],
            nodes_evaluated: 0,
            primitive_evaluations: 0,
        };
        assert!(empty_result.matched_rules.is_empty());
        assert_eq!(empty_result.nodes_evaluated, 0);
        assert_eq!(empty_result.primitive_evaluations, 0);

        // Test with large values
        let large_result: EngineResult = DagEvaluationResult {
            matched_rules: (1..=1000).collect(),
            nodes_evaluated: 50000,
            primitive_evaluations: 25000,
        };
        assert_eq!(large_result.matched_rules.len(), 1000);
        assert_eq!(large_result.nodes_evaluated, 50000);
        assert_eq!(large_result.primitive_evaluations, 25000);
    }
}
