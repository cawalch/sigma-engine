//! Primary DAG execution engine for SIGMA rules.
//!
//! This module provides the consolidated DAG-based execution engine that replaces
//! the hybrid stack/DAG architecture. It offers high-performance rule evaluation
//! with shared computation across rules with common primitives.
//!
//! # Example
//!
//! ```rust,ignore
//! use sigma_engine::dag::{DagEngine, DagBuilder};
//! use sigma_engine::ir::CompiledRuleset;
//!
//! // Create DAG engine from compiled ruleset
//! let engine = DagEngine::from_rules(&rules)?;
//!
//! // Execute against event data
//! let results = engine.evaluate(&event_data)?;
//! ```

pub mod batch_evaluator;
pub mod builder;
pub mod engine;
pub mod evaluator;
pub mod optimizer;
pub mod parallel_evaluator;
pub mod prefilter;
pub mod types;

// Re-export main types for convenience
pub use batch_evaluator::{BatchDagEvaluator, BatchMemoryPool};
pub use builder::DagBuilder;
pub use engine::DagEngine;
pub use evaluator::{DagEvaluationResult, DagEvaluator};
pub use optimizer::DagOptimizer;
pub use parallel_evaluator::{ParallelConfig, ParallelDagEvaluator, RulePartition};
pub use types::{CompiledDag, DagNode, DagStatistics, LogicalOp, NodeId, NodeType};

use crate::ir::CompiledRuleset;

/// Check if DAG execution should be used based on rule characteristics.
///
/// This function provides intelligent selection logic for determining when
/// DAG execution provides performance benefits over other execution strategies.
pub fn should_use_dag(rule_count: usize, complexity_score: f32) -> bool {
    // DAG provides benefits for:
    // - Large rule sets (100+ rules) due to shared computation
    // - Complex rules with high primitive sharing potential
    // - High-frequency execution scenarios

    match rule_count {
        0..=49 => false,                   // Small rule sets: overhead not worth it
        50..=99 => complexity_score > 0.5, // Medium: depends on complexity
        100.. => true,                     // Large rule sets: always beneficial
    }
}

/// Estimate sharing potential for a compiled ruleset.
///
/// Returns a score (0.0 to 1.0) indicating how much primitive sharing
/// is possible across rules in the ruleset.
pub fn estimate_sharing_potential(ruleset: &CompiledRuleset) -> f32 {
    if ruleset.primitives.len() <= 1 {
        return 0.0;
    }

    // For DAG-only architecture, sharing potential is based on primitive reuse
    // Higher primitive count suggests more potential for sharing
    let primitive_count = ruleset.primitives.len() as f32;

    // Normalize to 0.0-1.0 range, with higher primitive counts indicating more sharing potential
    (primitive_count / 100.0).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CompiledRuleset, Primitive};
    use std::collections::HashMap;

    #[test]
    fn test_should_use_dag_small_rule_sets() {
        // Small rule sets should not use DAG regardless of complexity
        assert!(!should_use_dag(0, 1.0));
        assert!(!should_use_dag(25, 1.0));
        assert!(!should_use_dag(49, 1.0));
    }

    #[test]
    fn test_should_use_dag_medium_rule_sets() {
        // Medium rule sets depend on complexity
        assert!(!should_use_dag(50, 0.3));
        assert!(!should_use_dag(75, 0.5));
        assert!(should_use_dag(50, 0.6));
        assert!(should_use_dag(99, 0.8));
    }

    #[test]
    fn test_should_use_dag_large_rule_sets() {
        // Large rule sets should always use DAG
        assert!(should_use_dag(100, 0.0));
        assert!(should_use_dag(500, 0.1));
        assert!(should_use_dag(1000, 1.0));
    }

    #[test]
    fn test_estimate_sharing_potential_empty() {
        let ruleset = CompiledRuleset {
            primitive_map: HashMap::new(),
            primitives: Vec::new(),
        };
        assert_eq!(estimate_sharing_potential(&ruleset), 0.0);
    }

    #[test]
    fn test_estimate_sharing_potential_single_primitive() {
        let primitive = Primitive::new(
            "field".to_string(),
            "equals".to_string(),
            vec!["value".to_string()],
            Vec::new(),
        );
        let mut primitive_map = HashMap::new();
        primitive_map.insert(primitive.clone(), 0);

        let ruleset = CompiledRuleset {
            primitive_map,
            primitives: vec![primitive],
        };
        assert_eq!(estimate_sharing_potential(&ruleset), 0.0);
    }

    #[test]
    fn test_estimate_sharing_potential_multiple_primitives() {
        let primitive1 = Primitive::new(
            "field1".to_string(),
            "equals".to_string(),
            vec!["value1".to_string()],
            Vec::new(),
        );
        let primitive2 = Primitive::new(
            "field2".to_string(),
            "equals".to_string(),
            vec!["value2".to_string()],
            Vec::new(),
        );

        let mut primitive_map = HashMap::new();
        primitive_map.insert(primitive1.clone(), 0);
        primitive_map.insert(primitive2.clone(), 1);

        let ruleset = CompiledRuleset {
            primitive_map,
            primitives: vec![primitive1, primitive2],
        };

        let potential = estimate_sharing_potential(&ruleset);
        assert!(potential > 0.0);
        assert!(potential <= 1.0);
        assert_eq!(potential, 0.02); // 2/100 = 0.02
    }

    #[test]
    fn test_estimate_sharing_potential_max_value() {
        // Create a ruleset with 100+ primitives to test the max value
        let mut primitives = Vec::new();
        let mut primitive_map = HashMap::new();

        for i in 0..150 {
            let primitive = Primitive::new(
                format!("field{i}"),
                "equals".to_string(),
                vec![format!("value{}", i)],
                Vec::new(),
            );
            primitive_map.insert(primitive.clone(), i);
            primitives.push(primitive);
        }

        let ruleset = CompiledRuleset {
            primitive_map,
            primitives,
        };

        let potential = estimate_sharing_potential(&ruleset);
        assert_eq!(potential, 1.0); // Should be capped at 1.0
    }
}
