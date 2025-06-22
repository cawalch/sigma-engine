//! Setup utilities for SIGMA engine benchmarks.

use super::{BenchmarkConfig, TestEnvironment};
use crate::common::test_data;
use sigma_engine::{
    ir::CompiledRuleset,
    matcher::{CompiledPrimitive, MatcherBuilder},
    Compiler, dag::DagEngine,
};
use std::collections::HashMap;

/// Create a complete test environment for benchmarking.
pub fn create_test_environment(config: &BenchmarkConfig) -> anyhow::Result<TestEnvironment> {
    // Generate test rules
    let rules = test_data::generate_test_rules(config.rule_count);

    // Compile rules
    let mut compiler = Compiler::new();

    // For now, create empty ruleset since we don't have rule parsing yet
    let ruleset = compiler.into_ruleset();

    // Compile primitives for matching
    let builder = MatcherBuilder::new();
    let compiled_primitives = builder.compile(&ruleset.primitives)?;

    // Create primitive map for DAG evaluator
    let mut primitive_map = HashMap::new();
    for (i, primitive) in compiled_primitives.iter().enumerate() {
        primitive_map.insert(i as u32, primitive.clone());
    }

    // Create DAG engine
    let dag_engine = DagEngine::from_ruleset(ruleset.clone())?;

    // Generate test events
    let test_events = test_data::create_test_events(config.event_count);

    // Create primitive results for execution (simplified for benchmarking)
    let primitive_results = (0..ruleset.primitives.len()).map(|i| i % 3 == 0).collect();

    Ok(TestEnvironment {
        ruleset,
        compiled_primitives,
        primitive_map,
        dag_engine,
        test_events,
        primitive_results,
    })
}

/// Create a minimal test environment for simple benchmarks.
pub fn create_minimal_test_environment() -> anyhow::Result<TestEnvironment> {
    let config = BenchmarkConfig::new()
        .with_rule_count(1)
        .with_event_count(1);
    create_test_environment(&config)
}

/// Create a test environment optimized for high EPS benchmarks.
pub fn create_high_eps_test_environment() -> anyhow::Result<TestEnvironment> {
    let config = BenchmarkConfig::high_eps();
    create_test_environment(&config)
}

/// Create a test environment for scaling benchmarks.
pub fn create_scaling_test_environment(rule_count: usize) -> anyhow::Result<TestEnvironment> {
    let config = BenchmarkConfig::scaling()
        .with_rule_count(rule_count);
    create_test_environment(&config)
}

/// Create a test environment for memory efficiency benchmarks.
pub fn create_memory_test_environment() -> anyhow::Result<TestEnvironment> {
    let config = BenchmarkConfig::memory_efficient();
    create_test_environment(&config)
}

/// Setup utilities for specific benchmark types.
pub mod specialized {
    use super::*;

    /// Create a test environment with specific rule patterns.
    pub fn create_pattern_test_environment(
        pattern: &str,
        rule_count: usize,
        event_count: usize,
    ) -> anyhow::Result<TestEnvironment> {
        // Generate rules based on pattern
        let rules = match pattern {
            "simple" => (0..rule_count)
                .map(|i| format!(
                    r#"
title: Simple Rule {}
id: simple-rule-{:04}
detection:
    selection:
        EventID: 4624
    condition: selection
"#, i + 1, i))
                .collect(),
            "complex" => (0..rule_count)
                .map(|i| format!(
                    r#"
title: Complex Rule {}
id: complex-rule-{:04}
detection:
    sel1:
        EventID: 4624
        ProcessName: svchost.exe
    sel2:
        EventID: 4625
        User: Administrator
    condition: sel1 or sel2
"#, i + 1, i))
                .collect(),
            _ => test_data::generate_test_rules(rule_count),
        };

        // Compile rules
        let mut compiler = Compiler::new();

        // For now, create empty ruleset since we don't have rule parsing yet
        let ruleset = compiler.into_ruleset();

        // Compile primitives
        let builder = MatcherBuilder::new();
        let compiled_primitives = builder.compile(&ruleset.primitives)?;

        // Create primitive map
        let mut primitive_map = HashMap::new();
        for (i, primitive) in compiled_primitives.iter().enumerate() {
            primitive_map.insert(i as u32, primitive.clone());
        }

        // Create DAG engine
        let dag_engine = DagEngine::from_ruleset(ruleset.clone())?;

        // Generate events based on pattern
        let test_events = test_data::create_pattern_test_events(pattern, event_count);

        // Create primitive results
        let primitive_results = (0..ruleset.primitives.len()).map(|i| i % 2 == 0).collect();

        Ok(TestEnvironment {
            ruleset,
            compiled_primitives,
            primitive_map,
            dag_engine,
            test_events,
            primitive_results,
        })
    }
}

/// Validation utilities for benchmark setup.
pub mod validation {
    use super::*;

    /// Validate that the test environment is correctly configured.
    pub fn validate_test_environment(env: &TestEnvironment) -> anyhow::Result<()> {
        // Check that we have primitives
        if env.compiled_primitives.is_empty() {
            anyhow::bail!("Test environment has no compiled primitives");
        }

        // Check that we have test events
        if env.test_events.is_empty() {
            anyhow::bail!("Test environment has no test events");
        }

        // Check that primitive results match primitive count
        if env.primitive_results.len() != env.ruleset.primitives.len() {
            anyhow::bail!(
                "Primitive results count ({}) doesn't match primitives count ({})",
                env.primitive_results.len(),
                env.ruleset.primitives.len()
            );
        }

        // Check that primitive map is consistent
        if env.primitive_map.len() != env.compiled_primitives.len() {
            anyhow::bail!(
                "Primitive map size ({}) doesn't match compiled primitives count ({})",
                env.primitive_map.len(),
                env.compiled_primitives.len()
            );
        }

        Ok(())
    }

    /// Validate benchmark configuration.
    pub fn validate_benchmark_config(config: &BenchmarkConfig) -> anyhow::Result<()> {
        if config.rule_count == 0 {
            anyhow::bail!("Rule count must be greater than 0");
        }

        if config.event_count == 0 {
            anyhow::bail!("Event count must be greater than 0");
        }

        Ok(())
    }
}
