//! Common utilities for SIGMA engine benchmarks.
//!
//! This module provides shared functionality across all benchmark files,
//! following Rust idioms for benchmark organization and reducing code duplication.

pub mod test_data;
pub mod setup;
pub mod metrics;

use serde_json::Value;
use sigma_engine::{
    ir::CompiledRuleset,
    matcher::CompiledPrimitive,
    dag::DagEngine,
};
use std::collections::HashMap;

/// Standard benchmark configuration for consistent testing.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Number of rules to generate for testing
    pub rule_count: usize,
    /// Number of events to process in batch tests
    pub event_count: usize,
    /// Whether to enable metrics collection
    pub enable_metrics: bool,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            rule_count: 100,
            event_count: 1000,
            enable_metrics: false,
        }
    }
}

impl BenchmarkConfig {
    /// Create a new benchmark configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of rules for testing.
    pub fn with_rule_count(mut self, count: usize) -> Self {
        self.rule_count = count;
        self
    }

    /// Set the number of events for batch testing.
    pub fn with_event_count(mut self, count: usize) -> Self {
        self.event_count = count;
        self
    }

    /// Enable metrics collection.
    pub fn with_metrics(mut self, enable: bool) -> Self {
        self.enable_metrics = enable;
        self
    }

    /// Create a configuration for high EPS testing.
    pub fn high_eps() -> Self {
        Self {
            rule_count: 1000,
            event_count: 10000,
            enable_metrics: true,
        }
    }

    /// Create a configuration for scaling tests.
    pub fn scaling() -> Self {
        Self {
            rule_count: 2000,
            event_count: 1000,
            enable_metrics: true,
        }
    }

    /// Create a configuration for memory efficiency tests.
    pub fn memory_efficient() -> Self {
        Self {
            rule_count: 500,
            event_count: 5000,
            enable_metrics: true,
        }
    }
}

/// Standard test environment for benchmarks.
pub struct TestEnvironment {
    pub ruleset: CompiledRuleset,
    pub compiled_primitives: Vec<CompiledPrimitive>,
    pub primitive_map: HashMap<u32, CompiledPrimitive>,
    pub dag_engine: DagEngine,
    pub test_events: Vec<Value>,
    pub primitive_results: Vec<bool>,
}

impl TestEnvironment {
    /// Create a new test environment with the given configuration.
    pub fn new(config: &BenchmarkConfig) -> anyhow::Result<Self> {
        setup::create_test_environment(config)
    }

    /// Get a single test event for benchmarking.
    pub fn test_event(&self) -> &Value {
        &self.test_events[0]
    }

    /// Get multiple test events for batch benchmarking.
    pub fn test_events(&self) -> &[Value] {
        &self.test_events
    }

    /// Get primitive results for VM execution.
    pub fn primitive_results(&self) -> &[bool] {
        &self.primitive_results
    }

    /// Get DAG engine for execution.
    pub fn dag_engine(&mut self) -> &mut DagEngine {
        &mut self.dag_engine
    }
}

/// Benchmark result metrics for performance analysis.
#[derive(Debug, Clone, Default)]
pub struct BenchmarkMetrics {
    pub execution_time_ns: u64,
    pub matches_found: usize,
    pub rules_processed: usize,
    pub events_processed: usize,
    pub memory_allocations: Option<usize>,
    pub bytes_allocated: Option<usize>,
    pub cpu_cycles: Option<u64>,
}

impl BenchmarkMetrics {
    /// Create new benchmark metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate throughput in operations per second.
    pub fn throughput_ops_per_sec(&self) -> f64 {
        if self.execution_time_ns == 0 {
            return 0.0;
        }
        let total_ops = self.rules_processed * self.events_processed;
        (total_ops as f64) / (self.execution_time_ns as f64 / 1_000_000_000.0)
    }

    /// Calculate events per second.
    pub fn events_per_sec(&self) -> f64 {
        if self.execution_time_ns == 0 {
            return 0.0;
        }
        (self.events_processed as f64) / (self.execution_time_ns as f64 / 1_000_000_000.0)
    }

    /// Calculate rules per second.
    pub fn rules_per_sec(&self) -> f64 {
        if self.execution_time_ns == 0 {
            return 0.0;
        }
        (self.rules_processed as f64) / (self.execution_time_ns as f64 / 1_000_000_000.0)
    }

    /// Calculate memory efficiency (bytes per operation).
    pub fn memory_efficiency(&self) -> Option<f64> {
        if let Some(bytes) = self.bytes_allocated {
            let total_ops = self.rules_processed * self.events_processed;
            if total_ops > 0 {
                Some(bytes as f64 / total_ops as f64)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Common benchmark patterns for consistent testing.
pub mod patterns {
    use super::*;
    use criterion::{black_box, Bencher};

    /// Execute DAG engine against a single event.
    pub fn single_event<F>(b: &mut Bencher, env: &mut TestEnvironment, mut execute_fn: F)
    where
        F: FnMut(&mut DagEngine, &Value) -> anyhow::Result<bool>,
    {
        let event = env.test_event();

        b.iter(|| {
            let result = execute_fn(
                black_box(env.dag_engine()),
                black_box(event),
            );
            black_box(result)
        });
    }

    /// Execute DAG engine against multiple events (batch processing).
    pub fn batch_processing<F>(b: &mut Bencher, env: &mut TestEnvironment, mut execute_fn: F)
    where
        F: FnMut(&mut DagEngine, &[Value]) -> anyhow::Result<Vec<bool>>,
    {
        let events = env.test_events();

        b.iter(|| {
            let result = execute_fn(
                black_box(env.dag_engine()),
                black_box(events),
            );
            black_box(result)
        });
    }
}

/// Utility functions for benchmark setup and teardown.
pub mod utils {
    use super::*;

    /// Create a simple test rule for basic benchmarking.
    pub fn create_simple_test_rule(id: u32) -> String {
        format!(
            r#"
title: Simple Test Rule {}
id: test-rule-{:04}
status: experimental
description: Simple test rule for benchmarking
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
"#,
            id, id
        )
    }

    /// Create a complex test rule with multiple conditions.
    pub fn create_complex_test_rule(id: u32) -> String {
        format!(
            r#"
title: Complex Test Rule {}
id: test-rule-{:04}
status: experimental
description: Complex test rule for benchmarking
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4624
        ProcessName: svchost.exe
    selection2:
        EventID: 4625
        User: Administrator
    condition: selection1 or selection2
"#,
            id, id
        )
    }

    /// Validate benchmark results for correctness.
    pub fn validate_benchmark_results(
        results: &[Option<u32>],
        expected_matches: usize,
    ) -> anyhow::Result<()> {
        let actual_matches = results.iter().filter(|r| r.is_some()).count();
        if actual_matches != expected_matches {
            anyhow::bail!(
                "Benchmark validation failed: expected {} matches, got {}",
                expected_matches,
                actual_matches
            );
        }
        Ok(())
    }
}
