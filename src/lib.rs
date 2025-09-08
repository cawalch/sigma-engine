//! # SIGMA Detection Engine
//!
//! A high-performance Rust library for compiling and executing [SIGMA detection rules](https://github.com/SigmaHQ/sigma)
//! using a DAG-based execution engine with shared computation optimization.
//!
//!
//! ## Quick Start
//!
//! ### Basic Usage
//!
//! ```rust,ignore
//! use sigma_engine::{Compiler, SigmaEngine};
//!
//! // Compile SIGMA rules
//! let mut compiler = Compiler::new();
//! let rule_yaml = r#"
//! title: Windows Login Event
//! logsource:
//!     category: authentication
//! detection:
//!     selection:
//!         EventID: 4624
//!         LogonType: 2
//!     condition: selection
//! "#;
//!
//! let rules = vec![rule_yaml];
//!
//! // Create engine
//! let mut engine = SigmaEngine::from_rules(&rules)?;
//!
//! // Evaluate events
//! let event = serde_json::json!({
//!     "EventID": "4624",
//!     "LogonType": 2
//! });
//!
//! let result = engine.evaluate(&event)?;
//! println!("Matched rules: {:?}", result.matched_rules);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Batch Processing
//!
//! ```rust,ignore
//! use sigma_engine::{Compiler, SigmaEngine};
//!
//! let mut engine = SigmaEngine::from_rules(&rules)?;
//!
//! // Process multiple events efficiently
//! let events = vec![
//!     serde_json::json!({"EventID": "4624", "LogonType": 2}),
//!     serde_json::json!({"EventID": "4625", "LogonType": 3}),
//!     serde_json::json!({"EventID": "4624", "LogonType": 2}),
//! ];
//!
//! let results = engine.evaluate_batch(&events)?;
//! let total_matches: usize = results.iter().map(|r| r.matched_rules.len()).sum();
//! println!("Processed {} events, {} total matches", events.len(), total_matches);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Field Mapping
//!
//! ```rust,ignore
//! use sigma_engine::{Compiler, FieldMapping, SigmaEngine};
//!
//! // Map SIGMA field names to your event schema
//! let mut field_mapping = FieldMapping::with_taxonomy("custom_edr".to_string());
//! field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
//! field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());
//!
//! let mut engine = SigmaEngine::from_rules_with_compiler(&rules, compiler, EngineConfig::default())?;
//!
//! // Events use your custom field names
//! let event = serde_json::json!({
//!     "EventID": 1,
//!     "Image": "C:\\Windows\\System32\\powershell.exe",
//!     "CommandLine": "powershell.exe -Command Get-Process"
//! });
//!
//! let result = engine.evaluate(&event)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod compiler;
pub mod config;
pub mod error;
pub mod ir;
pub mod matcher;

// Primary DAG execution engine
pub mod dag;

#[cfg(feature = "profiling")]
pub mod profiling;

// Primary engine interface - simplified to use DagEngine directly
pub use dag::engine::{
    DagEngine as SigmaEngine, DagEngineBuilder as SigmaEngineBuilder, DagEngineConfig,
};
pub use dag::evaluator::DagEvaluationResult as EngineResult;

// Compiler and configuration
pub use compiler::{Compiler, FieldMapping};
pub use config::{
    BatchConfig, EngineConfig, ExecutionStrategy, MemoryConfig, PerformanceConfig, SecurityConfig,
};

// Core types and errors
pub use error::{Result, SigmaError};
pub use ir::{CompiledRuleset, Primitive, PrimitiveId, RuleId};

// Matcher system
pub use matcher::{
    CompiledPrimitive, EventContext, FieldExtractorFn, MatchFn, MatcherBuilder, ModifierFn,
};

// DAG execution engine (for advanced use cases)
pub use dag::engine::DagExecutionResult;
pub use dag::{
    CompiledDag, DagBuilder, DagEngine, DagEvaluationResult, DagEvaluator, DagNode, DagOptimizer,
    DagStatistics, EvaluationStrategy, EvaluatorConfig, LogicalOp, NodeId, NodeType,
};
