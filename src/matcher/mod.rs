//! Zero-allocation functional registry for SIGMA primitive matching.
//!
//! This module implements a high-performance, zero-allocation primitive matching system
//! designed for production SIGMA deployments with dozens to thousands of rules.
//!
//! ## Architecture
//!
//! The matcher system separates compilation from evaluation:
//! - **Compilation Phase**: Pre-compiles patterns, regex, and modifier chains
//! - **Evaluation Phase**: Zero-allocation evaluation using pre-compiled data
//!
//! ## Core Components
//!
//! - [`EventContext`] - Field value caching for repeated access
//! - [`CompiledPrimitive`] - Pre-compiled primitive with Arc-based sharing
//! - [`FunctionalMatcher`] - Zero-allocation evaluation engine
//! - [`MatcherBuilder`] - Registry pattern for function registration
//!
//! ## Multi-Layer Integration
//!
//! The system supports compilation-phase hooks for extracting literals to external
//! filtering libraries (AhoCorasick, FST, XOR filters) for multi-layer processing.
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use sigma_engine::matcher::{MatcherBuilder, EventContext};
//! use serde_json::Value;
//!
//! // Build matcher with default implementations
//! let matcher = MatcherBuilder::new()
//!     .compile(&primitives)?;
//!
//! // Zero-allocation evaluation
//! let event: Value = serde_json::from_str(r#"{"EventID": "4624"}"#)?;
//! let results = matcher.evaluate(&event)?;
//! ```

pub mod builder;
pub mod compiled;
pub mod context;
pub mod defaults;
pub mod functional;
pub mod hooks;
pub mod types;

pub use builder::*;
pub use compiled::*;
pub use context::*;
pub use defaults::*;
pub use functional::*;
pub use hooks::*;
pub use types::*;
