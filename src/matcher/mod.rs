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
//! - Zero-allocation evaluation engine
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

pub mod advanced;
pub mod builder;
pub mod cache;
pub mod compiled;
pub mod context;
pub mod defaults;
pub mod filters;
pub mod hooks;
pub mod modifiers;
pub mod types;

// Some deprecated modules removed - keeping hooks for multi-layer integration

// Re-export main types for convenience
pub use builder::MatcherBuilder;
pub use cache::{
    global_regex_cache, init_global_cache, CacheConfig, GlobalRegexCache, PatternComplexity,
};
pub use compiled::CompiledPrimitive;
pub use context::EventContext;
pub use defaults::{
    create_base64_decode, create_contains_match, create_endswith_match, create_exact_match,
    create_regex_match, create_startswith_match, create_utf16_decode, register_defaults,
    register_defaults_with_comprehensive_modifiers,
};

pub use filters::{FilterIntegration, FilterStatistics};

pub use hooks::{CompilationContext, CompilationHookFn, CompilationPhase};

pub use modifiers::register_comprehensive_modifiers;

pub use types::{FieldExtractorFn, MatchFn, ModifierFn};

// Re-export advanced match functions with explicit names to avoid conflicts
pub use advanced::create_cidr_match as create_advanced_cidr_match;

pub use advanced::{
    create_fuzzy_match as create_advanced_fuzzy_match,
    create_range_match as create_advanced_range_match,
};

// Enterprise features removed - they were not part of core functionality
