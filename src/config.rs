//! Unified configuration system for SIGMA Engine.
//!
//! This module provides comprehensive configuration control over all aspects
//! of the SIGMA engine including batch processing, memory management,
//! performance tuning, and execution strategies.

/// Execution strategy for DAG processing.
///
/// Controls the trade-off between performance and safety during rule execution.
/// Simplified to three essential strategies that cover all practical use cases.
///
/// # Strategy Comparison
///
/// | Strategy | Performance | Safety | Use Case |
/// |----------|-------------|--------|----------|
/// | `Development` | Low | High | Development, debugging, testing |
/// | `Production` | High | Medium | Production systems, trusted rules |
/// | `Adaptive` | Variable | High | Automatic optimization (default) |
///
/// # Examples
///
/// ```rust
/// use sigma_engine::ExecutionStrategy;
///
/// // For development and testing
/// let dev_strategy = ExecutionStrategy::Development;
///
/// // For production systems
/// let prod_strategy = ExecutionStrategy::Production;
///
/// // Let the engine decide automatically (recommended)
/// let adaptive_strategy = ExecutionStrategy::Adaptive;
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExecutionStrategy {
    /// Development execution with full error checking and validation.
    ///
    /// - **Performance**: Lower (extensive validation)
    /// - **Safety**: Highest (full error checking)
    /// - **Use Case**: Development, debugging, testing, untrusted rules
    ///
    /// Features:
    /// - Full bounds checking and validation
    /// - Comprehensive error reporting
    /// - Detailed logging and diagnostics
    /// - Strict execution limits
    Development,

    /// Production execution optimized for performance.
    ///
    /// - **Performance**: High (aggressive optimization)
    /// - **Safety**: Medium (essential checks only)
    /// - **Use Case**: Production systems, high-throughput, trusted rules
    ///
    /// Features:
    /// - Minimal bounds checking
    /// - Fast-path optimizations
    /// - Aggressive caching strategies
    /// - Optimized for maximum throughput
    Production,

    /// Adaptive execution that automatically selects the best strategy.
    ///
    /// - **Performance**: Variable (context-dependent)
    /// - **Safety**: High (intelligent selection)
    /// - **Use Case**: Mixed workloads, automatic optimization
    ///
    /// Features:
    /// - Automatic strategy selection based on rule analysis
    /// - Context-aware safety measures
    /// - Dynamic optimization during execution
    ///
    /// **Default**: This is the recommended strategy for most use cases
    Adaptive,
}

/// Complexity classification for rules based on DAG analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleComplexity {
    /// Simple rules: 1-3 operations, shallow DAG depth, can use optimization
    Simple,
    /// Medium rules: 4-8 operations, moderate DAG depth, benefit from caching
    Medium,
    /// Complex rules: >8 operations, deep DAG structure, require full evaluation
    Complex,
}

impl Default for ExecutionStrategy {
    fn default() -> Self {
        Self::Adaptive
    }
}

impl RuleComplexity {
    /// Analyze rule complexity based on bytecode characteristics.
    pub fn analyze(opcode_count: usize, max_stack_depth: usize, primitive_count: usize) -> Self {
        // Simple rules: few operations, minimal stack usage
        if opcode_count <= 3 && max_stack_depth <= 2 {
            return Self::Simple;
        }

        // Complex rules: many operations or deep stack usage
        if opcode_count > 8 || max_stack_depth > 4 || primitive_count > 10 {
            return Self::Complex;
        }

        // Everything else is medium complexity
        Self::Medium
    }

    /// Get the recommended execution strategy for this complexity level.
    pub fn recommended_strategy(self) -> ExecutionStrategy {
        match self {
            Self::Simple => ExecutionStrategy::Production,
            Self::Medium => ExecutionStrategy::Adaptive,
            Self::Complex => ExecutionStrategy::Adaptive,
        }
    }
}

/// Simplified SIGMA Engine configuration.
///
/// Provides essential configuration options that cover the majority of use cases
/// while reducing complexity and decision paralysis. Only the most commonly used
/// and impactful settings are exposed.
///
/// # Essential Configuration Options
///
/// 1. **Batch Size**: Controls event processing batch size for performance
/// 2. **Execution Strategy**: Controls performance vs safety trade-offs
/// 3. **Parallel Processing**: Enable/disable multi-threading
/// 4. **Prefiltering**: Enable/disable literal pattern prefiltering
/// 5. **Memory Limit**: Maximum memory usage for compiled rules
///
/// # Example
/// ```rust,ignore
/// use sigma_engine::config::{EngineConfig, ExecutionStrategy};
///
/// let config = EngineConfig::new()
///     .with_batch_size(500)
///     .with_execution_strategy(ExecutionStrategy::Production)
///     .with_parallel_processing(true)
///     .with_prefilter(true);
/// ```
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Preferred batch size for processing multiple events together.
    ///
    /// Controls how many events are processed in a single batch operation.
    /// Larger batches improve throughput but increase latency and memory usage.
    ///
    /// **Recommended values:**
    /// - Real-time systems: 10-50
    /// - Standard processing: 100-500
    /// - High-throughput: 1000-5000
    ///
    /// **Default**: 100
    pub batch_size: usize,

    /// Execution strategy controlling performance vs safety trade-offs.
    ///
    /// **Default**: Adaptive (recommended for most use cases)
    pub execution_strategy: ExecutionStrategy,

    /// Enable parallel processing for rule evaluation.
    ///
    /// When enabled, rules are evaluated across multiple threads for better
    /// performance on multi-core systems. Disable for single-threaded environments
    /// or when deterministic execution order is required.
    ///
    /// **Default**: true
    pub enable_parallel_processing: bool,

    /// Enable literal prefiltering for fast event elimination.
    ///
    /// When enabled, events are first checked against literal patterns extracted
    /// from rules. Events that don't contain any required literals are quickly
    /// filtered out before full rule evaluation.
    ///
    /// **Default**: true
    pub enable_prefilter: bool,

    /// Maximum memory usage for compiled rules (in bytes).
    ///
    /// Sets a hard limit on memory used for storing compiled rule data.
    /// When exceeded, compilation will fail with an error.
    ///
    /// **Recommended values:**
    /// - Small deployments (≤100 rules): 64MB
    /// - Medium deployments (≤1000 rules): 256MB
    /// - Large deployments (≤5000 rules): 1GB
    ///
    /// **Default**: 512MB
    pub max_memory_bytes: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            execution_strategy: ExecutionStrategy::Adaptive,
            enable_parallel_processing: true,
            enable_prefilter: true,
            max_memory_bytes: 512 * 1024 * 1024, // 512MB
        }
    }
}

impl EngineConfig {
    /// Create a new engine configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a configuration optimized for production use.
    ///
    /// Enables all performance optimizations and uses production-grade settings
    /// for high-throughput, low-latency processing.
    pub fn production() -> Self {
        Self {
            batch_size: 1000,
            execution_strategy: ExecutionStrategy::Production,
            enable_parallel_processing: true,
            enable_prefilter: true,
            max_memory_bytes: 1024 * 1024 * 1024, // 1GB
        }
    }

    /// Create a configuration for development and debugging.
    ///
    /// Uses conservative settings optimized for debugging and development work.
    /// Disables optimizations that might make debugging difficult.
    pub fn development() -> Self {
        Self {
            batch_size: 10,
            execution_strategy: ExecutionStrategy::Development,
            enable_parallel_processing: false,
            enable_prefilter: false,
            max_memory_bytes: 64 * 1024 * 1024, // 64MB
        }
    }

    // Essential builder methods for common configuration needs

    /// Set the batch size for processing multiple events.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Set the execution strategy.
    pub fn with_execution_strategy(mut self, strategy: ExecutionStrategy) -> Self {
        self.execution_strategy = strategy;
        self
    }

    /// Enable or disable parallel processing.
    pub fn with_parallel_processing(mut self, enable: bool) -> Self {
        self.enable_parallel_processing = enable;
        self
    }

    /// Enable or disable literal prefiltering.
    pub fn with_prefilter(mut self, enable: bool) -> Self {
        self.enable_prefilter = enable;
        self
    }

    /// Set maximum memory usage in bytes.
    pub fn with_max_memory(mut self, bytes: usize) -> Self {
        self.max_memory_bytes = bytes;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EngineConfig::default();

        assert_eq!(config.batch_size, 100);
        assert_eq!(config.execution_strategy, ExecutionStrategy::Adaptive);
        assert!(config.enable_parallel_processing);
        assert!(config.enable_prefilter);
        assert_eq!(config.max_memory_bytes, 512 * 1024 * 1024);
    }

    #[test]
    fn test_production_config() {
        let config = EngineConfig::production();

        assert_eq!(config.batch_size, 1000);
        assert_eq!(config.execution_strategy, ExecutionStrategy::Production);
        assert!(config.enable_parallel_processing);
        assert!(config.enable_prefilter);
        assert_eq!(config.max_memory_bytes, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_development_config() {
        let config = EngineConfig::development();

        assert_eq!(config.batch_size, 10);
        assert_eq!(config.execution_strategy, ExecutionStrategy::Development);
        assert!(!config.enable_parallel_processing);
        assert!(!config.enable_prefilter);
        assert_eq!(config.max_memory_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn test_builder_methods() {
        let config = EngineConfig::new()
            .with_batch_size(500)
            .with_execution_strategy(ExecutionStrategy::Production)
            .with_parallel_processing(false)
            .with_prefilter(true)
            .with_max_memory(256 * 1024 * 1024);

        assert_eq!(config.batch_size, 500);
        assert_eq!(config.execution_strategy, ExecutionStrategy::Production);
        assert!(!config.enable_parallel_processing);
        assert!(config.enable_prefilter);
        assert_eq!(config.max_memory_bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn test_execution_strategy_default() {
        assert_eq!(ExecutionStrategy::default(), ExecutionStrategy::Adaptive);
    }

    #[test]
    fn test_memory_configuration() {
        let config = EngineConfig::new().with_max_memory(256 * 1024 * 1024);

        assert_eq!(config.max_memory_bytes, 256 * 1024 * 1024);
    }
}
