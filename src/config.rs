//! Unified configuration system for SIGMA Engine.
//!
//! This module provides comprehensive configuration control over all aspects
//! of the SIGMA engine including batch processing, memory management,
//! performance tuning, and execution strategies.

use crate::matcher::cache::CacheConfig;
use std::time::Duration;

/// Execution strategy for DAG processing.
///
/// Controls the trade-off between performance and safety during rule execution.
/// Each strategy optimizes for different use cases and performance requirements.
///
/// # Strategy Comparison
///
/// | Strategy | Performance | Safety | Memory | Use Case |
/// |----------|-------------|--------|--------|----------|
/// | `Safe` | Lowest | Highest | Low | Development, debugging |
/// | `Balanced` | Medium | High | Medium | Production default |
/// | `Performance` | High | Medium | Medium | High-throughput systems |
/// | `Adaptive` | Variable | High | Variable | Automatic optimization |
///
/// # Examples
///
/// ```rust
/// use sigma_engine::ExecutionStrategy;
///
/// // For development and testing
/// let safe_strategy = ExecutionStrategy::Safe;
///
/// // For production systems (recommended)
/// let balanced_strategy = ExecutionStrategy::Balanced;
///
/// // For high-performance requirements
/// let performance_strategy = ExecutionStrategy::Performance;
///
/// // Let the engine decide automatically (default)
/// let adaptive_strategy = ExecutionStrategy::Adaptive;
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExecutionStrategy {
    /// Standard safe execution with full error checking and bounds validation.
    ///
    /// - **Performance**: Lowest (extensive validation)
    /// - **Safety**: Highest (full error checking)
    /// - **Memory**: Low (minimal caching)
    /// - **Use Case**: Development, debugging, untrusted rules
    ///
    /// Features:
    /// - Full bounds checking on all operations
    /// - Comprehensive error reporting
    /// - Memory usage tracking
    /// - Strict execution time limits
    /// - Detailed logging and diagnostics
    Safe,

    /// Balanced execution with optimizations but safety guarantees.
    ///
    /// - **Performance**: Medium (optimized with safety)
    /// - **Safety**: High (essential checks only)
    /// - **Memory**: Medium (selective caching)
    /// - **Use Case**: Production default, most applications
    ///
    /// Features:
    /// - Essential bounds checking
    /// - Error reporting for critical issues
    /// - Moderate caching for performance
    /// - Reasonable execution limits
    /// - Good balance of speed and safety
    Balanced,

    /// High-performance execution with aggressive optimizations.
    ///
    /// - **Performance**: High (aggressive optimization)
    /// - **Safety**: Medium (minimal checks)
    /// - **Memory**: Medium (performance caching)
    /// - **Use Case**: High-throughput systems, trusted rules
    ///
    /// Features:
    /// - Minimal bounds checking
    /// - Fast-path optimizations
    /// - Aggressive caching strategies
    /// - Relaxed execution limits
    /// - Optimized for maximum throughput
    Performance,

    /// Adaptive execution that automatically selects the best strategy.
    ///
    /// - **Performance**: Variable (context-dependent)
    /// - **Safety**: High (intelligent selection)
    /// - **Memory**: Variable (adaptive caching)
    /// - **Use Case**: Mixed workloads, automatic optimization
    ///
    /// Features:
    /// - Automatic strategy selection based on rule analysis
    /// - Rule complexity assessment
    /// - Dynamic optimization during execution
    /// - Context-aware safety measures
    ///
    /// The engine analyzes rule characteristics and selects the optimal strategy:
    /// - Simple rules (≤3 operations) → Performance strategy
    /// - Medium rules (4-8 operations) → Balanced strategy
    /// - Complex rules (>8 operations) → Balanced strategy with extra safety
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
            Self::Simple => ExecutionStrategy::Performance,
            Self::Medium => ExecutionStrategy::Balanced,
            Self::Complex => ExecutionStrategy::Balanced,
        }
    }
}

/// Batch processing configuration for optimizing multi-event evaluation.
///
/// Controls how the engine processes multiple events together to achieve
/// optimal performance through shared computation and memory efficiency.
///
/// # Performance Impact
///
/// Batch processing can provide significant performance improvements:
/// - **10x+ speedup** for large batches (1000+ events)
/// - **Shared computation** across events with common primitives
/// - **Memory efficiency** through buffer reuse
/// - **Cache optimization** for repeated patterns
///
/// # Batch Size Guidelines
///
/// | Batch Size | Memory Usage | Latency | Throughput | Use Case |
/// |------------|--------------|---------|------------|----------|
/// | 1-10 | Very Low | Very Low | Low | Interactive, real-time |
/// | 10-100 | Low | Low | Medium | Standard processing |
/// | 100-1000 | Medium | Medium | High | High-throughput |
/// | 1000+ | High | High | Very High | Bulk processing |
///
/// # Examples
///
/// ```rust
/// use sigma_engine::{BatchConfig, ExecutionStrategy};
///
/// // Real-time processing (low latency)
/// let realtime_config = BatchConfig {
///     preferred_batch_size: 10,
///     max_batch_size: 50,
///     enable_early_termination: true,
///     use_preallocated_buffers: true,
///     execution_strategy: ExecutionStrategy::Balanced,
/// };
///
/// // High-throughput processing
/// let throughput_config = BatchConfig {
///     preferred_batch_size: 1000,
///     max_batch_size: 10000,
///     enable_early_termination: false,
///     use_preallocated_buffers: true,
///     execution_strategy: ExecutionStrategy::Performance,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Preferred batch size for processing multiple events.
    ///
    /// This is the target number of events to process together in a single batch.
    /// The engine will attempt to collect this many events before processing,
    /// but may process smaller batches if events arrive slowly.
    ///
    /// **Recommended values:**
    /// - Real-time systems: 10-50
    /// - Standard processing: 100-500
    /// - High-throughput: 1000-5000
    ///
    /// **Default**: 100
    pub preferred_batch_size: usize,

    /// Maximum batch size to prevent memory exhaustion.
    ///
    /// Hard limit on the number of events that can be processed in a single batch.
    /// This prevents memory exhaustion when events arrive faster than they can be processed.
    ///
    /// **Recommended values:**
    /// - Memory-constrained: 1000-5000
    /// - Standard systems: 10000-50000
    /// - High-memory systems: 100000+
    ///
    /// **Default**: 10000
    pub max_batch_size: usize,

    /// Enable early termination on first match per event.
    ///
    /// When enabled, the engine stops evaluating rules for an event as soon as
    /// the first rule matches. This can significantly improve performance when
    /// you only need to know if any rule matches, not which specific rules match.
    ///
    /// **Use cases:**
    /// - Alert systems (any match triggers action)
    /// - Filtering systems (pass/fail decisions)
    /// - Performance-critical systems
    ///
    /// **Trade-offs:**
    /// - + Faster processing for events with matches
    /// - - Incomplete match information
    /// - - Non-deterministic results (order-dependent)
    ///
    /// **Default**: false
    pub enable_early_termination: bool,

    /// Use pre-allocated buffers for zero-allocation processing.
    ///
    /// When enabled, the engine pre-allocates and reuses memory buffers for
    /// batch processing, eliminating allocations during the hot path.
    ///
    /// **Benefits:**
    /// - Zero allocations during processing
    /// - Reduced garbage collection pressure
    /// - More predictable performance
    /// - Lower memory fragmentation
    ///
    /// **Trade-offs:**
    /// - + Better performance and predictability
    /// - - Higher baseline memory usage
    /// - - Memory not released between batches
    ///
    /// **Default**: true (recommended for most use cases)
    pub use_preallocated_buffers: bool,

    /// Default execution strategy for batch processing.
    ///
    /// Determines the performance/safety trade-off for batch operations.
    /// Can be overridden per batch if needed.
    ///
    /// **Strategy selection:**
    /// - `Safe`: Development, debugging, untrusted rules
    /// - `Balanced`: Production default (recommended)
    /// - `Performance`: High-throughput systems
    /// - `Adaptive`: Automatic optimization (default)
    ///
    /// **Default**: Adaptive
    pub execution_strategy: ExecutionStrategy,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            preferred_batch_size: 100,
            max_batch_size: 10000,
            enable_early_termination: false,
            use_preallocated_buffers: true,
            execution_strategy: ExecutionStrategy::Adaptive,
        }
    }
}

/// Memory management configuration for optimizing memory usage and performance.
///
/// Controls how the engine manages memory allocation and buffer pre-allocation
/// for large rule sets. Proper memory configuration can significantly impact
/// both performance and memory efficiency.
///
/// # Memory Optimization Strategies
///
/// 1. **Buffer Pre-allocation**: Reduces allocation overhead
/// 2. **Capacity Planning**: Optimizes initial allocations
///
/// # Memory Usage Guidelines
///
/// | Rule Count | Compiled Memory |
/// |------------|-----------------|
/// | 1-100 | 16MB |
/// | 100-1000 | 64MB |
/// | 1000-5000 | 256MB |
/// | 5000+ | 512MB+ |
///
/// # Examples
///
/// ```rust
/// use sigma_engine::MemoryConfig;
///
/// // Memory-efficient configuration for small deployments
/// let efficient_config = MemoryConfig {
///     max_compiled_memory: 64 * 1024 * 1024, // 64MB
/// };
///
/// // High-capacity configuration for large deployments
/// let large_config = MemoryConfig {
///     max_compiled_memory: 2 * 1024 * 1024 * 1024, // 2GB
/// };
/// ```
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    /// Maximum memory usage for compiled primitives (in bytes).
    ///
    /// Sets a hard limit on the amount of memory that can be used for storing
    /// compiled rule primitives. When this limit is reached, the engine will
    /// either reject new rules or use memory mapping if enabled.
    ///
    /// **Sizing guidelines:**
    /// - Small deployments (≤100 rules): 16-64MB
    /// - Medium deployments (100-1000 rules): 64-256MB
    /// - Large deployments (1000-5000 rules): 256MB-1GB
    /// - Enterprise deployments (5000+ rules): 1GB+
    ///
    /// **Default**: 512MB
    pub max_compiled_memory: usize,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_compiled_memory: 512 * 1024 * 1024, // 512MB
        }
    }
}

/// Performance tuning configuration.
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Enable performance metrics collection
    pub enable_metrics: bool,
    /// Execution timeout per rule (None for no timeout)
    pub execution_timeout: Option<Duration>,
    /// Execution strategy for DAG processing
    pub execution_strategy: ExecutionStrategy,
    /// Enable DAG optimization passes
    pub enable_dag_optimization: bool,
    /// DAG optimization level (0-3, higher = more aggressive)
    pub dag_optimization_level: u8,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enable_metrics: false,
            execution_timeout: Some(Duration::from_millis(100)),
            execution_strategy: ExecutionStrategy::Adaptive,
            enable_dag_optimization: true,
            dag_optimization_level: 2,
        }
    }
}

/// Security and safety configuration.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Enable regex complexity analysis
    pub enable_regex_analysis: bool,
    /// Reject potentially dangerous regex patterns
    pub reject_dangerous_patterns: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_regex_analysis: true,
            reject_dangerous_patterns: true,
        }
    }
}

/// Configuration for parallel processing in the DAG engine.
#[derive(Debug, Clone, PartialEq)]
pub struct ParallelConfig {
    /// Number of threads to use for parallel processing.
    pub num_threads: usize,
    /// Minimum number of rules per thread for parallel processing.
    pub min_rules_per_thread: usize,
    /// Enable parallel processing of events within batches.
    pub enable_event_parallelism: bool,
    /// Minimum batch size to enable parallel processing.
    pub min_batch_size_for_parallelism: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            num_threads: num_cpus::get(),
            min_rules_per_thread: 10,
            enable_event_parallelism: true,
            min_batch_size_for_parallelism: 100,
        }
    }
}

/// Comprehensive SIGMA Engine configuration.
///
/// This structure provides centralized control over all aspects of the SIGMA engine
/// including batch processing, memory management, performance tuning, security,
/// parallel processing, and prefiltering.
///
/// # Example
/// ```rust,ignore
/// use sigma_engine::config::{EngineConfig, ExecutionStrategy};
///
/// let config = EngineConfig::new()
///     .with_batch_size(500)
///     .with_execution_strategy(ExecutionStrategy::Performance)
///     .with_parallel_processing(true)
///     .with_prefilter(true);
/// ```
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Batch processing configuration
    pub batch: BatchConfig,
    /// Memory management configuration
    pub memory: MemoryConfig,
    /// Performance tuning configuration
    pub performance: PerformanceConfig,
    /// Security and safety configuration
    pub security: SecurityConfig,
    /// Regex cache configuration
    pub cache: CacheConfig,
    /// Enable parallel processing for rule evaluation
    pub enable_parallel_processing: bool,
    /// Parallel processing configuration
    pub parallel_config: ParallelConfig,
    /// Enable literal prefiltering for fast event elimination
    pub enable_prefilter: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            batch: BatchConfig::default(),
            memory: MemoryConfig::default(),
            performance: PerformanceConfig::default(),
            security: SecurityConfig::default(),
            cache: CacheConfig::default(),
            enable_parallel_processing: false,
            parallel_config: ParallelConfig::default(),
            enable_prefilter: true,
        }
    }
}

impl EngineConfig {
    /// Create a new engine configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a configuration optimized for high-throughput processing.
    pub fn high_throughput() -> Self {
        Self {
            batch: BatchConfig {
                preferred_batch_size: 1000,
                max_batch_size: 50000,
                enable_early_termination: true,
                use_preallocated_buffers: true,
                execution_strategy: ExecutionStrategy::Performance,
            },
            memory: MemoryConfig {
                ..Default::default()
            },
            performance: PerformanceConfig {
                enable_metrics: false,
                execution_timeout: Some(Duration::from_millis(10)),
                enable_dag_optimization: true,
                dag_optimization_level: 3,
                ..Default::default()
            },
            security: SecurityConfig {
                ..Default::default()
            },
            cache: CacheConfig {
                max_size: 5000,
                hot_threshold: 5,
                warm_threshold: 2,
                analyze_complexity: false, // Skip for performance
                reject_dangerous: true,
            },
            enable_parallel_processing: true,
            parallel_config: ParallelConfig {
                num_threads: rayon::current_num_threads(),
                min_rules_per_thread: 5,
                enable_event_parallelism: true,
                min_batch_size_for_parallelism: 50,
            },
            enable_prefilter: true,
        }
    }

    /// Create a configuration optimized for memory efficiency.
    pub fn memory_efficient() -> Self {
        Self {
            batch: BatchConfig {
                preferred_batch_size: 50,
                max_batch_size: 1000,
                use_preallocated_buffers: true,
                ..Default::default()
            },
            memory: MemoryConfig {
                max_compiled_memory: 64 * 1024 * 1024, // 64MB
            },
            performance: PerformanceConfig {
                enable_metrics: false,
                dag_optimization_level: 1, // Lower optimization for memory efficiency
                ..Default::default()
            },
            cache: CacheConfig {
                max_size: 500,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create a configuration for development and debugging.
    pub fn development() -> Self {
        Self {
            batch: BatchConfig {
                preferred_batch_size: 10,
                execution_strategy: ExecutionStrategy::Safe,
                ..Default::default()
            },
            performance: PerformanceConfig {
                enable_metrics: true,
                execution_timeout: Some(Duration::from_secs(1)),
                ..Default::default()
            },
            security: SecurityConfig {
                ..Default::default()
            },
            cache: CacheConfig {
                analyze_complexity: true,
                reject_dangerous: true,
                ..Default::default()
            },
            enable_parallel_processing: false,
            enable_prefilter: false,
            ..Default::default()
        }
    }

    /// Create a configuration optimized for high-performance parallel processing.
    pub fn high_performance() -> Self {
        Self {
            batch: BatchConfig {
                preferred_batch_size: 1000,
                execution_strategy: ExecutionStrategy::Performance,
                enable_early_termination: true,
                ..Default::default()
            },
            performance: PerformanceConfig {
                enable_dag_optimization: true,
                dag_optimization_level: 3,
                execution_strategy: ExecutionStrategy::Performance,
                ..Default::default()
            },
            enable_parallel_processing: true,
            parallel_config: ParallelConfig {
                num_threads: rayon::current_num_threads(),
                min_rules_per_thread: 5,
                enable_event_parallelism: true,
                min_batch_size_for_parallelism: 50,
            },
            enable_prefilter: true,
            ..Default::default()
        }
    }

    /// Create a configuration for streaming workloads.
    pub fn streaming() -> Self {
        Self {
            batch: BatchConfig {
                preferred_batch_size: 500,
                execution_strategy: ExecutionStrategy::Performance,
                enable_early_termination: false, // Process all events in stream
                ..Default::default()
            },
            performance: PerformanceConfig {
                enable_dag_optimization: true,
                dag_optimization_level: 3,
                execution_strategy: ExecutionStrategy::Performance,
                ..Default::default()
            },
            enable_parallel_processing: true,
            parallel_config: ParallelConfig {
                num_threads: rayon::current_num_threads(),
                min_rules_per_thread: 10,
                enable_event_parallelism: true,
                min_batch_size_for_parallelism: 100,
            },
            enable_prefilter: true,
            ..Default::default()
        }
    }

    // Builder methods for batch configuration

    /// Set the preferred batch size for processing.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch.preferred_batch_size = size;
        self
    }

    /// Set the maximum batch size.
    pub fn with_max_batch_size(mut self, size: usize) -> Self {
        self.batch.max_batch_size = size;
        self
    }

    /// Set the execution strategy.
    pub fn with_execution_strategy(mut self, strategy: ExecutionStrategy) -> Self {
        self.batch.execution_strategy = strategy;
        self
    }

    /// Enable or disable early termination on first match.
    pub fn with_early_termination(mut self, enable: bool) -> Self {
        self.batch.enable_early_termination = enable;
        self
    }

    /// Enable or disable pre-allocated buffers.
    pub fn with_preallocated_buffers(mut self, enable: bool) -> Self {
        self.batch.use_preallocated_buffers = enable;
        self
    }

    // Builder methods for memory configuration

    /// Set maximum compiled memory usage.
    pub fn with_max_memory(mut self, bytes: usize) -> Self {
        self.memory.max_compiled_memory = bytes;
        self
    }

    // Builder methods for performance configuration

    /// Enable or disable performance metrics collection.
    pub fn with_metrics(mut self, enable: bool) -> Self {
        self.performance.enable_metrics = enable;
        self
    }

    /// Set execution timeout per rule.
    pub fn with_execution_timeout(mut self, timeout: Duration) -> Self {
        self.performance.execution_timeout = Some(timeout);
        self
    }

    /// Enable or disable DAG optimization passes.
    pub fn with_dag_optimization(mut self, enable: bool) -> Self {
        self.performance.enable_dag_optimization = enable;
        self
    }

    /// Set DAG optimization level (0-3).
    pub fn with_dag_optimization_level(mut self, level: u8) -> Self {
        self.performance.dag_optimization_level = level.min(3);
        self
    }

    /// Disable execution timeout.
    pub fn without_execution_timeout(mut self) -> Self {
        self.performance.execution_timeout = None;
        self
    }

    // Builder methods for parallel processing configuration

    /// Enable or disable parallel processing.
    pub fn with_parallel_processing(mut self, enable: bool) -> Self {
        self.enable_parallel_processing = enable;
        self
    }

    /// Set the number of threads for parallel processing.
    pub fn with_parallel_threads(mut self, num_threads: usize) -> Self {
        self.parallel_config.num_threads = num_threads;
        self
    }

    /// Set minimum rules per thread for parallel processing.
    pub fn with_min_rules_per_thread(mut self, min_rules: usize) -> Self {
        self.parallel_config.min_rules_per_thread = min_rules;
        self
    }

    /// Enable or disable event parallelism within batches.
    pub fn with_event_parallelism(mut self, enable: bool) -> Self {
        self.parallel_config.enable_event_parallelism = enable;
        self
    }

    /// Set minimum batch size for parallel processing.
    pub fn with_min_batch_size_for_parallelism(mut self, min_size: usize) -> Self {
        self.parallel_config.min_batch_size_for_parallelism = min_size;
        self
    }

    // Builder methods for prefilter configuration

    /// Enable or disable literal prefiltering.
    pub fn with_prefilter(mut self, enable: bool) -> Self {
        self.enable_prefilter = enable;
        self
    }

    // Builder methods for security configuration

    /// Enable or disable regex complexity analysis.
    pub fn with_regex_analysis(mut self, enable: bool) -> Self {
        self.security.enable_regex_analysis = enable;
        self
    }

    // Builder methods for cache configuration

    /// Set the maximum cache size.
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache.max_size = size;
        self
    }

    /// Set cache hot threshold.
    pub fn with_hot_threshold(mut self, threshold: usize) -> Self {
        self.cache.hot_threshold = threshold;
        self
    }

    /// Enable or disable dangerous pattern rejection.
    pub fn with_dangerous_pattern_rejection(mut self, enable: bool) -> Self {
        self.cache.reject_dangerous = enable;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EngineConfig::default();

        assert_eq!(config.batch.preferred_batch_size, 100);
        assert_eq!(config.batch.execution_strategy, ExecutionStrategy::Adaptive);
        assert!(config.performance.enable_dag_optimization);
        assert_eq!(config.performance.dag_optimization_level, 2);

        assert_eq!(config.cache.max_size, 1000);
    }

    #[test]
    fn test_high_throughput_config() {
        let config = EngineConfig::high_throughput();

        assert_eq!(config.batch.preferred_batch_size, 1000);
        assert_eq!(
            config.batch.execution_strategy,
            ExecutionStrategy::Performance
        );
        assert!(config.batch.enable_early_termination);

        assert!(config.performance.enable_dag_optimization);
        assert_eq!(config.performance.dag_optimization_level, 3);
    }

    #[test]
    fn test_memory_efficient_config() {
        let config = EngineConfig::memory_efficient();

        assert_eq!(config.batch.preferred_batch_size, 50);
        assert_eq!(config.memory.max_compiled_memory, 64 * 1024 * 1024);
        assert_eq!(config.performance.dag_optimization_level, 1);
        assert_eq!(config.cache.max_size, 500);
    }

    #[test]
    fn test_development_config() {
        let config = EngineConfig::development();

        assert_eq!(config.batch.preferred_batch_size, 10);
        assert_eq!(config.batch.execution_strategy, ExecutionStrategy::Safe);
        assert!(config.performance.enable_metrics);

        assert!(config.cache.analyze_complexity);
    }

    #[test]
    fn test_builder_methods() {
        let config = EngineConfig::new()
            .with_batch_size(500)
            .with_execution_strategy(ExecutionStrategy::Performance)
            .with_dag_optimization_level(3)
            .with_metrics(true)
            .with_execution_timeout(Duration::from_millis(50))
            .with_cache_size(2000);

        assert_eq!(config.batch.preferred_batch_size, 500);
        assert_eq!(
            config.batch.execution_strategy,
            ExecutionStrategy::Performance
        );

        assert_eq!(config.performance.dag_optimization_level, 3);
        assert!(config.performance.enable_metrics);
        assert_eq!(
            config.performance.execution_timeout,
            Some(Duration::from_millis(50))
        );
        assert_eq!(config.cache.max_size, 2000);
    }

    #[test]
    fn test_execution_strategy_default() {
        assert_eq!(ExecutionStrategy::default(), ExecutionStrategy::Adaptive);
    }

    #[test]
    fn test_timeout_configuration() {
        let config = EngineConfig::new()
            .with_execution_timeout(Duration::from_millis(100))
            .without_execution_timeout();

        assert_eq!(config.performance.execution_timeout, None);
    }

    #[test]
    fn test_security_configuration() {
        let config = EngineConfig::new().with_regex_analysis(false);

        assert!(!config.security.enable_regex_analysis);
    }

    #[test]
    fn test_memory_configuration() {
        let config = EngineConfig::new().with_max_memory(256 * 1024 * 1024);

        assert_eq!(config.memory.max_compiled_memory, 256 * 1024 * 1024);
    }

    #[test]
    fn test_batch_configuration() {
        let config = EngineConfig::new()
            .with_max_batch_size(20000)
            .with_early_termination(true)
            .with_preallocated_buffers(false);

        assert_eq!(config.batch.max_batch_size, 20000);
        assert!(config.batch.enable_early_termination);
        assert!(!config.batch.use_preallocated_buffers);
    }
}
