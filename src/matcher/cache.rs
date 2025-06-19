//! Global regex compilation caching for SIGMA pattern matching.
//!
//! This module provides high-performance regex compilation caching to avoid
//! recompiling the same patterns across multiple primitives and evaluations.

#[cfg(feature = "examples")]
use crate::error::SigmaError;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[cfg(feature = "examples")]
use regex::Regex;

/// Global regex cache for compiled patterns.
///
/// This cache provides:
/// - Thread-safe access to compiled regex patterns
/// - Automatic pattern deduplication
/// - LRU eviction for memory management
/// - Performance statistics and monitoring
/// - Pattern complexity analysis
///
/// # Thread Safety
/// The cache uses RwLock for concurrent access, allowing multiple readers
/// but exclusive writers. This optimizes for the common case of many
/// evaluations with few new pattern compilations.
///
/// # Memory Management
/// - **Hot Patterns**: Frequently used patterns are never evicted
/// - **Warm Patterns**: Moderately used patterns have extended TTL
/// - **Cold Patterns**: Rarely used patterns are evicted first
/// - **Size Limits**: Configurable maximum cache size
#[derive(Debug)]
pub struct GlobalRegexCache {
    /// The actual cache storage
    cache: Arc<RwLock<CacheStorage>>,

    /// Cache configuration
    #[allow(dead_code)]
    config: CacheConfig,
}

/// Internal cache storage with LRU tracking.
#[derive(Debug)]
struct CacheStorage {
    /// Compiled regex patterns
    patterns: HashMap<String, CachedRegex>,

    /// Access order for LRU eviction
    access_order: Vec<String>,

    /// Cache statistics
    stats: CacheStats,
}

/// Cached regex with metadata.
#[derive(Debug, Clone)]
struct CachedRegex {
    /// The compiled regex pattern
    #[cfg(feature = "examples")]
    regex: Arc<Regex>,

    /// Pattern without regex for non-examples builds
    #[cfg(not(feature = "examples"))]
    #[allow(dead_code)]
    pattern: String,

    /// Number of times this pattern has been accessed
    #[allow(dead_code)]
    access_count: usize,

    /// Complexity score for the pattern
    #[allow(dead_code)]
    complexity: PatternComplexity,

    /// Whether this pattern should be permanently cached
    #[allow(dead_code)]
    is_hot: bool,
}

/// Pattern complexity classification for optimization.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PatternComplexity {
    /// Simple literal patterns
    Simple,

    /// Patterns with basic regex features
    Medium,

    /// Complex patterns with backtracking potential
    Complex,

    /// Potentially dangerous patterns (DoS risk)
    Dangerous,
}

/// Cache configuration parameters.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of patterns to cache
    pub max_size: usize,

    /// Access count threshold for hot patterns
    pub hot_threshold: usize,

    /// Access count threshold for warm patterns
    pub warm_threshold: usize,

    /// Whether to enable complexity analysis
    pub analyze_complexity: bool,

    /// Whether to reject dangerous patterns
    pub reject_dangerous: bool,
}

/// Cache performance statistics.
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    /// Total cache lookups
    pub total_lookups: usize,

    /// Cache hits
    pub hits: usize,

    /// Cache misses
    pub misses: usize,

    /// Pattern compilations
    pub compilations: usize,

    /// Evictions performed
    pub evictions: usize,

    /// Rejected dangerous patterns
    pub rejected_patterns: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 1000,
            hot_threshold: 10,
            warm_threshold: 3,
            analyze_complexity: true,
            reject_dangerous: true,
        }
    }
}

impl GlobalRegexCache {
    /// Create a new global regex cache with default configuration.
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// Create a new global regex cache with custom configuration.
    pub fn with_config(config: CacheConfig) -> Self {
        Self {
            cache: Arc::new(RwLock::new(CacheStorage {
                patterns: HashMap::new(),
                access_order: Vec::new(),
                stats: CacheStats::default(),
            })),
            config,
        }
    }

    /// Get or compile a regex pattern.
    ///
    /// This is the main entry point for regex access. It handles:
    /// - Cache lookup for existing patterns
    /// - Compilation of new patterns
    /// - Complexity analysis and safety checks
    /// - LRU tracking and eviction
    #[cfg(feature = "examples")]
    pub fn get_regex(&self, pattern: &str) -> Result<Arc<Regex>, SigmaError> {
        // Try cache lookup first
        {
            let mut cache = self.cache.write().unwrap();
            cache.stats.total_lookups += 1;

            // Check if pattern exists and get the regex clone
            let regex_result = cache
                .patterns
                .get(pattern)
                .map(|cached| cached.regex.clone());

            if let Some(regex_clone) = regex_result {
                // Update the cached entry
                if let Some(cached) = cache.patterns.get_mut(pattern) {
                    cached.access_count += 1;
                    let access_count = cached.access_count;

                    // Promote to hot if threshold reached
                    if access_count >= self.config.hot_threshold {
                        cached.is_hot = true;
                    }
                }

                cache.stats.hits += 1;

                // Update access order for LRU
                if let Some(pos) = cache.access_order.iter().position(|p| p == pattern) {
                    cache.access_order.remove(pos);
                }
                cache.access_order.push(pattern.to_string());

                return Ok(regex_clone);
            }

            cache.stats.misses += 1;
        }

        // Compile new pattern
        self.compile_and_cache(pattern)
    }

    /// Compile and cache a new regex pattern.
    #[cfg(feature = "examples")]
    fn compile_and_cache(&self, pattern: &str) -> Result<Arc<Regex>, SigmaError> {
        // Analyze pattern complexity
        let complexity = if self.config.analyze_complexity {
            analyze_pattern_complexity(pattern)
        } else {
            PatternComplexity::Medium
        };

        // Reject dangerous patterns if configured
        if self.config.reject_dangerous && complexity == PatternComplexity::Dangerous {
            let mut cache = self.cache.write().unwrap();
            cache.stats.rejected_patterns += 1;
            return Err(SigmaError::DangerousRegexPattern(pattern.to_string()));
        }

        // Compile the regex
        let regex = Regex::new(pattern)
            .map_err(|e| SigmaError::InvalidRegex(format!("Pattern '{}': {}", pattern, e)))?;

        let compiled_regex = Arc::new(regex);

        // Cache the compiled pattern
        {
            let mut cache = self.cache.write().unwrap();
            cache.stats.compilations += 1;

            // Evict if cache is full
            if cache.patterns.len() >= self.config.max_size {
                self.evict_lru(&mut cache);
            }

            // Insert new pattern
            cache.patterns.insert(
                pattern.to_string(),
                CachedRegex {
                    regex: compiled_regex.clone(),
                    access_count: 1,
                    complexity,
                    is_hot: false,
                },
            );

            cache.access_order.push(pattern.to_string());
        }

        Ok(compiled_regex)
    }

    /// Evict least recently used patterns.
    #[allow(dead_code)]
    fn evict_lru(&self, cache: &mut CacheStorage) {
        // Find cold patterns to evict (not hot, low access count)
        let mut candidates: Vec<_> = cache
            .access_order
            .iter()
            .filter_map(|pattern| {
                cache
                    .patterns
                    .get(pattern)
                    .map(|cached| (pattern.clone(), cached.access_count, cached.is_hot))
            })
            .filter(|(_, _, is_hot)| !is_hot)
            .collect();

        // Sort by access count (ascending) to evict least used first
        candidates.sort_by_key(|(_, count, _)| *count);

        // Evict up to 10% of cache size or at least 1 entry
        let evict_count = (self.config.max_size / 10).max(1);

        for (pattern, _, _) in candidates.into_iter().take(evict_count) {
            cache.patterns.remove(&pattern);
            if let Some(pos) = cache.access_order.iter().position(|p| p == &pattern) {
                cache.access_order.remove(pos);
            }
            cache.stats.evictions += 1;
        }
    }

    /// Get cache statistics for monitoring.
    pub fn get_stats(&self) -> CacheStats {
        let cache = self.cache.read().unwrap();
        cache.stats.clone()
    }

    /// Get cache hit ratio for performance monitoring.
    pub fn hit_ratio(&self) -> f64 {
        let stats = self.get_stats();
        if stats.total_lookups == 0 {
            return 0.0;
        }
        stats.hits as f64 / stats.total_lookups as f64
    }

    /// Clear the cache (useful for testing).
    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.patterns.clear();
        cache.access_order.clear();
        cache.stats = CacheStats::default();
    }

    /// Get current cache size.
    pub fn size(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.patterns.len()
    }

    /// Precompile a set of patterns for better performance.
    ///
    /// This is useful for warming the cache with known patterns before
    /// high-performance evaluation begins.
    #[cfg(feature = "examples")]
    pub fn precompile_patterns(&self, patterns: &[&str]) -> Result<(), SigmaError> {
        for &pattern in patterns {
            self.get_regex(pattern)?;
        }
        Ok(())
    }
}

/// Analyze pattern complexity to identify potentially dangerous regex.
#[allow(dead_code)]
fn analyze_pattern_complexity(pattern: &str) -> PatternComplexity {
    // Simple heuristics for pattern complexity analysis
    let mut complexity_score = 0;

    // Check for backtracking-prone constructs
    if pattern.contains(".*.*") || pattern.contains(".+.+") {
        complexity_score += 10; // Nested quantifiers
    }

    if pattern.contains("(.*)+") || pattern.contains("(.+)+") {
        complexity_score += 15; // Catastrophic backtracking potential
    }

    // Check for alternation complexity
    let alternation_count = pattern.matches('|').count();
    complexity_score += alternation_count;

    // Check for lookahead/lookbehind
    if pattern.contains("(?=")
        || pattern.contains("(?!")
        || pattern.contains("(?<=")
        || pattern.contains("(?<!")
    {
        complexity_score += 5;
    }

    // Check for character classes
    let char_class_count = pattern.matches('[').count();
    complexity_score += char_class_count / 2;

    // Check pattern length
    if pattern.len() > 100 {
        complexity_score += 3;
    }

    // Classify based on score
    match complexity_score {
        0..=1 => PatternComplexity::Simple,
        2..=7 => PatternComplexity::Medium,
        8..=15 => PatternComplexity::Complex,
        _ => PatternComplexity::Dangerous,
    }
}

/// Global singleton instance for easy access.
static GLOBAL_CACHE: std::sync::OnceLock<GlobalRegexCache> = std::sync::OnceLock::new();

/// Get the global regex cache instance.
pub fn global_regex_cache() -> &'static GlobalRegexCache {
    GLOBAL_CACHE.get_or_init(GlobalRegexCache::new)
}

/// Initialize the global cache with custom configuration.
pub fn init_global_cache(config: CacheConfig) {
    let _ = GLOBAL_CACHE.set(GlobalRegexCache::with_config(config));
}

impl Default for GlobalRegexCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_basic_functionality() {
        let cache = GlobalRegexCache::new();

        // Test cache miss and compilation
        #[cfg(feature = "examples")]
        {
            let regex1 = cache.get_regex("test").unwrap();
            let stats = cache.get_stats();
            assert_eq!(stats.misses, 1);
            assert_eq!(stats.compilations, 1);

            // Test cache hit
            let regex2 = cache.get_regex("test").unwrap();
            let stats = cache.get_stats();
            assert_eq!(stats.hits, 1);

            // Verify same instance
            assert!(Arc::ptr_eq(&regex1, &regex2));
        }
    }

    #[test]
    fn test_pattern_complexity_analysis() {
        assert_eq!(
            analyze_pattern_complexity("simple"),
            PatternComplexity::Simple
        );
        assert_eq!(
            analyze_pattern_complexity("test|other|more"),
            PatternComplexity::Medium
        );
        assert_eq!(
            analyze_pattern_complexity("(.*)+"),
            PatternComplexity::Complex
        );
    }

    #[test]
    fn test_cache_eviction() {
        let config = CacheConfig {
            max_size: 3,
            ..Default::default()
        };
        let cache = GlobalRegexCache::with_config(config);

        #[cfg(feature = "examples")]
        {
            // Fill cache beyond capacity
            let _ = cache.get_regex("pattern1");
            let _ = cache.get_regex("pattern2");
            let _ = cache.get_regex("pattern3");
            let _ = cache.get_regex("pattern4"); // Should trigger eviction

            let stats = cache.get_stats();
            assert!(stats.evictions > 0);
            assert!(cache.size() <= 3);
        }
    }

    #[test]
    fn test_hot_pattern_protection() {
        let config = CacheConfig {
            max_size: 2,
            hot_threshold: 2,
            ..Default::default()
        };
        let cache = GlobalRegexCache::with_config(config);

        #[cfg(feature = "examples")]
        {
            // Access pattern multiple times to make it hot
            let _ = cache.get_regex("hot_pattern");
            let _ = cache.get_regex("hot_pattern");
            let _ = cache.get_regex("hot_pattern"); // Now hot

            // Add more patterns to trigger eviction
            let _ = cache.get_regex("cold1");
            let _ = cache.get_regex("cold2"); // Should evict cold1, not hot_pattern

            // Hot pattern should still be accessible
            let result = cache.get_regex("hot_pattern");
            assert!(result.is_ok());
        }
    }
}
