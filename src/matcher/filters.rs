//! External filter integration helpers for multi-layer processing.
//!
//! This module provides utilities for extracting patterns and values from SIGMA
//! primitives to populate external filtering libraries like AhoCorasick, FST,
//! XOR filters, and Cuckoo filters for high-performance pre-filtering.

use crate::error::SigmaError;
use crate::ir::Primitive;
use crate::matcher::hooks::{CompilationContext, CompilationHookFn};
use std::collections::HashMap;
use std::sync::Arc;

/// Statistics collected during filter compilation for optimization decisions.
#[derive(Debug, Clone, Default)]
pub struct FilterCompilationStats {
    /// Total number of primitives processed
    pub total_primitives: usize,
    /// Number of literal-only primitives (suitable for fast filters)
    pub literal_primitives: usize,
    /// Number of regex primitives (need separate handling)
    pub regex_primitives: usize,
    /// Number of unique fields encountered
    pub unique_fields: usize,
    /// Average selectivity across all patterns
    pub average_selectivity: f64,
    /// Estimated memory usage for filters (in bytes)
    pub estimated_memory_usage: usize,
}

/// Helper for collecting patterns and values for external filter integration.
///
/// This struct accumulates patterns during compilation phase hooks and provides
/// convenient methods for building external filters with optimal performance.
///
/// # Supported Filter Types
/// - **AhoCorasick**: Multi-pattern string matching
/// - **FST (Finite State Transducer)**: Ordered string sets
/// - **XOR/Cuckoo Filters**: Probabilistic membership testing
/// - **Bloom Filters**: Probabilistic membership with false positives
///
/// # Performance Considerations
/// - Patterns are deduplicated automatically
/// - Field-specific grouping for targeted filtering
/// - Selectivity hints for optimization decisions
/// - Zero-copy pattern extraction where possible
#[derive(Debug, Clone, Default)]
pub struct FilterIntegration {
    /// Collected literal patterns for AhoCorasick multi-pattern matching
    pub aho_corasick_patterns: Vec<String>,

    /// Field-to-patterns mapping for field-specific filtering
    pub field_patterns: HashMap<String, Vec<String>>,

    /// Collected values for FST construction (automatically sorted)
    pub fst_values: Vec<String>,

    /// Values suitable for XOR/Cuckoo filter insertion
    pub filter_values: Vec<String>,

    /// Regex patterns that need separate handling
    pub regex_patterns: Vec<String>,

    /// Values suitable for Bloom filter insertion
    pub bloom_filter_values: Vec<String>,

    /// Values suitable for XOR filter insertion (requires exact membership)
    pub xor_filter_values: Vec<String>,

    /// Selectivity hints for optimization (pattern -> selectivity score)
    pub selectivity_map: HashMap<String, f64>,

    /// Pattern frequency counts for optimization
    pub pattern_frequency: HashMap<String, usize>,

    /// Field access frequency for cache optimization
    pub field_frequency: HashMap<String, usize>,

    /// Zero-copy pattern references for optimization
    pub zero_copy_patterns: Vec<&'static str>,

    /// Compilation statistics for optimization decisions
    pub compilation_stats: FilterCompilationStats,
}

impl FilterIntegration {
    /// Create a new FilterIntegration helper.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a literal pattern for AhoCorasick matching.
    ///
    /// # Arguments
    /// * `pattern` - The literal string pattern
    /// * `field` - Optional field name for field-specific filtering
    /// * `selectivity` - Selectivity hint (0.0 = very selective, 1.0 = matches everything)
    pub fn add_aho_corasick_pattern(
        &mut self,
        pattern: &str,
        field: Option<&str>,
        selectivity: f64,
    ) {
        // Deduplicate patterns
        if !self.aho_corasick_patterns.contains(&pattern.to_string()) {
            self.aho_corasick_patterns.push(pattern.to_string());
        }

        // Track field-specific patterns
        if let Some(field_name) = field {
            self.field_patterns
                .entry(field_name.to_string())
                .or_default()
                .push(pattern.to_string());

            // Track field frequency
            *self
                .field_frequency
                .entry(field_name.to_string())
                .or_insert(0) += 1;
        }

        // Track selectivity and frequency
        self.selectivity_map
            .insert(pattern.to_string(), selectivity);
        *self
            .pattern_frequency
            .entry(pattern.to_string())
            .or_insert(0) += 1;
    }

    /// Add a value for FST construction.
    ///
    /// FST values are automatically sorted and deduplicated for optimal performance.
    pub fn add_fst_value(&mut self, value: &str, selectivity: f64) {
        if !self.fst_values.contains(&value.to_string()) {
            self.fst_values.push(value.to_string());
        }
        self.selectivity_map.insert(value.to_string(), selectivity);
    }

    /// Add a value for probabilistic filter (XOR/Cuckoo/Bloom).
    ///
    /// These filters are optimized for membership testing with controlled false positive rates.
    pub fn add_filter_value(&mut self, value: &str, selectivity: f64) {
        if !self.filter_values.contains(&value.to_string()) {
            self.filter_values.push(value.to_string());
        }
        self.selectivity_map.insert(value.to_string(), selectivity);
    }

    /// Add a regex pattern for separate processing.
    ///
    /// Regex patterns typically require separate compilation and cannot be
    /// efficiently handled by literal string filters.
    pub fn add_regex_pattern(&mut self, pattern: &str, field: Option<&str>, selectivity: f64) {
        if !self.regex_patterns.contains(&pattern.to_string()) {
            self.regex_patterns.push(pattern.to_string());
        }

        if let Some(field_name) = field {
            *self
                .field_frequency
                .entry(field_name.to_string())
                .or_insert(0) += 1;
        }

        self.selectivity_map
            .insert(pattern.to_string(), selectivity);
    }

    /// Add a value for Bloom filter insertion.
    ///
    /// Bloom filters provide probabilistic membership testing with false positives
    /// but no false negatives. Suitable for pre-filtering with high-volume data.
    pub fn add_bloom_filter_value(&mut self, value: &str, selectivity: f64) {
        if !self.bloom_filter_values.contains(&value.to_string()) {
            self.bloom_filter_values.push(value.to_string());
        }

        self.selectivity_map.insert(value.to_string(), selectivity);
        *self.pattern_frequency.entry(value.to_string()).or_insert(0) += 1;
    }

    /// Add a value for XOR filter insertion.
    ///
    /// XOR filters provide exact membership testing with no false positives or negatives.
    /// More memory efficient than hash sets for static data.
    pub fn add_xor_filter_value(&mut self, value: &str, selectivity: f64) {
        if !self.xor_filter_values.contains(&value.to_string()) {
            self.xor_filter_values.push(value.to_string());
        }

        self.selectivity_map.insert(value.to_string(), selectivity);
        *self.pattern_frequency.entry(value.to_string()).or_insert(0) += 1;
    }

    /// Add a zero-copy pattern reference for optimization.
    ///
    /// This method allows referencing static string literals without allocation,
    /// providing optimal performance for frequently used patterns.
    pub fn add_zero_copy_pattern(&mut self, pattern: &'static str, selectivity: f64) {
        if !self.zero_copy_patterns.contains(&pattern) {
            self.zero_copy_patterns.push(pattern);
        }

        self.selectivity_map
            .insert(pattern.to_string(), selectivity);
        *self
            .pattern_frequency
            .entry(pattern.to_string())
            .or_insert(0) += 1;
    }

    /// Create a compilation hook that automatically populates this FilterIntegration.
    ///
    /// This hook can be registered with MatcherBuilder to automatically extract
    /// patterns during compilation without manual intervention.
    ///
    /// # Returns
    /// A compilation hook function that can be registered with MatcherBuilder.
    ///
    /// # Example
    /// ```rust,ignore
    /// use sigma_engine::matcher::filters::FilterIntegration;
    /// use sigma_engine::MatcherBuilder;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let integration = Arc::new(Mutex::new(FilterIntegration::new()));
    /// let hook = FilterIntegration::create_compilation_hook(integration.clone());
    ///
    /// let builder = MatcherBuilder::new()
    ///     .register_compilation_hook(CompilationPhase::PrimitiveDiscovery, hook);
    /// ```
    pub fn create_compilation_hook(
        integration: Arc<std::sync::Mutex<FilterIntegration>>,
    ) -> CompilationHookFn {
        Arc::new(move |context: &CompilationContext| {
            let mut integration = integration.lock().map_err(|_| {
                SigmaError::CompilationError(
                    "Failed to acquire filter integration lock".to_string(),
                )
            })?;

            // Update compilation statistics
            integration.compilation_stats.total_primitives += 1;
            if context.is_literal_only {
                integration.compilation_stats.literal_primitives += 1;
            }
            if context.match_type == "regex" {
                integration.compilation_stats.regex_primitives += 1;
            }

            // Extract patterns based on match type and selectivity
            let selectivity = integration.estimate_selectivity_from_context(context);

            match context.match_type {
                "equals" | "contains" | "startswith" | "endswith" if context.is_literal_only => {
                    for &value in context.literal_values {
                        // Add to AhoCorasick for multi-pattern matching
                        integration.add_aho_corasick_pattern(
                            value,
                            Some(context.normalized_field),
                            selectivity,
                        );

                        // Add to FST if highly selective
                        if selectivity < 0.3 {
                            integration.add_fst_value(value, selectivity);
                        }

                        // Add to XOR filter if very selective and exact matching
                        if selectivity <= 0.1 && context.match_type == "equals" {
                            integration.add_xor_filter_value(value, selectivity);
                        }

                        // Add to Bloom filter for probabilistic pre-filtering
                        if selectivity < 0.5 {
                            integration.add_bloom_filter_value(value, selectivity);
                        }
                    }
                }
                "regex" => {
                    for &value in context.literal_values {
                        integration.add_regex_pattern(
                            value,
                            Some(context.normalized_field),
                            selectivity,
                        );
                    }
                }
                _ => {
                    // Handle other match types with general filter values
                    for &value in context.literal_values {
                        integration.add_filter_value(value, selectivity);
                    }
                }
            }

            Ok(())
        })
    }

    /// Estimate selectivity from compilation context.
    fn estimate_selectivity_from_context(&self, context: &CompilationContext) -> f64 {
        let base_selectivity = match context.match_type {
            "equals" => 0.1,                  // Very selective
            "contains" => 0.3,                // Moderately selective
            "startswith" | "endswith" => 0.2, // Selective
            "regex" => 0.5,                   // Variable selectivity
            "cidr" => 0.4,                    // Network-dependent
            "range" => 0.6,                   // Range-dependent
            "fuzzy" => 0.7,                   // Generally less selective
            _ => 0.5,                         // Unknown - assume moderate
        };

        // Adjust based on modifiers
        let modifier_adjustment = if context.modifiers.is_empty() {
            1.0
        } else {
            // Modifiers generally make matching less selective
            1.2
        };

        // Adjust based on value count (more values = less selective)
        let value_count_adjustment = 1.0 + (context.literal_values.len() as f64 * 0.1);

        (base_selectivity * modifier_adjustment * value_count_adjustment).min(1.0)
    }

    /// Get patterns optimized for AhoCorasick construction.
    ///
    /// Returns patterns sorted by frequency and selectivity for optimal automaton construction.
    pub fn get_aho_corasick_patterns(&self) -> Vec<String> {
        let mut patterns = self.aho_corasick_patterns.clone();

        // Sort by frequency (descending) then by selectivity (ascending)
        patterns.sort_by(|a, b| {
            let freq_a = self.pattern_frequency.get(a).unwrap_or(&0);
            let freq_b = self.pattern_frequency.get(b).unwrap_or(&0);
            let sel_a = self.selectivity_map.get(a).unwrap_or(&0.5);
            let sel_b = self.selectivity_map.get(b).unwrap_or(&0.5);

            freq_b.cmp(freq_a).then_with(|| {
                sel_a
                    .partial_cmp(sel_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });

        patterns
    }

    /// Get values optimized for FST construction.
    ///
    /// Returns sorted and deduplicated values ready for FST building.
    pub fn get_fst_values(&self) -> Vec<String> {
        let mut values = self.fst_values.clone();
        values.sort();
        values.dedup();
        values
    }

    /// Get field-specific patterns for targeted filtering.
    ///
    /// Returns patterns grouped by field for field-specific filter construction.
    pub fn get_field_patterns(&self) -> &HashMap<String, Vec<String>> {
        &self.field_patterns
    }

    /// Get highly selective patterns for probabilistic filters.
    ///
    /// Returns only patterns with selectivity below the threshold, suitable for
    /// XOR/Cuckoo filters where false positives should be minimized.
    pub fn get_selective_patterns(&self, max_selectivity: f64) -> Vec<String> {
        self.filter_values
            .iter()
            .filter(|pattern| {
                self.selectivity_map
                    .get(*pattern)
                    .map(|&sel| sel <= max_selectivity)
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Get optimization statistics for filter tuning.
    ///
    /// Returns statistics useful for optimizing filter construction and usage.
    pub fn get_statistics(&self) -> FilterStatistics {
        FilterStatistics {
            total_patterns: self.aho_corasick_patterns.len(),
            total_fst_values: self.fst_values.len(),
            total_filter_values: self.filter_values.len(),
            total_regex_patterns: self.regex_patterns.len(),
            unique_fields: self.field_patterns.len(),
            avg_selectivity: self.calculate_average_selectivity(),
            most_frequent_field: self.get_most_frequent_field(),
            pattern_distribution: self.get_pattern_distribution(),
        }
    }

    /// Extract patterns from a collection of primitives.
    ///
    /// This is a convenience method for bulk pattern extraction from compiled primitives.
    pub fn extract_from_primitives(&mut self, primitives: &[Primitive]) -> Result<(), SigmaError> {
        for primitive in primitives {
            self.extract_from_primitive(primitive)?;
        }
        Ok(())
    }

    /// Extract patterns from a single primitive.
    ///
    /// Analyzes the primitive's match type and values to determine the best
    /// filter integration strategy.
    pub fn extract_from_primitive(&mut self, primitive: &Primitive) -> Result<(), SigmaError> {
        let selectivity = self.estimate_selectivity(primitive);
        let field = Some(primitive.field.as_str());

        // Update compilation statistics
        self.compilation_stats.total_primitives += 1;
        if primitive.match_type.as_str() == "regex" {
            self.compilation_stats.regex_primitives += 1;
        } else {
            self.compilation_stats.literal_primitives += 1;
        }

        match primitive.match_type.as_str() {
            "equals" | "contains" | "startswith" | "endswith" => {
                // Literal patterns suitable for multiple filter types
                for value in &primitive.values {
                    let value_str = value.as_str();
                    self.add_aho_corasick_pattern(value_str, field, selectivity);

                    // Add to FST if highly selective
                    if selectivity < 0.3 {
                        self.add_fst_value(value_str, selectivity);
                    }

                    // Add to XOR filter if very selective and exact matching
                    if selectivity <= 0.1 && primitive.match_type.as_str() == "equals" {
                        self.add_xor_filter_value(value_str, selectivity);
                    }

                    // Add to Bloom filter for probabilistic pre-filtering
                    if selectivity < 0.5 {
                        self.add_bloom_filter_value(value_str, selectivity);
                    }

                    // Add to general filter values if very selective
                    if selectivity <= 0.1 {
                        self.add_filter_value(value_str, selectivity);
                    }
                }
            }
            "regex" => {
                // Regex patterns need separate handling
                for value in &primitive.values {
                    self.add_regex_pattern(value.as_str(), field, selectivity);
                }
            }
            "cidr" | "range" | "fuzzy" => {
                // Complex patterns - add to filter values for membership testing
                for value in &primitive.values {
                    self.add_filter_value(value.as_str(), selectivity);
                }
            }
            _ => {
                // Unknown match type - conservative approach
                for value in &primitive.values {
                    self.add_filter_value(value.as_str(), selectivity);
                }
            }
        }

        Ok(())
    }

    /// Get all regex patterns for separate compilation.
    pub fn get_regex_patterns(&self) -> &[String] {
        &self.regex_patterns
    }

    /// Get all Bloom filter values.
    pub fn get_bloom_filter_values(&self) -> &[String] {
        &self.bloom_filter_values
    }

    /// Get all XOR filter values.
    pub fn get_xor_filter_values(&self) -> &[String] {
        &self.xor_filter_values
    }

    /// Get zero-copy pattern references.
    pub fn get_zero_copy_patterns(&self) -> &[&'static str] {
        &self.zero_copy_patterns
    }

    /// Get compilation statistics.
    pub fn get_compilation_stats(&self) -> &FilterCompilationStats {
        &self.compilation_stats
    }

    fn estimate_selectivity(&self, primitive: &Primitive) -> f64 {
        // Estimate selectivity based on match type and value characteristics
        match primitive.match_type.as_str() {
            "equals" => 0.1,                  // Very selective
            "contains" => 0.3,                // Moderately selective
            "startswith" | "endswith" => 0.2, // Selective
            "regex" => 0.5,                   // Variable selectivity
            "cidr" => 0.4,                    // Network-dependent
            "range" => 0.6,                   // Range-dependent
            "fuzzy" => 0.7,                   // Generally less selective
            _ => 0.5,                         // Unknown - assume moderate
        }
    }

    fn calculate_average_selectivity(&self) -> f64 {
        if self.selectivity_map.is_empty() {
            return 0.5;
        }

        let sum: f64 = self.selectivity_map.values().sum();
        sum / self.selectivity_map.len() as f64
    }

    fn get_most_frequent_field(&self) -> Option<String> {
        self.field_frequency
            .iter()
            .max_by_key(|(_, &count)| count)
            .map(|(field, _)| field.clone())
    }

    fn get_pattern_distribution(&self) -> HashMap<String, usize> {
        let mut distribution = HashMap::new();

        distribution.insert("aho_corasick".to_string(), self.aho_corasick_patterns.len());
        distribution.insert("fst".to_string(), self.fst_values.len());
        distribution.insert("filter".to_string(), self.filter_values.len());
        distribution.insert("regex".to_string(), self.regex_patterns.len());
        distribution.insert("bloom".to_string(), self.bloom_filter_values.len());
        distribution.insert("xor".to_string(), self.xor_filter_values.len());
        distribution.insert("zero_copy".to_string(), self.zero_copy_patterns.len());

        distribution
    }
}

/// Statistics for filter optimization and tuning.
#[derive(Debug, Clone)]
pub struct FilterStatistics {
    /// Total number of AhoCorasick patterns
    pub total_patterns: usize,

    /// Total number of FST values
    pub total_fst_values: usize,

    /// Total number of probabilistic filter values
    pub total_filter_values: usize,

    /// Total number of regex patterns
    pub total_regex_patterns: usize,

    /// Number of unique fields
    pub unique_fields: usize,

    /// Average selectivity across all patterns
    pub avg_selectivity: f64,

    /// Most frequently accessed field
    pub most_frequent_field: Option<String>,

    /// Pattern distribution across filter types
    pub pattern_distribution: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Primitive;

    #[test]
    fn test_filter_integration_basic() {
        let mut integration = FilterIntegration::new();

        integration.add_aho_corasick_pattern("test", Some("field1"), 0.1);
        integration.add_fst_value("value1", 0.2);
        integration.add_filter_value("filter1", 0.05);

        assert_eq!(integration.aho_corasick_patterns.len(), 1);
        assert_eq!(integration.fst_values.len(), 1);
        assert_eq!(integration.filter_values.len(), 1);
    }

    #[test]
    fn test_pattern_deduplication() {
        let mut integration = FilterIntegration::new();

        integration.add_aho_corasick_pattern("duplicate", None, 0.1);
        integration.add_aho_corasick_pattern("duplicate", None, 0.1);

        assert_eq!(integration.aho_corasick_patterns.len(), 1);
    }

    #[test]
    fn test_selective_patterns() {
        let mut integration = FilterIntegration::new();

        integration.add_filter_value("selective", 0.05);
        integration.add_filter_value("not_selective", 0.8);

        let selective = integration.get_selective_patterns(0.1);
        assert_eq!(selective.len(), 1);
        assert_eq!(selective[0], "selective");
    }

    #[test]
    fn test_primitive_extraction() {
        let mut integration = FilterIntegration::new();

        let primitive = Primitive::new_static("EventID", "equals", &["4624"], &[]);

        integration.extract_from_primitive(&primitive).unwrap();

        assert!(!integration.aho_corasick_patterns.is_empty());
        assert!(integration.field_patterns.contains_key("EventID"));
    }

    #[test]
    fn test_filter_integration_comprehensive() {
        let mut integration = FilterIntegration::new();

        // Add various types of patterns
        integration.add_aho_corasick_pattern("pattern1", Some("field1"), 0.3);
        integration.add_aho_corasick_pattern("pattern2", Some("field2"), 0.7);
        integration.add_fst_value("value1", 0.4);
        integration.add_fst_value("value2", 0.8);
        integration.add_filter_value("filter1", 0.2);
        integration.add_regex_pattern("regex1", None, 0.6);

        let stats = integration.get_statistics();
        assert_eq!(stats.total_patterns, 2);
        assert_eq!(stats.total_fst_values, 2);
        assert_eq!(stats.total_filter_values, 1);
        assert_eq!(stats.total_regex_patterns, 1);
        assert_eq!(stats.unique_fields, 2);

        // Test field-specific patterns
        let field_patterns = integration.get_field_patterns();
        assert!(field_patterns.contains_key("field1"));
        assert!(field_patterns.contains_key("field2"));
        assert_eq!(field_patterns["field1"].len(), 1);
        assert_eq!(field_patterns["field2"].len(), 1);
    }

    #[test]
    fn test_filter_integration_optimization() {
        let mut integration = FilterIntegration::new();

        // Add patterns with different selectivities
        integration.add_aho_corasick_pattern("high_sel", None, 0.9);
        integration.add_aho_corasick_pattern("med_sel", None, 0.5);
        integration.add_aho_corasick_pattern("low_sel", None, 0.1);

        // Get optimized patterns
        let optimized = integration.get_aho_corasick_patterns();
        assert_eq!(optimized.len(), 3);

        // Verify selective patterns - use filter_values instead since that's what get_selective_patterns uses
        integration.add_filter_value("high_sel", 0.9);
        integration.add_filter_value("med_sel", 0.5);
        integration.add_filter_value("low_sel", 0.1);

        let selective = integration.get_selective_patterns(0.4);
        assert!(!selective.contains(&"high_sel".to_string())); // 0.9 > 0.4
        assert!(!selective.contains(&"med_sel".to_string())); // 0.5 > 0.4
        assert!(selective.contains(&"low_sel".to_string())); // 0.1 < 0.4
    }

    #[test]
    fn test_filter_integration_statistics() {
        let mut integration = FilterIntegration::new();

        // Add patterns to the same field multiple times
        integration.add_aho_corasick_pattern("p1", Some("common_field"), 0.2);
        integration.add_aho_corasick_pattern("p2", Some("common_field"), 0.4);
        integration.add_aho_corasick_pattern("p3", Some("rare_field"), 0.6);

        let stats = integration.get_statistics();
        assert_eq!(stats.unique_fields, 2);
        assert_eq!(stats.most_frequent_field, Some("common_field".to_string()));

        // Average selectivity should be (0.2 + 0.4 + 0.6) / 3 = 0.4
        assert!((stats.avg_selectivity - 0.4).abs() < 0.001);
    }

    #[test]
    fn test_filter_integration_empty() {
        let integration = FilterIntegration::new();

        let stats = integration.get_statistics();
        assert_eq!(stats.total_patterns, 0);
        assert_eq!(stats.total_fst_values, 0);
        assert_eq!(stats.total_filter_values, 0);
        assert_eq!(stats.total_regex_patterns, 0);
        assert_eq!(stats.unique_fields, 0);
        // avg_selectivity might be NaN or 0.5 for empty case
        assert!(
            stats.avg_selectivity.is_nan()
                || stats.avg_selectivity == 0.5
                || stats.avg_selectivity == 0.0
        );
        assert!(stats.most_frequent_field.is_none());

        let patterns = integration.get_aho_corasick_patterns();
        assert!(patterns.is_empty());

        let field_patterns = integration.get_field_patterns();
        assert!(field_patterns.is_empty());
    }

    #[test]
    fn test_primitive_extraction_comprehensive() {
        let mut integration = FilterIntegration::new();

        // Test different match types
        let primitives = vec![
            Primitive::new_static("EventID", "equals", &["4624"], &[]),
            Primitive::new_static("ProcessName", "contains", &["powershell"], &[]),
            Primitive::new_static("CommandLine", "regex", &[".*\\.exe.*"], &[]),
        ];

        for primitive in primitives {
            integration.extract_from_primitive(&primitive).unwrap();
        }

        // Check that patterns were extracted (exact counts may vary based on implementation)
        assert!(!integration.aho_corasick_patterns.is_empty());
        assert!(!integration.field_patterns.is_empty());
    }

    #[test]
    fn test_new_filter_types() {
        let mut integration = FilterIntegration::new();

        // Test Bloom filter values
        integration.add_bloom_filter_value("bloom_value", 0.3);
        assert_eq!(integration.get_bloom_filter_values().len(), 1);
        assert_eq!(integration.get_bloom_filter_values()[0], "bloom_value");

        // Test XOR filter values
        integration.add_xor_filter_value("xor_value", 0.05);
        assert_eq!(integration.get_xor_filter_values().len(), 1);
        assert_eq!(integration.get_xor_filter_values()[0], "xor_value");

        // Test zero-copy patterns
        integration.add_zero_copy_pattern("static_pattern", 0.1);
        assert_eq!(integration.get_zero_copy_patterns().len(), 1);
        assert_eq!(integration.get_zero_copy_patterns()[0], "static_pattern");
    }

    #[test]
    fn test_compilation_stats() {
        let mut integration = FilterIntegration::new();

        // Extract from primitives to populate stats
        let primitives = vec![
            Primitive {
                field: "EventID".into(),
                match_type: "equals".into(),
                values: vec!["4624".into()],
                modifiers: vec![],
            },
            Primitive {
                field: "CommandLine".into(),
                match_type: "regex".into(),
                values: vec![".*\\.exe.*".into()],
                modifiers: vec![],
            },
        ];

        for primitive in primitives {
            integration.extract_from_primitive(&primitive).unwrap();
        }

        let stats = integration.get_compilation_stats();
        assert_eq!(stats.total_primitives, 2);
        assert_eq!(stats.literal_primitives, 1);
        assert_eq!(stats.regex_primitives, 1);
    }

    #[test]
    fn test_automatic_filter_selection() {
        let mut integration = FilterIntegration::new();

        // Test equals primitive (very selective) - should go to multiple filters
        let equals_primitive = Primitive {
            field: "EventID".into(),
            match_type: "equals".into(),
            values: vec!["4624".into()],
            modifiers: vec![],
        };

        integration
            .extract_from_primitive(&equals_primitive)
            .unwrap();

        // Should be added to AhoCorasick, FST, XOR, Bloom, and general filters
        // Note: equals match type has selectivity 0.1, which should trigger XOR filter (< 0.1 threshold)
        assert!(!integration.aho_corasick_patterns.is_empty());
        assert!(!integration.fst_values.is_empty());
        assert!(!integration.xor_filter_values.is_empty());
        assert!(!integration.bloom_filter_values.is_empty());
        assert!(!integration.filter_values.is_empty());

        // Test contains primitive (moderately selective) - should go to fewer filters
        let mut integration2 = FilterIntegration::new();
        let contains_primitive = Primitive {
            field: "ProcessName".into(),
            match_type: "contains".into(),
            values: vec!["powershell".into()],
            modifiers: vec![],
        };

        integration2
            .extract_from_primitive(&contains_primitive)
            .unwrap();

        // Should be added to AhoCorasick and Bloom, but not XOR (not selective enough)
        assert!(!integration2.aho_corasick_patterns.is_empty());
        assert!(!integration2.bloom_filter_values.is_empty());
        assert!(integration2.xor_filter_values.is_empty()); // Too selective threshold
    }

    #[test]
    fn test_compilation_hook_creation() {
        use crate::ir::Primitive;
        use std::sync::{Arc, Mutex};

        let integration = Arc::new(Mutex::new(FilterIntegration::new()));
        let hook = FilterIntegration::create_compilation_hook(integration.clone());

        // Create a test primitive and context
        let primitive = Primitive::new_static("EventID", "equals", &["test_value"], &[]);
        let literal_values = ["test_value"];
        let literal_refs: Vec<&str> = literal_values.to_vec();
        let modifiers: [&str; 0] = [];
        let modifier_refs: Vec<&str> = modifiers.to_vec();

        let context = CompilationContext::new(
            &primitive,
            1,
            Some("Test Rule"),
            &literal_refs,
            "EventID",
            "EventID",
            "equals",
            &modifier_refs,
            true,
            0.1,
        );

        // Execute the hook
        let result = hook(&context);
        assert!(result.is_ok());

        // Check that patterns were added
        let integration_guard = integration.lock().unwrap();
        assert!(!integration_guard.aho_corasick_patterns.is_empty());
        assert_eq!(integration_guard.compilation_stats.total_primitives, 1);
        assert_eq!(integration_guard.compilation_stats.literal_primitives, 1);
    }
}
