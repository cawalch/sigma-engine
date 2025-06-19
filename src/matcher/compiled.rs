//! Compiled primitive for zero-allocation evaluation.

use crate::matcher::types::{MatchFn, ModifierFn};
use std::sync::Arc;

/// Compiled primitive for zero-allocation evaluation.
///
/// Contains pre-compiled data structures optimized for high-performance evaluation.
/// All data is shared using Arc to minimize memory overhead when the same patterns
/// appear across multiple rules.
///
/// # Memory Layout
/// - `field_path`: Pre-parsed field path for nested JSON access
/// - `match_fn`: Pre-compiled match function with zero-allocation signature
/// - `modifier_chain`: Pre-compiled modifier pipeline for value transformation
/// - `values`: Pre-allocated values for matching
/// - `raw_modifiers`: Raw modifier names for reference
///
/// # Example
/// ```rust,ignore
/// use sigma_engine::matcher::{CompiledPrimitive, MatchFn};
/// use std::sync::Arc;
///
/// let exact_match: MatchFn = Arc::new(|field_value, values, _modifiers| {
///     values.iter().any(|&v| field_value == v).then(|| true).ok_or_else(|| false)
/// });
///
/// let compiled = CompiledPrimitive {
///     field_path: Arc::new(vec!["EventID".to_string()]),
///     match_fn: exact_match,
///     modifier_chain: Arc::new(vec![]),
///     values: Arc::new(vec!["4624".to_string()]),
///     raw_modifiers: Arc::new(vec![]),
/// };
/// ```
#[derive(Clone)]
pub struct CompiledPrimitive {
    /// Pre-parsed field path (e.g., ["nested", "field"] for "nested.field")
    pub field_path: Arc<[String]>,

    /// Pre-compiled match function for zero-allocation evaluation
    pub match_fn: MatchFn,

    /// Pre-compiled modifier pipeline applied in sequence
    pub modifier_chain: Arc<[ModifierFn]>,

    /// Pre-allocated values for matching
    pub values: Arc<[String]>,

    /// Raw modifier names for reference and debugging
    pub raw_modifiers: Arc<[String]>,
}

impl CompiledPrimitive {
    /// Create a new compiled primitive.
    ///
    /// # Arguments
    /// * `field_path` - Pre-parsed field path components
    /// * `match_fn` - Pre-compiled match function
    /// * `modifier_chain` - Pre-compiled modifier functions
    /// * `values` - Values to match against
    /// * `raw_modifiers` - Raw modifier names for reference
    ///
    /// # Example
    /// ```rust,ignore
    /// let compiled = CompiledPrimitive::new(
    ///     vec!["EventID".to_string()],
    ///     exact_match_fn,
    ///     vec![],
    ///     vec!["4624".to_string()],
    ///     vec![],
    /// );
    /// ```
    pub fn new(
        field_path: Vec<String>,
        match_fn: MatchFn,
        modifier_chain: Vec<ModifierFn>,
        values: Vec<String>,
        raw_modifiers: Vec<String>,
    ) -> Self {
        Self {
            field_path: field_path.into(),
            match_fn,
            modifier_chain: modifier_chain.into(),
            values: values.into(),
            raw_modifiers: raw_modifiers.into(),
        }
    }

    /// Get the field path as a dot-separated string.
    ///
    /// # Returns
    /// Field path joined with dots (e.g., "nested.field")
    ///
    /// # Example
    /// ```rust,ignore
    /// let compiled = CompiledPrimitive::new(
    ///     vec!["nested".to_string(), "field".to_string()],
    ///     match_fn, vec![], vec![], vec![]
    /// );
    /// assert_eq!(compiled.field_path_string(), "nested.field");
    /// ```
    pub fn field_path_string(&self) -> String {
        self.field_path.join(".")
    }

    /// Check if this primitive has any modifiers.
    ///
    /// # Returns
    /// `true` if the primitive has modifiers, `false` otherwise
    pub fn has_modifiers(&self) -> bool {
        !self.modifier_chain.is_empty()
    }

    /// Get the number of values this primitive matches against.
    ///
    /// # Returns
    /// Number of values in the values array
    pub fn value_count(&self) -> usize {
        self.values.len()
    }

    /// Check if this primitive contains only literal values (no wildcards or regex).
    ///
    /// This is used for optimization hints and external filter integration.
    ///
    /// # Returns
    /// `true` if all values are literal (no *, ?, or regex patterns)
    pub fn is_literal_only(&self) -> bool {
        // This is a simplified check - in a full implementation, this would
        // be determined during compilation based on the match type
        !self
            .values
            .iter()
            .any(|v| v.contains('*') || v.contains('?'))
    }

    /// Get memory usage estimate for this compiled primitive.
    ///
    /// Useful for memory profiling and optimization.
    ///
    /// # Returns
    /// Estimated memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        let field_path_size: usize = self.field_path.iter().map(|s| s.len()).sum();
        let values_size: usize = self.values.iter().map(|s| s.len()).sum();
        let modifiers_size: usize = self.raw_modifiers.iter().map(|s| s.len()).sum();

        field_path_size
            + values_size
            + modifiers_size
            + (self.field_path.len() + self.values.len() + self.raw_modifiers.len())
                * std::mem::size_of::<String>()
    }
}

impl std::fmt::Debug for CompiledPrimitive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledPrimitive")
            .field("field_path", &self.field_path_string())
            .field("values", &self.values)
            .field("raw_modifiers", &self.raw_modifiers)
            .field("has_modifiers", &self.has_modifiers())
            .field("value_count", &self.value_count())
            .field("is_literal_only", &self.is_literal_only())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_match_fn() -> MatchFn {
        Arc::new(|field_value, values, _modifiers| {
            for &value in values {
                if field_value == value {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    fn create_test_modifier_fn() -> ModifierFn {
        Arc::new(|input| Ok(input.to_uppercase()))
    }

    #[test]
    fn test_compiled_primitive_creation() {
        let compiled = CompiledPrimitive::new(
            vec!["EventID".to_string()],
            create_test_match_fn(),
            vec![],
            vec!["4624".to_string(), "4625".to_string()],
            vec![],
        );

        assert_eq!(compiled.field_path_string(), "EventID");
        assert_eq!(compiled.value_count(), 2);
        assert!(!compiled.has_modifiers());
        assert!(compiled.is_literal_only());
    }

    #[test]
    fn test_nested_field_path() {
        let compiled = CompiledPrimitive::new(
            vec!["nested".to_string(), "field".to_string()],
            create_test_match_fn(),
            vec![],
            vec!["value".to_string()],
            vec![],
        );

        assert_eq!(compiled.field_path_string(), "nested.field");
    }

    #[test]
    fn test_with_modifiers() {
        let compiled = CompiledPrimitive::new(
            vec!["EventID".to_string()],
            create_test_match_fn(),
            vec![create_test_modifier_fn()],
            vec!["4624".to_string()],
            vec!["uppercase".to_string()],
        );

        assert!(compiled.has_modifiers());
        assert_eq!(compiled.raw_modifiers.len(), 1);
        assert_eq!(compiled.raw_modifiers[0], "uppercase");
    }

    #[test]
    fn test_literal_only_detection() {
        let literal_compiled = CompiledPrimitive::new(
            vec!["EventID".to_string()],
            create_test_match_fn(),
            vec![],
            vec!["4624".to_string(), "literal_value".to_string()],
            vec![],
        );
        assert!(literal_compiled.is_literal_only());

        let wildcard_compiled = CompiledPrimitive::new(
            vec!["EventID".to_string()],
            create_test_match_fn(),
            vec![],
            vec!["test*".to_string(), "literal".to_string()],
            vec![],
        );
        assert!(!wildcard_compiled.is_literal_only());
    }

    #[test]
    fn test_memory_usage_calculation() {
        let compiled = CompiledPrimitive::new(
            vec!["EventID".to_string()],
            create_test_match_fn(),
            vec![],
            vec!["4624".to_string()],
            vec![],
        );

        let usage = compiled.memory_usage();
        assert!(usage > 0);
        // Should include field path + values + basic overhead
        assert!(usage >= "EventID".len() + "4624".len());
    }

    #[test]
    fn test_debug_formatting() {
        let compiled = CompiledPrimitive::new(
            vec!["EventID".to_string()],
            create_test_match_fn(),
            vec![],
            vec!["4624".to_string()],
            vec![],
        );

        let debug_str = format!("{:?}", compiled);
        assert!(debug_str.contains("EventID"));
        assert!(debug_str.contains("4624"));
        assert!(debug_str.contains("CompiledPrimitive"));
    }

    #[test]
    fn test_clone() {
        let compiled = CompiledPrimitive::new(
            vec!["EventID".to_string()],
            create_test_match_fn(),
            vec![],
            vec!["4624".to_string()],
            vec![],
        );

        let cloned = compiled.clone();
        assert_eq!(cloned.field_path_string(), compiled.field_path_string());
        assert_eq!(cloned.value_count(), compiled.value_count());
    }
}
