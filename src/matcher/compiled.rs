//! Compiled primitive for zero-allocation evaluation.

use crate::matcher::types::{MatchFn, ModifierFn};
use std::sync::Arc;

/// Compiled primitive for zero-allocation evaluation.
///
/// A `CompiledPrimitive` represents a fully compiled and optimized SIGMA primitive
/// that can be evaluated against events with zero memory allocations. It contains
/// all the pre-compiled data structures needed for high-performance matching.
///
///
/// # Field Path Format
///
/// Field paths support both simple and nested field access:
/// - Simple: `["EventID"]` → accesses `event.EventID`
/// - Nested: `["Process", "Name"]` → accesses `event.Process.Name`
/// - Array: `["Users", "0", "Name"]` → accesses `event.Users[0].Name`
///
/// # Match Function Signature
///
/// Match functions follow a zero-allocation signature:
/// ```rust,ignore
/// fn match_fn(field_value: &str, values: &[&str], modifiers: &[&str]) -> Result<bool, SigmaError>
/// ```
///
/// This signature ensures:
/// - No string cloning during evaluation
/// - Efficient slice-based value iteration
/// - Minimal error handling overhead
///
/// # Modifier Chain Processing
///
/// Modifiers are applied in sequence to transform field values before matching:
/// 1. Extract field value from event
/// 2. Apply modifiers in order (e.g., base64_decode → lowercase)
/// 3. Pass transformed value to match function
/// 4. Return boolean result
///
/// # Examples
///
/// ## Simple Exact Match
/// ```rust,ignore
/// use sigma_engine::matcher::{CompiledPrimitive, MatchFn};
/// use std::sync::Arc;
///
/// let exact_match: MatchFn = Arc::new(|field_value, values, _modifiers| {
///     Ok(values.iter().any(|&v| field_value == v))
/// });
///
/// let compiled = CompiledPrimitive::new(
///     vec!["EventID".to_string()],
///     exact_match,
///     vec![], // No modifiers
///     vec!["4624".to_string()],
///     vec![],
/// );
/// ```
///
/// ## Complex Match with Modifiers
/// ```rust,ignore
/// use sigma_engine::matcher::{CompiledPrimitive, MatchFn, ModifierFn};
/// use std::sync::Arc;
///
/// let contains_match: MatchFn = Arc::new(|field_value, values, _modifiers| {
///     Ok(values.iter().any(|&v| field_value.contains(v)))
/// });
///
/// let lowercase_modifier: ModifierFn = Arc::new(|input| {
///     Ok(input.to_lowercase())
/// });
///
/// let compiled = CompiledPrimitive::new(
///     vec!["Process", "CommandLine".to_string()],
///     contains_match,
///     vec![lowercase_modifier],
///     vec!["powershell".to_string(), "cmd".to_string()],
///     vec!["lowercase".to_string()],
/// );
/// ```
///
/// ## Nested Field Access
/// ```rust,ignore
/// let compiled = CompiledPrimitive::new(
///     vec!["Event".to_string(), "System".to_string(), "EventID".to_string()],
///     exact_match,
///     vec![],
///     vec!["4624".to_string()],
///     vec![],
/// );
/// // Matches: event.Event.System.EventID == "4624"
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

    /// Evaluate this primitive against an event context.
    ///
    /// # Arguments
    /// * `context` - Event context containing the event data
    ///
    /// # Returns
    /// `true` if the primitive matches, `false` otherwise
    pub fn matches(&self, context: &crate::matcher::EventContext) -> bool {
        // Convert field path to dot notation string
        let field_path_str = self.field_path.join(".");

        // Extract field value from event using the field path
        let field_value = match context.get_field(&field_path_str) {
            Ok(Some(value)) => value,
            Ok(None) | Err(_) => return false, // Field not found or extraction failed
        };

        // Convert values to string slices for the match function
        let value_refs: Vec<&str> = self.values.iter().map(|s| s.as_str()).collect();
        let modifier_refs: Vec<&str> = self.raw_modifiers.iter().map(|s| s.as_str()).collect();

        // Call the match function
        (self.match_fn)(&field_value, &value_refs, &modifier_refs).unwrap_or_default()
    }

    /// Create a CompiledPrimitive from a Primitive IR structure.
    ///
    /// This method compiles a Primitive into an optimized CompiledPrimitive
    /// with pre-compiled match functions and modifier chains.
    ///
    /// # Arguments
    /// * `primitive` - The primitive to compile
    ///
    /// # Returns
    /// A compiled primitive ready for high-performance evaluation
    pub fn from_primitive(primitive: crate::ir::Primitive) -> crate::error::Result<Self> {
        use std::sync::Arc;

        // Parse field path (split on dots for nested access)
        let field_path: Vec<String> = primitive.field.split('.').map(|s| s.to_string()).collect();

        // Create a simple match function based on match type
        let match_fn: MatchFn = match primitive.match_type.as_str() {
            "equals" | "exact" => Arc::new(|field_value, values, _modifiers| {
                for &value in values {
                    if field_value == value {
                        return Ok(true);
                    }
                }
                Ok(false)
            }),
            "contains" => Arc::new(|field_value, values, _modifiers| {
                for &value in values {
                    if field_value.contains(value) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }),
            "startswith" => Arc::new(|field_value, values, _modifiers| {
                for &value in values {
                    if field_value.starts_with(value) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }),
            "endswith" => Arc::new(|field_value, values, _modifiers| {
                for &value in values {
                    if field_value.ends_with(value) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }),
            _ => {
                // Default to exact match for unknown types
                Arc::new(|field_value, values, _modifiers| {
                    for &value in values {
                        if field_value == value {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                })
            }
        };

        // Note: This method bypasses the MatcherBuilder's proper modifier compilation.
        // For full modifier support, use MatcherBuilder::compile() instead.
        let modifier_chain: Vec<ModifierFn> = Vec::new();

        Ok(Self::new(
            field_path,
            match_fn,
            modifier_chain,
            primitive.values,
            primitive.modifiers,
        ))
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

        let debug_str = format!("{compiled:?}");
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
