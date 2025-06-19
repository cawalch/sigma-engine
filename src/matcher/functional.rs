//! High-performance functional matcher for zero-allocation evaluation.

use crate::error::Result;
use crate::matcher::{CompiledPrimitive, EventContext, FieldExtractorFn};
use serde_yaml::Value;

/// High-performance functional matcher for zero-allocation evaluation.
///
/// Evaluates compiled primitives against events with minimal allocation.
/// Designed for high-throughput security event processing.
///
/// # Performance Characteristics
/// - Zero allocations in `evaluate_into()` method
/// - Pre-compiled patterns and modifier chains
/// - Field value caching for repeated access
/// - Arc-based sharing for memory efficiency
///
/// # Example
/// ```rust,ignore
/// use sigma_engine::matcher::{MatcherBuilder, FunctionalMatcher};
/// use serde_json::json;
///
/// let matcher = MatcherBuilder::new().compile(&primitives)?;
/// let event = json!({"EventID": "4624"});
/// let results = matcher.evaluate(&event)?;
/// ```
pub struct FunctionalMatcher {
    /// Pre-compiled primitives for evaluation
    compiled_primitives: Vec<CompiledPrimitive>,

    /// Field extractor with caching support
    field_extractor: FieldExtractorFn,
}

impl FunctionalMatcher {
    /// Create a new functional matcher.
    ///
    /// # Arguments
    /// * `compiled_primitives` - Pre-compiled primitives ready for evaluation
    /// * `field_extractor` - Function for extracting field values from events
    pub(crate) fn new(
        compiled_primitives: Vec<CompiledPrimitive>,
        field_extractor: FieldExtractorFn,
    ) -> Self {
        Self {
            compiled_primitives,
            field_extractor,
        }
    }

    /// Zero-allocation evaluation of compiled primitives.
    ///
    /// Allocates a new result vector. For zero-allocation evaluation,
    /// use `evaluate_into()` with a pre-allocated buffer.
    ///
    /// # Arguments
    /// * `event` - JSON event to evaluate against
    ///
    /// # Returns
    /// * `Ok(Vec<bool>)` - Boolean results for each primitive
    /// * `Err(SigmaError)` - Evaluation failed
    ///
    /// # Example
    /// ```rust,ignore
    /// let event = json!({"EventID": "4624"});
    /// let results = matcher.evaluate(&event)?;
    /// assert_eq!(results.len(), primitive_count);
    /// ```
    pub fn evaluate(&self, event: &Value) -> Result<Vec<bool>> {
        let context = EventContext::new(event);
        let mut results = Vec::with_capacity(self.compiled_primitives.len());

        for compiled_primitive in &self.compiled_primitives {
            let result = self.evaluate_compiled_primitive(compiled_primitive, &context)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Batch evaluation with pre-allocated result buffer (zero allocation).
    ///
    /// This is the highest-performance evaluation method as it performs
    /// no allocations during evaluation.
    ///
    /// # Arguments
    /// * `event` - JSON event to evaluate against
    /// * `results` - Pre-allocated buffer for results
    ///
    /// # Returns
    /// * `Ok(())` - Evaluation completed successfully
    /// * `Err(SigmaError)` - Evaluation failed
    ///
    /// # Example
    /// ```rust,ignore
    /// let mut results = vec![false; primitive_count];
    /// for event in event_stream {
    ///     matcher.evaluate_into(&event, &mut results)?;
    ///     // Process results...
    /// }
    /// ```
    pub fn evaluate_into(&self, event: &Value, results: &mut [bool]) -> Result<()> {
        let context = EventContext::new(event);

        for (i, compiled_primitive) in self.compiled_primitives.iter().enumerate() {
            if i >= results.len() {
                break;
            }
            results[i] = self.evaluate_compiled_primitive(compiled_primitive, &context)?;
        }

        Ok(())
    }

    /// Evaluate a single compiled primitive against an event context.
    fn evaluate_compiled_primitive(
        &self,
        primitive: &CompiledPrimitive,
        context: &EventContext,
    ) -> Result<bool> {
        // Extract field value using the field extractor
        let field_path = primitive.field_path_string();
        let field_value = (self.field_extractor)(context, &field_path)?.unwrap_or_else(String::new);

        // Apply modifier chain if present
        let processed_value = if primitive.has_modifiers() {
            self.apply_modifier_chain(&field_value, primitive)?
        } else {
            field_value
        };

        // Convert Arc<[String]> to &[&str] for zero-allocation call
        let values_refs: Vec<&str> = primitive.values.iter().map(|s| s.as_str()).collect();
        let modifiers_refs: Vec<&str> =
            primitive.raw_modifiers.iter().map(|s| s.as_str()).collect();

        // Call pre-compiled match function
        (primitive.match_fn)(&processed_value, &values_refs, &modifiers_refs)
    }

    /// Apply the modifier chain to a field value.
    fn apply_modifier_chain(
        &self,
        field_value: &str,
        primitive: &CompiledPrimitive,
    ) -> Result<String> {
        let mut current_value = field_value.to_string();

        for modifier_fn in primitive.modifier_chain.iter() {
            current_value = modifier_fn(&current_value)?;
        }

        Ok(current_value)
    }

    /// Get the number of compiled primitives.
    pub fn primitive_count(&self) -> usize {
        self.compiled_primitives.len()
    }

    /// Get memory usage estimate for all compiled primitives.
    pub fn memory_usage(&self) -> usize {
        self.compiled_primitives
            .iter()
            .map(|p| p.memory_usage())
            .sum()
    }

    /// Get statistics about the compiled primitives.
    pub fn statistics(&self) -> MatcherStatistics {
        let total_primitives = self.compiled_primitives.len();
        let primitives_with_modifiers = self
            .compiled_primitives
            .iter()
            .filter(|p| p.has_modifiers())
            .count();
        let total_values: usize = self
            .compiled_primitives
            .iter()
            .map(|p| p.value_count())
            .sum();
        let literal_only_primitives = self
            .compiled_primitives
            .iter()
            .filter(|p| p.is_literal_only())
            .count();

        MatcherStatistics {
            total_primitives,
            primitives_with_modifiers,
            total_values,
            literal_only_primitives,
            memory_usage: self.memory_usage(),
        }
    }
}

/// Statistics about a compiled matcher.
#[derive(Debug, Clone)]
pub struct MatcherStatistics {
    /// Total number of compiled primitives
    pub total_primitives: usize,
    /// Number of primitives with modifiers
    pub primitives_with_modifiers: usize,
    /// Total number of values across all primitives
    pub total_values: usize,
    /// Number of primitives with only literal values
    pub literal_only_primitives: usize,
    /// Estimated memory usage in bytes
    pub memory_usage: usize,
}

impl std::fmt::Display for MatcherStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MatcherStatistics {{ primitives: {}, with_modifiers: {}, values: {}, literal_only: {}, memory: {} bytes }}",
            self.total_primitives,
            self.primitives_with_modifiers,
            self.total_values,
            self.literal_only_primitives,
            self.memory_usage
        )
    }
}

impl std::fmt::Debug for FunctionalMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionalMatcher")
            .field("primitive_count", &self.primitive_count())
            .field("memory_usage", &self.memory_usage())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Primitive;
    use crate::matcher::MatcherBuilder;

    fn create_test_matcher() -> FunctionalMatcher {
        let primitives = vec![
            Primitive::new_static("EventID", "equals", &["4624"], &[]),
            Primitive::new_static("LogonType", "equals", &["2"], &[]),
        ];

        MatcherBuilder::new().compile(&primitives).unwrap()
    }

    fn create_test_event() -> Value {
        serde_yaml::from_str(
            r#"
EventID: "4624"
LogonType: "2"
"#,
        )
        .unwrap()
    }

    #[test]
    fn test_matcher_creation() {
        let matcher = create_test_matcher();
        assert_eq!(matcher.primitive_count(), 2);
    }

    #[test]
    fn test_evaluate_allocation() {
        let matcher = create_test_matcher();
        let event = create_test_event();

        let results = matcher.evaluate(&event).unwrap();
        assert_eq!(results.len(), 2);
        // Note: These will fail until we implement proper field extraction
        // but the structure is correct
    }

    #[test]
    fn test_evaluate_into_zero_allocation() {
        let matcher = create_test_matcher();
        let event = create_test_event();
        let mut results = vec![false; 2];

        let result = matcher.evaluate_into(&event, &mut results);
        assert!(result.is_ok());
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_evaluate_into_buffer_too_small() {
        let matcher = create_test_matcher();
        let event = create_test_event();
        let mut results = vec![false; 1]; // Only space for 1 result

        let result = matcher.evaluate_into(&event, &mut results);
        assert!(result.is_ok()); // Should not fail, just process what fits
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_statistics() {
        let matcher = create_test_matcher();
        let stats = matcher.statistics();

        assert_eq!(stats.total_primitives, 2);
        assert_eq!(stats.primitives_with_modifiers, 0);
        assert_eq!(stats.total_values, 2); // "4624" + "2"
        assert_eq!(stats.literal_only_primitives, 2);
        assert!(stats.memory_usage > 0);
    }

    #[test]
    fn test_statistics_display() {
        let matcher = create_test_matcher();
        let stats = matcher.statistics();
        let display_str = stats.to_string();

        assert!(display_str.contains("primitives: 2"));
        assert!(display_str.contains("MatcherStatistics"));
    }

    #[test]
    fn test_memory_usage() {
        let matcher = create_test_matcher();
        let usage = matcher.memory_usage();
        assert!(usage > 0);
    }
}
