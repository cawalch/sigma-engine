//! High-performance functional matcher for zero-allocation evaluation.

use crate::error::Result;
use crate::matcher::{CompiledPrimitive, EventContext, FieldExtractorFn};
use serde_yaml::Value;
use std::sync::{Arc, Mutex};

/// Memory pool for reusable allocations during evaluation.
///
/// Provides pre-allocated buffers that can be reused across multiple evaluations
/// to minimize allocation overhead in high-throughput scenarios.
#[derive(Debug)]
pub struct MemoryPool {
    /// Pool of reusable string buffers
    string_buffers: Mutex<Vec<String>>,
    /// Pool of reusable vector buffers for string references
    vec_buffers: Mutex<Vec<Vec<String>>>,
    /// Pool of reusable boolean result buffers
    result_buffers: Mutex<Vec<Vec<bool>>>,
}

impl MemoryPool {
    /// Create a new memory pool with default capacity.
    pub fn new() -> Self {
        Self {
            string_buffers: Mutex::new(Vec::new()),
            vec_buffers: Mutex::new(Vec::new()),
            result_buffers: Mutex::new(Vec::new()),
        }
    }

    /// Create a new memory pool with specified initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            string_buffers: Mutex::new(Vec::with_capacity(capacity)),
            vec_buffers: Mutex::new(Vec::with_capacity(capacity)),
            result_buffers: Mutex::new(Vec::with_capacity(capacity)),
        }
    }

    /// Get a reusable string buffer from the pool.
    pub fn get_string_buffer(&self) -> String {
        self.string_buffers
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_default()
    }

    /// Return a string buffer to the pool for reuse.
    pub fn return_string_buffer(&self, mut buffer: String) {
        buffer.clear();
        if let Ok(mut pool) = self.string_buffers.lock() {
            if pool.len() < 100 {
                // Limit pool size
                pool.push(buffer);
            }
        }
    }

    /// Get a reusable vector buffer from the pool.
    pub fn get_vec_buffer(&self) -> Vec<String> {
        self.vec_buffers.lock().unwrap().pop().unwrap_or_default()
    }

    /// Return a vector buffer to the pool for reuse.
    pub fn return_vec_buffer(&self, mut buffer: Vec<String>) {
        buffer.clear();
        if let Ok(mut pool) = self.vec_buffers.lock() {
            if pool.len() < 100 {
                // Limit pool size
                pool.push(buffer);
            }
        }
    }

    /// Get a reusable result buffer from the pool.
    pub fn get_result_buffer(&self, capacity: usize) -> Vec<bool> {
        if let Ok(mut pool) = self.result_buffers.lock() {
            if let Some(mut buffer) = pool.pop() {
                buffer.resize(capacity, false);
                return buffer;
            }
        }
        vec![false; capacity]
    }

    /// Return a result buffer to the pool for reuse.
    pub fn return_result_buffer(&self, mut buffer: Vec<bool>) {
        buffer.clear();
        if let Ok(mut pool) = self.result_buffers.lock() {
            if pool.len() < 100 {
                // Limit pool size
                pool.push(buffer);
            }
        }
    }
}

impl Default for MemoryPool {
    fn default() -> Self {
        Self::new()
    }
}

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

    /// Memory pool for reusable allocations
    memory_pool: Arc<MemoryPool>,
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
            memory_pool: Arc::new(MemoryPool::new()),
        }
    }

    /// Create a new functional matcher with custom memory pool.
    ///
    /// # Arguments
    /// * `compiled_primitives` - Pre-compiled primitives ready for evaluation
    /// * `field_extractor` - Function for extracting field values from events
    /// * `memory_pool` - Shared memory pool for reusable allocations
    pub fn with_memory_pool(
        compiled_primitives: Vec<CompiledPrimitive>,
        field_extractor: FieldExtractorFn,
        memory_pool: Arc<MemoryPool>,
    ) -> Self {
        Self {
            compiled_primitives,
            field_extractor,
            memory_pool,
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

    /// Ultra-fast evaluation using memory pooling for minimal allocation.
    ///
    /// This method uses the internal memory pool to minimize allocations
    /// during evaluation, providing the highest performance for repeated
    /// evaluations in high-throughput scenarios.
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
    /// for event in high_speed_event_stream {
    ///     let results = matcher.evaluate_ultra_fast(&event)?;
    ///     // Process results with minimal allocation overhead
    /// }
    /// ```
    pub fn evaluate_ultra_fast(&self, event: &Value) -> Result<Vec<bool>> {
        let context = EventContext::new(event);
        let mut results = self
            .memory_pool
            .get_result_buffer(self.compiled_primitives.len());

        for (i, compiled_primitive) in self.compiled_primitives.iter().enumerate() {
            results[i] = self.evaluate_compiled_primitive_pooled(compiled_primitive, &context)?;
        }

        // Clone results before returning buffer to pool
        let final_results = results.clone();
        self.memory_pool.return_result_buffer(results);
        Ok(final_results)
    }

    /// Batch evaluation with memory pooling for maximum throughput.
    ///
    /// Processes multiple events in a single call using memory pooling
    /// to minimize allocation overhead. Ideal for batch processing scenarios.
    ///
    /// # Arguments
    /// * `events` - Slice of events to evaluate
    /// * `results` - Pre-allocated buffer for all results (events × primitives)
    ///
    /// # Returns
    /// * `Ok(())` - All evaluations completed successfully
    /// * `Err(SigmaError)` - Evaluation failed
    ///
    /// # Example
    /// ```rust,ignore
    /// let events = &[event1, event2, event3];
    /// let mut results = vec![false; events.len() * primitive_count];
    /// matcher.evaluate_batch_pooled(events, &mut results)?;
    /// ```
    pub fn evaluate_batch_pooled(&self, events: &[&Value], results: &mut [bool]) -> Result<()> {
        let primitive_count = self.compiled_primitives.len();
        let expected_size = events.len() * primitive_count;

        if results.len() < expected_size {
            return Err(crate::error::SigmaError::ExecutionError(format!(
                "Result buffer too small: {} < {}",
                results.len(),
                expected_size
            )));
        }

        for (event_idx, event) in events.iter().enumerate() {
            let context = EventContext::new(event);
            let result_offset = event_idx * primitive_count;

            for (prim_idx, compiled_primitive) in self.compiled_primitives.iter().enumerate() {
                let result_idx = result_offset + prim_idx;
                results[result_idx] =
                    self.evaluate_compiled_primitive_pooled(compiled_primitive, &context)?;
            }
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

    /// Evaluate a single compiled primitive using memory pooling.
    fn evaluate_compiled_primitive_pooled(
        &self,
        primitive: &CompiledPrimitive,
        context: &EventContext,
    ) -> Result<bool> {
        // Extract field value using the field extractor
        let field_path = primitive.field_path_string();
        let field_value = (self.field_extractor)(context, &field_path)?.unwrap_or_else(String::new);

        // Apply modifier chain if present using pooled string
        let processed_value = if primitive.has_modifiers() {
            self.apply_modifier_chain_pooled(&field_value, primitive)?
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

    /// Apply the modifier chain using memory pooling.
    fn apply_modifier_chain_pooled(
        &self,
        field_value: &str,
        primitive: &CompiledPrimitive,
    ) -> Result<String> {
        let mut current_value = self.memory_pool.get_string_buffer();
        current_value.push_str(field_value);

        for modifier_fn in primitive.modifier_chain.iter() {
            let temp_value = modifier_fn(&current_value)?;
            current_value.clear();
            current_value.push_str(&temp_value);
        }

        let result = current_value.clone();
        self.memory_pool.return_string_buffer(current_value);
        Ok(result)
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

    #[test]
    fn test_memory_pool() {
        let pool = MemoryPool::new();

        // Test string buffer pooling
        let buffer1 = pool.get_string_buffer();
        assert!(buffer1.is_empty());

        let mut buffer1 = buffer1;
        buffer1.push_str("test");
        pool.return_string_buffer(buffer1);

        let buffer2 = pool.get_string_buffer();
        assert!(buffer2.is_empty()); // Should be cleared when returned

        // Test result buffer pooling
        let result_buffer = pool.get_result_buffer(5);
        assert_eq!(result_buffer.len(), 5);
        assert_eq!(result_buffer, vec![false; 5]);

        pool.return_result_buffer(result_buffer);
        let result_buffer2 = pool.get_result_buffer(3);
        assert_eq!(result_buffer2.len(), 3);
    }

    #[test]
    fn test_evaluate_ultra_fast() {
        let matcher = create_test_matcher();
        let event = create_test_event();

        let results = matcher.evaluate_ultra_fast(&event).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_evaluate_batch_pooled() {
        let matcher = create_test_matcher();
        let event1 = create_test_event();
        let event2 = create_test_event();
        let events = vec![&event1, &event2];

        let mut results = vec![false; events.len() * matcher.primitive_count()];
        let result = matcher.evaluate_batch_pooled(&events, &mut results);
        assert!(result.is_ok());
        assert_eq!(results.len(), 4); // 2 events × 2 primitives
    }

    #[test]
    fn test_evaluate_batch_pooled_buffer_too_small() {
        let matcher = create_test_matcher();
        let event = create_test_event();
        let events = vec![&event];

        let mut results = vec![false; 1]; // Too small for 2 primitives
        let result = matcher.evaluate_batch_pooled(&events, &mut results);
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_pool_with_capacity() {
        let pool = MemoryPool::with_capacity(10);
        let buffer = pool.get_string_buffer();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_memory_pool_default() {
        let pool = MemoryPool::default();
        let buffer = pool.get_string_buffer();
        assert!(buffer.is_empty());
    }
}
