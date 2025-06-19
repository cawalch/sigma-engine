//! Builder for constructing high-performance matchers with registry pattern.

use crate::error::{Result, SigmaError};
use crate::ir::Primitive;
use crate::matcher::{
    CompiledPrimitive, EventContext, FieldExtractorFn, FunctionalMatcher, MatchFn, ModifierFn,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Builder for constructing high-performance matchers with registry pattern.
///
/// Uses the registry pattern to allow flexible registration of match functions
/// and modifiers while maintaining zero-allocation evaluation performance.
///
/// # Example
/// ```rust,ignore
/// use sigma_engine::matcher::MatcherBuilder;
///
/// let matcher = MatcherBuilder::new()
///     .register_match("custom_equals", |field_value, values, _modifiers| {
///         values.iter().any(|&v| field_value == v)
///     })
///     .register_modifier("custom_upper", |input| Ok(input.to_uppercase()))
///     .compile(&primitives)?;
/// ```
pub struct MatcherBuilder {
    /// Registry of match functions by match type name
    match_registry: HashMap<String, MatchFn>,

    /// Registry of modifier functions by modifier name
    modifier_registry: HashMap<String, ModifierFn>,

    /// Optional custom field extractor
    field_extractor: Option<FieldExtractorFn>,
}

impl MatcherBuilder {
    /// Create a new matcher builder with default implementations.
    ///
    /// Automatically registers common match types and modifiers for immediate use.
    ///
    /// # Example
    /// ```rust,ignore
    /// let builder = MatcherBuilder::new();
    /// // Now has default implementations for: equals, contains, startswith, endswith, regex
    /// // And default modifiers: base64_decode, utf16_decode
    /// ```
    pub fn new() -> Self {
        let mut builder = Self {
            match_registry: HashMap::new(),
            modifier_registry: HashMap::new(),
            field_extractor: None,
        };

        // Register default implementations
        builder.register_defaults();
        builder
    }

    /// Register a zero-allocation match function.
    ///
    /// # Arguments
    /// * `match_type` - Name of the match type (e.g., "equals", "contains")
    /// * `func` - Function implementing the match logic
    ///
    /// # Example
    /// ```rust,ignore
    /// builder.register_match("exact", |field_value, values, modifiers| {
    ///     let case_sensitive = modifiers.contains(&"case_sensitive");
    ///     for &value in values {
    ///         let matches = if case_sensitive {
    ///             field_value == value
    ///         } else {
    ///             field_value.eq_ignore_ascii_case(value)
    ///         };
    ///         if matches { return Ok(true); }
    ///     }
    ///     Ok(false)
    /// });
    /// ```
    pub fn register_match<F>(&mut self, match_type: &str, func: F) -> &mut Self
    where
        F: Fn(&str, &[&str], &[&str]) -> Result<bool> + Send + Sync + 'static,
    {
        self.match_registry
            .insert(match_type.to_string(), Arc::new(func));
        self
    }

    /// Register a modifier processor.
    ///
    /// # Arguments
    /// * `modifier` - Name of the modifier (e.g., "base64_decode", "uppercase")
    /// * `processor` - Function implementing the modifier logic
    ///
    /// # Example
    /// ```rust,ignore
    /// builder.register_modifier("uppercase", |input| {
    ///     Ok(input.to_uppercase())
    /// });
    /// ```
    pub fn register_modifier<F>(&mut self, modifier: &str, processor: F) -> &mut Self
    where
        F: Fn(&str) -> Result<String> + Send + Sync + 'static,
    {
        self.modifier_registry
            .insert(modifier.to_string(), Arc::new(processor));
        self
    }

    /// Set custom field extractor with caching support.
    ///
    /// # Arguments
    /// * `extractor` - Function for extracting field values from events
    ///
    /// # Example
    /// ```rust,ignore
    /// builder.with_field_extractor(|context, field| {
    ///     // Custom field extraction logic
    ///     context.get_field(field)
    /// });
    /// ```
    pub fn with_field_extractor<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&EventContext, &str) -> Result<Option<String>> + Send + Sync + 'static,
    {
        self.field_extractor = Some(Arc::new(extractor));
        self
    }

    /// Compile primitives into high-performance matcher.
    ///
    /// # Arguments
    /// * `primitives` - Array of primitives to compile
    ///
    /// # Returns
    /// * `Ok(FunctionalMatcher)` - Compiled matcher ready for evaluation
    /// * `Err(SigmaError)` - Compilation failed
    ///
    /// # Example
    /// ```rust,ignore
    /// let primitives = vec![
    ///     Primitive::new_static("EventID", "equals", &["4624"], &[]),
    /// ];
    /// let matcher = builder.compile(&primitives)?;
    /// ```
    pub fn compile(self, primitives: &[Primitive]) -> Result<FunctionalMatcher> {
        let mut compiled_primitives = Vec::with_capacity(primitives.len());

        for primitive in primitives {
            let compiled = self.compile_primitive(primitive)?;
            compiled_primitives.push(compiled);
        }

        Ok(FunctionalMatcher::new(
            compiled_primitives,
            self.field_extractor
                .unwrap_or_else(|| Arc::new(default_field_extractor)),
        ))
    }

    /// Compile a single primitive into a CompiledPrimitive.
    fn compile_primitive(&self, primitive: &Primitive) -> Result<CompiledPrimitive> {
        // Pre-parse field path for nested access
        let field_path: Vec<String> = primitive.field.split('.').map(|s| s.to_string()).collect();

        // Get match function
        let match_fn = self
            .match_registry
            .get(primitive.match_type.as_ref())
            .ok_or_else(|| SigmaError::UnsupportedMatchType(primitive.match_type.to_string()))?
            .clone();

        // Pre-compile modifier chain
        let mut modifier_chain = Vec::new();
        for modifier in &primitive.modifiers {
            if let Some(modifier_fn) = self.modifier_registry.get(modifier.as_ref()) {
                modifier_chain.push(modifier_fn.clone());
            }
            // Note: Missing modifiers are silently ignored for now
            // In production, this might be configurable behavior
        }

        // Pre-allocate values and modifiers
        let values: Vec<String> = primitive.values.iter().map(|v| v.to_string()).collect();

        let raw_modifiers: Vec<String> =
            primitive.modifiers.iter().map(|m| m.to_string()).collect();

        Ok(CompiledPrimitive::new(
            field_path,
            match_fn,
            modifier_chain,
            values,
            raw_modifiers,
        ))
    }

    /// Register default match types and modifiers.
    fn register_defaults(&mut self) {
        crate::matcher::defaults::register_defaults(
            &mut self.match_registry,
            &mut self.modifier_registry,
        );
    }

    /// Get the number of registered match types.
    pub fn match_type_count(&self) -> usize {
        self.match_registry.len()
    }

    /// Get the number of registered modifiers.
    pub fn modifier_count(&self) -> usize {
        self.modifier_registry.len()
    }

    /// Check if a match type is registered.
    pub fn has_match_type(&self, match_type: &str) -> bool {
        self.match_registry.contains_key(match_type)
    }

    /// Check if a modifier is registered.
    pub fn has_modifier(&self, modifier: &str) -> bool {
        self.modifier_registry.contains_key(modifier)
    }
}

impl Default for MatcherBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Default field extractor implementation.
fn default_field_extractor(context: &EventContext, field: &str) -> Result<Option<String>> {
    // Use the EventContext's built-in field extraction
    context.get_field(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Primitive;

    #[test]
    fn test_builder_creation() {
        let builder = MatcherBuilder::new();
        assert!(builder.match_type_count() > 0); // Should have defaults
        assert!(builder.modifier_count() > 0); // Should have default modifiers
    }

    #[test]
    fn test_match_registration() {
        let mut builder = MatcherBuilder::new();
        let initial_count = builder.match_type_count();

        builder.register_match("custom", |_field, _values, _modifiers| Ok(true));

        assert_eq!(builder.match_type_count(), initial_count + 1);
        assert!(builder.has_match_type("custom"));
        assert!(!builder.has_match_type("nonexistent"));
    }

    #[test]
    fn test_modifier_registration() {
        let mut builder = MatcherBuilder::new();
        let initial_count = builder.modifier_count();

        builder.register_modifier("uppercase", |input| Ok(input.to_uppercase()));

        assert_eq!(builder.modifier_count(), initial_count + 1);
        assert!(builder.has_modifier("uppercase"));
        assert!(!builder.has_modifier("nonexistent"));
    }

    #[test]
    fn test_primitive_compilation() {
        let builder = MatcherBuilder::new();
        let primitive = Primitive::new_static("EventID", "equals", &["4624"], &[]);

        let result = builder.compile_primitive(&primitive);
        assert!(result.is_ok());

        let compiled = result.unwrap();
        assert_eq!(compiled.field_path_string(), "EventID");
        assert_eq!(compiled.value_count(), 1);
    }

    #[test]
    fn test_unsupported_match_type() {
        let builder = MatcherBuilder::new();
        let primitive = Primitive::new_static("EventID", "unsupported", &["4624"], &[]);

        let result = builder.compile_primitive(&primitive);
        assert!(result.is_err());
        match result.unwrap_err() {
            SigmaError::UnsupportedMatchType(match_type) => {
                assert_eq!(match_type, "unsupported");
            }
            _ => panic!("Expected UnsupportedMatchType error"),
        }
    }

    #[test]
    fn test_nested_field_compilation() {
        let builder = MatcherBuilder::new();
        let primitive = Primitive::new_static("nested.field", "equals", &["value"], &[]);

        let compiled = builder.compile_primitive(&primitive).unwrap();
        assert_eq!(compiled.field_path_string(), "nested.field");
        assert_eq!(compiled.field_path.len(), 2);
    }
}
