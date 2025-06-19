//! Builder for constructing high-performance matchers with registry pattern.

use crate::error::{Result, SigmaError};
use crate::ir::Primitive;
use crate::matcher::{
    CompilationContext, CompilationHookFn, CompilationPhase, CompiledPrimitive, EventContext,
    FieldExtractorFn, FunctionalMatcher, MatchFn, ModifierFn,
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

    /// Compilation hooks organized by phase
    compilation_hooks: HashMap<CompilationPhase, Vec<CompilationHookFn>>,
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
            compilation_hooks: HashMap::new(),
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

    /// Register a compilation hook for a specific phase.
    ///
    /// Compilation hooks are called during different phases of primitive compilation
    /// to allow external libraries to extract patterns for multi-layer filtering.
    ///
    /// # Arguments
    /// * `phase` - The compilation phase when this hook should be called
    /// * `hook` - Function to call during the specified phase
    ///
    /// # Example
    /// ```rust,ignore
    /// builder.register_compilation_hook(
    ///     CompilationPhase::PrimitiveDiscovery,
    ///     |ctx| {
    ///         if ctx.is_literal_only {
    ///             for &value in ctx.literal_values {
    ///                 // Add literal to external filter
    ///                 println!("Adding literal: {}", value);
    ///             }
    ///         }
    ///         Ok(())
    ///     }
    /// );
    /// ```
    pub fn register_compilation_hook<F>(&mut self, phase: CompilationPhase, hook: F) -> &mut Self
    where
        F: Fn(&CompilationContext) -> Result<()> + Send + Sync + 'static,
    {
        self.compilation_hooks
            .entry(phase)
            .or_default()
            .push(Arc::new(hook));
        self
    }

    /// Convenience method for AhoCorasick pattern extraction.
    ///
    /// Registers a hook that extracts literal values during primitive discovery
    /// for use with AhoCorasick automaton construction.
    ///
    /// # Arguments
    /// * `extractor` - Function called with each literal value and selectivity hint
    ///
    /// # Example
    /// ```rust,ignore
    /// builder.with_aho_corasick_extraction(|literal, selectivity| {
    ///     if selectivity < 0.5 {  // Only add selective patterns
    ///         aho_corasick_patterns.push(literal.to_string());
    ///     }
    ///     Ok(())
    /// });
    /// ```
    pub fn with_aho_corasick_extraction<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&str, f64) -> Result<()> + Send + Sync + 'static,
    {
        let hook = Arc::new(move |ctx: &CompilationContext| {
            if ctx.is_literal_only {
                for &value in ctx.literal_values {
                    extractor(value, ctx.selectivity_hint)?;
                }
            }
            Ok(())
        });

        self.register_compilation_hook(CompilationPhase::PrimitiveDiscovery, move |ctx| hook(ctx));
        self
    }

    /// Convenience method for FST (Finite State Transducer) pattern extraction.
    ///
    /// Registers a hook that extracts patterns suitable for FST construction.
    ///
    /// # Arguments
    /// * `extractor` - Function called with field name, pattern, and metadata
    ///
    /// # Example
    /// ```rust,ignore
    /// builder.with_fst_extraction(|field, pattern, is_literal| {
    ///     if is_literal {
    ///         fst_builder.add_pattern(field, pattern);
    ///     }
    ///     Ok(())
    /// });
    /// ```
    pub fn with_fst_extraction<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&str, &str, bool) -> Result<()> + Send + Sync + 'static,
    {
        let hook = Arc::new(move |ctx: &CompilationContext| {
            for &value in ctx.literal_values {
                extractor(ctx.normalized_field, value, ctx.is_literal_only)?;
            }
            Ok(())
        });

        self.register_compilation_hook(CompilationPhase::PrimitiveDiscovery, move |ctx| hook(ctx));
        self
    }

    /// Convenience method for XOR/Cuckoo filter pattern extraction.
    ///
    /// Registers a hook that extracts patterns for probabilistic filters.
    ///
    /// # Arguments
    /// * `extractor` - Function called with pattern and selectivity hint
    ///
    /// # Example
    /// ```rust,ignore
    /// builder.with_filter_extraction(|pattern, selectivity| {
    ///     if selectivity < 0.3 {  // Only very selective patterns
    ///         xor_filter.add_pattern(pattern);
    ///     }
    ///     Ok(())
    /// });
    /// ```
    pub fn with_filter_extraction<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&str, f64) -> Result<()> + Send + Sync + 'static,
    {
        let hook = Arc::new(move |ctx: &CompilationContext| {
            if ctx.is_literal_only {
                for &value in ctx.literal_values {
                    extractor(value, ctx.selectivity_hint)?;
                }
            }
            Ok(())
        });

        self.register_compilation_hook(CompilationPhase::PrimitiveDiscovery, move |ctx| hook(ctx));
        self
    }

    /// Compile primitives into high-performance matcher with hook execution.
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
        // Execute pre-compilation hooks
        if let Some(hooks) = self
            .compilation_hooks
            .get(&CompilationPhase::PreCompilation)
        {
            for hook in hooks {
                let summary_ctx = CompilationContext::new_summary(0, Some("Compilation"));
                hook(&summary_ctx)?;
            }
        }

        let mut compiled_primitives = Vec::with_capacity(primitives.len());

        for (index, primitive) in primitives.iter().enumerate() {
            // Execute primitive discovery hooks
            if let Some(hooks) = self
                .compilation_hooks
                .get(&CompilationPhase::PrimitiveDiscovery)
            {
                self.execute_primitive_hooks(primitive, index as u32, hooks)?;
            }

            let compiled = self.compile_primitive(primitive)?;
            compiled_primitives.push(compiled);
        }

        // Execute post-compilation hooks
        if let Some(hooks) = self
            .compilation_hooks
            .get(&CompilationPhase::PostCompilation)
        {
            for hook in hooks {
                let summary_ctx = CompilationContext::new_summary(0, Some("Compilation Complete"));
                hook(&summary_ctx)?;
            }
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

    /// Execute primitive discovery hooks for a primitive.
    fn execute_primitive_hooks(
        &self,
        primitive: &Primitive,
        rule_id: u32,
        hooks: &[CompilationHookFn],
    ) -> Result<()> {
        // Extract literal values from the primitive
        let literal_values: Vec<&str> = primitive.values.iter().map(|v| v.as_ref()).collect();

        // Extract modifier names
        let modifiers: Vec<&str> = primitive.modifiers.iter().map(|m| m.as_ref()).collect();

        // Calculate selectivity hint based on match type and values
        let selectivity_hint = self.calculate_selectivity_hint(primitive);

        // Determine if this primitive contains only literal values
        let is_literal_only = self.is_primitive_literal_only(primitive);

        // Create compilation context with proper lifetimes
        let ctx = CompilationContext::new(
            primitive,
            rule_id,
            None, // Rule name not available at this level
            &literal_values,
            primitive.field.as_ref(), // Raw field
            primitive.field.as_ref(), // Normalized field (same for now)
            primitive.match_type.as_ref(),
            &modifiers,
            is_literal_only,
            selectivity_hint,
        );

        // Execute all hooks for this primitive
        for hook in hooks {
            hook(&ctx)?;
        }

        Ok(())
    }

    /// Calculate selectivity hint for a primitive.
    fn calculate_selectivity_hint(&self, primitive: &Primitive) -> f64 {
        match primitive.match_type.as_ref() {
            "equals" => 0.1,     // Very selective
            "contains" => 0.3,   // Moderately selective
            "startswith" => 0.2, // Selective
            "endswith" => 0.2,   // Selective
            "regex" => 0.5,      // Variable selectivity
            _ => 0.5,            // Default moderate selectivity
        }
    }

    /// Check if a primitive contains only literal values.
    fn is_primitive_literal_only(&self, primitive: &Primitive) -> bool {
        match primitive.match_type.as_ref() {
            "equals" | "contains" | "startswith" | "endswith" => {
                // Check if any values contain wildcards or regex patterns
                !primitive.values.iter().any(|v| {
                    let value = v.as_ref();
                    value.contains('*')
                        || value.contains('?')
                        || value.contains('[')
                        || value.contains('^')
                })
            }
            "regex" => false, // Regex patterns are not literal
            _ => true,        // Default to literal for unknown types
        }
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

    /// Get the number of registered compilation hooks for a phase.
    pub fn hook_count(&self, phase: CompilationPhase) -> usize {
        self.compilation_hooks
            .get(&phase)
            .map_or(0, |hooks| hooks.len())
    }

    /// Check if any hooks are registered for a phase.
    pub fn has_hooks(&self, phase: CompilationPhase) -> bool {
        self.hook_count(phase) > 0
    }

    /// Get the total number of registered hooks across all phases.
    pub fn total_hook_count(&self) -> usize {
        self.compilation_hooks
            .values()
            .map(|hooks| hooks.len())
            .sum()
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

    #[test]
    fn test_hook_registration() {
        use crate::matcher::CompilationPhase;

        let mut builder = MatcherBuilder::new();
        assert_eq!(builder.hook_count(CompilationPhase::PrimitiveDiscovery), 0);
        assert!(!builder.has_hooks(CompilationPhase::PrimitiveDiscovery));

        builder.register_compilation_hook(CompilationPhase::PrimitiveDiscovery, |_ctx| Ok(()));

        assert_eq!(builder.hook_count(CompilationPhase::PrimitiveDiscovery), 1);
        assert!(builder.has_hooks(CompilationPhase::PrimitiveDiscovery));
        assert_eq!(builder.total_hook_count(), 1);
    }

    #[test]
    fn test_convenience_hook_methods() {
        use std::sync::{Arc, Mutex};

        let extracted_patterns = Arc::new(Mutex::new(Vec::<String>::new()));
        let patterns_clone = extracted_patterns.clone();

        let builder =
            MatcherBuilder::new().with_aho_corasick_extraction(move |literal, _selectivity| {
                patterns_clone.lock().unwrap().push(literal.to_string());
                Ok(())
            });

        assert!(builder.has_hooks(CompilationPhase::PrimitiveDiscovery));

        // Test compilation with hook execution
        let primitives = vec![Primitive::new_static("EventID", "equals", &["4624"], &[])];

        let _matcher = builder.compile(&primitives).unwrap();

        // Check that the hook was called
        let patterns = extracted_patterns.lock().unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0], "4624");
    }

    #[test]
    fn test_selectivity_calculation() {
        let builder = MatcherBuilder::new();

        let equals_primitive = Primitive::new_static("field", "equals", &["value"], &[]);
        assert_eq!(builder.calculate_selectivity_hint(&equals_primitive), 0.1);

        let contains_primitive = Primitive::new_static("field", "contains", &["value"], &[]);
        assert_eq!(builder.calculate_selectivity_hint(&contains_primitive), 0.3);

        let regex_primitive = Primitive::new_static("field", "regex", &[".*"], &[]);
        assert_eq!(builder.calculate_selectivity_hint(&regex_primitive), 0.5);
    }

    #[test]
    fn test_literal_only_detection() {
        let builder = MatcherBuilder::new();

        let literal_primitive = Primitive::new_static("field", "equals", &["literal"], &[]);
        assert!(builder.is_primitive_literal_only(&literal_primitive));

        let wildcard_primitive = Primitive::new_static("field", "equals", &["test*"], &[]);
        assert!(!builder.is_primitive_literal_only(&wildcard_primitive));

        let regex_primitive = Primitive::new_static("field", "regex", &[".*"], &[]);
        assert!(!builder.is_primitive_literal_only(&regex_primitive));
    }
}
