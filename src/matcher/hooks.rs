//! Compilation hooks for multi-layer integration.

use crate::error::SigmaError;
use crate::ir::Primitive;
use std::sync::Arc;

/// Hook function signature for compilation phases.
///
/// Compilation hooks are called during different phases of primitive compilation
/// to allow external libraries to extract patterns for multi-layer filtering.
///
/// # Arguments
/// * `context` - Compilation context containing primitive metadata and extracted data
///
/// # Returns
/// * `Ok(())` - Hook executed successfully
/// * `Err(SigmaError)` - Hook execution failed
///
/// # Example
/// ```rust,ignore
/// let aho_corasick_hook: CompilationHookFn = Arc::new(|ctx| {
///     if ctx.is_literal_only {
///         for &value in ctx.literal_values {
///             // Add literal to AhoCorasick automaton
///             println!("Adding literal: {}", value);
///         }
///     }
///     Ok(())
/// });
/// ```
pub type CompilationHookFn =
    Arc<dyn Fn(&CompilationContext) -> Result<(), SigmaError> + Send + Sync>;

/// Compilation phases where hooks can be registered.
///
/// Different phases provide different levels of information and are suitable
/// for different types of external filter integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompilationPhase {
    /// Called for each primitive during discovery phase.
    ///
    /// Provides access to individual primitive data including field names,
    /// match types, values, and modifiers. Ideal for extracting patterns
    /// for external filtering libraries.
    PrimitiveDiscovery,

    /// Called after all primitives are discovered but before compilation.
    ///
    /// Provides a summary view of all discovered primitives. Useful for
    /// global optimizations and filter preparation.
    PreCompilation,

    /// Called after compilation is complete.
    ///
    /// Provides access to final compiled state. Useful for cleanup,
    /// finalization, and performance metrics collection.
    PostCompilation,
}

/// Context provided to compilation hooks containing extracted primitive data.
///
/// This struct provides comprehensive information about a primitive being compiled,
/// including metadata, extracted values, and optimization hints.
#[derive(Debug)]
pub struct CompilationContext<'a> {
    /// The primitive being compiled
    pub primitive: &'a Primitive,

    /// The rule ID this primitive belongs to
    pub rule_id: u32,

    /// The rule name/title if available
    pub rule_name: Option<&'a str>,

    /// Extracted literal values (post-modifier processing if applicable)
    ///
    /// These are the actual string values that will be matched against,
    /// after any modifiers have been applied. Useful for external filters
    /// that need the final processed values.
    pub literal_values: &'a [&'a str],

    /// Raw field name before any normalization
    ///
    /// The original field name as it appears in the SIGMA rule,
    /// before any field mapping or normalization is applied.
    pub raw_field: &'a str,

    /// Normalized field name after field mapping
    ///
    /// The field name after applying field mapping rules and normalization.
    /// This is the field name that will be used during evaluation.
    pub normalized_field: &'a str,

    /// Match type (equals, contains, regex, etc.)
    ///
    /// The type of matching operation to be performed. This affects
    /// how external filters should process the values.
    pub match_type: &'a str,

    /// Applied modifiers
    ///
    /// List of modifiers that will be applied to field values before matching.
    /// External filters may need to consider these when processing patterns.
    pub modifiers: &'a [&'a str],

    /// Indicates if this primitive contains only literal values (no regex/wildcards)
    ///
    /// When true, all values are literal strings that can be efficiently
    /// processed by external filters like AhoCorasick or XOR filters.
    /// When false, values may contain regex patterns or wildcards.
    pub is_literal_only: bool,

    /// Estimated selectivity (0.0 = very selective, 1.0 = matches everything)
    ///
    /// A hint about how selective this primitive is likely to be.
    /// Lower values indicate more selective patterns that are likely
    /// to match fewer events. Useful for optimization decisions.
    pub selectivity_hint: f64,
}

impl<'a> CompilationContext<'a> {
    /// Create a new compilation context for a primitive.
    ///
    /// # Arguments
    /// * `primitive` - The primitive being compiled
    /// * `rule_id` - The rule ID this primitive belongs to
    /// * `rule_name` - Optional rule name/title
    /// * `literal_values` - Extracted literal values
    /// * `raw_field` - Raw field name before normalization
    /// * `normalized_field` - Normalized field name
    /// * `match_type` - Match type string
    /// * `modifiers` - Applied modifiers
    /// * `is_literal_only` - Whether all values are literals
    /// * `selectivity_hint` - Estimated selectivity
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        primitive: &'a Primitive,
        rule_id: u32,
        rule_name: Option<&'a str>,
        literal_values: &'a [&'a str],
        raw_field: &'a str,
        normalized_field: &'a str,
        match_type: &'a str,
        modifiers: &'a [&'a str],
        is_literal_only: bool,
        selectivity_hint: f64,
    ) -> Self {
        Self {
            primitive,
            rule_id,
            rule_name,
            literal_values,
            raw_field,
            normalized_field,
            match_type,
            modifiers,
            is_literal_only,
            selectivity_hint,
        }
    }

    /// Create a summary context for pre/post compilation phases.
    ///
    /// Used when hooks need to be called but there's no specific primitive
    /// being processed (e.g., during pre-compilation or post-compilation phases).
    ///
    /// # Arguments
    /// * `rule_id` - The rule ID
    /// * `rule_name` - Optional rule name/title
    pub fn new_summary(
        rule_id: u32,
        rule_name: Option<&'static str>,
    ) -> CompilationContext<'static> {
        // Create a placeholder primitive for summary contexts
        // Use Box::leak to create a static reference
        let placeholder = Box::leak(Box::new(Primitive::new_static("", "", &[], &[])));

        CompilationContext {
            primitive: placeholder,
            rule_id,
            rule_name,
            literal_values: &[],
            raw_field: "",
            normalized_field: "",
            match_type: "",
            modifiers: &[],
            is_literal_only: false,
            selectivity_hint: 0.5,
        }
    }

    /// Check if this context represents a summary (non-primitive-specific) context.
    pub fn is_summary(&self) -> bool {
        self.raw_field.is_empty() && self.match_type.is_empty()
    }

    /// Get the number of literal values.
    pub fn literal_value_count(&self) -> usize {
        self.literal_values.len()
    }

    /// Check if this primitive has any modifiers.
    pub fn has_modifiers(&self) -> bool {
        !self.modifiers.is_empty()
    }

    /// Get a description of the compilation context for debugging.
    pub fn description(&self) -> String {
        if self.is_summary() {
            format!(
                "Summary context for rule {} ({})",
                self.rule_id,
                self.rule_name.unwrap_or("unnamed")
            )
        } else {
            format!(
                "Primitive context: {} {} {} (rule {}, {} values, selectivity: {:.2})",
                self.normalized_field,
                self.match_type,
                if self.is_literal_only {
                    "literal"
                } else {
                    "pattern"
                },
                self.rule_id,
                self.literal_value_count(),
                self.selectivity_hint
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compilation_phase_equality() {
        assert_eq!(
            CompilationPhase::PrimitiveDiscovery,
            CompilationPhase::PrimitiveDiscovery
        );
        assert_ne!(
            CompilationPhase::PrimitiveDiscovery,
            CompilationPhase::PreCompilation
        );
    }

    #[test]
    fn test_compilation_context_creation() {
        let primitive = Primitive::new_static("EventID", "equals", &["4624"], &[]);
        let literal_values = ["4624"];
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

        assert_eq!(context.rule_id, 1);
        assert_eq!(context.rule_name, Some("Test Rule"));
        assert_eq!(context.literal_values.len(), 1);
        assert_eq!(context.literal_values[0], "4624");
        assert_eq!(context.raw_field, "EventID");
        assert_eq!(context.normalized_field, "EventID");
        assert_eq!(context.match_type, "equals");
        assert!(context.is_literal_only);
        assert_eq!(context.selectivity_hint, 0.1);
        assert!(!context.is_summary());
        assert_eq!(context.literal_value_count(), 1);
        assert!(!context.has_modifiers());
    }

    #[test]
    fn test_summary_context() {
        let context = CompilationContext::new_summary(42, Some("Summary Rule"));

        assert_eq!(context.rule_id, 42);
        assert_eq!(context.rule_name, Some("Summary Rule"));
        assert!(context.is_summary());
        assert_eq!(context.literal_value_count(), 0);
        assert!(!context.has_modifiers());
    }

    #[test]
    fn test_context_description() {
        let primitive = Primitive::new_static("EventID", "equals", &["4624"], &[]);
        let literal_values = ["4624"];
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

        let description = context.description();
        assert!(description.contains("EventID"));
        assert!(description.contains("equals"));
        assert!(description.contains("literal"));
        assert!(description.contains("rule 1"));

        let summary_context = CompilationContext::new_summary(42, Some("Summary Rule"));
        let summary_description = summary_context.description();
        assert!(summary_description.contains("Summary context"));
        assert!(summary_description.contains("rule 42"));
        assert!(summary_description.contains("Summary Rule"));
    }

    #[test]
    fn test_hook_function_signature() {
        let hook: CompilationHookFn = Arc::new(|ctx| {
            // Simple test hook that just checks the context
            assert!(ctx.rule_id > 0);
            Ok(())
        });

        let context = CompilationContext::new_summary(1, Some("Test"));
        let result = hook(&context);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hook_function_error() {
        let failing_hook: CompilationHookFn =
            Arc::new(|_ctx| Err(SigmaError::CompilationError("Test hook error".to_string())));

        let context = CompilationContext::new_summary(1, Some("Test"));
        let result = failing_hook(&context);
        assert!(result.is_err());
        match result.unwrap_err() {
            SigmaError::CompilationError(msg) => assert_eq!(msg, "Test hook error"),
            _ => panic!("Expected CompilationError"),
        }
    }
}
