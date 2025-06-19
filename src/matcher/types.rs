//! Core type definitions for the zero-allocation functional registry.

use crate::error::SigmaError;
use std::sync::Arc;

/// Zero-allocation match function signature.
///
/// Takes a field value and array of values/modifiers as string slices to avoid cloning.
/// Returns true if any of the values match according to the match type logic.
///
/// # Arguments
/// * `field_value` - The extracted field value from the event
/// * `values` - Array of values to match against
/// * `modifiers` - Array of modifier names that affect matching behavior
///
/// # Example
/// ```rust,ignore
/// let exact_match: MatchFn = Arc::new(|field_value, values, modifiers| {
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
pub type MatchFn = Arc<dyn Fn(&str, &[&str], &[&str]) -> Result<bool, SigmaError> + Send + Sync>;

/// Zero-allocation modifier processor.
///
/// Takes an input string and returns a processed string. Modifiers are applied
/// in sequence during primitive evaluation.
///
/// # Arguments
/// * `input` - The input string to process
///
/// # Returns
/// * `Ok(String)` - The processed string
/// * `Err(SigmaError)` - If processing fails
///
/// # Example
/// ```rust,ignore
/// let base64_decode: ModifierFn = Arc::new(|input| {
///     base64::decode(input)
///         .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
///         .map_err(|e| SigmaError::ModifierError(format!("Base64 decode failed: {}", e)))
/// });
/// ```
pub type ModifierFn = Arc<dyn Fn(&str) -> Result<String, SigmaError> + Send + Sync>;

/// Field extraction with caching support for multi-layer processing.
///
/// Extracts field values from events with caching to avoid repeated JSON parsing.
/// Returns an owned string to avoid lifetime issues with caching.
///
/// # Arguments
/// * `context` - The event context containing the event and field cache
/// * `field` - The field name or path to extract
///
/// # Returns
/// * `Ok(Some(String))` - Field value found and cached
/// * `Ok(None)` - Field not found in event
/// * `Err(SigmaError)` - Field extraction failed
///
/// # Example
/// ```rust,ignore
/// let field_extractor: FieldExtractorFn = Arc::new(|context, field| {
///     context.get_field(field)
/// });
/// ```
pub type FieldExtractorFn =
    Arc<dyn Fn(&super::EventContext, &str) -> Result<Option<String>, SigmaError> + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_fn_signature() {
        let exact_match: MatchFn = Arc::new(|field_value, values, _modifiers| {
            for &value in values {
                if field_value == value {
                    return Ok(true);
                }
            }
            Ok(false)
        });

        let result = exact_match("test", &["test", "other"], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = exact_match("nomatch", &["test", "other"], &[]);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_modifier_fn_signature() {
        let uppercase: ModifierFn = Arc::new(|input| Ok(input.to_uppercase()));

        let result = uppercase("hello");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "HELLO");
    }

    #[test]
    fn test_modifier_fn_error() {
        let failing_modifier: ModifierFn =
            Arc::new(|_input| Err(SigmaError::ModifierError("Test error".to_string())));

        let result = failing_modifier("test");
        assert!(result.is_err());
        match result.unwrap_err() {
            SigmaError::ModifierError(msg) => assert_eq!(msg, "Test error"),
            _ => panic!("Expected ModifierError"),
        }
    }

    #[test]
    fn test_function_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MatchFn>();
        assert_send_sync::<ModifierFn>();
        assert_send_sync::<FieldExtractorFn>();
    }
}
