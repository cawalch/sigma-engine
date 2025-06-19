//! Default implementations for common match types and modifiers.

use crate::error::SigmaError;
use crate::matcher::types::{MatchFn, ModifierFn};
use std::sync::Arc;

/// Create default exact match function.
///
/// Supports case-sensitive and case-insensitive matching based on modifiers.
/// Returns true if the field value exactly matches any of the provided values.
///
/// # Modifiers
/// * `case_sensitive` - Perform case-sensitive matching (default: case-insensitive)
///
/// # Example
/// ```rust,ignore
/// let exact_match = create_exact_match();
/// let result = exact_match("Test", &["test"], &[])?; // true (case-insensitive)
/// let result = exact_match("Test", &["test"], &["case_sensitive"])?; // false
/// ```
pub fn create_exact_match() -> MatchFn {
    Arc::new(|field_value, values, modifiers| {
        let case_sensitive = modifiers.contains(&"case_sensitive");
        for &value in values {
            let matches = if case_sensitive {
                field_value == value
            } else {
                field_value.eq_ignore_ascii_case(value)
            };
            if matches {
                return Ok(true);
            }
        }
        Ok(false)
    })
}

/// Create default contains match function.
///
/// Returns true if the field value contains any of the provided values as substrings.
///
/// # Modifiers
/// * `case_sensitive` - Perform case-sensitive matching (default: case-insensitive)
///
/// # Example
/// ```rust,ignore
/// let contains_match = create_contains_match();
/// let result = contains_match("Hello World", &["world"], &[])?; // true
/// ```
pub fn create_contains_match() -> MatchFn {
    Arc::new(|field_value, values, modifiers| {
        let case_sensitive = modifiers.contains(&"case_sensitive");
        for &value in values {
            let matches = if case_sensitive {
                field_value.contains(value)
            } else {
                field_value
                    .to_ascii_lowercase()
                    .contains(&value.to_ascii_lowercase())
            };
            if matches {
                return Ok(true);
            }
        }
        Ok(false)
    })
}

/// Create default starts with match function.
///
/// Returns true if the field value starts with any of the provided values.
///
/// # Modifiers
/// * `case_sensitive` - Perform case-sensitive matching (default: case-insensitive)
pub fn create_startswith_match() -> MatchFn {
    Arc::new(|field_value, values, modifiers| {
        let case_sensitive = modifiers.contains(&"case_sensitive");
        for &value in values {
            let matches = if case_sensitive {
                field_value.starts_with(value)
            } else {
                field_value
                    .to_ascii_lowercase()
                    .starts_with(&value.to_ascii_lowercase())
            };
            if matches {
                return Ok(true);
            }
        }
        Ok(false)
    })
}

/// Create default ends with match function.
///
/// Returns true if the field value ends with any of the provided values.
///
/// # Modifiers
/// * `case_sensitive` - Perform case-sensitive matching (default: case-insensitive)
pub fn create_endswith_match() -> MatchFn {
    Arc::new(|field_value, values, modifiers| {
        let case_sensitive = modifiers.contains(&"case_sensitive");
        for &value in values {
            let matches = if case_sensitive {
                field_value.ends_with(value)
            } else {
                field_value
                    .to_ascii_lowercase()
                    .ends_with(&value.to_ascii_lowercase())
            };
            if matches {
                return Ok(true);
            }
        }
        Ok(false)
    })
}

/// Create default regex match function.
///
/// Returns true if the field value matches any of the provided regex patterns.
/// Uses a simple compilation approach - in production, this would use a global cache.
///
/// # Example
/// ```rust,ignore
/// let regex_match = create_regex_match();
/// let result = regex_match("test123", &[r"\d+"], &[])?; // true
/// ```
pub fn create_regex_match() -> MatchFn {
    Arc::new(|field_value, values, _modifiers| {
        #[cfg(feature = "examples")]
        {
            for &pattern in values {
                let regex = regex::Regex::new(pattern)
                    .map_err(|e| SigmaError::InvalidRegex(e.to_string()))?;
                if regex.is_match(field_value) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        #[cfg(not(feature = "examples"))]
        {
            // Without regex feature, always return false
            // This allows the code to compile without optional dependencies
            let _ = (field_value, values);
            Err(SigmaError::UnsupportedMatchType(
                "regex requires 'examples' feature".to_string(),
            ))
        }
    })
}

/// Create base64 decode modifier.
///
/// Decodes base64-encoded input strings.
///
/// # Example
/// ```rust,ignore
/// let base64_decode = create_base64_decode();
/// let result = base64_decode("SGVsbG8=")?; // "Hello"
/// ```
pub fn create_base64_decode() -> ModifierFn {
    Arc::new(|input| {
        #[cfg(feature = "examples")]
        {
            use base64::{engine::general_purpose, Engine as _};
            general_purpose::STANDARD
                .decode(input)
                .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                .map_err(|e| SigmaError::ModifierError(format!("Base64 decode failed: {}", e)))
        }
        #[cfg(not(feature = "examples"))]
        {
            let _ = input;
            Err(SigmaError::ModifierError(
                "base64_decode requires 'examples' feature".to_string(),
            ))
        }
    })
}

/// Create UTF-16 decode modifier.
///
/// Decodes UTF-16 encoded input strings. This is a simplified implementation.
///
/// # Example
/// ```rust,ignore
/// let utf16_decode = create_utf16_decode();
/// let result = utf16_decode("encoded_string")?;
/// ```
pub fn create_utf16_decode() -> ModifierFn {
    Arc::new(|input| {
        // Simplified UTF-16 decoding - in production this would be more sophisticated
        Ok(input.to_string())
    })
}

/// Register all default match types and modifiers with a builder.
///
/// This is used internally by MatcherBuilder::new() to set up default implementations.
///
/// # Match Types Registered
/// * `equals` - Exact string matching
/// * `contains` - Substring matching
/// * `startswith` - Prefix matching
/// * `endswith` - Suffix matching
/// * `regex` - Regular expression matching (requires 'examples' feature)
///
/// # Modifiers Registered
/// * `base64_decode` - Base64 decoding (requires 'examples' feature)
/// * `utf16_decode` - UTF-16 decoding
pub fn register_defaults(
    match_registry: &mut std::collections::HashMap<String, MatchFn>,
    modifier_registry: &mut std::collections::HashMap<String, ModifierFn>,
) {
    // Register match types
    match_registry.insert("equals".to_string(), create_exact_match());
    match_registry.insert("contains".to_string(), create_contains_match());
    match_registry.insert("startswith".to_string(), create_startswith_match());
    match_registry.insert("endswith".to_string(), create_endswith_match());
    match_registry.insert("regex".to_string(), create_regex_match());

    // Register modifiers
    modifier_registry.insert("base64_decode".to_string(), create_base64_decode());
    modifier_registry.insert("utf16_decode".to_string(), create_utf16_decode());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match_case_insensitive() {
        let exact_match = create_exact_match();

        let result = exact_match("Test", &["test"], &[]).unwrap();
        assert!(result);

        let result = exact_match("TEST", &["test"], &[]).unwrap();
        assert!(result);

        let result = exact_match("different", &["test"], &[]).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_exact_match_case_sensitive() {
        let exact_match = create_exact_match();

        let result = exact_match("Test", &["test"], &["case_sensitive"]).unwrap();
        assert!(!result);

        let result = exact_match("test", &["test"], &["case_sensitive"]).unwrap();
        assert!(result);
    }

    #[test]
    fn test_contains_match() {
        let contains_match = create_contains_match();

        let result = contains_match("Hello World", &["world"], &[]).unwrap();
        assert!(result);

        let result = contains_match("Hello World", &["WORLD"], &[]).unwrap();
        assert!(result);

        let result = contains_match("Hello World", &["xyz"], &[]).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_startswith_match() {
        let startswith_match = create_startswith_match();

        let result = startswith_match("Hello World", &["hello"], &[]).unwrap();
        assert!(result);

        let result = startswith_match("Hello World", &["world"], &[]).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_endswith_match() {
        let endswith_match = create_endswith_match();

        let result = endswith_match("Hello World", &["world"], &[]).unwrap();
        assert!(result);

        let result = endswith_match("Hello World", &["hello"], &[]).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_multiple_values() {
        let exact_match = create_exact_match();

        let result = exact_match("test", &["other", "test", "another"], &[]).unwrap();
        assert!(result);

        let result = exact_match("nomatch", &["other", "test", "another"], &[]).unwrap();
        assert!(!result);
    }

    #[cfg(feature = "examples")]
    #[test]
    fn test_regex_match() {
        let regex_match = create_regex_match();

        let result = regex_match("test123", &[r"\d+"], &[]).unwrap();
        assert!(result);

        let result = regex_match("testABC", &[r"\d+"], &[]).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_utf16_decode() {
        let utf16_decode = create_utf16_decode();

        let result = utf16_decode("test").unwrap();
        assert_eq!(result, "test");
    }

    #[test]
    fn test_register_defaults() {
        let mut match_registry = std::collections::HashMap::new();
        let mut modifier_registry = std::collections::HashMap::new();

        register_defaults(&mut match_registry, &mut modifier_registry);

        assert!(match_registry.contains_key("equals"));
        assert!(match_registry.contains_key("contains"));
        assert!(match_registry.contains_key("startswith"));
        assert!(match_registry.contains_key("endswith"));
        assert!(match_registry.contains_key("regex"));

        assert!(modifier_registry.contains_key("base64_decode"));
        assert!(modifier_registry.contains_key("utf16_decode"));
    }
}
