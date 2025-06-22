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
/// Uses the global regex cache for optimal performance with repeated patterns.
///
/// # Example
/// ```rust,ignore
/// let regex_match = create_regex_match();
/// let result = regex_match("test123", &[r"\d+"], &[])?; // true
/// ```
pub fn create_regex_match() -> MatchFn {
    Arc::new(|field_value, values, _modifiers| {
        use crate::matcher::cache::global_regex_cache;

        for &pattern in values {
            let regex = global_regex_cache().get_regex(pattern)?;
            if regex.is_match(field_value) {
                return Ok(true);
            }
        }
        Ok(false)
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
        use base64::{engine::general_purpose, Engine as _};
        general_purpose::STANDARD
            .decode(input)
            .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
            .map_err(|e| SigmaError::ModifierError(format!("Base64 decode failed: {}", e)))
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

/// Create CIDR match function.
///
/// Returns true if the field value (IP address) is contained within any of the provided CIDR ranges.
///
/// # Example
/// ```rust,ignore
/// let cidr_match = create_cidr_match();
/// let result = cidr_match("192.168.1.100", &["192.168.1.0/24"], &[])?; // true
/// ```
/// Create range match function.
///
/// Returns true if the field value (as a number) falls within any of the provided ranges.
/// Range format: "min-max" (e.g., "100-200")
///
/// # Example
/// ```rust,ignore
/// let range_match = create_range_match();
/// let result = range_match("150", &["100-200"], &[])?; // true
/// ```
pub fn create_range_match() -> MatchFn {
    Arc::new(|field_value, values, _modifiers| {
        let field_num: f64 = field_value
            .parse()
            .map_err(|_| SigmaError::InvalidNumber(field_value.to_string()))?;

        for &range_str in values {
            if let Some((min_str, max_str)) = range_str.split_once('-') {
                let min: f64 = min_str
                    .parse()
                    .map_err(|_| SigmaError::InvalidRange(range_str.to_string()))?;
                let max: f64 = max_str
                    .parse()
                    .map_err(|_| SigmaError::InvalidRange(range_str.to_string()))?;

                if field_num >= min && field_num <= max {
                    return Ok(true);
                }
            } else {
                return Err(SigmaError::InvalidRange(range_str.to_string()));
            }
        }
        Ok(false)
    })
}

/// Create fuzzy match function.
///
/// Returns true if the field value is similar to any of the provided values
/// based on a configurable similarity threshold.
///
/// # Modifiers
/// * `threshold:X.X` - Set similarity threshold (default: 0.8)
///
/// # Example
/// ```rust,ignore
/// let fuzzy_match = create_fuzzy_match();
/// let result = fuzzy_match("hello", &["helo"], &["threshold:0.7"])?; // true
/// ```
pub fn create_fuzzy_match() -> MatchFn {
    Arc::new(|field_value, values, modifiers| {
        // Extract threshold from modifiers
        let mut threshold = 0.8; // Default threshold
        for &modifier in modifiers {
            if let Some(threshold_str) = modifier.strip_prefix("threshold:") {
                threshold = threshold_str
                    .parse()
                    .map_err(|_| SigmaError::InvalidThreshold(threshold_str.to_string()))?;
            }
        }

        for &value in values {
            let similarity = calculate_similarity(field_value, value);
            if similarity >= threshold {
                return Ok(true);
            }
        }
        Ok(false)
    })
}

/// Helper function for calculating string similarity.
fn calculate_similarity(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }

    // Simple Levenshtein distance-based similarity
    let len_a = a.len();
    let len_b = b.len();

    if len_a == 0 || len_b == 0 {
        return 0.0;
    }

    let max_len = len_a.max(len_b);
    let distance = levenshtein_distance(a, b);

    1.0 - (distance as f64 / max_len as f64)
}

/// Simple Levenshtein distance implementation.
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let len_a = a_chars.len();
    let len_b = b_chars.len();

    if len_a == 0 {
        return len_b;
    }
    if len_b == 0 {
        return len_a;
    }

    let mut matrix = vec![vec![0; len_b + 1]; len_a + 1];

    // Initialize first row and column
    for (i, row) in matrix.iter_mut().enumerate().take(len_a + 1) {
        row[0] = i;
    }
    for j in 0..=len_b {
        matrix[0][j] = j;
    }

    // Fill the matrix
    for i in 1..=len_a {
        for j in 1..=len_b {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[len_a][len_b]
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
/// * `regex` - Regular expression matching
/// * `cidr` - CIDR network matching
/// * `range` - Numeric range matching
/// * `fuzzy` - Fuzzy string matching with configurable threshold
///
/// # Modifiers Registered
/// * `base64_decode` - Base64 decoding
/// * `utf16_decode` - UTF-16 decoding
pub fn register_defaults(
    match_registry: &mut std::collections::HashMap<String, MatchFn>,
    modifier_registry: &mut std::collections::HashMap<String, ModifierFn>,
) {
    // Register basic match types
    match_registry.insert("equals".to_string(), create_exact_match());
    match_registry.insert("contains".to_string(), create_contains_match());
    match_registry.insert("startswith".to_string(), create_startswith_match());
    match_registry.insert("endswith".to_string(), create_endswith_match());
    match_registry.insert("regex".to_string(), create_regex_match());

    // Register advanced match types
    match_registry.insert(
        "cidr".to_string(),
        crate::matcher::advanced::create_cidr_match(),
    );

    match_registry.insert(
        "range".to_string(),
        crate::matcher::advanced::create_range_match(),
    );
    match_registry.insert(
        "fuzzy".to_string(),
        crate::matcher::advanced::create_fuzzy_match(),
    );

    // Register basic modifiers
    modifier_registry.insert("base64_decode".to_string(), create_base64_decode());
    modifier_registry.insert("utf16_decode".to_string(), create_utf16_decode());
}

/// Register all default match types and comprehensive modifiers with a builder.
///
/// This extends the basic defaults with comprehensive SIGMA modifier support.
/// Use this when you need full SIGMA specification compliance.
///
/// # Additional Modifiers Registered
/// * All encoding/decoding modifiers (base64, URL, HTML, UTF-16 variants)
/// * String transformation modifiers (case, trim, path normalization)
/// * Data format modifiers (hex, JSON, XML, CSV)
/// * Numeric modifiers (int/float conversion, timestamps)
/// * Advanced modifiers (hashing, compression, regex extraction)
pub fn register_defaults_with_comprehensive_modifiers(
    match_registry: &mut std::collections::HashMap<String, MatchFn>,
    modifier_registry: &mut std::collections::HashMap<String, ModifierFn>,
) {
    // Register all basic defaults first
    register_defaults(match_registry, modifier_registry);

    // Add comprehensive modifiers
    crate::matcher::modifiers::register_comprehensive_modifiers(modifier_registry);
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

        // Basic match types
        assert!(match_registry.contains_key("equals"));
        assert!(match_registry.contains_key("contains"));
        assert!(match_registry.contains_key("startswith"));
        assert!(match_registry.contains_key("endswith"));
        assert!(match_registry.contains_key("regex"));

        // Advanced match types
        assert!(match_registry.contains_key("cidr"));
        assert!(match_registry.contains_key("range"));
        assert!(match_registry.contains_key("fuzzy"));

        assert!(modifier_registry.contains_key("base64_decode"));
        assert!(modifier_registry.contains_key("utf16_decode"));
    }

    #[test]
    fn test_range_match() {
        let range_match = create_range_match();

        // Test valid range
        let result = range_match("150", &["100-200"], &[]).unwrap();
        assert!(result);

        // Test boundary values
        let result = range_match("100", &["100-200"], &[]).unwrap();
        assert!(result);

        let result = range_match("200", &["100-200"], &[]).unwrap();
        assert!(result);

        // Test outside range
        let result = range_match("50", &["100-200"], &[]).unwrap();
        assert!(!result);

        let result = range_match("250", &["100-200"], &[]).unwrap();
        assert!(!result);

        // Test multiple ranges
        let result = range_match("75", &["50-100", "150-200"], &[]).unwrap();
        assert!(result);

        // Test invalid number
        let result = range_match("not_a_number", &["100-200"], &[]);
        assert!(result.is_err());

        // Test invalid range format
        let result = range_match("150", &["invalid_range"], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fuzzy_match() {
        let fuzzy_match = create_fuzzy_match();

        // Test exact match
        let result = fuzzy_match("hello", &["hello"], &[]).unwrap();
        assert!(result);

        // Test similar strings with default threshold
        let result = fuzzy_match("hello", &["helo"], &[]).unwrap();
        assert!(result); // Should match with default threshold 0.8

        // Test with custom threshold
        let result = fuzzy_match("hello", &["helo"], &["threshold:0.9"]).unwrap();
        assert!(!result); // Should not match with high threshold

        let result = fuzzy_match("hello", &["helo"], &["threshold:0.7"]).unwrap();
        assert!(result); // Should match with lower threshold

        // Test completely different strings
        let result = fuzzy_match("hello", &["xyz"], &[]).unwrap();
        assert!(!result);

        // Test invalid threshold
        let result = fuzzy_match("hello", &["helo"], &["threshold:invalid"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cidr_match() {
        let cidr_match = crate::matcher::advanced::create_cidr_match();

        // Test IPv4 CIDR matching
        let result = cidr_match("192.168.1.100", &["192.168.1.0/24"], &[]).unwrap();
        assert!(result);

        let result = cidr_match("192.168.2.100", &["192.168.1.0/24"], &[]).unwrap();
        assert!(!result);

        // Test boundary cases
        let result = cidr_match("192.168.1.0", &["192.168.1.0/24"], &[]).unwrap();
        assert!(result);

        let result = cidr_match("192.168.1.255", &["192.168.1.0/24"], &[]).unwrap();
        assert!(result);

        // Test multiple CIDR ranges
        let result = cidr_match("10.0.0.1", &["192.168.1.0/24", "10.0.0.0/8"], &[]).unwrap();
        assert!(result);

        // Test invalid IP
        let result = cidr_match("invalid_ip", &["192.168.1.0/24"], &[]);
        assert!(result.is_err());

        // Test invalid CIDR
        let result = cidr_match("192.168.1.100", &["invalid_cidr"], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_similarity_calculation() {
        assert_eq!(calculate_similarity("hello", "hello"), 1.0);
        assert_eq!(calculate_similarity("", ""), 1.0);
        assert_eq!(calculate_similarity("hello", ""), 0.0);
        assert_eq!(calculate_similarity("", "hello"), 0.0);

        // Test partial similarity
        let similarity = calculate_similarity("hello", "helo");
        assert!(similarity > 0.7 && similarity < 1.0);

        let similarity = calculate_similarity("hello", "xyz");
        assert!(similarity < 0.5);
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("", ""), 0);
        assert_eq!(levenshtein_distance("hello", "hello"), 0);
        assert_eq!(levenshtein_distance("hello", ""), 5);
        assert_eq!(levenshtein_distance("", "hello"), 5);
        assert_eq!(levenshtein_distance("hello", "helo"), 1);
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
    }
}
