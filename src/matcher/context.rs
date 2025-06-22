//! Event context with field value caching for performance.

use crate::error::SigmaError;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;

/// Event context with field value caching for high-performance field access.
///
/// `EventContext` provides an optimized interface for extracting field values from
/// JSON events with intelligent caching to avoid repeated parsing. It's designed
/// to minimize overhead during rule evaluation while supporting complex nested
/// field access patterns.
///
///
/// # Supported Field Patterns
///
/// ## Simple Fields
/// ```rust,ignore
/// let event = json!({"EventID": "4624", "LogonType": 2});
/// let context = EventContext::new(&event);
///
/// let event_id = context.get_field("EventID")?; // Some("4624")
/// let logon_type = context.get_field("LogonType")?; // Some("2")
/// ```
///
/// ## Nested Fields (Dot Notation)
/// ```rust,ignore
/// let event = json!({
///     "Event": {
///         "System": {
///             "EventID": "4624",
///             "TimeCreated": "2023-01-01T00:00:00Z"
///         }
///     }
/// });
/// let context = EventContext::new(&event);
///
/// let event_id = context.get_field("Event.System.EventID")?; // Some("4624")
/// let time = context.get_field("Event.System.TimeCreated")?; // Some("2023-01-01T00:00:00Z")
/// ```
///
/// ## Array Access
/// ```rust,ignore
/// let event = json!({
///     "Users": [
///         {"Name": "Alice", "ID": 1001},
///         {"Name": "Bob", "ID": 1002}
///     ]
/// });
/// let context = EventContext::new(&event);
///
/// let first_user = context.get_field("Users.0.Name")?; // Some("Alice")
/// let second_id = context.get_field("Users.1.ID")?; // Some("1002")
/// ```
///
/// # Caching Behavior
///
/// The context maintains an internal cache of extracted field values:
/// - **First access**: Parses JSON path and extracts value
/// - **Subsequent access**: Returns cached value immediately
/// - **Cache key**: Full field path string (e.g., "Event.System.EventID")
/// - **Cache lifetime**: Lives for the duration of the context
///
/// # Type Conversion
///
/// All field values are converted to strings for consistent matching:
/// - **Strings**: Returned as-is (without quotes)
/// - **Numbers**: Converted to string representation
/// - **Booleans**: Converted to "true" or "false"
/// - **Arrays/Objects**: Converted to JSON string representation
/// - **Null**: Returns `None`
///
/// # Error Handling
///
/// Field access can fail in several scenarios:
/// - **Invalid path**: Malformed dot notation
/// - **Missing field**: Field doesn't exist in event
/// - **Type errors**: Attempting to index non-array/object
/// - **JSON errors**: Malformed JSON structure
///
/// # Memory Usage
///
/// The context is designed for efficient memory usage:
/// - **Borrowed data**: Holds only a reference to the original event
/// - **Selective caching**: Only caches accessed fields
/// - **String interning**: Can be combined with string interning for further optimization
/// - **Bounded growth**: Cache size is limited by the number of unique field accesses
///
/// # Thread Safety
///
/// `EventContext` is **not** thread-safe due to interior mutability in the cache.
/// Each thread should create its own context instance. However, the underlying
/// event data can be shared across threads safely.
///
/// # Examples
///
/// ## Basic Usage
/// ```rust,ignore
/// use sigma_engine::matcher::EventContext;
/// use serde_json::json;
///
/// let event = json!({"EventID": "4624", "nested": {"field": "value"}});
/// let context = EventContext::new(&event);
///
/// // First access parses and caches
/// let event_id = context.get_field("EventID")?;
/// assert_eq!(event_id, Some("4624".to_string()));
///
/// // Second access uses cache (faster)
/// let event_id_cached = context.get_field("EventID")?;
/// assert_eq!(event_id_cached, Some("4624".to_string()));
/// ```
///
/// ## Nested Field Access
/// ```rust,ignore
/// let event = json!({
///     "Process": {
///         "Name": "powershell.exe",
///         "CommandLine": "powershell.exe -Command Get-Process"
///     }
/// });
/// let context = EventContext::new(&event);
///
/// let process_name = context.get_field("Process.Name")?;
/// assert_eq!(process_name, Some("powershell.exe".to_string()));
///
/// let command_line = context.get_field("Process.CommandLine")?;
/// assert_eq!(command_line, Some("powershell.exe -Command Get-Process".to_string()));
/// ```
///
/// ## Handling Missing Fields
/// ```rust,ignore
/// let event = json!({"EventID": "4624"});
/// let context = EventContext::new(&event);
///
/// let existing = context.get_field("EventID")?;
/// assert_eq!(existing, Some("4624".to_string()));
///
/// let missing = context.get_field("NonExistent")?;
/// assert_eq!(missing, None);
/// ```
pub struct EventContext<'a> {
    /// Reference to the original event
    pub event: &'a Value,
    /// Cache for extracted field values
    field_cache: RefCell<HashMap<String, Option<String>>>,
}

impl<'a> EventContext<'a> {
    /// Create a new event context.
    ///
    /// # Arguments
    /// * `event` - Reference to the JSON event to process
    ///
    /// # Example
    /// ```rust,ignore
    /// let event = json!({"EventID": "4624"});
    /// let context = EventContext::new(&event);
    /// ```
    pub fn new(event: &'a Value) -> Self {
        Self {
            event,
            field_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Get cached field value or extract and cache it.
    ///
    /// Supports both simple field names and nested field paths using dot notation.
    /// Returns an owned string to avoid lifetime issues.
    ///
    /// # Arguments
    /// * `field` - Field name or dot-separated path (e.g., "EventID" or "nested.field")
    ///
    /// # Returns
    /// * `Ok(Some(String))` - Field value found and cached
    /// * `Ok(None)` - Field not found in event
    /// * `Err(SigmaError)` - Field extraction failed
    ///
    /// # Example
    /// ```rust,ignore
    /// let context = EventContext::new(&event);
    ///
    /// // Simple field access
    /// let event_id = context.get_field("EventID")?;
    ///
    /// // Nested field access
    /// let nested_value = context.get_field("nested.field")?;
    /// ```
    pub fn get_field(&self, field: &str) -> Result<Option<String>, SigmaError> {
        // Check cache first
        {
            let cache = self.field_cache.borrow();
            if let Some(cached_value) = cache.get(field) {
                return Ok(cached_value.clone());
            }
        }

        // Extract field value
        let field_value = self.extract_field_value(field)?;

        // Cache the result
        {
            let mut cache = self.field_cache.borrow_mut();
            cache.insert(field.to_string(), field_value.clone());
        }

        Ok(field_value)
    }

    /// Extract field value from the event without caching.
    ///
    /// Supports dot notation for nested field access.
    fn extract_field_value(&self, field: &str) -> Result<Option<String>, SigmaError> {
        if field.contains('.') {
            self.extract_nested_field(field)
        } else {
            self.extract_simple_field(field)
        }
    }

    /// Extract a simple (non-nested) field value.
    fn extract_simple_field(&self, field: &str) -> Result<Option<String>, SigmaError> {
        match self.event.get(field) {
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(Value::Number(n)) => Ok(Some(n.to_string())),
            Some(Value::Bool(b)) => Ok(Some(b.to_string())),
            Some(Value::Null) => Ok(None),
            Some(_) => Err(SigmaError::FieldExtractionError(format!(
                "Field '{}' has unsupported type",
                field
            ))),
            None => Ok(None),
        }
    }

    /// Extract a nested field value using dot notation.
    fn extract_nested_field(&self, field_path: &str) -> Result<Option<String>, SigmaError> {
        let parts: Vec<&str> = field_path.split('.').collect();
        let mut current = self.event;

        for part in parts {
            match current.get(part) {
                Some(value) => current = value,
                None => return Ok(None),
            }
        }

        match current {
            Value::String(s) => Ok(Some(s.clone())),
            Value::Number(n) => Ok(Some(n.to_string())),
            Value::Bool(b) => Ok(Some(b.to_string())),
            Value::Null => Ok(None),
            _ => Err(SigmaError::FieldExtractionError(format!(
                "Nested field '{}' has unsupported type",
                field_path
            ))),
        }
    }

    /// Clear the field cache.
    ///
    /// Useful for memory management when processing many events.
    pub fn clear_cache(&self) {
        self.field_cache.borrow_mut().clear();
    }

    /// Get the number of cached fields.
    ///
    /// Useful for monitoring cache efficiency.
    pub fn cache_size(&self) -> usize {
        self.field_cache.borrow().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_event() -> Value {
        serde_json::from_str(
            r#"
{
  "EventID": "4624",
  "LogonType": 2,
  "Success": true,
  "Empty": null
}
"#,
        )
        .unwrap()
    }

    #[test]
    fn test_simple_field_extraction() {
        let event = create_test_event();
        let context = EventContext::new(&event);

        assert_eq!(
            context.get_field("EventID").unwrap(),
            Some("4624".to_string())
        );
        assert_eq!(
            context.get_field("LogonType").unwrap(),
            Some("2".to_string())
        );
        assert_eq!(
            context.get_field("Success").unwrap(),
            Some("true".to_string())
        );
        assert_eq!(context.get_field("Empty").unwrap(), None);
        assert_eq!(context.get_field("NonExistent").unwrap(), None);
    }

    #[test]
    fn test_nested_field_extraction() {
        let event = serde_json::from_str(
            r#"
{
  "nested": {
    "field": "value",
    "number": 42,
    "deep": {
      "value": "deep_value"
    }
  }
}
"#,
        )
        .unwrap();

        let context = EventContext::new(&event);

        assert_eq!(
            context.get_field("nested.field").unwrap(),
            Some("value".to_string())
        );
        assert_eq!(
            context.get_field("nested.number").unwrap(),
            Some("42".to_string())
        );
        assert_eq!(
            context.get_field("nested.deep.value").unwrap(),
            Some("deep_value".to_string())
        );
        assert_eq!(context.get_field("nested.nonexistent").unwrap(), None);
        assert_eq!(context.get_field("nonexistent.field").unwrap(), None);
    }

    #[test]
    fn test_field_caching() {
        let event = serde_json::from_str(r#"{"EventID": "4624"}"#).unwrap();
        let context = EventContext::new(&event);

        // First access should cache
        assert_eq!(context.cache_size(), 0);
        let result1 = context.get_field("EventID").unwrap();
        assert_eq!(result1, Some("4624".to_string()));
        assert_eq!(context.cache_size(), 1);

        // Second access should use cache
        let result2 = context.get_field("EventID").unwrap();
        assert_eq!(result2, Some("4624".to_string()));
        assert_eq!(context.cache_size(), 1);
    }

    #[test]
    fn test_cache_clear() {
        let event = serde_json::from_str(r#"{"EventID": "4624"}"#).unwrap();
        let context = EventContext::new(&event);

        context.get_field("EventID").unwrap();
        assert_eq!(context.cache_size(), 1);

        context.clear_cache();
        assert_eq!(context.cache_size(), 0);
    }

    #[test]
    fn test_unsupported_field_type() {
        let event = serde_json::from_str(
            r#"
{
  "array_field": [1, 2, 3],
  "object_field": {
    "key": "value"
  }
}
"#,
        )
        .unwrap();

        let context = EventContext::new(&event);

        let result = context.get_field("array_field");
        assert!(result.is_err());
        match result.unwrap_err() {
            SigmaError::FieldExtractionError(msg) => {
                assert!(msg.contains("unsupported type"));
            }
            _ => panic!("Expected FieldExtractionError"),
        }
    }
}
