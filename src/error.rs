//! Error types for the SIGMA BVM crate.

use std::fmt;

pub type Result<T> = std::result::Result<T, SigmaError>;

#[derive(Debug, Clone, PartialEq)]
pub enum SigmaError {
    CompilationError(String),
    ExecutionError(String),
    InvalidBytecode(String),
    InvalidPrimitiveId(u32),
    StackUnderflow,
    StackOverflow,
    IoError(String),
    YamlError(String),
    // Matcher-related errors
    UnsupportedMatchType(String),
    InvalidRegex(String),
    InvalidIpAddress(String),
    InvalidCidr(String),
    InvalidNumber(String),
    InvalidRange(String),
    InvalidThreshold(String),
    ModifierError(String),
    FieldExtractionError(String),
    ExecutionTimeout,
    TooManyOperations(u64),
    TooManyRegexOperations(u64),
    BatchSizeMismatch,
    InvalidPrimitiveIndex(usize),
    IncompatibleVersion(u32),
    // Advanced matcher errors
    InvalidNumericValue(String),
    InvalidFieldPath(String),
    DangerousRegexPattern(String),
}

impl fmt::Display for SigmaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigmaError::CompilationError(msg) => write!(f, "Compilation error: {msg}"),
            SigmaError::ExecutionError(msg) => write!(f, "Execution error: {msg}"),
            SigmaError::InvalidBytecode(msg) => write!(f, "Invalid bytecode: {msg}"),
            SigmaError::InvalidPrimitiveId(id) => write!(f, "Invalid primitive ID: {id}"),
            SigmaError::StackUnderflow => write!(f, "Stack underflow during execution"),
            SigmaError::StackOverflow => write!(f, "Stack overflow during execution"),
            SigmaError::IoError(msg) => write!(f, "IO error: {msg}"),
            SigmaError::YamlError(msg) => write!(f, "YAML parsing error: {msg}"),
            SigmaError::UnsupportedMatchType(match_type) => {
                write!(f, "Unsupported match type: {match_type}")
            }
            SigmaError::InvalidRegex(pattern) => write!(f, "Invalid regex pattern: {pattern}"),
            SigmaError::InvalidIpAddress(ip) => write!(f, "Invalid IP address: {ip}"),
            SigmaError::InvalidCidr(cidr) => write!(f, "Invalid CIDR notation: {cidr}"),
            SigmaError::InvalidNumber(num) => write!(f, "Invalid number: {num}"),
            SigmaError::InvalidRange(range) => write!(f, "Invalid range: {range}"),
            SigmaError::InvalidThreshold(threshold) => {
                write!(f, "Invalid threshold: {threshold}")
            }
            SigmaError::ModifierError(msg) => write!(f, "Modifier error: {msg}"),
            SigmaError::FieldExtractionError(msg) => write!(f, "Field extraction error: {msg}"),
            SigmaError::ExecutionTimeout => write!(f, "Execution timeout exceeded"),
            SigmaError::TooManyOperations(count) => write!(f, "Too many operations: {count}"),
            SigmaError::TooManyRegexOperations(count) => {
                write!(f, "Too many regex operations: {count}")
            }
            SigmaError::BatchSizeMismatch => write!(f, "Batch size mismatch"),
            SigmaError::InvalidPrimitiveIndex(idx) => write!(f, "Invalid primitive index: {idx}"),
            SigmaError::IncompatibleVersion(version) => {
                write!(f, "Incompatible version: {version}")
            }
            SigmaError::InvalidNumericValue(value) => write!(f, "Invalid numeric value: {value}"),
            SigmaError::InvalidFieldPath(path) => write!(f, "Invalid field path: {path}"),
            SigmaError::DangerousRegexPattern(pattern) => {
                write!(f, "Dangerous regex pattern detected: {pattern}")
            }
        }
    }
}

impl std::error::Error for SigmaError {}

impl From<std::io::Error> for SigmaError {
    fn from(err: std::io::Error) -> Self {
        SigmaError::IoError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_compilation_error() {
        let error = SigmaError::CompilationError("test message".to_string());
        assert_eq!(error.to_string(), "Compilation error: test message");
        assert!(error.source().is_none());
    }

    #[test]
    fn test_execution_error() {
        let error = SigmaError::ExecutionError("execution failed".to_string());
        assert_eq!(error.to_string(), "Execution error: execution failed");
    }

    #[test]
    fn test_invalid_bytecode() {
        let error = SigmaError::InvalidBytecode("malformed bytecode".to_string());
        assert_eq!(error.to_string(), "Invalid bytecode: malformed bytecode");
    }

    #[test]
    fn test_invalid_primitive_id() {
        let error = SigmaError::InvalidPrimitiveId(42);
        assert_eq!(error.to_string(), "Invalid primitive ID: 42");
    }

    #[test]
    fn test_stack_underflow() {
        let error = SigmaError::StackUnderflow;
        assert_eq!(error.to_string(), "Stack underflow during execution");
    }

    #[test]
    fn test_stack_overflow() {
        let error = SigmaError::StackOverflow;
        assert_eq!(error.to_string(), "Stack overflow during execution");
    }

    #[test]
    fn test_io_error() {
        let error = SigmaError::IoError("file not found".to_string());
        assert_eq!(error.to_string(), "IO error: file not found");
    }

    #[test]
    fn test_yaml_error() {
        let error = SigmaError::YamlError("invalid yaml syntax".to_string());
        assert_eq!(error.to_string(), "YAML parsing error: invalid yaml syntax");
    }

    #[test]
    fn test_error_equality() {
        let error1 = SigmaError::CompilationError("test".to_string());
        let error2 = SigmaError::CompilationError("test".to_string());
        let error3 = SigmaError::CompilationError("different".to_string());

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    #[test]
    fn test_error_clone() {
        let error = SigmaError::InvalidPrimitiveId(123);
        let cloned = error.clone();
        assert_eq!(error, cloned);
    }

    #[test]
    fn test_error_debug() {
        let error = SigmaError::StackOverflow;
        let debug_str = format!("{error:?}");
        assert_eq!(debug_str, "StackOverflow");
    }

    #[test]
    fn test_from_io_error() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let sigma_error: SigmaError = io_error.into();

        match sigma_error {
            SigmaError::IoError(msg) => assert!(msg.contains("file not found")),
            _ => panic!("Expected IoError variant"),
        }
    }

    #[test]
    fn test_result_type_alias() {
        fn test_function() -> Result<i32> {
            Ok(42)
        }

        let result = test_function();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_result_type_alias_error() {
        fn test_function() -> Result<i32> {
            Err(SigmaError::CompilationError("test error".to_string()))
        }

        let result = test_function();
        assert!(result.is_err());
        match result.unwrap_err() {
            SigmaError::CompilationError(msg) => assert_eq!(msg, "test error"),
            _ => panic!("Expected CompilationError"),
        }
    }

    #[test]
    fn test_error_display_comprehensive() {
        let err = SigmaError::CompilationError("test compilation error".to_string());
        assert_eq!(
            format!("{err}"),
            "Compilation error: test compilation error"
        );

        let err = SigmaError::ExecutionError("test execution error".to_string());
        assert_eq!(format!("{err}"), "Execution error: test execution error");

        let err = SigmaError::InvalidBytecode("test invalid bytecode".to_string());
        assert_eq!(format!("{err}"), "Invalid bytecode: test invalid bytecode");

        let err = SigmaError::InvalidPrimitiveId(42);
        assert_eq!(format!("{err}"), "Invalid primitive ID: 42");

        let err = SigmaError::StackOverflow;
        assert_eq!(format!("{err}"), "Stack overflow during execution");

        let err = SigmaError::StackUnderflow;
        assert_eq!(format!("{err}"), "Stack underflow during execution");
    }

    #[test]
    fn test_error_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let sigma_err = SigmaError::from(io_err);
        assert!(sigma_err.source().is_none()); // IoError converts to string, no source

        let err = SigmaError::StackOverflow;
        assert!(err.source().is_none());

        let err = SigmaError::CompilationError("test".to_string());
        assert!(err.source().is_none());
    }

    #[test]
    fn test_error_from_conversions() {
        // Test From<std::io::Error>
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let sigma_err: SigmaError = io_err.into();
        assert!(matches!(sigma_err, SigmaError::IoError(_)));

        // Test manual conversion for serde_yaml::Error
        let yaml_str = "invalid: yaml: content: [";
        let yaml_err = serde_yaml::from_str::<serde_yaml::Value>(yaml_str).unwrap_err();
        let sigma_err = SigmaError::YamlError(yaml_err.to_string());
        assert!(matches!(sigma_err, SigmaError::YamlError(_)));
    }

    #[test]
    fn test_all_error_variants_display() {
        // Test all error variants for display formatting
        let errors = vec![
            SigmaError::UnsupportedMatchType("custom".to_string()),
            SigmaError::InvalidRegex("invalid[".to_string()),
            SigmaError::InvalidIpAddress("256.256.256.256".to_string()),
            SigmaError::InvalidCidr("192.168.1.0/33".to_string()),
            SigmaError::InvalidNumber("not_a_number".to_string()),
            SigmaError::InvalidRange("invalid_range".to_string()),
            SigmaError::InvalidThreshold("invalid_threshold".to_string()),
            SigmaError::ModifierError("modifier failed".to_string()),
            SigmaError::FieldExtractionError("field not found".to_string()),
            SigmaError::ExecutionTimeout,
            SigmaError::TooManyOperations(1000),
            SigmaError::TooManyRegexOperations(500),
            SigmaError::BatchSizeMismatch,
            SigmaError::InvalidPrimitiveIndex(99),
            SigmaError::IncompatibleVersion(2),
            SigmaError::InvalidNumericValue("NaN".to_string()),
            SigmaError::InvalidFieldPath("invalid.path".to_string()),
            SigmaError::DangerousRegexPattern("(a+)+".to_string()),
        ];

        for error in errors {
            let display_str = error.to_string();
            assert!(!display_str.is_empty());

            // Verify specific error messages
            match &error {
                SigmaError::UnsupportedMatchType(match_type) => {
                    assert!(display_str.contains("Unsupported match type"));
                    assert!(display_str.contains(match_type));
                }
                SigmaError::InvalidRegex(pattern) => {
                    assert!(display_str.contains("Invalid regex pattern"));
                    assert!(display_str.contains(pattern));
                }
                SigmaError::InvalidIpAddress(ip) => {
                    assert!(display_str.contains("Invalid IP address"));
                    assert!(display_str.contains(ip));
                }
                SigmaError::InvalidCidr(cidr) => {
                    assert!(display_str.contains("Invalid CIDR notation"));
                    assert!(display_str.contains(cidr));
                }
                SigmaError::InvalidNumber(num) => {
                    assert!(display_str.contains("Invalid number"));
                    assert!(display_str.contains(num));
                }
                SigmaError::InvalidRange(range) => {
                    assert!(display_str.contains("Invalid range"));
                    assert!(display_str.contains(range));
                }
                SigmaError::InvalidThreshold(threshold) => {
                    assert!(display_str.contains("Invalid threshold"));
                    assert!(display_str.contains(threshold));
                }
                SigmaError::ModifierError(msg) => {
                    assert!(display_str.contains("Modifier error"));
                    assert!(display_str.contains(msg));
                }
                SigmaError::FieldExtractionError(msg) => {
                    assert!(display_str.contains("Field extraction error"));
                    assert!(display_str.contains(msg));
                }
                SigmaError::ExecutionTimeout => {
                    assert!(display_str.contains("Execution timeout exceeded"));
                }
                SigmaError::TooManyOperations(count) => {
                    assert!(display_str.contains("Too many operations"));
                    assert!(display_str.contains(&count.to_string()));
                }
                SigmaError::TooManyRegexOperations(count) => {
                    assert!(display_str.contains("Too many regex operations"));
                    assert!(display_str.contains(&count.to_string()));
                }
                SigmaError::BatchSizeMismatch => {
                    assert!(display_str.contains("Batch size mismatch"));
                }
                SigmaError::InvalidPrimitiveIndex(idx) => {
                    assert!(display_str.contains("Invalid primitive index"));
                    assert!(display_str.contains(&idx.to_string()));
                }
                SigmaError::IncompatibleVersion(version) => {
                    assert!(display_str.contains("Incompatible version"));
                    assert!(display_str.contains(&version.to_string()));
                }
                SigmaError::InvalidNumericValue(value) => {
                    assert!(display_str.contains("Invalid numeric value"));
                    assert!(display_str.contains(value));
                }
                SigmaError::InvalidFieldPath(path) => {
                    assert!(display_str.contains("Invalid field path"));
                    assert!(display_str.contains(path));
                }
                SigmaError::DangerousRegexPattern(pattern) => {
                    assert!(display_str.contains("Dangerous regex pattern detected"));
                    assert!(display_str.contains(pattern));
                }
                _ => {} // Already tested above
            }
        }
    }

    #[test]
    fn test_error_equality_comprehensive() {
        // Test equality for all error variants
        assert_eq!(
            SigmaError::UnsupportedMatchType("test".to_string()),
            SigmaError::UnsupportedMatchType("test".to_string())
        );
        assert_ne!(
            SigmaError::UnsupportedMatchType("test1".to_string()),
            SigmaError::UnsupportedMatchType("test2".to_string())
        );

        assert_eq!(SigmaError::ExecutionTimeout, SigmaError::ExecutionTimeout);
        assert_eq!(SigmaError::BatchSizeMismatch, SigmaError::BatchSizeMismatch);
        assert_eq!(SigmaError::StackOverflow, SigmaError::StackOverflow);
        assert_eq!(SigmaError::StackUnderflow, SigmaError::StackUnderflow);

        assert_eq!(
            SigmaError::TooManyOperations(100),
            SigmaError::TooManyOperations(100)
        );
        assert_ne!(
            SigmaError::TooManyOperations(100),
            SigmaError::TooManyOperations(200)
        );

        assert_eq!(
            SigmaError::InvalidPrimitiveId(42),
            SigmaError::InvalidPrimitiveId(42)
        );
        assert_ne!(
            SigmaError::InvalidPrimitiveId(42),
            SigmaError::InvalidPrimitiveId(43)
        );

        // Test inequality between different variants
        assert_ne!(
            SigmaError::CompilationError("test".to_string()),
            SigmaError::ExecutionError("test".to_string())
        );
        assert_ne!(SigmaError::StackOverflow, SigmaError::StackUnderflow);
        assert_ne!(SigmaError::ExecutionTimeout, SigmaError::BatchSizeMismatch);
    }

    #[test]
    fn test_error_clone_comprehensive() {
        let errors = vec![
            SigmaError::CompilationError("test".to_string()),
            SigmaError::ExecutionError("test".to_string()),
            SigmaError::InvalidBytecode("test".to_string()),
            SigmaError::InvalidPrimitiveId(42),
            SigmaError::StackUnderflow,
            SigmaError::StackOverflow,
            SigmaError::IoError("test".to_string()),
            SigmaError::YamlError("test".to_string()),
            SigmaError::UnsupportedMatchType("test".to_string()),
            SigmaError::InvalidRegex("test".to_string()),
            SigmaError::InvalidIpAddress("test".to_string()),
            SigmaError::InvalidCidr("test".to_string()),
            SigmaError::InvalidNumber("test".to_string()),
            SigmaError::InvalidRange("test".to_string()),
            SigmaError::InvalidThreshold("test".to_string()),
            SigmaError::ModifierError("test".to_string()),
            SigmaError::FieldExtractionError("test".to_string()),
            SigmaError::ExecutionTimeout,
            SigmaError::TooManyOperations(100),
            SigmaError::TooManyRegexOperations(50),
            SigmaError::BatchSizeMismatch,
            SigmaError::InvalidPrimitiveIndex(10),
            SigmaError::IncompatibleVersion(1),
            SigmaError::InvalidNumericValue("test".to_string()),
            SigmaError::InvalidFieldPath("test".to_string()),
            SigmaError::DangerousRegexPattern("test".to_string()),
        ];

        for error in errors {
            let cloned = error.clone();
            assert_eq!(error, cloned);
        }
    }

    #[test]
    fn test_error_debug_comprehensive() {
        let errors = vec![
            (
                SigmaError::CompilationError("test".to_string()),
                "CompilationError",
            ),
            (
                SigmaError::ExecutionError("test".to_string()),
                "ExecutionError",
            ),
            (
                SigmaError::InvalidBytecode("test".to_string()),
                "InvalidBytecode",
            ),
            (SigmaError::InvalidPrimitiveId(42), "InvalidPrimitiveId"),
            (SigmaError::StackUnderflow, "StackUnderflow"),
            (SigmaError::StackOverflow, "StackOverflow"),
            (SigmaError::IoError("test".to_string()), "IoError"),
            (SigmaError::YamlError("test".to_string()), "YamlError"),
            (
                SigmaError::UnsupportedMatchType("test".to_string()),
                "UnsupportedMatchType",
            ),
            (SigmaError::InvalidRegex("test".to_string()), "InvalidRegex"),
            (
                SigmaError::InvalidIpAddress("test".to_string()),
                "InvalidIpAddress",
            ),
            (SigmaError::InvalidCidr("test".to_string()), "InvalidCidr"),
            (
                SigmaError::InvalidNumber("test".to_string()),
                "InvalidNumber",
            ),
            (SigmaError::InvalidRange("test".to_string()), "InvalidRange"),
            (
                SigmaError::InvalidThreshold("test".to_string()),
                "InvalidThreshold",
            ),
            (
                SigmaError::ModifierError("test".to_string()),
                "ModifierError",
            ),
            (
                SigmaError::FieldExtractionError("test".to_string()),
                "FieldExtractionError",
            ),
            (SigmaError::ExecutionTimeout, "ExecutionTimeout"),
            (SigmaError::TooManyOperations(100), "TooManyOperations"),
            (
                SigmaError::TooManyRegexOperations(50),
                "TooManyRegexOperations",
            ),
            (SigmaError::BatchSizeMismatch, "BatchSizeMismatch"),
            (
                SigmaError::InvalidPrimitiveIndex(10),
                "InvalidPrimitiveIndex",
            ),
            (SigmaError::IncompatibleVersion(1), "IncompatibleVersion"),
            (
                SigmaError::InvalidNumericValue("test".to_string()),
                "InvalidNumericValue",
            ),
            (
                SigmaError::InvalidFieldPath("test".to_string()),
                "InvalidFieldPath",
            ),
            (
                SigmaError::DangerousRegexPattern("test".to_string()),
                "DangerousRegexPattern",
            ),
        ];

        for (error, expected_variant) in errors {
            let debug_str = format!("{error:?}");
            assert!(debug_str.contains(expected_variant));
        }
    }
}
