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
}

impl fmt::Display for SigmaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigmaError::CompilationError(msg) => write!(f, "Compilation error: {}", msg),
            SigmaError::ExecutionError(msg) => write!(f, "Execution error: {}", msg),
            SigmaError::InvalidBytecode(msg) => write!(f, "Invalid bytecode: {}", msg),
            SigmaError::InvalidPrimitiveId(id) => write!(f, "Invalid primitive ID: {}", id),
            SigmaError::StackUnderflow => write!(f, "Stack underflow during execution"),
            SigmaError::StackOverflow => write!(f, "Stack overflow during execution"),
            SigmaError::IoError(msg) => write!(f, "IO error: {}", msg),
            SigmaError::YamlError(msg) => write!(f, "YAML parsing error: {}", msg),
            SigmaError::UnsupportedMatchType(match_type) => {
                write!(f, "Unsupported match type: {}", match_type)
            }
            SigmaError::InvalidRegex(pattern) => write!(f, "Invalid regex pattern: {}", pattern),
            SigmaError::InvalidIpAddress(ip) => write!(f, "Invalid IP address: {}", ip),
            SigmaError::InvalidCidr(cidr) => write!(f, "Invalid CIDR notation: {}", cidr),
            SigmaError::InvalidNumber(num) => write!(f, "Invalid number: {}", num),
            SigmaError::InvalidRange(range) => write!(f, "Invalid range: {}", range),
            SigmaError::InvalidThreshold(threshold) => {
                write!(f, "Invalid threshold: {}", threshold)
            }
            SigmaError::ModifierError(msg) => write!(f, "Modifier error: {}", msg),
            SigmaError::FieldExtractionError(msg) => write!(f, "Field extraction error: {}", msg),
            SigmaError::ExecutionTimeout => write!(f, "Execution timeout exceeded"),
            SigmaError::TooManyOperations(count) => write!(f, "Too many operations: {}", count),
            SigmaError::TooManyRegexOperations(count) => {
                write!(f, "Too many regex operations: {}", count)
            }
            SigmaError::BatchSizeMismatch => write!(f, "Batch size mismatch"),
            SigmaError::InvalidPrimitiveIndex(idx) => write!(f, "Invalid primitive index: {}", idx),
            SigmaError::IncompatibleVersion(version) => {
                write!(f, "Incompatible version: {}", version)
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
        let debug_str = format!("{:?}", error);
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
}
