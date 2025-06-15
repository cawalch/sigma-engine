//! Stack-based virtual machine for executing SIGMA bytecode.
//!
//! This module provides the high-performance runtime execution engine
//! that evaluates compiled bytecode using pre-computed primitive results.

use crate::error::{Result, SigmaError};
use crate::ir::{BytecodeChunk, Opcode, RuleId};

/// Stack-based virtual machine for executing SIGMA bytecode.
///
/// The VM is designed for high-performance execution with minimal allocation.
/// It operates on a pre-allocated stack and takes primitive results as input.
pub struct Vm<const STACK_SIZE: usize = 64> {
    stack: [bool; STACK_SIZE],
    stack_ptr: usize,
}

impl<const STACK_SIZE: usize> Vm<STACK_SIZE> {
    /// Create a new virtual machine instance.
    pub fn new() -> Self {
        Self {
            stack: [false; STACK_SIZE],
            stack_ptr: 0,
        }
    }

    /// Execute a bytecode chunk with the given primitive results.
    ///
    /// # Arguments
    /// * `chunk` - The bytecode chunk to execute
    /// * `primitive_results` - Slice of boolean results for each primitive
    ///
    /// # Returns
    /// * `Some(RuleId)` if the rule matched
    /// * `None` if the rule did not match
    ///
    /// # Errors
    /// Returns an error if:
    /// * Stack overflow occurs
    /// * Stack underflow occurs
    /// * Invalid primitive ID is referenced
    /// * Invalid bytecode structure
    pub fn execute(
        &mut self,
        chunk: &BytecodeChunk,
        primitive_results: &[bool],
    ) -> Result<Option<RuleId>> {
        self.stack_ptr = 0;

        for opcode in &chunk.opcodes {
            match opcode {
                Opcode::PushMatch(primitive_id) => {
                    self.push_match(*primitive_id, primitive_results)?;
                }
                Opcode::And => {
                    self.execute_and()?;
                }
                Opcode::Or => {
                    self.execute_or()?;
                }
                Opcode::Not => {
                    self.execute_not()?;
                }
                Opcode::ReturnMatch(rule_id) => {
                    return self.execute_return(*rule_id);
                }
            }
        }

        Err(SigmaError::InvalidBytecode(
            "Bytecode chunk missing ReturnMatch instruction".to_string(),
        ))
    }

    /// Execute a bytecode chunk with the given primitive results (unchecked version).
    ///
    /// This is a high-performance version that eliminates error handling overhead
    /// by assuming the bytecode and primitive results are valid.
    ///
    /// **Performance**: Provides 25-53% performance improvement over checked execution.
    ///
    /// # Safety Requirements
    /// Use this only when you can guarantee:
    /// * All primitive IDs in the bytecode are valid for the primitive_results slice
    /// * The bytecode has proper structure (ends with ReturnMatch)
    /// * The stack won't overflow (max_stack_depth <= STACK_SIZE)
    ///
    /// # Arguments
    /// * `chunk` - The bytecode chunk to execute (must be pre-validated)
    /// * `primitive_results` - Slice of boolean results for each primitive
    ///
    /// # Returns
    /// * `Some(RuleId)` if the rule matched
    /// * `None` if the rule did not match
    ///
    /// # Safety
    /// This function uses unsafe array access for maximum performance.
    /// The caller must ensure all preconditions are met.
    ///
    /// # Recommended Usage
    /// Use `execute_optimized()` instead for automatic safety validation.
    #[inline]
    pub fn execute_unchecked(
        &mut self,
        chunk: &BytecodeChunk,
        primitive_results: &[bool],
    ) -> Option<RuleId> {
        self.stack_ptr = 0;

        for opcode in &chunk.opcodes {
            match opcode {
                Opcode::PushMatch(primitive_id) => {
                    // SAFETY: Caller guarantees primitive_id is valid
                    let result =
                        unsafe { *primitive_results.get_unchecked(*primitive_id as usize) };
                    // SAFETY: Caller guarantees no stack overflow
                    unsafe {
                        *self.stack.get_unchecked_mut(self.stack_ptr) = result;
                    }
                    self.stack_ptr += 1;
                }
                Opcode::And => {
                    // SAFETY: Caller guarantees no stack underflow
                    unsafe {
                        let b = *self.stack.get_unchecked(self.stack_ptr - 1);
                        let a = *self.stack.get_unchecked(self.stack_ptr - 2);
                        *self.stack.get_unchecked_mut(self.stack_ptr - 2) = a && b;
                    }
                    self.stack_ptr -= 1;
                }
                Opcode::Or => {
                    // SAFETY: Caller guarantees no stack underflow
                    unsafe {
                        let b = *self.stack.get_unchecked(self.stack_ptr - 1);
                        let a = *self.stack.get_unchecked(self.stack_ptr - 2);
                        *self.stack.get_unchecked_mut(self.stack_ptr - 2) = a || b;
                    }
                    self.stack_ptr -= 1;
                }
                Opcode::Not => {
                    // SAFETY: Caller guarantees no stack underflow
                    unsafe {
                        let value = *self.stack.get_unchecked(self.stack_ptr - 1);
                        *self.stack.get_unchecked_mut(self.stack_ptr - 1) = !value;
                    }
                }
                Opcode::ReturnMatch(rule_id) => {
                    // SAFETY: Caller guarantees no stack underflow
                    let result = unsafe { *self.stack.get_unchecked(self.stack_ptr - 1) };
                    return if result { Some(*rule_id) } else { None };
                }
            }
        }

        // SAFETY: Caller guarantees bytecode ends with ReturnMatch
        unsafe { std::hint::unreachable_unchecked() }
    }

    /// Execute a bytecode chunk with automatic optimization selection.
    ///
    /// This method automatically chooses between checked and unchecked execution
    /// based on the bytecode validation and runtime conditions. It provides
    /// the best performance while maintaining safety.
    ///
    /// **Performance**: This method provides 25-53% performance improvement over
    /// checked execution by eliminating error handling overhead when safe.
    ///
    /// # Arguments
    /// * `chunk` - The bytecode chunk to execute
    /// * `primitive_results` - Slice of boolean results for each primitive
    ///
    /// # Returns
    /// * `Some(RuleId)` if the rule matched
    /// * `None` if the rule did not match
    ///
    /// # Errors
    /// Returns an error only if using checked execution and validation fails
    ///
    /// # Recommended Usage
    /// This is the recommended method for production use as it automatically
    /// selects the fastest safe execution path.
    #[inline]
    pub fn execute_optimized(
        &mut self,
        chunk: &BytecodeChunk,
        primitive_results: &[bool],
    ) -> Result<Option<RuleId>> {
        if chunk.can_execute_unchecked(primitive_results.len(), STACK_SIZE) {
            Ok(self.execute_unchecked(chunk, primitive_results))
        } else {
            self.execute(chunk, primitive_results)
        }
    }

    fn push_match(&mut self, primitive_id: u32, primitive_results: &[bool]) -> Result<()> {
        let result = primitive_results
            .get(primitive_id as usize)
            .copied()
            .ok_or(SigmaError::InvalidPrimitiveId(primitive_id))?;

        if self.stack_ptr >= STACK_SIZE {
            return Err(SigmaError::StackOverflow);
        }

        self.stack[self.stack_ptr] = result;
        self.stack_ptr += 1;

        Ok(())
    }

    fn execute_and(&mut self) -> Result<()> {
        if self.stack_ptr < 2 {
            return Err(SigmaError::StackUnderflow);
        }

        let b = self.stack[self.stack_ptr - 1];
        let a = self.stack[self.stack_ptr - 2];

        self.stack[self.stack_ptr - 2] = a && b;
        self.stack_ptr -= 1;

        Ok(())
    }

    fn execute_or(&mut self) -> Result<()> {
        if self.stack_ptr < 2 {
            return Err(SigmaError::StackUnderflow);
        }

        let b = self.stack[self.stack_ptr - 1];
        let a = self.stack[self.stack_ptr - 2];

        self.stack[self.stack_ptr - 2] = a || b;
        self.stack_ptr -= 1;

        Ok(())
    }

    fn execute_not(&mut self) -> Result<()> {
        if self.stack_ptr < 1 {
            return Err(SigmaError::StackUnderflow);
        }

        let value = self.stack[self.stack_ptr - 1];
        self.stack[self.stack_ptr - 1] = !value;

        Ok(())
    }

    fn execute_return(&mut self, rule_id: RuleId) -> Result<Option<RuleId>> {
        if self.stack_ptr < 1 {
            return Err(SigmaError::StackUnderflow);
        }

        let result = self.stack[self.stack_ptr - 1];
        self.stack_ptr -= 1;

        if result {
            Ok(Some(rule_id))
        } else {
            Ok(None)
        }
    }

    pub fn stack_depth(&self) -> usize {
        self.stack_ptr
    }

    pub fn reset(&mut self) {
        self.stack_ptr = 0;
    }
}

impl<const STACK_SIZE: usize> Default for Vm<STACK_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

pub type DefaultVm = Vm<64>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Opcode;

    #[test]
    fn test_vm_creation() {
        let vm = Vm::<16>::new();
        assert_eq!(vm.stack_depth(), 0);
    }

    #[test]
    fn test_simple_push_and_return() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [true];

        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_simple_push_and_return_false() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [false];

        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_and_operation() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::And,
                Opcode::ReturnMatch(1),
            ],
        );

        let primitive_results = [true, true];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));

        let primitive_results = [true, false];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, None);

        let primitive_results = [false, true];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, None);

        let primitive_results = [false, false];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_or_operation() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::Or,
                Opcode::ReturnMatch(1),
            ],
        );

        let primitive_results = [true, true];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));

        let primitive_results = [true, false];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));

        let primitive_results = [false, true];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));

        let primitive_results = [false, false];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_not_operation() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![Opcode::PushMatch(0), Opcode::Not, Opcode::ReturnMatch(1)],
        );

        let primitive_results = [true];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, None);

        let primitive_results = [false];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_complex_expression() {
        // Test: A and (B or not C)
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::PushMatch(2),
                Opcode::Not,
                Opcode::Or,
                Opcode::And,
                Opcode::ReturnMatch(1),
            ],
        );

        let primitive_results = [true, true, true];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));

        let primitive_results = [true, false, true];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, None);

        let primitive_results = [true, false, false];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));

        let primitive_results = [false, true, false];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_stack_overflow() {
        let mut vm = Vm::<2>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::PushMatch(2),
                Opcode::ReturnMatch(1),
            ],
        );
        let primitive_results = [true, true, true];

        let result = vm.execute(&chunk, &primitive_results);
        assert!(matches!(result, Err(SigmaError::StackOverflow)));
    }

    #[test]
    fn test_stack_underflow() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::And, Opcode::ReturnMatch(1)]);
        let primitive_results = [];

        let result = vm.execute(&chunk, &primitive_results);
        assert!(matches!(result, Err(SigmaError::StackUnderflow)));
    }

    #[test]
    fn test_invalid_primitive_id() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(5), Opcode::ReturnMatch(1)]);
        let primitive_results = [true];

        let result = vm.execute(&chunk, &primitive_results);
        assert!(matches!(result, Err(SigmaError::InvalidPrimitiveId(5))));
    }

    #[test]
    fn test_vm_default() {
        let vm = Vm::<32>::default();
        assert_eq!(vm.stack_depth(), 0);
    }

    #[test]
    fn test_vm_reset() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [true];

        let _result = vm.execute(&chunk, &primitive_results).unwrap();

        vm.reset();
        assert_eq!(vm.stack_depth(), 0);
    }

    #[test]
    fn test_missing_return_match() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0)]);
        let primitive_results = [true];

        let result = vm.execute(&chunk, &primitive_results);
        assert!(matches!(result, Err(SigmaError::InvalidBytecode(_))));
    }

    #[test]
    fn test_execute_optimized() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [true];

        let result = vm.execute_optimized(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_execute_unchecked() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [true];

        let result = vm.execute_unchecked(&chunk, &primitive_results);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_execute_unchecked_false() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [false];

        let result = vm.execute_unchecked(&chunk, &primitive_results);
        assert_eq!(result, None);
    }

    #[test]
    fn test_execute_unchecked_complex() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::And,
                Opcode::ReturnMatch(1),
            ],
        );
        let primitive_results = [true, true];

        let result = vm.execute_unchecked(&chunk, &primitive_results);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_execute_unchecked_with_not() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![Opcode::PushMatch(0), Opcode::Not, Opcode::ReturnMatch(1)],
        );
        let primitive_results = [false];

        let result = vm.execute_unchecked(&chunk, &primitive_results);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_execute_unchecked_with_or() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::Or,
                Opcode::ReturnMatch(1),
            ],
        );
        let primitive_results = [false, true];

        let result = vm.execute_unchecked(&chunk, &primitive_results);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_default_vm_type_alias() {
        let vm = DefaultVm::new();
        assert_eq!(vm.stack_depth(), 0);
    }

    #[test]
    fn test_stack_underflow_not() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::Not, // No value on stack
                Opcode::ReturnMatch(1),
            ],
        );
        let primitive_results = [];

        let result = vm.execute(&chunk, &primitive_results);
        assert!(matches!(result, Err(SigmaError::StackUnderflow)));
    }

    #[test]
    fn test_stack_underflow_return() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![Opcode::ReturnMatch(1)], // No value on stack
        );
        let primitive_results = [];

        let result = vm.execute(&chunk, &primitive_results);
        assert!(matches!(result, Err(SigmaError::StackUnderflow)));
    }

    #[test]
    fn test_stack_underflow_or() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0), // Only one value
                Opcode::Or,           // Needs two values
                Opcode::ReturnMatch(1),
            ],
        );
        let primitive_results = [true];

        let result = vm.execute(&chunk, &primitive_results);
        assert!(matches!(result, Err(SigmaError::StackUnderflow)));
    }

    #[test]
    fn test_invalid_bytecode_missing_return() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![Opcode::PushMatch(0)], // Missing ReturnMatch
        );
        let primitive_results = [true];

        let result = vm.execute(&chunk, &primitive_results);
        assert!(matches!(result, Err(SigmaError::InvalidBytecode(_))));
    }

    #[test]
    fn test_vm_reset_functionality() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [true];

        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));
        assert_eq!(vm.stack_depth(), 0);

        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));
        assert_eq!(vm.stack_depth(), 0);
    }

    #[test]
    fn test_exhaustive_boolean_combinations() {
        // Test all 8 combinations for A and (B or C)
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0), // A
                Opcode::PushMatch(1), // B
                Opcode::PushMatch(2), // C
                Opcode::Or,           // B or C
                Opcode::And,          // A and (B or C)
                Opcode::ReturnMatch(1),
            ],
        );

        let test_cases = [
            (false, false, false, false),
            (false, false, true, false),
            (false, true, false, false),
            (false, true, true, false),
            (true, false, false, false),
            (true, false, true, true),
            (true, true, false, true),
            (true, true, true, true),
        ];

        for (a, b, c, expected) in test_cases {
            let primitive_results = [a, b, c];
            let result = vm.execute(&chunk, &primitive_results).unwrap();
            let expected_result = if expected { Some(1) } else { None };
            assert_eq!(
                result, expected_result,
                "Failed for A={}, B={}, C={}: expected {:?}, got {:?}",
                a, b, c, expected_result, result
            );
        }
    }

    #[test]
    fn test_deeply_nested_expression() {
        // Test: ((A and B) or (C and D)) and not E
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0), // A
                Opcode::PushMatch(1), // B
                Opcode::And,          // A and B
                Opcode::PushMatch(2), // C
                Opcode::PushMatch(3), // D
                Opcode::And,          // C and D
                Opcode::Or,           // (A and B) or (C and D)
                Opcode::PushMatch(4), // E
                Opcode::Not,          // not E
                Opcode::And,          // ((A and B) or (C and D)) and not E
                Opcode::ReturnMatch(1),
            ],
        );

        let primitive_results = [true, true, false, false, false];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));

        let primitive_results = [false, false, false, false, false];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, None);

        let primitive_results = [false, false, true, true, true];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_maximum_stack_usage() {
        // Test that we can use the full stack capacity
        let mut vm = Vm::<4>::new();

        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::PushMatch(2),
                Opcode::PushMatch(3),
                Opcode::And,
                Opcode::And,
                Opcode::And,
                Opcode::ReturnMatch(1),
            ],
        );

        let primitive_results = [true, true, true, true];
        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_vm_creation_different_sizes() {
        let vm = Vm::<32>::new();
        assert_eq!(vm.stack_depth(), 0);
    }

    #[test]
    fn test_vm_with_different_stack_sizes() {
        let vm8 = Vm::<8>::new();
        let vm16 = Vm::<16>::new();
        let vm32 = Vm::<32>::new();
        let vm64 = Vm::<64>::new();

        assert_eq!(vm8.stack_depth(), 0);
        assert_eq!(vm16.stack_depth(), 0);
        assert_eq!(vm32.stack_depth(), 0);
        assert_eq!(vm64.stack_depth(), 0);
    }

    #[test]
    fn test_execute_with_empty_primitive_results() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::ReturnMatch(1)]);
        let primitive_results = [];

        let result = vm.execute(&chunk, &primitive_results);
        assert!(matches!(result, Err(SigmaError::StackUnderflow)));
    }

    #[test]
    fn test_execute_optimized_with_false_result() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [false];

        let result = vm.execute_optimized(&chunk, &primitive_results).unwrap();
        assert_eq!(result, None);
    }
}
