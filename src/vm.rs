//! Stack-based virtual machine for executing SIGMA bytecode.
//!
//! This module provides the high-performance runtime execution engine
//! that evaluates compiled bytecode using pre-computed primitive results.

use crate::error::{Result, SigmaError};
use crate::ir::{BytecodeChunk, ChunkComplexity, Opcode, RuleId};

/// Performance metrics for adaptive execution monitoring.
#[derive(Debug, Default, Clone)]
pub struct VmMetrics {
    /// Number of simple chunks executed
    pub simple_executions: u64,
    /// Number of medium chunks executed
    pub medium_executions: u64,
    /// Number of complex chunks executed
    pub complex_executions: u64,
    /// Total execution count
    pub total_executions: u64,
    /// Total execution time in nanoseconds (when timing is enabled)
    pub total_execution_time_ns: u64,
    /// Average execution time per operation
    pub avg_execution_time_ns: f64,
}

impl VmMetrics {
    /// Calculate performance statistics.
    pub fn performance_summary(&self) -> String {
        if self.total_executions == 0 {
            return "No executions recorded".to_string();
        }

        let simple_pct = (self.simple_executions as f64 / self.total_executions as f64) * 100.0;
        let medium_pct = (self.medium_executions as f64 / self.total_executions as f64) * 100.0;
        let complex_pct = (self.complex_executions as f64 / self.total_executions as f64) * 100.0;

        format!(
            "VM Performance Summary:\n\
             Total Executions: {}\n\
             Simple Rules: {} ({:.1}%)\n\
             Medium Rules: {} ({:.1}%)\n\
             Complex Rules: {} ({:.1}%)\n\
             Avg Time/Op: {:.2} ns",
            self.total_executions,
            self.simple_executions,
            simple_pct,
            self.medium_executions,
            medium_pct,
            self.complex_executions,
            complex_pct,
            self.avg_execution_time_ns
        )
    }

    /// Update timing metrics.
    pub fn update_timing(&mut self, execution_time_ns: u64) {
        self.total_execution_time_ns += execution_time_ns;
        self.avg_execution_time_ns =
            self.total_execution_time_ns as f64 / self.total_executions as f64;
    }
}

/// Stack-based virtual machine for executing SIGMA bytecode.
///
/// The VM is designed for high-performance execution with minimal allocation.
/// It operates on a pre-allocated stack and takes primitive results as input.
pub struct Vm<const STACK_SIZE: usize = 64> {
    stack: [bool; STACK_SIZE],
    stack_ptr: usize,
    /// Performance metrics for monitoring adaptive execution
    #[cfg(feature = "metrics")]
    metrics: VmMetrics,
}

impl<const STACK_SIZE: usize> Vm<STACK_SIZE> {
    /// Create a new virtual machine instance.
    pub fn new() -> Self {
        Self {
            stack: [false; STACK_SIZE],
            stack_ptr: 0,
            #[cfg(feature = "metrics")]
            metrics: VmMetrics::default(),
        }
    }

    /// Ultra-fast execution using unsafe optimizations.
    ///
    /// # Safety
    /// Assumes all bytecode is valid and uses unsafe array access.
    #[inline]
    pub fn execute_ultra_fast(
        &mut self,
        chunk: &BytecodeChunk,
        primitive_results: &[bool],
    ) -> Option<RuleId> {
        self.stack_ptr = 0;

        for opcode in &chunk.opcodes {
            match opcode {
                Opcode::PushMatch(primitive_id) => unsafe {
                    let result = *primitive_results.get_unchecked(*primitive_id as usize);
                    *self.stack.get_unchecked_mut(self.stack_ptr) = result;
                    self.stack_ptr += 1;
                },
                Opcode::And => unsafe {
                    self.stack_ptr -= 1;
                    let b = *self.stack.get_unchecked(self.stack_ptr);
                    let a = *self.stack.get_unchecked(self.stack_ptr - 1);
                    *self.stack.get_unchecked_mut(self.stack_ptr - 1) = a && b;
                },
                Opcode::Or => unsafe {
                    self.stack_ptr -= 1;
                    let b = *self.stack.get_unchecked(self.stack_ptr);
                    let a = *self.stack.get_unchecked(self.stack_ptr - 1);
                    *self.stack.get_unchecked_mut(self.stack_ptr - 1) = a || b;
                },
                Opcode::ReturnMatch(rule_id) => unsafe {
                    let result = *self.stack.get_unchecked(self.stack_ptr - 1);
                    return if result { Some(*rule_id) } else { None };
                },
                Opcode::Not => unsafe {
                    let value = *self.stack.get_unchecked(self.stack_ptr - 1);
                    *self.stack.get_unchecked_mut(self.stack_ptr - 1) = !value;
                },
            }
        }

        unsafe { std::hint::unreachable_unchecked() }
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

    /// Execute bytecode without bounds checking for maximum performance.
    ///
    /// # Safety
    /// Caller must ensure:
    /// - All primitive IDs are valid
    /// - Bytecode ends with ReturnMatch
    /// - Stack won't overflow
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
                    let result =
                        unsafe { *primitive_results.get_unchecked(*primitive_id as usize) };
                    unsafe {
                        *self.stack.get_unchecked_mut(self.stack_ptr) = result;
                    }
                    self.stack_ptr += 1;
                }
                Opcode::And => {
                    unsafe {
                        let b = *self.stack.get_unchecked(self.stack_ptr - 1);
                        let a = *self.stack.get_unchecked(self.stack_ptr - 2);
                        *self.stack.get_unchecked_mut(self.stack_ptr - 2) = a && b;
                    }
                    self.stack_ptr -= 1;
                }
                Opcode::Or => {
                    unsafe {
                        let b = *self.stack.get_unchecked(self.stack_ptr - 1);
                        let a = *self.stack.get_unchecked(self.stack_ptr - 2);
                        *self.stack.get_unchecked_mut(self.stack_ptr - 2) = a || b;
                    }
                    self.stack_ptr -= 1;
                }
                Opcode::Not => unsafe {
                    let value = *self.stack.get_unchecked(self.stack_ptr - 1);
                    *self.stack.get_unchecked_mut(self.stack_ptr - 1) = !value;
                },
                Opcode::ReturnMatch(rule_id) => {
                    let result = unsafe { *self.stack.get_unchecked(self.stack_ptr - 1) };
                    return if result { Some(*rule_id) } else { None };
                }
            }
        }

        unsafe { std::hint::unreachable_unchecked() }
    }

    /// Execute with automatic optimization selection.
    #[inline]
    pub fn execute_optimized(
        &mut self,
        chunk: &BytecodeChunk,
        primitive_results: &[bool],
    ) -> Result<Option<RuleId>> {
        if chunk.can_execute_unchecked(primitive_results.len(), STACK_SIZE) {
            Ok(self.execute_ultra_fast(chunk, primitive_results))
        } else {
            self.execute(chunk, primitive_results)
        }
    }

    /// Execute using complexity-based strategy selection.
    #[inline]
    pub fn execute_adaptive(
        &mut self,
        chunk: &BytecodeChunk,
        primitive_results: &[bool],
    ) -> Option<RuleId> {
        let complexity = chunk.complexity;

        #[cfg(feature = "metrics")]
        {
            self.metrics.total_executions += 1;
            match complexity {
                ChunkComplexity::Simple => self.metrics.simple_executions += 1,
                ChunkComplexity::Medium => self.metrics.medium_executions += 1,
                ChunkComplexity::Complex => self.metrics.complex_executions += 1,
            }
        }

        match complexity {
            ChunkComplexity::Simple => self.execute_simple_optimized(chunk, primitive_results),
            ChunkComplexity::Medium => self.execute_ultra_fast(chunk, primitive_results),
            ChunkComplexity::Complex => self.execute_complex_optimized(chunk, primitive_results),
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

    #[cfg(feature = "metrics")]
    pub fn metrics(&self) -> &VmMetrics {
        &self.metrics
    }

    /// Reset performance metrics.
    #[cfg(feature = "metrics")]
    pub fn reset_metrics(&mut self) {
        self.metrics = VmMetrics::default();
    }

    /// Execute multiple chunks optimized for batch processing.
    pub fn execute_batch_optimized(
        &mut self,
        chunks: &[BytecodeChunk],
        primitive_results: &[bool],
    ) -> Result<Vec<RuleId>> {
        let mut matches = Vec::with_capacity(chunks.len() / 10);

        let mut simple_chunks = Vec::new();
        let mut medium_chunks = Vec::new();
        let mut complex_chunks = Vec::new();

        for (idx, chunk) in chunks.iter().enumerate() {
            match chunk.complexity {
                ChunkComplexity::Simple => simple_chunks.push((idx, chunk)),
                ChunkComplexity::Medium => medium_chunks.push((idx, chunk)),
                ChunkComplexity::Complex => complex_chunks.push((idx, chunk)),
            }
        }

        for (_, chunk) in simple_chunks {
            if let Some(rule_id) = self.execute_simple_optimized(chunk, primitive_results) {
                matches.push(rule_id);
            }
        }

        for (_, chunk) in medium_chunks {
            if chunk.can_execute_unchecked(primitive_results.len(), STACK_SIZE) {
                if let Some(rule_id) = self.execute_ultra_fast(chunk, primitive_results) {
                    matches.push(rule_id);
                }
            } else if let Some(rule_id) = self.execute(chunk, primitive_results)? {
                matches.push(rule_id);
            }
        }

        for (_, chunk) in complex_chunks {
            if chunk.can_execute_unchecked(primitive_results.len(), STACK_SIZE) {
                if let Some(rule_id) = self.execute_complex_optimized(chunk, primitive_results) {
                    matches.push(rule_id);
                }
            } else if let Some(rule_id) = self.execute(chunk, primitive_results)? {
                matches.push(rule_id);
            }
        }

        Ok(matches)
    }

    #[cfg(feature = "metrics")]
    pub fn execute_with_timing(
        &mut self,
        chunk: &BytecodeChunk,
        primitive_results: &[bool],
    ) -> Result<Option<RuleId>> {
        let start = std::time::Instant::now();

        let result = if chunk.can_execute_unchecked(primitive_results.len(), STACK_SIZE) {
            Ok(self.execute_adaptive(chunk, primitive_results))
        } else {
            self.execute(chunk, primitive_results)
        };

        let execution_time = start.elapsed().as_nanos() as u64;
        self.metrics.update_timing(execution_time);

        result
    }

    #[cfg(feature = "metrics")]
    pub fn detect_regression(&self, baseline_avg_ns: f64, threshold_pct: f64) -> bool {
        if self.metrics.total_executions < 100 {
            return false;
        }

        let current_avg = self.metrics.avg_execution_time_ns;
        let regression_threshold = baseline_avg_ns * (1.0 + threshold_pct / 100.0);

        current_avg > regression_threshold
    }

    #[inline]
    fn execute_simple_optimized(
        &mut self,
        chunk: &BytecodeChunk,
        primitive_results: &[bool],
    ) -> Option<RuleId> {
        self.stack_ptr = 0;

        for opcode in &chunk.opcodes {
            match opcode {
                Opcode::PushMatch(primitive_id) => unsafe {
                    let result = *primitive_results.get_unchecked(*primitive_id as usize);
                    *self.stack.get_unchecked_mut(self.stack_ptr) = result;
                    self.stack_ptr += 1;
                },
                Opcode::ReturnMatch(rule_id) => unsafe {
                    let result = *self.stack.get_unchecked(self.stack_ptr - 1);
                    return if result { Some(*rule_id) } else { None };
                },
                Opcode::And => unsafe {
                    self.stack_ptr -= 1;
                    let b = *self.stack.get_unchecked(self.stack_ptr);
                    let a = *self.stack.get_unchecked(self.stack_ptr - 1);
                    *self.stack.get_unchecked_mut(self.stack_ptr - 1) = a && b;
                },
                Opcode::Or => unsafe {
                    self.stack_ptr -= 1;
                    let b = *self.stack.get_unchecked(self.stack_ptr);
                    let a = *self.stack.get_unchecked(self.stack_ptr - 1);
                    *self.stack.get_unchecked_mut(self.stack_ptr - 1) = a || b;
                },
                Opcode::Not => unsafe {
                    let value = *self.stack.get_unchecked(self.stack_ptr - 1);
                    *self.stack.get_unchecked_mut(self.stack_ptr - 1) = !value;
                },
            }
        }

        unsafe { std::hint::unreachable_unchecked() }
    }

    #[inline]
    fn execute_complex_optimized(
        &mut self,
        chunk: &BytecodeChunk,
        primitive_results: &[bool],
    ) -> Option<RuleId> {
        self.stack_ptr = 0;

        for opcode in &chunk.opcodes {
            match opcode {
                Opcode::And => unsafe {
                    self.stack_ptr -= 1;
                    let b = *self.stack.get_unchecked(self.stack_ptr);
                    let a = *self.stack.get_unchecked(self.stack_ptr - 1);
                    *self.stack.get_unchecked_mut(self.stack_ptr - 1) = a && b;
                },
                Opcode::Or => unsafe {
                    self.stack_ptr -= 1;
                    let b = *self.stack.get_unchecked(self.stack_ptr);
                    let a = *self.stack.get_unchecked(self.stack_ptr - 1);
                    *self.stack.get_unchecked_mut(self.stack_ptr - 1) = a || b;
                },
                Opcode::PushMatch(primitive_id) => unsafe {
                    let result = *primitive_results.get_unchecked(*primitive_id as usize);
                    *self.stack.get_unchecked_mut(self.stack_ptr) = result;
                    self.stack_ptr += 1;
                },
                Opcode::Not => unsafe {
                    let value = *self.stack.get_unchecked(self.stack_ptr - 1);
                    *self.stack.get_unchecked_mut(self.stack_ptr - 1) = !value;
                },
                Opcode::ReturnMatch(rule_id) => unsafe {
                    let result = *self.stack.get_unchecked(self.stack_ptr - 1);
                    return if result { Some(*rule_id) } else { None };
                },
            }
        }

        unsafe { std::hint::unreachable_unchecked() }
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

    #[test]
    fn test_execute_batch_optimized() {
        let mut vm = Vm::<16>::new();

        // Create chunks with different complexities
        let simple_chunk =
            BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let medium_chunk = BytecodeChunk::new(
            2,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::And,
                Opcode::ReturnMatch(2),
            ],
        );
        let complex_chunk = BytecodeChunk::new(
            3,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::And,
                Opcode::PushMatch(2),
                Opcode::Or,
                Opcode::Not,
                Opcode::ReturnMatch(3),
            ],
        );

        let chunks = [simple_chunk, medium_chunk, complex_chunk];
        let primitive_results = [true, false, true];

        let result = vm
            .execute_batch_optimized(&chunks, &primitive_results)
            .unwrap();

        // Simple chunk should match (true), medium should not match (true && false = false)
        // Complex should match (!((true && false) || true) = !(false || true) = !true = false)
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 1);
    }

    #[test]
    fn test_execute_batch_optimized_empty() {
        let mut vm = Vm::<16>::new();
        let chunks = [];
        let primitive_results = [true];

        let result = vm
            .execute_batch_optimized(&chunks, &primitive_results)
            .unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_execute_batch_optimized_multiple_matches() {
        let mut vm = Vm::<16>::new();

        let chunk1 = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let chunk2 = BytecodeChunk::new(2, vec![Opcode::PushMatch(1), Opcode::ReturnMatch(2)]);
        let chunk3 = BytecodeChunk::new(3, vec![Opcode::PushMatch(2), Opcode::ReturnMatch(3)]);

        let chunks = [chunk1, chunk2, chunk3];
        let primitive_results = [true, true, false];

        let result = vm
            .execute_batch_optimized(&chunks, &primitive_results)
            .unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&1));
        assert!(result.contains(&2));
    }

    #[test]
    fn test_execute_adaptive() {
        let mut vm = Vm::<16>::new();

        // Test simple chunk
        let simple_chunk =
            BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [true];

        let result = vm.execute_adaptive(&simple_chunk, &primitive_results);
        assert_eq!(result, Some(1));

        // Test medium complexity chunk
        let medium_chunk = BytecodeChunk::new(
            2,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::And,
                Opcode::ReturnMatch(2),
            ],
        );
        let primitive_results = [true, true];

        let result = vm.execute_adaptive(&medium_chunk, &primitive_results);
        assert_eq!(result, Some(2));

        // Test complex chunk
        let complex_chunk = BytecodeChunk::new(
            3,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::And,
                Opcode::PushMatch(2),
                Opcode::Or,
                Opcode::ReturnMatch(3),
            ],
        );
        let primitive_results = [false, false, true];

        let result = vm.execute_adaptive(&complex_chunk, &primitive_results);
        assert_eq!(result, Some(3));
    }

    #[test]
    fn test_execute_simple_optimized() {
        let mut vm = Vm::<16>::new();

        // Test simple chunk with single primitive
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [true];

        let result = vm.execute_simple_optimized(&chunk, &primitive_results);
        assert_eq!(result, Some(1));

        // Test simple chunk with false result
        let primitive_results = [false];
        let result = vm.execute_simple_optimized(&chunk, &primitive_results);
        assert_eq!(result, None);

        // Test simple chunk with AND operation
        let chunk = BytecodeChunk::new(
            2,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::And,
                Opcode::ReturnMatch(2),
            ],
        );
        let primitive_results = [true, true];

        let result = vm.execute_simple_optimized(&chunk, &primitive_results);
        assert_eq!(result, Some(2));
    }

    #[test]
    fn test_execute_complex_optimized() {
        let mut vm = Vm::<16>::new();

        // Test complex chunk with multiple operations
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::And,
                Opcode::PushMatch(2),
                Opcode::Or,
                Opcode::Not,
                Opcode::ReturnMatch(1),
            ],
        );
        let primitive_results = [true, false, true];

        let result = vm.execute_complex_optimized(&chunk, &primitive_results);
        assert_eq!(result, None); // !((true && false) || true) = !(false || true) = !true = false

        // Test with different values
        let primitive_results = [false, false, false];
        let result = vm.execute_complex_optimized(&chunk, &primitive_results);
        assert_eq!(result, Some(1)); // !((false && false) || false) = !(false || false) = !false = true
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_execute_with_timing() {
        let mut vm = Vm::<16>::new();
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [true];

        let result = vm.execute_with_timing(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));

        // Check that metrics were updated
        assert!(vm.metrics.total_executions > 0);
        assert!(vm.metrics.avg_execution_time_ns > 0.0);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_vm_metrics_tracking() {
        let mut vm = Vm::<16>::new();

        // Test simple chunk metrics
        let simple_chunk =
            BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [true];

        let _result = vm
            .execute_with_timing(&simple_chunk, &primitive_results)
            .unwrap();
        assert_eq!(vm.metrics.simple_executions, 1);
        assert_eq!(vm.metrics.medium_executions, 0);
        assert_eq!(vm.metrics.complex_executions, 0);

        // Test medium complexity chunk metrics (needs more operations to qualify as medium)
        let medium_chunk = BytecodeChunk::new(
            2,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::And,
                Opcode::PushMatch(2),
                Opcode::Or,
                Opcode::PushMatch(3),
                Opcode::And,
                Opcode::ReturnMatch(2),
            ],
        );

        let medium_primitive_results = [true, false, true, true];
        let _result = vm
            .execute_with_timing(&medium_chunk, &medium_primitive_results)
            .unwrap();
        assert_eq!(vm.metrics.simple_executions, 1);
        assert_eq!(vm.metrics.medium_executions, 1);
        assert_eq!(vm.metrics.complex_executions, 0);
    }

    #[test]
    fn test_vm_reset_with_metrics() {
        let mut vm = Vm::<16>::new();

        // Execute something to change VM state
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
        let primitive_results = [true];
        let _result = vm.execute(&chunk, &primitive_results).unwrap();

        // Reset and verify state is clean
        vm.reset();
        assert_eq!(vm.stack_depth(), 0);

        #[cfg(feature = "metrics")]
        {
            // Metrics should be reset too
            assert_eq!(vm.metrics.total_executions, 0);
            assert_eq!(vm.metrics.simple_executions, 0);
            assert_eq!(vm.metrics.medium_executions, 0);
            assert_eq!(vm.metrics.complex_executions, 0);
        }
    }

    #[test]
    fn test_execute_batch_optimized_with_error() {
        let mut vm = Vm::<2>::new(); // Small stack to trigger overflow

        // Create a chunk that will cause stack overflow
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::PushMatch(2), // This should cause overflow with stack size 2
                Opcode::ReturnMatch(1),
            ],
        );

        let chunks = [chunk];
        let primitive_results = [true, true, true];

        let result = vm.execute_batch_optimized(&chunks, &primitive_results);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_optimized_fallback_to_checked() {
        let mut vm = Vm::<16>::new();

        // Create a chunk that cannot be executed unchecked (invalid primitive ID)
        let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(10), Opcode::ReturnMatch(1)]);
        let primitive_results = [true]; // Only one primitive, but chunk references primitive 10

        let result = vm.execute_optimized(&chunk, &primitive_results);
        assert!(result.is_err());
        assert!(matches!(result, Err(SigmaError::InvalidPrimitiveId(10))));
    }

    #[test]
    fn test_execute_ultra_fast_edge_cases() {
        let mut vm = Vm::<16>::new();

        // Test with NOT operation
        let chunk = BytecodeChunk::new(
            1,
            vec![Opcode::PushMatch(0), Opcode::Not, Opcode::ReturnMatch(1)],
        );
        let primitive_results = [false];

        let result = vm.execute_ultra_fast(&chunk, &primitive_results);
        assert_eq!(result, Some(1)); // !false = true

        // Test with OR operation
        let chunk = BytecodeChunk::new(
            2,
            vec![
                Opcode::PushMatch(0),
                Opcode::PushMatch(1),
                Opcode::Or,
                Opcode::ReturnMatch(2),
            ],
        );
        let primitive_results = [false, true];

        let result = vm.execute_ultra_fast(&chunk, &primitive_results);
        assert_eq!(result, Some(2)); // false || true = true
    }

    #[test]
    fn test_execute_unchecked_comprehensive() {
        let mut vm = Vm::<16>::new();

        // Test complex expression: (A && B) || (!C)
        let chunk = BytecodeChunk::new(
            1,
            vec![
                Opcode::PushMatch(0), // A
                Opcode::PushMatch(1), // B
                Opcode::And,          // A && B
                Opcode::PushMatch(2), // C
                Opcode::Not,          // !C
                Opcode::Or,           // (A && B) || (!C)
                Opcode::ReturnMatch(1),
            ],
        );

        // Test case 1: A=true, B=true, C=false -> (true && true) || (!false) = true || true = true
        let primitive_results = [true, true, false];
        let result = vm.execute_unchecked(&chunk, &primitive_results);
        assert_eq!(result, Some(1));

        // Test case 2: A=false, B=true, C=true -> (false && true) || (!true) = false || false = false
        let primitive_results = [false, true, true];
        let result = vm.execute_unchecked(&chunk, &primitive_results);
        assert_eq!(result, None);

        // Test case 3: A=false, B=false, C=true -> (false && false) || (!true) = false || false = false
        let primitive_results = [false, false, true];
        let result = vm.execute_unchecked(&chunk, &primitive_results);
        assert_eq!(result, None);

        // Test case 4: A=false, B=false, C=false -> (false && false) || (!false) = false || true = true
        let primitive_results = [false, false, false];
        let result = vm.execute_unchecked(&chunk, &primitive_results);
        assert_eq!(result, Some(1));
    }

    #[test]
    fn test_stack_depth_tracking() {
        let mut vm = Vm::<16>::new();
        assert_eq!(vm.stack_depth(), 0);

        // Execute something that uses stack
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

        let _result = vm.execute(&chunk, &primitive_results).unwrap();

        // After execution, stack should be reset
        assert_eq!(vm.stack_depth(), 0);
    }

    #[test]
    fn test_push_match_error_handling() {
        let mut vm = Vm::<16>::new();

        // Test invalid primitive ID
        let result = vm.push_match(999, &[true, false]);
        assert!(matches!(result, Err(SigmaError::InvalidPrimitiveId(999))));

        // Test stack overflow by manually filling stack
        for i in 0..16 {
            let result = vm.push_match(0, &[true]);
            if i < 16 {
                assert!(result.is_ok());
            }
        }

        // Next push should overflow
        let result = vm.push_match(0, &[true]);
        assert!(matches!(result, Err(SigmaError::StackOverflow)));
    }

    #[test]
    fn test_vm_with_large_stack() {
        let mut vm = Vm::<1024>::new();
        assert_eq!(vm.stack_depth(), 0);

        // Test that we can handle large operations
        let mut opcodes = Vec::new();
        for i in 0..100 {
            opcodes.push(Opcode::PushMatch(i % 10)); // Use modulo to stay within primitive bounds
        }
        for _ in 0..99 {
            opcodes.push(Opcode::And);
        }
        opcodes.push(Opcode::ReturnMatch(1));

        let chunk = BytecodeChunk::new(1, opcodes);
        let primitive_results = [true; 10];

        let result = vm.execute(&chunk, &primitive_results).unwrap();
        assert_eq!(result, Some(1));
    }
}
