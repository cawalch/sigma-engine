//! Intermediate Representation (IR) for SIGMA bytecode.
//!
//! This module defines the core data structures used throughout the compilation
//! and execution pipeline.

use std::borrow::Cow;
use std::collections::HashMap;

pub type PrimitiveId = u32;
pub type RuleId = u32;

/// Bytecode opcodes for the stack-based virtual machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opcode {
    PushMatch(PrimitiveId),
    And,
    Or,
    Not,
    ReturnMatch(RuleId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Primitive {
    pub field: Cow<'static, str>,
    pub match_type: Cow<'static, str>,
    pub values: Vec<Cow<'static, str>>,
    pub modifiers: Vec<Cow<'static, str>>,
}

impl Primitive {
    pub fn new(
        field: String,
        match_type: String,
        values: Vec<String>,
        modifiers: Vec<String>,
    ) -> Self {
        Self {
            field: Cow::Owned(field),
            match_type: Cow::Owned(match_type),
            values: values.into_iter().map(Cow::Owned).collect(),
            modifiers: modifiers.into_iter().map(Cow::Owned).collect(),
        }
    }

    pub fn new_static(
        field: &'static str,
        match_type: &'static str,
        values: &[&'static str],
        modifiers: &[&'static str],
    ) -> Self {
        Self {
            field: Cow::Borrowed(field),
            match_type: Cow::Borrowed(match_type),
            values: values.iter().map(|&s| Cow::Borrowed(s)).collect(),
            modifiers: modifiers.iter().map(|&s| Cow::Borrowed(s)).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytecodeChunk {
    pub rule_id: RuleId,
    pub opcodes: Vec<Opcode>,
    pub rule_name: Option<String>,
    pub max_stack_depth: usize,
    pub max_primitive_id: Option<PrimitiveId>,
    pub is_validated: bool,
}

impl BytecodeChunk {
    pub fn new(rule_id: RuleId, opcodes: Vec<Opcode>) -> Self {
        let max_stack_depth = Self::calculate_max_stack_depth(&opcodes);
        let max_primitive_id = Self::find_max_primitive_id(&opcodes);
        let is_validated = Self::validate_bytecode_structure(&opcodes);

        Self {
            rule_id,
            opcodes,
            rule_name: None,
            max_stack_depth,
            max_primitive_id,
            is_validated,
        }
    }

    pub fn with_name(rule_id: RuleId, opcodes: Vec<Opcode>, rule_name: String) -> Self {
        let max_stack_depth = Self::calculate_max_stack_depth(&opcodes);
        let max_primitive_id = Self::find_max_primitive_id(&opcodes);
        let is_validated = Self::validate_bytecode_structure(&opcodes);

        Self {
            rule_id,
            opcodes,
            rule_name: Some(rule_name),
            max_stack_depth,
            max_primitive_id,
            is_validated,
        }
    }

    fn calculate_max_stack_depth(opcodes: &[Opcode]) -> usize {
        let mut current_depth: usize = 0;
        let mut max_depth: usize = 0;

        for opcode in opcodes {
            match opcode {
                Opcode::PushMatch(_) => {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth);
                }
                Opcode::And | Opcode::Or => {
                    current_depth = current_depth.saturating_sub(1);
                }
                Opcode::Not => {
                    // No net change
                }
                Opcode::ReturnMatch(_) => {
                    current_depth = current_depth.saturating_sub(1);
                }
            }
        }

        max_depth
    }

    fn find_max_primitive_id(opcodes: &[Opcode]) -> Option<PrimitiveId> {
        opcodes
            .iter()
            .filter_map(|opcode| match opcode {
                Opcode::PushMatch(id) => Some(*id),
                _ => None,
            })
            .max()
    }

    fn validate_bytecode_structure(opcodes: &[Opcode]) -> bool {
        if opcodes.is_empty() {
            return false;
        }

        if !matches!(opcodes.last(), Some(Opcode::ReturnMatch(_))) {
            return false;
        }

        let mut stack_depth: i32 = 0;

        for opcode in opcodes {
            match opcode {
                Opcode::PushMatch(_) => {
                    stack_depth += 1;
                }
                Opcode::And | Opcode::Or => {
                    if stack_depth < 2 {
                        return false;
                    }
                    stack_depth -= 1;
                }
                Opcode::Not => {
                    if stack_depth < 1 {
                        return false;
                    }
                }
                Opcode::ReturnMatch(_) => {
                    if stack_depth < 1 {
                        return false;
                    }
                    stack_depth -= 1;
                }
            }
        }

        stack_depth == 0
    }

    /// Check if this bytecode chunk can be safely executed with unchecked methods.
    ///
    /// # Arguments
    /// * `primitive_results_len` - The length of the primitive results array
    /// * `vm_stack_size` - The VM stack size to check against
    ///
    /// # Returns
    /// * `true` if safe for unchecked execution
    /// * `false` if checked execution should be used
    pub fn can_execute_unchecked(
        &self,
        primitive_results_len: usize,
        vm_stack_size: usize,
    ) -> bool {
        if !self.is_validated {
            return false;
        }

        if self.max_stack_depth > vm_stack_size {
            return false;
        }

        if let Some(max_id) = self.max_primitive_id {
            if max_id as usize >= primitive_results_len {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone)]
pub struct CompiledRuleset {
    pub chunks: Vec<BytecodeChunk>,
    pub primitive_map: HashMap<Primitive, PrimitiveId>,
    pub primitives: Vec<Primitive>,
}

impl CompiledRuleset {
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            primitive_map: HashMap::new(),
            primitives: Vec::new(),
        }
    }

    pub fn primitive_count(&self) -> usize {
        self.primitives.len()
    }

    pub fn get_primitive(&self, id: PrimitiveId) -> Option<&Primitive> {
        self.primitives.get(id as usize)
    }
}

impl Default for CompiledRuleset {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_creation() {
        let prim = Primitive::new(
            "EventID".to_string(),
            "equals".to_string(),
            vec!["4624".to_string()],
            vec![],
        );

        assert_eq!(prim.field, "EventID");
        assert_eq!(prim.match_type, "equals");
        assert_eq!(prim.values, vec!["4624"]);
        assert!(prim.modifiers.is_empty());
    }

    #[test]
    fn test_primitive_static_creation() {
        let prim = Primitive::new_static(
            "EventID",
            "equals",
            &["4624", "4625"],
            &["case_insensitive"],
        );

        assert_eq!(prim.field, "EventID");
        assert_eq!(prim.match_type, "equals");
        assert_eq!(prim.values, vec!["4624", "4625"]);
        assert_eq!(prim.modifiers, vec!["case_insensitive"]);
    }

    #[test]
    fn test_bytecode_chunk_stack_depth() {
        let opcodes = vec![
            Opcode::PushMatch(0),
            Opcode::PushMatch(1),
            Opcode::And,
            Opcode::ReturnMatch(1),
        ];

        let chunk = BytecodeChunk::new(1, opcodes);
        assert_eq!(chunk.max_stack_depth, 2);
    }

    #[test]
    fn test_bytecode_chunk_complex_stack_depth() {
        let opcodes = vec![
            Opcode::PushMatch(0),
            Opcode::PushMatch(1),
            Opcode::PushMatch(2),
            Opcode::Or,
            Opcode::And,
            Opcode::ReturnMatch(1),
        ];

        let chunk = BytecodeChunk::new(1, opcodes);
        assert_eq!(chunk.max_stack_depth, 3);
    }

    #[test]
    fn test_compiled_ruleset() {
        let mut ruleset = CompiledRuleset::new();
        assert_eq!(ruleset.primitive_count(), 0);

        let prim = Primitive::new_static("EventID", "equals", &["4624"], &[]);
        ruleset.primitive_map.insert(prim.clone(), 0);
        ruleset.primitives.push(prim.clone());

        assert_eq!(ruleset.primitive_count(), 1);
        assert_eq!(ruleset.get_primitive(0), Some(&prim));
        assert_eq!(ruleset.get_primitive(1), None);
    }
}
