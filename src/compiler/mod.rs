//! SIGMA rule compiler.
//!
//! This module handles the offline compilation of SIGMA YAML rules into
//! efficient bytecode for execution by the virtual machine.
//!
//! The compiler is organized into several sub-modules:
//! - [`field_mapping`] - Field name normalization and taxonomy support
//! - [`parser`] - Tokenization and parsing of SIGMA condition expressions
//! - [`codegen`] - Bytecode generation from parsed ASTs
//!
//! # Examples
//!
//! Basic usage:
//! ```rust
//! use sigma_engine::Compiler;
//!
//! let mut compiler = Compiler::new();
//! let rule_yaml = r#"
//! title: Windows Login Event
//! logsource:
//!     category: authentication
//! detection:
//!     selection:
//!         EventID: 4624
//!         LogonType: 2
//!     condition: selection
//! "#;
//!
//! let bytecode = compiler.compile_rule(rule_yaml)?;
//! # Ok::<(), sigma_engine::SigmaError>(())
//! ```
//!
//! With custom field mapping:
//! ```rust
//! use sigma_engine::{Compiler, FieldMapping};
//!
//! let mut field_mapping = FieldMapping::new();
//! field_mapping.add_mapping("Event_ID".to_string(), "EventID".to_string());
//!
//! let mut compiler = Compiler::with_field_mapping(field_mapping);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod codegen;
pub mod field_mapping;
pub mod parser;

pub use field_mapping::FieldMapping;

use crate::error::{Result, SigmaError};
use crate::ir::{BytecodeChunk, CompiledRuleset, Opcode, Primitive, PrimitiveId, RuleId};
use crate::matcher::{FunctionalMatcher, MatcherBuilder};
use serde_yaml::Value;
use std::collections::HashMap;

/// The SIGMA rule compiler.
///
/// This struct maintains state during compilation, including the mapping
/// of primitives to their IDs for deduplication across rules.
///
/// # Examples
///
/// ```rust
/// use sigma_engine::Compiler;
///
/// let mut compiler = Compiler::new();
/// assert_eq!(compiler.primitive_count(), 0);
/// ```
pub struct Compiler {
    primitive_map: HashMap<Primitive, PrimitiveId>,
    primitives: Vec<Primitive>,
    next_primitive_id: PrimitiveId,
    current_selection_map: HashMap<String, Vec<PrimitiveId>>,
    field_mapping: FieldMapping,
}

impl Compiler {
    /// Create a new compiler instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::Compiler;
    ///
    /// let compiler = Compiler::new();
    /// assert_eq!(compiler.primitive_count(), 0);
    /// ```
    pub fn new() -> Self {
        Self {
            primitive_map: HashMap::new(),
            primitives: Vec::new(),
            next_primitive_id: 0,
            current_selection_map: HashMap::new(),
            field_mapping: FieldMapping::new(),
        }
    }

    /// Create a new compiler instance with custom field mapping.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::{Compiler, FieldMapping};
    ///
    /// let field_mapping = FieldMapping::with_taxonomy("custom".to_string());
    /// let compiler = Compiler::with_field_mapping(field_mapping);
    /// assert_eq!(compiler.field_mapping().taxonomy(), "custom");
    /// ```
    pub fn with_field_mapping(field_mapping: FieldMapping) -> Self {
        Self {
            primitive_map: HashMap::new(),
            primitives: Vec::new(),
            next_primitive_id: 0,
            current_selection_map: HashMap::new(),
            field_mapping,
        }
    }

    /// Get a mutable reference to the field mapping for configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::Compiler;
    ///
    /// let mut compiler = Compiler::new();
    /// compiler.field_mapping_mut().add_mapping(
    ///     "Event_ID".to_string(),
    ///     "EventID".to_string()
    /// );
    /// ```
    pub fn field_mapping_mut(&mut self) -> &mut FieldMapping {
        &mut self.field_mapping
    }

    /// Get a reference to the field mapping.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::Compiler;
    ///
    /// let compiler = Compiler::new();
    /// assert_eq!(compiler.field_mapping().taxonomy(), "sigma");
    /// ```
    pub fn field_mapping(&self) -> &FieldMapping {
        &self.field_mapping
    }

    /// Get a reference to the discovered primitives (for testing).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::Compiler;
    ///
    /// let compiler = Compiler::new();
    /// assert_eq!(compiler.primitives().len(), 0);
    /// ```
    pub fn primitives(&self) -> &[Primitive] {
        &self.primitives
    }

    /// Get a reference to the current selection map (for testing).
    pub fn current_selection_map(&self) -> &HashMap<String, Vec<PrimitiveId>> {
        &self.current_selection_map
    }

    /// Compile a single SIGMA rule from YAML.
    ///
    /// This method parses the YAML, discovers primitives, and generates bytecode.
    ///
    /// # Arguments
    /// * `rule_yaml` - The SIGMA rule in YAML format
    ///
    /// # Returns
    /// A compiled bytecode chunk ready for execution.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The YAML is malformed
    /// - The rule structure is invalid
    /// - The condition expression cannot be parsed
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::Compiler;
    ///
    /// let mut compiler = Compiler::new();
    /// let rule_yaml = r#"
    /// title: Test Rule
    /// logsource:
    ///     category: test
    /// detection:
    ///     selection:
    ///         EventID: 4624
    ///     condition: selection
    /// "#;
    ///
    /// let bytecode = compiler.compile_rule(rule_yaml)?;
    /// assert_eq!(bytecode.rule_name, Some("Test Rule".to_string()));
    /// # Ok::<(), sigma_engine::SigmaError>(())
    /// ```
    pub fn compile_rule(&mut self, rule_yaml: &str) -> Result<BytecodeChunk> {
        self.current_selection_map.clear();

        let yaml_doc: Value = serde_yaml::from_str(rule_yaml)
            .map_err(|e| SigmaError::YamlError(format!("Failed to parse YAML: {}", e)))?;

        let rule_id = self.extract_rule_id_from_yaml(&yaml_doc);
        let rule_title = yaml_doc
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Untitled Rule")
            .to_string();

        self.parse_detection_from_yaml(&yaml_doc)?;

        let opcodes = self.compile_condition_from_yaml(&yaml_doc)?;

        Ok(BytecodeChunk::with_name(rule_id, opcodes, rule_title))
    }

    /// Get the compiled ruleset with all primitives and bytecode chunks.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::{Compiler, BytecodeChunk, Opcode};
    ///
    /// let compiler = Compiler::new();
    /// let chunk = BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)]);
    /// let ruleset = compiler.into_ruleset(vec![chunk]);
    /// assert_eq!(ruleset.chunks.len(), 1);
    /// ```
    pub fn into_ruleset(self, chunks: Vec<BytecodeChunk>) -> CompiledRuleset {
        CompiledRuleset {
            chunks,
            primitive_map: self.primitive_map,
            primitives: self.primitives,
        }
    }

    /// Get the compiled ruleset with all primitives (no chunks).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::Compiler;
    ///
    /// let compiler = Compiler::new();
    /// let ruleset = compiler.into_empty_ruleset();
    /// assert_eq!(ruleset.chunks.len(), 0);
    /// ```
    pub fn into_empty_ruleset(self) -> CompiledRuleset {
        CompiledRuleset {
            chunks: Vec::new(),
            primitive_map: self.primitive_map,
            primitives: self.primitives,
        }
    }

    /// Get the current primitive count.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::Compiler;
    ///
    /// let compiler = Compiler::new();
    /// assert_eq!(compiler.primitive_count(), 0);
    /// ```
    pub fn primitive_count(&self) -> usize {
        self.primitives.len()
    }

    /// Create a functional matcher from the discovered primitives.
    ///
    /// This method creates a high-performance functional matcher that can be used
    /// for zero-allocation primitive evaluation. The matcher is built using the
    /// primitives discovered during rule compilation.
    ///
    /// # Returns
    /// A functional matcher ready for evaluation, or an error if compilation fails.
    ///
    /// # Example
    /// ```rust,ignore
    /// use sigma_engine::Compiler;
    ///
    /// let mut compiler = Compiler::new();
    /// // Compile some rules to discover primitives
    /// let rule_yaml = r#"
    /// title: Test Rule
    /// detection:
    ///     selection:
    ///         EventID: 4624
    ///     condition: selection
    /// "#;
    /// compiler.compile_rule(rule_yaml)?;
    ///
    /// // Create functional matcher from discovered primitives
    /// let matcher = compiler.create_functional_matcher()?;
    /// # Ok::<(), sigma_engine::SigmaError>(())
    /// ```
    pub fn create_functional_matcher(&self) -> Result<FunctionalMatcher> {
        let builder = MatcherBuilder::new();
        builder.compile(&self.primitives)
    }

    /// Create a functional matcher with custom hooks.
    ///
    /// This method allows you to register compilation hooks before creating the matcher.
    /// Hooks can be used to extract patterns for external filtering libraries.
    ///
    /// # Arguments
    /// * `builder_fn` - Function that configures the MatcherBuilder with hooks
    ///
    /// # Returns
    /// A functional matcher with hooks executed during compilation.
    ///
    /// # Example
    /// ```rust,ignore
    /// use sigma_engine::{Compiler, CompilationPhase};
    /// use std::sync::{Arc, Mutex};
    ///
    /// let mut compiler = Compiler::new();
    /// // ... compile rules ...
    ///
    /// let patterns = Arc::new(Mutex::new(Vec::new()));
    /// let patterns_clone = patterns.clone();
    ///
    /// let matcher = compiler.create_functional_matcher_with_hooks(|builder| {
    ///     builder.with_aho_corasick_extraction(move |literal, _selectivity| {
    ///         patterns_clone.lock().unwrap().push(literal.to_string());
    ///         Ok(())
    ///     })
    /// })?;
    /// # Ok::<(), sigma_engine::SigmaError>(())
    /// ```
    pub fn create_functional_matcher_with_hooks<F>(
        &self,
        builder_fn: F,
    ) -> Result<FunctionalMatcher>
    where
        F: FnOnce(MatcherBuilder) -> MatcherBuilder,
    {
        let builder = MatcherBuilder::new();
        let configured_builder = builder_fn(builder);
        configured_builder.compile(&self.primitives)
    }

    fn extract_rule_id_from_yaml(&self, yaml_doc: &Value) -> RuleId {
        yaml_doc
            .get("id")
            .and_then(|v| {
                // Try as number first, then as string
                if let Some(n) = v.as_u64() {
                    Some(n as RuleId)
                } else if let Some(s) = v.as_str() {
                    s.parse::<RuleId>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn parse_detection_from_yaml(&mut self, yaml_doc: &Value) -> Result<()> {
        let detection = yaml_doc
            .get("detection")
            .ok_or_else(|| SigmaError::CompilationError("Missing detection section".to_string()))?;

        if let Value::Mapping(detection_map) = detection {
            for (key, value) in detection_map {
                if let Some(key_str) = key.as_str() {
                    if key_str != "condition" {
                        self.process_selection_from_yaml(key_str, value)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn process_selection_from_yaml(
        &mut self,
        selection_name: &str,
        selection_value: &Value,
    ) -> Result<()> {
        let mut primitive_ids = Vec::new();

        if let Value::Mapping(selection_map) = selection_value {
            for (field_key, field_value) in selection_map {
                if let Some(field_name) = field_key.as_str() {
                    let (base_field, match_type, modifiers) =
                        self.parse_field_with_modifiers(field_name);

                    let normalized_field = self.field_mapping.normalize_field(&base_field);

                    match field_value {
                        Value::String(s) => {
                            let primitive = Primitive::new(
                                normalized_field,
                                match_type.clone(),
                                vec![s.clone()],
                                modifiers.clone(),
                            );
                            let primitive_id = self.get_or_create_primitive_id(primitive);
                            primitive_ids.push(primitive_id);
                        }
                        Value::Number(n) => {
                            let value = if let Some(i) = n.as_i64() {
                                i.to_string()
                            } else if let Some(f) = n.as_f64() {
                                f.to_string()
                            } else {
                                return Err(SigmaError::CompilationError(
                                    "Invalid number format".to_string(),
                                ));
                            };
                            let primitive = Primitive::new(
                                normalized_field,
                                match_type.clone(),
                                vec![value],
                                modifiers.clone(),
                            );
                            let primitive_id = self.get_or_create_primitive_id(primitive);
                            primitive_ids.push(primitive_id);
                        }
                        Value::Sequence(seq) => {
                            let mut values = Vec::new();
                            for item in seq {
                                if let Some(s) = item.as_str() {
                                    values.push(s.to_string());
                                } else if let Some(n) = item.as_i64() {
                                    values.push(n.to_string());
                                } else if let Some(f) = item.as_f64() {
                                    values.push(f.to_string());
                                }
                            }

                            if !values.is_empty() {
                                let primitive =
                                    Primitive::new(normalized_field, match_type, values, modifiers);
                                let primitive_id = self.get_or_create_primitive_id(primitive);
                                primitive_ids.push(primitive_id);
                            }
                        }
                        _ => {
                            return Err(SigmaError::CompilationError(format!(
                                "Unsupported field value type for field '{}'",
                                field_name
                            )));
                        }
                    }
                }
            }
        }

        self.current_selection_map
            .insert(selection_name.to_string(), primitive_ids);

        Ok(())
    }

    fn get_or_create_primitive_id(&mut self, primitive: Primitive) -> PrimitiveId {
        if let Some(&existing_id) = self.primitive_map.get(&primitive) {
            existing_id
        } else {
            let new_id = self.next_primitive_id;
            self.primitive_map.insert(primitive.clone(), new_id);
            self.primitives.push(primitive);
            self.next_primitive_id += 1;
            new_id
        }
    }

    fn compile_condition_from_yaml(&self, yaml_doc: &Value) -> Result<Vec<Opcode>> {
        let detection = yaml_doc
            .get("detection")
            .ok_or_else(|| SigmaError::CompilationError("Missing detection section".to_string()))?;

        let condition_str = detection
            .get("condition")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SigmaError::CompilationError("Missing condition".to_string()))?;

        let tokens = parser::tokenize_condition(condition_str)?;
        let ast = parser::parse_tokens(&tokens, &self.current_selection_map)?;

        let mut opcodes = codegen::generate_bytecode(&ast, &self.current_selection_map)?;

        opcodes.push(Opcode::ReturnMatch(
            self.extract_rule_id_from_yaml(yaml_doc),
        ));

        Ok(opcodes)
    }

    /// Parse a field name with SIGMA modifiers.
    ///
    /// Examples:
    /// - "Image" -> ("Image", "equals", [])
    /// - "Image|endswith" -> ("Image", "endswith", [])
    /// - "CommandLine|contains" -> ("CommandLine", "contains", [])
    /// - "User|cased" -> ("User", "equals", ["case_sensitive"])
    /// - "Hash|re" -> ("Hash", "regex", [])
    fn parse_field_with_modifiers(&self, field_spec: &str) -> (String, String, Vec<String>) {
        let parts: Vec<&str> = field_spec.split('|').collect();

        if parts.len() == 1 {
            return (parts[0].to_string(), "equals".to_string(), vec![]);
        }

        let field_name = parts[0].to_string();
        let mut match_type = "equals".to_string();
        let mut modifiers = Vec::new();

        for modifier in &parts[1..] {
            match *modifier {
                "contains" => match_type = "contains".to_string(),
                "startswith" => match_type = "startswith".to_string(),
                "endswith" => match_type = "endswith".to_string(),
                "re" => match_type = "regex".to_string(),
                "cased" => modifiers.push("case_sensitive".to_string()),
                "base64" => modifiers.push("base64_decode".to_string()),
                "base64offset" => modifiers.push("base64_offset_decode".to_string()),
                "utf16" => modifiers.push("utf16_decode".to_string()),
                "utf16le" => modifiers.push("utf16le_decode".to_string()),
                "utf16be" => modifiers.push("utf16be_decode".to_string()),
                "wide" => modifiers.push("wide_decode".to_string()),
                _ => {
                    modifiers.push(modifier.to_string());
                }
            }
        }

        (field_name, match_type, modifiers)
    }
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml::Value;

    #[test]
    fn test_compiler_new() {
        let compiler = Compiler::new();
        assert_eq!(compiler.primitive_count(), 0);
        assert_eq!(compiler.field_mapping().taxonomy(), "sigma");
        assert_eq!(compiler.primitives().len(), 0);
        assert_eq!(compiler.current_selection_map().len(), 0);
    }

    #[test]
    fn test_compiler_with_field_mapping() {
        let field_mapping = FieldMapping::with_taxonomy("custom".to_string());
        let compiler = Compiler::with_field_mapping(field_mapping);
        assert_eq!(compiler.field_mapping().taxonomy(), "custom");
    }

    #[test]
    fn test_compiler_default() {
        let compiler = Compiler::default();
        assert_eq!(compiler.primitive_count(), 0);
        assert_eq!(compiler.field_mapping().taxonomy(), "sigma");
    }

    #[test]
    fn test_field_mapping_mut() {
        let mut compiler = Compiler::new();
        compiler
            .field_mapping_mut()
            .add_mapping("Event_ID".to_string(), "EventID".to_string());
        assert!(compiler.field_mapping().has_mapping("Event_ID"));
    }

    #[test]
    fn test_into_ruleset() {
        let compiler = Compiler::new();
        let chunk = crate::ir::BytecodeChunk::new(1, vec![crate::ir::Opcode::PushMatch(0)]);
        let ruleset = compiler.into_ruleset(vec![chunk]);
        assert_eq!(ruleset.chunks.len(), 1);
    }

    #[test]
    fn test_into_empty_ruleset() {
        let compiler = Compiler::new();
        let ruleset = compiler.into_empty_ruleset();
        assert_eq!(ruleset.chunks.len(), 0);
    }

    #[test]
    fn test_parse_field_with_modifiers_simple() {
        let compiler = Compiler::new();
        let (field, match_type, modifiers) = compiler.parse_field_with_modifiers("Image");
        assert_eq!(field, "Image");
        assert_eq!(match_type, "equals");
        assert_eq!(modifiers.len(), 0);
    }

    #[test]
    fn test_parse_field_with_modifiers_contains() {
        let compiler = Compiler::new();
        let (field, match_type, modifiers) =
            compiler.parse_field_with_modifiers("CommandLine|contains");
        assert_eq!(field, "CommandLine");
        assert_eq!(match_type, "contains");
        assert_eq!(modifiers.len(), 0);
    }

    #[test]
    fn test_parse_field_with_modifiers_startswith() {
        let compiler = Compiler::new();
        let (field, match_type, modifiers) =
            compiler.parse_field_with_modifiers("Image|startswith");
        assert_eq!(field, "Image");
        assert_eq!(match_type, "startswith");
        assert_eq!(modifiers.len(), 0);
    }

    #[test]
    fn test_parse_field_with_modifiers_endswith() {
        let compiler = Compiler::new();
        let (field, match_type, modifiers) = compiler.parse_field_with_modifiers("Image|endswith");
        assert_eq!(field, "Image");
        assert_eq!(match_type, "endswith");
        assert_eq!(modifiers.len(), 0);
    }

    #[test]
    fn test_parse_field_with_modifiers_regex() {
        let compiler = Compiler::new();
        let (field, match_type, modifiers) = compiler.parse_field_with_modifiers("Hash|re");
        assert_eq!(field, "Hash");
        assert_eq!(match_type, "regex");
        assert_eq!(modifiers.len(), 0);
    }

    #[test]
    fn test_parse_field_with_modifiers_cased() {
        let compiler = Compiler::new();
        let (field, match_type, modifiers) = compiler.parse_field_with_modifiers("User|cased");
        assert_eq!(field, "User");
        assert_eq!(match_type, "equals");
        assert_eq!(modifiers, vec!["case_sensitive"]);
    }

    #[test]
    fn test_parse_field_with_modifiers_base64() {
        let compiler = Compiler::new();
        let (field, match_type, modifiers) = compiler.parse_field_with_modifiers("Data|base64");
        assert_eq!(field, "Data");
        assert_eq!(match_type, "equals");
        assert_eq!(modifiers, vec!["base64_decode"]);
    }

    #[test]
    fn test_parse_field_with_modifiers_multiple() {
        let compiler = Compiler::new();
        let (field, match_type, modifiers) =
            compiler.parse_field_with_modifiers("Data|contains|base64|cased");
        assert_eq!(field, "Data");
        assert_eq!(match_type, "contains");
        assert_eq!(modifiers, vec!["base64_decode", "case_sensitive"]);
    }

    #[test]
    fn test_parse_field_with_modifiers_unknown() {
        let compiler = Compiler::new();
        let (field, match_type, modifiers) =
            compiler.parse_field_with_modifiers("Field|unknown_modifier");
        assert_eq!(field, "Field");
        assert_eq!(match_type, "equals");
        assert_eq!(modifiers, vec!["unknown_modifier"]);
    }

    #[test]
    fn test_parse_field_with_modifiers_utf16_variants() {
        let compiler = Compiler::new();

        let (_, _, modifiers) = compiler.parse_field_with_modifiers("Data|utf16");
        assert_eq!(modifiers, vec!["utf16_decode"]);

        let (_, _, modifiers) = compiler.parse_field_with_modifiers("Data|utf16le");
        assert_eq!(modifiers, vec!["utf16le_decode"]);

        let (_, _, modifiers) = compiler.parse_field_with_modifiers("Data|utf16be");
        assert_eq!(modifiers, vec!["utf16be_decode"]);

        let (_, _, modifiers) = compiler.parse_field_with_modifiers("Data|wide");
        assert_eq!(modifiers, vec!["wide_decode"]);

        let (_, _, modifiers) = compiler.parse_field_with_modifiers("Data|base64offset");
        assert_eq!(modifiers, vec!["base64_offset_decode"]);
    }

    #[test]
    fn test_create_functional_matcher() {
        let mut compiler = Compiler::new();

        // Compile a simple rule to discover primitives
        let rule_yaml = r#"
        title: Test Rule
        detection:
            selection:
                EventID: 4624
                LogonType: 2
            condition: selection
        "#;

        let _bytecode = compiler.compile_rule(rule_yaml).unwrap();
        assert!(compiler.primitive_count() > 0);

        // Create functional matcher from discovered primitives
        let matcher = compiler.create_functional_matcher().unwrap();
        assert_eq!(matcher.primitive_count(), compiler.primitive_count());
    }

    #[test]
    fn test_create_functional_matcher_with_hooks() {
        use std::sync::{Arc, Mutex};

        let mut compiler = Compiler::new();

        // Compile a rule with literal values
        let rule_yaml = r#"
        title: Test Rule
        detection:
            selection:
                EventID: 4624
                ProcessName: "notepad.exe"
            condition: selection
        "#;

        let _bytecode = compiler.compile_rule(rule_yaml).unwrap();

        // Create matcher with hooks
        let extracted_patterns = Arc::new(Mutex::new(Vec::<String>::new()));
        let patterns_clone = extracted_patterns.clone();

        let matcher = compiler
            .create_functional_matcher_with_hooks(|builder| {
                builder.with_aho_corasick_extraction(move |literal, _selectivity| {
                    patterns_clone.lock().unwrap().push(literal.to_string());
                    Ok(())
                })
            })
            .unwrap();

        assert_eq!(matcher.primitive_count(), compiler.primitive_count());

        // Check that hooks were executed
        let patterns = extracted_patterns.lock().unwrap();
        assert!(!patterns.is_empty());
        assert!(patterns.contains(&"4624".to_string()));
        assert!(patterns.contains(&"notepad.exe".to_string()));
    }

    #[test]
    fn test_extract_rule_id_from_yaml() {
        let compiler = Compiler::new();

        // Test with valid ID
        let yaml_str = r#"
        id: 12345
        title: Test Rule
        "#;
        let yaml_doc: Value = serde_yaml::from_str(yaml_str).unwrap();
        let rule_id = compiler.extract_rule_id_from_yaml(&yaml_doc);
        assert_eq!(rule_id, 12345);

        // Test with no ID
        let yaml_str = r#"
        title: Test Rule
        "#;
        let yaml_doc: Value = serde_yaml::from_str(yaml_str).unwrap();
        let rule_id = compiler.extract_rule_id_from_yaml(&yaml_doc);
        assert_eq!(rule_id, 0);

        // Test with invalid ID
        let yaml_str = r#"
        id: "not_a_number"
        title: Test Rule
        "#;
        let yaml_doc: Value = serde_yaml::from_str(yaml_str).unwrap();
        let rule_id = compiler.extract_rule_id_from_yaml(&yaml_doc);
        assert_eq!(rule_id, 0);
    }

    #[test]
    fn test_compile_rule_missing_detection() {
        let mut compiler = Compiler::new();
        let rule_yaml = r#"
        title: Test Rule
        logsource:
            category: test
        "#;

        let result = compiler.compile_rule(rule_yaml);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Missing detection section"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_compile_rule_missing_condition() {
        let mut compiler = Compiler::new();
        let rule_yaml = r#"
        title: Test Rule
        detection:
            selection:
                EventID: 4624
        "#;

        let result = compiler.compile_rule(rule_yaml);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Missing condition"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_compile_rule_with_number_values() {
        let mut compiler = Compiler::new();
        let rule_yaml = r#"
        title: Test Rule
        detection:
            selection:
                EventID: 4624
                ProcessId: 1234
                Score: 95.5
            condition: selection
        "#;

        let result = compiler.compile_rule(rule_yaml);
        assert!(result.is_ok());

        let chunk = result.unwrap();
        assert_eq!(chunk.rule_name, Some("Test Rule".to_string()));
        assert_eq!(compiler.primitive_count(), 3); // EventID, ProcessId, Score
    }

    #[test]
    fn test_compile_rule_with_sequence_values() {
        let mut compiler = Compiler::new();
        let rule_yaml = r#"
        title: Test Rule
        detection:
            selection:
                EventID:
                    - 4624
                    - 4625
                    - 4634
                ProcessName:
                    - "cmd.exe"
                    - "powershell.exe"
            condition: selection
        "#;

        let result = compiler.compile_rule(rule_yaml);
        assert!(result.is_ok());

        let chunk = result.unwrap();
        assert_eq!(chunk.rule_name, Some("Test Rule".to_string()));
        assert_eq!(compiler.primitive_count(), 2); // EventID list, ProcessName list
    }

    #[test]
    fn test_compile_rule_with_mixed_sequence() {
        let mut compiler = Compiler::new();
        let rule_yaml = r#"
        title: Test Rule
        detection:
            selection:
                EventID:
                    - 4624
                    - 4625
                    - 95.5
            condition: selection
        "#;

        let result = compiler.compile_rule(rule_yaml);
        assert!(result.is_ok());

        assert_eq!(compiler.primitive_count(), 1);
    }

    #[test]
    fn test_compile_rule_invalid_field_value() {
        let mut compiler = Compiler::new();
        let rule_yaml = r#"
        title: Test Rule
        detection:
            selection:
                EventID:
                    nested:
                        invalid: structure
            condition: selection
        "#;

        let result = compiler.compile_rule(rule_yaml);
        assert!(result.is_err());

        if let Err(SigmaError::CompilationError(msg)) = result {
            assert!(msg.contains("Unsupported field value type"));
        } else {
            panic!("Expected CompilationError");
        }
    }

    #[test]
    fn test_get_or_create_primitive_id_deduplication() {
        let mut compiler = Compiler::new();

        let primitive1 = crate::ir::Primitive::new(
            "EventID".to_string(),
            "equals".to_string(),
            vec!["4624".to_string()],
            vec![],
        );

        let primitive2 = crate::ir::Primitive::new(
            "EventID".to_string(),
            "equals".to_string(),
            vec!["4624".to_string()],
            vec![],
        );

        let id1 = compiler.get_or_create_primitive_id(primitive1);
        let id2 = compiler.get_or_create_primitive_id(primitive2);

        assert_eq!(id1, id2); // Should be deduplicated
        assert_eq!(compiler.primitive_count(), 1);
    }

    #[test]
    fn test_compile_rule_with_field_mapping() {
        let mut field_mapping = FieldMapping::new();
        field_mapping.add_mapping("Event_ID".to_string(), "EventID".to_string());

        let mut compiler = Compiler::with_field_mapping(field_mapping);
        let rule_yaml = r#"
        title: Test Rule
        detection:
            selection:
                Event_ID: 4624
            condition: selection
        "#;

        let result = compiler.compile_rule(rule_yaml);
        assert!(result.is_ok());

        // Check that the primitive was created with the normalized field name
        let primitives = compiler.primitives();
        assert_eq!(primitives.len(), 1);
        assert_eq!(primitives[0].field, "EventID");
    }

    #[test]
    fn test_compile_rule_invalid_yaml() {
        let mut compiler = Compiler::new();
        let invalid_yaml = "invalid: yaml: [unclosed";

        let result = compiler.compile_rule(invalid_yaml);
        assert!(result.is_err());

        if let Err(SigmaError::YamlError(msg)) = result {
            assert!(msg.contains("Failed to parse YAML"));
        } else {
            panic!("Expected YamlError");
        }
    }

    #[test]
    fn test_compile_rule_with_invalid_number() {
        let mut compiler = Compiler::new();
        // This should work fine as serde_yaml handles number parsing
        let rule_yaml = r#"
        title: Test Rule
        detection:
            selection:
                EventID: 4624
                Score: 95.5
            condition: selection
        "#;

        let result = compiler.compile_rule(rule_yaml);
        assert!(result.is_ok());
    }
}
