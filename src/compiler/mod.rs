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

    fn extract_rule_id_from_yaml(&self, yaml_doc: &Value) -> RuleId {
        yaml_doc
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.parse::<RuleId>().unwrap_or(0))
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
