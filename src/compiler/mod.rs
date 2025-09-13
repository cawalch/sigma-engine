//! SIGMA rule compiler.
//!
//! This module handles the offline compilation of SIGMA YAML rules into
//! efficient DAG structures for execution by the DAG engine.
//!
//! The compiler is organized into several sub-modules:
//! - [`field_mapping`] - Field name normalization and taxonomy support
//! - [`parser`] - Tokenization and parsing of SIGMA condition expressions

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
//! let ruleset = compiler.into_ruleset();
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

pub mod field_mapping;
pub mod parser;

pub use field_mapping::FieldMapping;

use crate::error::{Result, SigmaError};
use crate::ir::{CompiledRule, CompiledRuleset, Primitive, PrimitiveId, RuleId};

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
#[derive(Debug)]
pub struct Compiler {
    primitive_map: HashMap<Primitive, PrimitiveId>,
    primitives: Vec<Primitive>,
    next_primitive_id: PrimitiveId,
    current_selection_map: HashMap<String, Vec<PrimitiveId>>,
    field_mapping: FieldMapping,
    next_rule_id: RuleId,
    compiled_rules: Vec<CompiledRule>,
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
            next_rule_id: 0,
            compiled_rules: Vec::new(),
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
            next_rule_id: 0,
            compiled_rules: Vec::new(),
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

    /// Compile a single SIGMA rule and add it to the compiler state.
    ///
    /// This method parses a SIGMA rule and extracts its primitives, adding them
    /// to the compiler's internal state for later compilation into a complete ruleset.
    ///
    /// # Arguments
    /// * `rule_yaml` - The SIGMA rule in YAML format
    ///
    /// # Returns
    /// The rule ID assigned to this rule.
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
    /// let rule_id = compiler.compile_rule(rule_yaml)?;
    /// # Ok::<(), sigma_engine::SigmaError>(())
    /// ```
    pub fn compile_rule(&mut self, rule_yaml: &str) -> Result<RuleId> {
        self.current_selection_map.clear();

        // Use optimized selective YAML parsing for better performance
        let (rule_id, detection_yaml) = self.parse_rule_selective(rule_yaml)?;

        // Parse detection section to extract primitives
        self.parse_detection_value(&detection_yaml)?;

        // Extract condition string and record compiled rule
        let condition = Self::extract_condition_string(&detection_yaml)?;
        let selections = self.current_selection_map.clone();
        self.compiled_rules.push(CompiledRule {
            rule_id,
            selections,
            condition,
        });

        Ok(rule_id)
    }

    /// Parse YAML rule and extract rule ID and detection section.
    ///
    /// # Arguments
    /// * `rule_yaml` - The SIGMA rule in YAML format
    ///
    /// # Returns
    /// A tuple containing (rule_id, detection_value) for further processing.
    fn parse_rule_selective(&mut self, rule_yaml: &str) -> Result<(RuleId, Value)> {
        // Parse YAML using serde_yaml
        let yaml_doc: Value = serde_yaml::from_str(rule_yaml)
            .map_err(|e| SigmaError::YamlError(format!("Failed to parse YAML: {e}")))?;

        // Extract rule ID from YAML document
        let rule_id = self.extract_rule_id_from_yaml(&yaml_doc);

        // Extract detection section
        let detection_value = yaml_doc
            .get("detection")
            .ok_or_else(|| SigmaError::CompilationError("Missing detection section".to_string()))?
            .clone();

        Ok((rule_id, detection_value))
    }

    /// Extract rule ID from YAML document.
    ///
    /// This method extracts the rule ID from the YAML document, falling back
    /// to auto-generated IDs if no ID is specified.
    fn extract_rule_id_from_yaml(&mut self, yaml_doc: &Value) -> RuleId {
        if let Some(id_value) = yaml_doc.get("id") {
            // Try as number first
            if let Some(n) = id_value.as_u64() {
                return n as RuleId;
            }
            // Try as string that can be parsed as number
            if let Some(s) = id_value.as_str() {
                if let Ok(n) = s.parse::<RuleId>() {
                    return n;
                }
            }
        }

        // No ID found or couldn't parse - assign sequential ID
        let new_id = self.next_rule_id;
        self.next_rule_id += 1;
        new_id
    }

    /// Compile multiple SIGMA rules into a complete ruleset.
    ///
    /// This method compiles multiple rules and returns a complete ruleset
    /// that can be used to create a SigmaEngine for execution.
    ///
    /// # Arguments
    /// * `rule_yamls` - Vector of SIGMA rules in YAML format
    ///
    /// # Returns
    /// A compiled ruleset ready for engine creation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::Compiler;
    ///
    /// let mut compiler = Compiler::new();
    /// let rules = vec![
    ///     r#"
    ///     title: Rule 1
    ///     detection:
    ///         selection:
    ///             EventID: 4624
    ///         condition: selection
    ///     "#,
    ///     r#"
    ///     title: Rule 2
    ///     detection:
    ///         selection:
    ///             EventID: 4625
    ///         condition: selection
    ///     "#,
    /// ];
    ///
    /// let ruleset = compiler.compile_ruleset(&rules)?;
    /// # Ok::<(), sigma_engine::SigmaError>(())
    /// ```
    pub fn compile_ruleset(&mut self, rule_yamls: &[&str]) -> Result<CompiledRuleset> {
        // Compile each rule to extract primitives and record rule metadata
        for rule_yaml in rule_yamls {
            self.compile_rule(rule_yaml)?;
        }

        // Return the compiled ruleset
        Ok(CompiledRuleset {
            primitive_map: self.primitive_map.clone(),
            primitives: self.primitives.clone(),
            rules: self.compiled_rules.clone(),
        })
    }

    /// Get the compiled ruleset with all primitives.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::Compiler;
    ///
    /// let compiler = Compiler::new();
    /// let ruleset = compiler.into_ruleset();
    /// assert_eq!(ruleset.primitive_count(), 0);
    /// ```
    pub fn into_ruleset(self) -> CompiledRuleset {
        CompiledRuleset {
            primitive_map: self.primitive_map,
            primitives: self.primitives,
            rules: self.compiled_rules,
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

    /// Parse detection section directly from a detection Value.
    ///
    /// This method processes the detection section without requiring the full YAML document,
    /// providing better performance for selective parsing scenarios.
    /// Extract the condition string from the detection mapping.
    fn extract_condition_string(detection: &Value) -> Result<String> {
        if let Value::Mapping(map) = detection {
            if let Some(cond_val) = map.get(Value::from("condition")) {
                if let Some(s) = cond_val.as_str() {
                    return Ok(s.to_string());
                }
                return Err(SigmaError::CompilationError(
                    "Condition must be a string".to_string(),
                ));
            }
        }
        Err(SigmaError::CompilationError(
            "Missing detection.condition".to_string(),
        ))
    }

    fn parse_detection_value(&mut self, detection: &Value) -> Result<()> {
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
                                "Unsupported field value type for field '{field_name}'"
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

    /// Parse a field name with SIGMA modifiers.
    ///
    /// Examples:
    /// - "Image" -> ("Image", "equals", [])
    /// - "Image|endswith" -> ("Image", "endswith", [])
    /// - "CommandLine|contains" -> ("CommandLine", "contains", [])
    /// - "User|cased" -> ("User", "equals", ["case_sensitive"])
    /// - "Hash|re" -> ("Hash", "regex", [])
    pub fn parse_field_with_modifiers(&self, field_spec: &str) -> (String, String, Vec<String>) {
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
                "range" => match_type = "range".to_string(),
                "cidr" => match_type = "cidr".to_string(),
                "fuzzy" => match_type = "fuzzy".to_string(),
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
    fn test_compile_rule() {
        let mut compiler = Compiler::new();
        let rule_yaml = r#"
title: Test Rule
logsource:
    category: test
detection:
    selection:
        EventID: 4624
    condition: selection
"#;

        let rule_id = compiler.compile_rule(rule_yaml);
        assert!(rule_id.is_ok());
        assert_eq!(rule_id.unwrap(), 0); // Default rule ID
        assert!(compiler.primitive_count() > 0);
    }

    #[test]
    fn test_compile_ruleset() {
        let mut compiler = Compiler::new();
        let rules = vec![
            r#"
title: Rule 1
detection:
    selection:
        EventID: 4624
    condition: selection
"#,
            r#"
title: Rule 2
detection:
    selection:
        EventID: 4625
    condition: selection
"#,
        ];

        let ruleset = compiler.compile_ruleset(&rules);
        assert!(ruleset.is_ok());

        let ruleset = ruleset.unwrap();
        assert!(ruleset.primitive_count() > 0);
        assert!(!ruleset.primitive_map.is_empty());
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
        let ruleset = compiler.into_ruleset();
        assert_eq!(ruleset.primitive_count(), 0);
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
}
