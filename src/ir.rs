//! Intermediate Representation (IR) for SIGMA rules.
//!
//! This module defines the core data structures used throughout the compilation
//! and execution pipeline, including primitives and compiled rulesets.

use std::collections::HashMap;

pub type PrimitiveId = u32;
pub type RuleId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Primitive {
    pub field: String,
    pub match_type: String,
    pub values: Vec<String>,
    pub modifiers: Vec<String>,
}

impl Primitive {
    pub fn new(
        field: String,
        match_type: String,
        values: Vec<String>,
        modifiers: Vec<String>,
    ) -> Self {
        Self {
            field,
            match_type,
            values,
            modifiers,
        }
    }

    pub fn new_static(
        field: &'static str,
        match_type: &'static str,
        values: &[&'static str],
        modifiers: &[&'static str],
    ) -> Self {
        Self {
            field: field.to_string(),
            match_type: match_type.to_string(),
            values: values.iter().map(|&s| s.to_string()).collect(),
            modifiers: modifiers.iter().map(|&s| s.to_string()).collect(),
        }
    }

    /// Create a new primitive from string slices.
    pub fn from_strs(field: &str, match_type: &str, values: &[&str], modifiers: &[&str]) -> Self {
        Self {
            field: field.to_string(),
            match_type: match_type.to_string(),
            values: values.iter().map(|&v| v.to_string()).collect(),
            modifiers: modifiers.iter().map(|&m| m.to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledRuleset {
    pub primitive_map: HashMap<Primitive, PrimitiveId>,
    pub primitives: Vec<Primitive>,
}

impl CompiledRuleset {
    pub fn new() -> Self {
        Self {
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

        assert_eq!(prim.field.as_str(), "EventID");
        assert_eq!(prim.match_type.as_str(), "equals");
        assert_eq!(prim.values.len(), 1);
        assert_eq!(prim.values[0].as_str(), "4624");
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

        assert_eq!(prim.field.as_str(), "EventID");
        assert_eq!(prim.match_type.as_str(), "equals");
        assert_eq!(prim.values.len(), 2);
        assert_eq!(prim.values[0].as_str(), "4624");
        assert_eq!(prim.values[1].as_str(), "4625");
        assert_eq!(prim.modifiers.len(), 1);
        assert_eq!(prim.modifiers[0].as_str(), "case_insensitive");
    }

    #[test]
    fn test_primitive_from_strs_creation() {
        let prim = Primitive::from_strs(
            "EventID",
            "equals",
            &["4624", "4625"],
            &["case_insensitive"],
        );

        assert_eq!(prim.field, "EventID");
        assert_eq!(prim.match_type, "equals");
        assert_eq!(prim.values.len(), 2);
        assert_eq!(prim.values[0], "4624");
        assert_eq!(prim.values[1], "4625");
        assert_eq!(prim.modifiers.len(), 1);
        assert_eq!(prim.modifiers[0], "case_insensitive");
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

    #[test]
    fn test_compiled_ruleset_default() {
        let ruleset = CompiledRuleset::default();
        assert_eq!(ruleset.primitive_count(), 0);
        assert!(ruleset.primitive_map.is_empty());
        assert!(ruleset.primitives.is_empty());
    }

    #[test]
    fn test_primitive_equality_and_hashing() {
        let prim1 = Primitive::new(
            "EventID".to_string(),
            "equals".to_string(),
            vec!["4624".to_string()],
            vec!["case_insensitive".to_string()],
        );

        let prim2 = Primitive::new(
            "EventID".to_string(),
            "equals".to_string(),
            vec!["4624".to_string()],
            vec!["case_insensitive".to_string()],
        );

        let prim3 = Primitive::new(
            "EventID".to_string(),
            "equals".to_string(),
            vec!["4625".to_string()], // Different value
            vec!["case_insensitive".to_string()],
        );

        // Test equality
        assert_eq!(prim1, prim2);
        assert_ne!(prim1, prim3);
        assert_ne!(prim2, prim3);

        // Test that equal primitives can be used as HashMap keys
        let mut map = HashMap::new();
        map.insert(prim1.clone(), 0);
        map.insert(prim2.clone(), 1); // Should overwrite the first entry
        map.insert(prim3.clone(), 2);

        assert_eq!(map.len(), 2); // Only 2 unique primitives
        assert_eq!(map.get(&prim1), Some(&1)); // prim2 overwrote prim1's value
        assert_eq!(map.get(&prim2), Some(&1));
        assert_eq!(map.get(&prim3), Some(&2));
    }

    #[test]
    fn test_primitive_clone() {
        let prim = Primitive::new(
            "EventID".to_string(),
            "equals".to_string(),
            vec!["4624".to_string(), "4625".to_string()],
            vec!["case_insensitive".to_string()],
        );

        let cloned = prim.clone();
        assert_eq!(prim, cloned);
        assert_eq!(prim.field, cloned.field);
        assert_eq!(prim.match_type, cloned.match_type);
        assert_eq!(prim.values, cloned.values);
        assert_eq!(prim.modifiers, cloned.modifiers);
    }

    #[test]
    fn test_primitive_debug_format() {
        let prim = Primitive::new(
            "EventID".to_string(),
            "equals".to_string(),
            vec!["4624".to_string()],
            vec!["case_insensitive".to_string()],
        );

        let debug_str = format!("{prim:?}");
        assert!(debug_str.contains("EventID"));
        assert!(debug_str.contains("equals"));
        assert!(debug_str.contains("4624"));
        assert!(debug_str.contains("case_insensitive"));
    }

    #[test]
    fn test_primitive_empty_values_and_modifiers() {
        let prim = Primitive::new(
            "EventID".to_string(),
            "exists".to_string(),
            vec![], // Empty values
            vec![], // Empty modifiers
        );

        assert_eq!(prim.field, "EventID");
        assert_eq!(prim.match_type, "exists");
        assert!(prim.values.is_empty());
        assert!(prim.modifiers.is_empty());
    }

    #[test]
    fn test_primitive_multiple_values_and_modifiers() {
        let prim = Primitive::new(
            "EventID".to_string(),
            "equals".to_string(),
            vec!["4624".to_string(), "4625".to_string(), "4648".to_string()],
            vec!["case_insensitive".to_string(), "trim".to_string()],
        );

        assert_eq!(prim.values.len(), 3);
        assert_eq!(prim.values[0], "4624");
        assert_eq!(prim.values[1], "4625");
        assert_eq!(prim.values[2], "4648");

        assert_eq!(prim.modifiers.len(), 2);
        assert_eq!(prim.modifiers[0], "case_insensitive");
        assert_eq!(prim.modifiers[1], "trim");
    }

    #[test]
    fn test_compiled_ruleset_multiple_primitives() {
        let mut ruleset = CompiledRuleset::new();

        let prim1 = Primitive::new_static("EventID", "equals", &["4624"], &[]);
        let prim2 = Primitive::new_static("LogonType", "equals", &["2"], &[]);
        let prim3 = Primitive::new_static(
            "TargetUserName",
            "contains",
            &["admin"],
            &["case_insensitive"],
        );

        ruleset.primitive_map.insert(prim1.clone(), 0);
        ruleset.primitive_map.insert(prim2.clone(), 1);
        ruleset.primitive_map.insert(prim3.clone(), 2);

        ruleset.primitives.push(prim1.clone());
        ruleset.primitives.push(prim2.clone());
        ruleset.primitives.push(prim3.clone());

        assert_eq!(ruleset.primitive_count(), 3);
        assert_eq!(ruleset.get_primitive(0), Some(&prim1));
        assert_eq!(ruleset.get_primitive(1), Some(&prim2));
        assert_eq!(ruleset.get_primitive(2), Some(&prim3));
        assert_eq!(ruleset.get_primitive(3), None);
        assert_eq!(ruleset.get_primitive(999), None);
    }

    #[test]
    fn test_compiled_ruleset_clone() {
        let mut ruleset = CompiledRuleset::new();
        let prim = Primitive::new_static("EventID", "equals", &["4624"], &[]);
        ruleset.primitive_map.insert(prim.clone(), 0);
        ruleset.primitives.push(prim.clone());

        let cloned = ruleset.clone();
        assert_eq!(cloned.primitive_count(), 1);
        assert_eq!(cloned.get_primitive(0), Some(&prim));
        assert_eq!(cloned.primitive_map.len(), 1);
    }

    #[test]
    fn test_compiled_ruleset_debug_format() {
        let mut ruleset = CompiledRuleset::new();
        let prim = Primitive::new_static("EventID", "equals", &["4624"], &[]);
        ruleset.primitive_map.insert(prim.clone(), 0);
        ruleset.primitives.push(prim);

        let debug_str = format!("{ruleset:?}");
        assert!(debug_str.contains("CompiledRuleset"));
        assert!(debug_str.contains("primitive_map"));
        assert!(debug_str.contains("primitives"));
    }

    #[test]
    fn test_primitive_id_and_rule_id_types() {
        // Test that PrimitiveId and RuleId are the expected types
        let primitive_id: PrimitiveId = 42;
        let rule_id: RuleId = 123;

        assert_eq!(primitive_id, 42u32);
        assert_eq!(rule_id, 123u32);

        // Test that they can be used in collections
        let primitive_ids = [0, 1, 2];
        let rule_ids = [100, 200, 300];

        assert_eq!(primitive_ids.len(), 3);
        assert_eq!(rule_ids.len(), 3);
    }
}
