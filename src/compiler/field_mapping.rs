//! Field mapping configuration for normalizing field names.
//!
//! This module provides the [`FieldMapping`] struct which supports the SIGMA taxonomy
//! and custom field mappings according to the SIGMA specification.

use std::collections::HashMap;

/// Field mapping configuration for normalizing field names.
/// This supports the SIGMA taxonomy and custom field mappings.
///
/// According to the SIGMA specification, field mappings should be:
/// - Rule-driven: The SIGMA rule itself defines what fields it uses
/// - Taxonomy-based: Field mappings come from the taxonomy system
/// - Configurable: Field mappings should be configurable per deployment
///
/// # Examples
///
/// ```rust
/// use sigma_engine::compiler::FieldMapping;
/// use std::collections::HashMap;
///
/// // Create a new field mapping with default taxonomy
/// let mut mapping = FieldMapping::new();
/// assert_eq!(mapping.taxonomy(), "sigma");
///
/// // Add custom field mappings
/// mapping.add_mapping("Event_ID".to_string(), "EventID".to_string());
/// mapping.add_mapping("Process_Name".to_string(), "Image".to_string());
///
/// // Normalize field names
/// assert_eq!(mapping.normalize_field("Event_ID"), "EventID");
/// assert_eq!(mapping.normalize_field("Process_Name"), "Image");
/// assert_eq!(mapping.normalize_field("UnmappedField"), "UnmappedField");
/// ```
#[derive(Debug, Clone)]
pub struct FieldMapping {
    field_map: HashMap<String, String>,
    taxonomy: String,
}

impl FieldMapping {
    /// Create a new empty field mapping using the default SIGMA taxonomy.
    ///
    /// Field mappings should be configured based on the deployment environment
    /// and the specific taxonomy being used.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::compiler::FieldMapping;
    ///
    /// let mapping = FieldMapping::new();
    /// assert_eq!(mapping.taxonomy(), "sigma");
    /// assert_eq!(mapping.mappings().len(), 0);
    /// ```
    pub fn new() -> Self {
        Self {
            field_map: HashMap::new(),
            taxonomy: "sigma".to_string(),
        }
    }

    /// Create a new field mapping with a specific taxonomy.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::compiler::FieldMapping;
    ///
    /// let mapping = FieldMapping::with_taxonomy("custom".to_string());
    /// assert_eq!(mapping.taxonomy(), "custom");
    /// ```
    pub fn with_taxonomy(taxonomy: String) -> Self {
        Self {
            field_map: HashMap::new(),
            taxonomy,
        }
    }

    /// Load field mappings from a taxonomy configuration.
    ///
    /// This would typically be loaded from a configuration file or database
    /// based on the deployment environment.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::compiler::FieldMapping;
    /// use std::collections::HashMap;
    ///
    /// let mut mapping = FieldMapping::new();
    /// let mut taxonomy_mappings = HashMap::new();
    /// taxonomy_mappings.insert("Event_ID".to_string(), "EventID".to_string());
    /// taxonomy_mappings.insert("Process_Name".to_string(), "Image".to_string());
    ///
    /// mapping.load_taxonomy_mappings(taxonomy_mappings);
    /// assert_eq!(mapping.mappings().len(), 2);
    /// ```
    pub fn load_taxonomy_mappings(&mut self, mappings: HashMap<String, String>) {
        self.field_map.extend(mappings);
    }

    /// Add a custom field mapping.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::compiler::FieldMapping;
    ///
    /// let mut mapping = FieldMapping::new();
    /// mapping.add_mapping("custom_field".to_string(), "StandardField".to_string());
    /// assert!(mapping.has_mapping("custom_field"));
    /// ```
    pub fn add_mapping(&mut self, source_field: String, target_field: String) {
        self.field_map.insert(source_field, target_field);
    }

    /// Get the current taxonomy name.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::compiler::FieldMapping;
    ///
    /// let mapping = FieldMapping::with_taxonomy("custom".to_string());
    /// assert_eq!(mapping.taxonomy(), "custom");
    /// ```
    pub fn taxonomy(&self) -> &str {
        &self.taxonomy
    }

    /// Set the taxonomy name.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::compiler::FieldMapping;
    ///
    /// let mut mapping = FieldMapping::new();
    /// mapping.set_taxonomy("custom".to_string());
    /// assert_eq!(mapping.taxonomy(), "custom");
    /// ```
    pub fn set_taxonomy(&mut self, taxonomy: String) {
        self.taxonomy = taxonomy;
    }

    /// Normalize a field name according to the mapping.
    ///
    /// Returns the normalized field name, or the original if no mapping exists.
    ///
    /// According to SIGMA spec, if no mapping exists, the field name should be used as-is
    /// from the rule, following the principle that rules define their own field usage.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::compiler::FieldMapping;
    ///
    /// let mut mapping = FieldMapping::new();
    /// mapping.add_mapping("Event_ID".to_string(), "EventID".to_string());
    ///
    /// assert_eq!(mapping.normalize_field("Event_ID"), "EventID");
    /// assert_eq!(mapping.normalize_field("UnmappedField"), "UnmappedField");
    /// ```
    pub fn normalize_field(&self, field_name: &str) -> String {
        self.field_map
            .get(field_name)
            .cloned()
            .unwrap_or_else(|| field_name.to_string())
    }

    /// Check if a field mapping exists for the given field name.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::compiler::FieldMapping;
    ///
    /// let mut mapping = FieldMapping::new();
    /// mapping.add_mapping("Event_ID".to_string(), "EventID".to_string());
    ///
    /// assert!(mapping.has_mapping("Event_ID"));
    /// assert!(!mapping.has_mapping("UnmappedField"));
    /// ```
    pub fn has_mapping(&self, field_name: &str) -> bool {
        self.field_map.contains_key(field_name)
    }

    /// Get all configured field mappings.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sigma_engine::compiler::FieldMapping;
    ///
    /// let mut mapping = FieldMapping::new();
    /// mapping.add_mapping("Event_ID".to_string(), "EventID".to_string());
    ///
    /// assert_eq!(mapping.mappings().len(), 1);
    /// assert_eq!(mapping.mappings().get("Event_ID"), Some(&"EventID".to_string()));
    /// ```
    pub fn mappings(&self) -> &HashMap<String, String> {
        &self.field_map
    }
}

impl Default for FieldMapping {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_mapping_creation() {
        let mapping = FieldMapping::new();
        assert_eq!(mapping.taxonomy(), "sigma");
        assert_eq!(mapping.mappings().len(), 0);
    }

    #[test]
    fn test_field_mapping_with_taxonomy() {
        let mapping = FieldMapping::with_taxonomy("custom".to_string());
        assert_eq!(mapping.taxonomy(), "custom");
    }

    #[test]
    fn test_add_mapping() {
        let mut mapping = FieldMapping::new();
        mapping.add_mapping("Event_ID".to_string(), "EventID".to_string());

        assert!(mapping.has_mapping("Event_ID"));
        assert_eq!(mapping.normalize_field("Event_ID"), "EventID");
    }

    #[test]
    fn test_load_taxonomy_mappings() {
        let mut mapping = FieldMapping::new();
        let mut taxonomy_mappings = HashMap::new();
        taxonomy_mappings.insert("Event_ID".to_string(), "EventID".to_string());
        taxonomy_mappings.insert("Process_Name".to_string(), "Image".to_string());

        mapping.load_taxonomy_mappings(taxonomy_mappings);
        assert_eq!(mapping.mappings().len(), 2);
        assert_eq!(mapping.normalize_field("Event_ID"), "EventID");
        assert_eq!(mapping.normalize_field("Process_Name"), "Image");
    }

    #[test]
    fn test_normalize_field_unmapped() {
        let mapping = FieldMapping::new();
        assert_eq!(mapping.normalize_field("UnmappedField"), "UnmappedField");
    }

    #[test]
    fn test_set_taxonomy() {
        let mut mapping = FieldMapping::new();
        mapping.set_taxonomy("custom".to_string());
        assert_eq!(mapping.taxonomy(), "custom");
    }

    #[test]
    fn test_default_implementation() {
        let mapping = FieldMapping::default();
        assert_eq!(mapping.taxonomy(), "sigma");
        assert_eq!(mapping.mappings().len(), 0);
    }
}
