//! Basic tests for the matcher module functionality.

use serde_yaml::Value;
use sigma_engine::{EventContext, MatcherBuilder, Primitive};

fn create_simple_event() -> Value {
    serde_yaml::from_str(
        r#"
EventID: "4624"
LogonType: "2"
Message: "Login successful"
"#,
    )
    .unwrap()
}

#[test]
fn test_matcher_builder_creation() {
    let builder = MatcherBuilder::new();
    assert!(builder.match_type_count() > 0);
    assert!(builder.has_match_type("equals"));
    assert!(builder.has_match_type("contains"));
}

#[test]
fn test_primitive_compilation() {
    let primitives = vec![Primitive::new_static("EventID", "equals", &["4624"], &[])];

    let result = MatcherBuilder::new().compile(&primitives);
    assert!(result.is_ok());

    let matcher = result.unwrap();
    assert_eq!(matcher.primitive_count(), 1);
}

#[test]
fn test_event_context_basic() {
    let event = create_simple_event();
    let context = EventContext::new(&event);

    let event_id = context.get_field("EventID").unwrap();
    assert_eq!(event_id, Some("4624".to_string()));

    let logon_type = context.get_field("LogonType").unwrap();
    assert_eq!(logon_type, Some("2".to_string()));

    let nonexistent = context.get_field("NonExistent").unwrap();
    assert_eq!(nonexistent, None);
}

#[test]
fn test_field_caching() {
    let event = create_simple_event();
    let context = EventContext::new(&event);

    assert_eq!(context.cache_size(), 0);

    let _result1 = context.get_field("EventID").unwrap();
    assert_eq!(context.cache_size(), 1);

    let _result2 = context.get_field("EventID").unwrap();
    assert_eq!(context.cache_size(), 1); // Should not increase

    context.clear_cache();
    assert_eq!(context.cache_size(), 0);
}

#[test]
fn test_basic_evaluation() {
    let primitives = vec![
        Primitive::new_static("EventID", "equals", &["4624"], &[]),
        Primitive::new_static("LogonType", "equals", &["2"], &[]),
        Primitive::new_static("NonExistent", "equals", &["value"], &[]),
    ];

    let matcher = MatcherBuilder::new().compile(&primitives).unwrap();
    let event = create_simple_event();

    let results = matcher.evaluate(&event).unwrap();
    assert_eq!(results.len(), 3);
    assert!(results[0]); // EventID should match
    assert!(results[1]); // LogonType should match
    assert!(!results[2]); // NonExistent should not match
}

#[test]
fn test_evaluate_into_zero_allocation() {
    let primitives = vec![Primitive::new_static("EventID", "equals", &["4624"], &[])];

    let matcher = MatcherBuilder::new().compile(&primitives).unwrap();
    let event = create_simple_event();

    let mut results = vec![false; 1];
    matcher.evaluate_into(&event, &mut results).unwrap();
    assert!(results[0]);
}

#[test]
fn test_contains_matching() {
    let primitives = vec![
        Primitive::new_static("Message", "contains", &["successful"], &[]),
        Primitive::new_static("Message", "contains", &["failed"], &[]),
    ];

    let matcher = MatcherBuilder::new().compile(&primitives).unwrap();
    let event = create_simple_event();

    let results = matcher.evaluate(&event).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0]); // Should contain "successful"
    assert!(!results[1]); // Should not contain "failed"
}

#[test]
fn test_case_sensitivity() {
    let primitives = vec![
        Primitive::new_static("Message", "equals", &["login successful"], &[]),
        Primitive::new_static(
            "Message",
            "equals",
            &["login successful"],
            &["case_sensitive"],
        ),
    ];

    let matcher = MatcherBuilder::new().compile(&primitives).unwrap();
    let event = create_simple_event();

    let results = matcher.evaluate(&event).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0]); // Case-insensitive should match
    assert!(!results[1]); // Case-sensitive should not match (different case)
}

#[test]
fn test_multiple_values() {
    let primitives = vec![Primitive::new_static(
        "EventID",
        "equals",
        &["4624", "4625", "4634"],
        &[],
    )];

    let matcher = MatcherBuilder::new().compile(&primitives).unwrap();
    let event = create_simple_event();

    let results = matcher.evaluate(&event).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0]); // Should match first value "4624"
}

#[test]
fn test_matcher_statistics() {
    let primitives = vec![
        Primitive::new_static("EventID", "equals", &["4624", "4625"], &[]),
        Primitive::new_static("LogonType", "equals", &["2"], &[]),
    ];

    let matcher = MatcherBuilder::new().compile(&primitives).unwrap();
    let stats = matcher.statistics();

    assert_eq!(stats.total_primitives, 2);
    assert_eq!(stats.primitives_with_modifiers, 0);
    assert_eq!(stats.total_values, 3); // 2 + 1
    assert_eq!(stats.literal_only_primitives, 2);
    assert!(stats.memory_usage > 0);
}

#[test]
fn test_unsupported_match_type() {
    let primitives = vec![Primitive::new_static(
        "EventID",
        "unsupported",
        &["4624"],
        &[],
    )];

    let result = MatcherBuilder::new().compile(&primitives);
    assert!(result.is_err());
}

#[test]
fn test_custom_match_function() {
    let mut builder = MatcherBuilder::new();

    builder.register_match("always_true", |_field, _values, _modifiers| Ok(true));

    let primitives = vec![Primitive::new_static(
        "AnyField",
        "always_true",
        &["any_value"],
        &[],
    )];

    let matcher = builder.compile(&primitives).unwrap();
    let event = create_simple_event();

    let results = matcher.evaluate(&event).unwrap();
    assert!(results[0]);
}

#[test]
fn test_custom_modifier() {
    let mut builder = MatcherBuilder::new();

    builder.register_modifier("uppercase", |input| Ok(input.to_uppercase()));

    let primitives = vec![Primitive::new_static(
        "Message",
        "equals",
        &["LOGIN SUCCESSFUL"],
        &["uppercase"],
    )];

    let matcher = builder.compile(&primitives).unwrap();
    let event = create_simple_event();

    let results = matcher.evaluate(&event).unwrap();
    assert!(results[0]); // "Login successful" -> "LOGIN SUCCESSFUL" -> matches
}
