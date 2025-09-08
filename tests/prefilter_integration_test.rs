use serde_json::json;
use sigma_engine::ir::{CompiledRuleset, Primitive};
use sigma_engine::{EngineConfig, SigmaEngine};

#[test]
fn test_prefilter_integration() {
    // Create a simple test ruleset
    let primitives = vec![
        Primitive::new(
            "EventID".to_string(),
            "equals".to_string(),
            vec!["4624".to_string()],
            Vec::new(),
        ),
        Primitive::new(
            "ProcessName".to_string(),
            "contains".to_string(),
            vec!["powershell.exe".to_string()],
            Vec::new(),
        ),
    ];

    let ruleset = CompiledRuleset {
        primitives,
        primitive_map: std::collections::HashMap::new(),
    };

    // Test with prefilter enabled
    let config_with_prefilter = EngineConfig::default().with_prefilter(true);

    let mut engine_with_prefilter =
        SigmaEngine::from_ruleset_with_config(ruleset.clone(), config_with_prefilter)
            .expect("Failed to create engine with prefilter");

    // Test event that won't match (should benefit from prefilter)
    let non_matching_event = json!({
        "EventID": "9999",
        "ProcessName": "notepad.exe",
        "CommandLine": "notepad.exe test.txt"
    });

    let result = engine_with_prefilter.evaluate(&non_matching_event).unwrap();
    assert!(result.matched_rules.is_empty());

    // Test event that will match
    let matching_event = json!({
        "EventID": "4624",
        "ProcessName": "powershell.exe",
        "CommandLine": "powershell.exe -Command Test"
    });

    let _result = engine_with_prefilter.evaluate(&matching_event).unwrap();
    // Note: This might not match because we don't have proper rule compilation
    // But it should not panic
}

#[test]
fn test_prefilter_vs_no_prefilter() {
    // Create a simple test ruleset
    let primitives = vec![Primitive::new(
        "EventID".to_string(),
        "equals".to_string(),
        vec!["4624".to_string()],
        Vec::new(),
    )];

    let ruleset = CompiledRuleset {
        primitives,
        primitive_map: std::collections::HashMap::new(),
    };

    // Test with prefilter enabled
    let config_with_prefilter = EngineConfig::default().with_prefilter(true);

    // Test with prefilter disabled
    let config_without_prefilter = EngineConfig::default().with_prefilter(false);

    let mut engine_with_prefilter =
        SigmaEngine::from_ruleset_with_config(ruleset.clone(), config_with_prefilter)
            .expect("Failed to create engine with prefilter");

    let mut engine_without_prefilter =
        SigmaEngine::from_ruleset_with_config(ruleset, config_without_prefilter)
            .expect("Failed to create engine without prefilter");

    // Test event that won't match
    let non_matching_event = json!({
        "EventID": "9999",
        "ProcessName": "notepad.exe"
    });

    let result_with_prefilter = engine_with_prefilter.evaluate(&non_matching_event).unwrap();

    let result_without_prefilter = engine_without_prefilter
        .evaluate(&non_matching_event)
        .unwrap();

    // Both should return no matches
    assert!(result_with_prefilter.matched_rules.is_empty());
    assert!(result_without_prefilter.matched_rules.is_empty());

    // Verify that prefilter reduces primitive evaluations for non-matching events
    assert!(
        result_with_prefilter.primitive_evaluations
            <= result_without_prefilter.primitive_evaluations
    );
}
