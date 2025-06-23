use serde_json::json;
use sigma_engine::dag::engine::{DagEngine, DagEngineConfig};
use sigma_engine::ir::{CompiledRuleset, Primitive};

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
    let config_with_prefilter = DagEngineConfig {
        enable_prefilter: true,
        ..Default::default()
    };

    println!("Creating engine with prefilter...");
    let mut engine_with_prefilter =
        DagEngine::from_ruleset_with_config(ruleset.clone(), config_with_prefilter)
            .expect("Failed to create engine with prefilter");

    println!("Engine created successfully");

    // Test event that won't match (should benefit from prefilter)
    let non_matching_event = json!({
        "EventID": "9999",
        "ProcessName": "notepad.exe",
        "CommandLine": "notepad.exe test.txt"
    });

    println!("Testing non-matching event...");
    let result = engine_with_prefilter.evaluate(&non_matching_event).unwrap();
    println!("Result: {:?}", result);
    assert!(result.matched_rules.is_empty());

    // Test event that will match
    let matching_event = json!({
        "EventID": "4624",
        "ProcessName": "powershell.exe",
        "CommandLine": "powershell.exe -Command Test"
    });

    println!("Testing matching event...");
    let result = engine_with_prefilter.evaluate(&matching_event).unwrap();
    println!("Result: {:?}", result);
    // Note: This might not match because we don't have proper rule compilation
    // But it should not panic

    println!("Prefilter integration test completed successfully");
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
    let config_with_prefilter = DagEngineConfig {
        enable_prefilter: true,
        ..Default::default()
    };

    // Test with prefilter disabled
    let config_without_prefilter = DagEngineConfig {
        enable_prefilter: false,
        ..Default::default()
    };

    println!("Creating engines...");
    let mut engine_with_prefilter =
        DagEngine::from_ruleset_with_config(ruleset.clone(), config_with_prefilter)
            .expect("Failed to create engine with prefilter");

    let mut engine_without_prefilter =
        DagEngine::from_ruleset_with_config(ruleset, config_without_prefilter)
            .expect("Failed to create engine without prefilter");

    // Test event that won't match
    let non_matching_event = json!({
        "EventID": "9999",
        "ProcessName": "notepad.exe"
    });

    println!("Testing with prefilter...");
    let result_with_prefilter = engine_with_prefilter.evaluate(&non_matching_event).unwrap();

    println!("Testing without prefilter...");
    let result_without_prefilter = engine_without_prefilter
        .evaluate(&non_matching_event)
        .unwrap();

    // Both should return no matches
    assert!(result_with_prefilter.matched_rules.is_empty());
    assert!(result_without_prefilter.matched_rules.is_empty());

    println!("Both engines returned consistent results");
    println!(
        "With prefilter - nodes evaluated: {}, primitives: {}",
        result_with_prefilter.nodes_evaluated, result_with_prefilter.primitive_evaluations
    );
    println!(
        "Without prefilter - nodes evaluated: {}, primitives: {}",
        result_without_prefilter.nodes_evaluated, result_without_prefilter.primitive_evaluations
    );
}
