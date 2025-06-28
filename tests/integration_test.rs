//! Integration tests for the SIGMA Engine crate.
//!
//! These tests verify that the overall structure compiles and basic
//! functionality works as expected, with comprehensive coverage for
//! multiple rules compilation bug detection.

use serde_json::json;
use sigma_engine::{Compiler, DagEngineConfig, FieldMapping, Primitive, SigmaEngine};

#[test]
fn test_crate_structure_compiles() {
    // Test that we can create instances of the main types
    let _compiler = Compiler::new();
    // DAG engine is available through SigmaEngine

    // Test that we can create IR types
    let _primitive = Primitive::new_static("EventID", "equals", &["4624"], &[]);
}

#[test]
fn test_basic_dag_execution() {
    // Test basic DAG functionality through SigmaEngine
    // Test that we can create a compiler
    let compiler = Compiler::new();
    let ruleset = compiler.into_ruleset();
    assert_eq!(ruleset.primitive_count(), 0);
}

#[test]
fn test_primitive_equality_and_hashing() {
    use std::collections::HashMap;

    let prim1 = Primitive::new_static("EventID", "equals", &["4624"], &[]);
    let prim2 = Primitive::new_static("EventID", "equals", &["4624"], &[]);
    let prim3 = Primitive::new_static("EventID", "equals", &["4625"], &[]);

    // Test equality
    assert_eq!(prim1, prim2);
    assert_ne!(prim1, prim3);

    // Test that they can be used as HashMap keys
    let mut map = HashMap::new();
    map.insert(prim1.clone(), 0);
    map.insert(prim3.clone(), 1);

    assert_eq!(map.get(&prim2), Some(&0)); // prim2 equals prim1
    assert_eq!(map.len(), 2);
}

#[test]
fn test_compiler_basic_functionality() {
    let compiler = Compiler::new();
    let ruleset = compiler.into_ruleset();

    // Empty compiler should produce empty ruleset
    assert_eq!(ruleset.primitive_count(), 0);
}

/// Test multiple rules compilation bug - this is the critical test case
/// that should expose the bug where multiple rules compiled together
/// don't match, but work individually.
#[test]
fn test_multiple_rules_compilation_bug() {
    // Create field mapping for ProcessImage -> Image, ProcessCommandLine -> CommandLine
    let mut field_mapping = FieldMapping::new();
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());

    // Rule 1: Process creation with specific image
    let rule1 = r#"
title: Test Rule 1
id: rule-001
detection:
    selection:
        ProcessImage|endswith: '\notepad.exe'
    condition: selection
"#;

    // Rule 2: Process creation with command line
    let rule2 = r#"
title: Test Rule 2
id: rule-002
detection:
    selection:
        ProcessCommandLine|contains: 'test'
    condition: selection
"#;

    // Test event that should match both rules
    let test_event = json!({
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe test.txt"
    });

    // Test individual rule compilation - both should work
    let compiler1 = Compiler::with_field_mapping(field_mapping.clone());
    let config1 = DagEngineConfig::default();
    let mut engine1 = SigmaEngine::from_rules_with_compiler(&[rule1], compiler1, config1)
        .expect("Failed to create engine 1");
    let result1 = engine1
        .evaluate(&test_event)
        .expect("Failed to evaluate rule 1");
    println!("Rule 1 individual result: {result1:?}");
    assert!(
        !result1.matched_rules.is_empty(),
        "Rule 1 should match individually"
    );

    let compiler2 = Compiler::with_field_mapping(field_mapping.clone());
    let config2 = DagEngineConfig::default();
    let mut engine2 = SigmaEngine::from_rules_with_compiler(&[rule2], compiler2, config2)
        .expect("Failed to create engine 2");
    let result2 = engine2
        .evaluate(&test_event)
        .expect("Failed to evaluate rule 2");
    println!("Rule 2 individual result: {result2:?}");
    assert!(
        !result2.matched_rules.is_empty(),
        "Rule 2 should match individually"
    );

    // Test multiple rules compilation - THIS IS WHERE THE BUG OCCURS
    let compiler_multi = Compiler::with_field_mapping(field_mapping);
    let config_multi = DagEngineConfig::default();
    let mut engine_multi =
        SigmaEngine::from_rules_with_compiler(&[rule1, rule2], compiler_multi, config_multi)
            .expect("Failed to create multi engine");
    let result_multi = engine_multi
        .evaluate(&test_event)
        .expect("Failed to evaluate multiple rules");
    println!("Multiple rules result: {result_multi:?}");

    // This assertion should pass but currently fails due to the bug
    assert_eq!(
        result_multi.matched_rules.len(),
        2,
        "Both rules should match when compiled together. Got: {:?}",
        result_multi.matched_rules
    );
}

/// Test to confirm the rule ID collision bug
#[test]
fn test_rule_id_collision_bug() {
    // Rule with string ID that can't be parsed as number
    let rule1 = r#"
title: Test Rule 1
id: rule-001
detection:
    selection:
        EventID: 4688
    condition: selection
"#;

    // Rule with string ID that can't be parsed as number
    let rule2 = r#"
title: Test Rule 2
id: rule-002
detection:
    selection:
        EventID: 4689
    condition: selection
"#;

    // Test multiple rules compilation to see the rule_results mapping
    let mut compiler_multi = Compiler::new();
    let dag_multi = compiler_multi
        .compile_rules_to_dag(&[rule1, rule2])
        .expect("Failed to compile multiple rules");
    println!(
        "Multiple rules DAG rule_results: {:?}",
        dag_multi.rule_results
    );

    // The bug is now fixed: both rules get unique IDs, so two entries in rule_results
    assert_eq!(
        dag_multi.rule_results.len(),
        2,
        "Bug fixed: both rules have unique IDs"
    );
}

/// Test multiple rules with different field types and modifiers
#[test]
fn test_multiple_rules_different_fields() {
    let mut field_mapping = FieldMapping::new();
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());
    field_mapping.add_mapping("EventID".to_string(), "EventID".to_string());

    let rule1 = r#"
title: EventID Rule
id: rule-eventid
detection:
    selection:
        EventID: 4688
    condition: selection
"#;

    let rule2 = r#"
title: Image Rule
id: rule-image
detection:
    selection:
        ProcessImage|endswith: '\cmd.exe'
    condition: selection
"#;

    let rule3 = r#"
title: CommandLine Rule
id: rule-cmdline
detection:
    selection:
        ProcessCommandLine|contains: 'whoami'
    condition: selection
"#;

    // Event that matches all three rules
    let test_event = json!({
        "EventID": 4688,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami"
    });

    // Test individual compilation
    for (rule, rule_name) in [
        (rule1, "EventID rule"),
        (rule2, "Image rule"),
        (rule3, "CommandLine rule"),
    ] {
        let compiler = Compiler::with_field_mapping(field_mapping.clone());
        let config = DagEngineConfig::default();
        let mut engine = SigmaEngine::from_rules_with_compiler(&[rule], compiler, config)
            .unwrap_or_else(|_| panic!("Failed to create engine for {rule_name}"));
        let result = engine
            .evaluate(&test_event)
            .unwrap_or_else(|_| panic!("Failed to evaluate {rule_name}"));
        assert!(
            !result.matched_rules.is_empty(),
            "{rule_name} should match individually"
        );
    }

    // Test multiple rules compilation
    let compiler_multi = Compiler::with_field_mapping(field_mapping);
    let config_multi = DagEngineConfig::default();
    let mut engine_multi =
        SigmaEngine::from_rules_with_compiler(&[rule1, rule2, rule3], compiler_multi, config_multi)
            .expect("Failed to create multi engine");
    let result_multi = engine_multi
        .evaluate(&test_event)
        .expect("Failed to evaluate multiple rules");

    assert_eq!(
        result_multi.matched_rules.len(),
        3,
        "All three rules should match when compiled together. Got: {:?}",
        result_multi.matched_rules
    );
}

/// Test multiple rules with AND conditions
#[test]
fn test_multiple_rules_and_conditions() {
    let mut field_mapping = FieldMapping::new();
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());

    let rule1 = r#"
title: AND Rule 1
id: rule-and-1
detection:
    selection_image:
        ProcessImage|endswith: '\powershell.exe'
    selection_cmdline:
        ProcessCommandLine|contains: 'Invoke'
    condition: selection_image and selection_cmdline
"#;

    let rule2 = r#"
title: AND Rule 2
id: rule-and-2
detection:
    selection_image:
        ProcessImage|endswith: '\cmd.exe'
    selection_cmdline:
        ProcessCommandLine|contains: 'echo'
    condition: selection_image and selection_cmdline
"#;

    // Event that matches rule1
    let event1 = json!({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -Command Invoke-WebRequest"
    });

    // Event that matches rule2
    let event2 = json!({
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c echo hello"
    });

    // Event that matches neither
    let event3 = json!({
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe test.txt"
    });

    // Test multiple rules compilation
    let compiler = Compiler::with_field_mapping(field_mapping);
    let config = DagEngineConfig::default();
    let mut engine = SigmaEngine::from_rules_with_compiler(&[rule1, rule2], compiler, config)
        .expect("Failed to create engine");

    // Test event1 - should match rule1 only
    let result1 = engine.evaluate(&event1).expect("Failed to evaluate event1");
    assert_eq!(
        result1.matched_rules.len(),
        1,
        "Event1 should match exactly one rule"
    );

    // Test event2 - should match rule2 only
    let result2 = engine.evaluate(&event2).expect("Failed to evaluate event2");
    assert_eq!(
        result2.matched_rules.len(),
        1,
        "Event2 should match exactly one rule"
    );

    // Test event3 - should match no rules
    let result3 = engine.evaluate(&event3).expect("Failed to evaluate event3");
    assert_eq!(
        result3.matched_rules.len(),
        0,
        "Event3 should match no rules"
    );
}

/// Test multiple rules with OR conditions
#[test]
fn test_multiple_rules_or_conditions() {
    let mut field_mapping = FieldMapping::new();
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());

    let rule1 = r#"
title: OR Rule 1
id: rule-or-1
detection:
    selection_image:
        ProcessImage|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
    condition: selection_image
"#;

    let rule2 = r#"
title: OR Rule 2
id: rule-or-2
detection:
    selection_cmdline:
        ProcessCommandLine|contains:
            - 'test'
            - 'debug'
    condition: selection_cmdline
"#;

    // Event that matches both rules
    let event_both = json!({
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c test.bat"
    });

    // Event that matches rule1 only
    let event_rule1 = json!({
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -Command Get-Process"
    });

    // Event that matches rule2 only
    let event_rule2 = json!({
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "CommandLine": "notepad.exe debug.log"
    });

    // Test individual rule first to debug
    let compiler_rule1 = Compiler::with_field_mapping(field_mapping.clone());
    let config_rule1 = DagEngineConfig::default();
    let mut engine_rule1 =
        SigmaEngine::from_rules_with_compiler(&[rule1], compiler_rule1, config_rule1)
            .expect("Failed to create rule1 engine");
    let result_rule1_individual = engine_rule1
        .evaluate(&event_rule1)
        .expect("Failed to evaluate rule1 individually");
    println!("Rule1 individual result: {result_rule1_individual:?}");

    // Test multiple rules compilation
    let compiler = Compiler::with_field_mapping(field_mapping);
    let config = DagEngineConfig::default();
    let mut engine = SigmaEngine::from_rules_with_compiler(&[rule1, rule2], compiler, config)
        .expect("Failed to create engine");

    // Test event that matches both rules
    let result_both = engine
        .evaluate(&event_both)
        .expect("Failed to evaluate event_both");
    assert_eq!(
        result_both.matched_rules.len(),
        2,
        "Event should match both rules"
    );

    // Test event that matches rule1 only
    let result_rule1 = engine
        .evaluate(&event_rule1)
        .expect("Failed to evaluate event_rule1");
    assert_eq!(
        result_rule1.matched_rules.len(),
        1,
        "Event should match rule1 only"
    );

    // Test event that matches rule2 only
    let result_rule2 = engine
        .evaluate(&event_rule2)
        .expect("Failed to evaluate event_rule2");
    assert_eq!(
        result_rule2.matched_rules.len(),
        1,
        "Event should match rule2 only"
    );
}

/// Test multiple rules with shared primitives (optimization test)
#[test]
fn test_multiple_rules_shared_primitives() {
    let mut field_mapping = FieldMapping::new();
    field_mapping.add_mapping("EventID".to_string(), "EventID".to_string());
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());

    // Both rules share the EventID primitive
    let rule1 = r#"
title: Shared Primitive Rule 1
id: rule-shared-1
detection:
    selection:
        EventID: 4688
        ProcessImage|endswith: '\notepad.exe'
    condition: selection
"#;

    let rule2 = r#"
title: Shared Primitive Rule 2
id: rule-shared-2
detection:
    selection:
        EventID: 4688
        ProcessImage|endswith: '\calc.exe'
    condition: selection
"#;

    // Event that matches rule1
    let event1 = json!({
        "EventID": 4688,
        "Image": "C:\\Windows\\System32\\notepad.exe"
    });

    // Event that matches rule2
    let event2 = json!({
        "EventID": 4688,
        "Image": "C:\\Windows\\System32\\calc.exe"
    });

    // Event that matches neither (wrong EventID)
    let event3 = json!({
        "EventID": 4689,
        "Image": "C:\\Windows\\System32\\notepad.exe"
    });

    // Test multiple rules compilation
    let compiler = Compiler::with_field_mapping(field_mapping);
    let config = DagEngineConfig::default();
    let mut engine = SigmaEngine::from_rules_with_compiler(&[rule1, rule2], compiler, config)
        .expect("Failed to create engine");

    // Test events
    let result1 = engine.evaluate(&event1).expect("Failed to evaluate event1");
    assert_eq!(
        result1.matched_rules.len(),
        1,
        "Event1 should match rule1 only"
    );

    let result2 = engine.evaluate(&event2).expect("Failed to evaluate event2");
    assert_eq!(
        result2.matched_rules.len(),
        1,
        "Event2 should match rule2 only"
    );

    let result3 = engine.evaluate(&event3).expect("Failed to evaluate event3");
    assert_eq!(
        result3.matched_rules.len(),
        0,
        "Event3 should match no rules"
    );
}

/// Test multiple rules with complex nested conditions
#[test]
fn test_multiple_rules_complex_conditions() {
    let mut field_mapping = FieldMapping::new();
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());
    field_mapping.add_mapping("ParentProcessImage".to_string(), "ParentImage".to_string());

    let rule1 = r#"
title: Complex Rule 1
id: rule-complex-1
detection:
    selection_process:
        ProcessImage|endswith: '\powershell.exe'
    selection_parent:
        ParentProcessImage|endswith: '\cmd.exe'
    selection_cmdline:
        ProcessCommandLine|contains: 'Invoke'
    condition: selection_process and (selection_parent or selection_cmdline)
"#;

    let rule2 = r#"
title: Complex Rule 2
id: rule-complex-2
detection:
    selection_process:
        ProcessImage|endswith: '\cmd.exe'
    selection_cmdline:
        ProcessCommandLine|contains: 'echo'
    condition: selection_process and selection_cmdline
"#;

    // Event that matches rule1 (powershell with Invoke)
    let event1 = json!({
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -Command Invoke-WebRequest",
        "ParentImage": "C:\\Windows\\System32\\explorer.exe"
    });

    // Event that matches rule2 (cmd with echo)
    let event2 = json!({
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c echo test",
        "ParentImage": "C:\\Windows\\System32\\explorer.exe"
    });

    // Test multiple rules compilation
    let compiler = Compiler::with_field_mapping(field_mapping);
    let config = DagEngineConfig::default();
    let mut engine = SigmaEngine::from_rules_with_compiler(&[rule1, rule2], compiler, config)
        .expect("Failed to create engine");

    // Test events
    let result1 = engine.evaluate(&event1).expect("Failed to evaluate event1");
    assert_eq!(
        result1.matched_rules.len(),
        1,
        "Event1 should match rule1 only"
    );

    let result2 = engine.evaluate(&event2).expect("Failed to evaluate event2");
    assert_eq!(
        result2.matched_rules.len(),
        1,
        "Event2 should match rule2 only"
    );
}
