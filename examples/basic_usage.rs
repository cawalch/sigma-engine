//! Basic SIGMA Engine usage examples.
//!
//! This example demonstrates the core functionality of the SIGMA Engine
//! using the DAG-based execution architecture.

use serde_json::json;
use sigma_engine::SigmaEngine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("SIGMA Engine Basic Usage Examples");
    println!("=================================\n");

    // Example 1: Single rule evaluation
    single_rule_example()?;
    println!();

    // Example 2: Multiple rules with field mapping
    multiple_rules_example()?;
    println!();

    // Example 3: Batch processing
    batch_processing_example()?;

    Ok(())
}

/// Demonstrate single rule compilation and evaluation.
fn single_rule_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Single Rule Example ===");

    // Compile a SIGMA rule
    let rule_yaml = r#"
title: Windows Login Event
logsource:
    category: authentication
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection
"#;

    // Create engine using the new API that properly compiles DAG
    let mut engine = SigmaEngine::from_rules(&[rule_yaml])?;

    // Test with matching event
    let matching_event = json!({
        "EventID": "4624",
        "LogonType": 2
    });

    let result = engine.evaluate(&matching_event)?;
    println!("Matching event result: {:?}", result.matched_rules);

    // Test with non-matching event
    let non_matching_event = json!({
        "EventID": "4625",
        "LogonType": 3
    });

    let result = engine.evaluate(&non_matching_event)?;
    println!("Non-matching event result: {:?}", result.matched_rules);

    Ok(())
}

/// Demonstrate multiple rules with field mapping.
fn multiple_rules_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Multiple Rules with Field Mapping ===");

    let rules = [
        r#"
title: Suspicious PowerShell
logsource:
    category: process_creation
detection:
    selection:
        EventID: 1
        ProcessImage|endswith: '\powershell.exe'
        ProcessCommandLine|contains: 'Invoke-Expression'
    condition: selection
"#,
        r#"
title: Reconnaissance Tools
logsource:
    category: process_creation
detection:
    tools:
        ProcessImage|endswith:
            - '\whoami.exe'
            - '\net.exe'
    condition: tools
"#,
    ];

    println!("Compiled {} rules", rules.len());

    // Create engine with proper field mapping for ProcessImage -> Image and ProcessCommandLine -> CommandLine
    use sigma_engine::{Compiler, EngineConfig, FieldMapping};

    let mut field_mapping = FieldMapping::new();
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());

    let compiler = Compiler::with_field_mapping(field_mapping);
    let config = EngineConfig::default();
    let mut engine = SigmaEngine::from_rules_with_compiler(&rules, compiler, config)?;

    // Test PowerShell event
    let powershell_event = json!({
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -Command Invoke-Expression"
    });

    println!("Testing PowerShell event: {powershell_event}");
    let result = engine.evaluate(&powershell_event)?;
    println!("PowerShell event matches: {:?}", result.matched_rules);

    // Debug: Test a simpler rule to see if field mapping works
    println!("\n--- Debug: Testing simple field mapping ---");
    let simple_rule = r#"
title: Simple Field Mapping Test
detection:
    selection:
        ProcessImage: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    condition: selection
"#;

    let mut simple_field_mapping = FieldMapping::new();
    simple_field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    let simple_compiler = Compiler::with_field_mapping(simple_field_mapping);
    let simple_config = EngineConfig::default();
    let mut simple_engine =
        SigmaEngine::from_rules_with_compiler(&[simple_rule], simple_compiler, simple_config)?;

    let simple_result = simple_engine.evaluate(&powershell_event)?;
    println!(
        "Simple field mapping test result: {:?}",
        simple_result.matched_rules
    );

    // Debug: Test endswith modifier
    println!("\n--- Debug: Testing endswith modifier ---");
    let endswith_rule = r#"
title: Endswith Test
detection:
    selection:
        ProcessImage|endswith: 'powershell.exe'
    condition: selection
"#;

    let mut endswith_field_mapping = FieldMapping::new();
    endswith_field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    let endswith_compiler = Compiler::with_field_mapping(endswith_field_mapping);
    let endswith_config = EngineConfig::default();
    let mut endswith_engine = SigmaEngine::from_rules_with_compiler(
        &[endswith_rule],
        endswith_compiler,
        endswith_config,
    )?;

    let endswith_result = endswith_engine.evaluate(&powershell_event)?;
    println!("Endswith test result: {:?}", endswith_result.matched_rules);

    // Debug: Test contains modifier
    println!("\n--- Debug: Testing contains modifier ---");
    let contains_rule = r#"
title: Contains Test
detection:
    selection:
        ProcessCommandLine|contains: 'Invoke-Expression'
    condition: selection
"#;

    let mut contains_field_mapping = FieldMapping::new();
    contains_field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());
    let contains_compiler = Compiler::with_field_mapping(contains_field_mapping);
    let contains_config = EngineConfig::default();
    let mut contains_engine = SigmaEngine::from_rules_with_compiler(
        &[contains_rule],
        contains_compiler,
        contains_config,
    )?;

    let contains_result = contains_engine.evaluate(&powershell_event)?;
    println!("Contains test result: {:?}", contains_result.matched_rules);

    // Debug: Test the exact pattern from the original rule
    println!("\n--- Debug: Testing exact original patterns ---");
    let exact_endswith_rule = r#"
title: Exact Endswith Test
detection:
    selection:
        ProcessImage|endswith: '\powershell.exe'
    condition: selection
"#;

    let mut exact_field_mapping = FieldMapping::new();
    exact_field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    let exact_compiler = Compiler::with_field_mapping(exact_field_mapping);
    let exact_config = EngineConfig::default();
    let mut exact_engine = SigmaEngine::from_rules_with_compiler(
        &[exact_endswith_rule],
        exact_compiler,
        exact_config,
    )?;

    let exact_result = exact_engine.evaluate(&powershell_event)?;
    println!(
        "Exact endswith test (with backslash) result: {:?}",
        exact_result.matched_rules
    );
    println!("Event Image field: {}", powershell_event["Image"]);

    // Debug: Test combination of two conditions
    println!("\n--- Debug: Testing two conditions combined ---");
    let two_conditions_rule = r#"
title: Two Conditions Test
detection:
    selection:
        EventID: 1
        ProcessImage|endswith: '\powershell.exe'
    condition: selection
"#;

    let mut two_field_mapping = FieldMapping::new();
    two_field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    let two_compiler = Compiler::with_field_mapping(two_field_mapping);
    let two_config = EngineConfig::default();
    let mut two_engine =
        SigmaEngine::from_rules_with_compiler(&[two_conditions_rule], two_compiler, two_config)?;

    let two_result = two_engine.evaluate(&powershell_event)?;
    println!("Two conditions test result: {:?}", two_result.matched_rules);

    // Debug: Test the exact three conditions from the original rule
    println!("\n--- Debug: Testing exact three conditions ---");
    let three_conditions_rule = r#"
title: Three Conditions Test
detection:
    selection:
        EventID: 1
        ProcessImage|endswith: '\powershell.exe'
        ProcessCommandLine|contains: 'Invoke-Expression'
    condition: selection
"#;

    let mut three_field_mapping = FieldMapping::new();
    three_field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    three_field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());
    let three_compiler = Compiler::with_field_mapping(three_field_mapping);
    let three_config = EngineConfig::default();
    let mut three_engine = SigmaEngine::from_rules_with_compiler(
        &[three_conditions_rule],
        three_compiler,
        three_config,
    )?;

    let three_result = three_engine.evaluate(&powershell_event)?;
    println!(
        "Three conditions test result: {:?}",
        three_result.matched_rules
    );
    println!(
        "Event CommandLine field: {}",
        powershell_event["CommandLine"]
    );

    // Test reconnaissance tool event
    let recon_event = json!({
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\whoami.exe",
        "CommandLine": "whoami /all"
    });

    println!("Testing reconnaissance event: {recon_event}");
    let result = engine.evaluate(&recon_event)?;
    println!("Reconnaissance event matches: {:?}", result.matched_rules);

    // Debug: Test the reconnaissance rule individually
    println!("\n--- Debug: Testing reconnaissance rule individually ---");
    let recon_rule_only = r#"
title: Reconnaissance Tools
logsource:
    category: process_creation
detection:
    tools:
        ProcessImage|endswith:
            - '\whoami.exe'
            - '\net.exe'
    condition: tools
"#;

    let mut recon_field_mapping = FieldMapping::new();
    recon_field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    let recon_compiler = Compiler::with_field_mapping(recon_field_mapping);
    let recon_config = EngineConfig::default();
    let mut recon_engine =
        SigmaEngine::from_rules_with_compiler(&[recon_rule_only], recon_compiler, recon_config)?;

    let recon_individual_result = recon_engine.evaluate(&recon_event)?;
    println!(
        "Reconnaissance rule individual test result: {:?}",
        recon_individual_result.matched_rules
    );

    // Debug: Test the PowerShell rule individually
    println!("\n--- Debug: Testing PowerShell rule individually ---");
    let powershell_rule_only = r#"
title: Suspicious PowerShell
logsource:
    category: process_creation
detection:
    selection:
        EventID: 1
        ProcessImage|endswith: '\powershell.exe'
        ProcessCommandLine|contains: 'Invoke-Expression'
    condition: selection
"#;

    let mut ps_field_mapping = FieldMapping::new();
    ps_field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    ps_field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());
    let ps_compiler = Compiler::with_field_mapping(ps_field_mapping);
    let ps_config = EngineConfig::default();
    let mut ps_engine =
        SigmaEngine::from_rules_with_compiler(&[powershell_rule_only], ps_compiler, ps_config)?;

    let ps_individual_result = ps_engine.evaluate(&powershell_event)?;
    println!(
        "PowerShell rule individual test result: {:?}",
        ps_individual_result.matched_rules
    );

    Ok(())
}

/// Demonstrate batch processing for high throughput.
fn batch_processing_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Batch Processing Example ===");

    let rule_yaml = r#"
title: Windows Login Event
logsource:
    category: authentication
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection
"#;

    // Create engine using the new API that properly compiles DAG
    let mut engine = SigmaEngine::from_rules(&[rule_yaml])?;

    // Create batch of events
    let events = [
        json!({"EventID": "4624", "LogonType": 2}), // Match
        json!({"EventID": "4624", "LogonType": 3}), // No match
        json!({"EventID": "4625", "LogonType": 2}), // No match
        json!({"EventID": "4624", "LogonType": 2}), // Match
        json!({"EventID": "4624", "LogonType": 2}), // Match
    ];

    println!("Processing batch of {} events", events.len());

    let start_time = std::time::Instant::now();
    let results = engine.evaluate_batch(&events)?;
    let processing_time = start_time.elapsed();

    println!("Batch processing completed in {processing_time:?}");

    // Calculate total matches
    let total_matches: usize = results.iter().map(|r| r.matched_rules.len()).sum();
    println!("Total matches: {total_matches}");
    println!("Events processed: {}", events.len());
    println!(
        "Throughput: {:.0} events/sec",
        events.len() as f64 / processing_time.as_secs_f64()
    );

    // Show individual results
    for (i, result) in results.iter().enumerate() {
        println!(
            "Event {}: {} -> matches: {:?}",
            i, events[i], result.matched_rules
        );
    }

    // Test individual events to compare with batch results
    println!("\n--- Individual Event Testing ---");
    for (i, event) in events.iter().enumerate() {
        let individual_result = engine.evaluate(event)?;
        println!(
            "Individual Event {}: {} -> matches: {:?}",
            i, event, individual_result.matched_rules
        );
    }

    Ok(())
}
