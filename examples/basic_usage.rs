//! Basic SIGMA Engine usage examples.
//!
//! This example demonstrates the core functionality of the SIGMA Engine
//! using the DAG-based execution architecture.

use serde_json::json;
use sigma_engine::{Compiler, SigmaEngine};

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
    let mut compiler = Compiler::new();
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

    let ruleset = compiler.compile_ruleset(&[rule_yaml])?;
    println!(
        "Compiled ruleset with {} primitives",
        ruleset.primitives.len()
    );

    // Create engine
    let mut engine = SigmaEngine::from_ruleset(ruleset)?;

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

    // Set up field mapping for custom taxonomy
    let mut field_mapping = sigma_engine::FieldMapping::with_taxonomy("custom_edr".to_string());
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());

    let mut compiler = Compiler::with_field_mapping(field_mapping);

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

    let ruleset = compiler.compile_ruleset(&rules)?;
    println!(
        "Compiled {} rules with {} primitives",
        rules.len(),
        ruleset.primitives.len()
    );

    let mut engine = SigmaEngine::from_ruleset(ruleset)?;

    // Test PowerShell event
    let powershell_event = json!({
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -Command Invoke-Expression"
    });

    let result = engine.evaluate(&powershell_event)?;
    println!("PowerShell event matches: {:?}", result.matched_rules);

    // Test reconnaissance tool event
    let recon_event = json!({
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\whoami.exe",
        "CommandLine": "whoami /all"
    });

    let result = engine.evaluate(&recon_event)?;
    println!("Reconnaissance event matches: {:?}", result.matched_rules);

    Ok(())
}

/// Demonstrate batch processing for high throughput.
fn batch_processing_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Batch Processing Example ===");

    let mut compiler = Compiler::new();
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

    let ruleset = compiler.compile_ruleset(&[rule_yaml])?;
    let mut engine = SigmaEngine::from_ruleset(ruleset)?;

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

    println!("Batch processing completed in {:?}", processing_time);

    // Calculate total matches
    let total_matches: usize = results.iter().map(|r| r.matched_rules.len()).sum();
    println!("Total matches: {}", total_matches);
    println!("Events processed: {}", events.len());
    println!(
        "Throughput: {:.0} events/sec",
        events.len() as f64 / processing_time.as_secs_f64()
    );

    // Show individual results
    for (i, result) in results.iter().enumerate() {
        if !result.matched_rules.is_empty() {
            println!("Event {} matched rules: {:?}", i, result.matched_rules);
        }
    }

    Ok(())
}
