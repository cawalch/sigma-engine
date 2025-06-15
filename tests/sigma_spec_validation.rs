//! SIGMA Specification Validation Tests
//!
//! This module contains comprehensive tests that validate the implementation
//! against the official SIGMA rules specification.

use sigma_engine::{Compiler, FieldMapping};

/// Test real-world SIGMA rules from the official specification examples
#[test]
fn test_sigma_spec_basic_rule() {
    let mut compiler = Compiler::new();

    // Example from SIGMA specification - Windows Process Creation
    let rule_yaml = r#"
title: Suspicious Process Creation
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects suspicious process creation
author: SIGMA Test Suite
date: 2025/06/15
references:
    - https://github.com/SigmaHQ/sigma
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
        Image|endswith: '\powershell.exe'
        CommandLine|contains: 'Invoke-Expression'
    condition: selection
fields:
    - Image
    - CommandLine
    - User
falsepositives:
    - Administrative scripts
level: medium
tags:
    - attack.execution
    - attack.t1059.001
"#;

    let result = compiler.compile_rule(rule_yaml);
    assert!(result.is_ok(), "Failed to compile basic SIGMA rule");

    let chunk = result.unwrap();
    assert!(!chunk.opcodes.is_empty(), "Bytecode should not be empty");

    // Verify primitives were created correctly
    assert_eq!(compiler.primitive_count(), 3); // EventID, Image, CommandLine

    let primitives = compiler.primitives();
    assert!(primitives
        .iter()
        .any(|p| p.field == "EventID" && p.match_type == "equals"));
    assert!(primitives
        .iter()
        .any(|p| p.field == "Image" && p.match_type == "endswith"));
    assert!(primitives
        .iter()
        .any(|p| p.field == "CommandLine" && p.match_type == "contains"));
}

/// Test SIGMA rule with multiple selections and complex conditions
#[test]
fn test_sigma_spec_complex_conditions() {
    let mut compiler = Compiler::new();

    let rule_yaml = r#"
title: Complex Detection Rule
id: 87654321-4321-4321-4321-210987654321
status: stable
description: Complex rule with multiple selections
author: SIGMA Test Suite
date: 2025/06/15
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        EventID: 1
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    selection_cmdline:
        CommandLine|contains:
            - 'whoami'
            - 'net user'
            - 'systeminfo'
    filter_admin:
        User|startswith: 'SYSTEM'
    condition: (selection_process and selection_cmdline) and not filter_admin
fields:
    - Image
    - CommandLine
    - User
level: high
"#;

    let result = compiler.compile_rule(rule_yaml);
    assert!(result.is_ok(), "Failed to compile complex SIGMA rule");

    // Should have 4 primitives: EventID, Image, CommandLine, User
    // Each primitive can handle multiple values
    assert_eq!(compiler.primitive_count(), 4);

    // Verify selection mapping
    assert!(compiler
        .current_selection_map()
        .contains_key("selection_process"));
    assert!(compiler
        .current_selection_map()
        .contains_key("selection_cmdline"));
    assert!(compiler
        .current_selection_map()
        .contains_key("filter_admin"));
}

/// Test SIGMA rule with value modifiers
#[test]
fn test_sigma_spec_value_modifiers() {
    let mut compiler = Compiler::new();

    let rule_yaml = r#"
title: Value Modifiers Test
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Tests various SIGMA value modifiers
author: SIGMA Test Suite
date: 2025/06/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
        Image|contains: 'powershell'
        CommandLine|startswith: 'powershell.exe'
        ProcessName|endswith: '.exe'
        Hash|re: '[a-fA-F0-9]{32}'
        User|cased: 'Administrator'
    condition: selection
level: medium
"#;

    let result = compiler.compile_rule(rule_yaml);
    assert!(
        result.is_ok(),
        "Failed to compile rule with value modifiers"
    );

    let primitives = compiler.primitives();

    // Verify different match types
    assert!(primitives.iter().any(|p| p.match_type == "equals"));
    assert!(primitives.iter().any(|p| p.match_type == "contains"));
    assert!(primitives.iter().any(|p| p.match_type == "startswith"));
    assert!(primitives.iter().any(|p| p.match_type == "endswith"));
    assert!(primitives.iter().any(|p| p.match_type == "regex"));

    // Verify case sensitivity handling
    let user_primitive = primitives.iter().find(|p| p.field == "User").unwrap();
    assert!(user_primitive
        .modifiers
        .iter()
        .any(|m| m == "case_sensitive"));
}

/// Test SIGMA rule with "one of them" pattern
#[test]
fn test_sigma_spec_one_of_them() {
    let mut compiler = Compiler::new();

    let rule_yaml = r#"
title: One of Them Pattern
id: 99999999-8888-7777-6666-555555555555
status: experimental
description: Tests 'one of them' pattern
author: SIGMA Test Suite
date: 2025/06/15
logsource:
    category: process_creation
    product: windows
detection:
    suspicious_process1:
        Image|endswith: '\malware1.exe'
    suspicious_process2:
        Image|endswith: '\malware2.exe'
    suspicious_process3:
        Image|endswith: '\malware3.exe'
    condition: 1 of them
level: high
"#;

    let result = compiler.compile_rule(rule_yaml);
    assert!(result.is_ok(), "Failed to compile 'one of them' rule");

    // Should have 3 primitives for the 3 selections
    assert_eq!(compiler.primitive_count(), 3);

    // All should be Image field with endswith match type
    let primitives = compiler.primitives();
    assert_eq!(
        primitives
            .iter()
            .filter(|p| p.field == "Image" && p.match_type == "endswith")
            .count(),
        3
    );
}

/// Test field mapping with real SIGMA rule
#[test]
fn test_sigma_spec_field_mapping() {
    let mut field_mapping = FieldMapping::new();
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());

    let mut compiler = Compiler::with_field_mapping(field_mapping);

    let rule_yaml = r#"
title: Field Mapping Test
id: 77777777-6666-5555-4444-333333333333
status: experimental
description: Tests field mapping functionality
author: SIGMA Test Suite
date: 2025/06/15
logsource:
    category: process_creation
    product: custom_edr
detection:
    selection:
        EventID: 1
        ProcessImage|endswith: '\suspicious.exe'
        ProcessCommandLine|contains: 'malicious'
    condition: selection
level: medium
"#;

    let result = compiler.compile_rule(rule_yaml);
    assert!(result.is_ok(), "Failed to compile rule with field mapping");

    let primitives = compiler.primitives();

    // Verify fields were mapped correctly
    assert!(primitives.iter().any(|p| p.field == "Image"));
    assert!(primitives.iter().any(|p| p.field == "CommandLine"));

    // Original field names should not exist
    assert!(!primitives.iter().any(|p| p.field == "ProcessImage"));
    assert!(!primitives.iter().any(|p| p.field == "ProcessCommandLine"));
}

/// Test error handling with malformed SIGMA rules
#[test]
fn test_sigma_spec_error_handling() {
    let mut compiler = Compiler::new();

    // Rule missing required condition
    let malformed_rule = r#"
title: Malformed Rule
id: 00000000-0000-0000-0000-000000000000
logsource:
    category: test
detection:
    selection:
        EventID: 1
    # Missing condition field
"#;

    let result = compiler.compile_rule(malformed_rule);
    assert!(result.is_err(), "Should fail on malformed rule");

    // Invalid YAML
    let invalid_yaml = r#"
title: Invalid YAML
invalid_yaml_structure: [
"#;

    let result = compiler.compile_rule(invalid_yaml);
    assert!(result.is_err(), "Should fail on invalid YAML");
}
