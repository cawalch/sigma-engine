//! End-to-end benchmarks for SIGMA Engine
//!
//! These benchmarks test the complete pipeline from YAML rule compilation
//! to event evaluation, measuring real-world performance scenarios.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;
use sigma_engine::{Compiler, DagEngineConfig, SigmaEngine};

/// Benchmark single event evaluation through the complete pipeline
fn bench_end_to_end_single_event(c: &mut Criterion) {
    // Realistic SIGMA rule based on emerging threats patterns
    let rule_yaml = r#"
title: Suspicious PowerShell Execution with Base64 Encoding
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects suspicious PowerShell execution with base64 encoded commands
references:
    - https://github.com/SigmaHQ/sigma/tree/master/rules-emerging-threats
author: SIGMA Engine Benchmark
date: 2025/01/01
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: powershell
    definition: PowerShell Script Block Logging
detection:
    selection_powershell:
        EventID: 4104
    selection_base64:
        ScriptBlockText|contains:
            - 'FromBase64String'
            - 'ToBase64String'
            - '-EncodedCommand'
            - '-enc '
    selection_suspicious:
        ScriptBlockText|contains:
            - 'DownloadString'
            - 'WebClient'
            - 'Invoke-Expression'
            - 'IEX'
    condition: selection_powershell and (selection_base64 and selection_suspicious)
falsepositives:
    - Legitimate PowerShell scripts using base64 encoding
level: medium
"#;

    let mut compiler = Compiler::new();
    let ruleset = compiler.compile_ruleset(&[rule_yaml]).unwrap();
    let mut engine =
        SigmaEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default()).unwrap();

    let test_event = json!({
        "EventID": "4104",
        "ScriptBlockText": "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        "ProcessName": "powershell.exe",
        "User": "DOMAIN\\user",
        "Computer": "WORKSTATION01"
    });

    c.bench_function("end_to_end_single_event", |b| {
        b.iter(|| {
            let result = engine.evaluate(black_box(&test_event));
            black_box(result)
        })
    });
}

/// Benchmark batch event processing
fn bench_end_to_end_batch_events(c: &mut Criterion) {
    // Multiple realistic SIGMA rules for batch processing
    let rules = vec![
        r#"
title: Suspicious Process Creation
id: 11111111-1111-1111-1111-111111111111
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
    condition: selection
level: low
"#,
        r#"
title: Network Connection to Suspicious Domain
id: 22222222-2222-2222-2222-222222222222
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        DestinationHostname|contains:
            - 'malware.com'
            - 'evil.org'
            - 'badactor.net'
    condition: selection
level: high
"#,
        r#"
title: File Creation in System Directory
id: 33333333-3333-3333-3333-333333333333
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    condition: selection
level: medium
"#,
    ];

    let mut compiler = Compiler::new();
    let ruleset = compiler.compile_ruleset(&rules).unwrap();
    let mut engine =
        SigmaEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default()).unwrap();

    // Create test events manually
    let test_events: Vec<serde_json::Value> = (0..100)
        .map(|i| {
            json!({
                "EventID": "4688",
                "NewProcessName": format!("C:\\Windows\\System32\\process{}.exe", i),
                "ProcessId": format!("{}", 1000 + i),
                "User": "DOMAIN\\user",
                "Computer": "WORKSTATION01"
            })
        })
        .collect();

    c.bench_function("end_to_end_batch_100_events", |b| {
        b.iter(|| {
            let results = engine.evaluate_batch(black_box(&test_events));
            black_box(results)
        })
    });
}

/// Benchmark compilation performance
fn bench_compilation_performance(c: &mut Criterion) {
    let rule_yaml = r#"
title: Test Rule
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection
"#;

    c.bench_function("compilation_single_rule", |b| {
        b.iter(|| {
            let mut compiler = Compiler::new();
            let ruleset = compiler.compile_ruleset(black_box(&[rule_yaml]));
            black_box(ruleset)
        })
    });
}

/// Benchmark multiple rules compilation
fn bench_multiple_rules_compilation(c: &mut Criterion) {
    // Realistic emerging threat rules based on SigmaHQ patterns
    let rules = vec![
        r#"
title: Suspicious Registry Modification
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains:
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    condition: selection
level: medium
"#,
        r#"
title: Credential Dumping Tool Execution
id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith:
            - '\mimikatz.exe'
            - '\procdump.exe'
            - '\lsass.exe'
    condition: selection
level: critical
"#,
        r#"
title: Lateral Movement via WMI
id: cccccccc-cccc-cccc-cccc-cccccccccccc
logsource:
    product: windows
    service: wmi
detection:
    selection:
        EventID: 5857
        Operation: 'Started'
    condition: selection
level: high
"#,
    ];

    c.bench_function("compilation_multiple_rules", |b| {
        b.iter(|| {
            let mut compiler = Compiler::new();
            let ruleset = compiler.compile_ruleset(black_box(&rules));
            black_box(ruleset)
        })
    });
}

/// Benchmark engine creation from ruleset
fn bench_engine_creation(c: &mut Criterion) {
    let rule_yaml = r#"
title: Test Rule
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection
"#;

    let mut compiler = Compiler::new();
    let ruleset = compiler.compile_ruleset(&[rule_yaml]).unwrap();

    c.bench_function("engine_creation", |b| {
        b.iter(|| {
            let engine = SigmaEngine::from_ruleset_with_config(
                black_box(ruleset.clone()),
                DagEngineConfig::default(),
            );
            black_box(engine)
        })
    });
}

criterion_group!(
    benches,
    bench_end_to_end_single_event,
    bench_end_to_end_batch_events,
    bench_compilation_performance,
    bench_multiple_rules_compilation,
    bench_engine_creation
);
criterion_main!(benches);
