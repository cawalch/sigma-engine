//! Rule scaling benchmarks for SIGMA Engine
//!
//! These benchmarks test how the engine performs as the number of rules increases,
//! validating linear O(1) scaling characteristics.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::json;
use sigma_engine::{Compiler, DagEngineConfig, SigmaEngine};
use std::hint::black_box;

/// Generate realistic SIGMA rules for scaling benchmarks
fn generate_test_rules(count: usize) -> Vec<String> {
    let rule_templates = [
        // Process creation rules
        r#"
title: Suspicious Process Creation {}
id: {}-0000-0000-0000-000000000000
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith: '\{}.exe'
    condition: selection
level: medium
"#,
        // Network connection rules
        r#"
title: Network Connection {}
id: {}-1111-1111-1111-111111111111
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        DestinationPort: {}
    condition: selection
level: high
"#,
        // File creation rules
        r#"
title: File Creation {}
id: {}-2222-2222-2222-222222222222
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|contains: 'temp{}'
    condition: selection
level: low
"#,
        // Registry modification rules
        r#"
title: Registry Modification {}
id: {}-3333-3333-3333-333333333333
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains: 'Run{}'
    condition: selection
level: medium
"#,
    ];

    (0..count)
        .map(|i| {
            let template = &rule_templates[i % rule_templates.len()];
            let process_names = ["cmd", "powershell", "wscript", "cscript", "rundll32"];
            let process_name = process_names[i % process_names.len()];

            match i % rule_templates.len() {
                0 => template
                    .replace("{}", &format!("{i}"))
                    .replace("{}.exe", &format!("{process_name}.exe")),
                1 => template
                    .replace("{}", &format!("{i}"))
                    .replace("{}", &format!("{}", 8000 + (i % 1000))),
                _ => template.replace("{}", &format!("{i}")),
            }
        })
        .collect()
}

/// Benchmark rule execution scaling
fn bench_rule_scaling_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_scaling_simple");

    let test_event = json!({
        "EventID": "4688",
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "ProcessId": "1234",
        "User": "DOMAIN\\user",
        "Computer": "WORKSTATION01"
    });

    for rule_count in [10, 50, 100, 500, 1000].iter() {
        let rules = generate_test_rules(*rule_count);
        let rule_refs: Vec<&str> = rules.iter().map(|s| s.as_str()).collect();

        let mut compiler = Compiler::new();
        let ruleset = compiler.compile_ruleset(&rule_refs).unwrap();
        let mut engine =
            SigmaEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default()).unwrap();

        group.bench_with_input(
            BenchmarkId::new("execution", rule_count),
            rule_count,
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

/// Benchmark rule compilation scaling
fn bench_rule_scaling_compilation(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_scaling_compilation");

    for rule_count in [10, 50, 100, 500, 1000].iter() {
        let rules = generate_test_rules(*rule_count);
        let rule_refs: Vec<&str> = rules.iter().map(|s| s.as_str()).collect();

        group.bench_with_input(
            BenchmarkId::new("compilation", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| {
                    let mut compiler = Compiler::new();
                    let ruleset = compiler.compile_ruleset(black_box(&rule_refs));
                    black_box(ruleset)
                })
            },
        );
    }
    group.finish();
}

/// Benchmark batch processing scaling
fn bench_rule_scaling_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_scaling_batch");

    // Create test events manually for scaling tests
    let test_events: Vec<serde_json::Value> = (0..100)
        .map(|i| {
            json!({
                "EventID": "4688",
                "NewProcessName": format!("C:\\Windows\\System32\\test{}.exe", i),
                "ProcessId": format!("{}", 2000 + i),
                "User": "DOMAIN\\testuser",
                "Computer": "TESTSTATION01"
            })
        })
        .collect();

    for rule_count in [10, 50, 100, 500].iter() {
        let rules = generate_test_rules(*rule_count);
        let rule_refs: Vec<&str> = rules.iter().map(|s| s.as_str()).collect();

        let mut compiler = Compiler::new();
        let ruleset = compiler.compile_ruleset(&rule_refs).unwrap();
        let mut engine =
            SigmaEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default()).unwrap();

        group.bench_with_input(
            BenchmarkId::new("batch_100_events", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| {
                    let results = engine.evaluate_batch(black_box(&test_events));
                    black_box(results)
                })
            },
        );
    }
    group.finish();
}

/// Benchmark memory usage scaling
fn bench_rule_scaling_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_scaling_memory");

    for rule_count in [10, 50, 100, 500].iter() {
        let rules = generate_test_rules(*rule_count);
        let rule_refs: Vec<&str> = rules.iter().map(|s| s.as_str()).collect();

        group.bench_with_input(
            BenchmarkId::new("engine_creation", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| {
                    let mut compiler = Compiler::new();
                    let ruleset = compiler.compile_ruleset(black_box(&rule_refs)).unwrap();
                    let engine =
                        SigmaEngine::from_ruleset_with_config(ruleset, DagEngineConfig::default());
                    black_box(engine)
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_rule_scaling_execution,
    bench_rule_scaling_compilation,
    bench_rule_scaling_batch,
    bench_rule_scaling_memory
);
criterion_main!(benches);
