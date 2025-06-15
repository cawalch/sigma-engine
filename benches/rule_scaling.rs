//! Rule scaling benchmarks for the SIGMA bytecode engine.
//!
//! These benchmarks measure performance with different numbers of rules,
//! from small deployments to production-scale scenarios with 2k+ rules.

use aho_corasick::AhoCorasick;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use regex::Regex;
use serde_json::Value;
use sigma_engine::{Compiler, Primitive, Vm};
use std::collections::HashMap;

struct BenchPrimitiveMatcher {
    primitive_strategies: HashMap<u32, BenchMatchStrategy>,
    aho_corasick: Option<AhoCorasick>,
    ac_pattern_to_primitive: HashMap<usize, u32>,
    regex_patterns: Vec<(u32, Regex)>,
    cached_results: std::cell::RefCell<Vec<bool>>,
}

#[derive(Debug, Clone)]
enum BenchMatchStrategy {
    Exact(String),
    Contains(#[allow(dead_code)] String),
    Regex(#[allow(dead_code)] String),
}

impl BenchPrimitiveMatcher {
    fn event_to_search_string(event: &Value) -> String {
        match event {
            Value::Object(map) => {
                let mut parts = Vec::new();
                for (key, value) in map {
                    parts.push(key.clone());
                    match value {
                        Value::String(s) => parts.push(s.clone()),
                        Value::Number(n) => parts.push(n.to_string()),
                        Value::Bool(b) => parts.push(b.to_string()),
                        _ => parts.push(value.to_string()),
                    }
                }
                parts.join(" ")
            }
            _ => event.to_string(),
        }
    }

    fn new(primitives: &[Primitive]) -> anyhow::Result<Self> {
        let mut primitive_strategies = HashMap::new();
        let mut substring_patterns = Vec::new();
        let mut regex_patterns = Vec::new();
        let mut ac_pattern_to_primitive = HashMap::new();

        for (id, primitive) in primitives.iter().enumerate() {
            let id = id as u32;

            match primitive.match_type.as_ref() {
                "equals" => {
                    if let Some(value) = primitive.values.first() {
                        primitive_strategies
                            .insert(id, BenchMatchStrategy::Exact(value.to_string()));
                    }
                }
                "contains" => {
                    if let Some(value) = primitive.values.first() {
                        substring_patterns.push(value.as_ref());
                        ac_pattern_to_primitive.insert(substring_patterns.len() - 1, id);
                        primitive_strategies
                            .insert(id, BenchMatchStrategy::Contains(value.to_string()));
                    }
                }
                "regex" => {
                    if let Some(pattern) = primitive.values.first() {
                        let regex = Regex::new(pattern)?;
                        regex_patterns.push((id, regex));
                        primitive_strategies
                            .insert(id, BenchMatchStrategy::Regex(pattern.to_string()));
                    }
                }
                _ => {
                    if let Some(value) = primitive.values.first() {
                        primitive_strategies
                            .insert(id, BenchMatchStrategy::Exact(value.to_string()));
                    }
                }
            }
        }

        let aho_corasick = if !substring_patterns.is_empty() {
            Some(AhoCorasick::new(&substring_patterns)?)
        } else {
            None
        };

        Ok(Self {
            primitive_strategies,
            aho_corasick,
            ac_pattern_to_primitive,
            regex_patterns,
            cached_results: std::cell::RefCell::new(Vec::new()),
        })
    }

    fn evaluate_primitives_with_callback<F, R>(
        &self,
        event: &Value,
        primitive_count: usize,
        callback: F,
    ) -> R
    where
        F: FnOnce(&[bool]) -> R,
    {
        let mut cached_results = self.cached_results.borrow_mut();
        cached_results.clear();
        cached_results.resize(primitive_count, false);

        let event_str = Self::event_to_search_string(event);

        if let Some(ref ac) = self.aho_corasick {
            for mat in ac.find_iter(&event_str) {
                if let Some(&primitive_id) =
                    self.ac_pattern_to_primitive.get(&mat.pattern().as_usize())
                {
                    if (primitive_id as usize) < cached_results.len() {
                        cached_results[primitive_id as usize] = true;
                    }
                }
            }
        }

        for (primitive_id, regex) in &self.regex_patterns {
            if (*primitive_id as usize) < cached_results.len() {
                cached_results[*primitive_id as usize] = regex.is_match(&event_str);
            }
        }

        for (&primitive_id, strategy) in &self.primitive_strategies {
            if (primitive_id as usize) < cached_results.len() {
                match strategy {
                    BenchMatchStrategy::Exact(value) => {
                        cached_results[primitive_id as usize] = event_str.contains(value);
                    }
                    BenchMatchStrategy::Contains(_) => {}
                    BenchMatchStrategy::Regex(_) => {}
                }
            }
        }

        callback(&cached_results)
    }

    fn evaluate_primitives(&self, event: &Value, primitive_count: usize) -> Vec<bool> {
        let mut cached_results = self.cached_results.borrow_mut();
        cached_results.clear();
        cached_results.resize(primitive_count, false);

        let event_str = Self::event_to_search_string(event);

        if let Some(ref ac) = self.aho_corasick {
            for mat in ac.find_iter(&event_str) {
                if let Some(&primitive_id) =
                    self.ac_pattern_to_primitive.get(&mat.pattern().as_usize())
                {
                    if (primitive_id as usize) < cached_results.len() {
                        cached_results[primitive_id as usize] = true;
                    }
                }
            }
        }

        for (primitive_id, regex) in &self.regex_patterns {
            if (*primitive_id as usize) < cached_results.len() {
                cached_results[*primitive_id as usize] = regex.is_match(&event_str);
            }
        }

        for (&primitive_id, strategy) in &self.primitive_strategies {
            if (primitive_id as usize) < cached_results.len() {
                match strategy {
                    BenchMatchStrategy::Exact(value) => {
                        cached_results[primitive_id as usize] = event_str.contains(value);
                    }
                    BenchMatchStrategy::Contains(_) => {}
                    BenchMatchStrategy::Regex(_) => {}
                }
            }
        }

        cached_results.clone()
    }
}

fn generate_test_rule(rule_id: u32, complexity: RuleComplexity) -> String {
    match complexity {
        RuleComplexity::Simple => {
            format!(
                r#"
title: Test Rule {}
id: {}-1234-1234-1234-123456789abc
description: Simple test rule for benchmarking
author: Benchmark Generator
date: 2024-01-01
logsource:
    category: authentication
    product: windows
detection:
    selection:
        EventID: {}
        LogonType: {}
    condition: selection
level: low
tags:
    - attack.initial_access
"#,
                rule_id,
                rule_id,
                4624 + (rule_id % 10),
                2 + (rule_id % 5)
            )
        }
        RuleComplexity::Medium => {
            format!(
                r#"
title: Medium Test Rule {}
id: {}-2345-2345-2345-234567890abc
description: Medium complexity test rule for benchmarking
author: Benchmark Generator
date: 2024-01-01
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        EventID: {}
        ProcessName|contains:
            - "process{}.exe"
            - "app{}.exe"
    selection_2:
        CommandLine|contains:
            - "param{}"
            - "arg{}"
    condition: selection_1 and selection_2
level: medium
tags:
    - attack.execution
"#,
                rule_id,
                rule_id,
                4688 + (rule_id % 5),
                rule_id % 100,
                rule_id % 100,
                rule_id % 50,
                rule_id % 50
            )
        }
        RuleComplexity::Complex => {
            format!(
                r#"
title: Complex Test Rule {}
id: {}-3456-3456-3456-345678901abc
description: Complex test rule for benchmarking
author: Benchmark Generator
date: 2024-01-01
logsource:
    category: network_connection
    product: windows
detection:
    selection_1:
        EventID: {}
        ProcessName|contains:
            - "browser{}.exe"
            - "client{}.exe"
    selection_2:
        DestinationIp|contains:
            - "192.168.{}.{}"
            - "10.0.{}.{}"
    selection_3:
        DestinationPort:
            - {}
            - {}
    filter:
        SourceIp|contains: "127.0.0.1"
    condition: (selection_1 and selection_2 and selection_3) and not filter
level: high
tags:
    - attack.command_and_control
    - attack.exfiltration
"#,
                rule_id,
                rule_id,
                3 + (rule_id % 10),
                rule_id % 100,
                rule_id % 100,
                rule_id % 255,
                rule_id % 255,
                rule_id % 255,
                rule_id % 255,
                80 + (rule_id % 100),
                443 + (rule_id % 100)
            )
        }
    }
}

#[derive(Clone, Copy)]
enum RuleComplexity {
    Simple,
    Medium,
    Complex,
}

fn setup_test_environment_with_rules(
    rule_count: usize,
    complexity: RuleComplexity,
) -> (
    Vec<sigma_engine::ir::BytecodeChunk>,
    BenchPrimitiveMatcher,
    Vm<64>,
    usize,
) {
    let mut compiler = Compiler::new();
    let mut chunks = Vec::new();

    for i in 0..rule_count {
        let rule_yaml = generate_test_rule(i as u32, complexity);
        match compiler.compile_rule(&rule_yaml) {
            Ok(chunk) => chunks.push(chunk),
            Err(e) => {
                eprintln!("Failed to compile rule {}: {}", i, e);
                let fallback_rule = format!(
                    r#"
title: Fallback Rule {}
logsource:
    category: test
detection:
    selection:
        EventID: {}
    condition: selection
"#,
                    i,
                    4624 + (i % 10)
                );
                if let Ok(chunk) = compiler.compile_rule(&fallback_rule) {
                    chunks.push(chunk);
                }
            }
        }
    }

    let ruleset = compiler.into_ruleset(chunks.clone());

    let matcher = BenchPrimitiveMatcher::new(&ruleset.primitives)
        .expect("Failed to create primitive matcher");

    let vm = Vm::<64>::new();

    (chunks, matcher, vm, ruleset.primitive_count())
}

fn generate_test_events(count: usize) -> Vec<Value> {
    let mut events = Vec::new();

    for i in 0..count {
        let event = match i % 4 {
            0 => serde_json::json!({
                "EventID": format!("{}", 4624 + (i % 10)),
                "LogonType": format!("{}", 2 + (i % 5)),
                "TargetUserName": format!("user{}", i % 100),
                "SourceIp": format!("192.168.1.{}", i % 255)
            }),
            1 => serde_json::json!({
                "EventID": format!("{}", 4688 + (i % 5)),
                "ProcessName": format!("process{}.exe", i % 100),
                "CommandLine": format!("param{} arg{}", i % 50, i % 50),
                "User": format!("user{}", i % 100)
            }),
            2 => serde_json::json!({
                "EventID": format!("{}", 3 + (i % 10)),
                "ProcessName": format!("browser{}.exe", i % 100),
                "DestinationIp": format!("192.168.{}.{}", i % 255, i % 255),
                "DestinationPort": 80 + (i % 100),
                "SourceIp": if i % 10 == 0 { "127.0.0.1" } else { "10.0.1.1" }
            }),
            _ => serde_json::json!({
                "EventID": format!("{}", 1000 + (i % 100)),
                "ProcessName": format!("app{}.exe", i % 100),
                "User": format!("user{}", i % 100),
                "Action": format!("action{}", i % 20)
            }),
        };
        events.push(event);
    }

    events
}

fn bench_rule_scaling_simple(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_scaling_simple");

    for rule_count in [10, 50, 100, 500, 1000, 2000, 5000].iter() {
        let (chunks, matcher, mut vm, primitive_count) =
            setup_test_environment_with_rules(*rule_count, RuleComplexity::Simple);

        let test_events = generate_test_events(10);

        group.bench_with_input(
            BenchmarkId::new("execution", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| {
                    for event in &test_events {
                        matcher.evaluate_primitives_with_callback(
                            event,
                            primitive_count,
                            |primitive_results| {
                                for chunk in &chunks {
                                    let _result = vm.execute_optimized(chunk, primitive_results);
                                }
                            },
                        );
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_rule_scaling_medium(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_scaling_medium");

    for rule_count in [10, 50, 100, 500, 1000, 2000].iter() {
        let (chunks, matcher, mut vm, primitive_count) =
            setup_test_environment_with_rules(*rule_count, RuleComplexity::Medium);

        let test_events = generate_test_events(10);

        group.bench_with_input(
            BenchmarkId::new("execution", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| {
                    for event in &test_events {
                        matcher.evaluate_primitives_with_callback(
                            event,
                            primitive_count,
                            |primitive_results| {
                                for chunk in &chunks {
                                    let _result = vm.execute_optimized(chunk, primitive_results);
                                }
                            },
                        );
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_rule_scaling_complex(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_scaling_complex");

    for rule_count in [10, 50, 100, 500, 1000, 2000].iter() {
        let (chunks, matcher, mut vm, primitive_count) =
            setup_test_environment_with_rules(*rule_count, RuleComplexity::Complex);

        let test_events = generate_test_events(10);

        group.bench_with_input(
            BenchmarkId::new("execution", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| {
                    for event in &test_events {
                        matcher.evaluate_primitives_with_callback(
                            event,
                            primitive_count,
                            |primitive_results| {
                                for chunk in &chunks {
                                    let _result = vm.execute_optimized(chunk, primitive_results);
                                }
                            },
                        );
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_rule_scaling_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_scaling_mixed");

    for total_rules in [100, 500, 1000, 2000, 5000].iter() {
        let simple_count = (total_rules * 6) / 10;
        let medium_count = (total_rules * 3) / 10;
        let complex_count = total_rules - simple_count - medium_count;

        let mut compiler = Compiler::new();
        let mut chunks = Vec::new();

        let mut rule_id = 0u32;

        for _ in 0..simple_count {
            let rule_yaml = generate_test_rule(rule_id, RuleComplexity::Simple);
            if let Ok(chunk) = compiler.compile_rule(&rule_yaml) {
                chunks.push(chunk);
            }
            rule_id += 1;
        }

        for _ in 0..medium_count {
            let rule_yaml = generate_test_rule(rule_id, RuleComplexity::Medium);
            if let Ok(chunk) = compiler.compile_rule(&rule_yaml) {
                chunks.push(chunk);
            }
            rule_id += 1;
        }

        for _ in 0..complex_count {
            let rule_yaml = generate_test_rule(rule_id, RuleComplexity::Complex);
            if let Ok(chunk) = compiler.compile_rule(&rule_yaml) {
                chunks.push(chunk);
            }
            rule_id += 1;
        }

        let ruleset = compiler.into_ruleset(chunks.clone());
        let matcher = BenchPrimitiveMatcher::new(&ruleset.primitives)
            .expect("Failed to create primitive matcher");
        let mut vm = Vm::<64>::new();
        let primitive_count = ruleset.primitive_count();

        let test_events = generate_test_events(10);

        group.bench_with_input(
            BenchmarkId::new("mixed_execution", total_rules),
            total_rules,
            |b, _| {
                b.iter(|| {
                    for event in &test_events {
                        matcher.evaluate_primitives_with_callback(
                            event,
                            primitive_count,
                            |primitive_results| {
                                for chunk in &chunks {
                                    let _result = vm.execute_optimized(chunk, primitive_results);
                                }
                            },
                        );
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_primitive_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("primitive_scaling");

    for rule_count in [100, 500, 1000, 2000, 5000].iter() {
        let (_, matcher, _, primitive_count) =
            setup_test_environment_with_rules(*rule_count, RuleComplexity::Medium);

        let test_events = generate_test_events(100);

        group.bench_with_input(
            BenchmarkId::new("primitive_matching", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| {
                    for event in &test_events {
                        let _results = matcher.evaluate_primitives(event, primitive_count);
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_compilation_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("compilation_scaling");

    for rule_count in [10, 50, 100, 500, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("compilation_time", rule_count),
            rule_count,
            |b, &rule_count| {
                b.iter(|| {
                    let mut compiler = Compiler::new();
                    let mut chunks = Vec::new();

                    for i in 0..rule_count {
                        let rule_yaml = generate_test_rule(i as u32, RuleComplexity::Medium);
                        if let Ok(chunk) = compiler.compile_rule(&rule_yaml) {
                            chunks.push(chunk);
                        }
                    }

                    let _ruleset = compiler.into_ruleset(chunks);
                })
            },
        );
    }

    group.finish();
}

fn bench_single_event_many_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_event_many_rules");

    for rule_count in [100, 500, 1000, 2000, 5000].iter() {
        let (chunks, matcher, mut vm, primitive_count) =
            setup_test_environment_with_rules(*rule_count, RuleComplexity::Medium);

        let test_event = serde_json::json!({
            "EventID": "4688",
            "ProcessName": "process50.exe",
            "CommandLine": "param25 arg25",
            "User": "user75"
        });

        group.bench_with_input(
            BenchmarkId::new("single_event", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| {
                    let primitive_results =
                        matcher.evaluate_primitives(&test_event, primitive_count);

                    let mut matches = 0;
                    for chunk in &chunks {
                        if vm
                            .execute(chunk, &primitive_results)
                            .unwrap_or(None)
                            .is_some()
                        {
                            matches += 1;
                        }
                    }
                    black_box(matches);
                })
            },
        );
    }

    group.finish();
}

fn bench_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_patterns");

    for rule_count in [1000, 2000, 5000].iter() {
        group.bench_with_input(
            BenchmarkId::new("memory_allocation", rule_count),
            rule_count,
            |b, &rule_count| {
                b.iter(|| {
                    let (chunks, matcher, mut vm, primitive_count) =
                        setup_test_environment_with_rules(rule_count, RuleComplexity::Medium);

                    let test_events = generate_test_events(10);

                    for event in &test_events {
                        let primitive_results = matcher.evaluate_primitives(event, primitive_count);

                        for chunk in &chunks {
                            let _result = vm.execute(chunk, &primitive_results);
                        }
                    }

                    drop(chunks);
                    drop(matcher);
                    let _ = vm;
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_rule_scaling_simple,
    bench_rule_scaling_medium,
    bench_rule_scaling_complex,
    bench_rule_scaling_mixed,
    bench_primitive_scaling,
    bench_compilation_scaling,
    bench_single_event_many_rules,
    bench_memory_patterns
);
criterion_main!(benches);
