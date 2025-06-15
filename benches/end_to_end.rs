//! End-to-end benchmarks for the SIGMA bytecode engine.
//!
//! These benchmarks measure the complete pipeline from JSON parsing
//! through primitive matching to VM execution, providing realistic
//! performance metrics for production use.

use aho_corasick::AhoCorasick;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use regex::Regex;
use serde_json::Value;
use sigma_engine::{Compiler, Primitive, Vm};
use std::collections::HashMap;

/// Simplified primitive matcher for benchmarking
struct BenchPrimitiveMatcher {
    primitive_strategies: HashMap<u32, BenchMatchStrategy>,
    aho_corasick: Option<AhoCorasick>,
    ac_pattern_to_primitive: HashMap<usize, u32>,
    #[allow(dead_code)]
    regex_patterns: Vec<(u32, Regex)>,
}

#[derive(Debug, Clone)]
enum BenchMatchStrategy {
    ExactMatch {
        field: String,
        #[allow(dead_code)]
        ac_pattern_id: usize,
    },
    ContainsMatch {
        field: String,
        #[allow(dead_code)]
        ac_pattern_id: usize,
    },
    #[allow(dead_code)]
    RegexMatch {
        field: String,
        regex_id: usize,
    },
    Equals {
        field: String,
        value: String,
    },
}

impl BenchPrimitiveMatcher {
    fn new(primitives: &[Primitive]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut primitive_strategies = HashMap::new();
        let mut ac_patterns = Vec::new();
        let mut ac_pattern_to_primitive = HashMap::new();
        let regex_patterns = Vec::new();

        for (primitive_id, primitive) in primitives.iter().enumerate() {
            let primitive_id = primitive_id as u32;

            match primitive.match_type.as_ref() {
                "equals" => {
                    if primitive.values.len() == 1 {
                        let pattern_id = ac_patterns.len();
                        ac_patterns.push(primitive.values[0].as_ref());
                        ac_pattern_to_primitive.insert(pattern_id, primitive_id);

                        primitive_strategies.insert(
                            primitive_id,
                            BenchMatchStrategy::ExactMatch {
                                field: primitive.field.to_string(),
                                ac_pattern_id: pattern_id,
                            },
                        );
                    } else {
                        primitive_strategies.insert(
                            primitive_id,
                            BenchMatchStrategy::Equals {
                                field: primitive.field.to_string(),
                                value: primitive
                                    .values
                                    .first()
                                    .map(|v| v.to_string())
                                    .unwrap_or_default(),
                            },
                        );
                    }
                }
                "contains" => {
                    if !primitive.values.is_empty() {
                        let pattern_id = ac_patterns.len();
                        ac_patterns.push(primitive.values[0].as_ref());
                        ac_pattern_to_primitive.insert(pattern_id, primitive_id);

                        primitive_strategies.insert(
                            primitive_id,
                            BenchMatchStrategy::ContainsMatch {
                                field: primitive.field.to_string(),
                                ac_pattern_id: pattern_id,
                            },
                        );
                    }
                }
                _ => {
                    primitive_strategies.insert(
                        primitive_id,
                        BenchMatchStrategy::Equals {
                            field: primitive.field.to_string(),
                            value: primitive
                                .values
                                .first()
                                .map(|v| v.to_string())
                                .unwrap_or_default(),
                        },
                    );
                }
            }
        }

        let aho_corasick = if !ac_patterns.is_empty() {
            Some(AhoCorasick::new(&ac_patterns)?)
        } else {
            None
        };

        Ok(Self {
            primitive_strategies,
            aho_corasick,
            ac_pattern_to_primitive,
            regex_patterns,
        })
    }

    fn evaluate_primitives(&self, event: &Value, primitive_count: usize) -> Vec<bool> {
        let mut results = vec![false; primitive_count];

        // Process AhoCorasick matches
        if let Some(ref ac) = self.aho_corasick {
            for (primitive_id, strategy) in &self.primitive_strategies {
                match strategy {
                    BenchMatchStrategy::ExactMatch {
                        field,
                        ac_pattern_id: _,
                    }
                    | BenchMatchStrategy::ContainsMatch {
                        field,
                        ac_pattern_id: _,
                    } => {
                        if let Some(field_value) = self.extract_field_value(event, field) {
                            let matches = ac.find_iter(&field_value).any(|m| {
                                self.ac_pattern_to_primitive.get(&m.pattern().as_usize())
                                    == Some(primitive_id)
                            });

                            if matches {
                                let idx = *primitive_id as usize;
                                if idx < results.len() {
                                    results[idx] = match strategy {
                                        BenchMatchStrategy::ExactMatch { .. } => {
                                            ac.find(&field_value).is_some_and(|m| {
                                                m.start() == 0 && m.end() == field_value.len()
                                            })
                                        }
                                        BenchMatchStrategy::ContainsMatch { .. } => true,
                                        _ => false,
                                    };
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Process simple equality matches
        for (primitive_id, strategy) in &self.primitive_strategies {
            if let BenchMatchStrategy::Equals { field, value } = strategy {
                if let Some(field_value) = self.extract_field_value(event, field) {
                    if field_value == *value {
                        let idx = *primitive_id as usize;
                        if idx < results.len() {
                            results[idx] = true;
                        }
                    }
                }
            }
        }

        results
    }

    fn extract_field_value(&self, event: &Value, field: &str) -> Option<String> {
        match event.get(field) {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Number(n)) => Some(n.to_string()),
            Some(Value::Bool(b)) => Some(b.to_string()),
            _ => None,
        }
    }
}

fn setup_test_environment() -> (
    Vec<sigma_engine::ir::BytecodeChunk>,
    BenchPrimitiveMatcher,
    Vm<64>,
    usize,
) {
    let mut compiler = Compiler::new();

    // Create a simple test rule
    let rule_yaml = r#"
title: Test Login Event
logsource:
    category: authentication
detection:
    selection:
        EventID: 4624
    condition: selection
"#;

    let chunk = compiler
        .compile_rule(rule_yaml)
        .expect("Failed to compile test rule");
    let chunks = vec![chunk];
    let ruleset = compiler.into_ruleset(chunks.clone());

    let matcher = BenchPrimitiveMatcher::new(&ruleset.primitives)
        .expect("Failed to create primitive matcher");

    let vm = Vm::<64>::new();

    (chunks, matcher, vm, ruleset.primitive_count())
}

fn bench_end_to_end_single_event(c: &mut Criterion) {
    let (chunks, matcher, mut vm, primitive_count) = setup_test_environment();

    let test_event = r#"{"EventID": "4624", "LogonType": "2", "TargetUserName": "admin"}"#;
    let parsed_event: Value = serde_json::from_str(test_event).unwrap();

    c.bench_function("end_to_end_single_event", |b| {
        b.iter(|| {
            // Parse JSON (in real scenario this would be done once per event)
            let event = black_box(&parsed_event);

            // Evaluate primitives
            let primitive_results = matcher.evaluate_primitives(event, primitive_count);

            // Execute VM for each rule
            for chunk in &chunks {
                let _result = vm.execute(chunk, &primitive_results);
            }
        })
    });
}

fn bench_end_to_end_batch_events(c: &mut Criterion) {
    let (chunks, matcher, mut vm, primitive_count) = setup_test_environment();

    let test_events = [
        r#"{"EventID": "4624", "LogonType": "2", "TargetUserName": "admin"}"#,
        r#"{"EventID": "4625", "LogonType": "2", "TargetUserName": "user"}"#,
        r#"{"EventID": "4624", "LogonType": "3", "TargetUserName": "service"}"#,
        r#"{"ProcessName": "cmd.exe", "CommandLine": "whoami"}"#,
    ];

    let parsed_events: Vec<Value> = test_events
        .iter()
        .map(|e| serde_json::from_str(e).unwrap())
        .collect();

    for batch_size in [1, 10, 100, 1000].iter() {
        c.bench_with_input(
            BenchmarkId::new("end_to_end_batch", batch_size),
            batch_size,
            |b, &batch_size| {
                b.iter(|| {
                    for i in 0..batch_size {
                        let event = &parsed_events[i % parsed_events.len()];

                        // Evaluate primitives
                        let primitive_results = matcher.evaluate_primitives(event, primitive_count);

                        // Execute VM for each rule
                        for chunk in &chunks {
                            let _result = vm.execute(chunk, &primitive_results);
                        }
                    }
                })
            },
        );
    }
}

fn bench_primitive_matching_only(c: &mut Criterion) {
    let (_, matcher, _, primitive_count) = setup_test_environment();

    let test_event = r#"{"EventID": "4624", "LogonType": "2", "TargetUserName": "admin"}"#;
    let parsed_event: Value = serde_json::from_str(test_event).unwrap();

    c.bench_function("primitive_matching_only", |b| {
        b.iter(|| {
            let event = black_box(&parsed_event);
            let _results = matcher.evaluate_primitives(event, primitive_count);
        })
    });
}

fn bench_json_parsing_only(c: &mut Criterion) {
    let test_event = r#"{"EventID": "4624", "LogonType": "2", "TargetUserName": "admin"}"#;

    c.bench_function("json_parsing_only", |b| {
        b.iter(|| {
            let event_str = black_box(test_event);
            let _parsed: Value = serde_json::from_str(event_str).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_end_to_end_single_event,
    bench_end_to_end_batch_events,
    bench_primitive_matching_only,
    bench_json_parsing_only
);
criterion_main!(benches);
