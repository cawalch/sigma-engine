//! SIGMA Detection Engine Demo
//!
//! This example demonstrates end-to-end usage of the SIGMA detection engine,
//! including primitive matching, bytecode compilation, and VM execution.
//!
//! Run with: `cargo run --example engine_demo --features examples`

#[cfg(feature = "examples")]
use aho_corasick::AhoCorasick;
#[cfg(feature = "examples")]
use regex::Regex;
#[cfg(feature = "examples")]
use serde_json::Value;
#[cfg(feature = "examples")]
use sigma_engine::{Compiler, Primitive, Vm};
#[cfg(feature = "examples")]
use std::collections::HashMap;
#[cfg(feature = "examples")]
use std::fs::{self, File};
#[cfg(feature = "examples")]
use std::io::{BufRead, BufReader};
#[cfg(feature = "examples")]
use std::path::Path;
#[cfg(feature = "examples")]
use std::time::Instant;

#[cfg(not(feature = "examples"))]
fn main() {
    eprintln!("This example requires the 'examples' feature to be enabled.");
    eprintln!("Run with: cargo run --example engine_demo --features examples");
    std::process::exit(1);
}

#[cfg(feature = "examples")]
/// A primitive matcher that evaluates atomic conditions against JSON events.
///
/// This struct holds compiled patterns for efficient matching:
/// - AhoCorasick automaton for substring/exact matches
/// - Vector of compiled regexes for pattern matches
pub struct PrimitiveMatcher {
    /// Mapping from primitive ID to its evaluation strategy
    primitive_strategies: HashMap<u32, MatchStrategy>,

    /// AhoCorasick automaton for fast string matching
    aho_corasick: Option<AhoCorasick>,

    /// Mapping from AhoCorasick pattern ID to primitive ID
    ac_pattern_to_primitive: HashMap<usize, u32>,

    /// Compiled regex patterns
    regex_patterns: Vec<(u32, Regex)>,
}

/// Strategy for evaluating a primitive
#[derive(Debug, Clone)]
enum MatchStrategy {
    /// Exact string match using AhoCorasick
    ExactMatch {
        field: String,
        #[allow(dead_code)]
        ac_pattern_id: usize,
    },

    /// Substring match using AhoCorasick
    ContainsMatch {
        field: String,
        #[allow(dead_code)]
        ac_pattern_id: usize,
    },

    /// Regex pattern match
    RegexMatch {
        field: String,
        #[allow(dead_code)]
        regex_id: usize,
    },

    /// Simple equality check
    Equals { field: String, value: String },
}

impl PrimitiveMatcher {
    /// Create a new primitive matcher from the compiler's primitive map.
    pub fn new(primitives: &[Primitive]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut primitive_strategies = HashMap::new();
        let mut ac_patterns = Vec::new();
        let mut ac_pattern_to_primitive = HashMap::new();
        let mut regex_patterns = Vec::new();

        for (primitive_id, primitive) in primitives.iter().enumerate() {
            let primitive_id = primitive_id as u32;

            match primitive.match_type.as_ref() {
                "equals" => {
                    if primitive.values.len() == 1 {
                        // Simple equality - can use AhoCorasick for efficiency
                        let pattern_id = ac_patterns.len();
                        ac_patterns.push(primitive.values[0].as_ref());
                        ac_pattern_to_primitive.insert(pattern_id, primitive_id);

                        primitive_strategies.insert(
                            primitive_id,
                            MatchStrategy::ExactMatch {
                                field: primitive.field.to_string(),
                                ac_pattern_id: pattern_id,
                            },
                        );
                    } else {
                        // Multiple values - use first for demo
                        primitive_strategies.insert(
                            primitive_id,
                            MatchStrategy::Equals {
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
                            MatchStrategy::ContainsMatch {
                                field: primitive.field.to_string(),
                                ac_pattern_id: pattern_id,
                            },
                        );
                    }
                }
                "regex" => {
                    if !primitive.values.is_empty() {
                        let regex = Regex::new(&primitive.values[0])?;
                        let regex_id = regex_patterns.len();
                        regex_patterns.push((primitive_id, regex));

                        primitive_strategies.insert(
                            primitive_id,
                            MatchStrategy::RegexMatch {
                                field: primitive.field.to_string(),
                                regex_id,
                            },
                        );
                    }
                }
                _ => {
                    // Default to simple equality for unknown match types
                    primitive_strategies.insert(
                        primitive_id,
                        MatchStrategy::Equals {
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

        // Build AhoCorasick automaton if we have patterns
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

    /// Evaluate all primitives against a JSON event.
    /// Returns a vector of boolean results indexed by primitive ID.
    pub fn evaluate_primitives(&self, event: &Value, primitive_count: usize) -> Vec<bool> {
        let mut results = vec![false; primitive_count];

        // Process AhoCorasick matches
        if let Some(ref ac) = self.aho_corasick {
            for (primitive_id, strategy) in &self.primitive_strategies {
                match strategy {
                    MatchStrategy::ExactMatch {
                        field,
                        ac_pattern_id: _,
                    }
                    | MatchStrategy::ContainsMatch {
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
                                        MatchStrategy::ExactMatch { .. } => {
                                            // For exact match, check if the entire field equals the pattern
                                            ac.find(&field_value).is_some_and(|m| {
                                                m.start() == 0 && m.end() == field_value.len()
                                            })
                                        }
                                        MatchStrategy::ContainsMatch { .. } => true,
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

        // Process regex matches
        for (primitive_id, regex) in &self.regex_patterns {
            if let Some(MatchStrategy::RegexMatch { field, .. }) =
                self.primitive_strategies.get(primitive_id)
            {
                if let Some(field_value) = self.extract_field_value(event, field) {
                    if regex.is_match(&field_value) {
                        let idx = *primitive_id as usize;
                        if idx < results.len() {
                            results[idx] = true;
                        }
                    }
                }
            }
        }

        // Process simple equality matches
        for (primitive_id, strategy) in &self.primitive_strategies {
            if let MatchStrategy::Equals { field, value } = strategy {
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

    /// Extract a field value from a JSON event as a string.
    fn extract_field_value(&self, event: &Value, field: &str) -> Option<String> {
        match event.get(field) {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Number(n)) => Some(n.to_string()),
            Some(Value::Bool(b)) => Some(b.to_string()),
            _ => None,
        }
    }
}

/// Process events from a JSONL file
fn process_events_from_file(
    file_path: &Path,
    matcher: &PrimitiveMatcher,
    chunks: &[sigma_engine::ir::BytecodeChunk],
    vm: &mut Vm<64>,
    primitive_count: usize,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let mut total_events = 0;
    let mut total_matches = 0;

    println!("Processing events from: {}", file_path.display());

    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        // Parse JSON event
        let event: Value = serde_json::from_str(&line)?;

        // Evaluate primitives
        let primitive_results = matcher.evaluate_primitives(&event, primitive_count);

        // Execute each compiled rule
        for chunk in chunks {
            match vm.execute(chunk, &primitive_results) {
                Ok(Some(rule_id)) => {
                    println!(
                        "  Line {}: ✓ MATCH: Rule {} ({})",
                        line_num + 1,
                        rule_id,
                        chunk.rule_name.as_deref().unwrap_or("Unknown")
                    );
                    total_matches += 1;
                }
                Ok(None) => {
                    // No match - this is normal
                }
                Err(e) => {
                    println!("  Line {}: ✗ VM Error: {}", line_num + 1, e);
                }
            }
        }

        total_events += 1;
    }

    Ok((total_events, total_matches))
}

/// Main orchestration function
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("SIGMA Bytecode Engine Demo");
    println!("==========================");

    // Setup: Instantiate the compiler
    let mut compiler = Compiler::new();

    // Load and compile SIGMA rules from the tests directory
    let rules_dir = Path::new("tests/rules");
    let mut chunks = Vec::new();

    if rules_dir.exists() {
        println!("Loading SIGMA rules from: {}", rules_dir.display());

        for entry in fs::read_dir(rules_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path
                .extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
            {
                println!("  Compiling: {}", path.display());

                let rule_yaml = fs::read_to_string(&path)?;
                match compiler.compile_rule(&rule_yaml) {
                    Ok(chunk) => {
                        println!(
                            "    ✓ Compiled rule: {} (ID: {})",
                            chunk.rule_name.as_deref().unwrap_or("Unknown"),
                            chunk.rule_id
                        );
                        chunks.push(chunk);
                    }
                    Err(e) => {
                        println!("    ✗ Failed to compile {}: {}", path.display(), e);
                    }
                }
            }
        }
    } else {
        println!("Rules directory not found, creating a demo rule...");

        // Create a simple demo rule
        let demo_rule = r#"
title: Demo Login Event
logsource:
    category: authentication
detection:
    selection:
        EventID: 4624
    condition: selection
"#;

        let chunk = compiler.compile_rule(demo_rule)?;
        println!(
            "  ✓ Compiled demo rule: {} (ID: {})",
            chunk.rule_name.as_deref().unwrap_or("Unknown"),
            chunk.rule_id
        );
        chunks.push(chunk);
    }

    // Get the compiled ruleset
    let ruleset = compiler.into_ruleset(chunks.clone());

    println!("\nCompilation Summary:");
    println!("  Rules compiled: {}", chunks.len());
    println!("  Primitives discovered: {}", ruleset.primitive_count());

    // Instantiate the primitive matcher
    let matcher = PrimitiveMatcher::new(&ruleset.primitives)?;
    println!("  Primitive matcher initialized");

    // Instantiate the VM
    let mut vm = Vm::<64>::new();
    println!("  VM initialized with stack size: 64");

    // Demo execution with sample events
    println!("\nDemo Execution:");
    println!("===============");

    let sample_events = [
        r#"{"EventID": "4624", "LogonType": "2", "TargetUserName": "admin"}"#,
        r#"{"EventID": "4625", "LogonType": "2", "TargetUserName": "user"}"#,
        r#"{"EventID": "4624", "LogonType": "3", "TargetUserName": "service"}"#,
        r#"{"ProcessName": "cmd.exe", "CommandLine": "whoami"}"#,
    ];

    let start_time = Instant::now();
    let mut total_matches = 0;
    let mut total_events = 0;

    for (event_idx, event_json) in sample_events.iter().enumerate() {
        println!("\nProcessing event {}: {}", event_idx + 1, event_json);

        // Parse JSON event
        let event: Value = serde_json::from_str(event_json)?;

        // Evaluate primitives
        let primitive_results = matcher.evaluate_primitives(&event, ruleset.primitive_count());
        println!("  Primitive results: {:?}", primitive_results);

        // Execute each compiled rule
        for chunk in &chunks {
            match vm.execute(chunk, &primitive_results) {
                Ok(Some(rule_id)) => {
                    println!(
                        "  ✓ MATCH: Rule {} ({})",
                        rule_id,
                        chunk.rule_name.as_deref().unwrap_or("Unknown")
                    );
                    total_matches += 1;
                }
                Ok(None) => {
                    // No match - this is normal
                }
                Err(e) => {
                    println!("  ✗ VM Error: {}", e);
                }
            }
        }

        total_events += 1;
    }

    let elapsed = start_time.elapsed();

    println!("\nExecution Summary:");
    println!("==================");
    println!("  Total events processed: {}", total_events);
    println!("  Total matches found: {}", total_matches);
    println!("  Total execution time: {:?}", elapsed);
    println!(
        "  Average time per event: {:?}",
        elapsed / total_events as u32
    );

    if total_events > 0 {
        let events_per_second = total_events as f64 / elapsed.as_secs_f64();
        println!("  Events per second: {:.2}", events_per_second);
    }

    // Process events from file if available
    let sample_file = Path::new("examples/data/sample_events.jsonl");
    if sample_file.exists() {
        println!("\nFile Processing:");
        println!("================");

        let file_start_time = Instant::now();
        match process_events_from_file(
            sample_file,
            &matcher,
            &chunks,
            &mut vm,
            ruleset.primitive_count(),
        ) {
            Ok((file_events, file_matches)) => {
                let file_elapsed = file_start_time.elapsed();

                println!("\nFile Processing Summary:");
                println!("========================");
                println!("  Events processed from file: {}", file_events);
                println!("  Matches found in file: {}", file_matches);
                println!("  File processing time: {:?}", file_elapsed);

                if file_events > 0 {
                    println!(
                        "  Average time per file event: {:?}",
                        file_elapsed / file_events as u32
                    );
                    let file_eps = file_events as f64 / file_elapsed.as_secs_f64();
                    println!("  File events per second: {:.2}", file_eps);
                }

                // Combined statistics
                let combined_events = total_events + file_events;
                let combined_matches = total_matches + file_matches;
                let combined_elapsed = elapsed + file_elapsed;

                println!("\nCombined Summary:");
                println!("=================");
                println!("  Total events processed: {}", combined_events);
                println!("  Total matches found: {}", combined_matches);
                println!("  Total processing time: {:?}", combined_elapsed);

                if combined_events > 0 {
                    let combined_eps = combined_events as f64 / combined_elapsed.as_secs_f64();
                    println!("  Overall events per second: {:.2}", combined_eps);

                    let match_rate = (combined_matches as f64 / combined_events as f64) * 100.0;
                    println!("  Match rate: {:.1}%", match_rate);
                }
            }
            Err(e) => {
                println!("  ✗ Failed to process file: {}", e);
            }
        }
    } else {
        println!("\nSample file not found at: {}", sample_file.display());
        println!("You can create sample events in JSONL format for testing.");
    }

    Ok(())
}
