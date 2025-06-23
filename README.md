# SIGMA Engine

[![CI](https://github.com/cawalch/sigma-engine/workflows/CI/badge.svg)](https://github.com/cawalch/sigma-engine/actions)

A high-performance Rust library for compiling and executing [SIGMA detection rules](https://github.com/SigmaHQ/sigma) using a DAG-based execution engine with shared computation optimization and AhoCorasick prefiltering.

## Architecture

SIGMA Engine uses a **pure DAG architecture** with **literal prefiltering** optimized for high-performance event processing:

### Phase 1: YAML Rules → DAG (Compilation)

Parse SIGMA YAML rules and compile them directly into an optimized DAG structure with shared primitive nodes and optional AhoCorasick prefilter.

### Phase 2: DAG Execution (Runtime)

Process events directly as `serde_json::Value` with zero-copy patterns, shared computation across rules, and fast literal pattern elimination.

```rust
use sigma_engine::SigmaEngine;

// Simple API - automatic compilation and optimization
let mut engine = SigmaEngine::from_rules(&[rule_yaml])?;

// Online execution with prefiltering
let event = serde_json::from_str(r#"{"EventID": "4624"}"#)?;
let matches = engine.evaluate(&event)?;
```

## Installation

```toml
[dependencies]
sigma-engine = { git = "https://github.com/cawalch/sigma-engine.git" }
```

## Usage

### Basic Example

```rust
use sigma_engine::SigmaEngine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define SIGMA rule
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

    // Create engine with automatic compilation and optimization
    let mut engine = SigmaEngine::from_rules(&[rule_yaml])?;

    // Evaluate events
    let event = serde_json::json!({
        "EventID": "4624",
        "LogonType": 2
    });

    let result = engine.evaluate(&event)?;
    println!("Matched rules: {:?}", result.matched_rules);

    Ok(())
}
```

### Multiple Rules with Field Mapping

```rust
use sigma_engine::{Compiler, FieldMapping, SigmaEngine, DagEngineConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up field mapping for custom taxonomy
    let mut field_mapping = FieldMapping::new();
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());
    field_mapping.add_mapping("ProcessCommandLine".to_string(), "CommandLine".to_string());

    let compiler = Compiler::with_field_mapping(field_mapping);

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

    // Create engine with custom compiler and configuration
    let config = DagEngineConfig::default();
    let mut engine = SigmaEngine::from_rules_with_compiler(&rules, compiler, config)?;

    let event = serde_json::json!({
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -Command Invoke-Expression"
    });

    let result = engine.evaluate(&event)?;
    println!("Matched rules: {:?}", result.matched_rules);

    Ok(())
}
```

### Batch Processing

```rust
use sigma_engine::SigmaEngine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Create engine with automatic compilation
    let mut engine = SigmaEngine::from_rules(&[rule_yaml])?;

    let events = vec![
        serde_json::json!({"EventID": "4624", "LogonType": 2}),
        serde_json::json!({"EventID": "4624", "LogonType": 3}),
        serde_json::json!({"EventID": "4625", "LogonType": 2}),
    ];

    let results = engine.evaluate_batch(&events)?;
    let total_matches: usize = results.iter().map(|r| r.matched_rules.len()).sum();
    println!("Total matches: {}", total_matches);

    Ok(())
}
```

### Advanced Configuration

```rust
use sigma_engine::{SigmaEngine, DagEngineConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rule_yaml = r#"
title: High Performance Rule
detection:
    selection:
        EventID: 4624
    condition: selection
"#;

    // Configure for high-performance scenarios
    let config = DagEngineConfig {
        enable_optimization: true,
        enable_parallel_processing: true,
        enable_prefilter: true,
        ..Default::default()
    };

    // Use builder pattern for advanced configuration
    let mut engine = SigmaEngine::builder()
        .with_config(config)
        .build(&[rule_yaml])?;

    let event = serde_json::json!({"EventID": "4624"});
    let result = engine.evaluate(&event)?;
    println!("Matched rules: {:?}", result.matched_rules);

    Ok(())
}
```

## Features

- **High Performance**: DAG-based execution with shared computation optimization
- **Batch Processing**: Optimized batch evaluation for high-throughput scenarios
- **Zero-Copy Processing**: Efficient memory usage with `serde_json::Value`
- **Parallel Processing**: Multi-threaded evaluation for large event batches
- **Configurable Optimization**: Multiple optimization levels and caching strategies

```rust
use sigma_engine::{SigmaEngine, DagEngineConfig};

// Enable high-performance prefiltering
let config = DagEngineConfig {
    enable_prefilter: true,
    enable_optimization: true,
    ..Default::default()
};

let mut engine = SigmaEngine::builder()
    .with_config(config)
    .build(&rules)?;
```

## API Overview

```rust
// Simple API - automatic compilation and optimization
let mut engine = SigmaEngine::from_rules(&[rule_yaml])?;

// Builder pattern with configuration
let mut engine = SigmaEngine::builder()
    .with_prefilter(true)
    .with_optimization(true)
    .build(&[rule_yaml])?;

// Custom compiler and configuration
let mut engine = SigmaEngine::from_rules_with_compiler(&rules, compiler, config)?;
```

## Setup

```bash
git clone https://github.com/cawalch/sigma-engine.git
cd sigma-engine
make dev-setup
```

### Testing

```bash
make test      # Run tests
make coverage  # Run with coverage
make quality   # Run quality checks
```

### Benchmarking

```bash
# Run all benchmarks
cargo bench

# Run specific benchmarks
cargo bench --bench end_to_end
cargo bench --bench dag_execution
cargo bench --bench prefilter_performance

# Profile prefilter effectiveness
cargo run --example debug_benchmark_selectivity
```

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Acknowledgments

- [SIGMA Project](https://github.com/SigmaHQ/sigma) for the detection rule format.
- [Rust Community](https://www.rust-lang.org/community) for tooling and libraries.
