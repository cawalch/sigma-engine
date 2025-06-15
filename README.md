# SIGMA Engine - High-Performance SIGMA Detection Engine

[![CI](https://github.com/cawalch/sigma-engine/workflows/CI/badge.svg)](https://github.com/cawalch/sigma-engine/actions)

A Rust library for compiling and executing [SIGMA detection rules](https://github.com/SigmaHQ/sigma) using a stack-based bytecode virtual machine.

## Features

The engine is designed for performance and efficiency. Key characteristics include fast rule execution, minimal runtime memory allocation during VM execution, potential to handle a large number of rules with good throughput, broad compatibility with the SIGMA Rules Specification, efficient data structures, and support for concurrent execution.

## Performance

```
Simple Rules:    4.05 ns/rule   (250M rules/sec)
Complex Rules:   10.32 ns/rule  (97M rules/sec)
End-to-End:      85.9 ns/event  (11.6M events/sec)
2000 Rules:      5.8 µs/event   (173k events/sec)
```

## Architecture

SIGMA Engine separates rule processing into two phases:

1.  Offline Compilation: Parse SIGMA YAML rules and compile to efficient bytecode
2.  Online Execution: Execute bytecode with minimal allocation.

```rust
use sigma_engine::{Compiler, Vm};

// Offline: Compile SIGMA rules to bytecode
let mut compiler = Compiler::new();
let bytecode = compiler.compile_rule(&sigma_rule_yaml)?;

// Online: Execute bytecode with primitive results
let mut vm = Vm::new();
let result = vm.execute(&bytecode, &primitive_results)?;
```

## Installation

This project is currently in early development and not yet published on crates.io. You can include it in your project by specifying the git repository in your `Cargo.toml`.

```toml
[dependencies]
sigma-engine = { git = "https://github.com/cawalch/sigma-engine.git" }
```

For examples and demos, you can enable the `examples` feature:

```toml
[dependencies]
sigma-engine = { git = "https://github.com/cawalch/sigma-engine.git", features = ["examples"] }
```

## Quick Start

### Basic Usage

This example demonstrates compiling and executing a single SIGMA rule.

```rust
use sigma_engine::{Compiler, Vm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a compiler
    let mut compiler = Compiler::new();

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

    let bytecode = compiler.compile_rule(rule_yaml)?;

    // Create a VM and execute
    let mut vm = Vm::new();

    // Simulate primitive matching results
    let primitive_results = vec![true, true]; // EventID=4624: true, LogonType=2: true

    match vm.execute(&bytecode, &primitive_results)? {
        Some(rule_id) => println!("Rule {} matched!", rule_id),
        None => println!("No match"),
    }

    Ok(())
}
```

### Advanced Usage with Multiple Rules

This demonstrates compiling and executing a set of rules.

```rust
use sigma_engine::{Compiler, Vm, CompiledRuleset};

fn compile_ruleset(rule_files: &[&str]) -> Result<CompiledRuleset, Box<dyn std::error::Error>> {
    let mut compiler = Compiler::new();
    let mut chunks = Vec::new();

    for rule_file in rule_files {
        let rule_yaml = std::fs::read_to_string(rule_file)?;
        let chunk = compiler.compile_rule(&rule_yaml)?;
        chunks.push(chunk);
    }

    Ok(compiler.into_ruleset(chunks))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile multiple rules
    let ruleset = compile_ruleset(&["rule1.yml", "rule2.yml", "rule3.yml"])?;

    // Create VM with larger stack for complex rules
    let mut vm = Vm::<128>::new();

    // Process events
    for event in events {
        let primitive_results = evaluate_primitives(&event, &ruleset.primitives);

        for chunk in &ruleset.chunks {
            if let Some(rule_id) = vm.execute(chunk, &primitive_results)? {
                println!("Event matched rule {}: {}",
                    rule_id,
                    chunk.rule_name.as_deref().unwrap_or("Unknown")
                );
            }
        }
    }

    Ok(())
}
```

## Use Cases

Potential applications for SIGMA Engine include security information and event management (SIEM) for high-speed log analysis, endpoint detection and response (EDR) for real-time threat detection, network security monitoring for traffic analysis, threat hunting, and security orchestration.

## Documentation

- API Documentation (generated locally)
- Performance Benchmarks (README_BENCHMARKING.md)
- Profiling Guide (docs/PROFILING.md)
- Examples (examples/)

## Examples

You can run the provided examples locally to see the engine in action.

### Basic Usage

Learn the fundamentals with a simple example:

```bash
cargo run --example basic_usage --features examples
```

### Advanced Usage

Explore features like field mapping and multiple rules:

```bash
cargo run --example advanced_usage --features examples
```

### Full Engine Demo

See the complete pipeline with primitive matching:

```bash
cargo run --example engine_demo --features examples
```

### Performance Benchmarks

```bash
cargo bench
```

### Large Scale Testing

```bash
./scripts/demo_2k_rules.sh
```

## Benchmarking

SIGMA Engine includes benchmarking infrastructure.

```bash
# Run all benchmarks
make bench

# Run specific benchmark suites
cargo bench --bench vm_execution
cargo bench --bench end_to_end
cargo bench --bench rule_scaling
```

See README_BENCHMARKING.md for detailed performance analysis.

## Development

### Prerequisites

- Rust 1.72.0 or later
- Git

### Setup

```bash
git clone https://github.com/cawalch/sigma-engine.git
cd sigma-engine
make dev-setup
```

### Testing

```bash
# Run all tests
make test

# Run with coverage
make coverage

# Run quality checks
make quality
```

### Development Workflow

1.  Fork the repository.
2.  Create a feature branch.
3.  Make your changes.
4.  Run `make quality` to ensure code quality.
5.  Submit a pull request.

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Acknowledgments

- [SIGMA Project](https://github.com/SigmaHQ/sigma) for the detection rule format.
- [Rust Community](https://www.rust-lang.org/community) for tooling and libraries.
