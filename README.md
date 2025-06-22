# SIGMA Engine

[![CI](https://github.com/cawalch/sigma-engine/workflows/CI/badge.svg)](https://github.com/cawalch/sigma-engine/actions)

A high-performance Rust library for compiling and executing [SIGMA detection rules](https://github.com/SigmaHQ/sigma) using a DAG-based execution engine with shared computation optimization.

## Architecture

SIGMA Engine uses a **pure DAG architecture** optimized for high-performance event processing:

### Phase 1: YAML Rules → DAG (Compilation)

Parse SIGMA YAML rules and compile them directly into an optimized DAG structure with shared primitive nodes.

### Phase 2: DAG Execution (Runtime)

Process events directly as `serde_json::Value` with zero-copy patterns and shared computation across rules.

```rust
use sigma_engine::{Compiler, SigmaEngine};

// Offline compilation
let mut compiler = Compiler::new();
let ruleset = compiler.compile_ruleset(&rules)?;

// Create DAG engine
let mut engine = SigmaEngine::from_ruleset(ruleset)?;

// Online execution
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
use sigma_engine::{Compiler, SigmaEngine};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile SIGMA rules
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

    // Create engine
    let mut engine = SigmaEngine::from_ruleset(ruleset)?;

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
use sigma_engine::{Compiler, FieldMapping, SigmaEngine};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up field mapping for custom taxonomy
    let mut field_mapping = FieldMapping::with_taxonomy("custom_edr".to_string());
    field_mapping.add_mapping("ProcessImage".to_string(), "Image".to_string());

    let mut compiler = Compiler::with_field_mapping(field_mapping);

    let rules = vec![
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
    let mut engine = SigmaEngine::from_ruleset(ruleset)?;

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
use sigma_engine::{Compiler, SigmaEngine};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

## Use Cases

- **SIEM**: High-speed log analysis and correlation
- **EDR**: Real-time threat detection and response

## Development

### Prerequisites

- Rust 1.72.0 or later

### Setup

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

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Acknowledgments

- [SIGMA Project](https://github.com/SigmaHQ/sigma) for the detection rule format.
- [Rust Community](https://www.rust-lang.org/community) for tooling and libraries.
