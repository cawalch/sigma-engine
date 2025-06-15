//! # SIGMA Detection Engine
//!
//! A high-performance Rust library for compiling and executing SIGMA detection rules
//! using a stack-based bytecode virtual machine.
//!
//! ## Architecture
//!
//! This crate is divided into two main components:
//! - **Compiler** (offline): Parses SIGMA YAML rules and compiles them to bytecode
//! - **Virtual Machine** (online): Executes bytecode at high speed with minimal allocation
//!
//! ## Usage
//!
//! ```rust,ignore
//! use sigma_engine::{Compiler, Vm};
//!
//! // Offline compilation
//! let mut compiler = Compiler::new();
//! let bytecode = compiler.compile_rule(&sigma_rule)?;
//!
//! // Online execution
//! let mut vm = Vm::new();
//! let result = vm.execute(&bytecode, &primitive_results);
//! ```

pub mod compiler;
pub mod error;
pub mod ir;
pub mod vm;

pub use compiler::{Compiler, FieldMapping};
pub use error::{Result, SigmaError};
pub use ir::{BytecodeChunk, CompiledRuleset, Opcode, Primitive, PrimitiveId, RuleId};
pub use vm::{DefaultVm, Vm};
