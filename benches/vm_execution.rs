//! Benchmarks for SIGMA Engine execution performance.
//!
//! These benchmarks measure the performance of the virtual machine
//! in high-EPS (Events Per Second) scenarios.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sigma_engine::{BytecodeChunk, Opcode, Vm};

/// Create a simple bytecode chunk for benchmarking.
fn create_simple_chunk() -> BytecodeChunk {
    BytecodeChunk::new(1, vec![Opcode::PushMatch(0), Opcode::ReturnMatch(1)])
}

/// Create a complex bytecode chunk with multiple operations.
fn create_complex_chunk() -> BytecodeChunk {
    BytecodeChunk::new(
        2,
        vec![
            Opcode::PushMatch(0), // A
            Opcode::PushMatch(1), // B
            Opcode::And,          // A and B
            Opcode::PushMatch(2), // C
            Opcode::Or,           // (A and B) or C
            Opcode::PushMatch(3), // D
            Opcode::Not,          // not D
            Opcode::And,          // ((A and B) or C) and (not D)
            Opcode::ReturnMatch(2),
        ],
    )
}

/// Create a deeply nested expression for stress testing.
fn create_deeply_nested_chunk() -> BytecodeChunk {
    // Create a deeply nested expression: A and (B or (C and (D or (E and F))))
    let opcodes = vec![
        Opcode::PushMatch(0), // A
        Opcode::PushMatch(1), // B
        Opcode::PushMatch(2), // C
        Opcode::PushMatch(3), // D
        Opcode::PushMatch(4), // E
        Opcode::PushMatch(5), // F
        Opcode::And,          // E and F
        Opcode::Or,           // D or (E and F)
        Opcode::And,          // C and (D or (E and F))
        Opcode::Or,           // B or (C and (D or (E and F)))
        Opcode::And,          // A and (B or (C and (D or (E and F))))
        Opcode::ReturnMatch(3),
    ];

    BytecodeChunk::new(3, opcodes)
}

/// Benchmark simple VM execution.
fn bench_simple_execution(c: &mut Criterion) {
    let chunk = create_simple_chunk();
    let mut vm = Vm::<64>::new();

    let mut group = c.benchmark_group("simple_execution");

    // Benchmark checked execution
    group.bench_function("checked", |b| {
        b.iter(|| {
            let primitive_results = [black_box(true)];
            let result = vm.execute(black_box(&chunk), black_box(&primitive_results));
            black_box(result)
        })
    });

    // Benchmark unchecked execution
    group.bench_function("unchecked", |b| {
        b.iter(|| {
            let primitive_results = [black_box(true)];
            let result = vm.execute_unchecked(black_box(&chunk), black_box(&primitive_results));
            black_box(result)
        })
    });

    // Benchmark optimized execution (auto-selects best path)
    group.bench_function("optimized", |b| {
        b.iter(|| {
            let primitive_results = [black_box(true)];
            let result = vm.execute_optimized(black_box(&chunk), black_box(&primitive_results));
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark complex VM execution.
fn bench_complex_execution(c: &mut Criterion) {
    let chunk = create_complex_chunk();
    let mut vm = Vm::<64>::new();

    let mut group = c.benchmark_group("complex_execution");

    // Benchmark checked execution
    group.bench_function("checked", |b| {
        b.iter(|| {
            let primitive_results = [
                black_box(true),
                black_box(false),
                black_box(true),
                black_box(false),
            ];
            let result = vm.execute(black_box(&chunk), black_box(&primitive_results));
            black_box(result)
        })
    });

    // Benchmark unchecked execution
    group.bench_function("unchecked", |b| {
        b.iter(|| {
            let primitive_results = [
                black_box(true),
                black_box(false),
                black_box(true),
                black_box(false),
            ];
            let result = vm.execute_unchecked(black_box(&chunk), black_box(&primitive_results));
            black_box(result)
        })
    });

    // Benchmark optimized execution
    group.bench_function("optimized", |b| {
        b.iter(|| {
            let primitive_results = [
                black_box(true),
                black_box(false),
                black_box(true),
                black_box(false),
            ];
            let result = vm.execute_optimized(black_box(&chunk), black_box(&primitive_results));
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark deeply nested expression execution.
fn bench_deeply_nested_execution(c: &mut Criterion) {
    let chunk = create_deeply_nested_chunk();
    let mut vm = Vm::<64>::new();

    c.bench_function("deeply_nested_execution", |b| {
        b.iter(|| {
            let primitive_results = [
                black_box(true),
                black_box(false),
                black_box(true),
                black_box(false),
                black_box(true),
                black_box(false),
            ];
            let result = vm.execute(black_box(&chunk), black_box(&primitive_results));
            black_box(result)
        })
    });
}

/// Benchmark execution with varying primitive results.
fn bench_varying_primitive_results(c: &mut Criterion) {
    let chunk = create_complex_chunk();
    let mut vm = Vm::<64>::new();

    let test_cases = vec![
        ("all_true", [true, true, true, true]),
        ("all_false", [false, false, false, false]),
        ("mixed_1", [true, false, true, false]),
        ("mixed_2", [false, true, false, true]),
    ];

    let mut group = c.benchmark_group("varying_primitive_results");

    for (name, primitive_results) in test_cases {
        group.bench_with_input(
            BenchmarkId::new("complex", name),
            &primitive_results,
            |b, results| {
                b.iter(|| {
                    let result = vm.execute(black_box(&chunk), black_box(results));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

/// High-EPS simulation benchmark.
fn bench_high_eps_simulation(c: &mut Criterion) {
    let chunk = create_complex_chunk();
    let mut vm = Vm::<64>::new();

    let mut group = c.benchmark_group("high_eps_simulation");

    // Benchmark checked execution
    group.bench_function("checked", |b| {
        b.iter(|| {
            // Simulate processing 1000 events in a tight loop
            for i in 0..1000 {
                let primitive_results = [
                    black_box(i % 2 == 0),
                    black_box(i % 3 == 0),
                    black_box(i % 5 == 0),
                    black_box(i % 7 == 0),
                ];
                let result = vm.execute(black_box(&chunk), black_box(&primitive_results));
                let _ = black_box(result);
            }
        })
    });

    // Benchmark unchecked execution
    group.bench_function("unchecked", |b| {
        b.iter(|| {
            // Simulate processing 1000 events in a tight loop
            for i in 0..1000 {
                let primitive_results = [
                    black_box(i % 2 == 0),
                    black_box(i % 3 == 0),
                    black_box(i % 5 == 0),
                    black_box(i % 7 == 0),
                ];
                let result = vm.execute_unchecked(black_box(&chunk), black_box(&primitive_results));
                let _ = black_box(result);
            }
        })
    });

    // Benchmark optimized execution
    group.bench_function("optimized", |b| {
        b.iter(|| {
            // Simulate processing 1000 events in a tight loop
            for i in 0..1000 {
                let primitive_results = [
                    black_box(i % 2 == 0),
                    black_box(i % 3 == 0),
                    black_box(i % 5 == 0),
                    black_box(i % 7 == 0),
                ];
                let result = vm.execute_optimized(black_box(&chunk), black_box(&primitive_results));
                let _ = black_box(result);
            }
        })
    });

    group.finish();
}

/// Benchmark different VM stack sizes.
fn bench_different_stack_sizes(c: &mut Criterion) {
    let chunk = create_complex_chunk();
    let primitive_results = [true, false, true, false];

    let mut group = c.benchmark_group("stack_sizes");

    // Test different stack sizes
    group.bench_function("stack_16", |b| {
        let mut vm = Vm::<16>::new();
        b.iter(|| {
            let result = vm.execute(black_box(&chunk), black_box(&primitive_results));
            black_box(result)
        })
    });

    group.bench_function("stack_64", |b| {
        let mut vm = Vm::<64>::new();
        b.iter(|| {
            let result = vm.execute(black_box(&chunk), black_box(&primitive_results));
            black_box(result)
        })
    });

    group.bench_function("stack_256", |b| {
        let mut vm = Vm::<256>::new();
        b.iter(|| {
            let result = vm.execute(black_box(&chunk), black_box(&primitive_results));
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark with many primitive results.
fn bench_many_primitives(c: &mut Criterion) {
    // Create a chunk that uses many primitives
    let mut opcodes = Vec::new();
    for i in 0..32 {
        opcodes.push(Opcode::PushMatch(i));
        if i > 0 {
            opcodes.push(Opcode::Or);
        }
    }
    opcodes.push(Opcode::ReturnMatch(100));

    let chunk = BytecodeChunk::new(100, opcodes);
    let mut vm = Vm::<64>::new();

    c.bench_function("many_primitives", |b| {
        b.iter(|| {
            let primitive_results: Vec<bool> = (0..32).map(|i| i % 3 == 0).collect();
            let result = vm.execute(black_box(&chunk), black_box(&primitive_results));
            black_box(result)
        })
    });
}

criterion_group!(
    benches,
    bench_simple_execution,
    bench_complex_execution,
    bench_deeply_nested_execution,
    bench_varying_primitive_results,
    bench_high_eps_simulation,
    bench_different_stack_sizes,
    bench_many_primitives
);
criterion_main!(benches);
