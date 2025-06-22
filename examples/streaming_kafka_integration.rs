//! Comprehensive streaming architecture demonstration.
//!
//! This example showcases the complete streaming architecture designed for
//! Kafka integration patterns, including adaptive batching, backpressure
//! handling, and performance monitoring.

use serde_json::json;
use sigma_engine::streaming::{
    AdaptiveBatcher, BackpressureController, BatchingConfig, BatchingStrategy, EventMetadata,
    StreamingConfig, StreamingEngine, StreamingEvent,
};
use sigma_engine::Compiler;
use std::time::{Duration, Instant};

fn main() {
    println!("SIGMA Engine Streaming Architecture Demonstration");
    println!("================================================");
    println!();

    // Demonstrate adaptive batching
    demonstrate_adaptive_batching();
    println!();

    // Demonstrate backpressure control
    demonstrate_backpressure_control();
    println!();

    // Demonstrate streaming engine
    demonstrate_streaming_engine();
    println!();

    // Demonstrate Kafka integration patterns
    demonstrate_kafka_patterns();
}

/// Demonstrate adaptive batching capabilities.
fn demonstrate_adaptive_batching() {
    println!("=== Adaptive Batching Demonstration ===");

    let strategies = [
        ("Fixed", BatchingStrategy::Fixed),
        ("Adaptive", BatchingStrategy::Adaptive),
        ("Time-based", BatchingStrategy::TimeBased),
        ("Hybrid", BatchingStrategy::Hybrid),
    ];

    for (name, strategy) in strategies {
        let mut config = BatchingConfig::kafka_optimized();
        config.strategy = strategy;
        config.initial_batch_size = 100;

        let mut batcher = AdaptiveBatcher::new(config);

        // Simulate varying event arrival patterns
        let events = generate_test_events(500);
        let mut batches_created = 0;
        let _start_time = Instant::now();

        for event in events {
            batcher.add_event(event);

            if batcher.should_create_batch() {
                if let Some(batch) = batcher.create_batch() {
                    batches_created += 1;
                    // Simulate processing time
                    let processing_time = Duration::from_millis(10 + (batch.size() / 10) as u64);
                    batcher.update_metrics(batch.size(), processing_time);
                }
            }
        }

        // Flush remaining events
        if let Some(_batch) = batcher.flush() {
            batches_created += 1;
        }

        let stats = batcher.get_stats();
        println!("{} Strategy:", name);
        println!("  Batches created: {}", batches_created);
        println!("  Current batch size: {}", stats.current_batch_size);
        println!(
            "  Average throughput: {:.0} EPS",
            stats.average_throughput.unwrap_or(0.0)
        );
        println!(
            "  Processing time: {:.1}ms",
            stats
                .average_processing_time
                .unwrap_or(Duration::ZERO)
                .as_secs_f64()
                * 1000.0
        );
    }
}

/// Demonstrate backpressure control.
fn demonstrate_backpressure_control() {
    println!("=== Backpressure Control Demonstration ===");

    let mut config = sigma_engine::streaming::BackpressureConfig::kafka_optimized();
    config.max_queue_size = 1000;
    config.high_watermark = 0.8;

    let mut controller = BackpressureController::new(config);

    // Simulate high load scenario
    println!("Simulating high load scenario...");

    for i in 0..1200 {
        let event_size = 1024; // 1KB per event

        if controller.can_accept_event(event_size) {
            controller.event_added(event_size);
        } else {
            controller.event_dropped();
            println!("Event {} dropped due to backpressure", i);
        }

        // Simulate some processing
        if i % 100 == 0 {
            for _ in 0..50 {
                controller.event_processed(event_size);
            }
        }
    }

    let stats = controller.get_stats();
    println!("Backpressure Statistics:");
    println!("  State: {:?}", stats.state);
    println!(
        "  Queue utilization: {:.1}%",
        stats.queue_utilization * 100.0
    );
    println!(
        "  Memory utilization: {:.1}%",
        stats.memory_utilization * 100.0
    );
    println!("  Processing rate: {:.0} EPS", stats.processing_rate);
    println!("  Arrival rate: {:.0} EPS", stats.arrival_rate);
    println!("  Total dropped: {}", stats.total_dropped);
}

/// Demonstrate streaming engine capabilities.
fn demonstrate_streaming_engine() {
    println!("=== Streaming Engine Demonstration ===");

    // Create test rules
    let rules = [
        r#"
title: Successful Logon Detection
logsource:
    category: security
detection:
    selection:
        EventID: 4624
        LogonType: "3"
    condition: selection
"#,
        r#"
title: Failed Logon Detection
logsource:
    category: security
detection:
    selection:
        EventID: 4625
    condition: selection
"#,
        r#"
title: PowerShell Execution
logsource:
    category: process_creation
detection:
    selection:
        Image: "*powershell.exe"
    condition: selection
"#,
    ];

    let rule_strs: Vec<&str> = rules.iter().map(|s| s.as_ref()).collect();
    let mut compiler = Compiler::new();
    let ruleset = compiler
        .compile_ruleset(&rule_strs)
        .expect("Failed to compile rules");

    // Create streaming engine with Kafka-optimized configuration
    let config = StreamingConfig::kafka_optimized();
    let mut engine =
        StreamingEngine::new(ruleset, config).expect("Failed to create streaming engine");

    engine.start();

    // Generate test events
    let events = generate_test_events(1000);
    let start_time = Instant::now();

    // Process events
    let results = engine
        .process_events(events)
        .expect("Failed to process events");

    let processing_time = start_time.elapsed();
    let total_matches: usize = results.iter().map(|r| r.match_count()).sum();

    println!("Streaming Engine Results:");
    println!("  Events processed: {}", results.len());
    println!("  Total matches: {}", total_matches);
    println!(
        "  Processing time: {:.1}ms",
        processing_time.as_secs_f64() * 1000.0
    );
    println!(
        "  Throughput: {:.0} EPS",
        results.len() as f64 / processing_time.as_secs_f64()
    );

    // Get engine statistics
    let stats = engine.get_engine_stats();
    println!(
        "  Batching stats: {} pending events",
        stats.batching_stats.pending_events
    );
    println!("  Backpressure: {:?}", stats.backpressure_stats.state);

    if let Some(metrics) = stats.metrics_summary {
        println!("  Metrics: {}", metrics.format());
    }
}

/// Demonstrate Kafka integration patterns.
fn demonstrate_kafka_patterns() {
    println!("=== Kafka Integration Patterns ===");

    // Simulate Kafka consumer pattern
    println!("Simulating Kafka consumer with multiple partitions...");

    let configs = [
        ("Low Latency", StreamingConfig::low_latency()),
        ("High Throughput", StreamingConfig::high_throughput()),
        ("Kafka Optimized", StreamingConfig::kafka_optimized()),
    ];

    for (config_name, config) in configs {
        println!("\n{} Configuration:", config_name);

        // Create a simple ruleset for testing
        let rules = [r#"
title: Test Rule
logsource:
    category: test
detection:
    selection:
        EventID: 4624
    condition: selection
"#];

        let rule_strs: Vec<&str> = rules.iter().map(|s| s.as_ref()).collect();
        let mut compiler = Compiler::new();
        let ruleset = compiler
            .compile_ruleset(&rule_strs)
            .expect("Failed to compile rules");

        let mut engine = StreamingEngine::new(ruleset, config).expect("Failed to create engine");
        engine.start();

        // Simulate Kafka partition consumption
        let partitions = 4;
        let events_per_partition = 250;
        let mut total_processed = 0;
        let start_time = Instant::now();

        for partition_id in 0..partitions {
            let partition_events = generate_partition_events(partition_id, events_per_partition);
            let results = engine
                .process_events(partition_events)
                .expect("Failed to process partition events");
            total_processed += results.len();
        }

        let total_time = start_time.elapsed();
        let throughput = total_processed as f64 / total_time.as_secs_f64();

        println!("  Partitions: {}", partitions);
        println!("  Events per partition: {}", events_per_partition);
        println!("  Total processed: {}", total_processed);
        println!(
            "  Processing time: {:.1}ms",
            total_time.as_secs_f64() * 1000.0
        );
        println!("  Throughput: {:.0} EPS", throughput);

        let stats = engine.get_engine_stats();
        println!(
            "  Final batch size: {}",
            stats.batching_stats.current_batch_size
        );
        println!("  Backpressure state: {:?}", stats.backpressure_stats.state);
    }

    println!("\n=== Integration Summary ===");
    println!("The streaming architecture provides:");
    println!("1. **Adaptive Batching**: Automatically adjusts batch size for optimal performance");
    println!("2. **Backpressure Control**: Prevents memory exhaustion under high load");
    println!("3. **Performance Monitoring**: Real-time metrics and observability");
    println!("4. **Kafka Patterns**: Optimized for Kafka-style partition consumption");
    println!("5. **Zero Dependencies**: No direct Kafka dependency, pure integration patterns");
    println!();
    println!("Ready for production Kafka integration with:");
    println!("- Consumer group management");
    println!("- Partition assignment strategies");
    println!("- Offset management");
    println!("- Error handling and retry logic");
}

/// Generate test events for demonstrations.
fn generate_test_events(count: usize) -> Vec<StreamingEvent> {
    let mut events = Vec::with_capacity(count);

    for i in 0..count {
        let event_data = match i % 5 {
            0 => json!({
                "EventID": "4624",
                "LogonType": "3",
                "TargetUserName": format!("user{}", i),
                "SourceNetworkAddress": "192.168.1.100"
            }),
            1 => json!({
                "EventID": "4625",
                "LogonType": "2",
                "TargetUserName": format!("admin{}", i),
                "FailureReason": "Bad password"
            }),
            2 => json!({
                "Image": "C:\\Windows\\System32\\powershell.exe",
                "CommandLine": format!("Get-Process {}", i),
                "ProcessId": 1000 + i
            }),
            3 => json!({
                "EventID": "1",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": format!("dir C:\\temp\\{}", i)
            }),
            _ => json!({
                "EventID": "7045",
                "ServiceName": format!("Service{}", i),
                "ServiceFileName": "C:\\Windows\\System32\\svchost.exe"
            }),
        };

        events.push(StreamingEvent::new(event_data));
    }

    events
}

/// Generate events for a specific Kafka partition.
fn generate_partition_events(partition_id: u32, count: usize) -> Vec<StreamingEvent> {
    let mut events = Vec::with_capacity(count);

    for i in 0..count {
        let event_data = json!({
            "EventID": "4624",
            "LogonType": "3",
            "TargetUserName": format!("partition{}_user{}", partition_id, i),
            "SourceNetworkAddress": format!("192.168.{}.{}", partition_id, i % 255),
            "partition_id": partition_id,
            "event_index": i
        });

        let metadata =
            EventMetadata::with_topic_offset(format!("security-events-{}", partition_id), i as u64);

        events.push(StreamingEvent::with_metadata(event_data, metadata));
    }

    events
}
