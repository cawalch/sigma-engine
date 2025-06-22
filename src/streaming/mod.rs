//! Streaming architecture for high-throughput event processing.
//!
//! This module provides streaming architecture components optimized for Kafka-based
//! event processing with adaptive batching, backpressure handling, and performance
//! monitoring. The design provides integration patterns without adding Kafka as a
//! direct dependency.
//!
//! ## Kafka Integration Patterns
//!
//! This module provides the patterns and interfaces needed for Kafka integration:
//!
//! ```rust,ignore
//! use sigma_engine::streaming::{StreamingEngine, StreamingConfig};
//!
//! // Create streaming engine optimized for Kafka workloads
//! let config = StreamingConfig::kafka_optimized();
//! let mut engine = StreamingEngine::new(ruleset, config)?;
//!
//! // Process events with adaptive batching
//! let results = engine.process_events(events).await?;
//! ```
//!

pub mod adaptive_batcher;
pub mod backpressure;
pub mod batch_processor;
pub mod engine;
pub mod metrics;

// Re-export main types for convenience
pub use adaptive_batcher::{AdaptiveBatcher, BatchingConfig, BatchingStrategy};
pub use backpressure::{BackpressureConfig, BackpressureController, FlowControlStrategy};
pub use batch_processor::{BatchProcessor, BatchProcessorConfig, ProcessingResult};
pub use engine::StreamingEngine;
pub use metrics::{MetricsCollector, PerformanceStats, StreamingMetrics};

use serde_json::Value;
use std::time::{Duration, Instant};

/// Event metadata for streaming processing.
#[derive(Debug, Clone)]
pub struct EventMetadata {
    /// Timestamp when the event was received
    pub received_at: Instant,
    /// Optional partition key for Kafka-style partitioning
    pub partition_key: Option<String>,
    /// Optional offset for tracking position in stream
    pub offset: Option<u64>,
    /// Optional topic for multi-topic processing
    pub topic: Option<String>,
}

impl EventMetadata {
    /// Create new event metadata with current timestamp.
    pub fn new() -> Self {
        Self {
            received_at: Instant::now(),
            partition_key: None,
            offset: None,
            topic: None,
        }
    }

    /// Create event metadata with partition key.
    pub fn with_partition_key(partition_key: String) -> Self {
        Self {
            received_at: Instant::now(),
            partition_key: Some(partition_key),
            offset: None,
            topic: None,
        }
    }

    /// Create event metadata with offset.
    pub fn with_offset(offset: u64) -> Self {
        Self {
            received_at: Instant::now(),
            partition_key: None,
            offset: Some(offset),
            topic: None,
        }
    }

    /// Create event metadata with topic and offset.
    pub fn with_topic_offset(topic: String, offset: u64) -> Self {
        Self {
            received_at: Instant::now(),
            partition_key: None,
            offset: Some(offset),
            topic: Some(topic),
        }
    }

    /// Get the age of this event.
    pub fn age(&self) -> Duration {
        self.received_at.elapsed()
    }
}

impl Default for EventMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// A streaming event with metadata.
#[derive(Debug, Clone)]
pub struct StreamingEvent {
    /// The event data
    pub data: Value,
    /// Event metadata
    pub metadata: EventMetadata,
}

impl StreamingEvent {
    /// Create a new streaming event.
    pub fn new(data: Value) -> Self {
        Self {
            data,
            metadata: EventMetadata::new(),
        }
    }

    /// Create a streaming event with metadata.
    pub fn with_metadata(data: Value, metadata: EventMetadata) -> Self {
        Self { data, metadata }
    }

    /// Get the age of this event.
    pub fn age(&self) -> Duration {
        self.metadata.age()
    }
}

impl From<Value> for StreamingEvent {
    fn from(data: Value) -> Self {
        Self::new(data)
    }
}

/// Result of streaming event processing.
#[derive(Debug, Clone)]
pub struct StreamingResult {
    /// Matched rule IDs
    pub matched_rules: Vec<crate::ir::RuleId>,
    /// Processing latency
    pub latency: Duration,
    /// Event metadata
    pub metadata: EventMetadata,
    /// Performance metrics
    pub metrics: PerformanceStats,
}

impl StreamingResult {
    /// Create a new streaming result.
    pub fn new(
        matched_rules: Vec<crate::ir::RuleId>,
        latency: Duration,
        metadata: EventMetadata,
        metrics: PerformanceStats,
    ) -> Self {
        Self {
            matched_rules,
            latency,
            metadata,
            metrics,
        }
    }

    /// Check if any rules matched.
    pub fn has_matches(&self) -> bool {
        !self.matched_rules.is_empty()
    }

    /// Get the number of matched rules.
    pub fn match_count(&self) -> usize {
        self.matched_rules.len()
    }
}

/// Batch of streaming events for processing.
#[derive(Debug, Clone)]
pub struct EventBatch {
    /// Events in this batch
    pub events: Vec<StreamingEvent>,
    /// Batch creation timestamp
    pub created_at: Instant,
    /// Batch ID for tracking
    pub batch_id: u64,
}

impl EventBatch {
    /// Create a new event batch.
    pub fn new(events: Vec<StreamingEvent>, batch_id: u64) -> Self {
        Self {
            events,
            created_at: Instant::now(),
            batch_id,
        }
    }

    /// Get the size of this batch.
    pub fn size(&self) -> usize {
        self.events.len()
    }

    /// Check if this batch is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get the age of this batch.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get the oldest event in this batch.
    pub fn oldest_event_age(&self) -> Option<Duration> {
        self.events.iter().map(|e| e.age()).max()
    }
}

/// Result of batch processing.
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// Results for each event in the batch
    pub results: Vec<StreamingResult>,
    /// Batch processing latency
    pub batch_latency: Duration,
    /// Batch ID
    pub batch_id: u64,
    /// Aggregate metrics
    pub aggregate_metrics: PerformanceStats,
}

impl BatchResult {
    /// Create a new batch result.
    pub fn new(
        results: Vec<StreamingResult>,
        batch_latency: Duration,
        batch_id: u64,
        aggregate_metrics: PerformanceStats,
    ) -> Self {
        Self {
            results,
            batch_latency,
            batch_id,
            aggregate_metrics,
        }
    }

    /// Get the total number of matches across all events.
    pub fn total_matches(&self) -> usize {
        self.results.iter().map(|r| r.match_count()).sum()
    }

    /// Get the number of events that had matches.
    pub fn events_with_matches(&self) -> usize {
        self.results.iter().filter(|r| r.has_matches()).count()
    }

    /// Get the average processing latency per event.
    pub fn average_event_latency(&self) -> Duration {
        if self.results.is_empty() {
            return Duration::ZERO;
        }

        let total_nanos: u64 = self
            .results
            .iter()
            .map(|r| r.latency.as_nanos() as u64)
            .sum();

        Duration::from_nanos(total_nanos / self.results.len() as u64)
    }
}

/// Configuration for streaming processing.
#[derive(Debug, Clone)]
pub struct StreamingConfig {
    /// Batching configuration
    pub batching: BatchingConfig,
    /// Backpressure configuration
    pub backpressure: BackpressureConfig,
    /// Batch processor configuration
    pub processor: BatchProcessorConfig,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Target processing latency
    pub target_latency: Duration,
    /// Maximum event age before forced processing
    pub max_event_age: Duration,
}

impl StreamingConfig {
    /// Create a configuration optimized for Kafka workloads.
    pub fn kafka_optimized() -> Self {
        Self {
            batching: BatchingConfig::kafka_optimized(),
            backpressure: BackpressureConfig::kafka_optimized(),
            processor: BatchProcessorConfig::high_throughput(),
            enable_metrics: true,
            target_latency: Duration::from_millis(100),
            max_event_age: Duration::from_secs(5),
        }
    }

    /// Create a configuration optimized for low latency.
    pub fn low_latency() -> Self {
        Self {
            batching: BatchingConfig::low_latency(),
            backpressure: BackpressureConfig::low_latency(),
            processor: BatchProcessorConfig::low_latency(),
            enable_metrics: true,
            target_latency: Duration::from_millis(10),
            max_event_age: Duration::from_millis(500),
        }
    }

    /// Create a configuration optimized for high throughput.
    pub fn high_throughput() -> Self {
        Self {
            batching: BatchingConfig::high_throughput(),
            backpressure: BackpressureConfig::high_throughput(),
            processor: BatchProcessorConfig::high_throughput(),
            enable_metrics: true,
            target_latency: Duration::from_millis(500),
            max_event_age: Duration::from_secs(10),
        }
    }
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self::kafka_optimized()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn test_event_metadata_new() {
        let metadata = EventMetadata::new();
        assert!(metadata.partition_key.is_none());
        assert!(metadata.offset.is_none());
        assert!(metadata.topic.is_none());
        assert!(metadata.age() < Duration::from_millis(10)); // Should be very recent
    }

    #[test]
    fn test_event_metadata_with_partition_key() {
        let metadata = EventMetadata::with_partition_key("test-partition".to_string());
        assert_eq!(metadata.partition_key, Some("test-partition".to_string()));
        assert!(metadata.offset.is_none());
        assert!(metadata.topic.is_none());
    }

    #[test]
    fn test_event_metadata_with_offset() {
        let metadata = EventMetadata::with_offset(12345);
        assert!(metadata.partition_key.is_none());
        assert_eq!(metadata.offset, Some(12345));
        assert!(metadata.topic.is_none());
    }

    #[test]
    fn test_event_metadata_with_topic_offset() {
        let metadata = EventMetadata::with_topic_offset("test-topic".to_string(), 67890);
        assert!(metadata.partition_key.is_none());
        assert_eq!(metadata.offset, Some(67890));
        assert_eq!(metadata.topic, Some("test-topic".to_string()));
    }

    #[test]
    fn test_event_metadata_default() {
        let metadata = EventMetadata::default();
        assert!(metadata.partition_key.is_none());
        assert!(metadata.offset.is_none());
        assert!(metadata.topic.is_none());
    }

    #[test]
    fn test_streaming_event_new() {
        let data = json!({"field": "value"});
        let event = StreamingEvent::new(data.clone());
        assert_eq!(event.data, data);
        assert!(event.metadata.partition_key.is_none());
    }

    #[test]
    fn test_streaming_event_with_metadata() {
        let data = json!({"field": "value"});
        let metadata = EventMetadata::with_partition_key("test".to_string());
        let event = StreamingEvent::with_metadata(data.clone(), metadata.clone());
        assert_eq!(event.data, data);
        assert_eq!(event.metadata.partition_key, metadata.partition_key);
    }

    #[test]
    fn test_streaming_event_from_value() {
        let data = json!({"field": "value"});
        let event: StreamingEvent = data.clone().into();
        assert_eq!(event.data, data);
    }

    #[test]
    fn test_streaming_event_age() {
        let event = StreamingEvent::new(json!({}));
        let age = event.age();
        assert!(age < Duration::from_millis(10));
    }

    #[test]
    fn test_streaming_result_new() {
        let matched_rules = vec![1, 2, 3];
        let latency = Duration::from_millis(50);
        let metadata = EventMetadata::new();
        let metrics = PerformanceStats::default();

        let result = StreamingResult::new(matched_rules.clone(), latency, metadata, metrics);
        assert_eq!(result.matched_rules, matched_rules);
        assert_eq!(result.latency, latency);
    }

    #[test]
    fn test_streaming_result_has_matches() {
        let metadata = EventMetadata::new();
        let metrics = PerformanceStats::default();

        let result_with_matches = StreamingResult::new(
            vec![1, 2],
            Duration::from_millis(50),
            metadata.clone(),
            metrics.clone(),
        );
        assert!(result_with_matches.has_matches());

        let result_without_matches =
            StreamingResult::new(vec![], Duration::from_millis(50), metadata, metrics);
        assert!(!result_without_matches.has_matches());
    }

    #[test]
    fn test_streaming_result_match_count() {
        let metadata = EventMetadata::new();
        let metrics = PerformanceStats::default();

        let result =
            StreamingResult::new(vec![1, 2, 3], Duration::from_millis(50), metadata, metrics);
        assert_eq!(result.match_count(), 3);
    }

    #[test]
    fn test_event_batch_new() {
        let events = vec![
            StreamingEvent::new(json!({"field1": "value1"})),
            StreamingEvent::new(json!({"field2": "value2"})),
        ];
        let batch = EventBatch::new(events.clone(), 123);

        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.batch_id, 123);
        assert!(batch.age() < Duration::from_millis(10));
    }

    #[test]
    fn test_event_batch_size_and_empty() {
        let empty_batch = EventBatch::new(vec![], 1);
        assert_eq!(empty_batch.size(), 0);
        assert!(empty_batch.is_empty());

        let non_empty_batch = EventBatch::new(vec![StreamingEvent::new(json!({}))], 2);
        assert_eq!(non_empty_batch.size(), 1);
        assert!(!non_empty_batch.is_empty());
    }

    #[test]
    fn test_event_batch_oldest_event_age() {
        let empty_batch = EventBatch::new(vec![], 1);
        assert!(empty_batch.oldest_event_age().is_none());

        let batch_with_events = EventBatch::new(
            vec![
                StreamingEvent::new(json!({})),
                StreamingEvent::new(json!({})),
            ],
            2,
        );
        assert!(batch_with_events.oldest_event_age().is_some());
    }

    #[test]
    fn test_batch_result_new() {
        let results = vec![
            StreamingResult::new(
                vec![1],
                Duration::from_millis(10),
                EventMetadata::new(),
                PerformanceStats::default(),
            ),
            StreamingResult::new(
                vec![2, 3],
                Duration::from_millis(20),
                EventMetadata::new(),
                PerformanceStats::default(),
            ),
        ];
        let batch_latency = Duration::from_millis(100);
        let batch_id = 456;
        let aggregate_metrics = PerformanceStats::default();

        let batch_result =
            BatchResult::new(results.clone(), batch_latency, batch_id, aggregate_metrics);

        assert_eq!(batch_result.results.len(), 2);
        assert_eq!(batch_result.batch_latency, batch_latency);
        assert_eq!(batch_result.batch_id, batch_id);
    }

    #[test]
    fn test_batch_result_total_matches() {
        let results = vec![
            StreamingResult::new(
                vec![1],
                Duration::from_millis(10),
                EventMetadata::new(),
                PerformanceStats::default(),
            ),
            StreamingResult::new(
                vec![2, 3],
                Duration::from_millis(20),
                EventMetadata::new(),
                PerformanceStats::default(),
            ),
            StreamingResult::new(
                vec![],
                Duration::from_millis(15),
                EventMetadata::new(),
                PerformanceStats::default(),
            ),
        ];

        let batch_result = BatchResult::new(
            results,
            Duration::from_millis(100),
            1,
            PerformanceStats::default(),
        );

        assert_eq!(batch_result.total_matches(), 3); // 1 + 2 + 0
        assert_eq!(batch_result.events_with_matches(), 2); // 2 events had matches
    }

    #[test]
    fn test_batch_result_average_event_latency() {
        let results = vec![
            StreamingResult::new(
                vec![],
                Duration::from_millis(10),
                EventMetadata::new(),
                PerformanceStats::default(),
            ),
            StreamingResult::new(
                vec![],
                Duration::from_millis(20),
                EventMetadata::new(),
                PerformanceStats::default(),
            ),
        ];

        let batch_result = BatchResult::new(
            results,
            Duration::from_millis(100),
            1,
            PerformanceStats::default(),
        );

        let avg_latency = batch_result.average_event_latency();
        assert_eq!(avg_latency, Duration::from_millis(15)); // (10 + 20) / 2

        // Test empty results
        let empty_batch_result = BatchResult::new(
            vec![],
            Duration::from_millis(100),
            1,
            PerformanceStats::default(),
        );
        assert_eq!(empty_batch_result.average_event_latency(), Duration::ZERO);
    }

    #[test]
    fn test_streaming_config_kafka_optimized() {
        let config = StreamingConfig::kafka_optimized();
        assert!(config.enable_metrics);
        assert_eq!(config.target_latency, Duration::from_millis(100));
        assert_eq!(config.max_event_age, Duration::from_secs(5));
    }

    #[test]
    fn test_streaming_config_low_latency() {
        let config = StreamingConfig::low_latency();
        assert!(config.enable_metrics);
        assert_eq!(config.target_latency, Duration::from_millis(10));
        assert_eq!(config.max_event_age, Duration::from_millis(500));
    }

    #[test]
    fn test_streaming_config_high_throughput() {
        let config = StreamingConfig::high_throughput();
        assert!(config.enable_metrics);
        assert_eq!(config.target_latency, Duration::from_millis(500));
        assert_eq!(config.max_event_age, Duration::from_secs(10));
    }

    #[test]
    fn test_streaming_config_default() {
        let config = StreamingConfig::default();
        // Default should be kafka_optimized
        assert!(config.enable_metrics);
        assert_eq!(config.target_latency, Duration::from_millis(100));
        assert_eq!(config.max_event_age, Duration::from_secs(5));
    }
}
