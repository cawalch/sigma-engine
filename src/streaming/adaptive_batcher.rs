//! Adaptive batching for optimal throughput and latency.
//!
//! This module provides intelligent batch sizing that adapts to processing
//! characteristics and system load to optimize for target latency while
//! maximizing throughput.

use super::{EventBatch, StreamingEvent};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Strategy for adaptive batching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchingStrategy {
    /// Fixed batch size
    Fixed,
    /// Adaptive based on processing time
    Adaptive,
    /// Time-based batching with maximum size
    TimeBased,
    /// Hybrid approach combining time and size
    Hybrid,
}

/// Configuration for adaptive batching.
#[derive(Debug, Clone)]
pub struct BatchingConfig {
    /// Batching strategy to use
    pub strategy: BatchingStrategy,
    /// Initial batch size
    pub initial_batch_size: usize,
    /// Minimum batch size
    pub min_batch_size: usize,
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Target processing latency per batch
    pub target_latency: Duration,
    /// Maximum time to wait before forcing a batch
    pub max_wait_time: Duration,
    /// Adaptation rate (0.0 to 1.0)
    pub adaptation_rate: f64,
    /// Enable aggressive optimization
    pub aggressive_optimization: bool,
}

impl BatchingConfig {
    /// Create configuration optimized for Kafka workloads.
    pub fn kafka_optimized() -> Self {
        Self {
            strategy: BatchingStrategy::Hybrid,
            initial_batch_size: 1000,
            min_batch_size: 100,
            max_batch_size: 10000,
            target_latency: Duration::from_millis(100),
            max_wait_time: Duration::from_millis(50),
            adaptation_rate: 0.1,
            aggressive_optimization: true,
        }
    }

    /// Create configuration optimized for low latency.
    pub fn low_latency() -> Self {
        Self {
            strategy: BatchingStrategy::TimeBased,
            initial_batch_size: 100,
            min_batch_size: 10,
            max_batch_size: 1000,
            target_latency: Duration::from_millis(10),
            max_wait_time: Duration::from_millis(5),
            adaptation_rate: 0.2,
            aggressive_optimization: false,
        }
    }

    /// Create configuration optimized for high throughput.
    pub fn high_throughput() -> Self {
        Self {
            strategy: BatchingStrategy::Adaptive,
            initial_batch_size: 5000,
            min_batch_size: 1000,
            max_batch_size: 50000,
            target_latency: Duration::from_millis(500),
            max_wait_time: Duration::from_millis(100),
            adaptation_rate: 0.05,
            aggressive_optimization: true,
        }
    }
}

impl Default for BatchingConfig {
    fn default() -> Self {
        Self::kafka_optimized()
    }
}

/// Adaptive batcher for intelligent batch sizing.
pub struct AdaptiveBatcher {
    /// Configuration
    config: BatchingConfig,
    /// Current batch size
    current_batch_size: usize,
    /// Pending events
    pending_events: VecDeque<StreamingEvent>,
    /// Last batch creation time
    last_batch_time: Instant,
    /// Batch ID counter
    batch_id_counter: u64,
    /// Processing time history for adaptation
    processing_times: VecDeque<Duration>,
    /// Throughput history
    throughput_history: VecDeque<f64>,
    /// Last adaptation time
    last_adaptation: Instant,
}

impl AdaptiveBatcher {
    /// Create a new adaptive batcher.
    pub fn new(config: BatchingConfig) -> Self {
        Self {
            current_batch_size: config.initial_batch_size,
            config,
            pending_events: VecDeque::new(),
            last_batch_time: Instant::now(),
            batch_id_counter: 0,
            processing_times: VecDeque::with_capacity(100),
            throughput_history: VecDeque::with_capacity(100),
            last_adaptation: Instant::now(),
        }
    }

    /// Add an event to the batcher.
    pub fn add_event(&mut self, event: StreamingEvent) {
        self.pending_events.push_back(event);
    }

    /// Add multiple events to the batcher.
    pub fn add_events(&mut self, events: Vec<StreamingEvent>) {
        for event in events {
            self.pending_events.push_back(event);
        }
    }

    /// Check if a batch should be created.
    pub fn should_create_batch(&self) -> bool {
        match self.config.strategy {
            BatchingStrategy::Fixed => self.pending_events.len() >= self.current_batch_size,
            BatchingStrategy::Adaptive => {
                self.pending_events.len() >= self.current_batch_size
                    || self.last_batch_time.elapsed() >= self.config.max_wait_time
            }
            BatchingStrategy::TimeBased => {
                self.last_batch_time.elapsed() >= self.config.max_wait_time
                    || self.pending_events.len() >= self.config.max_batch_size
            }
            BatchingStrategy::Hybrid => {
                let time_threshold = self.last_batch_time.elapsed() >= self.config.max_wait_time;
                let size_threshold = self.pending_events.len() >= self.current_batch_size;
                let max_size_threshold = self.pending_events.len() >= self.config.max_batch_size;

                time_threshold || size_threshold || max_size_threshold
            }
        }
    }

    /// Create a batch from pending events.
    pub fn create_batch(&mut self) -> Option<EventBatch> {
        if self.pending_events.is_empty() {
            return None;
        }

        let batch_size = match self.config.strategy {
            BatchingStrategy::Fixed => self.current_batch_size.min(self.pending_events.len()),
            BatchingStrategy::TimeBased => self.pending_events.len(),
            _ => self.current_batch_size.min(self.pending_events.len()),
        };

        let mut events = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            if let Some(event) = self.pending_events.pop_front() {
                events.push(event);
            } else {
                break;
            }
        }

        if events.is_empty() {
            return None;
        }

        self.batch_id_counter += 1;
        self.last_batch_time = Instant::now();

        Some(EventBatch::new(events, self.batch_id_counter))
    }

    /// Update processing metrics for adaptation.
    pub fn update_metrics(&mut self, batch_size: usize, processing_time: Duration) {
        // Store processing time
        self.processing_times.push_back(processing_time);
        if self.processing_times.len() > 100 {
            self.processing_times.pop_front();
        }

        // Calculate throughput (events per second)
        let throughput = batch_size as f64 / processing_time.as_secs_f64();
        self.throughput_history.push_back(throughput);
        if self.throughput_history.len() > 100 {
            self.throughput_history.pop_front();
        }

        // Adapt batch size if needed
        if self.config.strategy == BatchingStrategy::Adaptive
            || self.config.strategy == BatchingStrategy::Hybrid
        {
            self.adapt_batch_size(processing_time);
        }
    }

    /// Adapt batch size based on processing metrics.
    fn adapt_batch_size(&mut self, processing_time: Duration) {
        // Only adapt periodically to avoid oscillation
        if self.last_adaptation.elapsed() < Duration::from_secs(1) {
            return;
        }

        let target_latency = self.config.target_latency;
        let adaptation_rate = self.config.adaptation_rate;

        // Calculate adaptation factor based on latency
        let latency_ratio = processing_time.as_secs_f64() / target_latency.as_secs_f64();

        let new_batch_size = if latency_ratio > 1.2 {
            // Processing is too slow, reduce batch size
            let reduction_factor = 1.0 - (adaptation_rate * (latency_ratio - 1.0));
            (self.current_batch_size as f64 * reduction_factor) as usize
        } else if latency_ratio < 0.8 {
            // Processing is fast, increase batch size
            let increase_factor = 1.0 + (adaptation_rate * (1.0 - latency_ratio));
            (self.current_batch_size as f64 * increase_factor) as usize
        } else {
            // Processing time is within target range
            self.current_batch_size
        };

        // Apply bounds
        self.current_batch_size = new_batch_size
            .max(self.config.min_batch_size)
            .min(self.config.max_batch_size);

        self.last_adaptation = Instant::now();
    }

    /// Get current batch size.
    pub fn current_batch_size(&self) -> usize {
        self.current_batch_size
    }

    /// Get number of pending events.
    pub fn pending_count(&self) -> usize {
        self.pending_events.len()
    }

    /// Get average processing time.
    pub fn average_processing_time(&self) -> Option<Duration> {
        if self.processing_times.is_empty() {
            return None;
        }

        let total_nanos: u64 = self
            .processing_times
            .iter()
            .map(|d| d.as_nanos() as u64)
            .sum();

        Some(Duration::from_nanos(
            total_nanos / self.processing_times.len() as u64,
        ))
    }

    /// Get average throughput.
    pub fn average_throughput(&self) -> Option<f64> {
        if self.throughput_history.is_empty() {
            return None;
        }

        let total: f64 = self.throughput_history.iter().sum();
        Some(total / self.throughput_history.len() as f64)
    }

    /// Force creation of a batch with all pending events.
    pub fn flush(&mut self) -> Option<EventBatch> {
        if self.pending_events.is_empty() {
            return None;
        }

        let events: Vec<_> = self.pending_events.drain(..).collect();
        self.batch_id_counter += 1;
        self.last_batch_time = Instant::now();

        Some(EventBatch::new(events, self.batch_id_counter))
    }

    /// Get batching statistics.
    pub fn get_stats(&self) -> BatchingStats {
        BatchingStats {
            current_batch_size: self.current_batch_size,
            pending_events: self.pending_events.len(),
            total_batches_created: self.batch_id_counter,
            average_processing_time: self.average_processing_time(),
            average_throughput: self.average_throughput(),
            time_since_last_batch: self.last_batch_time.elapsed(),
        }
    }
}

/// Statistics for adaptive batching.
#[derive(Debug, Clone)]
pub struct BatchingStats {
    /// Current batch size
    pub current_batch_size: usize,
    /// Number of pending events
    pub pending_events: usize,
    /// Total batches created
    pub total_batches_created: u64,
    /// Average processing time
    pub average_processing_time: Option<Duration>,
    /// Average throughput (events per second)
    pub average_throughput: Option<f64>,
    /// Time since last batch was created
    pub time_since_last_batch: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_adaptive_batcher_creation() {
        let config = BatchingConfig::default();
        let batcher = AdaptiveBatcher::new(config.clone());

        assert_eq!(batcher.current_batch_size(), config.initial_batch_size);
        assert_eq!(batcher.pending_count(), 0);
    }

    #[test]
    fn test_add_events() {
        let config = BatchingConfig::default();
        let mut batcher = AdaptiveBatcher::new(config);

        let event = StreamingEvent::new(json!({"test": "data"}));
        batcher.add_event(event);

        assert_eq!(batcher.pending_count(), 1);
    }

    #[test]
    fn test_batch_creation() {
        let config = BatchingConfig {
            initial_batch_size: 2,
            strategy: BatchingStrategy::Fixed,
            ..Default::default()
        };

        let mut batcher = AdaptiveBatcher::new(config);

        // Add events
        batcher.add_event(StreamingEvent::new(json!({"id": 1})));
        batcher.add_event(StreamingEvent::new(json!({"id": 2})));

        assert!(batcher.should_create_batch());

        let batch = batcher.create_batch().unwrap();
        assert_eq!(batch.size(), 2);
        assert_eq!(batcher.pending_count(), 0);
    }

    #[test]
    fn test_metrics_update() {
        let config = BatchingConfig::default();
        let mut batcher = AdaptiveBatcher::new(config);

        batcher.update_metrics(100, Duration::from_millis(50));

        assert!(batcher.average_processing_time().is_some());
        assert!(batcher.average_throughput().is_some());
    }

    #[test]
    fn test_flush() {
        let config = BatchingConfig::default();
        let mut batcher = AdaptiveBatcher::new(config);

        batcher.add_event(StreamingEvent::new(json!({"id": 1})));
        batcher.add_event(StreamingEvent::new(json!({"id": 2})));

        let batch = batcher.flush().unwrap();
        assert_eq!(batch.size(), 2);
        assert_eq!(batcher.pending_count(), 0);
    }
}
