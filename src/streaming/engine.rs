//! High-level streaming engine for Kafka integration patterns.
//!
//! This module provides the main `StreamingEngine` that orchestrates all
//! streaming components for optimal performance in Kafka-based workloads.

use super::{
    AdaptiveBatcher, BackpressureController, BatchProcessor, BatchResult, MetricsCollector,
    StreamingConfig, StreamingEvent, StreamingResult,
};
use crate::dag::DagEngine;
use crate::error::{Result, SigmaError};
use crate::ir::CompiledRuleset;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// High-level streaming engine for rule evaluation.
///
/// The `StreamingEngine` provides a complete streaming architecture optimized
/// for Kafka-based event processing with adaptive batching, backpressure
/// handling, and comprehensive performance monitoring.
///
/// ## Example
///
/// ```rust,ignore
/// use sigma_engine::streaming::{StreamingEngine, StreamingConfig};
///
/// // Create streaming engine optimized for Kafka workloads
/// let config = StreamingConfig::kafka_optimized();
/// let mut engine = StreamingEngine::new(ruleset, config)?;
///
/// // Process events with adaptive batching
/// let results = engine.process_events(events).await?;
/// ```
pub struct StreamingEngine {
    /// Configuration
    config: StreamingConfig,
    /// Adaptive batcher for intelligent batch sizing
    batcher: AdaptiveBatcher,
    /// Backpressure controller for flow control
    backpressure: BackpressureController,
    /// Batch processor for rule evaluation
    processor: BatchProcessor,
    /// Metrics collector for performance monitoring
    metrics: MetricsCollector,
    /// Pending results queue
    pending_results: VecDeque<BatchResult>,
    /// Engine state
    is_running: bool,
    /// Last processing time
    last_processing_time: Instant,
}

impl StreamingEngine {
    /// Create a new streaming engine from a compiled ruleset.
    pub fn new(ruleset: CompiledRuleset, config: StreamingConfig) -> Result<Self> {
        // Create DAG engine from ruleset
        let dag_engine = DagEngine::from_ruleset(ruleset)?;

        // Create components
        let batcher = AdaptiveBatcher::new(config.batching.clone());
        let backpressure = BackpressureController::new(config.backpressure.clone());
        let processor = BatchProcessor::new(dag_engine, config.processor.clone());
        let metrics = if config.enable_metrics {
            MetricsCollector::new()
        } else {
            MetricsCollector::with_history_size(1) // Minimal history for disabled metrics
        };

        Ok(Self {
            config,
            batcher,
            backpressure,
            processor,
            metrics,
            pending_results: VecDeque::new(),
            is_running: false,
            last_processing_time: Instant::now(),
        })
    }

    /// Start the streaming engine.
    pub fn start(&mut self) {
        self.is_running = true;
        self.last_processing_time = Instant::now();
    }

    /// Stop the streaming engine.
    pub fn stop(&mut self) {
        self.is_running = false;
    }

    /// Check if the engine is running.
    pub fn is_running(&self) -> bool {
        self.is_running
    }

    /// Process a single event.
    pub fn process_event(&mut self, event: StreamingEvent) -> Result<Option<StreamingResult>> {
        if !self.is_running {
            return Err(SigmaError::ExecutionError(
                "Streaming engine is not running".to_string(),
            ));
        }

        // Check backpressure
        let event_size = self.estimate_event_size(&event);
        if !self.backpressure.can_accept_event(event_size) {
            self.backpressure.event_dropped();
            return Ok(None); // Event dropped due to backpressure
        }

        // Add event to batcher
        self.backpressure.event_added(event_size);
        self.batcher.add_event(event);

        // Process batch if ready
        if self.batcher.should_create_batch() {
            self.process_pending_batch()?;
        }

        // Return result if available
        self.get_next_result()
    }

    /// Process multiple events.
    pub fn process_events(&mut self, events: Vec<StreamingEvent>) -> Result<Vec<StreamingResult>> {
        if !self.is_running {
            return Err(SigmaError::ExecutionError(
                "Streaming engine is not running".to_string(),
            ));
        }

        let mut results = Vec::new();

        for event in events {
            if let Some(result) = self.process_event(event)? {
                results.push(result);
            }
        }

        // Process any remaining batches
        self.flush_pending()?;

        // Collect all remaining results
        while let Some(result) = self.get_next_result()? {
            results.push(result);
        }

        Ok(results)
    }

    /// Flush all pending events and return results.
    pub fn flush(&mut self) -> Result<Vec<StreamingResult>> {
        self.flush_pending()?;

        let mut results = Vec::new();
        while let Some(result) = self.get_next_result()? {
            results.push(result);
        }

        Ok(results)
    }

    /// Process pending batch if available.
    fn process_pending_batch(&mut self) -> Result<()> {
        if let Some(batch) = self.batcher.create_batch() {
            let start_time = Instant::now();

            // Process the batch
            let batch_result = self.processor.process_batch(batch)?;
            let processing_time = start_time.elapsed();

            // Update metrics
            if self.config.enable_metrics {
                self.metrics
                    .record_batch(batch_result.results.len(), processing_time);
            }

            // Update batcher metrics for adaptation
            self.batcher
                .update_metrics(batch_result.results.len(), processing_time);

            // Update backpressure controller
            for _ in 0..batch_result.results.len() {
                self.backpressure
                    .event_processed(self.estimate_result_size(&batch_result));
            }

            // Store result
            self.pending_results.push_back(batch_result);
            self.last_processing_time = Instant::now();
        }

        Ok(())
    }

    /// Flush all pending events.
    fn flush_pending(&mut self) -> Result<()> {
        if let Some(batch) = self.batcher.flush() {
            let start_time = Instant::now();

            let batch_result = self.processor.process_batch(batch)?;
            let processing_time = start_time.elapsed();

            if self.config.enable_metrics {
                self.metrics
                    .record_batch(batch_result.results.len(), processing_time);
            }

            self.batcher
                .update_metrics(batch_result.results.len(), processing_time);

            for _ in 0..batch_result.results.len() {
                self.backpressure
                    .event_processed(self.estimate_result_size(&batch_result));
            }

            self.pending_results.push_back(batch_result);
        }

        Ok(())
    }

    /// Get the next available result.
    fn get_next_result(&mut self) -> Result<Option<StreamingResult>> {
        if let Some(batch_result) = self.pending_results.front_mut() {
            if !batch_result.results.is_empty() {
                let result = batch_result.results.remove(0);

                // Remove batch if empty
                if batch_result.results.is_empty() {
                    self.pending_results.pop_front();
                }

                return Ok(Some(result));
            }
        }

        Ok(None)
    }

    /// Estimate the size of an event for backpressure calculations.
    fn estimate_event_size(&self, event: &StreamingEvent) -> usize {
        // Simple estimation based on JSON string length
        // In a real implementation, this could be more sophisticated
        event.data.to_string().len() + 128 // Add overhead for metadata
    }

    /// Estimate the size of a batch result.
    fn estimate_result_size(&self, batch_result: &BatchResult) -> usize {
        // Simple estimation
        batch_result.results.len() * 64 // Rough estimate per result
    }

    /// Check if processing should be triggered by time.
    pub fn should_process_by_time(&self) -> bool {
        self.last_processing_time.elapsed() >= self.config.max_event_age
    }

    /// Force processing of pending events due to time constraints.
    pub fn force_process_by_time(&mut self) -> Result<Vec<StreamingResult>> {
        if self.should_process_by_time() {
            self.flush()
        } else {
            Ok(Vec::new())
        }
    }

    /// Get current performance statistics.
    pub fn get_performance_stats(&self) -> super::PerformanceStats {
        if self.config.enable_metrics {
            self.metrics.get_current_stats()
        } else {
            super::PerformanceStats::default()
        }
    }

    /// Get comprehensive engine statistics.
    pub fn get_engine_stats(&self) -> StreamingEngineStats {
        StreamingEngineStats {
            is_running: self.is_running,
            batching_stats: self.batcher.get_stats(),
            backpressure_stats: self.backpressure.get_stats(),
            processor_stats: self.processor.get_stats(),
            metrics_summary: if self.config.enable_metrics {
                Some(self.metrics.get_summary())
            } else {
                None
            },
            pending_results_count: self.pending_results.len(),
            time_since_last_processing: self.last_processing_time.elapsed(),
        }
    }

    /// Reset all statistics and state.
    pub fn reset_stats(&mut self) {
        self.metrics.reset();
        self.processor.reset_stats();
        self.pending_results.clear();
        self.last_processing_time = Instant::now();
    }
}

/// Comprehensive statistics for the streaming engine.
#[derive(Debug, Clone)]
pub struct StreamingEngineStats {
    /// Engine running state
    pub is_running: bool,
    /// Batching statistics
    pub batching_stats: super::adaptive_batcher::BatchingStats,
    /// Backpressure statistics
    pub backpressure_stats: super::backpressure::BackpressureStats,
    /// Processor statistics
    pub processor_stats: super::batch_processor::BatchProcessorStats,
    /// Metrics summary (if enabled)
    pub metrics_summary: Option<super::metrics::MetricsSummary>,
    /// Number of pending results
    pub pending_results_count: usize,
    /// Time since last processing
    pub time_since_last_processing: Duration,
}

impl StreamingEngineStats {
    /// Format statistics as a human-readable string.
    pub fn format(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "Streaming Engine Status: {}\n",
            if self.is_running {
                "Running"
            } else {
                "Stopped"
            }
        ));

        output.push_str(&format!(
            "Batching: {} events pending, batch size: {}\n",
            self.batching_stats.pending_events, self.batching_stats.current_batch_size
        ));

        output.push_str(&format!(
            "Backpressure: {:?}, queue: {:.1}%, memory: {:.1}%\n",
            self.backpressure_stats.state,
            self.backpressure_stats.queue_utilization * 100.0,
            self.backpressure_stats.memory_utilization * 100.0
        ));

        output.push_str(&format!(
            "Processor: {} batches, {:.0} EPS overall\n",
            self.processor_stats.total_batches_processed, self.processor_stats.overall_throughput
        ));

        if let Some(ref metrics) = self.metrics_summary {
            output.push_str(&format!("Metrics: {}\n", metrics.format()));
        }

        output.push_str(&format!(
            "Pending results: {}, last processing: {:.1}s ago",
            self.pending_results_count,
            self.time_since_last_processing.as_secs_f64()
        ));

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::CompiledRuleset;
    use serde_json::json;

    #[test]
    fn test_streaming_engine_creation() {
        let ruleset = CompiledRuleset::new();
        let config = StreamingConfig::default();

        let engine = StreamingEngine::new(ruleset, config);
        assert!(engine.is_ok());

        let engine = engine.unwrap();
        assert!(!engine.is_running());
    }

    #[test]
    fn test_engine_start_stop() {
        let ruleset = CompiledRuleset::new();
        let config = StreamingConfig::default();
        let mut engine = StreamingEngine::new(ruleset, config).unwrap();

        assert!(!engine.is_running());

        engine.start();
        assert!(engine.is_running());

        engine.stop();
        assert!(!engine.is_running());
    }

    #[test]
    fn test_process_single_event() {
        let ruleset = CompiledRuleset::new();
        let config = StreamingConfig::default();
        let mut engine = StreamingEngine::new(ruleset, config).unwrap();

        engine.start();

        let event = StreamingEvent::new(json!({"test": "data"}));
        let result = engine.process_event(event);

        assert!(result.is_ok());
    }

    #[test]
    fn test_process_multiple_events() {
        let ruleset = CompiledRuleset::new();
        let config = StreamingConfig::default();
        let mut engine = StreamingEngine::new(ruleset, config).unwrap();

        engine.start();

        let events = vec![
            StreamingEvent::new(json!({"id": 1})),
            StreamingEvent::new(json!({"id": 2})),
            StreamingEvent::new(json!({"id": 3})),
        ];

        let results = engine.process_events(events);
        assert!(results.is_ok());
    }
}
