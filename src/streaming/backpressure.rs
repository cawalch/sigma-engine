//! Backpressure control for streaming workloads.
//!
//! This module provides flow control mechanisms to prevent memory exhaustion
//! and maintain stable performance under high load conditions.

use std::time::{Duration, Instant};

/// Strategy for handling backpressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowControlStrategy {
    /// Drop oldest events when queue is full
    DropOldest,
    /// Drop newest events when queue is full
    DropNewest,
    /// Block until queue has space
    Block,
    /// Adaptive strategy based on processing rate
    Adaptive,
}

/// Configuration for backpressure control.
#[derive(Debug, Clone)]
pub struct BackpressureConfig {
    /// Flow control strategy
    pub strategy: FlowControlStrategy,
    /// Maximum queue size (number of events)
    pub max_queue_size: usize,
    /// High watermark threshold (percentage of max_queue_size)
    pub high_watermark: f64,
    /// Low watermark threshold (percentage of max_queue_size)
    pub low_watermark: f64,
    /// Maximum memory usage (bytes)
    pub max_memory_usage: usize,
    /// Enable adaptive queue sizing
    pub adaptive_sizing: bool,
    /// Minimum queue size for adaptive sizing
    pub min_queue_size: usize,
    /// Queue size adaptation rate
    pub adaptation_rate: f64,
}

impl BackpressureConfig {
    /// Create configuration optimized for Kafka workloads.
    pub fn kafka_optimized() -> Self {
        Self {
            strategy: FlowControlStrategy::Adaptive,
            max_queue_size: 100_000,
            high_watermark: 0.8,
            low_watermark: 0.2,
            max_memory_usage: 512 * 1024 * 1024, // 512 MB
            adaptive_sizing: true,
            min_queue_size: 10_000,
            adaptation_rate: 0.1,
        }
    }

    /// Create configuration optimized for low latency.
    pub fn low_latency() -> Self {
        Self {
            strategy: FlowControlStrategy::DropOldest,
            max_queue_size: 10_000,
            high_watermark: 0.7,
            low_watermark: 0.3,
            max_memory_usage: 64 * 1024 * 1024, // 64 MB
            adaptive_sizing: false,
            min_queue_size: 1_000,
            adaptation_rate: 0.2,
        }
    }

    /// Create configuration optimized for high throughput.
    pub fn high_throughput() -> Self {
        Self {
            strategy: FlowControlStrategy::Adaptive,
            max_queue_size: 1_000_000,
            high_watermark: 0.9,
            low_watermark: 0.1,
            max_memory_usage: 2 * 1024 * 1024 * 1024, // 2 GB
            adaptive_sizing: true,
            min_queue_size: 100_000,
            adaptation_rate: 0.05,
        }
    }
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self::kafka_optimized()
    }
}

/// Backpressure state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureState {
    /// Normal operation
    Normal,
    /// High load, approaching limits
    Warning,
    /// Critical load, backpressure active
    Critical,
    /// Overloaded, dropping events
    Overloaded,
}

/// Backpressure controller for flow control.
pub struct BackpressureController {
    /// Configuration
    config: BackpressureConfig,
    /// Current queue size
    current_queue_size: usize,
    /// Current memory usage estimate
    current_memory_usage: usize,
    /// Current backpressure state
    state: BackpressureState,
    /// Processing rate history (events per second)
    processing_rates: Vec<f64>,
    /// Arrival rate history (events per second)
    arrival_rates: Vec<f64>,
    /// Last rate calculation time
    last_rate_calculation: Instant,
    /// Events processed since last calculation
    events_processed_since_last: usize,
    /// Events arrived since last calculation
    events_arrived_since_last: usize,
    /// Total events dropped
    total_events_dropped: u64,
    /// Last adaptation time
    last_adaptation: Instant,
}

impl BackpressureController {
    /// Create a new backpressure controller.
    pub fn new(config: BackpressureConfig) -> Self {
        Self {
            config,
            current_queue_size: 0,
            current_memory_usage: 0,
            state: BackpressureState::Normal,
            processing_rates: Vec::with_capacity(60), // 1 minute of history
            arrival_rates: Vec::with_capacity(60),
            last_rate_calculation: Instant::now(),
            events_processed_since_last: 0,
            events_arrived_since_last: 0,
            total_events_dropped: 0,
            last_adaptation: Instant::now(),
        }
    }

    /// Check if an event can be accepted.
    pub fn can_accept_event(&mut self, _estimated_size: usize) -> bool {
        self.update_state();

        match self.state {
            BackpressureState::Normal | BackpressureState::Warning => true,
            BackpressureState::Critical => {
                match self.config.strategy {
                    FlowControlStrategy::Block => false,
                    FlowControlStrategy::Adaptive => {
                        // Accept if processing rate > arrival rate
                        self.get_processing_rate() > self.get_arrival_rate()
                    }
                    _ => true, // Will drop events instead
                }
            }
            BackpressureState::Overloaded => {
                match self.config.strategy {
                    FlowControlStrategy::Block => false,
                    _ => false, // Drop all new events
                }
            }
        }
    }

    /// Record that an event was added to the queue.
    pub fn event_added(&mut self, estimated_size: usize) {
        self.current_queue_size += 1;
        self.current_memory_usage += estimated_size;
        self.events_arrived_since_last += 1;
        self.update_rates();
    }

    /// Record that an event was processed from the queue.
    pub fn event_processed(&mut self, estimated_size: usize) {
        if self.current_queue_size > 0 {
            self.current_queue_size -= 1;
        }
        if self.current_memory_usage >= estimated_size {
            self.current_memory_usage -= estimated_size;
        }
        self.events_processed_since_last += 1;
        self.update_rates();
    }

    /// Record that an event was dropped.
    pub fn event_dropped(&mut self) {
        self.total_events_dropped += 1;
    }

    /// Update processing and arrival rates.
    fn update_rates(&mut self) {
        let elapsed = self.last_rate_calculation.elapsed();

        // Update rates every second
        if elapsed >= Duration::from_secs(1) {
            let processing_rate = self.events_processed_since_last as f64 / elapsed.as_secs_f64();
            let arrival_rate = self.events_arrived_since_last as f64 / elapsed.as_secs_f64();

            self.processing_rates.push(processing_rate);
            self.arrival_rates.push(arrival_rate);

            // Keep only last 60 seconds of history
            if self.processing_rates.len() > 60 {
                self.processing_rates.remove(0);
            }
            if self.arrival_rates.len() > 60 {
                self.arrival_rates.remove(0);
            }

            self.events_processed_since_last = 0;
            self.events_arrived_since_last = 0;
            self.last_rate_calculation = Instant::now();

            // Adapt queue size if enabled
            if self.config.adaptive_sizing {
                self.adapt_queue_size();
            }
        }
    }

    /// Update backpressure state based on current conditions.
    fn update_state(&mut self) {
        let queue_utilization = self.current_queue_size as f64 / self.config.max_queue_size as f64;
        let memory_utilization =
            self.current_memory_usage as f64 / self.config.max_memory_usage as f64;

        let max_utilization = queue_utilization.max(memory_utilization);

        self.state = if max_utilization >= 1.0 {
            BackpressureState::Overloaded
        } else if max_utilization >= self.config.high_watermark {
            BackpressureState::Critical
        } else if max_utilization >= self.config.low_watermark {
            BackpressureState::Warning
        } else {
            BackpressureState::Normal
        };
    }

    /// Adapt queue size based on processing patterns.
    fn adapt_queue_size(&mut self) {
        // Only adapt periodically
        if self.last_adaptation.elapsed() < Duration::from_secs(10) {
            return;
        }

        let processing_rate = self.get_processing_rate();
        let arrival_rate = self.get_arrival_rate();

        if processing_rate > 0.0 && arrival_rate > 0.0 {
            let rate_ratio = processing_rate / arrival_rate;

            // If processing is keeping up, we can reduce queue size
            // If processing is falling behind, we need more buffer
            let target_queue_size = if rate_ratio > 1.2 {
                // Processing is faster, reduce queue size
                (self.config.max_queue_size as f64 * 0.9) as usize
            } else if rate_ratio < 0.8 {
                // Processing is slower, increase queue size
                (self.config.max_queue_size as f64 * 1.1) as usize
            } else {
                self.config.max_queue_size
            };

            // Apply bounds
            self.config.max_queue_size = target_queue_size
                .max(self.config.min_queue_size)
                .min(1_000_000); // Hard upper limit

            self.last_adaptation = Instant::now();
        }
    }

    /// Get current processing rate (events per second).
    pub fn get_processing_rate(&self) -> f64 {
        if self.processing_rates.is_empty() {
            return 0.0;
        }
        self.processing_rates.iter().sum::<f64>() / self.processing_rates.len() as f64
    }

    /// Get current arrival rate (events per second).
    pub fn get_arrival_rate(&self) -> f64 {
        if self.arrival_rates.is_empty() {
            return 0.0;
        }
        self.arrival_rates.iter().sum::<f64>() / self.arrival_rates.len() as f64
    }

    /// Get current backpressure state.
    pub fn get_state(&self) -> BackpressureState {
        self.state
    }

    /// Get current queue utilization (0.0 to 1.0).
    pub fn get_queue_utilization(&self) -> f64 {
        self.current_queue_size as f64 / self.config.max_queue_size as f64
    }

    /// Get current memory utilization (0.0 to 1.0).
    pub fn get_memory_utilization(&self) -> f64 {
        self.current_memory_usage as f64 / self.config.max_memory_usage as f64
    }

    /// Get total events dropped.
    pub fn get_total_dropped(&self) -> u64 {
        self.total_events_dropped
    }

    /// Check if backpressure is active.
    pub fn is_backpressure_active(&self) -> bool {
        matches!(
            self.state,
            BackpressureState::Critical | BackpressureState::Overloaded
        )
    }

    /// Get backpressure statistics.
    pub fn get_stats(&self) -> BackpressureStats {
        BackpressureStats {
            state: self.state,
            queue_size: self.current_queue_size,
            max_queue_size: self.config.max_queue_size,
            memory_usage: self.current_memory_usage,
            max_memory_usage: self.config.max_memory_usage,
            processing_rate: self.get_processing_rate(),
            arrival_rate: self.get_arrival_rate(),
            total_dropped: self.total_events_dropped,
            queue_utilization: self.get_queue_utilization(),
            memory_utilization: self.get_memory_utilization(),
        }
    }
}

/// Statistics for backpressure control.
#[derive(Debug, Clone)]
pub struct BackpressureStats {
    /// Current backpressure state
    pub state: BackpressureState,
    /// Current queue size
    pub queue_size: usize,
    /// Maximum queue size
    pub max_queue_size: usize,
    /// Current memory usage
    pub memory_usage: usize,
    /// Maximum memory usage
    pub max_memory_usage: usize,
    /// Current processing rate (events/sec)
    pub processing_rate: f64,
    /// Current arrival rate (events/sec)
    pub arrival_rate: f64,
    /// Total events dropped
    pub total_dropped: u64,
    /// Queue utilization (0.0 to 1.0)
    pub queue_utilization: f64,
    /// Memory utilization (0.0 to 1.0)
    pub memory_utilization: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backpressure_controller_creation() {
        let config = BackpressureConfig::default();
        let controller = BackpressureController::new(config);

        assert_eq!(controller.get_state(), BackpressureState::Normal);
        assert_eq!(controller.current_queue_size, 0);
    }

    #[test]
    fn test_event_tracking() {
        let config = BackpressureConfig::default();
        let mut controller = BackpressureController::new(config);

        assert!(controller.can_accept_event(1024));

        controller.event_added(1024);
        assert_eq!(controller.current_queue_size, 1);
        assert_eq!(controller.current_memory_usage, 1024);

        controller.event_processed(1024);
        assert_eq!(controller.current_queue_size, 0);
        assert_eq!(controller.current_memory_usage, 0);
    }

    #[test]
    fn test_backpressure_states() {
        let config = BackpressureConfig {
            max_queue_size: 10,
            high_watermark: 0.8,
            ..Default::default()
        };

        let mut controller = BackpressureController::new(config);

        // Normal state
        assert_eq!(controller.get_state(), BackpressureState::Normal);

        // Add events to trigger warning state
        for _ in 0..8 {
            controller.event_added(100);
        }
        controller.update_state();
        assert_eq!(controller.get_state(), BackpressureState::Critical);
    }
}
