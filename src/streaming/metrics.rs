//! Performance metrics and monitoring for streaming workloads.
//!
//! This module provides comprehensive metrics collection and monitoring
//! capabilities for streaming rule evaluation performance.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Performance statistics for streaming operations.
#[derive(Debug, Clone)]
pub struct PerformanceStats {
    /// Events processed per second
    pub events_per_second: f64,
    /// Average processing latency
    pub average_latency: Duration,
    /// Memory usage in bytes
    pub memory_usage: usize,
    /// CPU usage percentage (0.0 to 100.0)
    pub cpu_usage: f64,
}

impl Default for PerformanceStats {
    fn default() -> Self {
        Self {
            events_per_second: 0.0,
            average_latency: Duration::ZERO,
            memory_usage: 0,
            cpu_usage: 0.0,
        }
    }
}

/// Metrics collector for streaming performance monitoring.
pub struct MetricsCollector {
    /// Processing latency history
    latency_history: VecDeque<Duration>,
    /// Throughput history (events per second)
    throughput_history: VecDeque<f64>,
    /// Memory usage history
    memory_history: VecDeque<usize>,
    /// CPU usage history
    cpu_history: VecDeque<f64>,
    /// Total events processed
    total_events: u64,
    /// Total processing time
    total_processing_time: Duration,
    /// Start time for rate calculations
    start_time: Instant,
    /// Last metrics update time
    last_update: Instant,
    /// Events processed since last update
    events_since_last_update: usize,
    /// Maximum history size
    max_history_size: usize,
}

impl MetricsCollector {
    /// Create a new metrics collector.
    pub fn new() -> Self {
        Self::with_history_size(1000)
    }

    /// Create a metrics collector with specified history size.
    pub fn with_history_size(max_history_size: usize) -> Self {
        let now = Instant::now();
        Self {
            latency_history: VecDeque::with_capacity(max_history_size),
            throughput_history: VecDeque::with_capacity(max_history_size),
            memory_history: VecDeque::with_capacity(max_history_size),
            cpu_history: VecDeque::with_capacity(max_history_size),
            total_events: 0,
            total_processing_time: Duration::ZERO,
            start_time: now,
            last_update: now,
            events_since_last_update: 0,
            max_history_size,
        }
    }

    /// Record processing metrics for a batch.
    pub fn record_batch(&mut self, events_processed: usize, processing_time: Duration) {
        self.total_events += events_processed as u64;
        self.total_processing_time += processing_time;
        self.events_since_last_update += events_processed;

        // Record latency
        self.latency_history.push_back(processing_time);
        if self.latency_history.len() > self.max_history_size {
            self.latency_history.pop_front();
        }

        // Calculate and record throughput
        let throughput = events_processed as f64 / processing_time.as_secs_f64();
        self.throughput_history.push_back(throughput);
        if self.throughput_history.len() > self.max_history_size {
            self.throughput_history.pop_front();
        }

        self.last_update = Instant::now();
    }

    /// Record memory usage.
    pub fn record_memory_usage(&mut self, memory_bytes: usize) {
        self.memory_history.push_back(memory_bytes);
        if self.memory_history.len() > self.max_history_size {
            self.memory_history.pop_front();
        }
    }

    /// Record CPU usage.
    pub fn record_cpu_usage(&mut self, cpu_percentage: f64) {
        self.cpu_history.push_back(cpu_percentage);
        if self.cpu_history.len() > self.max_history_size {
            self.cpu_history.pop_front();
        }
    }

    /// Get current performance statistics.
    pub fn get_current_stats(&self) -> PerformanceStats {
        PerformanceStats {
            events_per_second: self.get_current_throughput(),
            average_latency: self.get_average_latency(),
            memory_usage: self.get_current_memory_usage(),
            cpu_usage: self.get_current_cpu_usage(),
        }
    }

    /// Get current throughput (events per second).
    pub fn get_current_throughput(&self) -> f64 {
        if self.throughput_history.is_empty() {
            return 0.0;
        }

        // Use recent throughput samples for current rate
        let recent_samples = self.throughput_history.len().min(10);
        let recent_sum: f64 = self
            .throughput_history
            .iter()
            .rev()
            .take(recent_samples)
            .sum();

        recent_sum / recent_samples as f64
    }

    /// Get overall throughput since start.
    pub fn get_overall_throughput(&self) -> f64 {
        let elapsed = self.start_time.elapsed();
        if elapsed.as_secs_f64() > 0.0 {
            self.total_events as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        }
    }

    /// Get average processing latency.
    pub fn get_average_latency(&self) -> Duration {
        if self.latency_history.is_empty() {
            return Duration::ZERO;
        }

        let total_nanos: u64 = self
            .latency_history
            .iter()
            .map(|d| d.as_nanos() as u64)
            .sum();

        Duration::from_nanos(total_nanos / self.latency_history.len() as u64)
    }

    /// Get 95th percentile latency.
    pub fn get_p95_latency(&self) -> Duration {
        if self.latency_history.is_empty() {
            return Duration::ZERO;
        }

        let mut sorted_latencies: Vec<_> = self.latency_history.iter().cloned().collect();
        sorted_latencies.sort();

        let index = (sorted_latencies.len() as f64 * 0.95) as usize;
        sorted_latencies
            .get(index)
            .cloned()
            .unwrap_or(Duration::ZERO)
    }

    /// Get 99th percentile latency.
    pub fn get_p99_latency(&self) -> Duration {
        if self.latency_history.is_empty() {
            return Duration::ZERO;
        }

        let mut sorted_latencies: Vec<_> = self.latency_history.iter().cloned().collect();
        sorted_latencies.sort();

        let index = (sorted_latencies.len() as f64 * 0.99) as usize;
        sorted_latencies
            .get(index)
            .cloned()
            .unwrap_or(Duration::ZERO)
    }

    /// Get current memory usage.
    pub fn get_current_memory_usage(&self) -> usize {
        self.memory_history.back().cloned().unwrap_or(0)
    }

    /// Get current CPU usage.
    pub fn get_current_cpu_usage(&self) -> f64 {
        self.cpu_history.back().cloned().unwrap_or(0.0)
    }

    /// Get total events processed.
    pub fn get_total_events(&self) -> u64 {
        self.total_events
    }

    /// Get total processing time.
    pub fn get_total_processing_time(&self) -> Duration {
        self.total_processing_time
    }

    /// Get uptime since metrics collection started.
    pub fn get_uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Reset all metrics.
    pub fn reset(&mut self) {
        self.latency_history.clear();
        self.throughput_history.clear();
        self.memory_history.clear();
        self.cpu_history.clear();
        self.total_events = 0;
        self.total_processing_time = Duration::ZERO;
        self.start_time = Instant::now();
        self.last_update = Instant::now();
        self.events_since_last_update = 0;
    }

    /// Get comprehensive metrics summary.
    pub fn get_summary(&self) -> MetricsSummary {
        MetricsSummary {
            total_events: self.total_events,
            uptime: self.get_uptime(),
            overall_throughput: self.get_overall_throughput(),
            current_throughput: self.get_current_throughput(),
            average_latency: self.get_average_latency(),
            p95_latency: self.get_p95_latency(),
            p99_latency: self.get_p99_latency(),
            current_memory_usage: self.get_current_memory_usage(),
            current_cpu_usage: self.get_current_cpu_usage(),
            total_processing_time: self.total_processing_time,
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Comprehensive metrics summary.
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    /// Total events processed
    pub total_events: u64,
    /// Uptime since metrics collection started
    pub uptime: Duration,
    /// Overall throughput (events per second)
    pub overall_throughput: f64,
    /// Current throughput (events per second)
    pub current_throughput: f64,
    /// Average processing latency
    pub average_latency: Duration,
    /// 95th percentile latency
    pub p95_latency: Duration,
    /// 99th percentile latency
    pub p99_latency: Duration,
    /// Current memory usage
    pub current_memory_usage: usize,
    /// Current CPU usage
    pub current_cpu_usage: f64,
    /// Total processing time
    pub total_processing_time: Duration,
}

impl MetricsSummary {
    /// Format metrics as a human-readable string.
    pub fn format(&self) -> String {
        format!(
            "Events: {} | Uptime: {:.1}s | Throughput: {:.0} EPS (current: {:.0}) | \
             Latency: avg={:.1}ms, p95={:.1}ms, p99={:.1}ms | \
             Memory: {:.1}MB | CPU: {:.1}%",
            self.total_events,
            self.uptime.as_secs_f64(),
            self.overall_throughput,
            self.current_throughput,
            self.average_latency.as_secs_f64() * 1000.0,
            self.p95_latency.as_secs_f64() * 1000.0,
            self.p99_latency.as_secs_f64() * 1000.0,
            self.current_memory_usage as f64 / 1024.0 / 1024.0,
            self.current_cpu_usage
        )
    }
}

/// Streaming metrics aggregator for multiple collectors.
pub struct StreamingMetrics {
    /// Individual metrics collectors
    collectors: Vec<MetricsCollector>,
    /// Global start time
    start_time: Instant,
}

impl StreamingMetrics {
    /// Create a new streaming metrics aggregator.
    pub fn new() -> Self {
        Self {
            collectors: Vec::new(),
            start_time: Instant::now(),
        }
    }

    /// Add a metrics collector.
    pub fn add_collector(&mut self, collector: MetricsCollector) {
        self.collectors.push(collector);
    }

    /// Get aggregate performance statistics.
    pub fn get_aggregate_stats(&self) -> PerformanceStats {
        if self.collectors.is_empty() {
            return PerformanceStats::default();
        }

        let total_throughput: f64 = self
            .collectors
            .iter()
            .map(|c| c.get_current_throughput())
            .sum();

        let average_latency_nanos: u64 = self
            .collectors
            .iter()
            .map(|c| c.get_average_latency().as_nanos() as u64)
            .sum::<u64>()
            / self.collectors.len() as u64;

        let total_memory: usize = self
            .collectors
            .iter()
            .map(|c| c.get_current_memory_usage())
            .sum();

        let average_cpu: f64 = self
            .collectors
            .iter()
            .map(|c| c.get_current_cpu_usage())
            .sum::<f64>()
            / self.collectors.len() as f64;

        PerformanceStats {
            events_per_second: total_throughput,
            average_latency: Duration::from_nanos(average_latency_nanos),
            memory_usage: total_memory,
            cpu_usage: average_cpu,
        }
    }

    /// Get aggregate metrics summary.
    pub fn get_aggregate_summary(&self) -> MetricsSummary {
        let total_events: u64 = self.collectors.iter().map(|c| c.get_total_events()).sum();

        let total_throughput: f64 = self
            .collectors
            .iter()
            .map(|c| c.get_overall_throughput())
            .sum();

        let stats = self.get_aggregate_stats();

        MetricsSummary {
            total_events,
            uptime: self.start_time.elapsed(),
            overall_throughput: total_throughput,
            current_throughput: stats.events_per_second,
            average_latency: stats.average_latency,
            p95_latency: Duration::ZERO, // TODO: Implement aggregate percentiles
            p99_latency: Duration::ZERO, // TODO: Implement aggregate percentiles
            current_memory_usage: stats.memory_usage,
            current_cpu_usage: stats.cpu_usage,
            total_processing_time: Duration::ZERO, // TODO: Implement aggregate processing time
        }
    }
}

impl Default for StreamingMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.get_total_events(), 0);
        assert_eq!(collector.get_current_throughput(), 0.0);
    }

    #[test]
    fn test_record_batch() {
        let mut collector = MetricsCollector::new();

        collector.record_batch(100, Duration::from_millis(50));

        assert_eq!(collector.get_total_events(), 100);
        assert!(collector.get_current_throughput() > 0.0);
        assert!(collector.get_average_latency() > Duration::ZERO);
    }

    #[test]
    fn test_metrics_summary() {
        let mut collector = MetricsCollector::new();

        collector.record_batch(1000, Duration::from_millis(100));
        collector.record_memory_usage(1024 * 1024);
        collector.record_cpu_usage(50.0);

        let summary = collector.get_summary();
        assert_eq!(summary.total_events, 1000);
        assert!(summary.overall_throughput > 0.0);
        assert_eq!(summary.current_memory_usage, 1024 * 1024);
        assert_eq!(summary.current_cpu_usage, 50.0);
    }

    #[test]
    fn test_streaming_metrics() {
        let mut metrics = StreamingMetrics::new();
        let mut collector = MetricsCollector::new();

        collector.record_batch(500, Duration::from_millis(25));
        metrics.add_collector(collector);

        let stats = metrics.get_aggregate_stats();
        assert!(stats.events_per_second > 0.0);
    }
}
