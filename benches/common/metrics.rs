//! Metrics collection and analysis utilities for SIGMA engine benchmarks.

use super::BenchmarkMetrics;
use std::time::{Duration, Instant};

/// Performance measurement wrapper for benchmarks.
pub struct PerformanceMeasurement {
    start_time: Instant,
    #[cfg(feature = "profiling")]
    start_allocations: usize,
    #[cfg(feature = "profiling")]
    start_bytes: usize,
}

impl PerformanceMeasurement {
    /// Start a new performance measurement.
    pub fn start() -> Self {
        Self {
            start_time: Instant::now(),
            #[cfg(feature = "profiling")]
            start_allocations: get_allocation_count(),
            #[cfg(feature = "profiling")]
            start_bytes: get_allocated_bytes(),
        }
    }

    /// Finish the measurement and return metrics.
    pub fn finish(self) -> BenchmarkMetrics {
        let execution_time_ns = self.start_time.elapsed().as_nanos() as u64;

        #[cfg(feature = "profiling")]
        {
            let end_allocations = get_allocation_count();
            let end_bytes = get_allocated_bytes();
            
            BenchmarkMetrics {
                execution_time_ns,
                memory_allocations: Some(end_allocations.saturating_sub(self.start_allocations)),
                bytes_allocated: Some(end_bytes.saturating_sub(self.start_bytes)),
                ..Default::default()
            }
        }

        #[cfg(not(feature = "profiling"))]
        {
            BenchmarkMetrics {
                execution_time_ns,
                ..Default::default()
            }
        }
    }
}

/// Benchmark result collector for aggregating multiple measurements.
#[derive(Debug, Default)]
pub struct BenchmarkCollector {
    measurements: Vec<BenchmarkMetrics>,
    total_rules_processed: usize,
    total_events_processed: usize,
    total_matches_found: usize,
}

impl BenchmarkCollector {
    /// Create a new benchmark collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a measurement to the collector.
    pub fn add_measurement(&mut self, mut metrics: BenchmarkMetrics) {
        self.total_rules_processed += metrics.rules_processed;
        self.total_events_processed += metrics.events_processed;
        self.total_matches_found += metrics.matches_found;
        
        // Update the metrics with cumulative totals
        metrics.rules_processed = self.total_rules_processed;
        metrics.events_processed = self.total_events_processed;
        metrics.matches_found = self.total_matches_found;
        
        self.measurements.push(metrics);
    }

    /// Get aggregated statistics.
    pub fn statistics(&self) -> BenchmarkStatistics {
        if self.measurements.is_empty() {
            return BenchmarkStatistics::default();
        }

        let total_time_ns: u64 = self.measurements.iter().map(|m| m.execution_time_ns).sum();
        let avg_time_ns = total_time_ns / self.measurements.len() as u64;
        
        let min_time_ns = self.measurements.iter().map(|m| m.execution_time_ns).min().unwrap_or(0);
        let max_time_ns = self.measurements.iter().map(|m| m.execution_time_ns).max().unwrap_or(0);

        let total_allocations = self.measurements.iter()
            .filter_map(|m| m.memory_allocations)
            .sum::<usize>();
            
        let total_bytes = self.measurements.iter()
            .filter_map(|m| m.bytes_allocated)
            .sum::<usize>();

        BenchmarkStatistics {
            measurement_count: self.measurements.len(),
            total_execution_time_ns: total_time_ns,
            avg_execution_time_ns: avg_time_ns,
            min_execution_time_ns: min_time_ns,
            max_execution_time_ns: max_time_ns,
            total_rules_processed: self.total_rules_processed,
            total_events_processed: self.total_events_processed,
            total_matches_found: self.total_matches_found,
            total_memory_allocations: if total_allocations > 0 { Some(total_allocations) } else { None },
            total_bytes_allocated: if total_bytes > 0 { Some(total_bytes) } else { None },
            throughput_ops_per_sec: self.calculate_throughput(),
            events_per_sec: self.calculate_events_per_sec(),
            rules_per_sec: self.calculate_rules_per_sec(),
        }
    }

    fn calculate_throughput(&self) -> f64 {
        if self.measurements.is_empty() {
            return 0.0;
        }
        
        let total_time_s = self.measurements.iter().map(|m| m.execution_time_ns).sum::<u64>() as f64 / 1_000_000_000.0;
        let total_ops = self.total_rules_processed * self.total_events_processed;
        
        if total_time_s > 0.0 {
            total_ops as f64 / total_time_s
        } else {
            0.0
        }
    }

    fn calculate_events_per_sec(&self) -> f64 {
        if self.measurements.is_empty() {
            return 0.0;
        }
        
        let total_time_s = self.measurements.iter().map(|m| m.execution_time_ns).sum::<u64>() as f64 / 1_000_000_000.0;
        
        if total_time_s > 0.0 {
            self.total_events_processed as f64 / total_time_s
        } else {
            0.0
        }
    }

    fn calculate_rules_per_sec(&self) -> f64 {
        if self.measurements.is_empty() {
            return 0.0;
        }
        
        let total_time_s = self.measurements.iter().map(|m| m.execution_time_ns).sum::<u64>() as f64 / 1_000_000_000.0;
        
        if total_time_s > 0.0 {
            self.total_rules_processed as f64 / total_time_s
        } else {
            0.0
        }
    }
}

/// Aggregated benchmark statistics.
#[derive(Debug, Default)]
pub struct BenchmarkStatistics {
    pub measurement_count: usize,
    pub total_execution_time_ns: u64,
    pub avg_execution_time_ns: u64,
    pub min_execution_time_ns: u64,
    pub max_execution_time_ns: u64,
    pub total_rules_processed: usize,
    pub total_events_processed: usize,
    pub total_matches_found: usize,
    pub total_memory_allocations: Option<usize>,
    pub total_bytes_allocated: Option<usize>,
    pub throughput_ops_per_sec: f64,
    pub events_per_sec: f64,
    pub rules_per_sec: f64,
}

impl BenchmarkStatistics {
    /// Format statistics as a human-readable string.
    pub fn format(&self) -> String {
        let mut output = format!(
            "Benchmark Statistics:\n\
             Measurements: {}\n\
             Total Time: {:.2}ms\n\
             Avg Time: {:.2}μs\n\
             Min Time: {:.2}μs\n\
             Max Time: {:.2}μs\n\
             Rules Processed: {}\n\
             Events Processed: {}\n\
             Matches Found: {}\n\
             Throughput: {:.0} ops/sec\n\
             Events/sec: {:.0}\n\
             Rules/sec: {:.0}",
            self.measurement_count,
            self.total_execution_time_ns as f64 / 1_000_000.0,
            self.avg_execution_time_ns as f64 / 1_000.0,
            self.min_execution_time_ns as f64 / 1_000.0,
            self.max_execution_time_ns as f64 / 1_000.0,
            self.total_rules_processed,
            self.total_events_processed,
            self.total_matches_found,
            self.throughput_ops_per_sec,
            self.events_per_sec,
            self.rules_per_sec,
        );

        if let Some(allocations) = self.total_memory_allocations {
            output.push_str(&format!("\nMemory Allocations: {}", allocations));
        }

        if let Some(bytes) = self.total_bytes_allocated {
            output.push_str(&format!("\nBytes Allocated: {}", bytes));
        }

        output
    }

    /// Calculate memory efficiency (bytes per operation).
    pub fn memory_efficiency(&self) -> Option<f64> {
        if let Some(bytes) = self.total_bytes_allocated {
            let total_ops = self.total_rules_processed * self.total_events_processed;
            if total_ops > 0 {
                Some(bytes as f64 / total_ops as f64)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Calculate match rate (percentage of operations that resulted in matches).
    pub fn match_rate(&self) -> f64 {
        let total_ops = self.total_rules_processed * self.total_events_processed;
        if total_ops > 0 {
            (self.total_matches_found as f64 / total_ops as f64) * 100.0
        } else {
            0.0
        }
    }
}

/// Utility functions for performance measurement.
pub mod utils {
    use super::*;

    /// Measure the execution time of a function.
    pub fn measure_execution_time<F, R>(f: F) -> (R, Duration)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        (result, duration)
    }

    /// Measure execution with full metrics collection.
    pub fn measure_with_metrics<F, R>(f: F) -> (R, BenchmarkMetrics)
    where
        F: FnOnce() -> R,
    {
        let measurement = PerformanceMeasurement::start();
        let result = f();
        let metrics = measurement.finish();
        (result, metrics)
    }

    /// Create a timing closure for criterion benchmarks.
    pub fn timing_closure<F>(mut f: F) -> impl FnMut()
    where
        F: FnMut() -> (),
    {
        move || {
            f();
        }
    }
}

// Platform-specific allocation tracking (when profiling feature is enabled)
#[cfg(feature = "profiling")]
fn get_allocation_count() -> usize {
    // This would integrate with a memory profiler like jemalloc or custom allocator
    // For now, return 0 as a placeholder
    0
}

#[cfg(feature = "profiling")]
fn get_allocated_bytes() -> usize {
    // This would integrate with a memory profiler like jemalloc or custom allocator
    // For now, return 0 as a placeholder
    0
}
