//! Profiling utilities for SIGMA engine performance analysis
//!
//! This module provides tools for detailed performance analysis including
//! allocation tracking, CPU cycle counting, and bottleneck identification.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Global allocation tracker for zero-allocation validation
pub struct AllocationTracker {
    allocations: AtomicUsize,
    deallocations: AtomicUsize,
    bytes_allocated: AtomicUsize,
    bytes_deallocated: AtomicUsize,
    allocation_sites: Mutex<HashMap<usize, AllocationInfo>>,
}

#[derive(Debug, Clone)]
pub struct AllocationInfo {
    pub size: usize,
    pub count: usize,
    pub backtrace: String,
}

impl Default for AllocationTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl AllocationTracker {
    pub fn new() -> Self {
        Self {
            allocations: AtomicUsize::new(0),
            deallocations: AtomicUsize::new(0),
            bytes_allocated: AtomicUsize::new(0),
            bytes_deallocated: AtomicUsize::new(0),
            allocation_sites: Mutex::new(HashMap::new()),
        }
    }

    pub fn reset(&self) {
        self.allocations.store(0, Ordering::SeqCst);
        self.deallocations.store(0, Ordering::SeqCst);
        self.bytes_allocated.store(0, Ordering::SeqCst);
        self.bytes_deallocated.store(0, Ordering::SeqCst);
        if let Ok(mut sites) = self.allocation_sites.lock() {
            sites.clear();
        }
    }

    pub fn get_stats(&self) -> AllocationStats {
        AllocationStats {
            allocations: self.allocations.load(Ordering::SeqCst),
            deallocations: self.deallocations.load(Ordering::SeqCst),
            bytes_allocated: self.bytes_allocated.load(Ordering::SeqCst),
            bytes_deallocated: self.bytes_deallocated.load(Ordering::SeqCst),
            net_allocations: self
                .allocations
                .load(Ordering::SeqCst)
                .saturating_sub(self.deallocations.load(Ordering::SeqCst)),
            net_bytes: self
                .bytes_allocated
                .load(Ordering::SeqCst)
                .saturating_sub(self.bytes_deallocated.load(Ordering::SeqCst)),
        }
    }

    pub fn record_allocation(&self, size: usize) {
        self.allocations.fetch_add(1, Ordering::SeqCst);
        self.bytes_allocated.fetch_add(size, Ordering::SeqCst);

        // Record allocation site (simplified - in practice you'd want backtrace)
        let site_id = size; // Use size as a simple site identifier
        if let Ok(mut sites) = self.allocation_sites.lock() {
            let info = sites.entry(site_id).or_insert_with(|| AllocationInfo {
                size,
                count: 0,
                backtrace: format!("allocation_size_{size}"),
            });
            info.count += 1;
        }
    }

    pub fn record_deallocation(&self, size: usize) {
        self.deallocations.fetch_add(1, Ordering::SeqCst);
        self.bytes_deallocated.fetch_add(size, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone)]
pub struct AllocationStats {
    pub allocations: usize,
    pub deallocations: usize,
    pub bytes_allocated: usize,
    pub bytes_deallocated: usize,
    pub net_allocations: usize,
    pub net_bytes: usize,
}

impl AllocationStats {
    pub fn is_zero_allocation(&self) -> bool {
        self.net_allocations == 0
    }

    pub fn allocation_efficiency(&self) -> f64 {
        if self.allocations == 0 {
            1.0
        } else {
            self.deallocations as f64 / self.allocations as f64
        }
    }
}

/// Global allocation tracker instance
use std::sync::OnceLock;
static ALLOCATION_TRACKER: OnceLock<AllocationTracker> = OnceLock::new();

fn get_tracker() -> &'static AllocationTracker {
    ALLOCATION_TRACKER.get_or_init(AllocationTracker::new)
}

/// Custom allocator that tracks allocations
pub struct TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            get_tracker().record_allocation(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        get_tracker().record_deallocation(layout.size());
        System.dealloc(ptr, layout);
    }
}

/// Zero-allocation scope for validating allocation-free code paths
pub struct ZeroAllocationScope {
    initial_stats: AllocationStats,
}

impl Default for ZeroAllocationScope {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroAllocationScope {
    pub fn new() -> Self {
        let initial_stats = get_tracker().get_stats();
        Self { initial_stats }
    }

    pub fn validate(&self) -> Result<(), AllocationViolation> {
        let current_stats = get_tracker().get_stats();
        let net_allocations = current_stats.allocations - self.initial_stats.allocations;
        let net_bytes = current_stats.bytes_allocated - self.initial_stats.bytes_allocated;

        if net_allocations > 0 {
            Err(AllocationViolation {
                allocations: net_allocations,
                bytes: net_bytes,
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct AllocationViolation {
    pub allocations: usize,
    pub bytes: usize,
}

impl std::fmt::Display for AllocationViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Zero-allocation violation: {} allocations, {} bytes",
            self.allocations, self.bytes
        )
    }
}

impl std::error::Error for AllocationViolation {}

/// Performance measurement utilities
pub struct PerformanceMeasurement {
    start_time: std::time::Instant,
    start_cycles: u64,
    start_allocations: AllocationStats,
}

impl PerformanceMeasurement {
    pub fn start() -> Self {
        let start_allocations = get_tracker().get_stats();
        Self {
            start_time: std::time::Instant::now(),
            start_cycles: read_cpu_cycles(),
            start_allocations,
        }
    }

    pub fn finish(self) -> PerformanceResult {
        let end_time = std::time::Instant::now();
        let end_cycles = read_cpu_cycles();
        let end_allocations = get_tracker().get_stats();

        PerformanceResult {
            duration: end_time.duration_since(self.start_time),
            cycles: end_cycles.saturating_sub(self.start_cycles),
            allocations: end_allocations.allocations - self.start_allocations.allocations,
            bytes_allocated: end_allocations.bytes_allocated
                - self.start_allocations.bytes_allocated,
        }
    }
}

#[derive(Debug)]
pub struct PerformanceResult {
    pub duration: std::time::Duration,
    pub cycles: u64,
    pub allocations: usize,
    pub bytes_allocated: usize,
}

impl PerformanceResult {
    pub fn cycles_per_nanosecond(&self) -> f64 {
        if self.duration.as_nanos() == 0 {
            0.0
        } else {
            self.cycles as f64 / self.duration.as_nanos() as f64
        }
    }

    pub fn is_zero_allocation(&self) -> bool {
        self.allocations == 0
    }
}

/// CPU cycle reading function
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn read_cpu_cycles() -> u64 {
    unsafe { std::arch::x86_64::_rdtsc() }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn read_cpu_cycles() -> u64 {
    // Fallback for non-x86_64 or non-Linux architectures
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Macro for measuring performance of code blocks
#[macro_export]
macro_rules! measure_performance {
    ($code:block) => {{
        let measurement = $crate::profiling::PerformanceMeasurement::start();
        let result = $code;
        let perf_result = measurement.finish();
        (result, perf_result)
    }};
}

/// Macro for validating zero-allocation code blocks
#[macro_export]
macro_rules! validate_zero_allocation {
    ($code:block) => {{
        let scope = $crate::profiling::ZeroAllocationScope::new();
        let result = $code;
        scope.validate().map(|_| result)
    }};
}

/// Reset global allocation tracking
pub fn reset_allocation_tracking() {
    get_tracker().reset();
}

/// Get current allocation statistics
pub fn get_allocation_stats() -> AllocationStats {
    get_tracker().get_stats()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocation_tracking() {
        reset_allocation_tracking();

        let initial_stats = get_allocation_stats();

        // Manually record an allocation to test the tracking
        get_tracker().record_allocation(1024);

        let stats = get_allocation_stats();
        // Check that allocations increased by exactly 1
        assert_eq!(stats.allocations, initial_stats.allocations + 1);
        // Check that bytes allocated increased by at least 1024
        assert!(stats.bytes_allocated >= initial_stats.bytes_allocated + 1024);
    }

    #[test]
    fn test_zero_allocation_scope() {
        reset_allocation_tracking();

        // This should pass (no allocations)
        let scope = ZeroAllocationScope::new();
        let _result = 42;
        assert!(scope.validate().is_ok());

        // This should fail (has allocation) - manually record allocation
        let scope = ZeroAllocationScope::new();
        get_tracker().record_allocation(100);
        assert!(scope.validate().is_err());
    }

    #[test]
    fn test_performance_measurement() {
        let measurement = PerformanceMeasurement::start();

        // Do some work
        let mut _sum = 0;
        for i in 0..1000 {
            _sum += i;
        }

        let result = measurement.finish();
        assert!(result.duration.as_nanos() > 0);
        assert!(result.cycles > 0);
    }
}
