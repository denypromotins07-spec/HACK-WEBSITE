//! Memory management module with arena allocator and object pooling.
//! Enforces strict 2GB RAM ceiling using zero-copy paradigms.

pub mod arena;
pub mod pool;

pub use arena::{
    check_memory_pressure,
    get_arena,
    get_arena_mut,
    get_total_allocated,
    Arena,
    THREAD_ARENA,
};

pub use pool::{
    BufferPool,
    HttpClientPool,
    PooledBuffer,
    PoolStats,
};

/// Hard memory limit: 2GB
pub const MEMORY_LIMIT_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// Warning threshold: 90% of limit
pub const MEMORY_WARNING_THRESHOLD: usize = MEMORY_LIMIT_BYTES * 90 / 100;

/// Critical threshold: 95% of limit (circuit breaker triggers)
pub const MEMORY_CRITICAL_THRESHOLD: usize = MEMORY_LIMIT_BYTES * 95 / 100;

/// Global memory tracker using atomic operations for lock-free access
pub struct MemoryTracker {
    current_usage: std::sync::atomic::AtomicUsize,
    peak_usage: std::sync::atomic::AtomicUsize,
    allocation_count: std::sync::atomic::AtomicUsize,
}

impl MemoryTracker {
    pub const fn new() -> Self {
        MemoryTracker {
            current_usage: std::sync::atomic::AtomicUsize::new(0),
            peak_usage: std::sync::atomic::AtomicUsize::new(0),
            allocation_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Record an allocation
    pub fn record_alloc(&self, bytes: usize) {
        self.current_usage.fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
        self.allocation_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        // Update peak if necessary
        let mut peak = self.peak_usage.load(std::sync::atomic::Ordering::Relaxed);
        let current = self.current_usage.load(std::sync::atomic::Ordering::Relaxed);
        while current > peak {
            match self.peak_usage.compare_exchange_weak(
                peak,
                current,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
    }

    /// Record a deallocation
    pub fn record_dealloc(&self, bytes: usize) {
        self.current_usage.fetch_sub(bytes, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get current memory usage
    pub fn current(&self) -> usize {
        self.current_usage.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get peak memory usage
    pub fn peak(&self) -> usize {
        self.peak_usage.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get total allocation count
    pub fn allocation_count(&self) -> usize {
        self.allocation_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Check if approaching memory limit
    pub fn is_near_limit(&self) -> bool {
        self.current() >= MEMORY_WARNING_THRESHOLD
    }

    /// Check if circuit breaker should trigger
    pub fn should_trip_circuit(&self) -> bool {
        self.current() >= MEMORY_CRITICAL_THRESHOLD
    }

    /// Get memory usage as percentage of limit
    pub fn usage_percent(&self) -> f64 {
        (self.current() as f64 / MEMORY_LIMIT_BYTES as f64) * 100.0
    }
}

impl Default for MemoryTracker {
    fn default() -> Self {
        Self::new()
    }
}

// Global memory tracker instance
static GLOBAL_TRACKER: MemoryTracker = MemoryTracker::new();

/// Get reference to global memory tracker
pub fn global_tracker() -> &'static MemoryTracker {
    &GLOBAL_TRACKER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_tracker() {
        let tracker = MemoryTracker::new();
        tracker.record_alloc(1024);
        assert_eq!(tracker.current(), 1024);
        tracker.record_dealloc(512);
        assert_eq!(tracker.current(), 512);
    }

    #[test]
    fn test_memory_limits() {
        assert_eq!(MEMORY_LIMIT_BYTES, 2 * 1024 * 1024 * 1024);
        assert_eq!(MEMORY_WARNING_THRESHOLD, MEMORY_LIMIT_BYTES * 90 / 100);
    }
}
