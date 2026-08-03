//! Lock-free atomic metrics for real-time RAM usage monitoring.
//! Triggers circuit breaker if 2GB limit is approached.

use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use crate::memory::{MEMORY_LIMIT_BYTES, MEMORY_CRITICAL_THRESHOLD, global_tracker};

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed, operations allowed
    Closed,
    /// Circuit is open, operations blocked
    Open,
    /// Circuit is half-open, testing recovery
    HalfOpen,
}

/// Lock-free metrics registry using atomic operations
pub struct MetricsRegistry {
    /// Total bytes allocated
    bytes_allocated: AtomicU64,
    /// Total requests processed
    requests_total: AtomicU64,
    /// Successful requests
    requests_success: AtomicU64,
    /// Failed requests
    requests_failed: AtomicU64,
    /// Current active connections
    active_connections: AtomicU64,
    /// Peak memory usage observed
    peak_memory_bytes: AtomicU64,
    /// Circuit breaker state
    circuit_state: AtomicBool, // false = closed, true = open
    /// Last circuit breaker trip timestamp (nanos since epoch)
    circuit_trip_time: AtomicU64,
    /// Agent task count
    tasks_dispatched: AtomicU64,
    /// Tasks completed
    tasks_completed: AtomicU64,
}

impl MetricsRegistry {
    /// Create a new metrics registry
    pub const fn new() -> Self {
        MetricsRegistry {
            bytes_allocated: AtomicU64::new(0),
            requests_total: AtomicU64::new(0),
            requests_success: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            peak_memory_bytes: AtomicU64::new(0),
            circuit_state: AtomicBool::new(false),
            circuit_trip_time: AtomicU64::new(0),
            tasks_dispatched: AtomicU64::new(0),
            tasks_completed: AtomicU64::new(0),
        }
    }

    /// Record bytes allocated
    pub fn record_allocation(&self, bytes: u64) {
        self.bytes_allocated.fetch_add(bytes, Ordering::Relaxed);
        self.update_peak_memory();
        self.check_circuit_breaker();
    }

    /// Record bytes deallocated
    pub fn record_deallocation(&self, bytes: u64) {
        self.bytes_allocated.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Update peak memory if current exceeds previous peak
    fn update_peak_memory(&self) {
        let current = self.bytes_allocated.load(Ordering::Relaxed);
        let mut peak = self.peak_memory_bytes.load(Ordering::Relaxed);
        
        while current > peak {
            match self.peak_memory_bytes.compare_exchange_weak(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
    }

    /// Record an HTTP request
    pub fn record_request(&self, success: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if success {
            self.requests_success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.requests_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record connection opened
    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection closed
    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record task dispatched
    pub fn task_dispatched(&self) {
        self.tasks_dispatched.fetch_add(1, Ordering::Relaxed);
    }

    /// Record task completed
    pub fn task_completed(&self) {
        self.tasks_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Check and potentially trip the circuit breaker
    fn check_circuit_breaker(&self) {
        let current_memory = self.bytes_allocated.load(Ordering::Relaxed) as usize;
        
        if current_memory >= MEMORY_CRITICAL_THRESHOLD {
            // Trip the circuit breaker
            if !self.circuit_state.load(Ordering::Relaxed) {
                self.circuit_state.store(true, Ordering::Relaxed);
                self.circuit_trip_time.store(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64,
                    Ordering::Relaxed,
                );
                tracing::warn!(
                    "CIRCUIT BREAKER TRIPPED: Memory at {}% of limit",
                    (current_memory as f64 / MEMORY_LIMIT_BYTES as f64) * 100.0
                );
            }
        }
    }

    /// Get current circuit breaker state
    pub fn circuit_state(&self) -> CircuitState {
        if self.circuit_state.load(Ordering::Relaxed) {
            CircuitState::Open
        } else {
            CircuitState::Closed
        }
    }

    /// Reset circuit breaker (for recovery testing)
    pub fn reset_circuit(&self) {
        self.circuit_state.store(false, Ordering::Relaxed);
        self.circuit_trip_time.store(0, Ordering::Relaxed);
    }

    /// Get current memory usage
    pub fn current_memory(&self) -> u64 {
        self.bytes_allocated.load(Ordering::Relaxed)
    }

    /// Get peak memory usage
    pub fn peak_memory(&self) -> u64 {
        self.peak_memory_bytes.load(Ordering::Relaxed)
    }

    /// Get memory usage as percentage of limit
    pub fn memory_percent(&self) -> f64 {
        (self.current_memory() as f64 / MEMORY_LIMIT_BYTES as f64) * 100.0
    }

    /// Get request statistics
    pub fn request_stats(&self) -> RequestStats {
        RequestStats {
            total: self.requests_total.load(Ordering::Relaxed),
            success: self.requests_success.load(Ordering::Relaxed),
            failed: self.requests_failed.load(Ordering::Relaxed),
        }
    }

    /// Get full metrics snapshot
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            bytes_allocated: self.current_memory(),
            peak_memory: self.peak_memory(),
            memory_percent: self.memory_percent(),
            requests: self.request_stats(),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            tasks_dispatched: self.tasks_dispatched.load(Ordering::Relaxed),
            tasks_completed: self.tasks_completed.load(Ordering::Relaxed),
            circuit_state: self.circuit_state(),
            circuit_trip_time: self.circuit_trip_time.load(Ordering::Relaxed),
        }
    }

    /// Check if system is healthy (circuit closed and memory below warning)
    pub fn is_healthy(&self) -> bool {
        matches!(self.circuit_state(), CircuitState::Closed)
            && self.memory_percent() < 90.0
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Request statistics
#[derive(Debug, Clone, Copy)]
pub struct RequestStats {
    pub total: u64,
    pub success: u64,
    pub failed: u64,
}

/// Full metrics snapshot for reporting
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub bytes_allocated: u64,
    pub peak_memory: u64,
    pub memory_percent: f64,
    pub requests: RequestStats,
    pub active_connections: u64,
    pub tasks_dispatched: u64,
    pub tasks_completed: u64,
    pub circuit_state: CircuitState,
    pub circuit_trip_time: u64,
}

// Global metrics registry
static GLOBAL_METRICS: MetricsRegistry = MetricsRegistry::new();

/// Get reference to global metrics registry
pub fn global_metrics() -> &'static MetricsRegistry {
    &GLOBAL_METRICS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registry() {
        let metrics = MetricsRegistry::new();
        metrics.record_allocation(1024);
        assert_eq!(metrics.current_memory(), 1024);
        metrics.record_deallocation(512);
        assert_eq!(metrics.current_memory(), 512);
    }

    #[test]
    fn test_request_stats() {
        let metrics = MetricsRegistry::new();
        metrics.record_request(true);
        metrics.record_request(true);
        metrics.record_request(false);
        
        let stats = metrics.request_stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.success, 2);
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn test_circuit_state() {
        let metrics = MetricsRegistry::new();
        assert_eq!(metrics.circuit_state(), CircuitState::Closed);
    }
}
