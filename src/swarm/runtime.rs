//! Optimized Tokio multi-threaded runtime for the agent swarm.
//! Configured with strict worker thread limits and bounded I/O polling.

use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};
use crate::memory::{MemoryTracker, global_tracker};

/// Number of agent workers (fixed at 100)
pub const AGENT_COUNT: usize = 100;

/// Maximum concurrent requests the swarm can handle
pub const MAX_CONCURRENT_REQUESTS: usize = 10_000;

/// Worker thread count (typically CPU cores * 2 for I/O bound)
fn worker_thread_count() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get() * 2)
        .unwrap_or(16)
}

/// Build the optimized Tokio runtime
pub fn build_runtime() -> Result<Runtime, Box<dyn std::error::Error>> {
    let workers = worker_thread_count();
    
    let runtime = Builder::new_multi_thread()
        // Strict worker thread limit - no dynamic OS thread spawning
        .worker_threads(workers)
        // Pre-allocate thread stack to prevent fragmentation
        .thread_stack_size(2 * 1024 * 1024) // 2MB per thread
        // Bounded task queue
        .max_blocking_threads(512)
        // Enable all features needed for async operations
        .enable_all()
        // Custom thread name for debugging
        .thread_name_fn(|| {
            static ATOMIC_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            format!("swarm-worker-{}", id)
        })
        // Global pre-start hook for memory tracking
        .on_thread_start(|| {
            tracing::debug!("Swarm worker thread started");
        })
        // Thread stop hook for cleanup verification
        .on_thread_stop(|| {
            tracing::debug!("Swarm worker thread stopped");
        })
        .build()?;

    Ok(runtime)
}

/// Swarm runtime configuration
#[derive(Clone, Debug)]
pub struct SwarmRuntimeConfig {
    pub agent_count: usize,
    pub max_concurrent_requests: usize,
    pub worker_threads: usize,
    pub enable_telemetry: bool,
}

impl Default for SwarmRuntimeConfig {
    fn default() -> Self {
        SwarmRuntimeConfig {
            agent_count: AGENT_COUNT,
            max_concurrent_requests: MAX_CONCURRENT_REQUESTS,
            worker_threads: worker_thread_count(),
            enable_telemetry: true,
        }
    }
}

/// Runtime health status
#[derive(Debug, Clone)]
pub struct RuntimeHealth {
    pub active_workers: usize,
    pub memory_usage_percent: f64,
    pub is_healthy: bool,
    pub circuit_breaker_tripped: bool,
}

impl RuntimeHealth {
    pub fn check() -> Self {
        let tracker = global_tracker();
        let circuit_tripped = tracker.should_trip_circuit();
        
        RuntimeHealth {
            active_workers: worker_thread_count(),
            memory_usage_percent: tracker.usage_percent(),
            is_healthy: !circuit_tripped && tracker.current() < super::memory::MEMORY_WARNING_THRESHOLD,
            circuit_breaker_tripped: circuit_tripped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_config() {
        let config = SwarmRuntimeConfig::default();
        assert_eq!(config.agent_count, AGENT_COUNT);
        assert_eq!(config.max_concurrent_requests, MAX_CONCURRENT_REQUESTS);
    }

    #[test]
    fn test_runtime_health() {
        let health = RuntimeHealth::check();
        assert!(health.active_workers > 0);
        assert!(health.memory_usage_percent >= 0.0);
    }
}
