//! Telemetry module wiring together logger and metrics.
//! Exposes global logger and metric registry to the application.

pub mod logger;
pub mod metrics;

pub use logger::{
    init_logger,
    init_logger_with_config,
    shutdown_logger,
    get_logger,
    LoggerConfig,
    LoggerHandle,
};

pub use metrics::{
    global_metrics,
    CircuitState,
    MetricsRegistry,
    MetricsSnapshot,
    RequestStats,
};

/// Initialize the complete telemetry stack
pub fn init_telemetry(verbose: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logger
    init_logger(verbose)?;
    
    tracing::info!("Telemetry initialized");
    Ok(())
}

/// Get combined system health status
pub fn system_health() -> SystemHealth {
    let metrics = global_metrics();
    let tracker = crate::memory::global_tracker();
    
    SystemHealth {
        memory_usage_bytes: tracker.current() as u64,
        memory_peak_bytes: tracker.peak() as u64,
        memory_percent: tracker.usage_percent(),
        circuit_state: metrics.circuit_state(),
        is_healthy: metrics.is_healthy() && !tracker.should_trip_circuit(),
    }
}

/// Complete system health snapshot
#[derive(Debug, Clone)]
pub struct SystemHealth {
    pub memory_usage_bytes: u64,
    pub memory_peak_bytes: u64,
    pub memory_percent: f64,
    pub circuit_state: CircuitState,
    pub is_healthy: bool,
}

impl SystemHealth {
    /// Check if system is operating normally
    pub fn is_operational(&self) -> bool {
        self.is_healthy && matches!(self.circuit_state, CircuitState::Closed)
    }

    /// Get health as a status string
    pub fn status_str(&self) -> &'static str {
        if self.is_operational() {
            "operational"
        } else if matches!(self.circuit_state, CircuitState::Open) {
            "circuit_open"
        } else {
            "degraded"
        }
    }
}

/// Report current telemetry state for debugging
pub fn report_status() {
    let health = system_health();
    let metrics_snapshot = global_metrics().snapshot();
    
    tracing::info!(
        target: "telemetry",
        memory_usage_mb = health.memory_usage_bytes as f64 / (1024.0 * 1024.0),
        memory_peak_mb = health.memory_peak_bytes as f64 / (1024.0 * 1024.0),
        memory_percent = health.memory_percent,
        circuit_state = ?health.circuit_state,
        requests_total = metrics_snapshot.requests.total,
        requests_success = metrics_snapshot.requests.success,
        requests_failed = metrics_snapshot.requests.failed,
        tasks_dispatched = metrics_snapshot.tasks_dispatched,
        tasks_completed = metrics_snapshot.tasks_completed,
        "System status report"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_health() {
        let health = system_health();
        assert!(health.memory_percent >= 0.0);
        assert!(health.memory_percent <= 100.0);
    }

    #[test]
    fn test_health_status_str() {
        let health = system_health();
        let status = health.status_str();
        assert!(!status.is_empty());
    }
}
