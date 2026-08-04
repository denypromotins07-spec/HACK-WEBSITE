//! Resource Budget Enforcement
//! 
//! Enforces per-check CPU, RAM, request-count, and time budgets
//! to preserve the 10-minute target scan duration.

use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Resource budget constraints for a single check
#[derive(Debug, Clone, Copy)]
pub struct ResourceBudget {
    /// Maximum CPU time in milliseconds
    pub max_cpu_ms: u64,
    /// Maximum memory usage in bytes (2GB total system limit)
    pub max_memory_bytes: u64,
    /// Maximum number of HTTP requests allowed
    pub max_requests: u32,
    /// Maximum execution duration in milliseconds
    pub max_duration_ms: u64,
    /// Maximum payload size in bytes
    pub max_payload_size: usize,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            max_cpu_ms: 500,
            max_memory_bytes: 10 * 1024 * 1024, // 10MB per check
            max_requests: 50,
            max_duration_ms: 2000,
            max_payload_size: 4096,
        }
    }
}

impl ResourceBudget {
    /// Tight budget for safe checks
    pub fn safe() -> Self {
        Self {
            max_cpu_ms: 100,
            max_memory_bytes: 2 * 1024 * 1024,
            max_requests: 10,
            max_duration_ms: 500,
            max_payload_size: 1024,
        }
    }
    
    /// Expanded budget for advanced checks (god-mode only)
    pub fn advanced() -> Self {
        Self {
            max_cpu_ms: 2000,
            max_memory_bytes: 50 * 1024 * 1024,
            max_requests: 200,
            max_duration_ms: 10000,
            max_payload_size: 16384,
        }
    }
    
    /// Convert duration to milliseconds
    pub fn from_duration(d: Duration) -> u64 {
        d.as_millis() as u64
    }
}

/// Runtime tracker for resource consumption
pub struct ResourceTracker {
    start_time: Instant,
    cpu_ms: AtomicU64,
    memory_bytes: AtomicU64,
    request_count: AtomicU32,
    payload_size: AtomicU64,
    budget: ResourceBudget,
}

impl ResourceTracker {
    /// Create a new tracker with the given budget
    pub fn new(budget: ResourceBudget) -> Self {
        Self {
            start_time: Instant::now(),
            cpu_ms: AtomicU64::new(0),
            memory_bytes: AtomicU64::new(0),
            request_count: AtomicU32::new(0),
            payload_size: AtomicU64::new(0),
            budget,
        }
    }
    
    /// Record CPU time used
    pub fn record_cpu(&self, ms: u64) {
        self.cpu_ms.fetch_add(ms, Ordering::Relaxed);
    }
    
    /// Record memory allocation
    pub fn record_memory(&self, bytes: u64) {
        self.memory_bytes.store(bytes, Ordering::Relaxed);
    }
    
    /// Record an HTTP request
    pub fn record_request(&self) -> Result<(), BudgetError> {
        let count = self.request_count.fetch_add(1, Ordering::Relaxed);
        if count >= self.budget.max_requests {
            return Err(BudgetError::RequestLimitExceeded(count));
        }
        Ok(())
    }
    
    /// Record payload size
    pub fn record_payload(&self, bytes: usize) -> Result<(), BudgetError> {
        let current = self.payload_size.fetch_add(bytes as u64, Ordering::Relaxed);
        if current + bytes as u64 > self.budget.max_payload_size as u64 {
            return Err(BudgetError::PayloadSizeExceeded(current as usize + bytes));
        }
        Ok(())
    }
    
    /// Get elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
    
    /// Check if duration budget is exceeded
    pub fn is_duration_exceeded(&self) -> bool {
        self.elapsed_ms() > self.budget.max_duration_ms
    }
    
    /// Check if CPU budget is exceeded
    pub fn is_cpu_exceeded(&self) -> bool {
        self.cpu_ms.load(Ordering::Relaxed) > self.budget.max_cpu_ms
    }
    
    /// Check if memory budget is exceeded
    pub fn is_memory_exceeded(&self) -> bool {
        self.memory_bytes.load(Ordering::Relaxed) > self.budget.max_memory_bytes
    }
    
    /// Check if request budget is exceeded
    pub fn is_request_exceeded(&self) -> bool {
        self.request_count.load(Ordering::Relaxed) >= self.budget.max_requests
    }
    
    /// Check if any budget is exceeded
    pub fn is_any_exceeded(&self) -> bool {
        self.is_duration_exceeded() 
            || self.is_cpu_exceeded() 
            || self.is_memory_exceeded()
            || self.is_request_exceeded()
    }
    
    /// Get remaining duration in milliseconds
    pub fn remaining_duration_ms(&self) -> u64 {
        self.budget
            .max_duration_ms
            .saturating_sub(self.elapsed_ms())
    }
    
    /// Get remaining request count
    pub fn remaining_requests(&self) -> u32 {
        self.budget
            .max_requests
            .saturating_sub(self.request_count.load(Ordering::Relaxed))
    }
    
    /// Get current usage summary
    pub fn get_usage(&self) -> ResourceUsage {
        ResourceUsage {
            cpu_ms: self.cpu_ms.load(Ordering::Relaxed),
            memory_bytes: self.memory_bytes.load(Ordering::Relaxed),
            request_count: self.request_count.load(Ordering::Relaxed),
            duration_ms: self.elapsed_ms(),
            payload_size: self.payload_size.load(Ordering::Relaxed) as usize,
        }
    }
    
    /// Validate that operation can proceed
    pub fn validate(&self) -> Result<(), BudgetError> {
        if self.is_duration_exceeded() {
            return Err(BudgetError::DurationExceeded(self.elapsed_ms()));
        }
        if self.is_cpu_exceeded() {
            return Err(BudgetError::CpuExceeded(self.cpu_ms.load(Ordering::Relaxed)));
        }
        if self.is_memory_exceeded() {
            return Err(BudgetError::MemoryExceeded(self.memory_bytes.load(Ordering::Relaxed)));
        }
        if self.is_request_exceeded() {
            return Err(BudgetError::RequestLimitExceeded(self.request_count.load(Ordering::Relaxed)));
        }
        Ok(())
    }
}

/// Current resource usage snapshot
#[derive(Debug, Clone, Copy)]
pub struct ResourceUsage {
    pub cpu_ms: u64,
    pub memory_bytes: u64,
    pub request_count: u32,
    pub duration_ms: u64,
    pub payload_size: usize,
}

impl Default for ResourceUsage {
    fn default() -> Self {
        Self {
            cpu_ms: 0,
            memory_bytes: 0,
            request_count: 0,
            duration_ms: 0,
            payload_size: 0,
        }
    }
}

/// Budget violation errors
#[derive(Debug, Error)]
pub enum BudgetError {
    #[error("Duration exceeded: {0}ms")]
    DurationExceeded(u64),
    
    #[error("CPU limit exceeded: {0}ms")]
    CpuExceeded(u64),
    
    #[error("Memory limit exceeded: {0} bytes")]
    MemoryExceeded(u64),
    
    #[error("Request limit exceeded: {0}")]
    RequestLimitExceeded(u32),
    
    #[error("Payload size exceeded: {0} bytes")]
    PayloadSizeExceeded(usize),
    
    #[error("Budget validation failed: {0}")]
    ValidationFailed(String),
}

/// Global resource manager for the entire scanner
pub struct GlobalResourceManager {
    /// Total memory limit (2GB ceiling)
    max_total_memory: AtomicU64,
    /// Current memory usage across all agents
    current_memory: AtomicU64,
    /// Total request rate limit per second
    max_requests_per_second: AtomicU32,
    /// Current request count this second
    current_requests: AtomicU32,
}

impl GlobalResourceManager {
    /// Create with 2GB memory ceiling
    pub fn new() -> Self {
        Self {
            max_total_memory: AtomicU64::new(2 * 1024 * 1024 * 1024), // 2GB
            current_memory: AtomicU64::new(0),
            max_requests_per_second: AtomicU32::new(1000),
            current_requests: AtomicU32::new(0),
        }
    }
    
    /// Try to allocate memory
    pub fn try_allocate_memory(&self, bytes: u64) -> bool {
        let current = self.current_memory.load(Ordering::Relaxed);
        if current + bytes > self.max_total_memory.load(Ordering::Relaxed) {
            return false;
        }
        self.current_memory.fetch_add(bytes, Ordering::Relaxed);
        true
    }
    
    /// Release allocated memory
    pub fn release_memory(&self, bytes: u64) {
        self.current_memory.fetch_sub(bytes.min(self.current_memory.load(Ordering::Relaxed)), Ordering::Relaxed);
    }
    
    /// Try to make a request (rate limited)
    pub fn try_request(&self) -> bool {
        let current = self.current_requests.load(Ordering::Relaxed);
        if current >= self.max_requests_per_second.load(Ordering::Relaxed) {
            return false;
        }
        self.current_requests.fetch_add(1, Ordering::Relaxed);
        true
    }
    
    /// Reset request counter (call once per second)
    pub fn reset_request_counter(&self) {
        self.current_requests.store(0, Ordering::Relaxed);
    }
    
    /// Get current memory usage
    pub fn get_memory_usage(&self) -> u64 {
        self.current_memory.load(Ordering::Relaxed)
    }
    
    /// Get available memory
    pub fn get_available_memory(&self) -> u64 {
        self.max_total_memory
            .load(Ordering::Relaxed)
            .saturating_sub(self.current_memory.load(Ordering::Relaxed))
    }
}

impl Default for GlobalResourceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_resource_tracker_budget_exceeded() {
        let budget = ResourceBudget::safe();
        let tracker = ResourceTracker::new(budget);
        
        // Should pass initially
        assert!(tracker.validate().is_ok());
        
        // Simulate exceeding request limit
        for _ in 0..budget.max_requests {
            let _ = tracker.record_request();
        }
        
        assert!(tracker.is_request_exceeded());
        assert!(tracker.validate().is_err());
    }
    
    #[test]
    fn test_global_memory_manager() {
        let manager = GlobalResourceManager::new();
        
        // Allocate some memory
        assert!(manager.try_allocate_memory(100_000_000)); // 100MB
        assert_eq!(manager.get_memory_usage(), 100_000_000);
        
        // Release it
        manager.release_memory(100_000_000);
        assert_eq!(manager.get_memory_usage(), 0);
    }
    
    #[test]
    fn test_remaining_resources() {
        let budget = ResourceBudget {
            max_requests: 10,
            max_duration_ms: 1000,
            ..Default::default()
        };
        let tracker = ResourceTracker::new(budget);
        
        // Use some requests
        for _ in 0..3 {
            let _ = tracker.record_request();
        }
        
        assert_eq!(tracker.remaining_requests(), 7);
        assert!(tracker.remaining_duration_ms() <= 1000);
    }
}
