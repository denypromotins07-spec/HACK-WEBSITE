//! Timeout and Cancellation Management
//! 
//! Implements cancellation tokens and hard timeouts for runaway
//! vulnerability modules to ensure scan completion.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::time::timeout;
use thiserror::Error;

/// Cancellation token for cooperative task cancellation
#[derive(Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    reason: Arc<watch::Sender<Option<String>>>,
}

impl CancellationToken {
    /// Create a new cancellation token
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(None);
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            reason: Arc::new(tx),
        }
    }
    
    /// Create a child token that cancels with parent
    pub fn child(&self) -> Self {
        Self {
            cancelled: self.cancelled.clone(),
            reason: self.reason.clone(),
        }
    }
    
    /// Cancel the token with a reason
    pub fn cancel(&self, reason: impl Into<String>) {
        self.cancelled.store(true, Ordering::SeqCst);
        let _ = self.reason.send(Some(reason.into()));
    }
    
    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
    
    /// Get cancellation reason if any
    pub fn get_reason(&self) -> Option<String> {
        self.reason.borrow().clone()
    }
    
    /// Reset the token
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
        let _ = self.reason.send(None);
    }
    
    /// Wait for cancellation
    pub async fn wait_for_cancel(&self) {
        while !self.is_cancelled() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    
    /// Check and return error if cancelled
    pub fn check(&self) -> Result<(), CancelledError> {
        if self.is_cancelled() {
            Err(CancelledError(self.get_reason().unwrap_or_default()))
        } else {
            Ok(())
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned when operation is cancelled
#[derive(Debug, Error, Clone)]
#[error("Operation cancelled: {0}")]
pub struct CancelledError(pub String);

/// Hard timeout wrapper for module execution
pub struct TimeoutManager {
    default_timeout: Duration,
    max_timeout: Duration,
    start_time: Instant,
}

impl TimeoutManager {
    /// Create a new timeout manager
    pub fn new(default_timeout: Duration, max_timeout: Duration) -> Self {
        Self {
            default_timeout,
            max_timeout,
            start_time: Instant::now(),
        }
    }
    
    /// Get remaining time until default timeout
    pub fn remaining(&self) -> Duration {
        self.default_timeout.saturating_sub(self.start_time.elapsed())
    }
    
    /// Check if timeout has elapsed
    pub fn is_elapsed(&self) -> bool {
        self.start_time.elapsed() >= self.default_timeout
    }
    
    /// Execute a future with timeout
    pub async fn execute_with_timeout<F, T>(&self, future: F) -> Result<T, TimeoutError>
    where
        F: std::future::Future<Output = Result<T, TimeoutError>>,
    {
        match timeout(self.remaining(), future).await {
            Ok(result) => result,
            Err(_) => Err(TimeoutError::Elapsed(self.default_timeout.as_millis() as u64)),
        }
    }
    
    /// Execute with hard timeout (non-negotiable)
    pub async fn execute_hard_timeout<F, T>(&self, future: F) -> Result<T, TimeoutError>
    where
        F: std::future::Future<Output = T>,
    {
        match timeout(self.max_timeout, future).await {
            Ok(result) => Ok(result),
            Err(_) => Err(TimeoutError::HardLimitExceeded(self.max_timeout.as_millis() as u64)),
        }
    }
    
    /// Reset the timer
    pub fn reset(&mut self) {
        self.start_time = Instant::now();
    }
    
    /// Extend timeout by duration
    pub fn extend(&mut self, extension: Duration) {
        self.default_timeout += extension;
        if self.default_timeout > self.max_timeout {
            self.default_timeout = self.max_timeout;
        }
    }
}

/// Timeout errors
#[derive(Debug, Error)]
pub enum TimeoutError {
    #[error("Timeout elapsed after {0}ms")]
    Elapsed(u64),
    
    #[error("Hard timeout limit exceeded: {0}ms")]
    HardLimitExceeded(u64),
    
    #[error("Cancelled: {0}")]
    Cancelled(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Module execution guard with automatic timeout and cancellation
pub struct ExecutionGuard {
    token: CancellationToken,
    timeout_mgr: TimeoutManager,
    execution_count: Arc<AtomicU64>,
}

impl ExecutionGuard {
    /// Create a new execution guard
    pub fn new(token: CancellationToken, timeout_duration: Duration) -> Self {
        Self {
            token,
            timeout_mgr: TimeoutManager::new(timeout_duration, timeout_duration * 2),
            execution_count: Arc::new(AtomicU64::new(0)),
        }
    }
    
    /// Check if execution should continue
    pub fn should_continue(&self) -> Result<(), ExecutionError> {
        // Check cancellation
        self.token.check()?;
        
        // Check timeout
        if self.timeout_mgr.is_elapsed() {
            return Err(ExecutionError::Timeout(
                self.timeout_mgr.default_timeout.as_millis() as u64
            ));
        }
        
        Ok(())
    }
    
    /// Execute a closure with guard checks
    pub fn execute<F, T>(&self, f: F) -> Result<T, ExecutionError>
    where
        F: FnOnce() -> Result<T, ExecutionError>,
    {
        self.should_continue()?;
        self.execution_count.fetch_add(1, Ordering::Relaxed);
        f()
    }
    
    /// Get execution count
    pub fn execution_count(&self) -> u64 {
        self.execution_count.load(Ordering::Relaxed)
    }
    
    /// Get remaining time
    pub fn remaining(&self) -> Duration {
        self.timeout_mgr.remaining()
    }
    
    /// Cancel execution
    pub fn cancel(&self, reason: impl Into<String>) {
        self.token.cancel(reason);
    }
    
    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

/// Execution errors
#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("Timeout after {0}ms")]
    Timeout(u64),
    
    #[error("Cancelled: {0}")]
    Cancelled(String),
    
    #[error("Budget exceeded: {0}")]
    BudgetExceeded(String),
    
    #[error("Module error: {0}")]
    ModuleError(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<CancelledError> for ExecutionError {
    fn from(err: CancelledError) -> Self {
        ExecutionError::Cancelled(err.0)
    }
}

impl From<TimeoutError> for ExecutionError {
    fn from(err: TimeoutError) -> Self {
        match err {
            TimeoutError::Elapsed(ms) | TimeoutError::HardLimitExceeded(ms) => {
                ExecutionError::Timeout(ms)
            }
            TimeoutError::Cancelled(reason) => ExecutionError::Cancelled(reason),
            TimeoutError::Internal(msg) => ExecutionError::Internal(msg),
        }
    }
}

/// Watchdog for monitoring long-running operations
pub struct Watchdog {
    check_interval: Duration,
    max_no_progress: Duration,
    last_progress: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
}

impl Watchdog {
    /// Create a new watchdog
    pub fn new(check_interval: Duration, max_no_progress: Duration) -> Self {
        Self {
            check_interval,
            max_no_progress,
            last_progress: Arc::new(AtomicU64::new(Instant::now().elapsed().as_millis() as u64)),
            running: Arc::new(AtomicBool::new(true)),
        }
    }
    
    /// Signal progress
    pub fn ping(&self) {
        self.last_progress.store(
            Instant::now().elapsed().as_millis() as u64,
            Ordering::Relaxed,
        );
    }
    
    /// Check if watchdog has triggered
    pub fn is_alive(&self) -> bool {
        let elapsed = Instant::now().elapsed().as_millis() as u64;
        let last = self.last_progress.load(Ordering::Relaxed);
        elapsed - last < self.max_no_progress.as_millis() as u64
    }
    
    /// Stop the watchdog
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
    
    /// Run watchdog in background, cancel token if stuck
    pub async fn run(&self, token: CancellationToken) {
        while self.running.load(Ordering::Relaxed) && !token.is_cancelled() {
            tokio::time::sleep(self.check_interval).await;
            
            if !self.is_alive() {
                token.cancel("Watchdog detected no progress".to_string());
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cancellation_token() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        
        token.cancel("test reason");
        assert!(token.is_cancelled());
        assert_eq!(token.get_reason(), Some("test reason".to_string()));
    }
    
    #[test]
    fn test_token_check() {
        let token = CancellationToken::new();
        assert!(token.check().is_ok());
        
        token.cancel("cancelled");
        assert!(token.check().is_err());
    }
    
    #[tokio::test]
    async fn test_timeout_manager() {
        let mgr = TimeoutManager::new(
            Duration::from_millis(100),
            Duration::from_millis(200),
        );
        
        // Should complete in time
        let result = mgr.execute_hard_timeout(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            42
        }).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }
    
    #[tokio::test]
    async fn test_watchdog() {
        let watchdog = Watchdog::new(
            Duration::from_millis(50),
            Duration::from_millis(100),
        );
        
        assert!(watchdog.is_alive());
        watchdog.ping();
        assert!(watchdog.is_alive());
        
        // Let it expire
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!watchdog.is_alive());
    }
    
    #[test]
    fn test_execution_guard() {
        let token = CancellationToken::new();
        let guard = ExecutionGuard::new(token.clone(), Duration::from_secs(1));
        
        assert!(guard.should_continue().is_ok());
        assert!(!guard.is_cancelled());
        
        guard.cancel("stopped");
        assert!(guard.is_cancelled());
        assert!(guard.should_continue().is_err());
    }
}
