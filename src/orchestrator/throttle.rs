//! Request Throttling and Rate Limiting
//! 
//! Coordinates request pressure across agents to avoid target overload
//! and WAF bans during vulnerability scanning.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::sleep;

/// Throttle configuration
#[derive(Debug, Clone)]
pub struct ThrottleConfig {
    /// Maximum requests per second globally
    pub max_requests_per_second: u32,
    /// Maximum requests per second per agent
    pub max_per_agent_per_second: u32,
    /// Maximum concurrent connections
    pub max_concurrent_connections: usize,
    /// Delay between requests in milliseconds
    pub base_delay_ms: u64,
    /// Exponential backoff multiplier on errors
    pub backoff_multiplier: f32,
    /// Maximum backoff delay in milliseconds
    pub max_backoff_ms: u64,
    /// Cooldown period after too many errors (seconds)
    pub cooldown_seconds: u64,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            max_requests_per_second: 100,
            max_per_agent_per_second: 20,
            max_concurrent_connections: 50,
            base_delay_ms: 10,
            backoff_multiplier: 2.0,
            max_backoff_ms: 5000,
            cooldown_seconds: 60,
        }
    }
}

impl ThrottleConfig {
    /// Aggressive settings for god-mode scanning
    pub fn aggressive() -> Self {
        Self {
            max_requests_per_second: 500,
            max_per_agent_per_second: 100,
            max_concurrent_connections: 200,
            base_delay_ms: 1,
            ..Default::default()
        }
    }
    
    /// Conservative settings to avoid detection
    pub fn stealth() -> Self {
        Self {
            max_requests_per_second: 10,
            max_per_agent_per_second: 2,
            max_concurrent_connections: 5,
            base_delay_ms: 100,
            ..Default::default()
        }
    }
}

/// Per-agent rate limiter
pub struct AgentRateLimiter {
    last_request: AtomicU64, // timestamp in ms
    request_count: AtomicU32,
    window_start: AtomicU64,
    max_per_second: u32,
}

impl AgentRateLimiter {
    pub fn new(max_per_second: u32) -> Self {
        let now = Instant::now().elapsed().as_millis() as u64;
        Self {
            last_request: AtomicU64::new(0),
            request_count: AtomicU32::new(0),
            window_start: AtomicU64::new(now),
            max_per_second,
        }
    }
    
    /// Wait until ready to make a request
    pub async fn wait_for_slot(&self) {
        loop {
            let now = Instant::now().elapsed().as_millis() as u64;
            let window_start = self.window_start.load(Ordering::Relaxed);
            
            // Reset window if needed
            if now - window_start >= 1000 {
                self.window_start.store(now, Ordering::Relaxed);
                self.request_count.store(0, Ordering::Relaxed);
                break;
            }
            
            let count = self.request_count.load(Ordering::Relaxed);
            if count < self.max_per_second {
                break;
            }
            
            // Wait until next window
            sleep(Duration::from_millis(10)).await;
        }
        
        // Record this request
        self.last_request.store(
            Instant::now().elapsed().as_millis() as u64,
            Ordering::Relaxed,
        );
        self.request_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Get time until next available slot in ms
    pub fn time_until_ready(&self) -> u64 {
        let now = Instant::now().elapsed().as_millis() as u64;
        let window_start = self.window_start.load(Ordering::Relaxed);
        
        if now - window_start >= 1000 {
            return 0;
        }
        
        let count = self.request_count.load(Ordering::Relaxed);
        if count < self.max_per_second {
            return 0;
        }
        
        1000 - (now - window_start)
    }
}

/// Global throttle manager for all agents
pub struct ThrottleManager {
    config: ThrottleConfig,
    global_limiter: Arc<AgentRateLimiter>,
    concurrent_semaphore: Arc<Semaphore>,
    error_count: AtomicU32,
    last_error_time: AtomicU64,
    current_delay_ms: AtomicU64,
    is_cooldown: AtomicBool,
    cooldown_until: AtomicU64,
}

impl ThrottleManager {
    /// Create a new throttle manager
    pub fn new(config: ThrottleConfig) -> Self {
        Self {
            global_limiter: Arc::new(AgentRateLimiter::new(config.max_requests_per_second)),
            concurrent_semaphore: Arc::new(Semaphore::new(config.max_concurrent_connections)),
            config,
            error_count: AtomicU32::new(0),
            last_error_time: AtomicU64::new(0),
            current_delay_ms: AtomicU64::new(config.base_delay_ms),
            is_cooldown: AtomicBool::new(false),
            cooldown_until: AtomicU64::new(0),
        }
    }
    
    /// Acquire permission to make a request
    pub async fn acquire(&self) -> Result<ThrottlePermit, ThrottleError> {
        // Check cooldown
        if self.is_cooldown.load(Ordering::Relaxed) {
            let now = Instant::now().elapsed().as_millis() as u64;
            let until = self.cooldown_until.load(Ordering::Relaxed);
            if now < until {
                return Err(ThrottleError::InCooldown(until - now));
            } else {
                // Cooldown expired
                self.is_cooldown.store(false, Ordering::Relaxed);
                self.error_count.store(0, Ordering::Relaxed);
                self.current_delay_ms.store(self.config.base_delay_ms, Ordering::Relaxed);
            }
        }
        
        // Wait for global rate limit
        self.global_limiter.wait_for_slot().await;
        
        // Apply current delay
        let delay = self.current_delay_ms.load(Ordering::Relaxed);
        if delay > 0 {
            sleep(Duration::from_millis(delay)).await;
        }
        
        // Acquire concurrent connection slot
        let permit = self.concurrent_semaphore.clone().acquire_owned().await
            .map_err(|_| ThrottleError::Shutdown)?;
        
        Ok(ThrottlePermit {
            _permit: permit,
            manager: self,
        })
    }
    
    /// Record a successful request
    pub fn record_success(&self) {
        // Reduce delay on success (exponential decay back to base)
        let current = self.current_delay_ms.load(Ordering::Relaxed);
        let new_delay = (current as f32 * 0.9).max(self.config.base_delay_ms as f32) as u64;
        self.current_delay_ms.store(new_delay, Ordering::Relaxed);
    }
    
    /// Record a failed request (triggers backoff)
    pub fn record_error(&self) {
        let now = Instant::now().elapsed().as_millis() as u64;
        self.last_error_time.store(now, Ordering::Relaxed);
        
        let errors = self.error_count.fetch_add(1, Ordering::Relaxed) + 1;
        
        // Exponential backoff
        let current = self.current_delay_ms.load(Ordering::Relaxed);
        let new_delay = (current as f32 * self.config.backoff_multiplier) as u64;
        self.current_delay_ms.store(
            new_delay.min(self.config.max_backoff_ms),
            Ordering::Relaxed,
        );
        
        // Enter cooldown after threshold
        if errors >= 10 {
            self.enter_cooldown();
        }
    }
    
    /// Enter cooldown period
    fn enter_cooldown(&self) {
        let now = Instant::now().elapsed().as_millis() as u64;
        self.is_cooldown.store(true, Ordering::Relaxed);
        self.cooldown_until.store(
            now + (self.config.cooldown_seconds * 1000),
            Ordering::Relaxed,
        );
        self.error_count.store(0, Ordering::Relaxed);
    }
    
    /// Get current error count
    pub fn error_count(&self) -> u32 {
        self.error_count.load(Ordering::Relaxed)
    }
    
    /// Get current delay
    pub fn current_delay_ms(&self) -> u64 {
        self.current_delay_ms.load(Ordering::Relaxed)
    }
    
    /// Check if in cooldown
    pub fn is_in_cooldown(&self) -> bool {
        self.is_cooldown.load(Ordering::Relaxed)
    }
    
    /// Get remaining cooldown time in ms
    pub fn cooldown_remaining_ms(&self) -> u64 {
        if !self.is_cooldown.load(Ordering::Relaxed) {
            return 0;
        }
        let now = Instant::now().elapsed().as_millis() as u64;
        let until = self.cooldown_until.load(Ordering::Relaxed);
        until.saturating_sub(now)
    }
    
    /// Reset throttle state
    pub fn reset(&self) {
        self.error_count.store(0, Ordering::Relaxed);
        self.current_delay_ms.store(self.config.base_delay_ms, Ordering::Relaxed);
        self.is_cooldown.store(false, Ordering::Relaxed);
    }
    
    /// Update configuration
    pub fn update_config(&mut self, config: ThrottleConfig) {
        self.config = config;
    }
}

/// Permit representing permission to make a request
pub struct ThrottlePermit<'a> {
    _permit: tokio::sync::OwnedSemaphorePermit,
    manager: &'a ThrottleManager,
}

impl<'a> Drop for ThrottlePermit<'a> {
    fn drop(&mut self) {
        // Could record completion here if needed
    }
}

/// Throttle errors
#[derive(Debug, thiserror::Error)]
pub enum ThrottleError {
    #[error("In cooldown for {0}ms")]
    InCooldown(u64),
    
    #[error("Throttle manager shutdown")]
    Shutdown,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Connection limit reached")]
    ConnectionLimitReached,
}

/// Statistics about throttle state
#[derive(Debug, Clone, Default)]
pub struct ThrottleStats {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub current_delay_ms: u64,
    pub in_cooldown: bool,
    pub cooldown_remaining_ms: u64,
    pub active_connections: usize,
}

impl ThrottleManager {
    /// Get current statistics
    pub fn get_stats(&self) -> ThrottleStats {
        ThrottleStats {
            current_delay_ms: self.current_delay_ms(),
            in_cooldown: self.is_in_cooldown(),
            cooldown_remaining_ms: self.cooldown_remaining_ms(),
            // Additional stats would require more tracking
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_throttle_config_presets() {
        let default = ThrottleConfig::default();
        let aggressive = ThrottleConfig::aggressive();
        let stealth = ThrottleConfig::stealth();
        
        assert!(aggressive.max_requests_per_second > default.max_requests_per_second);
        assert!(stealth.max_requests_per_second < default.max_requests_per_second);
    }
    
    #[tokio::test]
    async fn test_throttle_manager_creation() {
        let manager = ThrottleManager::new(ThrottleConfig::default());
        assert_eq!(manager.error_count(), 0);
        assert!(!manager.is_in_cooldown());
        assert_eq!(manager.current_delay_ms(), 10);
    }
    
    #[tokio::test]
    async fn test_error_backoff() {
        let manager = ThrottleManager::new(ThrottleConfig {
            base_delay_ms: 10,
            backoff_multiplier: 2.0,
            max_backoff_ms: 1000,
            ..Default::default()
        });
        
        let initial = manager.current_delay_ms();
        
        // Record some errors
        manager.record_error();
        manager.record_error();
        manager.record_error();
        
        let after_errors = manager.current_delay_ms();
        assert!(after_errors > initial);
    }
    
    #[tokio::test]
    async fn test_success_decay() {
        let manager = ThrottleManager::new(ThrottleConfig {
            base_delay_ms: 10,
            ..Default::default()
        });
        
        // Increase delay artificially
        manager.current_delay_ms.store(100, Ordering::Relaxed);
        
        // Record successes
        for _ in 0..10 {
            manager.record_success();
        }
        
        // Should decay back toward base
        let final_delay = manager.current_delay_ms();
        assert!(final_delay < 100);
    }
}
