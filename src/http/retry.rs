use std::time::Duration;
use rand::Rng;

/// Advanced retry mechanism with exponential backoff, jitter, and circuit-breaker.
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub multiplier: f64,
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }
}

pub struct RetryPolicy {
    config: RetryConfig,
    attempt: u32,
}

impl RetryPolicy {
    pub fn new(config: RetryConfig) -> Self {
        Self { config, attempt: 0 }
    }

    /// Calculate delay with exponential backoff and jitter.
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.attempt >= self.config.max_retries {
            return None;
        }

        let delay_ms = (self.config.initial_delay_ms as f64
            * self.config.multiplier.powi(self.attempt as i32))
            .min(self.config.max_delay_ms as f64);

        // Add jitter
        let jitter = delay_ms * self.config.jitter_factor;
        let mut rng = rand::thread_rng();
        let jittered_delay = delay_ms + rng.gen_range(-jitter..jitter);

        self.attempt += 1;
        Some(Duration::from_millis(jittered_delay.max(0.0) as u64))
    }

    /// Reset the policy for a new operation.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Check if retries are exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.attempt >= self.config.max_retries
    }
}

/// Circuit breaker state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

pub struct CircuitBreaker {
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
    failures: u32,
    successes: u32,
    state: CircuitState,
    last_failure_time: Option<std::time::Instant>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, success_threshold: u32, timeout: Duration) -> Self {
        Self {
            failure_threshold,
            success_threshold,
            timeout,
            failures: 0,
            successes: 0,
            state: CircuitState::Closed,
            last_failure_time: None,
        }
    }

    /// Check if request should be allowed.
    pub fn allow_request(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout has elapsed
                if let Some(last_failure) = self.last_failure_time {
                    if last_failure.elapsed() >= self.timeout {
                        self.state = CircuitState::HalfOpen;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request.
    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::HalfOpen => {
                self.successes += 1;
                if self.successes >= self.success_threshold {
                    self.reset();
                }
            }
            CircuitState::Closed => {
                self.failures = 0; // Reset on success
            }
            _ => {}
        }
    }

    /// Record a failed request.
    pub fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure_time = Some(std::time::Instant::now());

        match self.state {
            CircuitState::Closed => {
                if self.failures >= self.failure_threshold {
                    self.state = CircuitState::Open;
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open immediately opens circuit
                self.state = CircuitState::Open;
            }
            _ => {}
        }
    }

    /// Reset the circuit breaker to closed state.
    pub fn reset(&mut self) {
        self.failures = 0;
        self.successes = 0;
        self.state = CircuitState::Closed;
        self.last_failure_time = None;
    }

    /// Get current state.
    pub fn state(&self) -> CircuitState {
        self.state
    }
}

/// Combined retry strategy with circuit breaker.
pub struct RetryWithCircuitBreaker {
    retry_policy: RetryPolicy,
    circuit_breaker: CircuitBreaker,
}

impl RetryWithCircuitBreaker {
    pub fn new(retry_config: RetryConfig, circuit_breaker: CircuitBreaker) -> Self {
        Self {
            retry_policy: RetryPolicy::new(retry_config),
            circuit_breaker,
        }
    }

    /// Execute an async operation with retry and circuit breaker.
    pub async fn execute<F, T, E>(&mut self, operation: F) -> Result<T, E>
    where
        F: Fn() -> tokio::sync::oneshot::Receiver<Result<T, E>>,
        E: std::error::Error,
    {
        loop {
            if !self.circuit_breaker.allow_request() {
                return Err(RetryError::CircuitOpen.into());
            }

            let receiver = operation();
            match receiver.await {
                Ok(result) => {
                    self.circuit_breaker.record_success();
                    self.retry_policy.reset();
                    return result;
                }
                Err(_) => {
                    self.circuit_breaker.record_failure();
                    
                    if let Some(delay) = self.retry_policy.next_delay() {
                        tokio::time::sleep(delay).await;
                    } else {
                        return Err(RetryError::MaxRetriesExceeded.into());
                    }
                }
            }
        }
    }

    /// Get circuit breaker state.
    pub fn circuit_state(&self) -> CircuitState {
        self.circuit_breaker.state()
    }
}

#[derive(Debug)]
pub enum RetryError {
    CircuitOpen,
    MaxRetriesExceeded,
}

impl std::fmt::Display for RetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetryError::CircuitOpen => write!(f, "Circuit breaker is open"),
            RetryError::MaxRetriesExceeded => write!(f, "Maximum retries exceeded"),
        }
    }
}

impl std::error::Error for RetryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_policy_backoff() {
        let config = RetryConfig {
            max_retries: 4,
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            multiplier: 2.0,
            jitter_factor: 0.0, // No jitter for predictable testing
        };
        
        let mut policy = RetryPolicy::new(config);
        
        let d1 = policy.next_delay().unwrap();
        let d2 = policy.next_delay().unwrap();
        let d3 = policy.next_delay().unwrap();
        
        assert!(d1.as_millis() >= 100);
        assert!(d2.as_millis() >= 200);
        assert!(d3.as_millis() >= 400);
        assert!(policy.next_delay().is_none()); // Exhausted
    }

    #[test]
    fn test_circuit_breaker() {
        let mut cb = CircuitBreaker::new(3, 2, Duration::from_millis(100));
        
        // Should start closed
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
        
        // Record failures to trip circuit
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }
}
