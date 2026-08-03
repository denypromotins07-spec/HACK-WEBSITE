use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Lock-free distributed token bucket rate limiter.
/// Prevents IP bans during the 100-agent swarm assault.
pub struct TokenBucket {
    capacity: u64,
    tokens: AtomicU64,
    refill_rate: u64, // tokens per second
    last_refill: AtomicU64, // timestamp in milliseconds
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_rate: u64) -> Self {
        let now = Instant::now();
        Self {
            capacity,
            tokens: AtomicU64::new(capacity),
            refill_rate,
            last_refill: AtomicU64::new(now.elapsed().as_millis() as u64),
        }
    }

    /// Try to consume a token without blocking.
    pub fn try_consume(&self) -> bool {
        self.refill();
        
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }
            
            if self
                .tokens
                .compare_exchange_weak(current, current - 1, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Consume multiple tokens atomically.
    pub fn try_consume_n(&self, count: u64) -> bool {
        self.refill();
        
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current < count {
                return false;
            }
            
            if self
                .tokens
                .compare_exchange_weak(current, current - count, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&self) {
        let now = Instant::now();
        let now_ms = now.elapsed().as_millis() as u64;
        let last = self.last_refill.load(Ordering::Relaxed);
        let elapsed_ms = now_ms.saturating_sub(last);

        if elapsed_ms >= 1000 / self.refill_rate.max(1) {
            let tokens_to_add = (elapsed_ms * self.ref_rate) / 1000;
            
            if tokens_to_add > 0 {
                let current = self.tokens.load(Ordering::Relaxed);
                let new_tokens = (current + tokens_to_add).min(self.capacity);
                
                self.tokens.store(new_tokens, Ordering::Relaxed);
                self.last_refill.store(now_ms, Ordering::Relaxed);
            }
        }
    }

    /// Get current token count.
    pub fn available(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed)
    }
}

/// Distributed rate limiter for the swarm.
pub struct SwarmRateLimiter {
    buckets: Vec<TokenBucket>,
    strategy: DistributionStrategy,
}

#[derive(Debug, Clone)]
pub enum DistributionStrategy {
    RoundRobin,
    LeastLoaded,
    HashBased(u64),
}

impl SwarmRateLimiter {
    pub fn new(agent_count: usize, total_capacity: u64, refill_rate: u64) -> Self {
        let per_agent_capacity = total_capacity / agent_count as u64;
        let per_agent_rate = refill_rate / agent_count as u64;

        let buckets: Vec<TokenBucket> = (0..agent_count)
            .map(|_| TokenBucket::new(per_agent_capacity, per_agent_rate.max(1)))
            .collect();

        Self {
            buckets,
            strategy: DistributionStrategy::RoundRobin,
        }
    }

    /// Try to acquire a token from the distributed pool.
    pub fn try_acquire(&self, agent_id: usize) -> bool {
        match self.strategy {
            DistributionStrategy::RoundRobin => {
                let idx = agent_id % self.buckets.len();
                self.buckets[idx].try_consume()
            }
            DistributionStrategy::LeastLoaded => {
                // Find bucket with most tokens
                let mut best_idx = 0;
                let mut max_tokens = 0;
                
                for (i, bucket) in self.buckets.iter().enumerate() {
                    let tokens = bucket.available();
                    if tokens > max_tokens {
                        max_tokens = tokens;
                        best_idx = i;
                    }
                }
                
                self.buckets[best_idx].try_consume()
            }
            DistributionStrategy::HashBased(seed) => {
                let idx = ((agent_id as u64).wrapping_mul(seed) % self.buckets.len() as u64) as usize;
                self.buckets[idx].try_consume()
            }
        }
    }

    /// Get total available tokens across all buckets.
    pub fn total_available(&self) -> u64 {
        self.buckets.iter().map(|b| b.available()).sum()
    }
}

/// Sliding window rate limiter for more accurate limiting.
pub struct SlidingWindowLimiter {
    window_size: Duration,
    max_requests: u64,
    timestamps: std::sync::Mutex<Vec<u64>>,
}

impl SlidingWindowLimiter {
    pub fn new(window_size: Duration, max_requests: u64) -> Self {
        Self {
            window_size,
            max_requests,
            timestamps: std::sync::Mutex::new(Vec::with_capacity(max_requests as usize)),
        }
    }

    pub fn try_acquire(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut timestamps = self.timestamps.lock().unwrap();
        let window_start = now.saturating_sub(self.window_size.as_millis() as u64);

        // Remove expired timestamps
        timestamps.retain(|&ts| ts > window_start);

        if timestamps.len() < self.max_requests as usize {
            timestamps.push(now);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_basic() {
        let bucket = TokenBucket::new(10, 5); // 10 capacity, 5/sec refill
        
        // Should be able to consume up to capacity
        for _ in 0..10 {
            assert!(bucket.try_consume());
        }
        
        // Should be empty now
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_swarm_limiter() {
        let limiter = SwarmRateLimiter::new(10, 100, 50);
        
        // Each agent should be able to acquire tokens
        for i in 0..10 {
            assert!(limiter.try_acquire(i));
        }
    }

    #[test]
    fn test_sliding_window() {
        let limiter = SlidingWindowLimiter::new(Duration::from_secs(1), 5);
        
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        
        // Should be limited now
        assert!(!limiter.try_acquire());
    }
}
