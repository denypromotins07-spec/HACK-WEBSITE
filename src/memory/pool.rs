//! Object pooling mechanism for HTTP clients and byte buffers.
//! Prevents heap fragmentation during scan windows by reusing allocations.

use std::collections::VecDeque;
use std::sync::Arc;
use parking_lot::{Mutex, MutexGuard};
use bytes::BytesMut;

/// Maximum pool size to prevent unbounded growth
const MAX_POOL_SIZE: usize = 1024;

/// Default buffer capacity (64KB)
const DEFAULT_BUFFER_CAPACITY: usize = 64 * 1024;

/// Pooled byte buffer for zero-copy operations
pub struct PooledBuffer {
    data: BytesMut,
    pool: Arc<BufferPool>,
}

impl PooledBuffer {
    fn new(pool: Arc<BufferPool>) -> Self {
        let data = BytesMut::with_capacity(DEFAULT_BUFFER_CAPACITY);
        PooledBuffer { data, pool }
    }

    /// Get mutable reference to underlying buffer
    pub fn as_mut(&mut self) -> &mut BytesMut {
        &mut self.data
    }

    /// Get immutable reference to underlying buffer
    pub fn as_ref(&self) -> &BytesMut {
        &self.data
    }

    /// Clear buffer for reuse without deallocation
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Resize buffer if needed, prefers staying within capacity
    pub fn resize(&mut self, len: usize) {
        self.data.resize(len, 0);
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Return to pool instead of deallocating
        self.data.clear();
        self.pool.return_buffer(std::mem::replace(
            &mut self.data,
            BytesMut::with_capacity(DEFAULT_BUFFER_CAPACITY),
        ));
    }
}

/// Thread-safe buffer pool
pub struct BufferPool {
    pool: Mutex<VecDeque<BytesMut>>,
    allocated_count: std::sync::atomic::AtomicUsize,
}

impl BufferPool {
    pub fn new() -> Self {
        let mut pool = VecDeque::with_capacity(MAX_POOL_SIZE);
        // Pre-warm pool with buffers
        for _ in 0..MAX_POOL_SIZE / 2 {
            pool.push_back(BytesMut::with_capacity(DEFAULT_BUFFER_CAPACITY));
        }
        BufferPool {
            pool: Mutex::new(pool),
            allocated_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Acquire a buffer from the pool or allocate new if empty
    pub fn acquire(self: &Arc<Self>) -> PooledBuffer {
        let mut guard = self.pool.lock();
        if let Some(buffer) = guard.pop_front() {
            PooledBuffer {
                data: buffer,
                pool: Arc::clone(self),
            }
        } else {
            self.allocated_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            PooledBuffer::new(Arc::clone(self))
        }
    }

    fn return_buffer(&self, buffer: BytesMut) {
        let mut guard = self.pool.lock();
        if guard.len() < MAX_POOL_SIZE {
            guard.push_back(buffer);
        }
        // If pool is full, buffer is dropped (deallocated)
    }

    /// Get current pool statistics
    pub fn stats(&self) -> PoolStats {
        let guard = self.pool.lock();
        PoolStats {
            pooled_count: guard.len(),
            allocated_count: self.allocated_count.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PoolStats {
    pub pooled_count: usize,
    pub allocated_count: usize,
}

/// HTTP Client wrapper with connection pooling
pub struct HttpClientPool {
    // In production, this would wrap reqwest::Client with custom connection limits
    client: reqwest::Client,
    max_concurrent: usize,
    active_count: std::sync::atomic::AtomicUsize,
}

impl HttpClientPool {
    pub fn new(max_concurrent: usize) -> Self {
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(max_concurrent)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        HttpClientPool {
            client,
            max_concurrent,
            active_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Acquire permission to make a request (circuit breaker pattern)
    pub fn try_acquire(&self) -> bool {
        let current = self.active_count.load(std::sync::atomic::Ordering::Relaxed);
        if current >= self.max_concurrent {
            return false;
        }
        self.active_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }

    /// Release request slot
    pub fn release(&self) {
        self.active_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get the underlying client
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Get active request count
    pub fn active_count(&self) -> usize {
        self.active_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool() {
        let pool = Arc::new(BufferPool::new());
        let buf = pool.acquire();
        assert_eq!(buf.as_ref().capacity(), DEFAULT_BUFFER_CAPACITY);
    }

    #[test]
    fn test_buffer_return() {
        let pool = Arc::new(BufferPool::new());
        {
            let _buf = pool.acquire();
        }
        // Buffer should be returned to pool
        let stats = pool.stats();
        assert!(stats.pooled_count > 0);
    }
}
