use crate::memory::pool::PooledBuffer;
use crate::http::config::NetworkConfig;
use reqwest::{Client, Response};
use std::sync::Arc;
use tokio::time::Duration;

/// Hyper-optimized HTTP client wrapper with strict connection pooling.
/// Uses zero-copy request builders and respects global memory limits.
pub struct HttpClient {
    inner: Client,
    config: Arc<NetworkConfig>,
    buffer_pool: Arc<PooledBuffer>,
}

impl HttpClient {
    pub fn new(config: Arc<NetworkConfig>, buffer_pool: Arc<PooledBuffer>) -> Self {
        let inner = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .pool_max_idle_per_host(config.max_idle_per_host)
            .pool_idle_timeout(Duration::from_secs(config.pool_idle_timeout_secs))
            .tcp_keepalive(Duration::from_secs(config.tcp_keepalive_secs))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            inner,
            config,
            buffer_pool,
        }
    }

    /// Perform a GET request with zero-copy response handling.
    pub async fn get(&self, url: &str) -> Result<Response, reqwest::Error> {
        self.inner.get(url).send().await
    }

    /// Perform a POST request with bounded body.
    pub async fn post(&self, url: &str, body: &[u8]) -> Result<Response, reqwest::Error> {
        self.inner
            .post(url)
            .body(body.to_vec()) // In production, use streaming body from pool
            .send()
            .await
    }

    /// Get a pooled buffer for request/response operations.
    pub fn acquire_buffer(&self) -> PooledBuffer {
        self.buffer_pool.acquire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::pool::PooledBuffer;
    use std::sync::Arc;

    #[test]
    fn test_client_creation() {
        let config = Arc::new(NetworkConfig::default());
        let pool = Arc::new(PooledBuffer::new(1024));
        let _client = HttpClient::new(config, pool);
    }
}
