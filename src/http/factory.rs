use crate::http::client::HttpClient;
use crate::http::config::NetworkConfig;
use crate::memory::pool::PooledBuffer;
use std::sync::Arc;

/// Factory for creating HTTP clients with bounded memory allocators.
/// Ensures every connection respects the global 2GB RAM ceiling.
pub struct ClientFactory {
    config: Arc<NetworkConfig>,
    buffer_pool: Arc<PooledBuffer>,
}

impl ClientFactory {
    pub fn new(config: Arc<NetworkConfig>, buffer_pool: Arc<PooledBuffer>) -> Self {
        Self {
            config,
            buffer_pool,
        }
    }

    /// Create a new HTTP client with injected memory allocator.
    pub fn create_client(&self) -> HttpClient {
        HttpClient::new(
            Arc::clone(&self.config),
            Arc::clone(&self.buffer_pool),
        )
    }

    /// Create multiple clients for the agent swarm.
    pub fn create_clients(&self, count: usize) -> Vec<HttpClient> {
        (0..count).map(|_| self.create_client()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_creation() {
        let config = Arc::new(NetworkConfig::default());
        let pool = Arc::new(PooledBuffer::new(1024));
        let factory = ClientFactory::new(config, pool);
        
        let _client = factory.create_client();
    }

    #[test]
    fn test_multiple_clients() {
        let config = Arc::new(NetworkConfig::default());
        let pool = Arc::new(PooledBuffer::new(1024));
        let factory = ClientFactory::new(config, pool);
        
        let clients = factory.create_clients(5);
        assert_eq!(clients.len(), 5);
    }
}
