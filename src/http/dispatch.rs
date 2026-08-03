use crate::http::client::HttpClient;
use crate::http::config::NetworkConfig;
use crate::http::throttle::{SwarmRateLimiter, TokenBucket};
use crate::http::retry::{RetryConfig, RetryPolicy, CircuitBreaker};
use crate::http::mutation::HeaderMutator;
use crate::http::waf::WafDetector;
use std::sync::Arc;
use std::time::Duration;

/// Unified high-throughput request dispatch loop.
/// Wires together throttling, retry, and mutation engines.
pub struct RequestDispatcher {
    client: HttpClient,
    rate_limiter: SwarmRateLimiter,
    retry_config: RetryConfig,
    header_mutator: HeaderMutator,
    waf_detector: WafDetector,
    config: Arc<NetworkConfig>,
}

impl RequestDispatcher {
    pub fn new(
        client: HttpClient,
        rate_limiter: SwarmRateLimiter,
        retry_config: RetryConfig,
        config: Arc<NetworkConfig>,
    ) -> Self {
        Self {
            client,
            rate_limiter,
            retry_config,
            header_mutator: HeaderMutator::new(),
            waf_detector: WafDetector::new(),
            config,
        }
    }

    /// Dispatch a single request with full pipeline (throttle, mutate, retry).
    pub async fn dispatch(&mut self, url: &str, agent_id: usize) -> DispatchResult {
        // Step 1: Check rate limit
        if !self.rate_limiter.try_acquire(agent_id) {
            return DispatchResult::RateLimited;
        }

        // Step 2: Build request with mutated headers
        let mut headers = vec![
            ("Host".to_string(), extract_host(url).unwrap_or_default()),
            ("User-Agent".to_string(), self.select_user_agent()),
        ];
        let mutated_headers = self.header_mutator.generate_evasive_headers(&headers);

        // Step 3: Execute with retry policy
        let mut retry_policy = RetryPolicy::new(self.retry_config.clone());
        let mut circuit_breaker = CircuitBreaker::new(5, 2, Duration::from_secs(30));

        loop {
            if !circuit_breaker.allow_request() {
                return DispatchResult::CircuitOpen;
            }

            match self.execute_request(url, &mutated_headers).await {
                Ok(response) => {
                    circuit_breaker.record_success();
                    
                    // Check for WAF
                    let waf_results = self.waf_detector.detect(
                        &response.headers,
                        response.status,
                        &response.body,
                    );
                    
                    return DispatchResult::Success {
                        status: response.status,
                        headers: response.headers,
                        body: response.body,
                        waf_detected: !waf_results.is_empty(),
                        waf_vendors: waf_results.iter().map(|r| r.vendor).collect(),
                    };
                }
                Err(e) => {
                    circuit_breaker.record_failure();
                    
                    if let Some(delay) = retry_policy.next_delay() {
                        tokio::time::sleep(delay).await;
                    } else {
                        return DispatchResult::Failed(e);
                    }
                }
            }
        }
    }

    /// Execute the actual HTTP request.
    async fn execute_request(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<RawResponse, DispatchError> {
        match self.client.get(url).await {
            Ok(response) => {
                let status = response.status().as_u16();
                
                // Extract headers zero-copy where possible
                let mut parsed_headers = Vec::new();
                for (name, value) in headers {
                    parsed_headers.push(httparse::Header {
                        name,
                        value: value.as_bytes(),
                    });
                }

                // Get body bytes
                let body = response.bytes().await.unwrap_or_default();

                Ok(RawResponse {
                    status,
                    headers: parsed_headers,
                    body: body.to_vec(),
                })
            }
            Err(e) => Err(DispatchError::HttpError(e.to_string())),
        }
    }

    /// Select a random user agent from the pool.
    fn select_user_agent(&mut self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let agents = crate::http::mutation::user_agents::ALL;
        agents[rng.gen_range(0..agents.len())].to_string()
    }

    /// Dispatch multiple requests concurrently across agents.
    pub async fn dispatch_batch(
        &mut self,
        urls: &[String],
        agent_id: usize,
    ) -> Vec<DispatchResult> {
        let mut results = Vec::with_capacity(urls.len());
        
        for url in urls {
            let result = self.dispatch(url, agent_id).await;
            results.push(result);
        }
        
        results
    }
}

#[derive(Debug)]
pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<httparse::Header<'static>>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum DispatchResult {
    Success {
        status: u16,
        headers: Vec<httparse::Header<'static>>,
        body: Vec<u8>,
        waf_detected: bool,
        waf_vendors: Vec<crate::http::waf::WafVendor>,
    },
    RateLimited,
    CircuitOpen,
    Failed(DispatchError),
}

#[derive(Debug)]
pub enum DispatchError {
    HttpError(String),
    Timeout,
    InvalidUrl,
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::HttpError(msg) => write!(f, "HTTP error: {}", msg),
            DispatchError::Timeout => write!(f, "Request timeout"),
            DispatchError::InvalidUrl => write!(f, "Invalid URL"),
        }
    }
}

impl std::error::Error for DispatchError {}

/// Helper to extract host from URL.
fn extract_host(url: &str) -> Option<String> {
    url.split("://").nth(1)
        .and_then(|s| s.split('/').next())
        .map(|s| s.split(':').next().unwrap_or(s).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::pool::PooledBuffer;

    #[test]
    fn test_extract_host() {
        assert_eq!(extract_host("https://example.com/path"), Some("example.com".to_string()));
        assert_eq!(extract_host("http://test.org:8080/api"), Some("test.org".to_string()));
        assert_eq!(extract_host("invalid"), None);
    }

    #[test]
    fn test_dispatcher_creation() {
        let config = Arc::new(NetworkConfig::default());
        let pool = Arc::new(PooledBuffer::new(1024));
        let client = HttpClient::new(Arc::clone(&config), Arc::clone(&pool));
        let limiter = SwarmRateLimiter::new(100, 1000, 100);
        
        let _dispatcher = RequestDispatcher::new(
            client,
            limiter,
            RetryConfig::default(),
            config,
        );
    }
}
