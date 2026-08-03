use std::time::Duration;

/// Global network configuration with strict timeouts and bounds.
/// All values are tuned for the 100-agent swarm under 2GB RAM limit.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Global request timeout in milliseconds
    pub timeout_ms: u64,
    /// Connection establishment timeout in milliseconds
    pub connect_timeout_ms: u64,
    /// Maximum idle connections per host in the pool
    pub max_idle_per_host: usize,
    /// Idle connection timeout in seconds
    pub pool_idle_timeout_secs: u64,
    /// TCP keepalive interval in seconds
    pub tcp_keepalive_secs: u64,
    /// DNS cache TTL in seconds
    pub dns_cache_ttl_secs: u64,
    /// Maximum concurrent streams per HTTP/2 connection
    pub h2_max_concurrent_streams: u32,
    /// Initial stream window size for HTTP/2 flow control
    pub h2_initial_window_size: u32,
    /// Initial connection window size for HTTP/2 flow control
    pub h2_initial_connection_window_size: u32,
    /// QUIC idle timeout in seconds
    pub quic_idle_timeout_secs: u64,
    /// QUIC maximum concurrent bidirectional streams
    pub quic_max_concurrent_bidi_streams: u32,
    /// Enable proxy rotation
    pub proxy_rotation_enabled: bool,
    /// Proxy list for rotation (comma-separated URLs)
    pub proxy_list: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000, // 30 second global timeout
            connect_timeout_ms: 5_000, // 5 second connection timeout
            max_idle_per_host: 8, // Bounded pool size
            pool_idle_timeout_secs: 90,
            tcp_keepalive_secs: 60,
            dns_cache_ttl_secs: 300, // 5 minute DNS cache
            h2_max_concurrent_streams: 100,
            h2_initial_window_size: 1024 * 1024, // 1MB
            h2_initial_connection_window_size: 10 * 1024 * 1024, // 10MB
            quic_idle_timeout_secs: 30,
            quic_max_concurrent_bidi_streams: 100,
            proxy_rotation_enabled: false,
            proxy_list: Vec::new(),
        }
    }
}

impl NetworkConfig {
    /// Create a new config with custom timeout values.
    pub fn with_timeouts(timeout_ms: u64, connect_timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            connect_timeout_ms,
            ..Default::default()
        }
    }

    /// Get the global scan timeout (10 minutes as per spec).
    pub fn global_scan_timeout() -> Duration {
        Duration::from_secs(600) // 10 minutes
    }
}
