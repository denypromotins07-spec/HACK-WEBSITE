//! HTTP Engine Module
//! 
//! Hyper-optimized HTTP client with protocol multiplexing (H1, H2, H3),
//! zero-copy parsing, WAF evasion, and concurrency control.

pub mod client;
pub mod config;
pub mod factory;
pub mod h1;
pub mod h2;
pub mod h3;
pub mod parser;
pub mod headers;
pub mod body;
pub mod waf;
pub mod mutation;
pub mod fingerprint;
pub mod throttle;
pub mod retry;
pub mod dispatch;

// Re-export main types for convenience
pub use client::HttpClient;
pub use config::NetworkConfig;
pub use factory::ClientFactory;
pub use h1::Http1Handler;
pub use h2::Http2Handler;
pub use h3::Http3Handler;
pub use parser::ResponseParser;
pub use headers::HeaderExtractor;
pub use body::BodyDecoder;
pub use waf::WafDetector;
pub use mutation::HeaderMutator;
pub use fingerprint::TlsFingerprinter;
pub use throttle::{TokenBucket, SwarmRateLimiter};
pub use retry::{RetryConfig, RetryPolicy, CircuitBreaker};
pub use dispatch::RequestDispatcher;
