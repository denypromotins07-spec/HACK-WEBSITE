//! API surface detection for REST, GraphQL, WebSocket, SSE, and JSONP endpoints.
//!
//! This module identifies specialized API protocols for targeted exploitation.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// API protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiProtocol {
    Rest,
    Graphql,
    WebSocket,
    ServerSentEvents,
    Jsonp,
    Soap,
    Grpc,
    Rpc,
    Unknown,
}

/// Discovered API endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    /// Endpoint URL
    pub url: String,
    /// Protocol type
    pub protocol: ApiProtocol,
    /// API version if detected
    pub version: Option<String>,
    /// Supported operations/methods
    pub operations: Vec<String>,
    /// Authentication requirements
    pub auth_type: Option<AuthType>,
    /// Request/response examples
    pub examples: Vec<String>,
    /// Schema/SDL if available
    pub schema: Option<String>,
    /// Rate limiting info
    pub rate_limit: Option<RateLimitInfo>,
}

impl ApiEndpoint {
    pub fn new(url: String, protocol: ApiProtocol) -> Self {
        Self {
            url,
            protocol,
            version: None,
            operations: Vec::new(),
            auth_type: None,
            examples: Vec::new(),
            schema: None,
            rate_limit: None,
        }
    }
}

/// Authentication type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthType {
    None,
    Basic,
    Bearer,
    ApiKey,
    Jwt,
    OAuth2,
    Session,
    Custom(String),
}

/// Rate limit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub requests_per_minute: Option<u32>,
    pub requests_per_hour: Option<u32>,
    pub headers_present: Vec<String>,
}

/// GraphQL-specific data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphqlSchema {
    pub queries: Vec<String>,
    pub mutations: Vec<String>,
    pub subscriptions: Vec<String>,
    pub types: Vec<String>,
    pub introspection_enabled: bool,
}

/// WebSocket message pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessagePattern {
    pub direction: MessageDirection,
    pub content_type: String,
    pub sample_payload: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MessageDirection {
    ClientToServer,
    ServerToClient,
    Bidirectional,
}

/// API Surface detector
pub struct ApiSurfaceDetector {
    endpoints: HashMap<String, ApiEndpoint>,
    graphql_schemas: HashMap<String, GraphqlSchema>,
}

impl ApiSurfaceDetector {
    pub fn new() -> Self {
        Self {
            endpoints: HashMap::new(),
            graphql_schemas: HashMap::new(),
        }
    }

    /// Detect API type from URL and response
    pub fn detect_api_type(url: &str, content_type: Option<&str>, body: &str) -> ApiProtocol {
        // Check URL patterns
        if url.contains("/graphql") || url.contains("graphql") {
            return ApiProtocol::Graphql;
        }
        if url.starts_with("ws://") || url.starts_with("wss://") {
            return ApiProtocol::WebSocket;
        }
        if url.contains("/sse") || url.contains("event-stream") {
            return ApiProtocol::ServerSentEvents;
        }
        if url.contains("callback=") || url.contains("jsonp=") {
            return ApiProtocol::Jsonp;
        }

        // Check content-type
        if let Some(ct) = content_type {
            if ct.contains("application/graphql") {
                return ApiProtocol::Graphql;
            }
            if ct.contains("text/event-stream") {
                return ApiProtocol::ServerSentEvents;
            }
        }

        // Check body content
        if body.contains("\"query\"") && (body.contains("\"mutation\"") || body.contains('{')) {
            return ApiProtocol::Graphql;
        }
        if body.contains("__doRequest") || body.contains("callback(") {
            return ApiProtocol::Jsonp;
        }

        // Default to REST for JSON APIs
        if body.starts_with('{') || body.starts_with('[') {
            return ApiProtocol::Rest;
        }

        ApiProtocol::Unknown
    }

    /// Add discovered endpoint
    pub fn add_endpoint(&mut self, endpoint: ApiEndpoint) {
        self.endpoints.insert(endpoint.url.clone(), endpoint);
    }

    /// Record GraphQL schema
    pub fn record_graphql_schema(&mut self, url: &str, schema: GraphqlSchema) {
        self.graphql_schemas.insert(url.to_string(), schema);
    }

    /// Get all endpoints
    pub fn all_endpoints(&self) -> Vec<&ApiEndpoint> {
        self.endpoints.values().collect()
    }

    /// Get GraphQL endpoints
    pub fn graphql_endpoints(&self) -> Vec<&ApiEndpoint> {
        self.endpoints.values()
            .filter(|e| e.protocol == ApiProtocol::Graphql)
            .collect()
    }

    /// Get WebSocket endpoints
    pub fn websocket_endpoints(&self) -> Vec<&ApiEndpoint> {
        self.endpoints.values()
            .filter(|e| e.protocol == ApiProtocol::WebSocket)
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> ApiStats {
        ApiStats {
            total_endpoints: self.endpoints.len(),
            rest_count: self.endpoints.values().filter(|e| e.protocol == ApiProtocol::Rest).count(),
            graphql_count: self.endpoints.values().filter(|e| e.protocol == ApiProtocol::Graphql).count(),
            websocket_count: self.endpoints.values().filter(|e| e.protocol == ApiProtocol::WebSocket).count(),
            sse_count: self.endpoints.values().filter(|e| e.protocol == ApiProtocol::ServerSentEvents).count(),
            jsonp_count: self.endpoints.values().filter(|e| e.protocol == ApiProtocol::Jsonp).count(),
            graphql_schemas: self.graphql_schemas.len(),
        }
    }
}

impl Default for ApiSurfaceDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// API statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiStats {
    pub total_endpoints: usize,
    pub rest_count: usize,
    pub graphql_count: usize,
    pub websocket_count: usize,
    pub sse_count: usize,
    pub jsonp_count: usize,
    pub graphql_schemas: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_graphql() {
        let body = r#"{"query": "{ user { id name } }"}"#;
        assert_eq!(ApiSurfaceDetector::detect_api_type("/graphql", None, body), ApiProtocol::Graphql);
    }

    #[test]
    fn test_detect_websocket() {
        assert_eq!(ApiSurfaceDetector::detect_api_type("wss://example.com/ws", None, ""), ApiProtocol::WebSocket);
    }

    #[test]
    fn test_api_stats() {
        let mut detector = ApiSurfaceDetector::new();
        detector.add_endpoint(ApiEndpoint::new("http://api.example.com/users".to_string(), ApiProtocol::Rest));
        detector.add_endpoint(ApiEndpoint::new("ws://example.com/ws".to_string(), ApiProtocol::WebSocket));
        
        let stats = detector.stats();
        assert_eq!(stats.total_endpoints, 2);
        assert_eq!(stats.rest_count, 1);
        assert_eq!(stats.websocket_count, 1);
    }
}
