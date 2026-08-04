//! Proxy Collapse Detection via HTTP Upgrade
//! Detects reverse proxy collapse by forcing raw TCP pass-through.
//! Uses zero-copy byte buffers and bounded protocol frames (Stage 1 memory constraints).

use crate::checks::Check;
use crate::http::{Request, Response};
use crate::learning::Cache;
use crate::findings::Finding;
use std::time::Duration;
use std::collections::HashMap;

/// Bounded upgrade protocols to test (max 8)
const UPGRADE_PROTOCOLS: [&str; 4] = [
    "websocket",
    "HTTP/2.0",
    "SPDY/3.1",
    "tcp-tunnel"
];

pub struct ProxyCollapseCheck {
    timeout: Duration,
    god_mode: bool,
}

impl ProxyCollapseCheck {
    pub fn new(timeout_ms: u64, god_mode: bool) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            god_mode,
        }
    }

    /// Detect proxy collapse vulnerability
    pub fn detect_collapse(&self, request: &Request, response: &Response) -> Option<Finding> {
        // Check if Upgrade header causes unexpected behavior
        if let Some(upgrade) = request.headers.get("Upgrade") {
            // If server accepts upgrade but behaves unexpectedly
            if response.status == 101 || response.status == 200 {
                // Check for signs of proxy bypass or raw TCP exposure
                if self.god_mode {
                    return Some(Finding::new(
                        "Proxy Collapse via HTTP Upgrade",
                        "CRITICAL",
                        &format!("Upgrade header '{}' may cause proxy to switch to raw TCP mode", upgrade),
                        "Validate Upgrade headers strictly and prevent unauthorized protocol switching",
                        Some(self.generate_payload(upgrade)),
                    ));
                }
            }
        }
        None
    }

    /// Generate malicious Upgrade payload for testing
    pub fn generate_payload(&self, protocol: &str) -> String {
        if self.god_mode {
            // Aggressive header combination for raw TCP pass-through
            format!(
                "Upgrade: {}\\r\\nConnection: Upgrade\\r\\nX-Forwarded-Proto: ws\\r\\nForwarded: for=127.0.0.1",
                protocol
            )
        } else {
            format!("Upgrade: {}", protocol)
        }
    }

    /// Build test requests with Upgrade headers
    pub fn build_test_requests(&self, target: &str) -> Vec<Request> {
        let mut requests = Vec::with_capacity(UPGRADE_PROTOCOLS.len());
        
        for protocol in UPGRADE_PROTOCOLS.iter() {
            let mut headers = HashMap::new();
            headers.insert("Upgrade".to_string(), protocol.to_string());
            headers.insert("Connection".to_string(), "Upgrade".to_string());
            
            requests.push(Request {
                method: "GET".to_string(),
                uri: target.to_string(),
                headers,
                body: vec![],
            });
        }
        
        requests
    }

    /// Test deep binary frame inspection (god-mode only)
    pub fn inspect_binary_frames(&self, data: &[u8]) -> Option<String> {
        if !self.god_mode {
            return None;
        }

        // Zero-copy inspection of first bytes for protocol signatures
        if data.len() >= 4 {
            // WebSocket handshake signature
            if data.starts_with(b"HTTP") {
                return Some("HTTP/WS handshake detected".to_string());
            }
            // HTTP/2 connection preface
            if data.starts_with(b"PRI ") {
                return Some("HTTP/2 preface detected".to_string());
            }
        }
        
        None
    }
}

impl Check for ProxyCollapseCheck {
    fn name(&self) -> &'static str {
        "proxy_collapse"
    }

    fn run(&self, target: &str, cache: &mut dyn Cache) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(2);
        
        for request in self.build_test_requests(target) {
            // Mock response - actual implementation uses Stage 2 HTTP engine
            let mock_response = Response {
                status: 101, // Switching Protocols
                headers: HashMap::new(),
                body: vec![],
            };

            if let Some(finding) = self.detect_collapse(&request, &mock_response) {
                findings.push(finding);
                // Cache successful proxy collapse vector
                if let Some(upgrade) = request.headers.get("Upgrade") {
                    cache.store(&format!("collapse_{}", upgrade), target);
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_collapse_detection() {
        let check = ProxyCollapseCheck::new(5000, true);
        assert_eq!(check.name(), "proxy_collapse");
        assert!(check.generate_payload("websocket").contains("Connection"));
    }

    #[test]
    fn test_binary_frame_inspection() {
        let check = ProxyCollapseCheck::new(5000, true);
        let http_data = b"HTTP/1.1 101 Switching Protocols";
        assert!(check.inspect_binary_frames(http_data).is_some());
    }
}
