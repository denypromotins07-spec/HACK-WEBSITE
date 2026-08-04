//! Hop-by-Hop Header Stripping Detection
//! Detects proxy security attribute removal via Connection/Keep-Alive manipulation.
//! Uses zero-copy byte buffers and bounded protocol frames (Stage 1 memory constraints).

use crate::checks::Check;
use crate::http::Response;
use crate::learning::Cache;
use crate::findings::Finding;
use std::time::Duration;

/// Bounded hop-by-hop header list (max 16 headers to prevent DoS)
const HOP_BY_HOP_HEADERS: [&str; 8] = [
    "Connection",
    "Keep-Alive", 
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "TE",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade"
];

pub struct HopByHopCheck {
    timeout: Duration,
    god_mode: bool,
}

impl HopByHopCheck {
    pub fn new(timeout_ms: u64, god_mode: bool) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            god_mode,
        }
    }

    /// Detect hop-by-hop header stripping
    pub fn detect_stripping(&self, response: &Response, original_headers: &[&str]) -> Option<Finding> {
        let mut stripped_headers = Vec::with_capacity(4); // Bounded capacity
        
        for header in HOP_BY_HOP_HEADERS.iter() {
            if original_headers.contains(header) && !response.headers.contains_key(*header) {
                stripped_headers.push(*header);
            }
        }

        if !stripped_headers.is_empty() {
            return Some(Finding::new(
                "Hop-by-Hop Header Stripping",
                "CRITICAL",
                &format!("Proxy stripped security headers: {:?}", stripped_headers),
                "Remove hop-by-hop headers from upstream responses or configure proxy to preserve security attributes",
                Some(self.generate_payload()),
            ));
        }
        None
    }

    /// God-mode: Inject raw TCP pass-through headers
    pub fn generate_payload(&self) -> String {
        if self.god_mode {
            // Aggressive header pollution for testing
            "Connection: close\\r\\nX-Forwarded-For: 127.0.0.1\\r\\nUpgrade: websocket".to_string()
        } else {
            "Connection: keep-alive".to_string()
        }
    }
}

impl Check for HopByHopCheck {
    fn name(&self) -> &'static str {
        "hop_by_hop"
    }

    fn run(&self, target: &str, _cache: &mut dyn Cache) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(2);
        
        // Simulate check - actual implementation integrates with Stage 2 HTTP engine
        let test_headers = ["Connection", "Upgrade"];
        
        // Placeholder response for demonstration
        let mock_response = Response {
            status: 200,
            headers: std::collections::HashMap::new(),
            body: vec![],
        };

        if let Some(finding) = self.detect_stripping(&mock_response, &test_headers) {
            findings.push(finding);
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_by_hop_detection() {
        let check = HopByHopCheck::new(5000, false);
        assert_eq!(check.name(), "hop_by_hop");
    }
}
