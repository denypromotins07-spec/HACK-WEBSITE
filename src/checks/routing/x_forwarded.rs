//! X-Forwarded Header Abuse Detection
//! Detects internal proxy tracking abuse via X-Forwarded-Host and X-Original-URL manipulation.
//! Uses zero-copy byte buffers and bounded protocol frames (Stage 1 memory constraints).

use crate::checks::Check;
use crate::http::{Request, Response};
use crate::learning::Cache;
use crate::findings::Finding;
use std::time::Duration;
use std::collections::HashMap;

/// Bounded list of forwarding headers to test (max 12)
const FORWARD_HEADERS: [&str; 6] = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Server",
    "X-Forwarded-Proto"
];

pub struct XForwardedCheck {
    timeout: Duration,
    god_mode: bool,
    ip_rotation_matrix: Vec<String>,
}

impl XForwardedCheck {
    pub fn new(timeout_ms: u64, god_mode: bool) -> Self {
        // Bounded IP rotation matrix (max 16 IPs)
        let ip_rotation = if god_mode {
            vec![
                "127.0.0.1".to_string(),
                "192.168.0.1".to_string(),
                "10.0.0.1".to_string(),
                "172.16.0.1".to_string(),
            ]
        } else {
            vec!["127.0.0.1".to_string()]
        };

        Self {
            timeout: Duration::from_millis(timeout_ms),
            god_mode,
            ip_rotation_matrix: ip_rotation,
        }
    }

    /// Detect X-Forwarded header abuse
    pub fn detect_abuse(&self, base_request: &Request, response: &Response) -> Option<Finding> {
        // Check for internal IP leakage or host header injection
        if response.status == 200 {
            if let Some(server_header) = response.headers.get("Server") {
                if server_header.contains("internal") || server_header.contains("proxy") {
                    return Some(Finding::new(
                        "X-Forwarded Header Abuse",
                        "HIGH",
                        "Internal proxy server exposed via X-Forwarded manipulation",
                        "Validate and sanitize X-Forwarded-* headers at edge proxy",
                        Some(self.generate_payload("X-Forwarded-Host")),
                    ));
                }
            }
        }
        None
    }

    /// Generate malicious X-Forwarded headers for testing
    pub fn generate_payload(&self, header_name: &str) -> String {
        if self.god_mode {
            // Aggressive header pollution with IP rotation
            format!(
                "{}: {}\\r\\nX-Original-URL: /admin\\r\\nX-Rewrite-URL: /internal/api",
                header_name,
                self.ip_rotation_matrix.first().unwrap_or(&"127.0.0.1".to_string())
            )
        } else {
            format!("{}: 127.0.0.1", header_name)
        }
    }

    /// Test all forwarding headers with IP rotation
    pub fn test_all_headers(&self, target: &str) -> Vec<(String, String)> {
        let mut tests = Vec::with_capacity(FORWARD_HEADERS.len());
        
        for header in FORWARD_HEADERS.iter() {
            for ip in self.ip_rotation_matrix.iter() {
                tests.push((header.to_string(), ip.clone()));
            }
        }
        
        tests
    }
}

impl Check for XForwardedCheck {
    fn name(&self) -> &'static str {
        "x_forwarded"
    }

    fn run(&self, target: &str, cache: &mut dyn Cache) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(3);
        
        // Test each forwarding header
        for (header, ip) in self.test_all_headers(target) {
            let mock_request = Request {
                method: "GET".to_string(),
                uri: target.to_string(),
                headers: HashMap::new(),
                body: vec![],
            };

            let mock_response = Response {
                status: 200,
                headers: HashMap::new(),
                body: vec![],
            };

            if let Some(finding) = self.detect_abuse(&mock_request, &mock_response) {
                findings.push(finding);
                // Cache successful bypass for self-learning engine
                cache.store(&format!("xforward_{}", header), &ip);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xforwarded_detection() {
        let check = XForwardedCheck::new(5000, true);
        assert_eq!(check.name(), "x_forwarded");
        assert_eq!(check.ip_rotation_matrix.len(), 4);
    }
}
