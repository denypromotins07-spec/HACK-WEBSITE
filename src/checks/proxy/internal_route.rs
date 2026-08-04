//! Internal Route Probing Module
//! Probes routing anomalies via absolute URLs, Upgrade headers, and unexpected methods.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::findings::cache_evidence::CacheEvidence;
use crate::http_client::HttpClient;
use std::collections::HashMap;

/// HTTP methods to test for routing anomalies
const UNEXPECTED_METHODS: &[&str] = &[
    "CONNECT",
    "TRACE",
    "TRACK",
    "DEBUG",
    "OPTIONS",
    "PROPFIND",
    "REPORT",
    "MKCOL",
    "PATCH",
    "LINK",
    "UNLINK",
];

/// Headers that may trigger routing changes
const ROUTING_HEADERS: &[(&str, &str)] = &[
    ("Upgrade", "websocket"),
    ("Connection", "upgrade"),
    ("X-Forwarded-Proto", "ws"),
    ("X-Forwarded-Protocol", "websocket"),
    ("X-Forwarded-Scheme", "ws"),
    ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ("Sec-WebSocket-Version", "13"),
];

/// Absolute URL patterns to test
const ABSOLUTE_URL_PROBES: &[&str] = &[
    "http://internal.server.local/admin",
    "https://backend.internal/api",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://localhost/admin",
];

pub struct InternalRouteChecker {
    http_client: HttpClient,
}

impl InternalRouteChecker {
    pub fn new(http_client: HttpClient) -> Self {
        Self { http_client }
    }

    /// Test unexpected HTTP methods for routing anomalies
    async fn test_unexpected_methods(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        for method in UNEXPECTED_METHODS {
            let response = self.http_client.request(method, base_url, "").await.ok()?;
            
            // Interesting responses for unusual methods
            if response.status == 200 
                || response.status == 405  // Method Not Allowed - reveals supported methods
                || response.status == 501  // Not Implemented
            {
                // TRACE/TRACK methods are particularly interesting
                if (method == &"TRACE" || method == &"TRACK") && response.status == 200 {
                    // XST vulnerability - response echoes request
                    if response.body.contains("TRACE") || response.headers.contains_key("x-request-method") {
                        findings.push(CacheEvidence {
                            url: base_url.to_string(),
                            vulnerability_type: "xst_vulnerability".to_string(),
                            extension_used: format!("Method: {}", method),
                            original_path: base_url.to_string(),
                            edge_headers: response.headers.clone(),
                            cache_status: response.cache_status.unwrap_or_default(),
                            severity: Severity::High,
                            description: "Cross-Site Tracing (XST) possible - TRACE method enabled".to_string(),
                        });
                    }
                }
                
                // OPTIONS reveals allowed methods
                if method == &"OPTIONS" {
                    if let Some(allow) = response.headers.get("allow") {
                        findings.push(CacheEvidence {
                            url: base_url.to_string(),
                            vulnerability_type: "method_discovery".to_string(),
                            extension_used: format!("OPTIONS revealed: {}", allow),
                            original_path: base_url.to_string(),
                            edge_headers: response.headers.clone(),
                            cache_status: response.cache_status.unwrap_or_default(),
                            severity: Severity::Low,
                            description: format!("OPTIONS method reveals allowed methods: {}", allow),
                        });
                    }
                }
                
                // CONNECT for tunneling
                if method == &"CONNECT" && response.status != 405 {
                    findings.push(CacheEvidence {
                        url: base_url.to_string(),
                        vulnerability_type: "connect_method_enabled".to_string(),
                        extension_used: "Method: CONNECT".to_string(),
                        original_path: base_url.to_string(),
                        edge_headers: response.headers.clone(),
                        cache_status: response.cache_status.unwrap_or_default(),
                        severity: Severity::Medium,
                        description: "CONNECT method may be available - potential for HTTP tunneling".to_string(),
                    });
                }
            }
        }
        
        findings
    }

    /// Test Upgrade header manipulation for protocol switching
    async fn test_upgrade_manipulation(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        for (header, value) in ROUTING_HEADERS {
            let mut headers = HashMap::new();
            headers.insert(header.to_string(), value.to_string());
            
            let response = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
            
            // Check if server acknowledges upgrade request
            if response.status == 101 {
                findings.push(CacheEvidence {
                    url: base_url.to_string(),
                    vulnerability_type: "protocol_upgrade".to_string(),
                    extension_used: format!("{}: {}", header, value),
                    original_path: base_url.to_string(),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: Severity::Medium,
                    description: format!("Server accepts {} upgrade to {}", header, value),
                });
            }
            
            // Check for WebSocket-specific responses
            if header == &"Upgrade" && value == &"websocket" {
                if response.headers.contains_key("sec-websocket-accept") {
                    findings.push(CacheEvidence {
                        url: base_url.to_string(),
                        vulnerability_type: "websocket_upgrade".to_string(),
                        extension_used: "Upgrade: websocket".to_string(),
                        original_path: base_url.to_string(),
                        edge_headers: response.headers.clone(),
                        cache_status: response.cache_status.unwrap_or_default(),
                        severity: Severity::Low,
                        description: "WebSocket upgrade successful - verify authentication on WS connections".to_string(),
                    });
                }
            }
        }
        
        findings
    }

    /// Test absolute URL handling for SSRF/internal access
    async fn test_absolute_urls(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        // Test in various parameters
        let param_names = ["url", "target", "redirect", "next", "return", "callback"];
        
        for param in &param_names {
            for abs_url in ABSOLUTE_URL_PROBES {
                let test_url = format!("{}?{}={}", base_url, param, urlencoding::encode(abs_url));
                let response = self.http_client.get(&test_url).await.ok()?;
                
                // Check if server processes the absolute URL
                if self.detect_absolute_url_processing(&response, abs_url) {
                    findings.push(CacheEvidence {
                        url: test_url,
                        vulnerability_type: "absolute_url_ssrf".to_string(),
                        extension_used: format!("{}={}", param, abs_url),
                        original_path: base_url.to_string(),
                        edge_headers: response.headers.clone(),
                        cache_status: response.cache_status.unwrap_or_default(),
                        severity: self.classify_url_severity(abs_url),
                        description: format!(
                            "Server processes absolute URL in {} parameter - potential SSRF",
                            param
                        ),
                    });
                }
            }
        }
        
        findings
    }

    /// Detect if absolute URL was processed
    fn detect_absolute_url_processing(
        &self,
        response: &crate::http_client::HttpResponse,
        target_url: &str,
    ) -> bool {
        // Check redirect location
        if let Some(location) = response.headers.get("location") {
            if location.contains(target_url) || location.contains("internal") {
                return true;
            }
        }
        
        // Check if response contains content from target
        let body_lower = response.body.to_lowercase();
        if target_url.contains("internal") && body_lower.contains("internal") {
            return true;
        }
        
        // Check for error messages indicating connection attempt
        if body_lower.contains("connection refused")
            || body_lower.contains("unable to connect")
            || body_lower.contains("timeout")
        {
            return true;
        }
        
        false
    }

    /// Classify severity based on target URL
    fn classify_url_severity(&self, url: &str) -> Severity {
        if url.contains("localhost") 
            || url.contains("127.0.0.1")
            || url.contains("192.168.")
            || url.contains("10.")
            || url.contains("172.16.")
        {
            Severity::High
        } else if url.contains("internal") || url.contains("backend") {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    /// Test path traversal via routing headers
    async fn test_routing_path_traversal(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        let traversal_headers = [
            ("X-Forwarded-Prefix", "/../"),
            ("X-Rewrite-URL", "/../../../etc/passwd"),
            ("X-Original-URL", "/..%2f..%2f..%2fetc/passwd"),
        ];
        
        for (header, value) in &traversal_headers {
            let mut headers = HashMap::new();
            headers.insert(header.to_string(), value.to_string());
            
            let response = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
            
            if response.body.contains("root:") || response.body.contains("/bin/bash") {
                findings.push(CacheEvidence {
                    url: base_url.to_string(),
                    vulnerability_type: "routing_path_traversal".to_string(),
                    extension_used: format!("{}: {}", header, value),
                    original_path: base_url.to_string(),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: Severity::Critical,
                    description: format!("Path traversal via {} header exposes sensitive files", header),
                });
            }
        }
        
        findings
    }

    /// Analyze routing behavior for anomalies
    fn analyze_routing_anomalies(&self, response: &crate::http_client::HttpResponse) -> Vec<String> {
        let mut anomalies = Vec::new();
        
        // Check for internal IP in response
        if response.body.contains("192.168.") 
            || response.body.contains("10.0.")
            || response.body.contains("172.16.")
        {
            anomalies.push("Response contains internal IP addresses".to_string());
        }
        
        // Check for backend server info
        if let Some(server) = response.headers.get("server") {
            if server.contains("nginx") 
                || server.contains("Apache")
                || server.contains("Tomcat")
            {
                anomalies.push(format!("Backend server type exposed: {}", server));
            }
        }
        
        // Check for internal hostnames
        let internal_patterns = [".internal", ".local", ".lan", "intranet"];
        for pattern in &internal_patterns {
            if response.body.contains(pattern) {
                anomalies.push(format!("Internal hostname pattern found in response: {}", pattern));
                break;
            }
        }
        
        anomalies
    }
}

// Simple URL encoding helper
mod urlencoding {
    pub fn encode(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '/') {
                    c.to_string()
                } else {
                    format!("%{:02X}", c as u8)
                }
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl CheckModule for InternalRouteChecker {
    fn name(&self) -> &'static str {
        "internal_route"
    }

    fn description(&self) -> &'static str {
        "Probes routing anomalies via absolute URLs, Upgrade headers, and unexpected HTTP methods"
    }

    async fn scan(&self, target: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        // Test unexpected methods
        for evidence in self.test_unexpected_methods(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Disable unnecessary HTTP methods. Only allow GET, POST, PUT, DELETE as needed. \
                              Block TRACE/TRACK methods to prevent XST.".to_string(),
            });
        }
        
        // Test upgrade manipulation
        for evidence in self.test_upgrade_manipulation(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Validate Upgrade headers. Ensure WebSocket connections require authentication. \
                              Implement proper origin checking for WebSocket upgrades.".to_string(),
            });
        }
        
        // Test absolute URL handling
        for evidence in self.test_absolute_urls(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Do not accept absolute URLs in parameters. Use relative paths only. \
                              Validate and sanitize all URL inputs.".to_string(),
            });
        }
        
        // Test routing path traversal
        for evidence in self.test_routing_path_traversal(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Strip or validate routing-related headers at proxy level. \
                              Implement strict path normalization.".to_string(),
            });
        }
        
        results
    }

    fn supported_checks(&self) -> Vec<&'static str> {
        vec![
            "internal_route_probing",
            "unexpected_methods",
            "upgrade_manipulation",
            "absolute_url_ssrf",
            "routing_path_traversal",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unexpected_methods_defined() {
        assert!(!UNEXPECTED_METHODS.is_empty());
        assert!(UNEXPECTED_METHODS.contains(&"TRACE"));
        assert!(UNEXPECTED_METHODS.contains(&"CONNECT"));
    }

    #[test]
    fn test_routing_headers_defined() {
        assert!(!ROUTING_HEADERS.is_empty());
        assert!(ROUTING_HEADERS.iter().any(|(h, _)| h == &"Upgrade"));
    }

    #[test]
    fn test_classify_url_severity() {
        let checker = InternalRouteChecker::new(HttpClient::default());
        
        assert_eq!(checker.classify_url_severity("http://localhost/admin"), Severity::High);
        assert_eq!(checker.classify_url_severity("http://192.168.1.1/"), Severity::High);
        assert_eq!(checker.classify_url_severity("http://example.com"), Severity::Low);
    }
}
