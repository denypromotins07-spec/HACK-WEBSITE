//! Cache Poisoning Detection Module
//! Detects cache poisoning via Host, X-Forwarded-Host, and unsafe redirect generators.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::findings::cache_evidence::CacheEvidence;
use crate::http_client::HttpClient;
use std::collections::HashMap;

/// Dangerous headers that can trigger cache poisoning
const POISONING_HEADERS: &[(&str, &[&str])] = &[
    ("Host", &["evil.com", "attacker.com", "malicious.org"]),
    ("X-Forwarded-Host", &["evil.com", "attacker.com"]),
    ("X-Real-IP", &["127.0.0.1", "0.0.0.0"]),
    ("X-Original-URL", &["/admin", "/.env", "/config"]),
    ("X-Rewrite-URL", &["/admin", "/internal"]),
    ("X-Forwarded-Scheme", &["https", "http"]),
    ("X-Forwarded-Proto", &["https", "http"]),
];

/// Redirect-related headers to test
const REDIRECT_HEADERS: &[(&str, &str)] = &[
    ("X-Redirect-URL", "https://evil.com"),
    ("X-Forwarded-URL", "https://evil.com/phishing"),
    ("Referer", "https://evil.com"),
    ("X-Client-IP", "127.0.0.1"),
];

pub struct CachePoisoningChecker {
    http_client: HttpClient,
}

impl CachePoisoningChecker {
    pub fn new(http_client: HttpClient) -> Self {
        Self { http_client }
    }

    /// Test if a header can be used for cache poisoning
    async fn test_poisoning_header(
        &self,
        base_url: &str,
        header_name: &str,
        header_values: &[&str],
    ) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        for value in header_values {
            let mut headers = HashMap::new();
            headers.insert(header_name.to_string(), value.to_string());
            
            // Make request with malicious header
            let response = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
            
            // Check for signs of successful poisoning
            if self.detect_poisoning_indicators(&response, header_name, value) {
                findings.push(CacheEvidence {
                    url: base_url.to_string(),
                    vulnerability_type: "cache_poisoning".to_string(),
                    extension_used: format!("{}: {}", header_name, value),
                    original_path: base_url.to_string(),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: self.calculate_severity(header_name, &response),
                    description: format!(
                        "Cache poisoning detected via {}: {} - Response contains attacker-controlled content",
                        header_name, value
                    ),
                });
            }
        }
        
        findings
    }

    /// Detect indicators of successful cache poisoning
    fn detect_poisoning_indicators(
        &self,
        response: &crate::http_client::HttpResponse,
        header_name: &str,
        header_value: &str,
    ) -> bool {
        // Check if response reflects the injected header value
        if response.body.contains(header_value) {
            return true;
        }
        
        // Check for redirect to attacker domain
        if header_name.contains("Host") || header_name.contains("Forwarded") {
            if let Some(location) = response.headers.get("location") {
                if location.contains(header_value) {
                    return true;
                }
            }
        }
        
        // Check for cache status indicating storage
        if let Some(cache_status) = &response.cache_status {
            if cache_status.contains("HIT") || cache_status.contains("STORE") {
                // Content was cached - check if it's poisoned
                if response.body.contains("evil") || response.body.contains("attacker") {
                    return true;
                }
            }
        }
        
        // Check for Set-Cookie with attacker domain
        if let Some(set_cookie) = response.headers.get("set-cookie") {
            if set_cookie.contains("domain=") && set_cookie.contains(header_value) {
                return true;
            }
        }
        
        false
    }

    /// Calculate severity based on poisoning type
    fn calculate_severity(&self, header_name: &str, response: &crate::http_client::HttpResponse) -> Severity {
        match header_name {
            "Host" | "X-Forwarded-Host" => {
                // Host header injection is critical
                if response.body.contains("<script") || response.body.contains("javascript:") {
                    Severity::Critical
                } else {
                    Severity::High
                }
            }
            "X-Original-URL" | "X-Rewrite-URL" => Severity::High,
            "X-Forwarded-Scheme" | "X-Forwarded-Proto" => Severity::Medium,
            _ => Severity::Medium,
        }
    }

    /// Test redirect-based poisoning
    async fn test_redirect_poisoning(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        for (header, value) in REDIRECT_HEADERS {
            let mut headers = HashMap::new();
            headers.insert(header.to_string(), value.to_string());
            
            let response = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
            
            // Check if redirect location reflects attacker input
            if let Some(location) = response.headers.get("location") {
                if location.contains("evil.com") || location.contains("attacker") {
                    findings.push(CacheEvidence {
                        url: base_url.to_string(),
                        vulnerability_type: "redirect_poisoning".to_string(),
                        extension_used: format!("{}: {}", header, value),
                        original_path: base_url.to_string(),
                        edge_headers: response.headers.clone(),
                        cache_status: response.cache_status.unwrap_or_default(),
                        severity: Severity::High,
                        description: format!(
                            "Redirect poisoning via {}: Server redirects to attacker-controlled URL {}",
                            header, location
                        ),
                    });
                }
            }
        }
        
        findings
    }

    /// Test Host header injection specifically
    async fn test_host_header_injection(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        let malicious_hosts = ["evil.com", "attacker.com", "malicious.org"];
        
        for host in &malicious_hosts {
            let mut headers = HashMap::new();
            headers.insert("Host".to_string(), host.to_string());
            
            let response = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
            
            // Check for password reset link poisoning, XSS, etc.
            let body_lower = response.body.to_lowercase();
            
            if body_lower.contains(&format!("https://{}", host)) 
                || body_lower.contains(&format!("http://{}", host))
                || response.body.contains(*host)
            {
                findings.push(CacheEvidence {
                    url: base_url.to_string(),
                    vulnerability_type: "host_header_injection".to_string(),
                    extension_used: format!("Host: {}", host),
                    original_path: base_url.to_string(),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: if body_lower.contains("<script") {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    description: format!(
                        "Host header injection: Response reflects malicious host {} - may enable password reset poisoning or XSS",
                        host
                    ),
                });
            }
        }
        
        findings
    }

    /// Analyze response for caching of dynamic content
    fn analyze_cacheability(&self, response: &crate::http_client::HttpResponse) -> Vec<String> {
        let mut warnings = Vec::new();
        
        // Check if dynamic content is being cached
        if response.body.contains("csrf") || response.body.contains("token") {
            if let Some(cc) = response.headers.get("cache-control") {
                if cc.contains("public") {
                    warnings.push("WARNING: Dynamic content with CSRF tokens marked as public cacheable".to_string());
                }
            }
        }
        
        // Check for user-specific content caching
        if response.body.contains("\"email\"") || response.body.contains("\"user_id\"") {
            warnings.push("WARNING: User-specific JSON content may be cached".to_string());
        }
        
        warnings
    }
}

#[async_trait::async_trait]
impl CheckModule for CachePoisoningChecker {
    fn name(&self) -> &'static str {
        "cache_poisoning"
    }

    fn description(&self) -> &'static str {
        "Detects cache poisoning vulnerabilities via Host header, X-Forwarded-Host, and redirect manipulation"
    }

    async fn scan(&self, target: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        // Test all poisoning headers
        for (header, values) in POISONING_HEADERS {
            for evidence in self.test_poisoning_header(target, header, values).await {
                results.push(CheckResult {
                    check_name: self.name(),
                    severity: evidence.severity,
                    finding: evidence.description,
                    evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                    remediation: "Validate and sanitize Host and X-Forwarded-* headers. \
                                  Configure CDN to ignore untrusted headers. \
                                  Use allowlists for acceptable header values.".to_string(),
                });
            }
        }
        
        // Test redirect poisoning
        for evidence in self.test_redirect_poisoning(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Do not use client-supplied headers for redirect targets. \
                              Validate redirect URLs against an allowlist.".to_string(),
            });
        }
        
        // Test Host header injection specifically
        for evidence in self.test_host_header_injection(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Configure web server to reject invalid Host headers. \
                              Use absolute URLs in responses instead of relying on Host header.".to_string(),
            });
        }
        
        results
    }

    fn supported_checks(&self) -> Vec<&'static str> {
        vec![
            "cache_poisoning",
            "host_header_injection",
            "x_forwarded_host_poisoning",
            "redirect_poisoning",
            "dynamic_content_caching",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poisoning_headers_defined() {
        assert!(!POISONING_HEADERS.is_empty());
        assert!(POISONING_HEADERS.iter().any(|(h, _)| h == &"Host"));
        assert!(POISONING_HEADERS.iter().any(|(h, _)| h == &"X-Forwarded-Host"));
    }

    #[test]
    fn test_redirect_headers_defined() {
        assert!(!REDIRECT_HEADERS.is_empty());
    }
}
