//! Reverse Proxy Misconfiguration Detection Module
//! Detects reverse proxy path manipulation exposing admin consoles or internal routes.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::findings::cache_evidence::CacheEvidence;
use crate::http_client::HttpClient;
use std::collections::HashMap;

/// Path patterns that may expose internal/admin routes via proxy misconfiguration
const PROXY_PATH_PROBES: &[&str] = &[
    "/admin",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/manager",
    "/console",
    "/actuator",
    "/swagger-ui",
    "/api-docs",
    "/internal",
    "/private",
    "/debug",
    "/metrics",
    "/health",
    "/status",
];

/// Header-based path manipulation techniques
const PATH_MANIPULATION_HEADERS: &[(&str, &str)] = &[
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-Prefix", "/admin"),
    ("X-Forwarded-Path", "/admin"),
    ("X-Proxy-Path", "/admin"),
    ("X-Backend-Path", "/internal"),
];

pub struct ReverseMisconfigChecker {
    http_client: HttpClient,
}

impl ReverseMisconfigChecker {
    pub fn new(http_client: HttpClient) -> Self {
        Self { http_client }
    }

    /// Test direct path access for exposed admin/internal routes
    async fn test_direct_paths(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        for path in PROXY_PATH_PROBES {
            let target_url = format!("{}{}", base_url, path);
            let response = self.http_client.get(&target_url).await.ok()?;
            
            // Check if we get meaningful response (not 404)
            if response.status == 200 || response.status == 401 || response.status == 403 {
                // Admin pages often have distinctive content
                if self.is_admin_or_internal_content(&response.body, path) {
                    findings.push(CacheEvidence {
                        url: target_url,
                        vulnerability_type: "exposed_admin_route".to_string(),
                        extension_used: format!("Direct path: {}", path),
                        original_path: base_url.to_string(),
                        edge_headers: response.headers.clone(),
                        cache_status: response.cache_status.unwrap_or_default(),
                        severity: self.classify_path_severity(path),
                        description: format!(
                            "Potentially sensitive route {} is accessible (status: {})",
                            path, response.status
                        ),
                    });
                }
            }
        }
        
        findings
    }

    /// Test header-based path manipulation
    async fn test_header_manipulation(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        for (header, path) in PATH_MANIPULATION_HEADERS {
            let mut headers = HashMap::new();
            headers.insert(header.to_string(), path.to_string());
            
            let response = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
            
            // Check if header caused different behavior
            if response.status != 404 && !response.body.is_empty() {
                if self.detect_proxy_manipulation_success(&response, path) {
                    findings.push(CacheEvidence {
                        url: base_url.to_string(),
                        vulnerability_type: "proxy_header_manipulation".to_string(),
                        extension_used: format!("{}: {}", header, path),
                        original_path: base_url.to_string(),
                        edge_headers: response.headers.clone(),
                        cache_status: response.cache_status.unwrap_or_default(),
                        severity: Severity::High,
                        description: format!(
                            "Reverse proxy processes {} header to access {} - potential path traversal",
                            header, path
                        ),
                    });
                }
            }
        }
        
        findings
    }

    /// Test path normalization bypasses
    async fn test_normalization_bypass(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        let bypass_techniques = [
            ("/admin", "/admin/."),
            ("/admin", "/admin/..;/"),
            ("/admin", "/admin;/"),
            ("/admin", "//admin//"),
            ("/admin", "/%2e%2e/admin"),
            ("/admin", "/admin%00.css"),
        ];
        
        for (original, bypass) in &bypass_techniques {
            let target_url = format!("{}{}", base_url, bypass);
            let response = self.http_client.get(&target_url).await.ok()?;
            
            // If bypass returns same content as original, normalization failed
            if response.status == 200 || response.status == 401 {
                findings.push(CacheEvidence {
                    url: target_url,
                    vulnerability_type: "path_normalization_bypass".to_string(),
                    extension_used: format!("Bypass: {}", bypass),
                    original_path: format!("{}{}", base_url, original),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: Severity::High,
                    description: format!(
                        "Path normalization bypass detected: {} accesses {}",
                        bypass, original
                    ),
                });
            }
        }
        
        findings
    }

    /// Check if response body indicates admin/internal content
    fn is_admin_or_internal_content(&self, body: &str, path: &str) -> bool {
        let body_lower = body.to_lowercase();
        
        // Common admin page indicators
        let admin_indicators = [
            "admin", "administrator", "login", "dashboard", "management",
            "console", "control panel", "cpanel", "webmail",
            "phpmyadmin", "mysql", "database", "swagger", "api",
            "actuator", "health", "metrics", "prometheus", "grafana",
        ];
        
        // Check if path suggests admin and body has relevant content
        let path_lower = path.to_lowercase();
        if path_lower.contains("admin") || path_lower.contains("internal") {
            return true;
        }
        
        // Check body for admin indicators
        admin_indicators.iter().any(|ind| body_lower.contains(ind))
    }

    /// Detect successful proxy manipulation
    fn detect_proxy_manipulation_success(
        &self,
        response: &crate::http_client::HttpResponse,
        expected_path: &str,
    ) -> bool {
        let body_lower = response.body.to_lowercase();
        
        // Check if response contains content related to the manipulated path
        if expected_path.contains("admin") && body_lower.contains("admin") {
            return true;
        }
        
        // Check for internal content exposure
        if body_lower.contains("internal") 
            || body_lower.contains("private")
            || body_lower.contains("confidential")
        {
            return true;
        }
        
        // Check for server information leakage
        if body_lower.contains("server:") 
            || body_lower.contains("version:")
            || body_lower.contains("build:")
        {
            return true;
        }
        
        false
    }

    /// Classify severity based on path type
    fn classify_path_severity(&self, path: &str) -> Severity {
        let path_lower = path.to_lowercase();
        
        if path_lower.contains("actuator") 
            || path_lower.contains("metrics")
            || path_lower.contains("debug")
            || path_lower.contains("internal")
        {
            Severity::Critical
        } else if path_lower.contains("admin") 
            || path_lower.contains("manager")
            || path_lower.contains("console")
        {
            Severity::High
        } else if path_lower.contains("swagger") 
            || path_lower.contains("api-docs")
        {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    /// Test for backend server discovery via proxy errors
    async fn test_backend_discovery(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        // Send malformed requests to trigger proxy error responses
        let malformed_paths = [
            "/../../../etc/passwd",
            "/..\\..\\..\\windows\\system32\\config\\sam",
            "/%00",
            "/\x00",
        ];
        
        for path in &malformed_paths {
            let target_url = format!("{}{}", base_url, path);
            let response = self.http_client.get(&target_url).await.ok()?;
            
            // Error responses may reveal backend technology
            if response.status >= 500 || response.status == 400 {
                if self.extract_backend_info(&response.body, &response.headers) {
                    findings.push(CacheEvidence {
                        url: target_url,
                        vulnerability_type: "backend_discovery".to_string(),
                        extension_used: format!("Malformed path: {}", path),
                        original_path: base_url.to_string(),
                        edge_headers: response.headers.clone(),
                        cache_status: response.cache_status.unwrap_or_default(),
                        severity: Severity::Medium,
                        description: "Error response reveals backend server information".to_string(),
                    });
                }
            }
        }
        
        findings
    }

    /// Extract backend information from error responses
    fn extract_backend_info(&self, body: &str, headers: &HashMap<String, String>) -> bool {
        // Check Server header
        if let Some(server) = headers.get("server") {
            if server.contains("nginx") 
                || server.contains("Apache")
                || server.contains("IIS")
                || server.contains("Tomcat")
                || server.contains("Jetty")
            {
                return true;
            }
        }
        
        // Check X-Powered-By
        if headers.contains_key("x-powered-by") {
            return true;
        }
        
        // Check body for stack traces or error details
        let body_lower = body.to_lowercase();
        if body_lower.contains("stack trace")
            || body_lower.contains("exception")
            || body_lower.contains("at com.")
            || body_lower.contains("at org.")
            || body_lower.contains(".php on line")
        {
            return true;
        }
        
        false
    }
}

#[async_trait::async_trait]
impl CheckModule for ReverseMisconfigChecker {
    fn name(&self) -> &'static str {
        "reverse_misconfig"
    }

    fn description(&self) -> &'static str {
        "Detects reverse proxy misconfigurations exposing admin consoles and internal routes"
    }

    async fn scan(&self, target: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        // Test direct path access
        for evidence in self.test_direct_paths(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Restrict access to admin/internal routes via IP allowlisting. \
                              Implement proper authentication. Configure proxy to block sensitive paths.".to_string(),
            });
        }
        
        // Test header manipulation
        for evidence in self.test_header_manipulation(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Strip or validate X-Original-URL, X-Rewrite-URL and similar headers at edge. \
                              Do not trust client-supplied path headers.".to_string(),
            });
        }
        
        // Test normalization bypasses
        for evidence in self.test_normalization_bypass(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Implement strict path normalization. Reject paths with unusual characters or encoding.".to_string(),
            });
        }
        
        // Test backend discovery
        for evidence in self.test_backend_discovery(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Configure custom error pages that don't reveal backend information. \
                              Disable debug mode in production.".to_string(),
            });
        }
        
        results
    }

    fn supported_checks(&self) -> Vec<&'static str> {
        vec![
            "reverse_proxy_misconfig",
            "admin_route_exposure",
            "header_path_manipulation",
            "path_normalization_bypass",
            "backend_discovery",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_path_probes_defined() {
        assert!(!PROXY_PATH_PROBES.is_empty());
        assert!(PROXY_PATH_PROBES.contains(&"/admin"));
        assert!(PROXY_PATH_PROBES.contains(&"/actuator"));
    }

    #[test]
    fn test_path_manipulation_headers_defined() {
        assert!(!PATH_MANIPULATION_HEADERS.is_empty());
        assert!(PATH_MANIPULATION_HEADERS.iter().any(|(h, _)| h == &"X-Original-URL"));
    }

    #[test]
    fn test_classify_path_severity() {
        let checker = ReverseMisconfigChecker {
            http_client: HttpClient::default(),
        };
        
        assert_eq!(checker.classify_path_severity("/actuator"), Severity::Critical);
        assert_eq!(checker.classify_path_severity("/admin"), Severity::High);
        assert_eq!(checker.classify_path_severity("/swagger-ui"), Severity::Medium);
    }
}
