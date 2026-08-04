//! Unkeyed Headers Detection Module
//! Detects unkeyed header exploitation using X-Forwarded-Scheme, X-Original-URL, and custom headers.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::findings::cache_evidence::CacheEvidence;
use crate::http_client::HttpClient;
use std::collections::HashMap;

/// Headers commonly not included in cache keys but can affect responses
const UNKEYED_HEADER_CANDIDATES: &[&str] = &[
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto", 
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Prefix",
    "X-External-Request",
    "X-Debug",
    "X-Cache-Bypass",
    "X-Get-Source",
    "X-Api-Version",
    "X-Request-ID",
    "X-Trace",
    "X-Correlation-ID",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Akamai-Edge-Cache",
];

/// Custom headers to probe for (common internal/debug headers)
const CUSTOM_HEADER_PROBES: &[(&str, &str)] = &[
    ("X-Debug", "true"),
    ("X-Trace", "enabled"),
    ("X-Verbose", "1"),
    ("X-Internal", "true"),
    ("X-Admin", "1"),
    ("X-Test", "true"),
    ("X-Environment", "staging"),
    ("X-Datacenter", "internal"),
];

pub struct UnkeyedHeadersChecker {
    http_client: HttpClient,
}

impl UnkeyedHeadersChecker {
    pub fn new(http_client: HttpClient) -> Self {
        Self { http_client }
    }

    /// Test if a header is unkeyed (affects response but not in cache key)
    async fn test_unkeyed_header(
        &self,
        base_url: &str,
        header_name: &str,
        header_value: &str,
    ) -> Option<CacheEvidence> {
        let mut headers = HashMap::new();
        headers.insert(header_name.to_string(), header_value.to_string());
        
        // First request with header - should populate cache
        let response_with = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
        let body_with = response_with.body.clone();
        let cache_status_with = response_with.cache_status.clone().unwrap_or_default();
        
        // Second request without header
        let response_without = self.http_client.get(base_url).await.ok()?;
        let body_without = response_without.body.clone();
        let cache_status_without = response_without.cache_status.clone().unwrap_or_default();
        
        // Third request with header again - check if it gets the cached version
        let response_again = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
        let body_again = response_again.body.clone();
        let cache_status_again = response_again.cache_status.clone().unwrap_or_default();
        
        // If responses differ based on header but both show HIT, header is unkeyed
        if body_with != body_without {
            // Header affects response
            if cache_status_again.contains("HIT") || cache_status_with.contains("HIT") {
                return Some(CacheEvidence {
                    url: base_url.to_string(),
                    vulnerability_type: "unkeyed_header".to_string(),
                    extension_used: format!("{}: {}", header_name, header_value),
                    original_path: base_url.to_string(),
                    edge_headers: response_with.headers.clone(),
                    cache_status: cache_status_with,
                    severity: self.classify_header_severity(header_name, &response_with),
                    description: format!(
                        "Header '{}' is not in cache key but affects response content (cache status: {})",
                        header_name, cache_status_with
                    ),
                });
            }
        }
        
        None
    }

    /// Classify severity based on header type and response content
    fn classify_header_severity(
        &self,
        header_name: &str,
        response: &crate::http_client::HttpResponse,
    ) -> Severity {
        match header_name {
            "X-Original-URL" | "X-Rewrite-URL" => {
                // Path manipulation is high severity
                if response.body.contains("admin") || response.body.contains("config") {
                    Severity::Critical
                } else {
                    Severity::High
                }
            }
            "X-Forwarded-Scheme" | "X-Forwarded-Proto" => {
                // Protocol downgrade could enable attacks
                Severity::High
            }
            "X-Debug" | "X-Trace" | "X-Verbose" => {
                // Debug info leakage
                if response.body.contains("stack") || response.body.contains("trace") {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            "X-Internal" | "X-Admin" => {
                // Internal/admin access bypass
                Severity::Critical
            }
            _ => Severity::Medium,
        }
    }

    /// Test X-Forwarded-Scheme specifically for protocol manipulation
    async fn test_forwarded_scheme(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        for (scheme, expected_behavior) in [
            ("http", "potential_downgrade"),
            ("https", "forced_secure"),
        ] {
            let mut headers = HashMap::new();
            headers.insert("X-Forwarded-Scheme".to_string(), scheme.to_string());
            
            let response = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
            
            // Check for protocol-related content changes
            let body_lower = response.body.to_lowercase();
            
            if (scheme == "http" && body_lower.contains("http://")) 
                || (scheme == "https" && !body_lower.contains("http://"))
            {
                // Check if this variation is cached
                if response.cache_status.as_ref().map(|s| s.contains("HIT")).unwrap_or(false) {
                    findings.push(CacheEvidence {
                        url: base_url.to_string(),
                        vulnerability_type: "unkeyed_scheme_header".to_string(),
                        extension_used: format!("X-Forwarded-Scheme: {}", scheme),
                        original_path: base_url.to_string(),
                        edge_headers: response.headers.clone(),
                        cache_status: response.cache_status.unwrap_or_default(),
                        severity: Severity::High,
                        description: format!(
                            "X-Forwarded-Scheme header ({}) affects response and may be cached - potential for protocol confusion attacks",
                            scheme
                        ),
                    });
                }
            }
        }
        
        findings
    }

    /// Test X-Original-URL for path manipulation
    async fn test_original_url(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        let test_paths = ["/admin", "/api/internal", "/debug", "/.env", "/config.php"];
        
        for path in &test_paths {
            let mut headers = HashMap::new();
            headers.insert("X-Original-URL".to_string(), path.to_string());
            
            let response = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
            
            // Check if server processes the injected path
            if response.status == 200 && !response.body.is_empty() {
                // Check for signs of accessing different resource
                if response.body.contains("admin") 
                    || response.body.contains("debug")
                    || response.body.contains("internal")
                    || (path.contains(".env") && response.body.contains("="))
                {
                    if response.cache_status.as_ref().map(|s| s.contains("HIT")).unwrap_or(false) {
                        findings.push(CacheEvidence {
                            url: base_url.to_string(),
                            vulnerability_type: "x_original_url_manipulation".to_string(),
                            extension_used: format!("X-Original-URL: {}", path),
                            original_path: base_url.to_string(),
                            edge_headers: response.headers.clone(),
                            cache_status: response.cache_status.unwrap_or_default(),
                            severity: Severity::Critical,
                            description: format!(
                                "X-Original-URL header allows accessing {} - content may be cached",
                                path
                            ),
                        });
                    }
                }
            }
        }
        
        findings
    }

    /// Probe for custom/internal headers that might be unkeyed
    async fn probe_custom_headers(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        for (header, value) in CUSTOM_HEADER_PROBES {
            if let Some(evidence) = self.test_unkeyed_header(base_url, header, value).await {
                findings.push(evidence);
            }
        }
        
        findings
    }

    /// Analyze Vary header to see what's supposed to be keyed
    fn analyze_vary_for_headers(&self, headers: &HashMap<String, String>) -> Vec<String> {
        let mut analysis = Vec::new();
        
        if let Some(vary) = headers.get("vary") {
            let vary_lower = vary.to_lowercase();
            
            for candidate in UNKEYED_HEADER_CANDIDATES {
                let candidate_lower = candidate.to_lowercase();
                let header_key = candidate_lower.strip_prefix("x-").unwrap_or(&candidate_lower);
                
                if !vary_lower.contains(header_key) && !vary_lower.contains(candidate_lower.as_str()) {
                    analysis.push(format!(
                        "Header '{}' likely not in Vary - may be unkeyed",
                        candidate
                    ));
                }
            }
        } else {
            analysis.push("No Vary header - all headers potentially unkeyed".to_string());
        }
        
        analysis
    }
}

#[async_trait::async_trait]
impl CheckModule for UnkeyedHeadersChecker {
    fn name(&self) -> &'static str {
        "unkeyed_headers"
    }

    fn description(&self) -> &'static str {
        "Detects unkeyed header exploitation via X-Forwarded-Scheme, X-Original-URL, and custom headers"
    }

    async fn scan(&self, target: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        // Test standard unkeyed header candidates
        for header in UNKEYED_HEADER_CANDIDATES {
            if let Some(evidence) = self.test_unkeyed_header(target, header, "test").await {
                results.push(CheckResult {
                    check_name: self.name(),
                    severity: evidence.severity,
                    finding: evidence.description,
                    evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                    remediation: "Include security-relevant headers in cache key configuration. \
                                  Use CDN rules to explicitly define which headers affect caching.".to_string(),
                });
            }
        }
        
        // Test X-Forwarded-Scheme specifically
        for evidence in self.test_forwarded_scheme(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Validate X-Forwarded-Scheme against expected values. \
                              Include in cache key if it affects response.".to_string(),
            });
        }
        
        // Test X-Original-URL specifically
        for evidence in self.test_original_url(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Strip or validate X-Original-URL header at edge. \
                              Do not allow client-supplied path overrides.".to_string(),
            });
        }
        
        // Probe custom headers
        for evidence in self.probe_custom_headers(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Remove debug/internal headers at CDN edge. \
                              Never expose internal headers to client requests.".to_string(),
            });
        }
        
        results
    }

    fn supported_checks(&self) -> Vec<&'static str> {
        vec![
            "unkeyed_headers",
            "x_forwarded_scheme_abuse",
            "x_original_url_manipulation",
            "custom_header_exploitation",
            "vary_header_analysis",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unkeyed_header_candidates_defined() {
        assert!(!UNKEYED_HEADER_CANDIDATES.is_empty());
        assert!(UNKEYED_HEADER_CANDIDATES.contains(&"X-Forwarded-Scheme"));
        assert!(UNKEYED_HEADER_CANDIDATES.contains(&"X-Original-URL"));
    }

    #[test]
    fn test_custom_header_probes_defined() {
        assert!(!CUSTOM_HEADER_PROBES.is_empty());
        assert!(CUSTOM_HEADER_PROBES.iter().any(|(h, _)| h == &"X-Debug"));
    }
}
