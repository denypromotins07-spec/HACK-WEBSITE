//! Cache Key Analysis Module
//! Identifies cache key formation using query, header, and cookie variation probes.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::findings::cache_evidence::CacheEvidence;
use crate::http_client::HttpClient;
use std::collections::HashMap;

/// Query parameters to test for cache key inclusion
const QUERY_PROBES: &[&str] = &[
    "cachebuster", "cb", "_", "t", "timestamp", "random",
    "utm_source", "utm_medium", "utm_campaign",
    "ref", "referrer", "tracking_id", "session_id",
    "callback", "jsonp", "format", "output",
];

/// Headers to test for cache key inclusion
const HEADER_PROBES: &[(&str, &str)] = &[
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Forwarded-Host", "evil.com"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("Accept", "text/html"),
    ("Accept-Language", "en-US"),
    ("Accept-Encoding", "gzip"),
    ("Cookie", "session=test"),
    ("User-Agent", "CustomBot/1.0"),
    ("Referer", "https://attacker.com"),
];

/// Cookie variations to test
const COOKIE_PROBES: &[(&str, &str)] = &[
    ("session", "test_value"),
    ("auth_token", "test_value"),
    ("user_id", "99999"),
    ("preferences", "{}"),
    ("tracking", "disabled"),
];

pub struct CacheKeyChecker {
    http_client: HttpClient,
}

impl CacheKeyChecker {
    pub fn new(http_client: HttpClient) -> Self {
        Self { http_client }
    }

    /// Test if a query parameter affects the cache key
    async fn test_query_param(
        &self,
        base_url: &str,
        param_name: &str,
        param_value: &str,
    ) -> Option<CacheEvidence> {
        let url_with_param = format!("{}?{}={}", base_url, param_name, param_value);
        let url_without_param = base_url.to_string();
        
        // Request with parameter
        let response_with = self.http_client.get(&url_with_param).await.ok()?;
        let body_with = response_with.body.clone();
        
        // Request without parameter
        let response_without = self.http_client.get(&url_without_param).await.ok()?;
        let body_without = response_without.body.clone();
        
        // If responses differ but cache status shows HIT for both, param may not be in cache key
        if body_with != body_without {
            let cache_status_with = response_with.cache_status.unwrap_or_default();
            let cache_status_without = response_without.cache_status.unwrap_or_default();
            
            // Both cached but different content = unkeyed input
            if cache_status_with.contains("HIT") && cache_status_without.contains("HIT") {
                return Some(CacheEvidence {
                    url: url_with_param,
                    vulnerability_type: "unkeyed_query_param".to_string(),
                    extension_used: format!("?{}={}", param_name, param_value),
                    original_path: base_url.to_string(),
                    edge_headers: response_with.headers.clone(),
                    cache_status: cache_status_with,
                    severity: Severity::Medium,
                    description: format!(
                        "Query parameter '{}' is not included in cache key but affects response content",
                        param_name
                    ),
                });
            }
        }
        
        None
    }

    /// Test if a header affects the cache key
    async fn test_header(
        &self,
        base_url: &str,
        header_name: &str,
        header_value: &str,
    ) -> Option<CacheEvidence> {
        let mut headers = HashMap::new();
        headers.insert(header_name.to_string(), header_value.to_string());
        
        // Request with custom header
        let response_with = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
        let body_with = response_with.body.clone();
        
        // Request without custom header
        let response_without = self.http_client.get(base_url).await.ok()?;
        let body_without = response_without.body.clone();
        
        // Compare responses and cache behavior
        if body_with != body_without {
            let cache_status_with = response_with.cache_status.unwrap_or_default();
            let cache_status_without = response_without.cache_status.unwrap_or_default();
            
            if cache_status_with.contains("HIT") && cache_status_without.contains("HIT") {
                return Some(CacheEvidence {
                    url: base_url.to_string(),
                    vulnerability_type: "unkeyed_header".to_string(),
                    extension_used: format!("{}: {}", header_name, header_value),
                    original_path: base_url.to_string(),
                    edge_headers: response_with.headers.clone(),
                    cache_status: cache_status_with,
                    severity: if header_name.contains("Forwarded") || header_name.contains("Original") {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    description: format!(
                        "Header '{}' is not included in cache key but affects response (potential cache poisoning)",
                        header_name
                    ),
                });
            }
        }
        
        None
    }

    /// Test if a cookie affects the cache key
    async fn test_cookie(
        &self,
        base_url: &str,
        cookie_name: &str,
        cookie_value: &str,
    ) -> Option<CacheEvidence> {
        let cookie_header = format!("{}={}", cookie_name, cookie_value);
        let mut headers = HashMap::new();
        headers.insert("Cookie".to_string(), cookie_header);
        
        // Request with cookie
        let response_with = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
        let body_with = response_with.body.clone();
        
        // Request without cookie
        let response_without = self.http_client.get(base_url).await.ok()?;
        let body_without = response_without.body.clone();
        
        if body_with != body_without {
            let cache_status_with = response_with.cache_status.unwrap_or_default();
            let cache_status_without = response_without.cache_status.unwrap_or_default();
            
            if cache_status_with.contains("HIT") && cache_status_without.contains("HIT") {
                return Some(CacheEvidence {
                    url: base_url.to_string(),
                    vulnerability_type: "unkeyed_cookie".to_string(),
                    extension_used: format!("Cookie: {}={}", cookie_name, cookie_value),
                    original_path: base_url.to_string(),
                    edge_headers: response_with.headers.clone(),
                    cache_status: cache_status_with,
                    severity: Severity::Medium,
                    description: format!(
                        "Cookie '{}' is not included in cache key but affects response content",
                        cookie_name
                    ),
                });
            }
        }
        
        None
    }

    /// Analyze Vary header to understand what should be in cache key
    fn analyze_vary_header(&self, headers: &HashMap<String, String>) -> Vec<String> {
        let mut findings = Vec::new();
        
        if let Some(vary) = headers.get("vary") {
            findings.push(format!("Vary header present: {}", vary));
            
            let vary_fields: Vec<&str> = vary.split(',').map(|s| s.trim()).collect();
            
            // Check for problematic Vary configurations
            if vary_fields.iter().any(|f| f.eq_ignore_ascii_case("*")) {
                findings.push("WARNING: Vary: * disables caching entirely".to_string());
            }
            
            if !vary_fields.iter().any(|f| f.eq_ignore_ascii_case("accept-encoding")) {
                findings.push("Note: Accept-Encoding not in Vary - may cause compression issues".to_string());
            }
        } else {
            findings.push("No Vary header present - cache may not differentiate properly".to_string());
        }
        
        findings
    }

    /// Determine cache key components from response analysis
    fn infer_cache_key(&self, responses: &[(&str, &str, &HashMap<String, String>)]) -> Vec<String> {
        let mut inferred_keys = Vec::new();
        
        // Analyze which request components correlate with response differences
        for (component, value, headers) in responses {
            if let Some(vary) = headers.get("vary") {
                if vary.to_lowercase().contains(&component.to_lowercase()) {
                    inferred_keys.push(format!("{} (from Vary)", component));
                }
            }
        }
        
        inferred_keys
    }
}

#[async_trait::async_trait]
impl CheckModule for CacheKeyChecker {
    fn name(&self) -> &'static str {
        "cache_key_analysis"
    }

    fn description(&self) -> &'static str {
        "Analyzes cache key formation by probing query parameters, headers, and cookies"
    }

    async fn scan(&self, target: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        // Test query parameters
        for param in QUERY_PROBES {
            if let Some(evidence) = self.test_query_param(target, param, "test").await {
                results.push(CheckResult {
                    check_name: self.name(),
                    severity: evidence.severity,
                    finding: evidence.description,
                    evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                    remediation: "Include all user-controllable inputs that affect response in the cache key. \
                                  Use Vary header to indicate which headers affect content.".to_string(),
                });
            }
        }
        
        // Test headers
        for (header, value) in HEADER_PROBES {
            if let Some(evidence) = self.test_header(target, header, value).await {
                results.push(CheckResult {
                    check_name: self.name(),
                    severity: evidence.severity,
                    finding: evidence.description,
                    evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                    remediation: "Configure CDN/proxy to include security-relevant headers in cache key. \
                                  Reject or sanitize dangerous headers like X-Forwarded-Host.".to_string(),
                });
            }
        }
        
        // Test cookies
        for (cookie, value) in COOKIE_PROBES {
            if let Some(evidence) = self.test_cookie(target, cookie, value).await {
                results.push(CheckResult {
                    check_name: self.name(),
                    severity: evidence.severity,
                    finding: evidence.description,
                    evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                    remediation: "Include authentication cookies in cache key or mark responses as private.".to_string(),
                });
            }
        }
        
        results
    }

    fn supported_checks(&self) -> Vec<&'static str> {
        vec![
            "cache_key_analysis",
            "unkeyed_query_params",
            "unkeyed_headers",
            "unkeyed_cookies",
            "vary_header_analysis",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_probes_defined() {
        assert!(!QUERY_PROBES.is_empty());
        assert!(QUERY_PROBES.contains(&"cachebuster"));
    }

    #[test]
    fn test_header_probes_defined() {
        assert!(!HEADER_PROBES.is_empty());
        assert!(HEADER_PROBES.iter().any(|(h, _)| h == &"X-Forwarded-For"));
    }

    #[test]
    fn test_cookie_probes_defined() {
        assert!(!COOKIE_PROBES.is_empty());
        assert!(COOKIE_PROBES.iter().any(|(name, _)| name == &"session"));
    }
}
