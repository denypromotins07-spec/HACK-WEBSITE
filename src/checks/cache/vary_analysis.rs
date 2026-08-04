//! Vary Header Analysis Module
//! Analyzes Vary header handling and cache normalization inconsistencies.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::findings::cache_evidence::CacheEvidence;
use crate::http_client::HttpClient;
use std::collections::{HashMap, HashSet};

/// Common Vary header values to analyze
const STANDARD_VARY_VALUES: &[&str] = &[
    "Accept",
    "Accept-Encoding",
    "Accept-Language",
    "User-Agent",
    "Cookie",
    "Authorization",
    "Host",
    "Origin",
];

/// Problematic Vary configurations
const PROBLEMATIC_VARY_PATTERNS: &[&str] = &[
    "*",
    "*.*",
    "X-Forwarded-For",
    "X-Real-IP",
];

pub struct VaryAnalysisChecker {
    http_client: HttpClient,
}

impl VaryAnalysisChecker {
    pub fn new(http_client: HttpClient) -> Self {
        Self { http_client }
    }

    /// Analyze the Vary header from a response
    async fn analyze_vary_header(&self, url: &str) -> Option<CacheEvidence> {
        let response = self.http_client.get(url).await.ok()?;
        
        if let Some(vary) = response.headers.get("vary") {
            let vary_analysis = self.parse_vary_header(vary);
            
            // Check for problematic patterns
            for pattern in PROBLEMATIC_VARY_PATTERNS {
                if vary.to_lowercase().contains(&pattern.to_lowercase()) {
                    return Some(CacheEvidence {
                        url: url.to_string(),
                        vulnerability_type: "problematic_vary".to_string(),
                        extension_used: format!("Vary: {}", vary),
                        original_path: url.to_string(),
                        edge_headers: response.headers.clone(),
                        cache_status: response.cache_status.unwrap_or_default(),
                        severity: if pattern == &"*" {
                            Severity::Medium // Disables caching
                        } else {
                            Severity::High // Unkeyed input risk
                        },
                        description: format!(
                            "Problematic Vary header detected: '{}' - pattern '{}' may cause cache issues",
                            vary, pattern
                        ),
                    });
                }
            }
            
            // Check for missing standard Vary values
            let missing = self.check_missing_standard_vary(&vary_analysis, &response.headers);
            if !missing.is_empty() {
                return Some(CacheEvidence {
                    url: url.to_string(),
                    vulnerability_type: "incomplete_vary".to_string(),
                    extension_used: format!("Missing: {}", missing.join(", ")),
                    original_path: url.to_string(),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: Severity::Low,
                    description: format!(
                        "Vary header may be incomplete. Missing potentially relevant fields: {}",
                        missing.join(", ")
                    ),
                });
            }
        } else {
            // No Vary header at all
            return Some(CacheEvidence {
                url: url.to_string(),
                vulnerability_type: "missing_vary".to_string(),
                extension_used: "No Vary header".to_string(),
                original_path: url.to_string(),
                edge_headers: response.headers.clone(),
                cache_status: response.cache_status.unwrap_or_default(),
                severity: Severity::Medium,
                description: "No Vary header present - cache may not properly differentiate requests".to_string(),
            });
        }
        
        None
    }

    /// Parse Vary header into individual fields
    fn parse_vary_header(&self, vary: &str) -> HashSet<String> {
        vary.split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Check for missing standard Vary values based on response content
    fn check_missing_standard_vary(
        &self,
        vary_fields: &HashSet<String>,
        headers: &HashMap<String, String>,
    ) -> Vec<String> {
        let mut missing = Vec::new();
        
        // Check Accept-Encoding
        if !vary_fields.contains("accept-encoding") {
            if let Some(ae) = headers.get("content-encoding") {
                if ae != "identity" {
                    missing.push("Accept-Encoding".to_string());
                }
            }
        }
        
        // Check Accept-Language (if content appears localized)
        if !vary_fields.contains("accept-language") {
            if let Some(cl) = headers.get("content-language") {
                missing.push("Accept-Language".to_string());
            }
        }
        
        // Check User-Agent (for mobile/desktop variations)
        if !vary_fields.contains("user-agent") {
            // This would need response body analysis to detect
        }
        
        missing
    }

    /// Test cache normalization by sending requests with different header combinations
    async fn test_normalization(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        // Test 1: Different Accept-Encoding values
        let encodings = ["gzip", "deflate", "br", "identity"];
        let mut responses_by_encoding = HashMap::new();
        
        for encoding in &encodings {
            let mut headers = HashMap::new();
            headers.insert("Accept-Encoding".to_string(), encoding.to_string());
            
            let response = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
            responses_by_encoding.insert(
                encoding.to_string(),
                (response.body.clone(), response.cache_status.clone()),
            );
        }
        
        // Check if different encodings return same cached content incorrectly
        let first_body = responses_by_encoding.get("gzip").map(|(b, _)| b.clone());
        for (encoding, (body, cache_status)) in &responses_by_encoding {
            if encoding != "gzip" {
                if Some(body) == first_body.as_ref() {
                    if let Some(cs) = cache_status {
                        if cs.contains("HIT") {
                            findings.push(CacheEvidence {
                                url: base_url.to_string(),
                                vulnerability_type: "encoding_normalization".to_string(),
                                extension_used: format!("Accept-Encoding: {}", encoding),
                                original_path: base_url.to_string(),
                                edge_headers: HashMap::new(),
                                cache_status: cache_status.clone().unwrap_or_default(),
                                severity: Severity::Medium,
                                description: format!(
                                    "Different Accept-Encoding values ({}) served same cached content - may indicate improper normalization",
                                    encodings.join(", ")
                                ),
                            });
                            break;
                        }
                    }
                }
            }
        }
        
        // Test 2: Different Accept-Language values
        let languages = ["en-US", "fr-FR", "de-DE", "ja-JP"];
        let mut lang_responses = Vec::new();
        
        for lang in &languages {
            let mut headers = HashMap::new();
            headers.insert("Accept-Language".to_string(), lang.to_string());
            
            let response = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
            lang_responses.push((lang.to_string(), response.body, response.cache_status));
        }
        
        // Check if language-specific content is being cached incorrectly
        for i in 0..lang_responses.len() {
            for j in (i + 1)..lang_responses.len() {
                if lang_responses[i].1 == lang_responses[j].1 {
                    // Same body for different languages
                    if let (Some(cs1), Some(cs2)) = (&lang_responses[i].2, &lang_responses[j].2) {
                        if cs1.contains("HIT") || cs2.contains("HIT") {
                            findings.push(CacheEvidence {
                                url: base_url.to_string(),
                                vulnerability_type: "language_normalization".to_string(),
                                extension_used: format!(
                                    "Accept-Language: {} vs {}",
                                    lang_responses[i].0, lang_responses[j].0
                                ),
                                original_path: base_url.to_string(),
                                edge_headers: HashMap::new(),
                                cache_status: cs1.clone().or_else(|| cs2.clone()).unwrap_or_default(),
                                severity: Severity::Medium,
                                description: format!(
                                    "Different Accept-Language values ({}, {}) returned identical cached content",
                                    lang_responses[i].0, lang_responses[j].0
                                ),
                            });
                        }
                    }
                }
            }
        }
        
        findings
    }

    /// Detect Vary header manipulation attacks
    async fn test_vary_manipulation(&self, base_url: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        // Try to inject fake Vary-related headers
        let fake_headers = [
            ("X-Vary", "Accept"),
            ("Vary-Control", "User-Agent"),
            ("Cache-Vary", "Cookie"),
        ];
        
        for (header, value) in &fake_headers {
            let mut headers = HashMap::new();
            headers.insert(header.to_string(), value.to_string());
            
            let response = self.http_client.get_with_headers(base_url, &headers).await.ok()?;
            
            // Check if the server responds to fake Vary control headers
            if response.headers.contains_key("vary") {
                let new_vary = response.headers.get("vary").unwrap();
                if new_vary.to_lowercase().contains(&value.to_lowercase()) {
                    findings.push(CacheEvidence {
                        url: base_url.to_string(),
                        vulnerability_type: "vary_header_injection".to_string(),
                        extension_used: format!("{}: {}", header, value),
                        original_path: base_url.to_string(),
                        edge_headers: response.headers.clone(),
                        cache_status: response.cache_status.unwrap_or_default(),
                        severity: Severity::High,
                        description: format!(
                            "Server appears to accept {} header to modify Vary behavior",
                            header
                        ),
                    });
                }
            }
        }
        
        findings
    }

    /// Analyze cache key consistency across multiple requests
    async fn analyze_cache_consistency(&self, base_url: &str) -> Vec<String> {
        let mut observations = Vec::new();
        
        // Make multiple identical requests
        let mut cache_statuses = Vec::new();
        for _ in 0..5 {
            let response = self.http_client.get(base_url).await.ok();
            if let Some(r) = response {
                cache_statuses.push(r.cache_status.unwrap_or_default());
            }
        }
        
        // Analyze pattern
        let hit_count = cache_statuses.iter().filter(|s| s.contains("HIT")).count();
        
        if hit_count == 0 {
            observations.push("Content never cached - may have restrictive Cache-Control".to_string());
        } else if hit_count == cache_statuses.len() {
            observations.push("Content always cached from second request".to_string());
        } else {
            observations.push(format!(
                "Inconsistent caching: {} HITs out of {} requests",
                hit_count,
                cache_statuses.len()
            ));
        }
        
        observations
    }
}

#[async_trait::async_trait]
impl CheckModule for VaryAnalysisChecker {
    fn name(&self) -> &'static str {
        "vary_analysis"
    }

    fn description(&self) -> &'static str {
        "Analyzes Vary header handling and detects cache normalization inconsistencies"
    }

    async fn scan(&self, target: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        // Analyze Vary header
        if let Some(evidence) = self.analyze_vary_header(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Configure appropriate Vary headers to ensure proper cache differentiation. \
                              Avoid Vary: * as it disables caching. Include Accept-Encoding at minimum.".to_string(),
            });
        }
        
        // Test normalization behavior
        for evidence in self.test_normalization(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Ensure CDN properly normalizes requests based on Vary header fields. \
                              Configure separate cache entries for different encodings/languages.".to_string(),
            });
        }
        
        // Test Vary manipulation
        for evidence in self.test_vary_manipulation(target).await {
            results.push(CheckResult {
                check_name: self.name(),
                severity: evidence.severity,
                finding: evidence.description,
                evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                remediation: "Do not allow client-controlled headers to modify Vary behavior. \
                              Strip unknown Vary-related headers at the edge.".to_string(),
            });
        }
        
        results
    }

    fn supported_checks(&self) -> Vec<&'static str> {
        vec![
            "vary_analysis",
            "vary_header_validation",
            "cache_normalization",
            "encoding_differentiation",
            "language_differentiation",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_vary_values_defined() {
        assert!(!STANDARD_VARY_VALUES.is_empty());
        assert!(STANDARD_VARY_VALUES.contains(&"Accept-Encoding"));
    }

    #[test]
    fn test_problematic_vary_patterns_defined() {
        assert!(!PROBLEMATIC_VARY_PATTERNS.is_empty());
        assert!(PROBLEMATIC_VARY_PATTERNS.contains(&"*"));
    }

    #[test]
    fn test_parse_vary_header() {
        let checker = VaryAnalysisChecker {
            http_client: HttpClient::default(),
        };
        
        let parsed = checker.parse_vary_header("Accept, Accept-Encoding, Host");
        assert!(parsed.contains("accept"));
        assert!(parsed.contains("accept-encoding"));
        assert!(parsed.contains("host"));
    }
}
