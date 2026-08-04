//! Path Confusion Detection Module
//! Tests path confusion using .css/.js suffixes, semicolons, and encoded delimiters.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::findings::cache_evidence::CacheEvidence;
use crate::http_client::HttpClient;

/// Path confusion techniques to test
const PATH_CONFUSION_TECHNIQUES: &[(&str, &str)] = &[
    // Suffix-based confusion
    ("/admin", "/admin.css"),
    ("/admin", "/admin.js"),
    ("/user/profile", "/user/profile.css"),
    ("/user/profile", "/user/profile.js"),
    
    // Semicolon-based path truncation
    ("/admin/secret", "/admin/secret;.css"),
    ("/api/user", "/api/user;.js"),
    
    // Encoded delimiter variations
    ("/admin", "/admin%2f.css"),
    ("/admin", "/admin%5c.css"),
    ("/admin", "/admin%00.css"),
    
    // Double encoding
    ("/admin", "/admin%252f.css"),
    ("/admin", "/admin%255c.js"),
    
    // Null byte injection (historical but still relevant)
    ("/config", "/config%00.css"),
    
    // Backslash variations (Windows-style)
    ("/admin", "/admin\\.css"),
    ("/admin", "/admin\\\\.js"),
];

/// Headers that may indicate cache behavior differences
const CACHE_INDICATOR_HEADERS: &[&str] = &[
    "x-cache", "x-cache-hits", "x-served-by", "via", "age",
    "cf-cache-status", "x-amz-cf-id", "x-varnish", "fastly-cache-status",
];

pub struct PathConfusionChecker {
    http_client: HttpClient,
}

impl PathConfusionChecker {
    pub fn new(http_client: HttpClient) -> Self {
        Self { http_client }
    }

    /// Test a specific path confusion technique
    async fn test_confusion(
        &self,
        base_url: &str,
        original_path: &str,
        confused_path: &str,
    ) -> Option<CacheEvidence> {
        let target_url = format!("{}{}", base_url, confused_path);
        
        // Make request with confused path
        let response = self.http_client.get(&target_url).await.ok()?;
        
        // Check if response indicates successful content retrieval
        if response.status == 200 && !response.body.is_empty() {
            // Compare with expected behavior for the original path
            let original_url = format!("{}{}", base_url, original_path);
            let original_response = self.http_client.get(&original_url).await.ok()?;
            
            // If confused path returns same content as original, potential vulnerability
            if response.body == original_response.body {
                let cache_indicators = self.extract_cache_indicators(&response.headers);
                
                return Some(CacheEvidence {
                    url: target_url,
                    vulnerability_type: "path_confusion".to_string(),
                    extension_used: confused_path.replace(original_path, "").to_string(),
                    original_path: original_path.to_string(),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: if cache_indicators.iter().any(|h| h.contains("HIT")) {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    description: format!(
                        "Path confusion detected: {} returns same content as {} (technique: {})",
                        confused_path, original_path,
                        self.identify_technique(confused_path)
                    ),
                });
            }
        }
        
        None
    }

    /// Extract cache-related headers from response
    fn extract_cache_indicators(&self, headers: &std::collections::HashMap<String, String>) -> Vec<String> {
        CACHE_INDICATOR_HEADERS
            .iter()
            .filter_map(|h| headers.get(*h).map(|v| format!("{}: {}", h, v)))
            .collect()
    }

    /// Identify which confusion technique was used
    fn identify_technique(&self, path: &str) -> &'static str {
        if path.contains(";") {
            "semicolon_truncation"
        } else if path.contains("%2f") || path.contains("%5c") {
            "encoded_delimiter"
        } else if path.contains("%00") {
            "null_byte_injection"
        } else if path.contains("%25") {
            "double_encoding"
        } else if path.contains("\\\\") || path.contains("\\.") {
            "backslash_variation"
        } else if path.ends_with(".css") || path.ends_with(".js") {
            "suffix_abuse"
        } else {
            "unknown"
        }
    }

    /// Test semicolon-based path truncation specifically
    async fn test_semicolon_truncation(&self, base_url: &str, path: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        for ext in [".css", ".js", ".png", ".jpg"] {
            let confused = format!("{};{}", path, ext);
            if let Some(evidence) = self.test_confusion(base_url, path, &confused).await {
                findings.push(evidence);
            }
        }
        
        findings
    }

    /// Test encoded delimiter variations
    async fn test_encoded_delimiters(&self, base_url: &str, path: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        let encodings = ["%2f", "%5c", "%2e", "%00"];
        for ext in [".css", ".js"] {
            for encoding in &encodings {
                let confused = format!("{}{}{}", path, encoding, ext);
                if let Some(evidence) = self.test_confusion(base_url, path, &confused).await {
                    findings.push(evidence);
                }
            }
        }
        
        findings
    }
}

#[async_trait::async_trait]
impl CheckModule for PathConfusionChecker {
    fn name(&self) -> &'static str {
        "path_confusion"
    }

    fn description(&self) -> &'static str {
        "Detects path confusion vulnerabilities using suffix manipulation, semicolons, and encoded delimiters"
    }

    async fn scan(&self, target: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        let paths_to_test = ["/admin", "/api/user", "/config", "/dashboard", "/settings"];
        
        for path in &paths_to_test {
            // Test all predefined techniques
            for (original, confused) in PATH_CONFUSION_TECHNIQUES {
                if *original == *path {
                    if let Some(evidence) = self.test_confusion(target, original, confused).await {
                        results.push(CheckResult {
                            check_name: self.name(),
                            severity: evidence.severity,
                            finding: evidence.description,
                            evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                            remediation: "Normalize URL paths before caching. Reject requests with \
                                          unusual path characters or encoding. Configure CDN to \
                                          ignore file extensions when determining cacheability.".to_string(),
                        });
                    }
                }
            }
            
            // Additional targeted tests
            for evidence in self.test_semicolon_truncation(target, path).await {
                results.push(CheckResult {
                    check_name: self.name(),
                    severity: evidence.severity,
                    finding: evidence.description,
                    evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                    remediation: "Strip semicolons and content after them from URLs before processing.".to_string(),
                });
            }
            
            for evidence in self.test_encoded_delimiters(target, path).await {
                results.push(CheckResult {
                    check_name: self.name(),
                    severity: evidence.severity,
                    finding: evidence.description,
                    evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                    remediation: "Decode URLs completely before path matching. Reject double-encoded paths.".to_string(),
                });
            }
        }
        
        results
    }

    fn supported_checks(&self) -> Vec<&'static str> {
        vec![
            "path_confusion",
            "semicolon_truncation",
            "encoded_delimiter_abuse",
            "null_byte_injection",
            "double_encoding",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_confusion_techniques_defined() {
        assert!(!PATH_CONFUSION_TECHNIQUES.is_empty());
    }

    #[test]
    fn test_identify_technique() {
        let checker = PathConfusionChecker {
            http_client: HttpClient::default(),
        };
        
        assert_eq!(checker.identify_technique("/admin;.css"), "semicolon_truncation");
        assert_eq!(checker.identify_technique("/admin%2f.css"), "encoded_delimiter");
        assert_eq!(checker.identify_technique("/admin%00.css"), "null_byte_injection");
    }
}
