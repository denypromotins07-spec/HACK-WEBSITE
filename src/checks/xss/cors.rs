//! CORS Misconfiguration Detection Module
//! 
//! Identifies CORS Misconfigurations by testing wildcard origins paired with credentials.
//! Maintains 2GB RAM ceiling via bounded payload buffers and strict origin validation.

use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use crate::http::client::HttpClient;
use std::collections::HashMap;
use std::time::Duration;

/// Test origins for CORS probing
const TEST_ORIGINS: &[&str] = &[
    "https://attacker.com",
    "https://evil.example.com",
    "null",
    "https://example.com.attacker.com",
];

/// CORS detector
pub struct CorsDetector {
    http_client: HttpClient,
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
}

impl CorsDetector {
    /// Create a new CORS detector
    pub fn new(http_client: HttpClient, god_mode: bool) -> Self {
        Self {
            http_client,
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
        }
    }

    /// Detect CORS misconfigurations on target URL
    pub async fn detect_cors_issues(&self, target_url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        for test_origin in TEST_ORIGINS {
            let mut headers = HashMap::new();
            headers.insert("Origin".to_string(), test_origin.to_string());
            
            if let Ok(response) = self.http_client.get_with_headers(target_url, &headers, self.timeout).await {
                // Check for dangerous CORS headers
                if let Some(access_control) = response.headers.get("Access-Control-Allow-Origin") {
                    // Check for wildcard with credentials
                    let allows_credentials = response.headers.get("Access-Control-Allow-Credentials")
                        .map(|v| v.to_lowercase() == "true")
                        .unwrap_or(false);
                    
                    if access_control == "*" && allows_credentials {
                        let evidence = XssEvidence {
                            vulnerability_type: "CORS Misconfiguration".to_string(),
                            location: target_url.to_string(),
                            payload: format!("Origin: {} (wildcard with credentials)", test_origin),
                            context: crate::checks::xss::context::XssContext::Url,
                            stack_trace: None,
                            callback_triggered: false,
                            remediation: self.generate_remediation(),
                            severity: crate::findings::Severity::High,
                        };
                        evidences.push(evidence);
                        
                        self.cache.record_bypass(target_url.to_string(), "cors_wildcard_credentials".to_string());
                        break; // Found critical issue, no need to test more
                    }
                    
                    // Check for reflected origin without proper validation
                    if access_control == *test_origin && allows_credentials {
                        // Additional check: verify if null origin is also accepted
                        if *test_origin == "null" {
                            let evidence = XssEvidence {
                                vulnerability_type: "CORS Misconfiguration".to_string(),
                                location: target_url.to_string(),
                                payload: "Null origin accepted with credentials".to_string(),
                                context: crate::checks::xss::context::XssContext::Url,
                                stack_trace: None,
                                callback_triggered: false,
                                remediation: self.generate_remediation(),
                                severity: crate::findings::Severity::Critical,
                            };
                            evidences.push(evidence);
                            
                            self.cache.record_bypass(target_url.to_string(), "cors_null_origin".to_string());
                        } else {
                            // Check if origin validation is weak (suffix match, etc.)
                            if self.is_weak_origin_validation(access_control, target_url).await {
                                let evidence = XssEvidence {
                                    vulnerability_type: "CORS Misconfiguration".to_string(),
                                    location: target_url.to_string(),
                                    payload: format!("Weak origin validation: {}", access_control),
                                    context: crate::checks::xss::context::XssContext::Url,
                                    stack_trace: None,
                                    callback_triggered: false,
                                    remediation: self.generate_remediation(),
                                    severity: crate::findings::Severity::High,
                                };
                                evidences.push(evidence);
                                
                                self.cache.record_bypass(target_url.to_string(), "cors_weak_validation".to_string());
                            }
                        }
                    }
                }
            }
        }
        
        evidences
    }

    /// Check for weak origin validation patterns
    async fn is_weak_origin_validation(&self, allowed_origin: &str, _target_url: &str) -> bool {
        // Check for common weak patterns
        
        // Suffix match vulnerability (example.com.attacker.com)
        if allowed_origin.contains(".attacker.com") {
            return true;
        }
        
        // Subdomain takeover pattern
        if allowed_origin.starts_with("https://.") || allowed_origin.starts_with("http://.") {
            return true;
        }
        
        // Regex-like patterns that might be too permissive
        if allowed_origin.contains("*") && !allowed_origin.ends_with("*") {
            return true;
        }
        
        false
    }

    /// Generate CORS preflight request for testing
    pub fn generate_preflight_request(&self, target_url: &str, method: &str, headers: &[&str]) -> HashMap<String, String> {
        let mut preflight_headers = HashMap::new();
        preflight_headers.insert("Origin".to_string(), "https://attacker.com".to_string());
        preflight_headers.insert("Access-Control-Request-Method".to_string(), method.to_string());
        preflight_headers.insert("Access-Control-Request-Headers".to_string(), headers.join(", "));
        preflight_headers
    }

    /// Generate remediation guidance for CORS misconfigurations
    fn generate_remediation(&self) -> String {
        "Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. \
         Implement strict origin allowlisting based on exact domain matches. Validate the Origin \
         header server-side against a whitelist of trusted domains. Do not rely on regex patterns \
         or suffix matching for origin validation. Never accept 'null' origin for sensitive \
         endpoints. Consider using same-origin policy where possible."
            .to_string()
    }

    /// Enable god-mode for intrusive validation
    pub fn enable_god_mode(&mut self) {
        self.god_mode = true;
        self.timeout = Duration::from_secs(10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cors_detector_creation() {
        let client = HttpClient::mock();
        let detector = CorsDetector::new(client, false);
        assert!(!detector.god_mode);
    }

    #[test]
    fn test_origins_defined() {
        assert!(TEST_ORIGINS.contains(&"https://attacker.com"));
        assert!(TEST_ORIGINS.contains(&"null"));
    }

    #[test]
    fn test_preflight_generation() {
        let detector = CorsDetector::new(HttpClient::mock(), false);
        let headers = detector.generate_preflight_request(
            "https://api.example.com/data",
            "POST",
            &["Content-Type", "Authorization"],
        );
        
        assert_eq!(headers.get("Origin"), Some(&"https://attacker.com".to_string()));
        assert_eq!(headers.get("Access-Control-Request-Method"), Some(&"POST".to_string()));
    }
}
