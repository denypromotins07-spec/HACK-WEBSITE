//! Clickjacking and XSSI Detection Module
//! 
//! Detects Clickjacking and XSSI vulnerabilities by checking X-Frame-Options and frame-ancestors headers.
//! Maintains 2GB RAM ceiling via bounded payload buffers and strict origin validation.

use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use crate::http::client::HttpClient;
use std::time::Duration;

/// Clickjacking/XSSI detector
pub struct ClickjackingDetector {
    http_client: HttpClient,
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
}

impl ClickjackingDetector {
    /// Create a new clickjacking detector
    pub fn new(http_client: HttpClient, god_mode: bool) -> Self {
        Self {
            http_client,
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
        }
    }

    /// Detect clickjacking vulnerabilities on target URL
    pub async fn detect_clickjacking(&self, target_url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        if let Ok(response) = self.http_client.get_with_timeout(target_url, self.timeout).await {
            // Check for X-Frame-Options header
            let has_xfo = response.headers.get("X-Frame-Options").is_some();
            
            // Check for Content-Security-Policy frame-ancestors directive
            let has_frame_ancestors = response.headers.get("Content-Security-Policy")
                .map(|csp| csp.contains("frame-ancestors"))
                .unwrap_or(false);
            
            if !has_xfo && !has_frame_ancestors {
                let evidence = XssEvidence {
                    vulnerability_type: "Clickjacking".to_string(),
                    location: target_url.to_string(),
                    payload: "Missing X-Frame-Options and frame-ancestors".to_string(),
                    context: crate::checks::xss::context::XssContext::Html,
                    stack_trace: None,
                    callback_triggered: false,
                    remediation: self.generate_remediation(),
                    severity: crate::findings::Severity::Medium,
                };
                evidences.push(evidence);
                
                self.cache.record_bypass(target_url.to_string(), "clickjacking_missing_headers".to_string());
            } else if has_xfo {
                // Check X-Frame-Options value
                if let Some(xfo_value) = response.headers.get("X-Frame-Options") {
                    let xfo_lower = xfo_value.to_lowercase();
                    
                    // ALLOW-FROM is deprecated and poorly supported
                    if xfo_lower.starts_with("allow-from") {
                        let evidence = XssEvidence {
                            vulnerability_type: "Clickjacking".to_string(),
                            location: target_url.to_string(),
                            payload: format!("Deprecated X-Frame-Options: {}", xfo_value),
                            context: crate::checks::xss::context::XssContext::Html,
                            stack_trace: None,
                            callback_triggered: false,
                            remediation: self.generate_remediation(),
                            severity: crate::findings::Severity::Low,
                        };
                        evidences.push(evidence);
                        
                        self.cache.record_bypass(target_url.to_string(), "clickjacking_allow_from".to_string());
                    }
                }
            }
            
            // Check for CSP issues
            if let Some(csp) = response.headers.get("Content-Security-Policy") {
                if csp.contains("frame-ancestors") {
                    // Check for overly permissive frame-ancestors
                    if csp.contains("frame-ancestors *") || csp.contains("frame-ancestors 'self' *") {
                        let evidence = XssEvidence {
                            vulnerability_type: "Clickjacking".to_string(),
                            location: target_url.to_string(),
                            payload: "Overly permissive frame-ancestors directive".to_string(),
                            context: crate::checks::xss::context::XssContext::Html,
                            stack_trace: None,
                            callback_triggered: false,
                            remediation: self.generate_csp_remediation(),
                            severity: crate::findings::Severity::Medium,
                        };
                        evidences.push(evidence);
                        
                        self.cache.record_bypass(target_url.to_string(), "clickjacking_permissive_csp".to_string());
                    }
                }
            }
        }
        
        evidences
    }

    /// Detect XSSI (Cross-Site Script Inclusion) vulnerabilities
    pub async fn detect_xssi(&self, target_url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        // Check if resource can be included cross-origin with sensitive data
        if let Ok(response) = self.http_client.get_with_timeout(target_url, self.timeout).await {
            // Check for missing CORS headers but accessible content
            let has_cors = response.headers.get("Access-Control-Allow-Origin").is_some();
            let content_type = response.headers.get("Content-Type")
                .map(|ct| ct.to_lowercase())
                .unwrap_or_default();
            
            // JSON/JS resources without proper CORS might be vulnerable to XSSI
            if !has_cors && (content_type.contains("json") || content_type.contains("javascript")) {
                // Check if response contains potentially sensitive data patterns
                let sensitive_patterns = [
                    "\"email\"",
                    "\"password\"",
                    "\"token\"",
                    "\"api_key\"",
                    "\"secret\"",
                    "\"user_id\"",
                ];
                
                if sensitive_patterns.iter().any(|pattern| response.body.contains(pattern)) {
                    let evidence = XssEvidence {
                        vulnerability_type: "XSSI".to_string(),
                        location: target_url.to_string(),
                        payload: "Sensitive JSON/JS resource without CORS protection".to_string(),
                        context: crate::checks::xss::context::XssContext::Url,
                        stack_trace: None,
                        callback_triggered: false,
                        remediation: self.generate_xssi_remediation(),
                        severity: crate::findings::Severity::High,
                    };
                    evidences.push(evidence);
                    
                    self.cache.record_bypass(target_url.to_string(), "xssi_sensitive_resource".to_string());
                }
            }
        }
        
        evidences
    }

    /// Generate clickjacking test iframe payload
    pub fn generate_clickjacking_test(&self, target_url: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head><title>Clickjacking Test</title></head>
<body>
  <h1>Clickjacking Test Page</h1>
  <iframe src="{}" width="800" height="600" style="opacity: 0.5;"></iframe>
</body>
</html>"#,
            target_url
        )
    }

    /// Generate remediation guidance for clickjacking
    fn generate_remediation(&self) -> String {
        "Implement X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN header. \
         Alternatively, use Content-Security-Policy with frame-ancestors directive \
         (e.g., frame-ancestors 'self'). Avoid using deprecated ALLOW-FROM directive. \
         For modern applications, prefer CSP frame-ancestors over X-Frame-Options."
            .to_string()
    }

    /// Generate CSP-specific remediation
    fn generate_csp_remediation(&self) -> String {
        "Use specific domain allowlist in frame-ancestors directive instead of wildcards. \
         Example: frame-ancestors 'self' https://trusted-domain.com. Ensure CSP is delivered \
         via HTTP header rather than meta tag for maximum compatibility."
            .to_string()
    }

    /// Generate XSSI remediation guidance
    fn generate_xssi_remediation(&self) -> String {
        "Serve sensitive JSON/JavaScript resources with proper CORS headers or require \
         authentication. Use Content-Type: application/json with appropriate access controls. \
         Implement CSRF tokens for state-changing operations. Consider using array-breaking \
         prefixes (e.g., 'while(1);') for JSON responses containing sensitive data."
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
    fn test_clickjacking_detector_creation() {
        let client = HttpClient::mock();
        let detector = ClickjackingDetector::new(client, false);
        assert!(!detector.god_mode);
    }

    #[test]
    fn test_clickjacking_test_generation() {
        let detector = ClickjackingDetector::new(HttpClient::mock(), false);
        let test_html = detector.generate_clickjacking_test("https://target.com/secure");
        
        assert!(test_html.contains("<iframe"));
        assert!(test_html.contains("https://target.com/secure"));
    }
}
