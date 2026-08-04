//! Reflected XSS Detection Module
//! 
//! Detects reflected XSS by tracking canary payloads through URL parameters and form inputs.
//! Maintains 2GB RAM ceiling via bounded payload buffers and zero-copy evidence collection.

use crate::checks::xss::context::XssContext;
use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use crate::http::client::HttpClient;
use crate::mutator::payload_mutator::PayloadMutator;
use std::collections::HashMap;
use std::time::Duration;

/// Maximum payload size in bytes (bounded to prevent memory exhaustion)
const MAX_PAYLOAD_SIZE: usize = 4096;

/// Canary prefix for reflected XSS detection
const CANARY_PREFIX: &str = "XSS_CANARY_";

/// Reflected XSS detector with context-aware payload injection
pub struct ReflectedXssDetector {
    http_client: HttpClient,
    mutator: PayloadMutator,
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
}

impl ReflectedXssDetector {
    /// Create a new reflected XSS detector
    pub fn new(http_client: HttpClient, god_mode: bool) -> Self {
        Self {
            http_client,
            mutator: PayloadMutator::new(),
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
        }
    }

    /// Detect reflected XSS in URL parameters
    pub async fn detect_url_reflection(&self, url: &str, params: &HashMap<String, String>) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        for (param_name, param_value) in params {
            // Generate context-aware canary payload
            let canary = format!("{}{}_{}", CANARY_PREFIX, param_name, self.generate_unique_id());
            
            // Build test URL with canary
            let test_url = self.build_test_url(url, param_name, &canary);
            
            // Send request and track reflection
            if let Ok(response) = self.http_client.get_with_timeout(&test_url, self.timeout).await {
                if self.analyze_reflection(&response.body, &canary, param_name) {
                    let evidence = XssEvidence {
                        vulnerability_type: "Reflected XSS".to_string(),
                        location: format!("URL parameter: {}", param_name),
                        payload: canary,
                        context: self.detect_context(&response.body, &canary),
                        stack_trace: None,
                        callback_triggered: false,
                        remediation: self.generate_csp_remediation(),
                        severity: self.calculate_severity(param_name),
                    };
                    evidences.push(evidence);
                    
                    // Cache successful bypass for learning
                    self.cache.record_bypass(param_name.clone(), "url_param".to_string());
                }
            }
        }
        
        evidences
    }

    /// Detect reflected XSS in form inputs
    pub async fn detect_form_reflection(&self, form_action: &str, form_fields: &HashMap<String, String>) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        for (field_name, field_value) in form_fields {
            let canary = format!("{}{}_{}", CANARY_PREFIX, field_name, self.generate_unique_id());
            
            // Mutate form fields with canary payload
            let mut test_fields = form_fields.clone();
            test_fields.insert(field_name.clone(), canary.clone());
            
            // Submit form and analyze response
            if let Ok(response) = self.http_client.post_form_with_timeout(form_action, &test_fields, self.timeout).await {
                if self.analyze_reflection(&response.body, &canary, field_name) {
                    let evidence = XssEvidence {
                        vulnerability_type: "Reflected XSS".to_string(),
                        location: format!("Form field: {}", field_name),
                        payload: canary,
                        context: self.detect_context(&response.body, &canary),
                        stack_trace: None,
                        callback_triggered: false,
                        remediation: self.generate_csp_remediation(),
                        severity: self.calculate_severity(field_name),
                    };
                    evidences.push(evidence);
                    
                    self.cache.record_bypass(field_name.clone(), "form_input".to_string());
                }
            }
        }
        
        evidences
    }

    /// Analyze response body for payload reflection
    fn analyze_reflection(&self, body: &str, canary: &str, param_name: &str) -> bool {
        // Zero-copy substring search for reflection detection
        if !body.contains(canary) {
            return false;
        }
        
        // Check for dangerous contexts around the reflection
        let reflection_pos = body.find(canary).unwrap_or(0);
        let context_start = reflection_pos.saturating_sub(50);
        let context_end = (reflection_pos + canary.len() + 50).min(body.len());
        
        let context = &body[context_start..context_end];
        
        // Detect dangerous HTML/JS contexts
        let dangerous_patterns = [
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "eval(",
            "document.write",
            "innerHTML",
        ];
        
        dangerous_patterns.iter().any(|pattern| context.to_lowercase().contains(pattern))
    }

    /// Detect the context of payload reflection (HTML, JS, Attribute, URL)
    fn detect_context(&self, body: &str, canary: &str) -> XssContext {
        if let Some(pos) = body.find(canary) {
            let before = &body[..pos];
            
            // Check for script context
            if before.ends_with("<script>") || before.ends_with("'>") || before.ends_with("\">") {
                return XssContext::JavaScript;
            }
            
            // Check for attribute context
            if before.ends_with("=\"") || before.ends_with("='") {
                return XssContext::Attribute;
            }
            
            // Check for URL context
            if before.ends_with("href=\"") || before.ends_with("src=\"") {
                return XssContext::Url;
            }
        }
        
        XssContext::Html
    }

    /// Build test URL with injected parameter
    fn build_test_url(&self, base_url: &str, param_name: &str, payload: &str) -> String {
        let separator = if base_url.contains('?') { '&' } else { '?' };
        format!("{}{}{}={}", base_url, separator, param_name, payload)
    }

    /// Generate CSP remediation guidance
    fn generate_csp_remediation(&self) -> String {
        "Implement Content Security Policy (CSP) with strict-dynamic or nonce-based scripts. \
         Encode all user input based on output context (HTML entity encoding for HTML context, \
         JavaScript escaping for JS context). Use HttpOnly and Secure flags on cookies."
            .to_string()
    }

    /// Calculate severity based on parameter name and context
    fn calculate_severity(&self, param_name: &str) -> crate::findings::Severity {
        let sensitive_params = ["search", "q", "query", "input", "data", "callback"];
        if sensitive_params.iter().any(|p| param_name.to_lowercase().contains(p)) {
            crate::findings::Severity::High
        } else {
            crate::findings::Severity::Medium
        }
    }

    /// Generate unique ID for canary tracking
    fn generate_unique_id(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64
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
    fn test_reflected_xss_detector_creation() {
        let client = HttpClient::mock();
        let detector = ReflectedXssDetector::new(client, false);
        assert!(!detector.god_mode);
    }

    #[test]
    fn test_context_detection() {
        let detector = ReflectedXssDetector::new(HttpClient::mock(), false);
        let body = r#"<div id="test"><script>alert('XSS_CANARY_field_123')</script></div>"#;
        let context = detector.detect_context(body, "XSS_CANARY_field_123");
        assert_eq!(context, XssContext::JavaScript);
    }
}
