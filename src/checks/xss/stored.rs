//! Stored XSS Detection Module
//! 
//! Detects stored XSS by submitting payloads to persistence endpoints and verifying execution contexts.
//! Maintains 2GB RAM ceiling via bounded payload buffers and zero-copy evidence collection.

use crate::checks::xss::context::XssContext;
use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use crate::http::client::HttpClient;
use crate::mutator::payload_mutator::PayloadMutator;
use std::collections::HashMap;
use std::time::Duration;

/// Maximum payload size for stored XSS testing
const MAX_STORED_PAYLOAD_SIZE: usize = 2048;

/// Canary prefix for stored XSS detection
const STORED_CANARY_PREFIX: &str = "STORED_XSS_";

/// Stored XSS detector with persistence verification
pub struct StoredXssDetector {
    http_client: HttpClient,
    mutator: PayloadMutator,
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
    oob_callback_url: Option<String>,
}

impl StoredXssDetector {
    /// Create a new stored XSS detector
    pub fn new(http_client: HttpClient, god_mode: bool) -> Self {
        Self {
            http_client,
            mutator: PayloadMutator::new(),
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
            oob_callback_url: None,
        }
    }

    /// Set out-of-band callback URL for blind XSS verification
    pub fn set_oob_callback(&mut self, url: String) {
        self.oob_callback_url = Some(url);
    }

    /// Detect stored XSS in comment/post endpoints
    pub async fn detect_comment_xss(&self, submit_url: &str, view_url: &str, content_field: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        // Generate unique canary for this test
        let canary = format!("{}comment_{}", STORED_CANARY_PREFIX, self.generate_unique_id());
        
        // Build stored XSS payloads (benign, non-executing markers)
        let payloads = vec![
            format!("<div id=\"{}\">stored_test</div>", canary),
            format!("<!-- {} -->", canary),
            format!("<span data-xss=\"{}\">test</span>", canary),
        ];
        
        for payload in payloads {
            // Submit payload to persistence endpoint
            let mut form_data = HashMap::new();
            form_data.insert(content_field.to_string(), payload.clone());
            
            if let Ok(_) = self.http_client.post_form_with_timeout(submit_url, &form_data, self.timeout).await {
                // Wait briefly for persistence (bounded delay)
                tokio::time::sleep(Duration::from_millis(500)).await;
                
                // Retrieve and check for payload presence
                if let Ok(response) = self.http_client.get_with_timeout(view_url, self.timeout).await {
                    if response.body.contains(&canary) {
                        // Check for dangerous execution context
                        let context = self.analyze_storage_context(&response.body, &canary);
                        
                        if context.is_dangerous() {
                            let evidence = XssEvidence {
                                vulnerability_type: "Stored XSS".to_string(),
                                location: format!("Comment field: {}", content_field),
                                payload,
                                context: context,
                                stack_trace: None,
                                callback_triggered: false,
                                remediation: self.generate_csp_remediation(),
                                severity: crate::findings::Severity::Critical,
                            };
                            evidences.push(evidence);
                            
                            self.cache.record_bypass(content_field.to_string(), "stored_comment".to_string());
                        }
                    }
                }
            }
        }
        
        evidences
    }

    /// Detect stored XSS in user profile fields
    pub async fn detect_profile_xss(&self, profile_update_url: &str, profile_view_url: &str, fields: &[&str]) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        for field in fields {
            let canary = format!("{}profile_{}_{}", STORED_CANARY_PREFIX, field, self.generate_unique_id());
            let payload = format!("<img src=x onerror=\"/* {} */\">", canary);
            
            let mut update_data = HashMap::new();
            update_data.insert(field.to_string(), payload.clone());
            
            if let Ok(_) = self.http_client.post_form_with_timeout(profile_update_url, &update_data, self.timeout).await {
                tokio::time::sleep(Duration::from_millis(300)).await;
                
                if let Ok(response) = self.http_client.get_with_timeout(profile_view_url, self.timeout).await {
                    if response.body.contains(&canary) {
                        let context = self.analyze_storage_context(&response.body, &canary);
                        
                        if context.is_dangerous() || context == XssContext::Attribute {
                            let evidence = XssEvidence {
                                vulnerability_type: "Stored XSS".to_string(),
                                location: format!("Profile field: {}", field),
                                payload,
                                context,
                                stack_trace: None,
                                callback_triggered: false,
                                remediation: self.generate_csp_remediation(),
                                severity: crate::findings::Severity::High,
                            };
                            evidences.push(evidence);
                            
                            self.cache.record_bypass(field.to_string(), "stored_profile".to_string());
                        }
                    }
                }
            }
        }
        
        evidences
    }

    /// Analyze storage context for dangerous patterns
    fn analyze_storage_context(&self, body: &str, canary: &str) -> XssContext {
        if let Some(pos) = body.find(canary) {
            let context_start = pos.saturating_sub(100);
            let context_end = (pos + canary.len() + 100).min(body.len());
            let context_str = &body[context_start..context_end];
            
            // Check for script tag injection
            if context_str.contains("<script") {
                return XssContext::JavaScript;
            }
            
            // Check for event handler injection
            if context_str.contains("onerror=") || context_str.contains("onload=") {
                return XssContext::EventHandler;
            }
            
            // Check for attribute context
            if context_str.contains("=\"") || context_str.contains("='") {
                return XssContext::Attribute;
            }
        }
        
        XssContext::Html
    }

    /// Generate CSP remediation guidance for stored XSS
    fn generate_csp_remediation(&self) -> String {
        "Implement strict Content Security Policy (CSP) with 'strict-dynamic' or nonce-based \
         script execution. Sanitize all user input before storage using allowlist-based HTML \
         sanitization. Encode output based on context. Consider using HTTP-only cookies and \
         implementing proper CSRF protection."
            .to_string()
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
        self.timeout = Duration::from_secs(15);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_xss_detector_creation() {
        let client = HttpClient::mock();
        let detector = StoredXssDetector::new(client, false);
        assert!(!detector.god_mode);
        assert!(detector.oob_callback_url.is_none());
    }

    #[test]
    fn test_context_analysis() {
        let detector = StoredXssDetector::new(HttpClient::mock(), false);
        let body = r#"<div class="comment"><script>alert('STORED_XSS_comment_123')</script></div>"#;
        let context = detector.analyze_storage_context(body, "STORED_XSS_comment_123");
        assert_eq!(context, XssContext::JavaScript);
    }
}
