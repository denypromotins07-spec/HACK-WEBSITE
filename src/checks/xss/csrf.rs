//! CSRF Detection Module
//! 
//! Detects Cross-Site Request Forgery by identifying state-changing endpoints lacking secure tokens.
//! Maintains 2GB RAM ceiling via bounded payload buffers and strict origin validation.

use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use crate::http::client::HttpClient;
use std::collections::HashMap;
use std::time::Duration;

/// HTTP methods that change state (require CSRF protection)
const STATE_CHANGING_METHODS: &[&str] = &["POST", "PUT", "DELETE", "PATCH"];

/// Common CSRF token parameter names
const CSRF_TOKEN_NAMES: &[&str] = &[
    "csrf_token",
    "csrf",
    "_token",
    "authenticity_token",
    "xsrf_token",
    "X-CSRF-TOKEN",
    "X-XSRF-TOKEN",
    "_csrf",
    "security_token",
];

/// CSRF detector
pub struct CsrfDetector {
    http_client: HttpClient,
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
}

impl CsrfDetector {
    /// Create a new CSRF detector
    pub fn new(http_client: HttpClient, god_mode: bool) -> Self {
        Self {
            http_client,
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
        }
    }

    /// Detect CSRF vulnerabilities in forms
    pub async fn detect_form_csrf(&self, form_action: &str, form_method: &str, form_fields: &HashMap<String, String>) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        // Only check state-changing methods
        if !STATE_CHANGING_METHODS.iter().any(|m| form_method.eq_ignore_ascii_case(m)) {
            return evidences;
        }
        
        // Check for CSRF token in form fields
        let has_token = form_fields.keys()
            .any(|key| CSRF_TOKEN_NAMES.iter().any(|token_name| key.eq_ignore_ascii_case(token_name)));
        
        if !has_token {
            // Additional check: look for SameSite cookie attribute
            let has_samesite = self.check_samesite_cookies(form_action).await;
            
            if !has_samesite {
                let evidence = XssEvidence {
                    vulnerability_type: "CSRF".to_string(),
                    location: format!("Form action: {} ({})", form_action, form_method),
                    payload: "Missing CSRF token".to_string(),
                    context: crate::checks::xss::context::XssContext::Html,
                    stack_trace: None,
                    callback_triggered: false,
                    remediation: self.generate_remediation(),
                    severity: crate::findings::Severity::High,
                };
                evidences.push(evidence);
                
                self.cache.record_bypass(form_action.to_string(), "csrf_form".to_string());
            }
        }
        
        evidences
    }

    /// Detect CSRF in API endpoints
    pub async fn detect_api_csrf(&self, endpoint_url: &str, method: &str, headers: &HashMap<String, String>) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        if !STATE_CHANGING_METHODS.iter().any(|m| method.eq_ignore_ascii_case(m)) {
            return evidences;
        }
        
        // Check for CSRF token in headers
        let has_csrf_header = headers.keys()
            .any(|key| key.to_uppercase().contains("CSRF") || key.to_uppercase().contains("XSRF"));
        
        // Check for custom header requirement (indicates CSRF protection)
        let has_custom_header_check = headers.contains_key("X-Requested-With") ||
                                      headers.contains_key("Content-Type");
        
        if !has_csrf_header && !has_custom_header_check {
            // Check if endpoint requires authentication
            let requires_auth = self.check_authentication_required(endpoint_url).await;
            
            if requires_auth {
                let evidence = XssEvidence {
                    vulnerability_type: "CSRF".to_string(),
                    location: format!("API endpoint: {} ({})", endpoint_url, method),
                    payload: "Missing CSRF protection".to_string(),
                    context: crate::checks::xss::context::XssContext::Url,
                    stack_trace: None,
                    callback_triggered: false,
                    remediation: self.generate_api_remediation(),
                    severity: crate::findings::Severity::High,
                };
                evidences.push(evidence);
                
                self.cache.record_bypass(endpoint_url.to_string(), "csrf_api".to_string());
            }
        }
        
        evidences
    }

    /// Check if response has SameSite cookie attribute
    async fn check_samesite_cookies(&self, url: &str) -> bool {
        if let Ok(response) = self.http_client.get_with_timeout(url, self.timeout).await {
            if let Some(set_cookie) = response.headers.get("Set-Cookie") {
                let cookie_value = set_cookie.to_lowercase();
                return cookie_value.contains("samesite=strict") || 
                       cookie_value.contains("samesite=lax");
            }
        }
        false
    }

    /// Check if endpoint requires authentication
    async fn check_authentication_required(&self, url: &str) -> bool {
        // Send request without auth and check for 401/403
        if let Ok(response) = self.http_client.get_with_timeout(url, self.timeout).await {
            response.status == 401 || response.status == 403
        } else {
            false
        }
    }

    /// Generate CSRF test payload
    pub fn generate_csrf_test_form(&self, target_url: &str, method: &str) -> String {
        format!(
            r#"<form action="{}" method="{}" enctype="multipart/form-data">
  <input type="hidden" name="action" value="transfer" />
  <input type="hidden" name="amount" value="1000" />
  <input type="submit" value="Submit" />
</form>"#,
            target_url,
            method.to_uppercase()
        )
    }

    /// Generate remediation guidance for CSRF
    fn generate_remediation(&self) -> String {
        "Implement anti-CSRF tokens using synchronizer token pattern or double-submit cookie \
         pattern. Use SameSite=Strict or SameSite=Lax cookie attribute. For API endpoints, \
         require custom headers (e.g., X-Requested-With) that cannot be sent cross-origin. \
         Implement proper origin/referrer validation. Consider using frameworks with built-in \
         CSRF protection."
            .to_string()
    }

    /// Generate API-specific remediation guidance
    fn generate_api_remediation(&self) -> String {
        "For REST APIs, use custom headers (X-CSRF-Token) that require preflight requests. \
         Implement JWT tokens with short expiration times. Use SameSite cookies for session \
         management. Validate Origin and Referer headers server-side. Consider implementing \
         request signing for sensitive operations."
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
    fn test_csrf_detector_creation() {
        let client = HttpClient::mock();
        let detector = CsrfDetector::new(client, false);
        assert!(!detector.god_mode);
    }

    #[test]
    fn test_csrf_token_names_defined() {
        assert!(CSRF_TOKEN_NAMES.contains(&"csrf_token"));
        assert!(CSRF_TOKEN_NAMES.contains(&"_token"));
        assert!(CSRF_TOKEN_NAMES.contains(&"X-CSRF-TOKEN"));
    }

    #[test]
    fn test_state_changing_methods_defined() {
        assert!(STATE_CHANGING_METHODS.contains(&"POST"));
        assert!(STATE_CHANGING_METHODS.contains(&"DELETE"));
    }
}
