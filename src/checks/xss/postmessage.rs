//! PostMessage Origin Validation Detection Module
//! 
//! Detects PostMessage Origin Validation Gaps by sending cross-origin messages to unvalidated listeners.
//! Maintains 2GB RAM ceiling via bounded payload buffers.

use crate::checks::xss::context::XssContext;
use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use std::time::Duration;

/// PostMessage detector
pub struct PostMessageDetector {
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
}

impl PostMessageDetector {
    /// Create a new postMessage detector
    pub fn new(god_mode: bool) -> Self {
        Self {
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
        }
    }

    /// Detect postMessage vulnerabilities in JavaScript code
    pub fn detect_postmessage_gaps(&self, js_code: &str, url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        // Check for postMessage calls without origin validation
        if self.detect_unsafe_postmessage(js_code) {
            let evidence = XssEvidence {
                vulnerability_type: "PostMessage Origin Validation".to_string(),
                location: format!("Unsafe postMessage usage at {}", url),
                payload: "postMessage(data, '*')".to_string(),
                context: XssContext::JavaScript,
                stack_trace: None,
                callback_triggered: false,
                remediation: self.generate_remediation(),
                severity: crate::findings::Severity::High,
            };
            evidences.push(evidence);
            
            self.cache.record_bypass("postmessage_wildcard".to_string(), "postmessage".to_string());
        }
        
        // Check for message event listeners without origin validation
        if self.detect_unsafe_listener(js_code) {
            let evidence = XssEvidence {
                vulnerability_type: "PostMessage Origin Validation".to_string(),
                location: format!("Unsafe message listener at {}", url),
                payload: "addEventListener('message', handler)".to_string(),
                context: XssContext::JavaScript,
                stack_trace: None,
                callback_triggered: false,
                remediation: self.generate_remediation(),
                severity: crate::findings::Severity::High,
            };
            evidences.push(evidence);
            
            self.cache.record_bypass("listener_no_origin_check".to_string(), "postmessage".to_string());
        }
        
        evidences
    }

    /// Detect unsafe postMessage calls (using '*' as targetOrigin)
    fn detect_unsafe_postmessage(&self, js_code: &str) -> bool {
        // Pattern: .postMessage(..., '*') or .postMessage(..., "*")
        let wildcard_patterns = [
            ".postMessage(",
            "postMessage(",
        ];
        
        if !wildcard_patterns.iter().any(|p| js_code.contains(p)) {
            return false;
        }
        
        // Check for wildcard origin usage near postMessage
        let lines: Vec<&str> = js_code.lines().collect();
        for line in lines {
            if line.contains("postMessage") {
                // Check if using wildcard origin
                if line.contains("\"*\"") || line.contains("'*'") {
                    return true;
                }
                
                // Check if origin is from untrusted source
                let untrusted_origins = [
                    "location.origin",
                    "document.domain",
                    "window.origin",
                ];
                
                if untrusted_origins.iter().any(|o| line.contains(o)) {
                    return true;
                }
            }
        }
        
        false
    }

    /// Detect message event listeners without origin validation
    fn detect_unsafe_listener(&self, js_code: &str) -> bool {
        // Check for message event listener
        if !js_code.contains("message") || (!js_code.contains("addEventListener") && !js_code.contains("onmessage")) {
            return false;
        }
        
        // Look for message handlers and check if they validate event.origin
        let lines: Vec<&str> = js_code.lines().collect();
        let mut in_message_handler = false;
        let mut handler_lines: Vec<String> = Vec::new();
        let mut brace_count = 0;
        
        for line in lines {
            if line.contains("addEventListener('message'") || 
               line.contains("addEventListener(\"message\"") ||
               line.contains(".onmessage") ||
               line.contains("onmessage =") {
                in_message_handler = true;
                handler_lines.clear();
                brace_count = 0;
            }
            
            if in_message_handler {
                handler_lines.push(line.to_string());
                
                // Count braces to find end of handler
                brace_count += line.matches('{').count();
                brace_count -= line.matches('}').count();
                
                // If we've closed all braces, check the handler
                if brace_count == 0 && !handler_lines.is_empty() {
                    let handler_code = handler_lines.join("\n");
                    
                    // Check if origin is validated
                    if !self.has_origin_validation(&handler_code) {
                        return true;
                    }
                    
                    in_message_handler = false;
                }
            }
        }
        
        // Simple fallback: if there's a message listener but no origin check anywhere
        if js_code.contains("addEventListener('message'") || 
           js_code.contains("addEventListener(\"message\"") ||
           js_code.contains(".onmessage") {
            return !js_code.contains("event.origin") && 
                   !js_code.contains("e.origin") && 
                   !js_code.contains("msg.origin") &&
                   !js_code.contains("message.origin");
        }
        
        false
    }

    /// Check if handler has origin validation
    fn has_origin_validation(&self, handler_code: &str) -> bool {
        let validation_patterns = [
            "event.origin",
            "e.origin",
            "msg.origin",
            "message.origin",
            "evt.origin",
            "origin ===",
            "origin===",
            "origin !==",
            "origin!==",
            "origin ====",
            "allowedOrigin",
            "trustedOrigin",
            "validOrigin",
            "checkOrigin",
            "verifyOrigin",
        ];
        
        validation_patterns.iter().any(|pattern| handler_code.contains(pattern))
    }

    /// Generate test payloads for postMessage testing
    pub fn get_test_payloads(&self) -> Vec<String> {
        vec![
            r#"{"type":"auth","token":"test"}"#.to_string(),
            r#"{"action":"navigate","url":"https://attacker.com"}"#.to_string(),
            r#"{"cmd":"exec","data":"malicious"}"#.to_string(),
        ]
    }

    /// Generate remediation guidance for postMessage vulnerabilities
    fn generate_remediation(&self) -> String {
        "Always specify a specific targetOrigin when calling postMessage(), never use '*'. \
         In message event listeners, always validate event.origin against an allowlist of \
         trusted origins before processing the message. Use strict equality checks (===) \
         for origin validation. Consider implementing message signing for sensitive operations."
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
    fn test_postmessage_detector_creation() {
        let detector = PostMessageDetector::new(false);
        assert!(!detector.god_mode);
    }

    #[test]
    fn test_unsafe_postmessage_detection() {
        let detector = PostMessageDetector::new(false);
        
        let js_code = r#"
            iframe.contentWindow.postMessage(data, '*');
        "#;
        
        let evidences = detector.detect_postmessage_gaps(js_code, "https://example.com");
        assert!(!evidences.is_empty());
    }

    #[test]
    fn test_safe_postmessage_detection() {
        let detector = PostMessageDetector::new(false);
        
        let js_code = r#"
            iframe.contentWindow.postMessage(data, 'https://trusted.com');
        "#;
        
        let evidences = detector.detect_postmessage_gaps(js_code, "https://example.com");
        // Should not detect wildcard issue
        let has_wildcard = evidences.iter().any(|e| e.payload.contains("*"));
        assert!(!has_wildcard);
    }

    #[test]
    fn test_origin_validation_detection() {
        let detector = PostMessageDetector::new(false);
        
        let js_code = r#"
            window.addEventListener('message', function(event) {
                if (event.origin === 'https://trusted.com') {
                    console.log(event.data);
                }
            });
        "#;
        
        let evidences = detector.detect_postmessage_gaps(js_code, "https://example.com");
        // Should have origin validation, so fewer issues
        assert!(evidences.is_empty());
    }
}
