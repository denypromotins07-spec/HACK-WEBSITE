//! HTTP Response Splitting Detection
//! 
//! Detects CRLF injection vulnerabilities that enable response splitting attacks.
//! Uses safe canary headers and boundary validation to identify injection points.

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// Response Splitting Detection Module
/// 
/// Tests for scenarios where:
/// - User input is reflected in HTTP headers without sanitization
/// - CRLF sequences (%0d%0a) can inject new headers
/// - Result: XSS, cache poisoning, or session fixation via split responses
pub struct ResponseSplittingCheck {
    metadata: CheckMetadata,
    crlf_payloads: Vec<String>,
}

impl ResponseSplittingCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-008".to_string(),
                name: "HTTP Response Splitting".to_string(),
                severity: crate::findings::severity::Severity::High,
                category: "HTTP Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 12,
                    max_memory_bytes: 1024 * 1024,
                    max_cpu_time_ms: 5000,
                },
                description: "Detects CRLF injection and HTTP response splitting vulnerabilities".to_string(),
                remediation_hint: "Sanitize all user input before including in HTTP headers. Encode CR and LF characters.".to_string(),
            },
            crlf_payloads: vec![
                "%0d%0aX-Injected: header-value".to_string(),
                "%0D%0ASet-Cookie: injected=true".to_string(),
                "\\r\\nX-Split: test".to_string(),
                "\r\nX-Split: test".to_string(), // Direct CRLF (if not URL-encoded)
                "%0aX-LF: injected".to_string(), // LF only
                "%0dX-CR: injected".to_string(), // CR only
                "%0d%0a%20%20injected-header".to_string(), // CRLF with spaces
                "%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>XSS</html>".to_string(),
            ],
        }
    }

    /// Generate probe with CRLF payload in common vulnerable parameters
    fn generate_header_injection_probe(&self, boundary_id: &str, payload: &str, param_name: &str) -> String {
        format!(
            "GET /smuggle-{}/test?{}={} HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             \r\n",
            boundary_id, param_name, payload
        )
    }

    /// Generate probe targeting redirect parameters (commonly vulnerable)
    fn generate_redirect_probe(&self, boundary_id: &str, payload: &str) -> String {
        format!(
            "GET /redirect?url={} HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             \r\n",
            payload
        )
    }

    /// Generate probe targeting custom header reflection
    fn generate_custom_header_probe(&self, boundary_id: &str, payload: &str) -> String {
        format!(
            "GET /smuggle-{}/header-test HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             X-Custom-Input: {}\r\n\
             \r\n",
            boundary_id, payload
        )
    }

    /// Analyze response for response splitting indicators
    fn analyze_response(&self, response: &str, boundary_id: &str, payload_used: &str) -> Option<Finding> {
        // Check for injected headers in response
        if response.contains("X-Injected:") || response.contains("X-Split:") {
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                "Response splitting confirmed: CRLF injection successful".to_string(),
                format!("Payload: {}\nResponse: {}", payload_used, response),
                self.metadata.remediation_hint.clone(),
            ));
        }

        // Check for Set-Cookie injection
        if response.contains("Set-Cookie: injected") {
            return Some(Finding::new(
                self.metadata.id.clone(),
                crate::findings::severity::Severity::Critical,
                "Cookie injection via response splitting confirmed".to_string(),
                format!("Payload: {}\nResponse: {}", payload_used, response),
                self.metadata.remediation_hint.clone(),
            ));
        }

        // Check for HTML injection (XSS via splitting)
        if response.contains("<html>") && response.contains("XSS") {
            return Some(Finding::new(
                self.metadata.id.clone(),
                crate::findings::severity::Severity::Critical,
                "HTML injection via response splitting confirmed".to_string(),
                format!("Payload: {}\nResponse: {}", payload_used, response),
                self.metadata.remediation_hint.clone(),
            ));
        }

        // Look for evidence of multiple HTTP responses (splitting)
        let http_count = response.matches("HTTP/1.").count();
        if http_count > 1 {
            return Some(Finding::new(
                self.metadata.id.clone(),
                crate::findings::severity::Severity::Critical,
                format!("HTTP response splitting confirmed: {} HTTP responses detected", http_count),
                format!("Payload: {}\nResponse: {}", payload_used, response),
                self.metadata.remediation_hint.clone(),
            ));
        }

        None
    }

    /// Safe canary-based detection
    fn generate_canary_probe(&self, boundary_id: &str) -> String {
        // Use a unique canary that should only appear if injection succeeds
        let canary = format!("CANARY_{}_SPLIT", boundary_id);
        format!(
            "GET /smuggle-{}/canary?redirect=%0d%0aX-Canary:{} HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             \r\n",
            boundary_id, canary
        )
    }

    fn analyze_canary_response(&self, response: &str, boundary_id: &str) -> Option<Finding> {
        let canary = format!("CANARY_{}_SPLIT", boundary_id);
        if response.contains(&canary) && response.contains("X-Canary:") {
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                "Response splitting confirmed via canary detection".to_string(),
                format!("Canary '{}' found in injected header", canary),
                self.metadata.remediation_hint.clone(),
            ));
        }
        None
    }
}

#[async_trait]
impl CheckModule for ResponseSplittingCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    async fn init(&mut self, _context: &CheckContext) -> Result<(), String> {
        Ok(())
    }

    async fn run(&self, context: &CheckContext) -> Result<CheckResult, String> {
        let client = context.client();
        let boundary_id = format!("{:08x}", rand::random::<u32>());
        let mut request_count = 0;

        // Test 1: Canary-based detection (safest first)
        let canary_payload = self.generate_canary_probe(&boundary_id);
        match client.send_raw(&canary_payload).await {
            Ok(response) => {
                if let Some(finding) = self.analyze_canary_response(&response, &boundary_id) {
                    return Ok(CheckResult::VulnerabilityFound(finding));
                }
                request_count += 1;
            }
            Err(_) => {}
        }

        // Test 2: Common parameter names with CRLF payloads
        let common_params = ["redirect", "url", "next", "return", "goto", "target", "page"];
        
        for payload in &self.crlf_payloads {
            if request_count >= self.metadata.resource_budget.max_requests as usize {
                break;
            }

            for param in &common_params {
                if request_count >= self.metadata.resource_budget.max_requests as usize {
                    break;
                }

                let probe = self.generate_header_injection_probe(&boundary_id, payload, param);
                match client.send_raw(&probe).await {
                    Ok(response) => {
                        if let Some(finding) = self.analyze_response(&response, &boundary_id, payload) {
                            return Ok(CheckResult::VulnerabilityFound(finding));
                        }
                        request_count += 1;
                    }
                    Err(_) => continue,
                }
            }
        }

        // Test 3: Custom header reflection
        for payload in &self.crlf_payloads[..2.min(self.crlf_payloads.len())] {
            if request_count >= self.metadata.resource_budget.max_requests as usize {
                break;
            }

            let header_probe = self.generate_custom_header_probe(&boundary_id, payload);
            match client.send_raw(&header_probe).await {
                Ok(response) => {
                    if let Some(finding) = self.analyze_response(&response, &boundary_id, payload) {
                        return Ok(CheckResult::VulnerabilityFound(finding));
                    }
                    request_count += 1;
                }
                Err(_) => continue,
            }
        }

        Ok(CheckResult::Safe)
    }

    async fn analyze(&self, result: &CheckResult) -> Result<Option<Finding>, String> {
        match result {
            CheckResult::VulnerabilityFound(finding) => Ok(Some(finding.clone())),
            _ => Ok(None),
        }
    }

    fn remediation(&self) -> Option<String> {
        Some(self.metadata.remediation_hint.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crlf_payloads() {
        let check = ResponseSplittingCheck::new();
        assert!(check.crlf_payloads.len() >= 6);
        assert!(check.crlf_payloads.iter().any(|p| p.contains("%0d%0a")));
    }

    #[test]
    fn test_header_injection_probe() {
        let check = ResponseSplittingCheck::new();
        let probe = check.generate_header_injection_probe("test123", "%0d%0aX-Test: val", "redirect");
        assert!(probe.contains("?redirect="));
        assert!(probe.contains("%0d%0a"));
    }

    #[test]
    fn test_canary_probe() {
        let check = ResponseSplittingCheck::new();
        let probe = check.generate_canary_probe("test123");
        assert!(probe.contains("CANARY_test123_SPLIT"));
    }

    #[test]
    fn test_metadata() {
        let check = ResponseSplittingCheck::new();
        assert_eq!(check.metadata().id, "HTTP-008");
        assert_eq!(check.metadata().severity, crate::findings::severity::Severity::High);
    }
}
