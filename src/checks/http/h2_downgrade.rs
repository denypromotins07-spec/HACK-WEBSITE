//! HTTP/2 to HTTP/1.1 Downgrade Detection
//! 
//! Detects vulnerabilities in HTTP/2 to HTTP/1.1 translation layers
//! where header normalization and request translation can be exploited.
//! Identifies gaps in protocol translation that enable smuggling.

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// H2 Downgrade Detection Module
/// 
/// Tests for scenarios where:
/// - HTTP/2 requests are translated to HTTP/1.1 for backend
/// - Header normalization creates parsing discrepancies
/// - Pseudo-headers or special frames are mishandled
pub struct H2DowngradeCheck {
    metadata: CheckMetadata,
}

impl H2DowngradeCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-005".to_string(),
                name: "H2 Downgrade Translation Flaw".to_string(),
                severity: crate::findings::severity::Severity::High,
                category: "HTTP/2 Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 6,
                    max_memory_bytes: 1024 * 1024,
                    max_cpu_time_ms: 5000,
                },
                description: "Detects HTTP/2 to HTTP/1.1 translation vulnerabilities".to_string(),
                remediation_hint: "Implement strict header normalization during protocol translation. Validate pseudo-header handling.".to_string(),
            },
        }
    }

    /// Generate HTTP/2 request with problematic headers for downgrade
    fn generate_h2_header_probe(&self, boundary_id: &str) -> Vec<u8> {
        // Simulated HTTP/2 HEADERS frame with multiple :authority headers
        // This would normally be sent over an established HTTP/2 connection
        let mut payload = Vec::new();
        
        // Connection preface
        payload.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        
        // SETTINGS frame
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        
        // Simulated HEADERS frame (simplified representation)
        // In real implementation, this would use proper HPACK encoding
        payload.extend_from_slice(&[0x00, 0x00, 0x20]); // Length: 32
        payload.push(0x01); // Type: HEADERS
        payload.push(0x04); // Flags: END_HEADERS
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Stream ID: 1
        
        // Pseudo-headers (simplified, not HPACK encoded)
        payload.extend_from_slice(b":method GET\r\n");
        payload.extend_from_slice(b":path /test\r\n");
        payload.extend_from_slice(format!(":authority smuggle-{}\r\n", boundary_id).as_bytes());
        payload.extend_from_slice(b"host: {{target_host}}\r\n");
        
        payload
    }

    /// Generate probe with duplicate headers (forbidden in HTTP/2)
    fn generate_duplicate_header_probe(&self, boundary_id: &str) -> String {
        // HTTP/1.1 representation of what might result from bad translation
        format!(
            "GET / HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Host: {{target_host}}\r\n\
             X-Forwarded-Host: {{target_host}}\r\n\
             X-Forwarded-Host: smuggle-{}.evil\r\n\
             \r\n",
            boundary_id
        )
    }

    /// Generate probe testing pseudo-header translation
    fn generate_pseudo_header_probe(&self, boundary_id: &str) -> String {
        format!(
            "GET / HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             :authority: smuggle-{}.test\r\n\
             :scheme: https\r\n\
             :method: GET\r\n\
             \r\n",
            boundary_id
        )
    }

    /// Analyze response for downgrade vulnerability indicators
    fn analyze_response(&self, response: &str, boundary_id: &str, probe_type: &str) -> Option<Finding> {
        if response.contains(&format!("smuggle-{}", boundary_id)) {
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                format!("H2 downgrade flaw confirmed via {} probe", probe_type),
                response.to_string(),
                self.metadata.remediation_hint.clone(),
            ));
        }

        // Check for header injection evidence
        if response.contains("evil") || response.contains(".test") {
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                format!("Header injection detected in {} probe", probe_type),
                response.to_string(),
                self.metadata.remediation_hint.clone(),
            ));
        }

        None
    }
}

#[async_trait]
impl CheckModule for H2DowngradeCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    async fn init(&mut self, _context: &CheckContext) -> Result<(), String> {
        Ok(())
    }

    async fn run(&self, context: &CheckContext) -> Result<CheckResult, String> {
        let client = context.client();
        let boundary_id = format!("{:08x}", rand::random::<u32>());

        // Test 1: Duplicate header probe (most common issue)
        let dup_payload = self.generate_duplicate_header_probe(&boundary_id);
        match client.send_raw(&dup_payload).await {
            Ok(response) => {
                if let Some(finding) = self.analyze_response(&response, &boundary_id, "duplicate-header") {
                    return Ok(CheckResult::VulnerabilityFound(finding));
                }
            }
            Err(_) => {}
        }

        // Test 2: Pseudo-header injection (testing translation layer)
        let pseudo_payload = self.generate_pseudo_header_probe(&boundary_id);
        match client.send_raw(&pseudo_payload).await {
            Ok(response) => {
                if let Some(finding) = self.analyze_response(&response, &boundary_id, "pseudo-header") {
                    return Ok(CheckResult::VulnerabilityFound(finding));
                }
                
                // If pseudo-headers are reflected, that's suspicious
                if response.contains(":authority") || response.contains(":scheme") {
                    return Ok(CheckResult::Suspicious {
                        reason: "Server reflects HTTP/2 pseudo-headers - possible translation flaw".to_string(),
                        confidence: 0.65,
                    });
                }
            }
            Err(_) => {}
        }

        // Test 3: HTTP/2 native test (if supported)
        if client.supports_http2() {
            let h2_payload = self.generate_h2_header_probe(&boundary_id);
            match client.send_h2(&h2_payload).await {
                Ok(h2_response) => {
                    if h2_response.contains(&format!("smuggle-{}", boundary_id)) {
                        return Ok(CheckResult::VulnerabilityFound(Finding::new(
                            self.metadata.id.clone(),
                            self.metadata.severity.clone(),
                            "H2 native smuggling confirmed".to_string(),
                            format!("{:?}", h2_response),
                            self.metadata.remediation_hint.clone(),
                        )));
                    }
                }
                Err(_) => {}
            }
        }

        Ok(CheckResult::Safe)
    }

    async fn analyze(&self, result: &CheckResult) -> Result<Option<Finding>, String> {
        match result {
            CheckResult::VulnerabilityFound(finding) => Ok(Some(finding.clone())),
            CheckResult::Suspicious { reason, confidence } => {
                if *confidence > 0.7 {
                    Ok(Some(Finding::new(
                        self.metadata.id.clone(),
                        crate::findings::severity::Severity::High,
                        reason.clone(),
                        "Analysis suggests H2 downgrade vulnerability".to_string(),
                        self.metadata.remediation_hint.clone(),
                    )))
                } else {
                    Ok(None)
                }
            }
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
    fn test_duplicate_header_probe() {
        let check = H2DowngradeCheck::new();
        let probe = check.generate_duplicate_header_probe("test123");
        assert!(probe.contains("Host: {{target_host}}"));
        assert!(probe.matches("Host:").count() >= 2); // Multiple Host headers
    }

    #[test]
    fn test_pseudo_header_probe() {
        let check = H2DowngradeCheck::new();
        let probe = check.generate_pseudo_header_probe("test123");
        assert!(probe.contains(":authority:"));
        assert!(probe.contains(":scheme:"));
        assert!(probe.contains(":method:"));
    }

    #[test]
    fn test_metadata() {
        let check = H2DowngradeCheck::new();
        assert_eq!(check.metadata().id, "HTTP-005");
        assert_eq!(check.metadata().severity, crate::findings::severity::Severity::High);
    }
}
