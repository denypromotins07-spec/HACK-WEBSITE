//! HTTP/2 and H2C Smuggling Detection
//! 
//! Detects HTTP/1.1 to HTTP/2 (H2C) upgrade smuggling vulnerabilities
//! where upgrade mechanisms are improperly validated.
//! Uses controlled upgrade frames and routing anomaly detection.

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// H2C Smuggling Detection Module
/// 
/// Tests for scenarios where:
/// - HTTP/1.1 Upgrade to H2C is accepted without proper validation
/// - Backend processes HTTP/2 frames differently than frontend expects
/// - Result: Request smuggling via upgrade mechanism
pub struct H2cSmugglingCheck {
    metadata: CheckMetadata,
}

impl H2cSmugglingCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-004".to_string(),
                name: "H2C Upgrade Smuggling".to_string(),
                severity: crate::findings::severity::Severity::High,
                category: "HTTP/2 Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 6,
                    max_memory_bytes: 1024 * 1024,
                    max_cpu_time_ms: 5000,
                },
                description: "Detects H2C upgrade smuggling vulnerabilities".to_string(),
                remediation_hint: "Validate HTTP/2 upgrade requests strictly. Ensure consistent frame parsing across layers.".to_string(),
            },
        }
    }

    /// Generate HTTP/1.1 to H2C upgrade probe
    fn generate_upgrade_probe(&self, boundary_id: &str) -> String {
        format!(
            "GET / HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Upgrade: h2c\r\n\
             HTTP2-Settings: {}\r\n\
             Connection: Upgrade, HTTP2-Settings\r\n\
             \r\n\
             GET /smuggle-{}/h2c HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             \r\n",
            base64_encode("AAEAAAAAAAMAAABkAARAAAAAAAIAAAAA"),
            boundary_id
        )
    }

    /// Generate malformed H2C settings probe
    fn generate_malformed_h2c_probe(&self, boundary_id: &str) -> String {
        // Malformed SETTINGS frame in base64
        format!(
            "GET / HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Upgrade: h2c\r\n\
             HTTP2-Settings: {}\r\n\
             Connection: Upgrade, HTTP2-Settings\r\n\
             \r\n",
            base64_encode("INVALID_H2C_SETTINGS_PAYLOAD"),
            boundary_id
        )
    }

    /// Analyze response for H2C smuggling indicators
    fn analyze_response(&self, response: &str, boundary_id: &str) -> Option<Finding> {
        // Check if smuggled request was processed
        if response.contains(&format!("smuggle-{}", boundary_id)) {
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                "H2C smuggling confirmed: backend processed request after upgrade".to_string(),
                response.to_string(),
                self.metadata.remediation_hint.clone(),
            ));
        }

        // Check for protocol switch indication
        if response.contains("101") && response.contains("upgrade") {
            // Server accepted upgrade - may be vulnerable
            // Further testing needed
        }

        None
    }

    /// Test direct HTTP/2 connection behavior
    fn generate_direct_h2_probe(&self, boundary_id: &str) -> Vec<u8> {
        // HTTP/2 connection preface + SETTINGS frame
        let mut payload = Vec::new();
        
        // Connection preface: PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
        payload.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        
        // SETTINGS frame (empty)
        payload.extend_from_slice(&[0x00, 0x00, 0x00]); // Length: 0
        payload.push(0x04); // Type: SETTINGS
        payload.push(0x00); // Flags
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Stream ID: 0
        
        payload
    }
}

#[async_trait]
impl CheckModule for H2cSmugglingCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    async fn init(&mut self, _context: &CheckContext) -> Result<(), String> {
        Ok(())
    }

    async fn run(&self, context: &CheckContext) -> Result<CheckResult, String> {
        let client = context.client();
        let boundary_id = format!("{:08x}", rand::random::<u32>());

        // Test 1: Standard H2C upgrade
        let upgrade_payload = self.generate_upgrade_probe(&boundary_id);
        let response = client.send_raw(&upgrade_payload).await?;
        
        if let Some(finding) = self.analyze_response(&response, &boundary_id) {
            return Ok(CheckResult::VulnerabilityFound(finding));
        }

        // Test 2: Malformed H2C settings
        let malformed_payload = self.generate_malformed_h2c_probe(&boundary_id);
        let response_malformed = client.send_raw(&malformed_payload).await?;
        
        // If server accepts malformed settings, that's suspicious
        if response_malformed.contains("101") || response_malformed.contains("upgrade") {
            return Ok(CheckResult::Suspicious {
                reason: "Server accepted malformed H2C upgrade request".to_string(),
                confidence: 0.6,
            });
        }

        // Test 3: Direct HTTP/2 connection (if supported)
        if client.supports_http2() {
            let h2_payload = self.generate_direct_h2_probe(&boundary_id);
            match client.send_h2(&h2_payload).await {
                Ok(h2_response) => {
                    if h2_response.contains(&format!("smuggle-{}", boundary_id)) {
                        return Ok(CheckResult::VulnerabilityFound(Finding::new(
                            self.metadata.id.clone(),
                            self.metadata.severity.clone(),
                            "Direct H2 smuggling confirmed".to_string(),
                            format!("{:?}", h2_response),
                            self.metadata.remediation_hint.clone(),
                        )));
                    }
                }
                Err(_) => {
                    // HTTP/2 not supported or rejected
                }
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
                        "Analysis suggests H2C vulnerability".to_string(),
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

/// Simple base64 encoding helper
fn base64_encode(input: &str) -> String {
    use std::collections::HashMap;
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let mut output = String::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] as u32 } else { 0 };
        
        let triple = (b0 << 16) | (b1 << 8) | b2;
        
        output.push(BASE64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        output.push(BASE64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        
        if i + 1 < bytes.len() {
            output.push(BASE64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            output.push('=');
        }
        
        if i + 2 < bytes.len() {
            output.push(BASE64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            output.push('=');
        }
        
        i += 3;
    }
    
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upgrade_probe_generation() {
        let check = H2cSmugglingCheck::new();
        let probe = check.generate_upgrade_probe("test123");
        assert!(probe.contains("Upgrade: h2c"));
        assert!(probe.contains("HTTP2-Settings:"));
        assert!(probe.contains("Connection: Upgrade"));
    }

    #[test]
    fn test_base64_encode() {
        let encoded = base64_encode("Hello");
        assert_eq!(encoded, "SGVsbG8=");
    }

    #[test]
    fn test_metadata() {
        let check = H2cSmugglingCheck::new();
        assert_eq!(check.metadata().id, "HTTP-004");
        assert_eq!(check.metadata().severity, crate::findings::severity::Severity::High);
    }
}
