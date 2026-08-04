//! WebSocket Tunnel and Bypass Detection
//! 
//! Detects WebSocket upgrade paths that bypass WAF or proxy authorization.
//! Tests for tunneling vulnerabilities in WebSocket handshake handling.

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// WebSocket Tunnel Detection Module
/// 
/// Tests for scenarios where:
/// - WebSocket upgrades bypass security controls
/// - Authorization is not validated on upgrade requests
/// - Data tunneling enables WAF evasion
pub struct WebSocketTunnelCheck {
    metadata: CheckMetadata,
}

impl WebSocketTunnelCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-010".to_string(),
                name: "WebSocket Tunnel Bypass".to_string(),
                severity: crate::findings::severity::Severity::High,
                category: "WebSocket Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 6,
                    max_memory_bytes: 2 * 1024 * 1024,
                    max_cpu_time_ms: 5000,
                },
                description: "Detects WebSocket upgrade paths that bypass WAF or proxy authorization".to_string(),
                remediation_hint: "Validate authorization on WebSocket upgrade requests. Apply same security policies to WS connections.".to_string(),
            },
        }
    }

    /// Generate WebSocket upgrade probe without authorization
    fn generate_ws_upgrade_probe(&self, boundary_id: &str) -> String {
        format!(
            "GET /ws HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n",
            base64_encode(&format!("smuggle-{}", boundary_id))
        )
    }

    /// Generate WebSocket upgrade with malformed key (bypass attempt)
    fn generate_malformed_ws_probe(&self, boundary_id: &str) -> String {
        format!(
            "GET /ws HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade, Keep-Alive\r\n\
             Sec-WebSocket-Key: invalid_key_{}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             X-Forwarded-Proto: ws\r\n\
             \r\n",
            boundary_id
        )
    }

    /// Generate WebSocket upgrade targeting protected endpoint
    fn generate_protected_ws_probe(&self, boundary_id: &str) -> String {
        format!(
            "GET /admin/ws HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n",
            base64_encode(&format!("admin-probe-{}", boundary_id))
        )
    }

    /// Analyze response for WebSocket bypass indicators
    fn analyze_response(&self, response: &str, boundary_id: &str, probe_type: &str) -> Option<Finding> {
        // Check for successful upgrade without auth
        if response.contains("101") && response.contains("websocket") {
            if probe_type == "unauth" {
                return Some(Finding::new(
                    self.metadata.id.clone(),
                    self.metadata.severity.clone(),
                    "WebSocket upgrade succeeded without authorization".to_string(),
                    format!("Probe type: {}\nResponse: {}", probe_type, response),
                    self.metadata.remediation_hint.clone(),
                ));
            }

            // Check if this was a protected endpoint
            if probe_type == "protected" {
                return Some(Finding::new(
                    self.metadata.id.clone(),
                    crate::findings::severity::Severity::Critical,
                    "WebSocket access to protected endpoint without auth".to_string(),
                    format!("Probe type: {}\nResponse: {}", probe_type, response),
                    self.metadata.remediation_hint.clone(),
                ));
            }
        }

        // Check for malformed key acceptance
        if response.contains("101") && probe_type == "malformed" {
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                "Server accepted malformed WebSocket key - possible validation bypass".to_string(),
                format!("Probe type: {}\nResponse: {}", probe_type, response),
                self.metadata.remediation_hint.clone(),
            ));
        }

        None
    }

    /// Test WebSocket data tunneling (if upgrade succeeds)
    fn generate_ws_data_probe(&self, boundary_id: &str) -> Vec<u8> {
        // Minimal WebSocket frame containing test data
        let mut frame = Vec::new();
        
        // FIN bit set, opcode TEXT (1)
        frame.push(0x81);
        
        // Payload length (masked)
        let payload = format!("smuggle-{}", boundary_id);
        let len = payload.len();
        
        if len < 126 {
            frame.push(0x80 | len as u8); // Mask bit + length
        } else if len < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        
        // Masking key (required for client->server)
        let mask: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        frame.extend_from_slice(&mask);
        
        // Masked payload
        for (i, byte) in payload.as_bytes().iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }
        
        frame
    }
}

#[async_trait]
impl CheckModule for WebSocketTunnelCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    async fn init(&mut self, _context: &CheckContext) -> Result<(), String> {
        Ok(())
    }

    async fn run(&self, context: &CheckContext) -> Result<CheckResult, String> {
        let client = context.client();
        let boundary_id = format!("{:08x}", rand::random::<u32>());

        // Test 1: Basic unauthenticated WebSocket upgrade
        let ws_probe = self.generate_ws_upgrade_probe(&boundary_id);
        match client.send_raw(&ws_probe).await {
            Ok(response) => {
                if let Some(finding) = self.analyze_response(&response, &boundary_id, "unauth") {
                    return Ok(CheckResult::VulnerabilityFound(finding));
                }
            }
            Err(_) => {}
        }

        // Test 2: Malformed WebSocket key
        let malformed_probe = self.generate_malformed_ws_probe(&boundary_id);
        match client.send_raw(&malformed_probe).await {
            Ok(response) => {
                if let Some(finding) = self.analyze_response(&response, &boundary_id, "malformed") {
                    return Ok(CheckResult::VulnerabilityFound(finding));
                }
            }
            Err(_) => {}
        }

        // Test 3: Protected endpoint WebSocket access
        if context.has_endpoint("/admin/ws") || context.has_endpoint("/admin/websocket") {
            let protected_probe = self.generate_protected_ws_probe(&boundary_id);
            match client.send_raw(&protected_probe).await {
                Ok(response) => {
                    if let Some(finding) = self.analyze_response(&response, &boundary_id, "protected") {
                        return Ok(CheckResult::VulnerabilityFound(finding));
                    }
                }
                Err(_) => {}
            }
        }

        // Test 4: If WebSocket upgrade succeeded, test data tunneling
        // This would require an actual WebSocket connection in real implementation
        
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

/// Simple base64 encoding helper
fn base64_encode(input: &str) -> String {
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
    fn test_ws_upgrade_probe() {
        let check = WebSocketTunnelCheck::new();
        let probe = check.generate_ws_upgrade_probe("test123");
        assert!(probe.contains("Upgrade: websocket"));
        assert!(probe.contains("Sec-WebSocket-Key:"));
        assert!(probe.contains("Sec-WebSocket-Version: 13"));
    }

    #[test]
    fn test_malformed_ws_probe() {
        let check = WebSocketTunnelCheck::new();
        let probe = check.generate_malformed_ws_probe("test123");
        assert!(probe.contains("invalid_key_test123"));
        assert!(probe.contains("X-Forwarded-Proto: ws"));
    }

    #[test]
    fn test_protected_ws_probe() {
        let check = WebSocketTunnelCheck::new();
        let probe = check.generate_protected_ws_probe("test123");
        assert!(probe.contains("/admin/ws"));
    }

    #[test]
    fn test_metadata() {
        let check = WebSocketTunnelCheck::new();
        assert_eq!(check.metadata().id, "HTTP-010");
        assert_eq!(check.metadata().severity, crate::findings::severity::Severity::High);
    }
}
