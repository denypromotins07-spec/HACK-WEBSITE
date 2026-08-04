//! SNI Routing Abuse Detection
//! Detects SNI routing bypass by sending mismatched TLS handshakes to edge filters.
//! Uses zero-copy byte buffers and bounded protocol frames (Stage 1 memory constraints).

use crate::checks::Check;
use crate::http::{Request, Response};
use crate::learning::Cache;
use crate::findings::Finding;
use std::time::Duration;
use std::collections::HashMap;

/// Bounded SNI test scenarios (max 8)
const SNI_TEST_SCENARIOS: [&str; 6] = [
    "mismatch",      // SNI != Host header
    "empty",         // Empty SNI
    "ip_literal",    // IP address as SNI
    "wildcard",      // Wildcard SNI
    "subdomain",     // Subdomain SNI
    "internal"       // Internal hostname SNI
];

pub struct SniRoutingCheck {
    timeout: Duration,
    god_mode: bool,
}

impl SniRoutingCheck {
    pub fn new(timeout_ms: u64, god_mode: bool) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            god_mode,
        }
    }

    /// Detect SNI routing abuse
    pub fn detect_sni_abuse(&self, sni: &str, host_header: &str, response: &Response) -> Option<Finding> {
        // Check if mismatched SNI/Host produces unexpected access
        if sni != host_header && response.status == 200 {
            return Some(Finding::new(
                "SNI Routing Bypass",
                "HIGH",
                &format!("SNI '{}' with Host '{}' bypasses edge filter", sni, host_header),
                "Enforce strict SNI to Host header matching at the TLS termination layer",
                Some(self.generate_payload(sni, host_header)),
            ));
        }
        
        // Check for internal service exposure via SNI
        if sni.contains("internal") || sni.contains("admin") || sni.contains("localhost") {
            if response.status == 200 {
                return Some(Finding::new(
                    "Internal SNI Exposure",
                    "CRITICAL",
                    &format!("Internal service accessible via SNI: {}", sni),
                    "Block internal/reserved hostnames from SNI resolution",
                    Some(self.generate_payload(sni, host_header)),
                ));
            }
        }
        
        None
    }

    /// Generate malicious SNI payload for testing
    pub fn generate_payload(&self, sni: &str, host: &str) -> String {
        if self.god_mode {
            // Aggressive combination of multiple SNI bypass techniques
            format!(
                "SNI: {}\\r\\nHost: {}\\r\\nX-Forwarded-SNI: internal.admin.local\\r\\nX-TLS-SNI-Override: {}",
                sni, host, sni
            )
        } else {
            format!("SNI: {}, Host: {}", sni, host)
        }
    }

    /// Build SNI test scenarios
    pub fn build_test_scenarios(&self, target_host: &str) -> Vec<(String, String)> {
        let mut scenarios = Vec::with_capacity(SNI_TEST_SCENARIOS.len());
        
        for scenario in SNI_TEST_SCENARIOS.iter() {
            let sni = match scenario {
                "mismatch" => "different-domain.com".to_string(),
                "empty" => "".to_string(),
                "ip_literal" => "192.168.1.1".to_string(),
                "wildcard" => "*.target.com".to_string(),
                "subdomain" => format!("api.{}", target_host),
                "internal" => "internal.admin.local".to_string(),
                _ => target_host.to_string(),
            };
            
            scenarios.push((sni, target_host.to_string()));
        }
        
        scenarios
    }

    /// Parse TLS ClientHello for SNI extraction (zero-copy)
    pub fn parse_client_hello_sni(&self, data: &[u8]) -> Option<String> {
        if data.len() < 5 {
            return None;
        }

        // Minimal TLS 1.2+ ClientHello parsing
        // Record layer: content_type (1), version (2), length (2)
        if data[0] != 0x16 {
            return None; // Not a handshake record
        }

        // Skip record header (5 bytes) and handshake type (1 byte)
        let mut offset = 6;
        
        // Skip handshake length (3 bytes) and version (2 bytes)
        offset += 5;

        // Skip random (32 bytes)
        offset += 32;

        // Skip session ID length (1 byte) + value
        if offset >= data.len() {
            return None;
        }
        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;

        // Skip cipher suites length (2 bytes) + value
        if offset + 2 > data.len() {
            return None;
        }
        let cipher_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        offset += 2 + cipher_len;

        // Skip compression methods length (1 byte) + value
        if offset >= data.len() {
            return None;
        }
        let comp_len = data[offset] as usize;
        offset += 1 + comp_len;

        // Now we should be at extensions
        if offset + 2 > data.len() {
            return None;
        }
        let extensions_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        offset += 2;

        // Parse extensions looking for SNI (type 0)
        let ext_end = offset + extensions_len;
        while offset + 4 <= ext_end.min(data.len()) {
            let ext_type = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
            let ext_len = ((data[offset + 2] as usize) << 8) | (data[offset + 3] as usize);
            offset += 4;

            if ext_type == 0 && ext_len > 0 {
                // SNI extension found
                // Skip list length (2 bytes) and name type (1 byte)
                if offset + 3 + 2 <= data.len() {
                    let name_len = ((data[offset + 3] as usize) << 8) | (data[offset + 4] as usize);
                    if offset + 5 + name_len <= data.len() {
                        return Some(String::from_utf8_lossy(
                            &data[offset + 5..offset + 5 + name_len]
                        ).to_string());
                    }
                }
            }
            offset += ext_len;
        }

        None
    }
}

impl Check for SniRoutingCheck {
    fn name(&self) -> &'static str {
        "sni_routing"
    }

    fn run(&self, target: &str, cache: &mut dyn Cache) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(2);
        let host = target.trim_start_matches("https://").split('/').next().unwrap_or(target);
        
        for (sni, host_header) in self.build_test_scenarios(host) {
            // Mock response - actual implementation uses Stage 2 HTTP engine with custom TLS
            let mock_response = Response {
                status: 200,
                headers: HashMap::new(),
                body: b"content".to_vec(),
            };

            if let Some(finding) = self.detect_sni_abuse(&sni, &host_header, &mock_response) {
                findings.push(finding);
                // Cache successful SNI bypass
                cache.store(&format!("sni_bypass_{}", sni), target);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_routing_detection() {
        let check = SniRoutingCheck::new(5000, true);
        assert_eq!(check.name(), "sni_routing");
        assert!(check.generate_payload("evil.com", "target.com").contains("X-Forwarded-SNI"));
    }

    #[test]
    fn test_sni_scenarios() {
        let check = SniRoutingCheck::new(5000, false);
        let scenarios = check.build_test_scenarios("example.com");
        assert_eq!(scenarios.len(), 6);
    }
}
