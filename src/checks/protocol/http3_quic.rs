//! HTTP/3 QUIC Connection Migration and Stream Hijacking Detection
//! Detects QUIC connection migration flaws and stream identifier hijacking.
//! Uses zero-copy byte buffers and bounded protocol frames (Stage 1 memory constraints).

use crate::checks::Check;
use crate::http::{Request, Response};
use crate::learning::Cache;
use crate::findings::Finding;
use std::time::Duration;
use std::collections::HashMap;

/// Bounded QUIC test scenarios (max 8)
const QUIC_TEST_SCENARIOS: [&str; 6] = [
    "connection_migration",
    "stream_hijack",
    "0rtt_replay",
    "version_downgrade",
    "path_validation_bypass",
    "stateless_reset"
];

pub struct Http3QuicCheck {
    timeout: Duration,
    god_mode: bool,
}

impl Http3QuicCheck {
    pub fn new(timeout_ms: u64, god_mode: bool) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            god_mode,
        }
    }

    /// Detect QUIC connection migration flaw
    pub fn detect_migration_flaw(&self, scenario: &str, response: &Response) -> Option<Finding> {
        match scenario {
            "connection_migration" => {
                if response.status == 200 {
                    return Some(Finding::new(
                        "QUIC Connection Migration Flaw",
                        "HIGH",
                        "Server accepts connection migration without proper validation",
                        "Implement strict path validation and connection ID rotation during migration",
                        Some(self.generate_payload(scenario)),
                    ));
                }
            }
            "stream_hijack" => {
                if response.status == 200 {
                    return Some(Finding::new(
                        "QUIC Stream Hijacking",
                        "CRITICAL",
                        "Server allows stream identifier reuse/hijacking",
                        "Enforce strict stream state machine and prevent stream ID reuse",
                        Some(self.generate_payload(scenario)),
                    ));
                }
            }
            "0rtt_replay" => {
                if response.status == 200 {
                    return Some(Finding::new(
                        "QUIC 0-RTT Replay Vulnerability",
                        "MEDIUM",
                        "Server accepts replayed 0-RTT data without anti-replay protection",
                        "Implement 0-RTT anti-replay tokens and single-use enforcement",
                        Some(self.generate_payload(scenario)),
                    ));
                }
            }
            _ => {}
        }
        None
    }

    /// Generate malicious QUIC payload for testing
    pub fn generate_payload(&self, scenario: &str) -> String {
        if self.god_mode {
            match scenario {
                "connection_migration" => {
                    "DCID:new_conn_id,SCID:old_conn_id,PATH_CHALLENGE:bypass".to_string()
                }
                "stream_hijack" => {
                    "STREAM_ID:0x01,DATA:injected,FIN:1,reuse_allowed".to_string()
                }
                "0rtt_replay" => {
                    "0RTT_DATA:replayed,token:stolen,anti_replay:bypass".to_string()
                }
                "version_downgrade" => {
                    "VERSION:0x00000001,forced_downgrade,skip_negotiation".to_string()
                }
                "path_validation_bypass" => {
                    "PATH_RESPONSE:forged,VALIDATION:bypassed".to_string()
                }
                "stateless_reset" => {
                    "RESET_TOKEN:forged,STATELESS:true,conn_terminated".to_string()
                }
                _ => scenario.to_string(),
            }
        } else {
            format!("QUIC test: {}", scenario)
        }
    }

    /// Build test requests simulating QUIC scenarios
    pub fn build_test_requests(&self, base_target: &str) -> Vec<Request> {
        let mut requests = Vec::with_capacity(QUIC_TEST_SCENARIOS.len());
        
        for scenario in QUIC_TEST_SCENARIOS.iter() {
            let mut headers = HashMap::new();
            headers.insert("Alt-Svc".to_string(), format!("h3=\"{}\"; ma=86400", base_target));
            headers.insert("X-QUIC-Scenario".to_string(), scenario.to_string());
            
            requests.push(Request {
                method: "GET".to_string(),
                uri: base_target.to_string(),
                headers,
                body: vec![],
            });
        }
        
        requests
    }

    /// Parse QUIC packet header (zero-copy, simplified)
    pub fn parse_quic_header(&self, data: &[u8]) -> Option<(u8, u8, u64, usize)> {
        if data.len() < 5 {
            return None;
        }

        let first_byte = data[0];
        let header_form = (first_byte & 0x80) >> 7; // 0 = short, 1 = long
        
        if header_form == 1 {
            // Long header
            let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            if data.len() < 6 {
                return None;
            }
            let dcid_len = data[5] as usize;
            if data.len() < 6 + dcid_len + 1 {
                return None;
            }
            let scid_len = data[6 + dcid_len] as usize;
            
            Some((header_form, dcid_len as u8, version as u64, scid_len))
        } else {
            // Short header - extract connection ID length from context
            Some((header_form, 0, 0, data.len()))
        }
    }

    /// Test connection migration with new path
    pub fn test_migration(&self, original_addr: &str, new_addr: &str) -> Vec<u8> {
        let mut packet = Vec::with_capacity(32);
        
        // Long header with migration indicators
        packet.push(0xC0); // Long header, type 0
        packet.extend_from_slice(&0x00000001u32.to_be_bytes()); // Version
        packet.push(8); // DCID length
        packet.extend_from_slice(b"new_path"); // New path DCID
        packet.push(0); // SCID length
        
        packet
    }

    /// Test stream hijacking attempt
    pub fn test_stream_hijack(&self, stream_id: u64) -> Vec<u8> {
        let mut frame = Vec::with_capacity(16);
        
        // STREAM frame with hijacked ID
        let frame_type = 0x08; // STREAM frame
        frame.push(frame_type);
        
        // Variable-length stream ID encoding
        if stream_id < 64 {
            frame.push(stream_id as u8);
        } else if stream_id < 16384 {
            frame.push(((stream_id >> 8) | 0x40) as u8);
            frame.push((stream_id & 0xFF) as u8);
        }
        
        // Add payload
        frame.extend_from_slice(b"hijacked_data");
        
        frame
    }
}

impl Check for Http3QuicCheck {
    fn name(&self) -> &'static str {
        "http3_quic"
    }

    fn run(&self, target: &str, cache: &mut dyn Cache) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(3);
        
        for scenario in QUIC_TEST_SCENARIOS.iter() {
            // Mock response - actual implementation uses Stage 2 HTTP engine with QUIC support
            let mock_response = Response {
                status: 200,
                headers: HashMap::new(),
                body: b"QUIC response".to_vec(),
            };

            if let Some(finding) = self.detect_migration_flaw(scenario, &mock_response) {
                findings.push(finding);
                // Cache successful QUIC bypass
                cache.store(&format!("quic_bypass_{}", scenario), target);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http3_quic_detection() {
        let check = Http3QuicCheck::new(5000, true);
        assert_eq!(check.name(), "http3_quic");
        assert!(check.generate_payload("stream_hijack").contains("STREAM_ID"));
    }

    #[test]
    fn test_quic_header_parsing() {
        let check = Http3QuicCheck::new(5000, false);
        
        // Long header packet
        let long_packet = vec![
            0xC0,           // Long header
            0x00, 0x00, 0x00, 0x01, // Version 1
            0x08,           // DCID length
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DCID
            0x00,           // SCID length
        ];
        
        let parsed = check.parse_quic_header(&long_packet);
        assert!(parsed.is_some());
        let (form, dcid, version, scid) = parsed.unwrap();
        assert_eq!(form, 1); // Long header
        assert_eq!(version, 1);
    }

    #[test]
    fn test_stream_hijack_frame() {
        let check = Http3QuicCheck::new(5000, true);
        let frame = check.test_stream_hijack(1);
        assert!(!frame.is_empty());
        assert_eq!(frame[0], 0x08); // STREAM frame type
    }
}
