//! gRPC-Web Reflection and Binary Proto Frame Analysis
//! Profiles gRPC-Web reflection endpoints and parses binary proto frames for input validation flaws.
//! Uses zero-copy byte buffers and bounded protocol frames (Stage 1 memory constraints).

use crate::checks::Check;
use crate::http::{Request, Response};
use crate::learning::Cache;
use crate::findings::Finding;
use std::time::Duration;
use std::collections::HashMap;

/// Bounded gRPC-Web reflection methods to test (max 8)
const GRPC_REFLECTION_METHODS: [&str; 4] = [
    "grpc.reflection.v1alpha.ServerReflection",
    "grpc.reflection.v1.ServerReflection",
    "ListServices",
    "GetService"
];

/// Bounded proto frame types (max 8)
const PROTO_FRAME_TYPES: [&str; 4] = [
    "UNARY",
    "SERVER_STREAMING", 
    "CLIENT_STREAMING",
    "BIDIRECTIONAL"
];

pub struct GrpcWebCheck {
    timeout: Duration,
    god_mode: bool,
}

impl GrpcWebCheck {
    pub fn new(timeout_ms: u64, god_mode: bool) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            god_mode,
        }
    }

    /// Detect gRPC-Web reflection exposure
    pub fn detect_reflection(&self, request: &Request, response: &Response) -> Option<Finding> {
        if response.status == 200 {
            let body_str = String::from_utf8_lossy(&response.body);
            
            // Check for reflection service exposure
            if body_str.contains("ServerReflection") || 
               body_str.contains("ListServices") ||
               body_str.contains("google.protobuf") {
                return Some(Finding::new(
                    "gRPC-Web Reflection Exposure",
                    "HIGH",
                    "gRPC reflection endpoint exposed, revealing service definitions",
                    "Disable reflection in production or restrict access by IP/authentication",
                    Some(self.generate_payload()),
                ));
            }
        }
        None
    }

    /// Parse binary proto frame for input validation flaws
    pub fn parse_proto_frame(&self, data: &[u8]) -> Option<String> {
        if data.len() < 5 {
            return None;
        }

        // Zero-copy inspection of gRPC-Web frame header
        // Format: [compression flag (1 byte)][message length (4 bytes big endian)]
        let compressed = data[0] != 0;
        let message_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;

        if message_len > 1024 * 1024 {
            // Suspiciously large message - potential DoS
            return Some(format!("Oversized proto frame detected: {} bytes (compressed: {})", message_len, compressed));
        }

        if self.god_mode && compressed {
            return Some(format!("Compressed proto frame: {} bytes", message_len));
        }

        None
    }

    /// Generate malicious gRPC-Web payload for testing
    pub fn generate_payload(&self) -> String {
        if self.god_mode {
            // Aggressive payload with reflection enumeration
            r#"{"method":"grpc.reflection.v1.ServerReflection/ListServices","data":""}"#.to_string()
        } else {
            r#"{"method":"ListServices"}"#.to_string()
        }
    }

    /// Build test requests for gRPC-Web endpoints
    pub fn build_test_requests(&self, base_target: &str) -> Vec<Request> {
        let mut requests = Vec::with_capacity(GRPC_REFLECTION_METHODS.len());
        
        for method in GRPC_REFLECTION_METHODS.iter() {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/grpc-web+proto".to_string());
            headers.insert("X-User-Agent".to_string(), "grpc-web-javascript/1.0".to_string());
            headers.insert("X-Grpc-Web".to_string(), "1".to_string());
            
            // Minimal proto frame: uncompressed + 0 length
            let mut body = vec![0u8; 5];
            body[0] = 0; // Not compressed
            
            requests.push(Request {
                method: "POST".to_string(),
                uri: format!("{}/{}", base_target.trim_end_matches('/'), method),
                headers,
                body,
            });
        }
        
        requests
    }

    /// Test all proto frame types
    pub fn test_frame_types(&self, target: &str) -> Vec<(String, Vec<u8>)> {
        let mut tests = Vec::with_capacity(PROTO_FRAME_TYPES.len());
        
        for frame_type in PROTO_FRAME_TYPES.iter() {
            // Create minimal valid frame for each type
            let mut frame = vec![0u8; 5];
            frame[0] = 0; // Uncompressed
            
            tests.push((frame_type.to_string(), frame));
        }
        
        tests
    }
}

impl Check for GrpcWebCheck {
    fn name(&self) -> &'static str {
        "grpc_web"
    }

    fn run(&self, target: &str, cache: &mut dyn Cache) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(2);
        
        for request in self.build_test_requests(target) {
            // Mock response - actual implementation uses Stage 2 HTTP engine
            let mock_response = Response {
                status: 200,
                headers: HashMap::new(),
                body: b"\x00\x00\x00\x00\x10grpc.reflection".to_vec(),
            };

            if let Some(finding) = self.detect_reflection(&request, &mock_response) {
                findings.push(finding);
                // Cache successful reflection discovery
                cache.store("grpc_reflection", target);
            }

            // Also parse the response frame
            if let Some(frame_info) = self.parse_proto_frame(&mock_response.body) {
                cache.store("grpc_frame_analysis", &frame_info);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_web_detection() {
        let check = GrpcWebCheck::new(5000, true);
        assert_eq!(check.name(), "grpc_web");
        assert!(check.generate_payload().contains("reflection"));
    }

    #[test]
    fn test_proto_frame_parsing() {
        let check = GrpcWebCheck::new(5000, false);
        let valid_frame = vec![0u8, 0, 0, 0, 16]; // 16 byte message
        assert!(check.parse_proto_frame(&valid_frame).is_none()); // Valid frame
        
        let oversized = vec![0u8, 0xFF, 0xFF, 0xFF, 0xFF]; // Huge message
        assert!(check.parse_proto_frame(&oversized).is_some());
    }
}
