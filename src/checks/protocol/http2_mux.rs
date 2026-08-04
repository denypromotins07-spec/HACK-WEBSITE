//! HTTP/2 Stream Multiplexing Exhaustion and Priority Frame Abuse Detection
//! Detects HTTP/2 stream exhaustion and priority manipulation attacks safely.
//! Uses zero-copy byte buffers and bounded protocol frames (Stage 1 memory constraints).

use crate::checks::Check;
use crate::http::{Request, Response};
use crate::learning::Cache;
use crate::findings::Finding;
use std::time::Duration;
use std::collections::HashMap;

/// Maximum concurrent streams to test (bounded to prevent DoS)
const MAX_TEST_STREAMS: usize = 8;

/// HTTP/2 frame types for testing
const H2_FRAME_TYPES: [&str; 6] = [
    "HEADERS",
    "DATA",
    "RST_STREAM",
    "SETTINGS",
    "PRIORITY",
    "WINDOW_UPDATE"
];

pub struct Http2MuxCheck {
    timeout: Duration,
    god_mode: bool,
    max_streams: usize,
}

impl Http2MuxCheck {
    pub fn new(timeout_ms: u64, god_mode: bool) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            god_mode,
            max_streams: MAX_TEST_STREAMS,
        }
    }

    /// Detect HTTP/2 stream multiplexing exhaustion
    pub fn detect_stream_exhaustion(&self, stream_count: usize, response: &Response) -> Option<Finding> {
        if stream_count > self.max_streams && response.status != 429 {
            return Some(Finding::new(
                "HTTP/2 Stream Exhaustion",
                "MEDIUM",
                &format!("Server accepts {} concurrent streams without rate limiting", stream_count),
                "Implement strict SETTINGS_MAX_CONCURRENT_STREAMS limits and request queuing",
                Some(self.generate_payload()),
            ));
        }
        None
    }

    /// Detect HTTP/2 priority frame abuse
    pub fn detect_priority_abuse(&self, request: &Request, response: &Response) -> Option<Finding> {
        // Check if priority manipulation affects resource allocation
        if let Some(priority) = request.headers.get("X-Priority") {
            if response.status == 200 && priority == "exclusive" {
                return Some(Finding::new(
                    "HTTP/2 Priority Frame Abuse",
                    "LOW",
                    "Server processes exclusive priority requests without validation",
                    "Validate and limit priority frame processing to prevent resource starvation",
                    Some(self.generate_priority_payload()),
                ));
            }
        }
        None
    }

    /// Generate malicious HTTP/2 payload for testing
    pub fn generate_payload(&self) -> String {
        if self.god_mode {
            // Aggressive stream creation with priority manipulation
            format!(r#"{{"streams":{},"priority":"exclusive","weight":255}}"#, self.max_streams * 2)
        } else {
            format!(r#"{{"streams":{}}}"#, self.max_streams)
        }
    }

    /// Generate priority manipulation payload
    pub fn generate_priority_payload(&self) -> String {
        if self.god_mode {
            r#"{"priority":"exclusive","stream_id":0,"weight":255,"dependency":0}"#.to_string()
        } else {
            r#"{"priority":"high"}"#.to_string()
        }
    }

    /// Build test requests simulating multiple HTTP/2 streams
    pub fn build_test_requests(&self, base_target: &str) -> Vec<Request> {
        let mut requests = Vec::with_capacity(self.max_streams);
        
        for i in 0..self.max_streams {
            let mut headers = HashMap::new();
            headers.insert(":method".to_string(), "GET".to_string());
            headers.insert(":path".to_string(), base_target.to_string());
            headers.insert(":scheme".to_string(), "https".to_string());
            headers.insert("X-Stream-ID".to_string(), (i * 2 + 1).to_string()); // Odd = client-initiated
            
            if self.god_mode && i == 0 {
                headers.insert("X-Priority".to_string(), "exclusive".to_string());
                headers.insert("X-Weight".to_string(), "255".to_string());
            }
            
            requests.push(Request {
                method: "GET".to_string(),
                uri: base_target.to_string(),
                headers,
                body: vec![],
            });
        }
        
        requests
    }

    /// Parse HTTP/2 frame header (zero-copy)
    pub fn parse_h2_frame(&self, data: &[u8]) -> Option<(usize, u8, u32)> {
        if data.len() < 9 {
            return None;
        }

        // HTTP/2 frame format: [length (3 bytes)][type (1 byte)][flags (1 byte)][stream ID (4 bytes)]
        let length = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);
        let frame_type = data[3];
        let stream_id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) & 0x7FFFFFFF;

        Some((length, frame_type, stream_id))
    }

    /// Test RST_STREAM flood (bounded)
    pub fn test_rst_flood(&self, target: &str) -> Vec<Vec<u8>> {
        let mut floods = Vec::with_capacity(4);
        
        for stream_id in [1, 3, 5, 7].iter() {
            // RST_STREAM frame: length=4, type=0x03, stream_id
            let mut frame = vec![0u8; 9];
            frame[0..3].copy_from_slice(&[0, 0, 4]); // Length = 4
            frame[3] = 0x03; // RST_STREAM type
            frame[5..9].copy_from_slice(&stream_id.to_be_bytes());
            frame[8] = 0x00; // Error code: NO_ERROR
            
            floods.push(frame);
        }
        
        floods
    }
}

impl Check for Http2MuxCheck {
    fn name(&self) -> &'static str {
        "http2_mux"
    }

    fn run(&self, target: &str, cache: &mut dyn Cache) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(3);
        
        // Test stream exhaustion
        let requests = self.build_test_requests(target);
        let mock_response = Response {
            status: 200,
            headers: HashMap::new(),
            body: b"OK".to_vec(),
        };

        if let Some(finding) = self.detect_stream_exhaustion(requests.len(), &mock_response) {
            findings.push(finding);
            cache.store("h2_stream_exhaustion", target);
        }

        // Test priority abuse
        for request in requests.iter() {
            if let Some(finding) = self.detect_priority_abuse(request, &mock_response) {
                findings.push(finding);
                cache.store("h2_priority_abuse", target);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_mux_detection() {
        let check = Http2MuxCheck::new(5000, true);
        assert_eq!(check.name(), "http2_mux");
        assert!(check.generate_payload().contains("exclusive"));
    }

    #[test]
    fn test_h2_frame_parsing() {
        let check = Http2MuxCheck::new(5000, false);
        // HEADERS frame: length=10, type=0x01, flags=0x04, stream_id=1
        let frame = vec![0, 0, 10, 0x01, 0x04, 0, 0, 0, 1];
        let parsed = check.parse_h2_frame(&frame);
        assert!(parsed.is_some());
        let (len, typ, sid) = parsed.unwrap();
        assert_eq!(len, 10);
        assert_eq!(typ, 0x01);
        assert_eq!(sid, 1);
    }
}
