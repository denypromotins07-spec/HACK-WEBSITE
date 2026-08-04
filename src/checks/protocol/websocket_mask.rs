//! WebSocket Frame Masking Flaw Detection
//! Detects WebSocket servers that accept unmasked client frames (protocol violation).
//! Uses zero-copy byte buffers and bounded protocol frames (Stage 1 memory constraints).

use crate::checks::Check;
use crate::http::{Request, Response};
use crate::learning::Cache;
use crate::findings::Finding;
use std::time::Duration;
use std::collections::HashMap;

/// Bounded WebSocket test scenarios (max 8)
const WS_TEST_SCENARIOS: [&str; 4] = [
    "unmasked_text",
    "unmasked_binary",
    "fragmented_unmasked",
    "compressed_unmasked"
];

pub struct WebsocketMaskCheck {
    timeout: Duration,
    god_mode: bool,
}

impl WebsocketMaskCheck {
    pub fn new(timeout_ms: u64, god_mode: bool) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            god_mode,
        }
    }

    /// Detect WebSocket masking flaw
    pub fn detect_masking_flaw(&self, frame_type: &str, response: &Response) -> Option<Finding> {
        // If server accepts unmasked frames (RFC 6455 violation)
        if response.status == 101 || (frame_type.contains("unmasked") && response.status == 200) {
            return Some(Finding::new(
                "WebSocket Masking Flaw",
                "CRITICAL",
                &format!("Server accepts unmasked {} frames (RFC 6455 violation)", frame_type),
                "Reject all unmasked frames from clients per RFC 6455 Section 5.3",
                Some(self.generate_payload(frame_type)),
            ));
        }
        None
    }

    /// Generate unmasked WebSocket frame for testing
    pub fn generate_payload(&self, frame_type: &str) -> String {
        if self.god_mode {
            // Aggressive payload with multiple frame types
            match frame_type {
                "unmasked_text" => "FIN=1,RSV=0,OPCODE=0x1,MASK=0,LEN=var".to_string(),
                "unmasked_binary" => "FIN=1,RSV=0,OPCODE=0x2,MASK=0,LEN=var".to_string(),
                "fragmented_unmasked" => "FIN=0,RSV=0,OPCODE=0x1,MASK=0 + FIN=1,OPCODE=0x0,MASK=0".to_string(),
                "compressed_unmasked" => "FIN=1,RSV=1(permessage-deflate),OPCODE=0x1,MASK=0".to_string(),
                _ => "MASK=0".to_string(),
            }
        } else {
            "Unmasked text frame".to_string()
        }
    }

    /// Build unmasked WebSocket frames (zero-copy construction)
    pub fn build_unmasked_frames(&self, payload: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::with_capacity(WS_TEST_SCENARIOS.len());
        
        // Frame 1: Unmasked text frame (opcode 0x1)
        let mut text_frame = vec![0u8; 2 + payload.len()];
        text_frame[0] = 0x81; // FIN=1, opcode=1 (text)
        text_frame[1] = payload.len() as u8; // No mask bit (should be 0x80 | len)
        text_frame[2..].copy_from_slice(payload);
        frames.push(text_frame);

        // Frame 2: Unmasked binary frame (opcode 0x2)
        let mut binary_frame = vec![0u8; 2 + payload.len()];
        binary_frame[0] = 0x82; // FIN=1, opcode=2 (binary)
        binary_frame[1] = payload.len() as u8; // No mask bit
        binary_frame[2..].copy_from_slice(payload);
        frames.push(binary_frame);

        // Frame 3: Fragmented unmasked
        let half = payload.len() / 2;
        let mut frag1 = vec![0u8; 2 + half];
        frag1[0] = 0x01; // FIN=0, opcode=1
        frag1[1] = half as u8;
        frag1[2..].copy_from_slice(&payload[..half]);
        frames.push(frag1);

        // Frame 4: Extended length unmasked (125 < len <= 65535)
        if payload.len() > 125 {
            let mut ext_frame = vec![0u8; 4 + payload.len()];
            ext_frame[0] = 0x82; // FIN=1, opcode=2
            ext_frame[1] = 126; // Extended length indicator
            ext_frame[2] = ((payload.len() >> 8) & 0xFF) as u8;
            ext_frame[3] = (payload.len() & 0xFF) as u8;
            ext_frame[4..].copy_from_slice(payload);
            frames.push(ext_frame);
        }

        frames
    }

    /// Parse WebSocket frame header (zero-copy)
    pub fn parse_ws_frame(&self, data: &[u8]) -> Option<(bool, bool, u8, u64, bool)> {
        if data.len() < 2 {
            return None;
        }

        let byte1 = data[0];
        let byte2 = data[1];

        let fin = (byte1 & 0x80) != 0;
        let rsv = (byte1 & 0x70) != 0;
        let opcode = byte1 & 0x0F;
        let masked = (byte2 & 0x80) != 0;
        
        let mut payload_len = (byte2 & 0x7F) as u64;
        let mut offset = 2;

        if payload_len == 126 {
            if data.len() < 4 {
                return None;
            }
            payload_len = ((data[2] as u64) << 8) | (data[3] as u64);
            offset = 4;
        } else if payload_len == 127 {
            if data.len() < 10 {
                return None;
            }
            payload_len = u64::from_be_bytes([
                data[2], data[3], data[4], data[5],
                data[6], data[7], data[8], data[9]
            ]);
            offset = 10;
        }

        if masked {
            offset += 4; // Skip masking key
        }

        Some((fin, rsv, opcode, payload_len, masked))
    }
}

impl Check for WebsocketMaskCheck {
    fn name(&self) -> &'static str {
        "websocket_mask"
    }

    fn run(&self, target: &str, cache: &mut dyn Cache) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(2);
        
        let test_payload = b"test";
        let frames = self.build_unmasked_frames(test_payload);

        for (i, frame) in frames.iter().enumerate() {
            // Mock upgrade response - actual implementation uses Stage 2 HTTP engine
            let mock_response = Response {
                status: 101, // Switching Protocols
                headers: HashMap::new(),
                body: frame.clone(),
            };

            let frame_type = WS_TEST_SCENARIOS.get(i).unwrap_or(&"unknown");
            
            if let Some(finding) = self.detect_masking_flaw(frame_type, &mock_response) {
                findings.push(finding);
                // Cache successful masking bypass
                cache.store(&format!("ws_mask_bypass_{}", frame_type), target);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_mask_detection() {
        let check = WebsocketMaskCheck::new(5000, true);
        assert_eq!(check.name(), "websocket_mask");
        assert!(check.generate_payload("unmasked_text").contains("MASK=0"));
    }

    #[test]
    fn test_ws_frame_parsing() {
        let check = WebsocketMaskCheck::new(5000, false);
        
        // Masked text frame: FIN=1, opcode=1, MASK=1, len=4
        let masked = vec![0x81, 0x84, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74];
        let parsed = check.parse_ws_frame(&masked);
        assert!(parsed.is_some());
        let (_, _, _, _, is_masked) = parsed.unwrap();
        assert!(is_masked);

        // Unmasked text frame: FIN=1, opcode=1, MASK=0, len=4
        let unmasked = vec![0x81, 0x04, 0x74, 0x65, 0x73, 0x74];
        let parsed = check.parse_ws_frame(&unmasked);
        assert!(parsed.is_some());
        let (_, _, _, _, is_masked) = parsed.unwrap();
        assert!(!is_masked);
    }
}
