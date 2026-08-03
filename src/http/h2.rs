use crate::http::config::NetworkConfig;
use bytes::Bytes;
use std::sync::Arc;

/// HTTP/2 stream multiplexing logic with bounded memory usage.
/// Handles priority frames, flow control, and stream exhaustion safely.
pub struct Http2Handler {
    max_concurrent_streams: u32,
    initial_window_size: u32,
    max_frame_size: u32,
}

impl Http2Handler {
    pub fn new(config: &NetworkConfig) -> Self {
        Self {
            max_concurrent_streams: config.h2_max_concurrent_streams,
            initial_window_size: config.h2_initial_window_size,
            max_frame_size: 16384, // Default HTTP/2 max frame size
        }
    }

    /// Check if a new stream can be created without exhausting limits.
    pub fn can_create_stream(&self, current_streams: u32) -> bool {
        current_streams < self.max_concurrent_streams
    }

    /// Calculate safe window update to prevent memory overflow.
    pub fn calculate_window_update(&self, consumed: u32, current_window: u32) -> u32 {
        let threshold = self.initial_window_size / 2;
        if current_window + consumed <= threshold {
            consumed
        } else {
            0
        }
    }

    /// Validate frame size against bounds.
    pub fn validate_frame_size(&self, size: u32) -> Result<(), Http2Error> {
        if size > self.max_frame_size {
            Err(Http2Error::FrameTooLarge(size))
        } else {
            Ok(())
        }
    }

    /// Handle stream priority changes within bounds.
    pub fn handle_priority(
        &self,
        stream_id: u32,
        dependency_id: u32,
        weight: u8,
    ) -> PriorityConfig {
        PriorityConfig {
            stream_id,
            dependency_id,
            weight: weight.saturating_add(1), // Weight is 1-256
        }
    }

    /// Detect stream exhaustion attack patterns.
    pub fn detect_exhaustion(&self, rapid_stream_count: u32, time_window_ms: u64) -> bool {
        // More than max streams in 1 second indicates attack
        if time_window_ms < 1000 && rapid_stream_count > self.max_concurrent_streams {
            return true;
        }
        false
    }
}

#[derive(Debug, Clone)]
pub struct PriorityConfig {
    pub stream_id: u32,
    pub dependency_id: u32,
    pub weight: u8,
}

#[derive(Debug)]
pub enum Http2Error {
    FrameTooLarge(u32),
    StreamExhausted,
    ProtocolError(String),
    FlowControlViolation,
}

impl std::fmt::Display for Http2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Http2Error::FrameTooLarge(size) => write!(f, "Frame too large: {} bytes", size),
            Http2Error::StreamExhausted => write!(f, "Stream limit exhausted"),
            Http2Error::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            Http2Error::FlowControlViolation => write!(f, "Flow control violation"),
        }
    }
}

impl std::error::Error for Http2Error {}

/// Zero-copy HTTP/2 frame parser.
pub struct FrameParser<'a> {
    data: &'a [u8],
}

impl<'a> FrameParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Parse frame header (9 bytes) without allocation.
    pub fn parse_header(&self) -> Option<FrameHeader> {
        if self.data.len() < 9 {
            return None;
        }

        let length = ((self.data[0] as u32) << 16)
            | ((self.data[1] as u32) << 8)
            | (self.data[2] as u32);
        let frame_type = self.data[3];
        let flags = self.data[4];
        let stream_id = u32::from_be_bytes([
            self.data[5] & 0x7F,
            self.data[6],
            self.data[7],
            self.data[8],
        ]);

        Some(FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
            payload: &self.data[9..9.min(self.data.len())],
        })
    }
}

#[derive(Debug)]
pub struct FrameHeader<'a> {
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_limit() {
        let config = NetworkConfig::default();
        let handler = Http2Handler::new(&config);
        
        assert!(handler.can_create_stream(50));
        assert!(!handler.can_create_stream(100));
    }

    #[test]
    fn test_frame_validation() {
        let config = NetworkConfig::default();
        let handler = Http2Handler::new(&config);
        
        assert!(handler.validate_frame_size(10000).is_ok());
        assert!(handler.validate_frame_size(20000).is_err());
    }
}
