use bytes::Bytes;
use std::io::{self, Read};

/// Bounded decoders for chunked and compressed bodies.
/// Enforces strict maximum size limits to prevent memory exhaustion.
pub struct BodyDecoder {
    max_size: usize,
}

impl BodyDecoder {
    pub fn new(max_size: usize) -> Self {
        Self { max_size }
    }

    /// Decode chunked transfer encoding with bounded output.
    pub fn decode_chunked(&self, input: &[u8]) -> Result<Vec<u8>, BodyError> {
        let mut output = Vec::with_capacity(self.max_size.min(65536)); // Pre-allocate bounded
        let mut pos = 0;

        while pos < input.len() {
            // Find end of line for chunk size
            let eol = input[pos..]
                .iter()
                .position(|&b| b == b'\n')
                .ok_or(BodyError::TruncatedChunk)?;

            let size_hex = std::str::from_utf8(&input[pos..pos + eol])
                .map_err(|_| BodyError::InvalidChunkSize)?
                .trim();

            let chunk_size = usize::from_str_radix(size_hex.split(';').next().unwrap_or(""), 16)
                .map_err(|_| BodyError::InvalidChunkSize)?;

            if chunk_size == 0 {
                // Final chunk
                break;
            }

            if output.len() + chunk_size > self.max_size {
                return Err(BodyError::SizeLimitExceeded(output.len() + chunk_size, self.max_size));
            }

            pos += eol + 1; // Skip size line
            let chunk_end = pos + chunk_size;
            
            if chunk_end > input.len() {
                return Err(BodyError::TruncatedChunk);
            }

            output.extend_from_slice(&input[pos..chunk_end]);
            pos = chunk_end;

            // Skip CRLF after chunk
            if pos + 1 < input.len() && input[pos] == b'\r' && input[pos + 1] == b'\n' {
                pos += 2;
            } else if pos < input.len() && input[pos] == b'\n' {
                pos += 1;
            }
        }

        Ok(output)
    }

    /// Decode gzip-compressed body with bounded output.
    #[cfg(feature = "compression")]
    pub fn decode_gzip(&self, input: &[u8]) -> Result<Vec<u8>, BodyError> {
        use flate2::read::GzDecoder;

        let mut decoder = GzDecoder::new(input);
        let mut output = Vec::with_capacity(self.max_size.min(65536));
        
        decoder
            .take((self.max_size - output.len()) as u64)
            .read_to_end(&mut output)
            .map_err(|e| BodyError::DecompressionError(e.to_string()))?;

        if output.len() > self.max_size {
            return Err(BodyError::SizeLimitExceeded(output.len(), self.max_size));
        }

        Ok(output)
    }

    /// Decode brotli-compressed body with bounded output.
    #[cfg(feature = "compression")]
    pub fn decode_brotli(&self, input: &[u8]) -> Result<Vec<u8>, BodyError> {
        use brotli::BrotliDecompress;

        let mut output = Vec::with_capacity(self.max_size.min(65536));
        
        BrotliDecompress(&mut io::Cursor::new(input), &mut output, self.max_size)
            .map_err(|e| BodyError::DecompressionError(e.to_string()))?;

        if output.len() > self.max_size {
            return Err(BodyError::SizeLimitExceeded(output.len(), self.max_size));
        }

        Ok(output)
    }

    /// Get content type from magic bytes without full parsing.
    pub fn detect_content_type(&self, data: &[u8]) -> Option<&'static str> {
        if data.len() < 4 {
            return None;
        }

        match &data[0..4] {
            b"\x1f\x8b\x08\x00" | b"\x1f\x8b\x08\x08" => Some("application/gzip"),
            b"BZh9" => Some("application/x-bzip2"),
            [0x50, 0x4b, 0x03, 0x04] => Some("application/zip"),
            _ => {
                if data.starts_with(b"{") || data.starts_with(b"[") {
                    Some("application/json")
                } else if data.starts_with(b"<") {
                    Some("text/html")
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum BodyError {
    TruncatedChunk,
    InvalidChunkSize,
    SizeLimitExceeded(usize, usize),
    DecompressionError(String),
    UnsupportedEncoding(String),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyError::TruncatedChunk => write!(f, "Truncated chunk"),
            BodyError::InvalidChunkSize => write!(f, "Invalid chunk size"),
            BodyError::SizeLimitExceeded(actual, max) => {
                write!(f, "Size limit exceeded: {} > {}", actual, max)
            }
            BodyError::DecompressionError(msg) => write!(f, "Decompression error: {}", msg),
            BodyError::UnsupportedEncoding(enc) => write!(f, "Unsupported encoding: {}", enc),
        }
    }
}

impl std::error::Error for BodyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_chunked() {
        let decoder = BodyDecoder::new(1024);
        // Chunked: "5\r\nhello\r\n0\r\n\r\n"
        let input = b"5\r\nhello\r\n0\r\n\r\n";
        
        let result = decoder.decode_chunked(input).unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_size_limit() {
        let decoder = BodyDecoder::new(5);
        let input = b"5\r\nhello\r\n0\r\n\r\n";
        
        let result = decoder.decode_chunked(input);
        assert!(matches!(result, Err(BodyError::SizeLimitExceeded(_, _))));
    }

    #[test]
    fn test_detect_content_type() {
        let decoder = BodyDecoder::new(1024);
        
        assert_eq!(decoder.detect_content_type(b"{\"key\": \"value\"}"), Some("application/json"));
        assert_eq!(decoder.detect_content_type(b"<html>"), Some("text/html"));
    }
}
