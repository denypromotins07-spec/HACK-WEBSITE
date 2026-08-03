use httparse::{Header, EMPTY_HEADER};

/// Ultra-fast header extraction using httparse.
/// Eliminates heap allocations during header reads via zero-copy slices.
pub struct HeaderExtractor {
    max_headers: usize,
}

impl HeaderExtractor {
    pub fn new(max_headers: usize) -> Self {
        Self { max_headers }
    }

    /// Extract a specific header value without allocation.
    /// Returns a byte slice reference into the original buffer.
    pub fn extract<'a>(&self, headers: &'a [Header], name: &str) -> Option<&'a [u8]> {
        for header in headers {
            if header.name.eq_ignore_ascii_case(name) {
                return Some(header.value);
            }
        }
        None
    }

    /// Extract all values for a header (handles duplicates).
    pub fn extract_all<'a>(&self, headers: &'a [Header], name: &str) -> Vec<&'a [u8]> {
        headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value)
            .collect()
    }

    /// Check if a header exists without extracting value.
    pub fn has_header(&self, headers: &[Header], name: &str) -> bool {
        headers.iter().any(|h| h.name.eq_ignore_ascii_case(name))
    }

    /// Parse raw HTTP request/response and extract headers zero-copy.
    pub fn parse_headers<'a>(&self, raw: &'a [u8]) -> Result<Vec<Header<'a>>, HeaderError> {
        let mut headers = vec![EMPTY_HEADER; self.max_headers];
        let mut offset = 0;

        // Skip status/request line
        if let Some(eol) = raw[offset..].iter().position(|&b| b == b'\n') {
            offset += eol + 1;
        } else {
            return Err(HeaderError::NoLineEnding);
        }

        let mut count = 0;
        while offset < raw.len() && count < self.max_headers {
            if let Some(eol) = raw[offset..].iter().position(|&b| b == b'\n') {
                if eol == 0 {
                    // Empty line marks end of headers
                    break;
                }

                let line = &raw[offset..offset + eol];
                if let Some(colon_pos) = line.iter().position(|&b| b == b':') {
                    let name = std::str::from_utf8(&line[..colon_pos])
                        .map_err(|_| HeaderError::InvalidUtf8)?;
                    
                    // Skip ": " after colon
                    let mut value_start = colon_pos + 1;
                    while value_start < line.len() && line[value_start] == b' ' {
                        value_start += 1;
                    }

                    headers[count] = Header {
                        name,
                        value: &line[value_start..],
                    };
                    count += 1;
                }

                offset += eol + 1;
            } else {
                break;
            }
        }

        Ok(headers[..count].to_vec())
    }

    /// Get content-length as u64 without parsing to String.
    pub fn get_content_length(&self, headers: &[Header]) -> Option<u64> {
        self.extract(headers, "content-length")
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|s| s.parse::<u64>().ok())
    }

    /// Check for transfer-encoding: chunked without allocation.
    pub fn is_chunked(&self, headers: &[Header]) -> bool {
        self.extract(headers, "transfer-encoding")
            .map(|v| v.eq_ignore_ascii_case(b"chunked"))
            .unwrap_or(false)
    }
}

#[derive(Debug)]
pub enum HeaderError {
    NoLineEnding,
    InvalidUtf8,
    TooManyHeaders,
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderError::NoLineEnding => write!(f, "No line ending found"),
            HeaderError::InvalidUtf8 => write!(f, "Invalid UTF-8 in header name"),
            HeaderError::TooManyHeaders => write!(f, "Too many headers"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// Common header names as static slices for zero-copy comparison.
pub mod header_names {
    pub const CONTENT_LENGTH: &str = "content-length";
    pub const CONTENT_TYPE: &str = "content-type";
    pub const TRANSFER_ENCODING: &str = "transfer-encoding";
    pub const CONNECTION: &str = "connection";
    pub const HOST: &str = "host";
    pub const USER_AGENT: &str = "user-agent";
    pub const SET_COOKIE: &str = "set-cookie";
    pub const COOKIE: &str = "cookie";
    pub const AUTHORIZATION: &str = "authorization";
    pub const LOCATION: &str = "location";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_header() {
        let extractor = HeaderExtractor::new(64);
        let headers = [
            Header { name: "content-type", value: b"application/json" },
            Header { name: "content-length", value: b"1234" },
        ];

        assert_eq!(extractor.extract(&headers, "content-type"), Some(&b"application/json"[..]));
        assert_eq!(extractor.extract(&headers, "content-length"), Some(&b"1234"[..]));
        assert_eq!(extractor.extract(&headers, "x-custom"), None);
    }

    #[test]
    fn test_get_content_length() {
        let extractor = HeaderExtractor::new(64);
        let headers = [
            Header { name: "content-length", value: b"5678" },
        ];

        assert_eq!(extractor.get_content_length(&headers), Some(5678));
    }

    #[test]
    fn test_is_chunked() {
        let extractor = HeaderExtractor::new(64);
        let chunked = [Header { name: "transfer-encoding", value: b"chunked" }];
        let not_chunked = [Header { name: "transfer-encoding", value: b"identity" }];

        assert!(extractor.is_chunked(&chunked));
        assert!(!extractor.is_chunked(&not_chunked));
    }
}
