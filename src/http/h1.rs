use crate::http::client::HttpClient;
use bytes::Bytes;

/// HTTP/1.1 keep-alive management and pipeline structures.
/// Handles connection reuse and detects potential smuggling vectors.
pub struct Http1Handler {
    keep_alive_timeout: u64,
    max_pipelined_requests: usize,
}

impl Http1Handler {
    pub fn new(keep_alive_timeout_secs: u64) -> Self {
        Self {
            keep_alive_timeout: keep_alive_timeout_secs,
            max_pipelined_requests: 4, // Conservative limit
        }
    }

    /// Check if connection should be kept alive based on headers.
    pub fn should_keep_alive(&self, headers: &httparse::Headers) -> bool {
        for header in headers.iter() {
            if header.name.eq_ignore_ascii_case("connection") {
                let value = std::str::from_utf8(header.value).unwrap_or("");
                return value.eq_ignore_ascii_case("keep-alive");
            }
        }
        false
    }

    /// Detect potential HTTP request smuggling via Content-Length/Transfer-Encoding conflicts.
    pub fn detect_smuggling(&self, raw_request: &[u8]) -> Option<SmugglingVector> {
        let mut has_cl = false;
        let mut has_te = false;
        let mut cl_values: Vec<u64> = Vec::new();

        // Zero-copy scan for conflicting headers
        let mut pos = 0;
        while pos < raw_request.len() {
            if let Some(eol) = raw_request[pos..].iter().position(|&b| b == b'\n') {
                let line = &raw_request[pos..pos + eol];
                
                if line.starts_with(b"Content-Length:") || line.starts_with(b"content-length:") {
                    has_cl = true;
                    if let Ok(val) = std::str::from_utf8(&line[15..].trim())
                        .and_then(|s| s.parse::<u64>()) 
                    {
                        cl_values.push(val);
                    }
                }
                
                if line.starts_with(b"Transfer-Encoding:") || line.starts_with(b"transfer-encoding:") {
                    has_te = true;
                }

                pos += eol + 1;
            } else {
                break;
            }
        }

        // Smuggling detected if both CL and TE present, or multiple CL values
        if has_cl && has_te {
            return Some(SmugglingVector::ClTeConflict);
        }
        
        if cl_values.len() > 1 && cl_values.windows(2).any(|w| w[0] != w[1]) {
            return Some(SmugglingVector::MultipleContentLength);
        }

        None
    }

    /// Build a zero-copy response slice from raw bytes.
    pub fn parse_response<'a>(&self, raw: &'a [u8]) -> Result<Http1Response<'a>, ParseError> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Response::new(&mut headers);
        
        match req.parse(raw)? {
            httparse::Status::Complete(offset) => {
                Ok(Http1Response {
                    version: req.version.unwrap_or(1),
                    status: req.code.unwrap_or(200),
                    headers: &headers[..req.headers.len()],
                    body: &raw[offset..],
                })
            }
            httparse::Status::Partial => Err(ParseError::Incomplete),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SmugglingVector {
    ClTeConflict,
    MultipleContentLength,
    InvalidChunkSize,
}

#[derive(Debug)]
pub struct Http1Response<'a> {
    pub version: u8,
    pub status: u16,
    pub headers: &'a [httparse::Header<'a>],
    pub body: &'a [u8],
}

#[derive(Debug)]
pub enum ParseError {
    Incomplete,
    InvalidHeader(httparse::Error),
}

impl From<httparse::Error> for ParseError {
    fn from(err: httparse::Error) -> Self {
        ParseError::InvalidHeader(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smuggling_detection() {
        let handler = Http1Handler::new(30);
        
        // Request with both CL and TE - smuggling vector
        let malicious = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(handler.detect_smuggling(malicious), Some(SmugglingVector::ClTeConflict)));
    }
}
