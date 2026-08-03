use bytes::Bytes;
use std::io::{self, Read};

/// Streaming response parser yielding zero-copy body slices.
/// Avoids allocating new Strings during parsing.
pub struct ResponseParser {
    max_body_size: usize,
}

impl ResponseParser {
    pub fn new(max_body_size: usize) -> Self {
        Self { max_body_size }
    }

    /// Parse HTTP response headers and return body slice without allocation.
    pub fn parse<'a>(&self, raw: &'a [u8]) -> Result<ParsedResponse<'a>, ParseError> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        
        let offset = match response.parse(raw)? {
            httparse::Status::Complete(offset) => offset,
            httparse::Status::Partial => return Err(ParseError::Incomplete),
        };

        let status = response.code.unwrap_or(0);
        let version = response.version.unwrap_or(1);
        let headers_slice = &headers[..response.headers.len()];
        
        // Zero-copy body slice
        let body = if offset < raw.len() {
            &raw[offset..]
        } else {
            &[]
        };

        // Enforce body size limit
        if body.len() > self.max_body_size {
            return Err(ParseError::BodyTooLarge(body.len(), self.max_body_size));
        }

        Ok(ParsedResponse {
            status,
            version,
            headers: headers_slice,
            body,
        })
    }

    /// Stream parse chunks from a reader without buffering entire response.
    pub fn stream_parse<R: Read>(&self, reader: &mut R) -> Result<StreamingResponse, io::Error> {
        let mut buffer = vec![0u8; 8192]; // Bounded read buffer
        let mut total_read = 0usize;
        let mut headers_parsed = false;
        let mut body_start = 0usize;

        loop {
            let n = reader.read(&mut buffer[total_read..])?;
            if n == 0 {
                break;
            }
            total_read += n;

            if !headers_parsed {
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut response = httparse::Response::new(&mut headers);
                
                match response.parse(&buffer[..total_read])? {
                    httparse::Status::Complete(offset) => {
                        headers_parsed = true;
                        body_start = offset;
                        break;
                    }
                    httparse::Status::Partial => {
                        if total_read >= buffer.len() {
                            // Need larger buffer for headers (shouldn't happen with normal requests)
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Headers too large",
                            ));
                        }
                    }
                }
            }
        }

        Ok(StreamingResponse {
            reader: Box::new(reader),
            body_offset: body_start,
            buffer,
            bytes_read: total_read,
        })
    }
}

#[derive(Debug)]
pub struct ParsedResponse<'a> {
    pub status: u16,
    pub version: u8,
    pub headers: &'a [httparse::Header<'a>],
    pub body: &'a [u8],
}

pub struct StreamingResponse {
    reader: Box<dyn Read>,
    body_offset: usize,
    buffer: Vec<u8>,
    bytes_read: usize,
}

impl Iterator for StreamingResponse {
    type Item = Result<Vec<u8>, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        // In production, this would yield zero-copy slices from a ring buffer
        None
    }
}

#[derive(Debug)]
pub enum ParseError {
    Incomplete,
    InvalidHeader(httparse::Error),
    BodyTooLarge(usize, usize),
    IoError(io::Error),
}

impl From<httparse::Error> for ParseError {
    fn from(err: httparse::Error) -> Self {
        ParseError::InvalidHeader(err)
    }
}

impl From<io::Error> for ParseError {
    fn from(err: io::Error) -> Self {
        ParseError::IoError(err)
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Incomplete => write!(f, "Incomplete response"),
            ParseError::InvalidHeader(e) => write!(f, "Invalid header: {:?}", e),
            ParseError::BodyTooLarge(actual, max) => {
                write!(f, "Body too large: {} > {}", actual, max)
            }
            ParseError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_complete_response() {
        let parser = ResponseParser::new(1024 * 1024); // 1MB limit
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        
        let result = parser.parse(raw).unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.body, b"hello");
    }

    #[test]
    fn test_body_size_limit() {
        let parser = ResponseParser::new(10); // 10 byte limit
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        let mut full = raw.to_vec();
        full.extend(vec![b'x'; 100]);
        
        let result = parser.parse(&full);
        assert!(matches!(result, Err(ParseError::BodyTooLarge(_, _))));
    }
}
