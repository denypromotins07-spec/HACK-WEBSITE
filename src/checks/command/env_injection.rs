//! Environment Variable Injection Detection
//! Detects environment variable injection and Httpoxy vulnerabilities.
//! Tests for CVE-2016-5385 (Httpoxy) and related proxy header injection flaws.

use crate::checks::Check;
use crate::findings::Finding;
use crate::http::{Request, Response};
use std::collections::HashMap;

/// Maximum number of headers to test (bounded)
const MAX_HEADERS: usize = 25;

/// Headers that may be converted to environment variables
const ENV_HEADERS: &[&str] = &[
    "Proxy",
    "Proxy-Agent",
    "X-Proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "PROXY_HOST",
    "PROXY_PORT",
    "CGI_HTTP_PROXY",
    "REDIRECT_HTTP_PROXY",
    // Additional CGI-related headers
    "Content-Type",
    "Content-Length",
    "Authorization",
    "Cookie",
    "X-Forwarded-Proto",
    "X-Forwarded-Ssl",
    "X-Forwarded-Port",
    "X-Original-URL",
    "X-Rewrite-URL",
];

/// Marker for Httpoxy detection
const HTTPOXY_MARKER: &str = "http://scanner.internal:9999";

pub struct EnvInjectionCheck {
    test_headers: Vec<String>,
}

impl EnvInjectionCheck {
    pub fn new() -> Self {
        let mut headers = Vec::with_capacity(MAX_HEADERS);
        
        for header in ENV_HEADERS.iter() {
            headers.push(header.to_string());
            
            // Add prefixed variants (CGI often adds HTTP_ prefix)
            if !header.starts_with("HTTP_") && !header.starts_with("REDIRECT_") {
                headers.push(format!("HTTP_{}", header.replace("-", "_").to_uppercase()));
            }
        }
        
        Self { test_headers: headers }
    }
    
    /// Test for Httpoxy vulnerability (CVE-2016-5385)
    fn test_httpoxy(&self, req: &Request) -> Option<Finding> {
        let mut test_req = req.clone();
        test_req.set_header("Proxy", HTTPOXY_MARKER);
        
        match test_req.send_with_timeout(5000) {
            Ok(response) => {
                if self.detect_httpoxy_response(&response) {
                    return Some(Finding::new(
                        "HTTPOXY_CVE_2016_5385",
                        "Server is vulnerable to Httpoxy (CVE-2016-5385)",
                        response.url(),
                        8,
                    )
                    .with_payload("Proxy: http://scanner.internal:9999")
                    .with_evidence("Proxy header was processed as environment variable")
                    .with_remediation(
                        "Block Proxy header at web server level. \
                         In Apache: RequestHeader unset Proxy. \
                         In Nginx: fastcgi_param HTTP_PROXY \"\". \
                         Update CGI libraries and frameworks."
                    ));
                }
            }
            Err(_) => {}
        }
        None
    }
    
    /// Detect Httpoxy exploitation indicators
    fn detect_httpoxy_response(&self, response: &Response) -> bool {
        let body = response.body_slice();
        
        // Check for connection errors indicating proxy attempt
        let indicators = [
            b"connection refused",
            b"proxy error",
            b"unable to connect",
            b"ECONNREFUSED",
            b"getaddrinfo",
            b"resolver",
            b"dns resolution",
        ];
        
        for indicator in indicators.iter() {
            if body.contains(indicator) {
                return true;
            }
        }
        
        // Check for timeout (proxy connection attempt)
        // This would need timing analysis from caller
        
        false
    }
    
    /// Test for general environment variable injection
    fn test_env_injection(&self, req: &Request, header: &str) -> Option<Finding> {
        let marker = format!("INJ{:X}", header.len() as u32);
        let mut test_req = req.clone();
        test_req.set_header(header, &marker);
        
        match test_req.send_with_timeout(5000) {
            Ok(response) => {
                if self.detect_env_reflection(&response, &marker) {
                    return Some(Finding::new(
                        "ENV_VARIABLE_INJECTION",
                        &format!(
                            "Header '{}' is converted to environment variable and reflected",
                            header
                        ),
                        response.url(),
                        7,
                    )
                    .with_payload(&format!("{}: {}", header, marker))
                    .with_evidence("Environment variable value reflected in response")
                    .with_remediation(
                        "Sanitize headers before converting to environment variables. \
                         Use allowlists for accepted headers. Avoid passing user input \
                         directly to subprocess environments."
                    ));
                }
            }
            Err(_) => {}
        }
        None
    }
    
    /// Detect environment variable reflection
    fn detect_env_reflection(&self, response: &Response, marker: &str) -> bool {
        let body = response.body_slice();
        
        // Check if marker appears in response
        if body.contains(marker.as_bytes()) {
            return true;
        }
        
        // Check headers for reflection
        for (_, value) in response.headers() {
            if value.contains(marker) {
                return true;
            }
        }
        
        false
    }
}

impl Check for EnvInjectionCheck {
    fn name(&self) -> &'static str {
        "EnvInjection"
    }
    
    fn run(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Test Httpoxy first
        if let Some(finding) = self.test_httpoxy(request) {
            findings.push(finding);
            return findings; // Critical finding, stop here
        }
        
        // Test other env injection vectors
        for header in self.test_headers.iter().take(10) {
            if let Some(finding) = self.test_env_injection(request, header) {
                findings.push(finding);
                break; // One finding per scan
            }
        }
        
        findings
    }
    
    fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("type", "environment_injection");
        meta.insert("severity", "high");
        meta.insert("cve", "CVE-2016-5385");
        meta.insert("cwe", "CWE-117,CWE-78");
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_header_bounds() {
        let check = EnvInjectionCheck::new();
        assert!(check.test_headers.len() <= MAX_HEADERS * 2);
    }
    
    #[test]
    fn test_httpoxy_header_included() {
        let check = EnvInjectionCheck::new();
        assert!(check.test_headers.iter().any(|h| h.contains("Proxy")));
    }
}
