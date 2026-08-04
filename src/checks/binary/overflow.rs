//! Integer and Buffer Overflow Detection
//! Detects integer overflows and buffer overflow signals via boundary value testing.
//! Uses safe boundary values that trigger errors without causing actual memory corruption.

use crate::checks::Check;
use crate::findings::Finding;
use crate::http::{Request, Response};
use std::collections::HashMap;

/// Maximum boundary values to test (bounded)
const MAX_BOUNDARY_VALUES: usize = 25;

/// Boundary values for overflow testing
const BOUNDARY_VALUES: &[i64] = &[
    // Max int8
    127,
    128,
    -128,
    -129,
    // Max int16
    32767,
    32768,
    -32768,
    -32769,
    // Max int32
    2147483647,
    2147483648,
    -2147483648,
    -2147483649,
    // Max int64 (edge cases)
    9223372036854775807,
    9223372036854775808,
    -9223372036854775808,
    // Zero and one boundaries
    0,
    1,
    -1,
    // Large positive/negative
    1000000,
    -1000000,
];

/// String-based overflow payloads
const STRING_OVERFLOW_PAYLOADS: &[&str] = &[
    "A".repeat(1000),   // 1KB string
    "A".repeat(10000),  // 10KB string
    "%n%n%n%n%n",       // Format string
    "%s%s%s%s%s",       // Format string variant
    "\\x00".repeat(100), // Null bytes
];

pub struct OverflowCheck {
    boundary_values: Vec<String>,
    string_payloads: Vec<String>,
}

impl OverflowCheck {
    pub fn new() -> Self {
        let mut boundary_values = Vec::with_capacity(MAX_BOUNDARY_VALUES);
        
        for val in BOUNDARY_VALUES.iter() {
            boundary_values.push(val.to_string());
            
            // Add hex representation
            boundary_values.push(format!("0x{:X}", val));
        }
        
        let string_payloads: Vec<String> = STRING_OVERFLOW_PAYLOADS
            .iter()
            .take(MAX_BOUNDARY_VALUES / 2)
            .map(|s| s.to_string())
            .collect();
        
        Self {
            boundary_values,
            string_payloads,
        }
    }
    
    /// Test parameter for overflow vulnerabilities
    fn test_overflow(&self, req: &Request, param: &str) -> Option<Finding> {
        // Test numeric boundaries
        for value in self.boundary_values.iter() {
            let mut test_req = req.clone();
            test_req.set_param(param, value);
            
            match test_req.send_with_timeout(5000) {
                Ok(response) => {
                    if self.detect_overflow_response(&response, param, value) {
                        return Some(Finding::new(
                            "INTEGER_OVERFLOW",
                            &format!(
                                "Parameter '{}' shows signs of integer overflow with value {}",
                                param, value
                            ),
                            response.url(),
                            8,
                        )
                        .with_payload(value)
                        .with_evidence("Unexpected server behavior at boundary value")
                        .with_remediation(
                            "Use bounded integer types. Validate input ranges. \
                             Implement proper error handling for overflow conditions."
                        ));
                    }
                }
                Err(_) => continue,
            }
        }
        
        // Test string-based overflows
        for payload in self.string_payloads.iter() {
            let mut test_req = req.clone();
            test_req.set_param(param, payload);
            
            match test_req.send_with_timeout(5000) {
                Ok(response) => {
                    if self.detect_buffer_overflow(&response, param) {
                        return Some(Finding::new(
                            "BUFFER_OVERFLOW",
                            &format!(
                                "Parameter '{}' may be vulnerable to buffer overflow",
                                param
                            ),
                            response.url(),
                            9,
                        )
                        .with_payload(&format!("String payload ({} bytes)", payload.len()))
                        .with_evidence("Server crash or unexpected behavior with large input")
                        .with_remediation(
                            "Implement input length validation. Use safe string functions. \
                             Allocate buffers dynamically based on input size."
                        ));
                    }
                }
                Err(_) => continue,
            }
        }
        
        None
    }
    
    /// Detect integer overflow indicators in response
    fn detect_overflow_response(&self, response: &Response, param: &str, value: &str) -> bool {
        let body = response.body_slice();
        
        // Check for error patterns indicating overflow
        let error_patterns = [
            b"overflow",
            b"out of range",
            b"exceeded",
            b"invalid value",
            b"arithmetic",
            b"wrap around",
            b"negative size",
            b"allocation failed",
        ];
        
        for pattern in error_patterns.iter() {
            if body.contains(pattern) {
                return true;
            }
        }
        
        // Check for server crash (500 error after boundary value)
        if response.status_code() == 500 {
            return true;
        }
        
        // Check for connection reset (possible crash)
        if response.status_code() == 0 {
            return true;
        }
        
        false
    }
    
    /// Detect buffer overflow indicators
    fn detect_buffer_overflow(&self, response: &Response, param: &str) -> bool {
        let body = response.body_slice();
        
        // Check for crash indicators
        let crash_patterns = [
            b"segmentation fault",
            b"access violation",
            b"core dumped",
            b"memory error",
            b"buffer",
            b"stack smashing",
            b"heap corruption",
        ];
        
        for pattern in crash_patterns.iter() {
            if body.contains(pattern) {
                return true;
            }
        }
        
        // Server error with large input
        if response.status_code() >= 500 {
            return true;
        }
        
        false
    }
    
    /// Test format string vulnerability (related to buffer issues)
    fn test_format_string(&self, req: &Request, param: &str) -> Option<Finding> {
        let format_payloads = ["%n", "%x", "%s", "%p", "%n%n%n%n"];
        
        for payload in format_payloads.iter() {
            let mut test_req = req.clone();
            test_req.set_param(param, payload);
            
            match test_req.send_with_timeout(5000) {
                Ok(response) => {
                    let body = response.body_slice();
                    
                    // Check for format string exploitation indicators
                    if body.contains(b"0x") && body.contains(b"ffff") {
                        return Some(Finding::new(
                            "FORMAT_STRING_VULNERABILITY",
                            &format!(
                                "Parameter '{}' may be vulnerable to format string attacks",
                                param
                            ),
                            response.url(),
                            8,
                        )
                        .with_payload(payload)
                        .with_evidence("Memory addresses leaked in response")
                        .with_remediation(
                            "Never pass user input as format string argument. \
                             Use explicit format strings like printf(\"%s\", user_input)."
                        ));
                    }
                }
                Err(_) => continue,
            }
        }
        None
    }
}

impl Check for OverflowCheck {
    fn name(&self) -> &'static str {
        "OverflowDetection"
    }
    
    fn run(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Test numeric-looking parameters
        let numeric_params = ["id", "count", "size", "length", "offset", "limit", "page"];
        for param in numeric_params.iter() {
            if request.has_param(param) {
                if let Some(finding) = self.test_overflow(request, param) {
                    findings.push(finding);
                    break;
                }
            }
        }
        
        // Test all parameters for format string
        for (param, _value) in request.query_params() {
            if let Some(finding) = self.test_format_string(request, param) {
                findings.push(finding);
                break;
            }
        }
        
        findings
    }
    
    fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("type", "overflow");
        meta.insert("severity", "high");
        meta.insert("cwe", "CWE-190,CWE-120,CWE-134");
        meta.insert("category", "memory_safety");
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_boundary_count() {
        let check = OverflowCheck::new();
        assert!(check.boundary_values.len() <= MAX_BOUNDARY_VALUES * 2);
    }
    
    #[test]
    fn test_boundary_values_present() {
        let check = OverflowCheck::new();
        assert!(check.boundary_values.iter().any(|v| v.contains("2147483647")));
        assert!(check.boundary_values.iter().any(|v| v.contains("32767")));
    }
}
