//! Native Deserialization Vulnerability Detection
//! Triggers memory issues via unvalidated inputs in compiled extensions.
//! Detects unsafe deserialization in native code (C/C++ extensions, JNI, etc.)

use crate::checks::Check;
use crate::findings::Finding;
use crate::http::{Request, Response};
use std::collections::HashMap;

/// Maximum payload variants (bounded)
const MAX_DESER_PAYLOADS: usize = 20;

/// Serialized object markers for different languages
const JAVA_SERIALIZED: &[u8] = &[0xAC, 0xED, 0x00, 0x05]; // Java serialization magic
const PHP_SERIALIZED: &[u8] = b"O:4:\"Test\""; // PHP serialized object
const PYTHON_PICKLE: &[u8] = &[0x80, 0x04]; // Python pickle protocol 4

/// Payloads designed to trigger deserialization issues
const DESER_PAYLOADS: &[&str] = &[
    // Java gadget chains (markers only, non-exploitative)
    "ACED000573720012DESER_TEST_MARKER",
    // PHP object injection
    "O:8:\"stdClass\":1:{s:4:\"test\";s:6:\"marker\";}",
    // Python pickle with marker
    "\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x8c\x0bDESER_TEST\x94.",
    // YAML deserialization markers
    "!!python/object:__main__.Test {}",
    "!!ruby/object:Gem::Installer {}",
    // .NET BinaryFormatter markers
    "AAEAAAD/////AQAAAAAAAAAMAgAA",
];

pub struct NativeDeserCheck {
    payloads: Vec<Vec<u8>>,
}

impl NativeDeserCheck {
    pub fn new() -> Self {
        let mut payloads = Vec::with_capacity(MAX_DESER_PAYLOADS);
        
        for payload_str in DESER_PAYLOADS.iter() {
            payloads.push(payload_str.as_bytes().to_vec());
            
            // Add base64 encoded variant
            let encoded = base64_encode(payload_str.as_bytes());
            if payloads.len() < MAX_DESER_PAYLOADS {
                payloads.push(encoded.into_bytes());
            }
        }
        
        Self { payloads }
    }
    
    /// Test deserialization endpoint
    fn test_deserialization(&self, req: &Request, param: &str) -> Option<Finding> {
        for payload in self.payloads.iter() {
            let mut test_req = req.clone();
            
            // Try as query parameter
            test_req.set_param(param, &String::from_utf8_lossy(payload));
            
            match test_req.send_with_timeout(5000) {
                Ok(response) => {
                    if self.detect_deser_vulnerability(&response, payload) {
                        return Some(Finding::new(
                            "NATIVE_DESERIALIZATION_VULNERABILITY",
                            &format!(
                                "Parameter '{}' accepts serialized objects potentially processed by native code",
                                param
                            ),
                            response.url(),
                            9,
                        )
                        .with_payload(&format!("Serialized payload ({} bytes)", payload.len()))
                        .with_evidence("Server accepted and potentially processed serialized object")
                        .with_remediation(
                            "Avoid deserializing untrusted data in native code. \
                             Use safe serialization formats (JSON). \
                             Validate input types before deserialization."
                        ));
                    }
                }
                Err(_) => continue,
            }
        }
        None
    }
    
    /// Detect deserialization vulnerability indicators
    fn detect_deser_vulnerability(&self, response: &Response, payload: &[u8]) -> bool {
        let body = response.body_slice();
        
        // Check for error patterns indicating deserialization attempt
        let error_patterns = [
            b"ClassCastException",
            b"InvalidClassException",
            b"StreamCorruptedException",
            b"unserialize()",
            b"unpickling",
            b"pickle",
            b"deserialization",
            b"yaml.load",
            b"BinaryFormatter",
            b"ObjectInputStream",
            b"segmentation fault",
            b"memory access",
        ];
        
        for pattern in error_patterns.iter() {
            if body.contains(pattern) {
                return true;
            }
        }
        
        // Check for crash indicators (server error after payload)
        if response.status_code() >= 500 {
            return true;
        }
        
        false
    }
    
    /// Test header-based deserialization (some frameworks deserialize headers)
    fn test_header_deserialization(&self, req: &Request, header: &str) -> Option<Finding> {
        for payload in self.payloads.iter().take(5) {
            let mut test_req = req.clone();
            test_req.set_header(header, &String::from_utf8_lossy(payload));
            
            match test_req.send_with_timeout(5000) {
                Ok(response) => {
                    if self.detect_deser_vulnerability(&response, payload) {
                        return Some(Finding::new(
                            "HEADER_DESERIALIZATION_VULNERABILITY",
                            &format!(
                                "Header '{}' accepts serialized objects",
                                header
                            ),
                            response.url(),
                            8,
                        )
                        .with_payload(&format!("Serialized payload in {}", header))
                        .with_evidence("Header value processed as serialized object")
                        .with_remediation(
                            "Do not deserialize header values. \
                             Validate and sanitize all header inputs."
                        ));
                    }
                }
                Err(_) => continue,
            }
        }
        None
    }
}

impl Check for NativeDeserCheck {
    fn name(&self) -> &'static str {
        "NativeDeserialization"
    }
    
    fn run(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Test common parameters that might accept serialized data
        let params = ["data", "object", "payload", "serialized", "input"];
        for param in params.iter() {
            if request.has_param(param) {
                if let Some(finding) = self.test_deserialization(request, param) {
                    findings.push(finding);
                    break;
                }
            }
        }
        
        // Test headers
        let headers = ["X-Object", "X-Serialized", "X-Data"];
        for header in headers.iter() {
            if let Some(finding) = self.test_header_deserialization(request, header) {
                findings.push(finding);
                break;
            }
        }
        
        findings
    }
    
    fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("type", "native_deserialization");
        meta.insert("severity", "critical");
        meta.insert("cwe", "CWE-502");
        meta.insert("category", "deserialization");
        meta
    }
}

/// Simple base64 encoding helper
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        
        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        
        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }
        
        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3F] as char);
        } else {
            result.push('=');
        }
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_payload_count() {
        let check = NativeDeserCheck::new();
        assert!(check.payloads.len() <= MAX_DESER_PAYLOADS * 2);
    }
    
    #[test]
    fn test_base64_encoding() {
        let encoded = base64_encode(b"Hello");
        assert_eq!(encoded, "SGVsbG8=");
    }
}
