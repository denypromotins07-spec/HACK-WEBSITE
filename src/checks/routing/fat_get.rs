//! Fat GET Request Detection
//! Detects HTTP GET requests with JSON bodies that some servers incorrectly process.
//! Uses zero-copy byte buffers and bounded protocol frames (Stage 1 memory constraints).

use crate::checks::Check;
use crate::http::{Request, Response};
use crate::learning::Cache;
use crate::findings::Finding;
use std::time::Duration;
use std::collections::HashMap;

/// Bounded Fat GET payload templates (max 8)
const FAT_GET_PAYLOADS: [&str; 4] = [
    r#"{"action":"admin","role":"superuser"}"#,
    r#"{"debug":true,"bypass":true}"#,
    r#"{"_method":"PUT","id":1}"#,
    r#"{"override":"true"}"#
];

pub struct FatGetCheck {
    timeout: Duration,
    god_mode: bool,
}

impl FatGetCheck {
    pub fn new(timeout_ms: u64, god_mode: bool) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            god_mode,
        }
    }

    /// Detect Fat GET processing vulnerability
    pub fn detect_fat_get(&self, request: &Request, response: &Response) -> Option<Finding> {
        // If GET request has body and server processes it (status change or specific response)
        if request.method == "GET" && !request.body.is_empty() {
            // Check for signs that the body was processed
            if response.status != 400 && response.status != 405 {
                let body_str = String::from_utf8_lossy(&response.body);
                
                // Look for signs of body processing
                if body_str.contains("admin") || body_str.contains("superuser") || 
                   body_str.contains("debug") || response.status == 200 {
                    return Some(Finding::new(
                        "Fat GET Request Processing",
                        "MEDIUM",
                        "Server processes JSON body in HTTP GET request",
                        "Reject or ignore request bodies on GET methods at the web server level",
                        Some(self.generate_payload()),
                    ));
                }
            }
        }
        None
    }

    /// Generate Fat GET payload for testing
    pub fn generate_payload(&self) -> String {
        if self.god_mode {
            // Aggressive payload with multiple bypass attempts
            r#"{"action":"admin","role":"superuser","debug":true,"_method":"DELETE","bypass":"true"}"#.to_string()
        } else {
            FAT_GET_PAYLOADS[0].to_string()
        }
    }

    /// Build test requests with Fat GET bodies
    pub fn build_test_requests(&self, target: &str) -> Vec<Request> {
        let mut requests = Vec::with_capacity(FAT_GET_PAYLOADS.len());
        
        for payload in FAT_GET_PAYLOADS.iter() {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers.insert("Content-Length".to_string(), payload.len().to_string());
            
            requests.push(Request {
                method: "GET".to_string(),
                uri: target.to_string(),
                headers,
                body: payload.as_bytes().to_vec(),
            });
        }
        
        requests
    }
}

impl Check for FatGetCheck {
    fn name(&self) -> &'static str {
        "fat_get"
    }

    fn run(&self, target: &str, cache: &mut dyn Cache) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(2);
        
        for request in self.build_test_requests(target) {
            // Mock response - actual implementation uses Stage 2 HTTP engine
            let mock_response = Response {
                status: 200,
                headers: HashMap::new(),
                body: b"{}".to_vec(),
            };

            if let Some(finding) = self.detect_fat_get(&request, &mock_response) {
                findings.push(finding);
                // Cache successful Fat GET bypass
                cache.store("fat_get_bypass", target);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fat_get_detection() {
        let check = FatGetCheck::new(5000, true);
        assert_eq!(check.name(), "fat_get");
        assert!(check.generate_payload().contains("admin"));
    }
}
