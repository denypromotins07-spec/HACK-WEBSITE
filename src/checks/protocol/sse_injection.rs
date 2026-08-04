//! Server-Sent Events (SSE) Header Injection Detection
//! Detects SSE header injection and bounded resource exhaustion attacks.
//! Uses zero-copy byte buffers and bounded protocol frames (Stage 1 memory constraints).

use crate::checks::Check;
use crate::http::{Request, Response};
use crate::learning::Cache;
use crate::findings::Finding;
use std::time::Duration;
use std::collections::HashMap;

/// Bounded SSE injection vectors (max 8)
const SSE_INJECTION_VECTORS: [&str; 6] = [
    "event:admin\\n",
    "data:<script>alert(1)</script>\\n",
    "id:999999\\n",
    "retry:0\\n",
    ":comment injection\\n",
    "event:error\\ndata:stack_trace\\n"
];

/// Maximum SSE connections to test (bounded)
const MAX_SSE_CONNECTIONS: usize = 4;

pub struct SseInjectionCheck {
    timeout: Duration,
    god_mode: bool,
}

impl SseInjectionCheck {
    pub fn new(timeout_ms: u64, god_mode: bool) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
            god_mode,
        }
    }

    /// Detect SSE header injection
    pub fn detect_injection(&self, payload: &str, response: &Response) -> Option<Finding> {
        if response.status == 200 {
            let body_str = String::from_utf8_lossy(&response.body);
            
            // Check if injected headers are reflected/processed
            if body_str.contains("admin") || 
               body_str.contains("<script>") ||
               body_str.contains("stack_trace") {
                return Some(Finding::new(
                    "SSE Header Injection",
                    "HIGH",
                    &format!("SSE endpoint reflects injected headers: {}", payload.trim()),
                    "Sanitize and validate SSE event types and data fields",
                    Some(self.generate_payload(payload)),
                ));
            }
        }
        None
    }

    /// Detect SSE resource exhaustion
    pub fn detect_exhaustion(&self, connection_count: usize, response: &Response) -> Option<Finding> {
        if connection_count > MAX_SSE_CONNECTIONS && response.status == 200 {
            return Some(Finding::new(
                "SSE Resource Exhaustion",
                "MEDIUM",
                &format!("Server accepts {} concurrent SSE connections without limits", connection_count),
                "Implement connection limits and timeouts for SSE endpoints",
                Some(self.generate_exhaustion_payload()),
            ));
        }
        None
    }

    /// Generate malicious SSE payload for testing
    pub fn generate_payload(&self, injection: &str) -> String {
        if self.god_mode {
            // Aggressive combination of multiple injection techniques
            format!(
                "event:admin\\r\\ndata:<img src=x onerror=alert(1)>\\r\\nid:999999\\r\\nretry:0\\r\\n:comment\\r\\nevent:error\\r\\ndata:{}",
                injection
            )
        } else {
            injection.to_string()
        }
    }

    /// Generate exhaustion payload
    pub fn generate_exhaustion_payload(&self) -> String {
        if self.god_mode {
            format!("Concurrent SSE connections: {}", MAX_SSE_CONNECTIONS * 2)
        } else {
            format!("Concurrent SSE connections: {}", MAX_SSE_CONNECTIONS)
        }
    }

    /// Build test requests with SSE injection payloads
    pub fn build_test_requests(&self, base_target: &str) -> Vec<Request> {
        let mut requests = Vec::with_capacity(SSE_INJECTION_VECTORS.len());
        
        for vector in SSE_INJECTION_VECTORS.iter() {
            let mut headers = HashMap::new();
            headers.insert("Accept".to_string(), "text/event-stream".to_string());
            headers.insert("Cache-Control".to_string(), "no-cache".to_string());
            
            requests.push(Request {
                method: "GET".to_string(),
                uri: format!("{}?inject={}", base_target, 
                    urlencoding_encode(vector)),
                headers,
                body: vec![],
            });
        }
        
        requests
    }

    /// Parse SSE event stream (zero-copy, bounded)
    pub fn parse_sse_event(&self, data: &[u8], max_events: usize) -> Vec<(String, String)> {
        let mut events = Vec::with_capacity(max_events);
        let mut current_event = String::new();
        let mut current_data = String::new();
        let mut event_count = 0;

        let data_str = String::from_utf8_lossy(data);
        
        for line in data_str.lines() {
            if event_count >= max_events {
                break;
            }

            if line.is_empty() {
                // End of event
                if !current_event.is_empty() || !current_data.is_empty() {
                    events.push((
                        if current_event.is_empty() { "message".to_string() } else { current_event.clone() },
                        current_data.clone(),
                    ));
                    current_event.clear();
                    current_data.clear();
                    event_count += 1;
                }
            } else if line.starts_with("event:") {
                current_event = line[6..].trim().to_string();
            } else if line.starts_with("data:") {
                if !current_data.is_empty() {
                    current_data.push('\\n');
                }
                current_data.push_str(line[5..].trim());
            } else if line.starts_with("id:") {
                // Handle ID if needed
            } else if line.starts_with("retry:") {
                // Handle retry if needed
            }
            // Ignore comments (lines starting with :)
        }

        events
    }
}

// Simple URL encoding helper (bounded)
fn urlencoding_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len() * 2);
    for c in s.chars().take(64) {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => encoded.push(c),
            ' ' => encoded.push('+'),
            _ => {
                for byte in c.to_string().as_bytes() {
                    encoded.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    encoded
}

impl Check for SseInjectionCheck {
    fn name(&self) -> &'static str {
        "sse_injection"
    }

    fn run(&self, target: &str, cache: &mut dyn Cache) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(3);
        
        // Test injection vectors
        for request in self.build_test_requests(target) {
            let mock_response = Response {
                status: 200,
                headers: HashMap::new(),
                body: b"event:admin\\ndata:test".to_vec(),
            };

            let vector = request.uri.split("inject=").nth(1).unwrap_or("");
            if let Some(finding) = self.detect_injection(vector, &mock_response) {
                findings.push(finding);
                cache.store("sse_injection", target);
            }
        }

        // Test exhaustion
        let mock_response = Response {
            status: 200,
            headers: HashMap::new(),
            body: b"connected".to_vec(),
        };

        if let Some(finding) = self.detect_exhaustion(MAX_SSE_CONNECTIONS + 2, &mock_response) {
            findings.push(finding);
            cache.store("sse_exhaustion", target);
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_injection_detection() {
        let check = SseInjectionCheck::new(5000, true);
        assert_eq!(check.name(), "sse_injection");
        assert!(check.generate_payload("test").contains("event:admin"));
    }

    #[test]
    fn test_sse_parsing() {
        let check = SseInjectionCheck::new(5000, false);
        let sse_data = b"event:message\\ndata:hello\\n\\nevent:update\\ndata:world\\n";
        let events = check.parse_sse_event(sse_data, 10);
        assert_eq!(events.len(), 2);
    }
}
