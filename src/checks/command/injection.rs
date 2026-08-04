//! OS Command Injection Detection
//! Detects OS command injection via argument injection and shell metacharacters.
//! Uses bounded payload buffers and zero-copy evidence to maintain 2GB RAM ceiling.

use crate::checks::Check;
use crate::findings::Finding;
use crate::http::{Request, Response};
use std::collections::HashMap;

/// Maximum number of payloads to test per parameter (bounded)
const MAX_PAYLOADS: usize = 50;

/// Shell metacharacters that indicate potential command injection
const SHELL_METACHARACTERS: &[&str] = &[
    ";", "|", "&", "$", "`", "(", ")", "{", "}", "<", ">", "\\", "\n", "\r",
];

/// Command injection detection patterns
const INJECTION_PATTERNS: &[&str] = &[
    "id", "whoami", "uname", "pwd", "ls", "dir", "echo", "cat",
];

pub struct CommandInjectionCheck {
    payloads: Vec<String>,
}

impl CommandInjectionCheck {
    pub fn new() -> Self {
        let mut payloads = Vec::with_capacity(MAX_PAYLOADS);
        
        // Generate bounded set of command injection payloads
        for pattern in INJECTION_PATTERNS.iter().take(10) {
            // Basic injection
            payloads.push(format!(";{}", pattern));
            payloads.push(format!("|{}", pattern));
            payloads.push(format!("&&{}", pattern));
            payloads.push(format!("||{}", pattern));
            
            // Backtick injection
            payloads.push(format!("`{}`", pattern));
            
            // $(...) injection
            payloads.push(format!("$({})", pattern));
            
            // Encoded variants
            payloads.push(format!("${{{}}}", pattern));
        }
        
        // Add metacharacter-only probes
        for meta in SHELL_METACHARACTERS.iter().take(8) {
            payloads.push(meta.to_string());
        }
        
        Self { payloads }
    }
    
    /// Test a single parameter for command injection
    fn test_parameter(&self, req: &Request, param_name: &str, original_value: &str) -> Option<Finding> {
        for payload in self.payloads.iter() {
            let mut test_req = req.clone();
            test_req.set_param(param_name, &format!("{}{}", original_value, payload));
            
            // Execute request with strict timeout
            match test_req.send_with_timeout(5000) {
                Ok(response) => {
                    if self.detect_injection_response(&response, payload) {
                        return Some(Finding::new(
                            "OS_COMMAND_INJECTION",
                            &format!("Parameter '{}' is vulnerable to command injection", param_name),
                            response.url(),
                            9, // Critical severity
                        )
                        .with_payload(payload)
                        .with_evidence(response.body_slice())
                        .with_remediation("Sanitize all user input, use parameterized commands, avoid shell execution"));
                    }
                }
                Err(_) => continue,
            }
        }
        None
    }
    
    /// Detect injection based on response content
    fn detect_injection_response(&self, response: &Response, payload: &str) -> bool {
        let body = response.body_slice();
        
        // Check for command output patterns
        let indicators = [
            "uid=", "gid=", "groups=", "root", "user", "Linux", "Windows",
            "total", "drwx", "-rw-", "bin/bash", "cmd.exe",
        ];
        
        for indicator in indicators.iter() {
            if body.contains(indicator.as_bytes()) {
                return true;
            }
        }
        
        // Check if payload appears reflected (error-based)
        if body.contains(payload.as_bytes()) && body.contains(b"error") {
            return true;
        }
        
        false
    }
}

impl Check for CommandInjectionCheck {
    fn name(&self) -> &'static str {
        "CommandInjection"
    }
    
    fn run(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Test URL parameters
        for (param, value) in request.query_params() {
            if let Some(finding) = self.test_parameter(request, param, value) {
                findings.push(finding);
                break; // One finding per parameter group
            }
        }
        
        // Test POST body parameters
        if let Some(body_params) = request.body_params() {
            for (param, value) in body_params {
                if let Some(finding) = self.test_parameter(request, param, value) {
                    findings.push(finding);
                    break;
                }
            }
        }
        
        // Test headers that might be passed to shell
        let dangerous_headers = ["X-Forwarded-For", "User-Agent", "Referer", "X-User-Agent"];
        for header in dangerous_headers.iter() {
            if let Some(value) = request.header(header) {
                if let Some(finding) = self.test_parameter(request, header, value) {
                    findings.push(finding);
                    break;
                }
            }
        }
        
        findings
    }
    
    fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("type", "os_command_injection");
        meta.insert("severity", "critical");
        meta.insert("owasp", "A03:2021-Injection");
        meta.insert("cwe", "CWE-78");
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_payload_generation() {
        let check = CommandInjectionCheck::new();
        assert!(check.payloads.len() <= MAX_PAYLOADS);
        assert!(check.payloads.iter().any(|p| p.contains("id")));
    }
}
