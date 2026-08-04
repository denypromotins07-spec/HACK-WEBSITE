//! Host Header Injection and Cache Poisoning Detection
//! 
//! Detects host header injection vulnerabilities that can lead to:
//! - Cache poisoning attacks
//! - Password reset poisoning
//! - SSRF via host header manipulation
//! - Web cache deception

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// Host Header Injection Detection Module
/// 
/// Tests for scenarios where:
//! - Application uses Host header for generating URLs
//! - Cache layers key on Host header without validation
//! - Password reset links use attacker-controlled host
pub struct HostHeaderCheck {
    metadata: CheckMetadata,
    injection_payloads: Vec<String>,
}

impl HostHeaderCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-007".to_string(),
                name: "Host Header Injection".to_string(),
                severity: crate::findings::severity::Severity::High,
                category: "HTTP Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 10,
                    max_memory_bytes: 1024 * 1024,
                    max_cpu_time_ms: 5000,
                },
                description: "Detects host header injection, cache poisoning, and password reset poisoning".to_string(),
                remediation_hint: "Validate Host header against allowed values. Use absolute URLs in configuration, not dynamic headers.".to_string(),
            },
            injection_payloads: vec![
                "evil.com".to_string(),
                "attacker.com".to_string(),
                "evil.com:80".to_string(),
                "evil.com%0d%0aX-Injected: header".to_string(), // CRLF attempt
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "{{target_host}}.evil.com".to_string(),
                "evil.com/{{target_host}}".to_string(),
            ],
        }
    }

    /// Generate host header injection probe
    fn generate_host_probe(&self, boundary_id: &str, evil_host: &str) -> String {
        format!(
            "GET /smuggle-{}/host-test HTTP/1.1\r\n\
             Host: {}\r\n\
             X-Forwarded-Host: {}\r\n\
             X-Host: {}\r\n\
             \r\n",
            boundary_id, evil_host, evil_host, evil_host
        )
    }

    /// Generate probe targeting password reset functionality
    fn generate_password_reset_probe(&self, boundary_id: &str, evil_host: &str) -> String {
        format!(
            "POST /password-reset HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 24\r\n\
             \r\n\
             email=test@smuggle-{}.com",
            evil_host, boundary_id
        )
    }

    /// Generate probe for cache poisoning test
    fn generate_cache_probe(&self, boundary_id: &str, evil_host: &str) -> String {
        format!(
            "GET /smuggle-{}/cache-test HTTP/1.1\r\n\
             Host: {}\r\n\
             Cache-Control: max-age=0\r\n\
             \r\n",
            boundary_id, evil_host
        )
    }

    /// Analyze response for host header injection indicators
    fn analyze_response(&self, response: &str, boundary_id: &str, evil_host: &str) -> Option<Finding> {
        // Check if evil host was reflected or used
        if response.contains(evil_host) {
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                format!("Host header injection confirmed: '{}' reflected in response", evil_host),
                response.to_string(),
                self.metadata.remediation_hint.clone(),
            ));
        }

        // Check for redirect to evil host
        if response.contains("Location:") && response.contains(evil_host) {
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                format!("Redirect to attacker host: '{}'", evil_host),
                response.to_string(),
                self.metadata.remediation_hint.clone(),
            ));
        }

        // Check for password reset link poisoning
        if response.contains("http://") && response.contains(evil_host) {
            return Some(Finding::new(
                self.metadata.id.clone(),
                crate::findings::severity::Severity::Critical,
                format!("Password reset link poisoning: URL contains attacker host '{}'", evil_host),
                response.to_string(),
                self.metadata.remediation_hint.clone(),
            ));
        }

        None
    }

    /// Check for cache poisoning evidence
    fn analyze_cache_response(&self, response: &str, boundary_id: &str) -> Option<Finding> {
        // Look for cache headers that might indicate poisoning success
        if response.contains("X-Cache:") || response.contains("Age:") {
            // Response was cached - check if our boundary ID is present
            if response.contains(&format!("smuggle-{}", boundary_id)) {
                return Some(Finding::new(
                    self.metadata.id.clone(),
                    crate::findings::severity::Severity::Critical,
                    "Web cache poisoning confirmed: malicious response was cached".to_string(),
                    response.to_string(),
                    self.metadata.remediation_hint.clone(),
                ));
            }
        }
        None
    }
}

#[async_trait]
impl CheckModule for HostHeaderCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    async fn init(&mut self, _context: &CheckContext) -> Result<(), String> {
        Ok(())
    }

    async fn run(&self, context: &CheckContext) -> Result<CheckResult, String> {
        let client = context.client();
        let boundary_id = format!("{:08x}", rand::random::<u32>());
        let mut request_count = 0;

        for evil_host in &self.injection_payloads {
            if request_count >= self.metadata.resource_budget.max_requests as usize {
                break;
            }

            // Replace placeholder with actual target host if needed
            let resolved_host = evil_host.replace("{{target_host}}", &client.get_host());

            // Test 1: Basic host header injection
            let host_payload = self.generate_host_probe(&boundary_id, &resolved_host);
            match client.send_raw(&host_payload).await {
                Ok(response) => {
                    if let Some(finding) = self.analyze_response(&response, &boundary_id, &resolved_host) {
                        return Ok(CheckResult::VulnerabilityFound(finding));
                    }
                    request_count += 1;
                }
                Err(_) => continue,
            }

            // Test 2: Cache poisoning attempt
            let cache_payload = self.generate_cache_probe(&boundary_id, &resolved_host);
            match client.send_raw(&cache_payload).await {
                Ok(response) => {
                    if let Some(finding) = self.analyze_cache_response(&response, &boundary_id) {
                        return Ok(CheckResult::VulnerabilityFound(finding));
                    }
                    request_count += 1;
                }
                Err(_) => continue,
            }

            // Test 3: Password reset poisoning (only on specific endpoints)
            if context.has_endpoint("/password-reset") || context.has_endpoint("/reset-password") {
                let reset_payload = self.generate_password_reset_probe(&boundary_id, &resolved_host);
                match client.send_raw(&reset_payload).await {
                    Ok(response) => {
                        if let Some(finding) = self.analyze_response(&response, &boundary_id, &resolved_host) {
                            return Ok(CheckResult::VulnerabilityFound(finding));
                        }
                        request_count += 1;
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(CheckResult::Safe)
    }

    async fn analyze(&self, result: &CheckResult) -> Result<Option<Finding>, String> {
        match result {
            CheckResult::VulnerabilityFound(finding) => Ok(Some(finding.clone())),
            _ => Ok(None),
        }
    }

    fn remediation(&self) -> Option<String> {
        Some(self.metadata.remediation_hint.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injection_payloads() {
        let check = HostHeaderCheck::new();
        assert!(check.injection_payloads.len() >= 6);
        assert!(check.injection_payloads.iter().any(|p| p.contains("evil")));
    }

    #[test]
    fn test_host_probe_generation() {
        let check = HostHeaderCheck::new();
        let probe = check.generate_host_probe("test123", "attacker.com");
        assert!(probe.contains("Host: attacker.com"));
        assert!(probe.contains("X-Forwarded-Host: attacker.com"));
        assert!(probe.contains("X-Host: attacker.com"));
    }

    #[test]
    fn test_password_reset_probe() {
        let check = HostHeaderCheck::new();
        let probe = check.generate_password_reset_probe("test123", "evil.com");
        assert!(probe.contains("POST /password-reset"));
        assert!(probe.contains("Host: evil.com"));
    }

    #[test]
    fn test_metadata() {
        let check = HostHeaderCheck::new();
        assert_eq!(check.metadata().id, "HTTP-007");
        assert_eq!(check.metadata().severity, crate::findings::severity::Severity::High);
    }
}
