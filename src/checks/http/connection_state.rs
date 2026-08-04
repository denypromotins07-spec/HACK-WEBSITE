//! Connection State Hijacking Detection
//! 
//! Detects vulnerabilities in persistent connection state management
//! that could enable session hijacking or request confusion attacks.
//! Uses bounded session reuse testing to identify state leakage.

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// Connection State Hijacking Detection Module
/// 
/// Tests for scenarios where:
/// - Connection state persists across different logical sessions
/// - Authentication state leaks between requests on same connection
/// - Keep-alive connections enable state confusion attacks
pub struct ConnectionStateCheck {
    metadata: CheckMetadata,
}

impl ConnectionStateCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-009".to_string(),
                name: "Connection State Hijacking".to_string(),
                severity: crate::findings::severity::Severity::High,
                category: "HTTP Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 8,
                    max_memory_bytes: 1024 * 1024,
                    max_cpu_time_ms: 5000,
                },
                description: "Detects persistent connection state hijacking vulnerabilities".to_string(),
                remediation_hint: "Reset connection state between sessions. Use separate connections for different security contexts.".to_string(),
            },
        }
    }

    /// Generate probe to test connection state persistence
    fn generate_auth_state_probe(&self, boundary_id: &str) -> String {
        format!(
            "GET /smuggle-{}/auth-check HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            boundary_id
        )
    }

    /// Generate probe with conflicting authentication states
    fn generate_conflicting_auth_probe(&self, boundary_id: &str) -> String {
        format!(
            "GET /smuggle-{}/admin HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Authorization: Bearer invalid_token_{}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            boundary_id
        )
    }

    /// Generate probe testing cookie/session state on reused connection
    fn generate_session_probe(&self, boundary_id: &str, session_id: &str) -> String {
        format!(
            "GET /smuggle-{}/session HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Cookie: session={}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            boundary_id, session_id
        )
    }

    /// Generate probe to test header state persistence
    fn generate_header_state_probe(&self, boundary_id: &str) -> String {
        format!(
            "GET /smuggle-{}/test HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             X-Custom-State: value-{}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            boundary_id
        )
    }

    /// Analyze response for connection state issues
    fn analyze_response(&self, response: &str, boundary_id: &str, test_type: &str) -> Option<Finding> {
        // Check if unauthorized access was granted (state from previous connection)
        if test_type == "auth" && (response.contains("200 OK") || response.contains("admin")) {
            // If we got admin access with invalid token, state may have leaked
            if !response.contains("401") && !response.contains("403") {
                return Some(Finding::new(
                    self.metadata.id.clone(),
                    self.metadata.severity.clone(),
                    "Connection state hijacking: unauthorized access granted on reused connection".to_string(),
                    format!("Test: {}\nResponse: {}", test_type, response),
                    self.metadata.remediation_hint.clone(),
                ));
            }
        }

        // Check for session confusion
        if test_type == "session" && response.contains(&format!("smuggle-{}", boundary_id)) {
            // Our boundary ID appeared in session context - possible leakage
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                "Session state leakage detected on persistent connection".to_string(),
                format!("Test: {}\nResponse: {}", test_type, response),
                self.metadata.remediation_hint.clone(),
            ));
        }

        // Check for header state persistence evidence
        if test_type == "header" && response.contains("X-Custom-State") {
            return Some(Finding::new(
                self.metadata.id.clone(),
                crate::findings::severity::Severity::Medium,
                "Header state reflected - verify isolation between requests".to_string(),
                format!("Test: {}\nResponse: {}", test_type, response),
                self.metadata.remediation_hint.clone(),
            ));
        }

        None
    }

    /// Test connection reuse behavior
    fn generate_connection_close_probe(&self, boundary_id: &str) -> String {
        format!(
            "GET /smuggle-{}/close-test HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Connection: close\r\n\
             \r\n",
            boundary_id
        )
    }
}

#[async_trait]
impl CheckModule for ConnectionStateCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    async fn init(&mut self, _context: &CheckContext) -> Result<(), String> {
        Ok(())
    }

    async fn run(&self, context: &CheckContext) -> Result<CheckResult, String> {
        let client = context.client();
        let boundary_id = format!("{:08x}", rand::random::<u32>());
        let mut findings = Vec::new();

        // Test 1: Baseline auth check
        let auth_probe = self.generate_auth_state_probe(&boundary_id);
        let baseline_response = match client.send_raw(&auth_probe).await {
            Ok(resp) => resp,
            Err(_) => return Ok(CheckResult::Safe),
        };

        // Test 2: Conflicting auth on same connection (if keep-alive supported)
        if client.supports_keepalive() {
            let conflict_probe = self.generate_conflicting_auth_probe(&boundary_id);
            match client.send_raw_same_connection(&conflict_probe).await {
                Ok(response) => {
                    if let Some(finding) = self.analyze_response(&response, &boundary_id, "auth") {
                        findings.push(finding);
                    }
                }
                Err(_) => {}
            }

            // Test 3: Session state on reused connection
            let fake_session = format!("fake_session_{}", boundary_id);
            let session_probe = self.generate_session_probe(&boundary_id, &fake_session);
            match client.send_raw_same_connection(&session_probe).await {
                Ok(response) => {
                    if let Some(finding) = self.analyze_response(&response, &boundary_id, "session") {
                        findings.push(finding);
                    }
                }
                Err(_) => {}
            }

            // Test 4: Header state persistence
            let header_probe = self.generate_header_state_probe(&boundary_id);
            match client.send_raw_same_connection(&header_probe).await {
                Ok(response) => {
                    if let Some(finding) = self.analyze_response(&response, &boundary_id, "header") {
                        findings.push(finding);
                    }
                }
                Err(_) => {}
            }
        }

        // Test 5: Connection close behavior (comparison)
        let close_probe = self.generate_connection_close_probe(&boundary_id);
        match client.send_raw(&close_probe).await {
            Ok(close_response) => {
                // Compare with keep-alive responses for anomalies
                if close_response != baseline_response {
                    // Different behavior with connection close - may indicate state issue
                    findings.push(Finding::new(
                        self.metadata.id.clone(),
                        crate::findings::severity::Severity::Medium,
                        "Connection handling differs between keep-alive and close modes".to_string(),
                        format!("Baseline vs Close response difference detected"),
                        self.metadata.remediation_hint.clone(),
                    ));
                }
            }
            Err(_) => {}
        }

        if !findings.is_empty() {
            return Ok(CheckResult::VulnerabilityFound(findings.into_iter().next().unwrap()));
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
    fn test_auth_state_probe() {
        let check = ConnectionStateCheck::new();
        let probe = check.generate_auth_state_probe("test123");
        assert!(probe.contains("Connection: keep-alive"));
        assert!(probe.contains("smuggle-test123"));
    }

    #[test]
    fn test_conflicting_auth_probe() {
        let check = ConnectionStateCheck::new();
        let probe = check.generate_conflicting_auth_probe("test123");
        assert!(probe.contains("Authorization: Bearer invalid_token_test123"));
    }

    #[test]
    fn test_session_probe() {
        let check = ConnectionStateCheck::new();
        let probe = check.generate_session_probe("test123", "session_abc");
        assert!(probe.contains("Cookie: session=session_abc"));
    }

    #[test]
    fn test_metadata() {
        let check = ConnectionStateCheck::new();
        assert_eq!(check.metadata().id, "HTTP-009");
        assert_eq!(check.metadata().severity, crate::findings::severity::Severity::High);
    }
}
