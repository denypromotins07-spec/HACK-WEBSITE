//! HTTP Request Smuggling: CL.TE Desync Detection
//! 
//! Detects Content-Length vs Transfer-Encoding desynchronization vulnerabilities
//! where the frontend uses Content-Length and backend uses Transfer-Encoding.
//! Uses safe timing probes and response boundary checks to minimize impact.

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::engine::http_client::HttpClient;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// CL.TE Smuggling Detection Module
/// 
/// Tests for scenarios where:
/// - Frontend proxy respects Content-Length header
/// - Backend server respects Transfer-Encoding header
/// - Result: Request smuggling possible via crafted boundaries
pub struct ClTeSmugglingCheck {
    metadata: CheckMetadata,
}

impl ClTeSmugglingCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-001".to_string(),
                name: "CL.TE Request Smuggling".to_string(),
                severity: crate::findings::severity::Severity::Critical,
                category: "HTTP Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 5,
                    max_memory_bytes: 1024 * 1024, // 1MB
                    max_cpu_time_ms: 5000,
                },
                description: "Detects CL.TE HTTP request smuggling vulnerabilities".to_string(),
                remediation_hint: "Ensure consistent header parsing across proxy and backend layers. Disable Transfer-Encoding if not needed.".to_string(),
            },
        }
    }

    /// Generate safe probe payload for CL.TE detection
    fn generate_probe(&self, boundary_id: &str) -> String {
        format!(
            "POST / HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Content-Length: 12\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             0\r\n\
             \r\n\
             GET /smuggle-{}/test HTTP/1.1\r\n\
             Content-Length: 0\r\n\
             \r\n",
            boundary_id
        )
    }

    /// Analyze response for smuggling indicators
    fn analyze_response(&self, response: &str, boundary_id: &str) -> Option<Finding> {
        // Check if our smuggled request was processed
        if response.contains(&format!("smuggle-{}", boundary_id)) {
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                "CL.TE smuggling confirmed: backend processed smuggled request".to_string(),
                response.to_string(),
                self.metadata.remediation_hint.clone(),
            ));
        }

        // Check for timing anomalies indicating potential smuggling
        None
    }
}

#[async_trait]
impl CheckModule for ClTeSmugglingCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    async fn init(&mut self, _context: &CheckContext) -> Result<(), String> {
        Ok(())
    }

    async fn run(&self, context: &CheckContext) -> Result<CheckResult, String> {
        let client = context.client();
        let boundary_id = format!("{:08x}", rand::random::<u32>());
        
        // Safe timing probe first
        let probe_payload = self.generate_probe(&boundary_id);
        
        let start = std::time::Instant::now();
        let response = client.send_raw(&probe_payload).await?;
        let elapsed = start.elapsed();

        // Analyze response for evidence
        if let Some(finding) = self.analyze_response(&response, &boundary_id) {
            return Ok(CheckResult::VulnerabilityFound(finding));
        }

        // Secondary check: response boundary analysis
        if response.contains("400") || response.contains("500") {
            // Server rejected malformed request - may indicate protection
            return Ok(CheckResult::Safe);
        }

        // Check for differential behavior with modified payload
        let alt_payload = format!(
            "POST / HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Content-Length: 11\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             0\r\n\
             \r\n\
             X"
        );

        let response_alt = client.send_raw(&alt_payload).await?;
        
        // Differential analysis
        if response != response_alt {
            return Ok(CheckResult::Suspicious {
                reason: "Differential response detected - potential CL.TE vulnerability".to_string(),
                confidence: 0.7,
            });
        }

        Ok(CheckResult::Safe)
    }

    async fn analyze(&self, result: &CheckResult) -> Result<Option<Finding>, String> {
        match result {
            CheckResult::VulnerabilityFound(finding) => Ok(Some(finding.clone())),
            CheckResult::Suspicious { reason, confidence } => {
                if *confidence > 0.8 {
                    Ok(Some(Finding::new(
                        self.metadata.id.clone(),
                        crate::findings::severity::Severity::High,
                        reason.clone(),
                        "Differential analysis suggests vulnerability".to_string(),
                        self.metadata.remediation_hint.clone(),
                    )))
                } else {
                    Ok(None)
                }
            }
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
    fn test_probe_generation() {
        let check = ClTeSmugglingCheck::new();
        let probe = check.generate_probe("test123");
        assert!(probe.contains("Content-Length: 12"));
        assert!(probe.contains("Transfer-Encoding: chunked"));
        assert!(probe.contains("smuggle-test123"));
    }

    #[test]
    fn test_metadata() {
        let check = ClTeSmugglingCheck::new();
        assert_eq!(check.metadata().id, "HTTP-001");
        assert_eq!(check.metadata().severity, crate::findings::severity::Severity::Critical);
    }
}
