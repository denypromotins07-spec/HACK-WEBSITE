//! Absolute URI Routing Anomaly Detection
//! 
//! Detects vulnerabilities in absolute-form URI handling through proxy layers.
//! Tests for request smuggling and routing bypass via absolute URI manipulation.

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// Absolute URI Routing Anomaly Detection Module
/// 
/// Tests for scenarios where:
/// - Proxies accept absolute-form URIs (http://host/path)
/// - Backend interprets the URI differently than frontend
/// - Result: Routing bypass or request smuggling
pub struct AbsoluteUriCheck {
    metadata: CheckMetadata,
}

impl AbsoluteUriCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-006".to_string(),
                name: "Absolute URI Routing Anomaly".to_string(),
                severity: crate::findings::severity::Severity::High,
                category: "HTTP Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 8,
                    max_memory_bytes: 1024 * 1024,
                    max_cpu_time_ms: 5000,
                },
                description: "Detects absolute-form URI routing anomalies through proxy layers".to_string(),
                remediation_hint: "Reject absolute-form URIs at proxy layer. Normalize all requests to origin-form.".to_string(),
            },
        }
    }

    /// Generate absolute-form URI probe
    fn generate_absolute_uri_probe(&self, boundary_id: &str, target_host: &str) -> String {
        format!(
            "GET http://{}/smuggle-{}/test HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             \r\n",
            target_host, boundary_id
        )
    }

    /// Generate absolute URI with different scheme
    fn generate_scheme_variation_probe(&self, boundary_id: &str, target_host: &str) -> String {
        format!(
            "GET https://{}/smuggle-{}/scheme HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             \r\n",
            target_host, boundary_id
        )
    }

    /// Generate absolute URI with port specification
    fn generate_port_variation_probe(&self, boundary_id: &str, target_host: &str) -> String {
        format!(
            "GET http://{}:8080/smuggle-{}/port HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             \r\n",
            target_host, boundary_id
        )
    }

    /// Generate probe with conflicting host headers
    fn generate_conflicting_host_probe(&self, boundary_id: &str, evil_host: &str) -> String {
        format!(
            "GET http://{}/smuggle-{}/conflict HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             X-Forwarded-Host: {}\r\n\
             \r\n",
            evil_host, boundary_id, evil_host
        )
    }

    /// Analyze response for absolute URI vulnerability indicators
    fn analyze_response(&self, response: &str, boundary_id: &str, probe_type: &str) -> Option<Finding> {
        if response.contains(&format!("smuggle-{}", boundary_id)) {
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                format!("Absolute URI routing anomaly confirmed via {} probe", probe_type),
                response.to_string(),
                self.metadata.remediation_hint.clone(),
            ));
        }

        // Check for host header confusion
        if response.contains("evil") || response.contains("different-host") {
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                format!("Host confusion detected in {} probe", probe_type),
                response.to_string(),
                self.metadata.remediation_hint.clone(),
            ));
        }

        None
    }

    /// Test URI normalization behavior
    fn generate_normalization_probe(&self, boundary_id: &str) -> String {
        // URI with encoded characters that might be normalized differently
        format!(
            "GET /smuggle-{}/%2e%2e/test HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             \r\n",
            boundary_id
        )
    }
}

#[async_trait]
impl CheckModule for AbsoluteUriCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    async fn init(&mut self, _context: &CheckContext) -> Result<(), String> {
        Ok(())
    }

    async fn run(&self, context: &CheckContext) -> Result<CheckResult, String> {
        let client = context.client();
        let boundary_id = format!("{:08x}", rand::random::<u32>());
        let target_host = client.get_host();

        // Test 1: Basic absolute-form URI
        let abs_payload = self.generate_absolute_uri_probe(&boundary_id, &target_host);
        match client.send_raw(&abs_payload).await {
            Ok(response) => {
                if let Some(finding) = self.analyze_response(&response, &boundary_id, "absolute-uri") {
                    return Ok(CheckResult::VulnerabilityFound(finding));
                }
            }
            Err(_) => {}
        }

        // Test 2: Scheme variation
        let scheme_payload = self.generate_scheme_variation_probe(&boundary_id, &target_host);
        match client.send_raw(&scheme_payload).await {
            Ok(response) => {
                if let Some(finding) = self.analyze_response(&response, &boundary_id, "scheme-variation") {
                    return Ok(CheckResult::VulnerabilityFound(finding));
                }
            }
            Err(_) => {}
        }

        // Test 3: Port variation
        let port_payload = self.generate_port_variation_probe(&boundary_id, &target_host);
        match client.send_raw(&port_payload).await {
            Ok(response) => {
                if let Some(finding) = self.analyze_response(&response, &boundary_id, "port-variation") {
                    return Ok(CheckResult::VulnerabilityFound(finding));
                }
            }
            Err(_) => {}
        }

        // Test 4: Conflicting host headers
        let conflict_payload = self.generate_conflicting_host_probe(&boundary_id, "different-host.evil");
        match client.send_raw(&conflict_payload).await {
            Ok(response) => {
                if let Some(finding) = self.analyze_response(&response, &boundary_id, "conflicting-host") {
                    return Ok(CheckResult::VulnerabilityFound(finding));
                }
            }
            Err(_) => {}
        }

        // Test 5: URI normalization
        let norm_payload = self.generate_normalization_probe(&boundary_id);
        match client.send_raw(&norm_payload).await {
            Ok(response) => {
                if response.contains(&format!("smuggle-{}", boundary_id)) {
                    return Ok(CheckResult::Suspicious {
                        reason: "URI normalization anomaly detected".to_string(),
                        confidence: 0.6,
                    });
                }
            }
            Err(_) => {}
        }

        Ok(CheckResult::Safe)
    }

    async fn analyze(&self, result: &CheckResult) -> Result<Option<Finding>, String> {
        match result {
            CheckResult::VulnerabilityFound(finding) => Ok(Some(finding.clone())),
            CheckResult::Suspicious { reason, confidence } => {
                if *confidence > 0.7 {
                    Ok(Some(Finding::new(
                        self.metadata.id.clone(),
                        crate::findings::severity::Severity::High,
                        reason.clone(),
                        "Analysis suggests absolute URI routing vulnerability".to_string(),
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
    fn test_absolute_uri_probe() {
        let check = AbsoluteUriCheck::new();
        let probe = check.generate_absolute_uri_probe("test123", "example.com");
        assert!(probe.contains("http://example.com/smuggle-test123/test"));
        assert!(probe.contains("Host:"));
    }

    #[test]
    fn test_scheme_variation() {
        let check = AbsoluteUriCheck::new();
        let probe = check.generate_scheme_variation_probe("test123", "example.com");
        assert!(probe.contains("https://example.com"));
    }

    #[test]
    fn test_port_variation() {
        let check = AbsoluteUriCheck::new();
        let probe = check.generate_port_variation_probe("test123", "example.com");
        assert!(probe.contains(":8080/"));
    }

    #[test]
    fn test_metadata() {
        let check = AbsoluteUriCheck::new();
        assert_eq!(check.metadata().id, "HTTP-006");
        assert_eq!(check.metadata().severity, crate::findings::severity::Severity::High);
    }
}
