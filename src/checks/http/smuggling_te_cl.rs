//! HTTP Request Smuggling: TE.CL Desync Detection
//! 
//! Detects Transfer-Encoding vs Content-Length desynchronization vulnerabilities
//! where the frontend uses Transfer-Encoding and backend uses Content-Length.
//! Uses obfuscated Transfer-Encoding variants and bounded payloads.

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// TE.CL Smuggling Detection Module
/// 
/// Tests for scenarios where:
/// - Frontend proxy respects Transfer-Encoding header (with obfuscation)
/// - Backend server respects Content-Length header
/// - Result: Request smuggling possible via chunked encoding bypass
pub struct TeClSmugglingCheck {
    metadata: CheckMetadata,
    te_variants: Vec<String>,
}

impl TeClSmugglingCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-002".to_string(),
                name: "TE.CL Request Smuggling".to_string(),
                severity: crate::findings::severity::Severity::Critical,
                category: "HTTP Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 8,
                    max_memory_bytes: 1024 * 1024,
                    max_cpu_time_ms: 5000,
                },
                description: "Detects TE.CL HTTP request smuggling using obfuscated Transfer-Encoding".to_string(),
                remediation_hint: "Normalize Transfer-Encoding headers at proxy layer. Reject requests with multiple or malformed TE headers.".to_string(),
            },
            te_variants: vec![
                "Transfer-Encoding".to_string(),
                "Transfer-Encoding ".to_string(), // trailing space
                " Transfer-Encoding".to_string(), // leading space
                "Transfer- Encoding".to_string(), // mid space
                "Transfer--Encoding".to_string(), // double dash
                "X-Transfer-Encoding".to_string(), // prefix
                "Transfer-Encoding-X".to_string(), // suffix
            ],
        }
    }

    /// Generate probe with obfuscated TE header
    fn generate_obfuscated_probe(&self, variant_idx: usize, boundary_id: &str) -> Option<String> {
        let variant = self.te_variants.get(variant_idx)?;
        
        Some(format!(
            "POST / HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             {}: chunked\r\n\
             Content-Length: 6\r\n\
             \r\n\
             0\r\n\
             \r\n\
             GET /smuggle-{}/test HTTP/1.1\r\n\
             Content-Length: 0\r\n\
             \r\n",
            variant, boundary_id
        ))
    }

    /// Analyze response for TE.CL smuggling indicators
    fn analyze_response(&self, response: &str, boundary_id: &str, variant_idx: usize) -> Option<Finding> {
        if response.contains(&format!("smuggle-{}", boundary_id)) {
            let variant_used = self.te_variants.get(variant_idx).unwrap_or(&"unknown".to_string());
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                format!("TE.CL smuggling confirmed via obfuscated TE header: '{}'", variant_used),
                response.to_string(),
                self.metadata.remediation_hint.clone(),
            ));
        }
        None
    }

    /// Test chunk size obfuscation
    fn generate_chunk_obfuscation(&self, boundary_id: &str) -> String {
        format!(
            "POST / HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Transfer-Encoding: chunked\r\n\
             Content-Length: 4\r\n\
             \r\n\
             ; extra comment\\r\\n\
             0\r\n\
             \\r\\n\
             GET /smuggle-{}/obf HTTP/1.1\r\n\
             Content-Length: 0\r\n\
             \\r\\n",
            boundary_id
        )
    }
}

#[async_trait]
impl CheckModule for TeClSmugglingCheck {
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

        // Test each TE variant
        for (idx, _variant) in self.te_variants.iter().enumerate() {
            if let Some(payload) = self.generate_obfuscated_probe(idx, &boundary_id) {
                let response = client.send_raw(&payload).await?;
                
                if let Some(finding) = self.analyze_response(&response, &boundary_id, idx) {
                    findings.push(finding);
                    break; // Found vulnerability, no need to test more
                }

                // Respect budget - limit requests
                if idx >= self.metadata.resource_budget.max_requests as usize - 2 {
                    break;
                }
            }
        }

        // Test chunk obfuscation if no findings yet
        if findings.is_empty() {
            let obf_payload = self.generate_chunk_obfuscation(&boundary_id);
            let response = client.send_raw(&obf_payload).await?;
            
            if response.contains(&format!("smuggle-{}", boundary_id)) {
                findings.push(Finding::new(
                    self.metadata.id.clone(),
                    self.metadata.severity.clone(),
                    "TE.CL smuggling confirmed via chunk obfuscation".to_string(),
                    response.to_string(),
                    self.metadata.remediation_hint.clone(),
                ));
            }
        }

        if !findings.is_empty() {
            return Ok(CheckResult::VulnerabilityFound(findings.into_iter().next().unwrap()));
        }

        // Check for suspicious behavior patterns
        let baseline = client.send_raw("GET / HTTP/1.1\r\nHost: {target_host}\r\n\r\n").await?;
        
        Ok(CheckResult::Safe)
    }

    async fn analyze(&self, result: &CheckResult) -> Result<Option<Finding>, String> {
        match result {
            CheckResult::VulnerabilityFound(finding) => Ok(Some(finding.clone())),
            CheckResult::Suspicious { reason, confidence } => {
                if *confidence > 0.75 {
                    Ok(Some(Finding::new(
                        self.metadata.id.clone(),
                        crate::findings::severity::Severity::High,
                        reason.clone(),
                        "Pattern analysis suggests TE.CL vulnerability".to_string(),
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
    fn test_te_variants() {
        let check = TeClSmugglingCheck::new();
        assert!(check.te_variants.len() >= 5);
        assert!(check.te_variants.iter().any(|v| v.contains("Transfer-Encoding")));
    }

    #[test]
    fn test_obfuscated_probe() {
        let check = TeClSmugglingCheck::new();
        let probe = check.generate_obfuscated_probe(0, "test");
        assert!(probe.is_some());
        let probe = probe.unwrap();
        assert!(probe.contains("chunked"));
        assert!(probe.contains("Content-Length: 6"));
    }

    #[test]
    fn test_metadata() {
        let check = TeClSmugglingCheck::new();
        assert_eq!(check.metadata().id, "HTTP-002");
    }
}
