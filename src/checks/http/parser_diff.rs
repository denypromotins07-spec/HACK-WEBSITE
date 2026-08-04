//! HTTP Parser Differential Detection
//! 
//! Compares frontend/backend parser behavior using harmless malformed request primitives.
//! Identifies parser inconsistencies that enable smuggling or bypass attacks.

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// HTTP Parser Differential Detection Module
/// 
/// Tests for scenarios where:
/// - Frontend and backend use different HTTP parsers
/// - Malformed requests are interpreted differently
/// - Parser edge cases enable security bypasses
pub struct ParserDiffCheck {
    metadata: CheckMetadata,
    malformed_primitives: Vec<String>,
}

impl ParserDiffCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-012".to_string(),
                name: "HTTP Parser Differential".to_string(),
                severity: crate::findings::severity::Severity::High,
                category: "HTTP Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 12,
                    max_memory_bytes: 2 * 1024 * 1024,
                    max_cpu_time_ms: 8000,
                },
                description: "Detects frontend/backend HTTP parser behavior differences".to_string(),
                remediation_hint: "Use consistent HTTP parser across all layers. Implement strict RFC compliance.".to_string(),
            },
            // Harmless malformed request primitives for differential testing
            malformed_primitives: vec![
                // Extra whitespace in various positions
                "GET  /test HTTP/1.1\r\nHost: test\r\n\r\n".to_string(),
                "GET /test  HTTP/1.1\r\nHost: test\r\n\r\n".to_string(),
                "GET /test HTTP/1.1 \r\nHost: test\r\n\r\n".to_string(),
                
                // Mixed case method
                "get /test HTTP/1.1\r\nHost: test\r\n\r\n".to_string(),
                "Get /test HTTP/1.1\r\nHost: test\r\n\r\n".to_string(),
                
                // Header anomalies
                "GET /test HTTP/1.1\r\nhost: test\r\n\r\n".to_string(),
                "GET /test HTTP/1.1\r\nHOST: test\r\n\r\n\r\n".to_string(),
                "GET /test HTTP/1.1\r\nHost : test\r\n\r\n".to_string(),
                "GET /test HTTP/1.1\r\n Host: test\r\n\r\n".to_string(),
                
                // Missing space variations
                "GET/test HTTP/1.1\r\nHost: test\r\n\r\n".to_string(),
                "GET /testHTTP/1.1\r\nHost: test\r\n\r\n".to_string(),
                
                // Line ending variations (if not normalized)
                "GET /test HTTP/1.1\nHost: test\n\n".to_string(),
                "GET /test HTTP/1.1\r\r\nHost: test\r\n\r\n".to_string(),
                
                // Null byte injection attempts
                "GET /test\0 HTTP/1.1\r\nHost: test\r\n\r\n".to_string(),
                
                // Tab vs space
                "GET\t/test\tHTTP/1.1\r\nHost:\ttest\r\n\r\n".to_string(),
            ],
        }
    }

    /// Generate probe with malformed primitive
    fn generate_malformed_probe(&self, boundary_id: &str, primitive: &str) -> String {
        // Insert boundary marker to track through parsing
        primitive.replace("test", &format!("smuggle-{}", boundary_id))
    }

    /// Generate probe with duplicate headers (parser handling varies)
    fn generate_duplicate_header_probe(&self, boundary_id: &str) -> String {
        format!(
            "GET /smuggle-{}/dup HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             X-Custom: value1\r\n\
             X-Custom: value2\r\n\
             X-Custom: value3\r\n\
             \r\n",
            boundary_id
        )
    }

    /// Generate probe with header folding (obsolete but still seen)
    fn generate_header_folding_probe(&self, boundary_id: &str) -> String {
        format!(
            "GET /smuggle-{}/fold HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             X-Long-Header: value1\r\n\
              continued-value\r\n\
              more-continuation\r\n\
             \r\n",
            boundary_id
        )
    }

    /// Analyze response for parser differential indicators
    fn analyze_response(&self, response: &str, boundary_id: &str, primitive_idx: usize) -> Option<Finding> {
        // Check if boundary marker was processed correctly
        let expected_marker = format!("smuggle-{}", boundary_id);
        
        if !response.contains(&expected_marker) {
            // Marker disappeared - parser may have dropped the request
            return Some(Finding::new(
                self.metadata.id.clone(),
                crate::findings::severity::Severity::Medium,
                format!("Parser differential: request dropped at primitive #{}", primitive_idx),
                format!("Primitive index: {}\nResponse: {}", primitive_idx, &response[..response.len().min(300)]),
                self.metadata.remediation_hint.clone(),
            ));
        }

        // Check for evidence of partial parsing
        if response.contains("malformed") || response.contains("bad request") || response.contains("400") {
            // Explicit rejection - may indicate strict parser
            // This is actually good behavior, but worth noting
        }

        // Check for unexpected behavior patterns
        if response.contains("value1") && response.contains("value3") && !response.contains("value2") {
            return Some(Finding::new(
                self.metadata.id.clone(),
                crate::findings::severity::Severity::Medium,
                "Inconsistent header handling detected - some values dropped".to_string(),
                format!("Response: {}", &response[..response.len().min(500)]),
                self.metadata.remediation_hint.clone(),
            ));
        }

        None
    }

    /// Compare responses from different primitives to identify patterns
    fn correlate_differentials(&self, responses: &[(usize, String)]) -> Option<f32> {
        if responses.len() < 5 {
            return None;
        }

        let mut error_count = 0;
        for (_, resp) in responses {
            if resp.contains("400") || resp.contains("406") || resp.contains("malformed") {
                error_count += 1;
            }
        }

        let error_ratio = error_count as f32 / responses.len() as f32;
        
        // If ~50% fail, suggests parser inconsistency
        if error_ratio > 0.3 && error_ratio < 0.7 {
            Some(error_ratio)
        } else {
            None
        }
    }
}

#[async_trait]
impl CheckModule for ParserDiffCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    async fn init(&mut self, _context: &CheckContext) -> Result<(), String> {
        Ok(())
    }

    async fn run(&self, context: &CheckContext) -> Result<CheckResult, String> {
        let client = context.client();
        let boundary_id = format!("{:08x}", rand::random::<u32>());
        let mut responses: Vec<(usize, String)> = Vec::new();
        let mut findings: Vec<Finding> = Vec::new();

        // Test 1: Malformed primitives
        for (idx, primitive) in self.malformed_primitives.iter().enumerate() {
            if idx >= self.metadata.resource_budget.max_requests as usize - 3 {
                break;
            }

            let probe = self.generate_malformed_probe(&boundary_id, primitive);
            match client.send_raw(&probe).await {
                Ok(response) => {
                    if let Some(finding) = self.analyze_response(&response, &boundary_id, idx) {
                        findings.push(finding);
                    }
                    responses.push((idx, response));
                }
                Err(e) => {
                    // Connection error - parser may have rejected at TCP level
                    responses.push((idx, format!("ERROR: {}", e)));
                }
            }
        }

        // Test 2: Duplicate headers
        let dup_probe = self.generate_duplicate_header_probe(&boundary_id);
        match client.send_raw(&dup_probe).await {
            Ok(response) => {
                if let Some(finding) = self.analyze_response(&response, &boundary_id, 999) {
                    findings.push(finding);
                }
                responses.push((999, response));
            }
            Err(_) => {}
        }

        // Test 3: Header folding
        let fold_probe = self.generate_header_folding_probe(&boundary_id);
        match client.send_raw(&fold_probe).await {
            Ok(response) => {
                if response.contains("continued-value") || response.contains("more-continuation") {
                    findings.push(Finding::new(
                        self.metadata.id.clone(),
                        crate::findings::severity::Severity::Low,
                        "Header folding supported - verify consistent handling".to_string(),
                        format!("Response: {}", &response[..response.len().min(300)]),
                        self.metadata.remediation_hint.clone(),
                    ));
                }
            }
            Err(_) => {}
        }

        // Correlate results
        if findings.is_empty() {
            if let Some(ratio) = self.correlate_differentials(&responses) {
                return Ok(CheckResult::Suspicious {
                    reason: format!("Parser differential pattern detected: {:.0}% error rate across primitives", ratio * 100.0),
                    confidence: 0.65,
                });
            }
        }

        if !findings.is_empty() {
            return Ok(CheckResult::VulnerabilityFound(findings.into_iter().next().unwrap()));
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
                        crate::findings::severity::Severity::Medium,
                        reason.clone(),
                        "Differential analysis suggests parser inconsistency".to_string(),
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
    fn test_malformed_primitives_count() {
        let check = ParserDiffCheck::new();
        assert!(check.malformed_primitives.len() >= 10);
    }

    #[test]
    fn test_malformed_probe_generation() {
        let check = ParserDiffCheck::new();
        let probe = check.generate_malformed_probe("test123", &check.malformed_primitives[0]);
        assert!(probe.contains("smuggle-test123"));
    }

    #[test]
    fn test_duplicate_header_probe() {
        let check = ParserDiffCheck::new();
        let probe = check.generate_duplicate_header_probe("test123");
        assert!(probe.contains("X-Custom: value1"));
        assert!(probe.contains("X-Custom: value2"));
        assert!(probe.contains("X-Custom: value3"));
    }

    #[test]
    fn test_metadata() {
        let check = ParserDiffCheck::new();
        assert_eq!(check.metadata().id, "HTTP-012");
        assert_eq!(check.metadata().severity, crate::findings::severity::Severity::High);
    }
}
