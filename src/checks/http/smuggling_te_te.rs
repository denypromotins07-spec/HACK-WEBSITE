//! HTTP Request Smuggling: TE.TE Desync Detection
//! 
//! Detects Transfer-Encoding vs Transfer-Encoding desynchronization vulnerabilities
//! where both frontend and backend process TE but interpret it differently.
//! Uses header mutation matrices and response correlation for detection.

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// TE.TE Smuggling Detection Module
/// 
/// Tests for scenarios where:
/// - Both frontend and backend respect Transfer-Encoding
/// - But they interpret obfuscation differently
/// - Result: One processes chunked, other doesn't, enabling smuggling
pub struct TeTeSmugglingCheck {
    metadata: CheckMetadata,
    mutation_matrix: Vec<(String, String)>,
}

impl TeTeSmugglingCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-003".to_string(),
                name: "TE.TE Request Smuggling".to_string(),
                severity: crate::findings::severity::Severity::Critical,
                category: "HTTP Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 10,
                    max_memory_bytes: 2 * 1024 * 1024, // 2MB for matrix testing
                    max_cpu_time_ms: 8000,
                },
                description: "Detects TE.TE HTTP request smuggling using header mutation matrices".to_string(),
                remediation_hint: "Implement strict TE header validation. Reject requests with multiple or malformed Transfer-Encoding values.".to_string(),
            },
            // Matrix of (header_name_variant, header_value_variant) pairs
            mutation_matrix: vec![
                ("Transfer-Encoding".to_string(), "chunked".to_string()),
                ("Transfer-Encoding".to_string(), " chunked".to_string()), // leading space
                ("Transfer-Encoding".to_string(), "chunked ".to_string()), // trailing space
                ("Transfer-Encoding".to_string(), "x-chunked".to_string()), // prefix
                ("Transfer-Encoding".to_string(), "chunked,gzip".to_string()), // multiple values
                ("Transfer-Encoding".to_string(), "\"chunked\"".to_string()), // quoted
                ("Transfer-Encoding".to_string(), "c h u n k e d".to_string()), // spaced chars
                ("Transfer-Encoding".to_string(), "chunk\\r\\ned".to_string()), // embedded CRLF
                ("X-Transfer-Encoding".to_string(), "chunked".to_string()), // prefixed name
                ("Transfer-Encoding".to_string(), "identity,chunked".to_string()), // identity first
            ],
        }
    }

    /// Generate probe with specific mutation from matrix
    fn generate_mutation_probe(&self, matrix_idx: usize, boundary_id: &str) -> Option<String> {
        let (name_variant, value_variant) = self.mutation_matrix.get(matrix_idx)?;
        
        Some(format!(
            "POST / HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             {}: {}\r\n\
             Transfer-Encoding: chunked\r\n\
             Content-Length: 4\r\n\
             \r\n\
             0\r\n\
             \r\n\
             GET /smuggle-{}/mut{} HTTP/1.1\r\n\
             Content-Length: 0\r\n\
             \r\n",
            name_variant, value_variant, boundary_id, matrix_idx
        ))
    }

    /// Generate double TE header probe
    fn generate_double_te_probe(&self, boundary_id: &str) -> String {
        format!(
            "POST / HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             Transfer-Encoding: chunked\r\n\
             Transfer-Encoding: identity\r\n\
             Content-Length: 4\r\n\
             \r\n\
             0\r\n\
             \r\n\
             GET /smuggle-{}/double HTTP/1.1\r\n\
             Content-Length: 0\r\n\
             \r\n",
            boundary_id
        )
    }

    /// Analyze response for TE.TE smuggling indicators
    fn analyze_response(&self, response: &str, boundary_id: &str, mutation_idx: Option<usize>) -> Option<Finding> {
        if response.contains(&format!("smuggle-{}", boundary_id)) {
            let detail = match mutation_idx {
                Some(idx) => format!(" via mutation #{}: {:?}", idx, self.mutation_matrix.get(idx)),
                None => " via double TE headers".to_string(),
            };
            
            return Some(Finding::new(
                self.metadata.id.clone(),
                self.metadata.severity.clone(),
                format!("TE.TE smuggling confirmed{}", detail),
                response.to_string(),
                self.metadata.remediation_hint.clone(),
            ));
        }
        
        // Check for timing-based indicators
        if response.len() > 500 && response.contains("200") {
            // Large response might indicate second request was processed
            // Further analysis needed
        }
        
        None
    }

    /// Correlate responses across mutations to identify patterns
    fn correlate_responses(&self, responses: &[(usize, String)]) -> Option<f32> {
        if responses.len() < 3 {
            return None;
        }

        let mut success_count = 0;
        for (_, resp) in responses {
            if resp.contains("smuggle-") || resp.len() > 1000 {
                success_count += 1;
            }
        }

        let ratio = success_count as f32 / responses.len() as f32;
        if ratio > 0.5 {
            Some(ratio)
        } else {
            None
        }
    }
}

#[async_trait]
impl CheckModule for TeTeSmugglingCheck {
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

        // Test mutation matrix entries (bounded by budget)
        let max_mutations = std::cmp::min(
            self.mutation_matrix.len(),
            self.metadata.resource_budget.max_requests as usize - 2
        );

        for idx in 0..max_mutations {
            if let Some(payload) = self.generate_mutation_probe(idx, &boundary_id) {
                match client.send_raw(&payload).await {
                    Ok(response) => {
                        if let Some(finding) = self.analyze_response(&response, &boundary_id, Some(idx)) {
                            findings.push(finding);
                            break;
                        }
                        responses.push((idx, response));
                    }
                    Err(_) => continue, // Skip failed requests
                }
            }
        }

        // If no direct findings, test double TE header
        if findings.is_empty() {
            let double_payload = self.generate_double_te_probe(&boundary_id);
            if let Ok(response) = client.send_raw(&double_payload).await {
                if let Some(finding) = self.analyze_response(&response, &boundary_id, None) {
                    findings.push(finding);
                }
            }
        }

        // Correlate responses if we have enough data
        if findings.is_empty() && responses.len() >= 3 {
            if let Some(correlation) = self.correlate_responses(&responses) {
                if correlation > 0.7 {
                    return Ok(CheckResult::Suspicious {
                        reason: format!("High correlation ({:.2}) across TE mutations suggests TE.TE vulnerability", correlation),
                        confidence: correlation as f64,
                    });
                }
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
                        crate::findings::severity::Severity::High,
                        reason.clone(),
                        "Correlation analysis suggests TE.TE vulnerability".to_string(),
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
    fn test_mutation_matrix_size() {
        let check = TeTeSmugglingCheck::new();
        assert!(check.mutation_matrix.len() >= 8);
    }

    #[test]
    fn test_mutation_probe_generation() {
        let check = TeTeSmugglingCheck::new();
        let probe = check.generate_mutation_probe(0, "test");
        assert!(probe.is_some());
        let probe = probe.unwrap();
        assert!(probe.contains("Transfer-Encoding: chunked"));
        assert!(probe.contains("smuggle-test/mut0"));
    }

    #[test]
    fn test_double_te_probe() {
        let check = TeTeSmugglingCheck::new();
        let probe = check.generate_double_te_probe("test");
        assert!(probe.contains("Transfer-Encoding: chunked"));
        assert!(probe.contains("Transfer-Encoding: identity"));
    }

    #[test]
    fn test_correlation() {
        let check = TeTeSmugglingCheck::new();
        let responses = vec![
            (0, "smuggle-test found".to_string()),
            (1, "smuggle-test found".to_string()),
            (2, "normal response".to_string()),
        ];
        let corr = check.correlate_responses(&responses);
        assert!(corr.is_some());
        assert!(corr.unwrap() > 0.5);
    }
}
