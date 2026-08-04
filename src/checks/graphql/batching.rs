//! GraphQL Batching Attack Detection Module
//! Detects rate-limit bypasses using GraphQL batching attacks with multiple operations.

use crate::checks::CheckModule;
use crate::findings::Finding;
use std::collections::HashMap;
use std::time::Instant;

const MAX_BATCH_SIZE: usize = 50;
const BATCH_SIZES: &[usize] = &[5, 10, 20, 30, 50];

pub struct BatchingCheck {
    enabled: bool,
    timeout_ms: u64,
    max_batch_size: usize,
}

impl BatchingCheck {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout_ms: 10000,
            max_batch_size: MAX_BATCH_SIZE,
        }
    }

    fn build_batch_query(&self, operation: &str, count: usize) -> String {
        let mut queries = Vec::with_capacity(count);
        for i in 0..count {
            queries.push(format!(r#"op{}: {}"#, i, operation));
        }
        format!("{{ {} }}", queries.join(" "))
    }

    fn build_batch_mutation(&self, mutation: &str, count: usize) -> String {
        let mut mutations = Vec::with_capacity(count);
        for i in 0..count {
            mutations.push(format!(r#"m{}: {}"#, i, mutation));
        }
        format!("mutation {{ {} }}", mutations.join(" "))
    }

    fn probe_batch(&self, endpoint: &str, client: &reqwest::Client, query: &str, batch_size: usize) -> Option<BatchResult> {
        let payload = serde_json::json!({ "query": query });
        
        let start = Instant::now();
        let resp = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .ok()?;
        let elapsed = start.elapsed();

        let status = resp.status();
        let body: serde_json::Value = resp.json().ok()?;

        let success_count = body.get("data")
            .and_then(|d| d.as_object())
            .map(|obj| obj.len())
            .unwrap_or(0);

        let error_count = body.get("errors")
            .and_then(|e| e.as_array())
            .map(|arr| arr.len())
            .unwrap_or(0);

        Some(BatchResult {
            batch_size,
            success_count,
            error_count,
            elapsed_ms: elapsed.as_millis() as u64,
            status_code: status.as_u16(),
        })
    }

    fn detect_rate_limit_bypass(&self, results: &[BatchResult]) -> Option<BypassEvidence> {
        if results.len() < 2 {
            return None;
        }

        // Check if larger batches complete proportionally faster than individual requests would
        let first = results.first()?;
        let last = results.last()?;

        if last.batch_size > first.batch_size && last.elapsed_ms < first.elapsed_ms * 2 {
            // Larger batch completed almost as fast as smaller one - potential bypass
            return Some(BypassEvidence {
                pattern: "proportional_timing".to_string(),
                description: format!("Batch of {} completed in {}ms, suggesting no per-operation rate limiting", 
                    last.batch_size, last.elapsed_ms),
                confidence: 0.75,
            });
        }

        // Check if all operations in large batch succeeded when they should be rate limited
        if last.batch_size >= 20 && last.success_count == last.batch_size {
            return Some(BypassEvidence {
                pattern: "no_rate_limiting".to_string(),
                description: format!("All {} operations in batch succeeded without rate limiting", last.batch_size),
                confidence: 0.80,
            });
        }

        None
    }
}

#[derive(Debug)]
struct BatchResult {
    batch_size: usize,
    success_count: usize,
    error_count: usize,
    elapsed_ms: u64,
    status_code: u16,
}

#[derive(Debug)]
struct BypassEvidence {
    pattern: String,
    description: String,
    confidence: f64,
}

impl CheckModule for BatchingCheck {
    fn name(&self) -> &'static str {
        "graphql_batching"
    }

    fn description(&self) -> &'static str {
        "Detects rate-limit bypasses using GraphQL batching attacks with multiple operations"
    }

    fn severity(&self) -> crate::checks::Severity {
        crate::checks::Severity::Medium
    }

    fn run(&self, target: &crate::target::Target, context: &crate::context::ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if !self.enabled {
            return findings;
        }

        let graphql_endpoints = context.graphql_endpoints();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .build()
            .unwrap_or_default();

        // Common operations to test batching with
        let test_operations = vec![
            "{ __typename }",
            "{ user(id: \"1\") { id } }",
            "{ posts { id } }",
        ];

        let test_mutations = vec![
            "createUser(input: {name: \"test\"}) { id }",
            "likePost(id: \"1\") { success }",
            "incrementView(id: \"1\") { count }",
        ];

        for endpoint in graphql_endpoints {
            let mut all_results: Vec<BatchResult> = Vec::new();

            // Test query batching
            for operation in &test_operations {
                let mut results = Vec::new();
                for batch_size in BATCH_SIZES.iter().take_while(|&&s| s <= self.max_batch_size) {
                    let query = self.build_batch_query(operation, *batch_size);
                    if let Some(result) = self.probe_batch(&endpoint, &client, &query, *batch_size) {
                        results.push(result);
                    }
                }
                all_results.extend(results);
            }

            // Test mutation batching (more likely to reveal rate limit issues)
            for mutation in &test_mutations {
                let mut results = Vec::new();
                for batch_size in BATCH_SIZES.iter().take_while(|&&s| s <= self.max_batch_size / 2) {
                    let query = self.build_batch_mutation(mutation, *batch_size);
                    if let Some(result) = self.probe_batch(&endpoint, &client, &query, *batch_size) {
                        results.push(result);
                    }
                }
                all_results.extend(results);
            }

            if let Some(bypass) = self.detect_rate_limit_bypass(&all_results) {
                let evidence = crate::findings::Evidence::new()
                    .with_detail("endpoint", endpoint.clone())
                    .with_detail("bypass_pattern", bypass.pattern.clone())
                    .with_detail("description", bypass.description.clone())
                    .with_raw_response(format!("Tested {} batch configurations", all_results.len()));

                findings.push(Finding::new(self.name())
                    .with_target(endpoint)
                    .with_severity(self.severity())
                    .with_title("GraphQL Rate Limit Bypass via Batching")
                    .with_description(bypass.description)
                    .with_evidence(evidence)
                    .with_confidence(bypass.confidence));
            }
        }

        findings
    }

    fn clone_box(&self) -> Box<dyn CheckModule> {
        Box::new(self.clone())
    }
}

impl Clone for BatchingCheck {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            timeout_ms: self.timeout_ms,
            max_batch_size: self.max_batch_size,
        }
    }
}
