//! GraphQL Depth DoS Detection Module
//! Detects GraphQL depth, size exhaustion, and circular fragment DoS vulnerabilities safely.

use crate::checks::CheckModule;
use crate::findings::Finding;
use std::time::Instant;

const MAX_DEPTH: usize = 10;
const DEPTH_TEST_LEVELS: &[usize] = &[5, 8, 10, 12, 15];
const TIMEOUT_MS: u64 = 8000;

pub struct DepthDosCheck {
    enabled: bool,
    max_test_depth: usize,
    timeout_ms: u64,
}

impl DepthDosCheck {
    pub fn new() -> Self {
        Self {
            enabled: true,
            max_test_depth: MAX_DEPTH,
            timeout_ms: TIMEOUT_MS,
        }
    }

    fn build_deep_query(&self, field: &str, depth: usize) -> String {
        let mut query = String::from("{ ");
        let mut closing = String::new();
        
        for i in 0..depth {
            if i == 0 {
                query.push_str(field);
                query.push_str(" { ");
            } else {
                query.push_str(field);
                query.push_str(" { ");
            }
            closing.push_str(" }");
        }
        
        query.push_str("id");
        query.push_str(&closing);
        query.push_str(" }");
        query
    }

    fn build_circular_fragment(&self, depth: usize) -> String {
        let mut fragments = String::new();
        for i in 0..depth {
            fragments.push_str(&format!(
                "fragment F{} on User {{ id name {} }} ",
                i,
                if i + 1 < depth { format!("...F{}", i + 1) } else { String::new() }
            ));
        }
        format!("{} {{ ...F0 }}", fragments)
    }

    fn build_wide_query(&self, field: &str, count: usize) -> String {
        let mut fields = Vec::with_capacity(count);
        for i in 0..count {
            fields.push(format!("{} {{ id }}", field));
        }
        format!("{{ {} }}", fields.join(" "))
    }

    fn probe_query(&self, endpoint: &str, client: &reqwest::Client, query: &str) -> Option<DosResult> {
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
        let body_text = resp.text().ok()?;

        let is_timeout = elapsed.as_millis() as u64 > self.timeout_ms;
        let has_error = body_text.contains("error") || body_text.contains("Error");
        let has_complexity_error = body_text.contains("complexity") || body_text.contains("depth");

        Some(DosResult {
            elapsed_ms: elapsed.as_millis() as u64,
            status_code: status.as_u16(),
            is_timeout,
            has_error,
            has_complexity_error,
            response_size: body_text.len(),
        })
    }
}

#[derive(Debug)]
struct DosResult {
    elapsed_ms: u64,
    status_code: u16,
    is_timeout: bool,
    has_error: bool,
    has_complexity_error: bool,
    response_size: usize,
}

impl CheckModule for DepthDosCheck {
    fn name(&self) -> &'static str {
        "graphql_depth_dos"
    }

    fn description(&self) -> &'static str {
        "Detects GraphQL depth, size exhaustion, and circular fragment DoS vulnerabilities safely"
    }

    fn severity(&self) -> crate::checks::Severity {
        crate::checks::Severity::High
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

        // Common nested fields to test depth with
        let nested_fields = vec!["user", "posts", "comments", "children", "friends", "followers"];

        for endpoint in graphql_endpoints {
            let mut dos_evidence: Vec<String> = Vec::new();
            let mut max_observed_depth: usize = 0;

            // Test depth-based DoS
            for field in &nested_fields {
                for depth in DEPTH_TEST_LEVELS.iter().take_while(|&&d| d <= self.max_test_depth) {
                    let query = self.build_deep_query(field, *depth);
                    
                    if let Some(result) = self.probe_query(&endpoint, &client, &query) {
                        if result.is_timeout {
                            dos_evidence.push(format!("Depth {} query timed out after {}ms", depth, result.elapsed_ms));
                            max_observed_depth = max_observed_depth.max(*depth);
                        } else if result.elapsed_ms > 3000 && !result.has_complexity_error {
                            // Slow response without complexity protection
                            dos_evidence.push(format!("Depth {} query took {}ms without complexity error", depth, result.elapsed_ms));
                            max_observed_depth = max_observed_depth.max(*depth);
                        }
                        
                        if result.elapsed_ms > 1000 {
                            break; // Stop testing deeper if already slow
                        }
                    }
                }
            }

            // Test circular fragment DoS (bounded)
            for depth in &[3, 5, 7] {
                if *depth > self.max_test_depth / 2 {
                    break;
                }
                let query = self.build_circular_fragment(*depth);
                
                if let Some(result) = self.probe_query(&endpoint, &client, &query) {
                    if result.is_timeout || (result.elapsed_ms > 2000 && !result.has_complexity_error) {
                        dos_evidence.push(format!("Circular fragment depth {} caused {}ms response", depth, result.elapsed_ms));
                    }
                }
            }

            // Test wide query DoS
            for field in &nested_fields {
                for width in &[10, 20, 30] {
                    let query = self.build_wide_query(field, *width);
                    
                    if let Some(result) = self.probe_query(&endpoint, &client, &query) {
                        if result.is_timeout || (result.elapsed_ms > 3000 && !result.has_complexity_error) {
                            dos_evidence.push(format!("Wide query with {} fields took {}ms", width, result.elapsed_ms));
                        }
                    }
                }
            }

            if !dos_evidence.is_empty() {
                let evidence = crate::findings::Evidence::new()
                    .with_detail("endpoint", endpoint.clone())
                    .with_detail("max_problematic_depth", max_observed_depth.to_string())
                    .with_detail("issues_found", dos_evidence.len().to_string())
                    .with_raw_response(dos_evidence.join("\n"));

                findings.push(Finding::new(self.name())
                    .with_target(endpoint)
                    .with_severity(self.severity())
                    .with_title("GraphQL Depth/Complexity DoS Vulnerability")
                    .with_description("GraphQL endpoint lacks proper depth or complexity limiting, allowing potential DoS attacks")
                    .with_evidence(evidence)
                    .with_confidence(0.85));
            }
        }

        findings
    }

    fn clone_box(&self) -> Box<dyn CheckModule> {
        Box::new(self.clone())
    }
}

impl Clone for DepthDosCheck {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            max_test_depth: self.max_test_depth,
            timeout_ms: self.timeout_ms,
        }
    }
}
