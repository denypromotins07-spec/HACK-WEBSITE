//! JSON Bomb Detection Module
//! Detects JSON bomb vulnerabilities by sending deeply nested structures to parser endpoints.

use crate::checks::CheckModule;
use crate::findings::Finding;
use std::time::Instant;

const MAX_DEPTH: usize = 500;
const DEPTH_STEPS: &[usize] = &[50, 100, 200, 300, 500];
const MAX_ARRAY_SIZE: usize = 10000;
const ARRAY_SIZES: &[usize] = &[100, 500, 1000, 5000, 10000];

pub struct JsonBombCheck {
    enabled: bool,
    timeout_ms: u64,
    max_depth: usize,
}

impl JsonBombCheck {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout_ms: 10000,
            max_depth: MAX_DEPTH,
        }
    }

    fn build_nested_object(&self, depth: usize) -> String {
        let mut json = String::with_capacity(depth * 4);
        for _ in 0..depth {
            json.push_str("{\"a\":");
        }
        json.push_str("1");
        for _ in 0..depth {
            json.push('}');
        }
        json
    }

    fn build_nested_array(&self, depth: usize) -> String {
        let mut json = String::with_capacity(depth * 3);
        for _ in 0..depth {
            json.push_str("[");
        }
        json.push_str("1");
        for _ in 0..depth {
            json.push_str("]");
        }
        json
    }

    fn build_wide_array(&self, size: usize) -> String {
        let mut json = String::with_capacity(size * 3);
        json.push('[');
        for i in 0..size {
            if i > 0 {
                json.push(',');
            }
            json.push_str("1");
        }
        json.push(']');
        json
    }

    fn build_recursive_object(&self, count: usize) -> String {
        // Creates an object with many keys (parser stress test)
        let mut json = String::with_capacity(count * 20);
        json.push('{');
        for i in 0..count {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!("\"key{}\":1", i));
        }
        json.push('}');
        json
    }

    fn probe_json(&self, url: &str, client: &reqwest::Client, payload: &str) -> Option<BombResult> {
        let start = Instant::now();
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .ok()?;
        let elapsed = start.elapsed();

        let status = resp.status().as_u16();
        let body = resp.text().ok()?;

        let is_timeout = elapsed.as_millis() as u64 > self.timeout_ms;
        let has_parser_error = body.contains("parse error") || 
                               body.contains("JSON") && body.contains("error") ||
                               body.contains("too deep") ||
                               body.contains("maximum") ||
                               body.contains("recursion");
        
        let server_error = status >= 500;

        if is_timeout || (server_error && has_parser_error) || elapsed.as_millis() > 5000 {
            Some(BombResult {
                url: url.to_string(),
                attack_type: if is_timeout { "timeout" } else { "parser_stress" }.to_string(),
                elapsed_ms: elapsed.as_millis() as u64,
                status_code: status,
                evidence: body.chars().take(300).collect::<String>(),
            })
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct BombResult {
    url: String,
    attack_type: String,
    elapsed_ms: u64,
    status_code: u16,
    evidence: String,
}

impl CheckModule for JsonBombCheck {
    fn name(&self) -> &'static str {
        "json_bomb"
    }

    fn description(&self) -> &'static str {
        "Detects JSON bomb vulnerabilities by sending deeply nested structures to parser endpoints"
    }

    fn severity(&self) -> crate::checks::Severity {
        crate::checks::Severity::High
    }

    fn run(&self, target: &crate::target::Target, context: &crate::context::ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if !self.enabled {
            return findings;
        }

        let json_endpoints = context.json_endpoints();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .build()
            .unwrap_or_default();

        let mut vulnerable_endpoints: std::collections::HashSet<String> = std::collections::HashSet::new();

        for endpoint in json_endpoints {
            if vulnerable_endpoints.contains(&endpoint) {
                continue;
            }

            let mut max_problematic_depth = 0;

            // Test nested object depth
            for depth in DEPTH_STEPS.iter().take_while(|&&d| d <= self.max_depth) {
                let payload = self.build_nested_object(*depth);
                
                if let Some(result) = self.probe_json(&endpoint, &client, &payload) {
                    max_problematic_depth = max_problematic_depth.max(*depth);
                    
                    let evidence = crate::findings::Evidence::new()
                        .with_detail("endpoint", result.url.clone())
                        .with_detail("attack_type", "nested_object".to_string())
                        .with_detail("depth", depth.to_string())
                        .with_detail("elapsed_ms", result.elapsed_ms.to_string())
                        .with_raw_response(result.evidence.clone());

                    findings.push(Finding::new(self.name())
                        .with_target(result.url)
                        .with_severity(self.severity())
                        .with_title("JSON Bomb Vulnerability (Nested Objects)")
                        .with_description(format!("Deeply nested JSON objects (depth {}) caused {}ms response", depth, result.elapsed_ms))
                        .with_evidence(evidence)
                        .with_confidence(0.85));
                    
                    vulnerable_endpoints.insert(endpoint.clone());
                    break;
                }
            }

            // Test nested array depth
            if !vulnerable_endpoints.contains(&endpoint) {
                for depth in DEPTH_STEPS.iter().take_while(|&&d| d <= self.max_depth / 2) {
                    let payload = self.build_nested_array(*depth);
                    
                    if let Some(result) = self.probe_json(&endpoint, &client, &payload) {
                        let evidence = crate::findings::Evidence::new()
                            .with_detail("endpoint", result.url.clone())
                            .with_detail("attack_type", "nested_array".to_string())
                            .with_detail("depth", depth.to_string())
                            .with_raw_response(result.evidence.clone());

                        findings.push(Finding::new(self.name())
                            .with_target(result.url)
                            .with_severity(self.severity())
                            .with_title("JSON Bomb Vulnerability (Nested Arrays)")
                            .with_description(format!("Deeply nested JSON arrays (depth {}) caused DoS condition", depth))
                            .with_evidence(evidence)
                            .with_confidence(0.85));
                        
                        vulnerable_endpoints.insert(endpoint.clone());
                        break;
                    }
                }
            }

            // Test wide arrays
            if !vulnerable_endpoints.contains(&endpoint) {
                for size in ARRAY_SIZES {
                    let payload = self.build_wide_array(*size);
                    
                    if let Some(result) = self.probe_json(&endpoint, &client, &payload) {
                        let evidence = crate::findings::Evidence::new()
                            .with_detail("endpoint", result.url.clone())
                            .with_detail("attack_type", "wide_array".to_string())
                            .with_detail("array_size", size.to_string())
                            .with_raw_response(result.evidence.clone());

                        findings.push(Finding::new(self.name())
                            .with_target(result.url)
                            .with_severity(self.severity())
                            .with_title("JSON Bomb Vulnerability (Wide Arrays)")
                            .with_description(format!("Large JSON array ({} elements) caused DoS condition", size))
                            .with_evidence(evidence)
                            .with_confidence(0.80));
                        
                        vulnerable_endpoints.insert(endpoint.clone());
                        break;
                    }
                }
            }

            // Test recursive/large objects
            if !vulnerable_endpoints.contains(&endpoint) {
                for count in &[100, 500, 1000] {
                    let payload = self.build_recursive_object(*count);
                    
                    if let Some(result) = self.probe_json(&endpoint, &client, &payload) {
                        let evidence = crate::findings::Evidence::new()
                            .with_detail("endpoint", result.url.clone())
                            .with_detail("attack_type", "large_object".to_string())
                            .with_detail("key_count", count.to_string())
                            .with_raw_response(result.evidence.clone());

                        findings.push(Finding::new(self.name())
                            .with_target(result.url)
                            .with_severity(self.severity())
                            .with_title("JSON Bomb Vulnerability (Large Objects)")
                            .with_description(format!("Large JSON object ({} keys) caused DoS condition", count))
                            .with_evidence(evidence)
                            .with_confidence(0.75));
                        
                        vulnerable_endpoints.insert(endpoint.clone());
                        break;
                    }
                }
            }
        }

        findings
    }

    fn clone_box(&self) -> Box<dyn CheckModule> {
        Box::new(self.clone())
    }
}

impl Clone for JsonBombCheck {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            timeout_ms: self.timeout_ms,
            max_depth: self.max_depth,
        }
    }
}
