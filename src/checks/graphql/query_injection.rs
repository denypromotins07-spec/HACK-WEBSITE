//! GraphQL Query Injection Detection Module
//! Detects GraphQL query injection via malformed variables and operator manipulation.

use crate::checks::CheckModule;
use crate::findings::Finding;
use std::collections::HashSet;

const INJECTION_PAYLOADS: &[&str] = &[
    "{{ __schema { types { name } } }}",
    "{ __type(name: \"User\") { fields { name } } }",
    "{ user(id: \"1' OR '1'='1\") { id name } }",
    "{ user(id: \"1; DROP TABLE users--\") { id name } }",
    "{ search(query: \"<script>alert(1)</script>\") { results } }",
    "{ user(filter: { id: { gt: \"1 OR 1=1\" } }) { id } }",
    "{\"query\": \"{ \\u0022__schema\\u0022: { types: { name } } }\"}",
    "{ a: __schema b: __schema { types { name } } }",
    "{ \"__typename\": \"Query\", \"user\": { \"id\": \"1\" } }",
];

const VARIABLE_INJECTIONS: &[(&str, &str)] = &[
    ("id", "1' OR '1'='1"),
    ("id", "1; DELETE FROM users"),
    ("name", "<img src=x onerror=alert(1)>"),
    ("filter", "{\"__proto__\": {\"isAdmin\": true}}"),
    ("where", "1=1 --"),
    ("orderBy", "id DESC; DROP TABLE--"),
];

pub struct QueryInjectionCheck {
    enabled: bool,
    timeout_ms: u64,
}

impl QueryInjectionCheck {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout_ms: 5000,
        }
    }

    fn probe_injection(&self, endpoint: &str, client: &reqwest::Client, query: &str) -> Option<String> {
        let payload = serde_json::json!({ "query": query });

        let resp = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .ok()?;

        let status = resp.status();
        let body_text = resp.text().ok()?;

        // Check for SQL error patterns
        if body_text.contains("SQL") && (body_text.contains("syntax") || body_text.contains("error")) {
            return Some(format!("SQL error detected: {}", body_text.chars().take(200).collect::<String>()));
        }

        // Check for GraphQL introspection leakage via injection
        if body_text.contains("__schema") || body_text.contains("__type") {
            if !query.contains("__schema") && !query.contains("__type") {
                return Some(format!("Unexpected schema exposure: {}", body_text.chars().take(200).collect::<String>()));
            }
        }

        // Check for XSS reflection
        if body_text.contains("<script>") || body_text.contains("onerror=") {
            return Some(format!("XSS reflection detected: {}", body_text.chars().take(200).collect::<String>()));
        }

        // Check for prototype pollution indicators
        if body_text.contains("__proto__") || body_text.contains("isAdmin") {
            return Some(format!("Prototype pollution indicator: {}", body_text.chars().take(200).collect::<String>()));
        }

        None
    }

    fn probe_variable_injection(&self, endpoint: &str, client: &reqwest::Client, field: &str, value: &str) -> Option<String> {
        let query = format!(r#"{{ user({}: "{}") {{ id name }} }}"#, field, value);
        self.probe_injection(endpoint, client, &query)
    }
}

impl CheckModule for QueryInjectionCheck {
    fn name(&self) -> &'static str {
        "graphql_query_injection"
    }

    fn description(&self) -> &'static str {
        "Detects GraphQL query injection via malformed variables and operator manipulation"
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

        let mut triggered_payloads: HashSet<String> = HashSet::new();

        for endpoint in graphql_endpoints {
            // Test direct injection payloads
            for payload in INJECTION_PAYLOADS {
                if let Some(evidence_msg) = self.probe_injection(&endpoint, &client, payload) {
                    triggered_payloads.insert(payload.to_string());
                    
                    let evidence = crate::findings::Evidence::new()
                        .with_detail("endpoint", endpoint.clone())
                        .with_detail("payload", payload.to_string())
                        .with_raw_response(evidence_msg.chars().take(500).to_string());

                    findings.push(Finding::new(self.name())
                        .with_target(endpoint.clone())
                        .with_severity(self.severity())
                        .with_title("GraphQL Query Injection Detected")
                        .with_description(format!("Injection payload '{}' triggered suspicious response", payload))
                        .with_evidence(evidence)
                        .with_confidence(0.80));
                    
                    break; // One finding per endpoint is enough
                }
            }

            // Test variable-based injections
            for (field, value) in VARIABLE_INJECTIONS {
                if let Some(evidence_msg) = self.probe_variable_injection(&endpoint, &client, field, value) {
                    let injection_key = format!("{}={}", field, value);
                    if !triggered_payloads.contains(&injection_key) {
                        triggered_payloads.insert(injection_key.clone());
                        
                        let evidence = crate::findings::Evidence::new()
                            .with_detail("endpoint", endpoint.clone())
                            .with_detail("field", field.to_string())
                            .with_detail("value", value.to_string())
                            .with_raw_response(evidence_msg.chars().take(500).to_string());

                        findings.push(Finding::new(self.name())
                            .with_target(endpoint.clone())
                            .with_severity(self.severity())
                            .with_title("GraphQL Variable Injection Detected")
                            .with_description(format!("Variable injection on field '{}' with value '{}'", field, value))
                            .with_evidence(evidence)
                            .with_confidence(0.75));
                        
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

impl Clone for QueryInjectionCheck {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            timeout_ms: self.timeout_ms,
        }
    }
}
