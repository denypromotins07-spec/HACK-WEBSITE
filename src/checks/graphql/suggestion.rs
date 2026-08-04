//! GraphQL Suggestion Exploitation Module
//! Exploits field suggestion errors to reconstruct schemas when introspection is disabled.

use crate::checks::CheckModule;
use crate::findings::Finding;
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

const COMMON_FIELD_NAMES: &[&str] = &[
    "id", "name", "title", "description", "email", "username", "password",
    "created_at", "updated_at", "status", "type", "data", "user", "users",
    "post", "posts", "comment", "comments", "order", "orders", "product",
    "products", "account", "accounts", "profile", "settings", "config",
    "token", "session", "auth", "login", "logout", "register", "signup",
    "delete", "update", "create", "get", "list", "search", "filter",
    "page", "limit", "offset", "sort", "orderBy", "where", "input",
    "payload", "result", "success", "error", "message", "code"
];

const COMMON_MUTATION_NAMES: &[&str] = &[
    "createUser", "updateUser", "deleteUser", "login", "logout", "register",
    "createPost", "updatePost", "deletePost", "createComment", "updateComment",
    "deleteComment", "createOrder", "updateOrder", "cancelOrder", "placeOrder",
    "addItem", "removeItem", "updateProfile", "changePassword", "resetPassword"
];

pub struct SuggestionCheck {
    enabled: bool,
    timeout_ms: u64,
    max_probes: usize,
    discovered_fields: BTreeSet<String>,
}

impl SuggestionCheck {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout_ms: 3000,
            max_probes: 200,
            discovered_fields: BTreeSet::new(),
        }
    }

    fn probe_field(&self, endpoint: &str, client: &reqwest::Client, field: &str) -> Option<String> {
        let query = format!(r#"{{ {} }}"#, field);
        let payload = serde_json::json!({ "query": query });

        let resp = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .ok()?;

        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().ok()?;
            if let Some(errors) = body.get("errors").and_then(|e| e.as_array()) {
                for err in errors {
                    if let Some(msg) = err.get("message").and_then(|m| m.as_str()) {
                        // Look for suggestion patterns like "Did you mean X?" or "Unknown field {}. Did you mean Y?"
                        if msg.contains("Did you mean") || msg.contains("unknown field") {
                            return Some(msg.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    fn probe_mutation(&self, endpoint: &str, client: &reqwest::Client, mutation: &str) -> Option<String> {
        let query = format!(r#"mutation {{ {} }}"#, mutation);
        let payload = serde_json::json!({ "query": query });

        let resp = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .ok()?;

        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().ok()?;
            if let Some(errors) = body.get("errors").and_then(|e| e.as_array()) {
                for err in errors {
                    if let Some(msg) = err.get("message").and_then(|m| m.as_str()) {
                        if msg.contains("Did you mean") || msg.contains("unknown field") || msg.contains("Unknown mutation") {
                            return Some(msg.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    fn extract_suggestions(&self, error_msg: &str) -> Vec<String> {
        let mut suggestions = Vec::new();
        
        // Pattern: "Did you mean 'X'?" or "Did you mean X?"
        if let Some(start) = error_msg.find("Did you mean") {
            let rest = &error_msg[start..];
            if let Some(quote_start) = rest.find('\'') {
                if let Some(quote_end) = rest[quote_start + 1..].find('\'') {
                    suggestions.push(rest[quote_start + 1..quote_start + 1 + quote_end].to_string());
                }
            } else if let Some(question_mark) = rest.find('?') {
                let candidate = rest["Did you mean ".len()..question_mark].trim();
                if !candidate.is_empty() {
                    suggestions.push(candidate.to_string());
                }
            }
        }

        // Pattern: "Unknown field 'X'. Did you mean 'Y'?"
        if error_msg.contains("Unknown field") {
            let parts: Vec<&str> = error_msg.split_whitespace().collect();
            for (i, part) in parts.iter().enumerate() {
                if *part == "field" && i + 1 < parts.len() {
                    let field = parts[i + 1].trim_matches(|c| c == '\'' || c == '"' || c == '.');
                    if !field.is_empty() {
                        suggestions.push(field.to_string());
                    }
                }
            }
        }

        suggestions
    }
}

impl CheckModule for SuggestionCheck {
    fn name(&self) -> &'static str {
        "graphql_suggestion"
    }

    fn description(&self) -> &'static str {
        "Exploits GraphQL field suggestion errors to reconstruct schemas when introspection is disabled"
    }

    fn severity(&self) -> crate::checks::Severity {
        crate::checks::Severity::Low
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

        let mut discovered_fields: BTreeSet<String> = BTreeSet::new();
        let mut probed_count = 0;

        for endpoint in graphql_endpoints {
            // Probe common field names
            for field in COMMON_FIELD_NAMES.iter() {
                if probed_count >= self.max_probes {
                    break;
                }
                probed_count += 1;

                if let Some(error_msg) = self.probe_field(&endpoint, &client, field) {
                    let suggestions = self.extract_suggestions(&error_msg);
                    for s in suggestions {
                        discovered_fields.insert(s);
                    }
                }
            }

            // Probe common mutation names
            for mutation in COMMON_MUTATION_NAMES.iter() {
                if probed_count >= self.max_probes {
                    break;
                }
                probed_count += 1;

                if let Some(error_msg) = self.probe_mutation(&endpoint, &client, mutation) {
                    let suggestions = self.extract_suggestions(&error_msg);
                    for s in suggestions {
                        discovered_fields.insert(s);
                    }
                }
            }

            if !discovered_fields.is_empty() {
                let evidence = crate::findings::Evidence::new()
                    .with_detail("endpoint", endpoint.clone())
                    .with_detail("fields_discovered", discovered_fields.len().to_string())
                    .with_raw_response(format!("{:?}", discovered_fields.iter().take(20).collect::<Vec<_>>()));

                findings.push(Finding::new(self.name())
                    .with_target(endpoint)
                    .with_severity(self.severity())
                    .with_title("GraphQL Schema Reconstruction via Suggestions")
                    .with_description("GraphQL error messages reveal field suggestions allowing partial schema reconstruction")
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

impl Clone for SuggestionCheck {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            timeout_ms: self.timeout_ms,
            max_probes: self.max_probes,
            discovered_fields: BTreeSet::new(),
        }
    }
}
