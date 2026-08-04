//! GraphQL Mass Assignment Detection Module
//! Detects GraphQL mass assignment by injecting hidden fields into mutations.

use crate::checks::CheckModule;
use crate::findings::Finding;
use std::collections::HashSet;

const PRIVILEGE_FIELDS: &[&str] = &[
    "isAdmin", "is_admin", "admin", "role", "roles", "permissions", "permission",
    "tier", "level", "accessLevel", "access_level", "privilege", "privileges",
    "isVerified", "is_verified", "verified", "isPremium", "is_premium", "premium",
    "accountType", "account_type", "userType", "user_type", "status",
    "ownerId", "owner_id", "createdBy", "created_by", "userId", "user_id"
];

const SENSITIVE_FIELDS: &[&str] = &[
    "password", "passwordHash", "password_hash", "secret", "apiKey", "api_key",
    "token", "refreshToken", "refresh_token", "sessionToken", "session_token",
    "creditCard", "credit_card", "ssn", "socialSecurity", "bankAccount", "bank_account"
];

pub struct GraphqlMassAssignmentCheck {
    enabled: bool,
    timeout_ms: u64,
}

impl GraphqlMassAssignmentCheck {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout_ms: 5000,
        }
    }

    fn build_mutation_with_field(&self, mutation_name: &str, field: &str, value: &str) -> String {
        format!(
            r#"mutation {{ {}(input: {{ name: "test", {}: {} }}) {{ id name }} }}"#,
            mutation_name, field, value
        )
    }

    fn build_nested_injection(&self, mutation_name: &str, field: &str, value: &str) -> String {
        format!(
            r#"mutation {{ {}(input: {{ user: {{ name: "test", {}: {} }} }}) {{ id }} }}"#,
            mutation_name, field, value
        )
    }

    fn probe_mutation(&self, endpoint: &str, client: &reqwest::Client, query: &str) -> Option<InjectionResult> {
        let payload = serde_json::json!({ "query": query });

        let resp = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .ok()?;

        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().ok()?;

        // Check if the field was accepted (no error about unknown field)
        let has_field_error = body.get("errors")
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter().any(|err| {
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .map(|msg| msg.contains("Unknown field") || msg.contains("unknown field") || msg.contains("not defined"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);

        let has_data = body.get("data").is_some();
        
        Some(InjectionResult {
            status_code: status,
            has_field_error,
            has_data,
            raw_response: body.to_string().chars().take(500).collect::<String>(),
        })
    }
}

#[derive(Debug)]
struct InjectionResult {
    status_code: u16,
    has_field_error: bool,
    has_data: bool,
    raw_response: String,
}

impl CheckModule for GraphqlMassAssignmentCheck {
    fn name(&self) -> &'static str {
        "graphql_mass_assignment"
    }

    fn description(&self) -> &'static str {
        "Detects GraphQL mass assignment by injecting hidden fields into mutations"
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

        // Common mutation names to test
        let mutation_names = vec![
            "createUser", "updateUser", "registerUser", "signup",
            "createAccount", "updateAccount", "updateProfile",
            "createPost", "updatePost", "createOrder", "updateOrder"
        ];

        let mut vulnerable_fields: HashSet<String> = HashSet::new();

        for endpoint in graphql_endpoints {
            for mutation in &mutation_names {
                // Test privilege fields with boolean values
                for field in PRIVILEGE_FIELDS {
                    let query = self.build_mutation_with_field(mutation, field, "true");
                    
                    if let Some(result) = self.probe_mutation(&endpoint, &client, &query) {
                        // If no field error and we got data back, the field might be accepted
                        if !result.has_field_error && result.has_data {
                            vulnerable_fields.insert(format!("{}->{}", mutation, field));
                            
                            let evidence = crate::findings::Evidence::new()
                                .with_detail("endpoint", endpoint.clone())
                                .with_detail("mutation", mutation.to_string())
                                .with_detail("injected_field", field.to_string())
                                .with_raw_response(result.raw_response.clone());

                            findings.push(Finding::new(self.name())
                                .with_target(endpoint.clone())
                                .with_severity(self.severity())
                                .with_title("GraphQL Mass Assignment Vulnerability")
                                .with_description(format!("Field '{}' can be injected into '{}' mutation", field, mutation))
                                .with_evidence(evidence)
                                .with_confidence(0.75));
                            
                            break; // One finding per mutation is enough
                        }
                    }
                }

                // Test nested injection patterns
                for field in SENSITIVE_FIELDS {
                    let query = self.build_nested_injection(mutation, field, "\"injected\"");
                    
                    if let Some(result) = self.probe_mutation(&endpoint, &client, &query) {
                        if !result.has_field_error && result.has_data {
                            let evidence = crate::findings::Evidence::new()
                                .with_detail("endpoint", endpoint.clone())
                                .with_detail("mutation", mutation.to_string())
                                .with_detail("nested_field", field.to_string())
                                .with_raw_response(result.raw_response.clone());

                            findings.push(Finding::new(self.name())
                                .with_target(endpoint.clone())
                                .with_severity(self.severity())
                                .with_title("GraphQL Nested Mass Assignment")
                                .with_description(format!("Nested field '{}' can be injected into '{}' mutation", field, mutation))
                                .with_evidence(evidence)
                                .with_confidence(0.70));
                            
                            break;
                        }
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

impl Clone for GraphqlMassAssignmentCheck {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            timeout_ms: self.timeout_ms,
        }
    }
}
