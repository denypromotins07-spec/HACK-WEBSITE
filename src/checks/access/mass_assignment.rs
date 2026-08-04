//! Mass Assignment Detection Module
//! Detects mass assignment vulnerabilities by injecting privilege fields into update payloads.

use crate::checks::module::{CheckModule, CheckResult, CheckMetadata, CheckCategory};
use crate::findings::finding::Finding;
use crate::session::session::Session;
use crate::http::client::HttpClient;
use crate::learning::access_cache::AccessCache;
use std::sync::Arc;
use serde_json::{json, Value};

/// Privilege fields that may be exploited via mass assignment
const PRIVILEGE_FIELDS: &[&str] = &[
    "role",
    "is_admin",
    "admin",
    "tier",
    "permission",
    "permissions",
    "privilege",
    "privileges",
    "user_type",
    "account_type",
    "access_level",
    "scope",
    "groups",
    "roles",
    "is_superuser",
    "is_staff",
    "verified",
    "email_verified",
    "active",
    "status",
    "balance",
    "credits",
    "currency",
];

/// Mass assignment detector
pub struct MassAssignmentDetector {
    http_client: Arc<HttpClient>,
    access_cache: Arc<AccessCache>,
    privilege_fields: Vec<String>,
    max_payload_size: usize,
}

impl MassAssignmentDetector {
    pub fn new(http_client: Arc<HttpClient>, access_cache: Arc<AccessCache>) -> Self {
        Self {
            http_client,
            access_cache,
            privilege_fields: PRIVILEGE_FIELDS.iter().map(|s| s.to_string()).collect(),
            max_payload_size: 4096,
        }
    }

    /// Inject privilege fields into a payload and test for mass assignment
    async fn test_mass_assignment(
        &self,
        session: &Session,
        endpoint: &str,
        base_payload: Option<Value>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Test each privilege field individually
        for field in &self.privilege_fields {
            let mut payload = base_payload.clone().unwrap_or_else(|| json!({}));
            
            // Try different value types for the privilege field
            let test_values = vec![
                json!("admin"),
                json!(true),
                json!(1),
                json!(["admin", "superuser"]),
                json!({"level": "admin"}),
            ];
            
            for value in test_values {
                if let Value::Object(ref mut map) = payload {
                    map.insert(field.clone(), value.clone());
                } else {
                    payload = json!({ field: value });
                }
                
                // Check payload size limit (bounded to prevent memory issues)
                let payload_str = payload.to_string();
                if payload_str.len() > self.max_payload_size {
                    continue;
                }
                
                let response = self.http_client
                    .put(endpoint)
                    .session(session)
                    .json(&payload)
                    .send()
                    .await;
                
                if response.status().is_success() {
                    let body = response.body();
                    
                    // Check if the privilege was actually applied
                    if self.detect_privilege_escalation(body, field, &value) {
                        findings.push(Finding::new()
                            .with_title("Mass Assignment: Privilege Escalation")
                            .with_description(format!(
                                "Field '{}' can be manipulated to escalate privileges",
                                field
                            ))
                            .with_endpoint(endpoint)
                            .with_severity(crate::findings::severity::Severity::Critical)
                            .with_evidence(format!(
                                "Injected value: {}, Response indicates success: {}",
                                value, 
                                &body[..body.len().min(200)]
                            )));
                        
                        // Cache successful exploitation pattern
                        self.access_cache.cache_mass_assignment_pattern(
                            endpoint.to_string(),
                            field.clone(),
                            value.to_string(),
                        );
                    }
                }
            }
        }
        
        findings
    }

    /// Detect if privilege escalation occurred based on response
    fn detect_privilege_escalation(&self, body: &str, field: &str, value: &Value) -> bool {
        let body_lower = body.to_lowercase();
        
        // Check for success indicators
        let success_indicators = [
            "success",
            "updated",
            "saved",
            "modified",
            "changed",
            "applied",
        ];
        
        let has_success = success_indicators.iter().any(|s| body_lower.contains(s));
        
        // Check if the field/value appears in response
        let field_confirmed = body.contains(field) || body.contains(&value.to_string());
        
        // Check for absence of error messages
        let error_indicators = [
            "error",
            "invalid",
            "forbidden",
            "unauthorized",
            "not allowed",
            "read-only",
            "protected",
        ];
        
        let has_errors = error_indicators.iter().any(|s| body_lower.contains(s));
        
        has_success && !has_errors && (field_confirmed || body.len() > 10)
    }

    /// Scan endpoints for mass assignment vulnerabilities
    pub async fn scan(&self, sessions: &[Session], update_endpoints: &[String]) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        for session in sessions {
            for endpoint in update_endpoints {
                // Look for update/PUT/POST endpoints
                if endpoint.contains("update") 
                    || endpoint.contains("edit")
                    || endpoint.contains("profile")
                    || endpoint.contains("settings")
                    || endpoint.contains("account")
                {
                    let findings = self.test_mass_assignment(session, endpoint, None).await;
                    results.extend(findings.into_iter().map(CheckResult::Finding));
                }
            }
        }
        
        results
    }

    /// Test with custom payload structure
    pub async fn test_with_payload(
        &self,
        session: &Session,
        endpoint: &str,
        base_payload: Value,
    ) -> Vec<Finding> {
        self.test_mass_assignment(session, endpoint, Some(base_payload)).await
    }
}

impl CheckModule for MassAssignmentDetector {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            name: "mass_assignment_detector".to_string(),
            category: CheckCategory::AccessControl,
            description: "Detects mass assignment vulnerabilities by injecting privilege fields".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    async fn execute(&self, context: &crate::orchestrator::graph::ScanContext) -> Vec<CheckResult> {
        let sessions = context.sessions();
        let endpoints = context.endpoints();
        self.scan(sessions, endpoints).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_fields_loaded() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let detector = MassAssignmentDetector::new(client, cache);
        
        assert!(detector.privilege_fields.contains(&"role".to_string()));
        assert!(detector.privilege_fields.contains(&"is_admin".to_string()));
        assert!(detector.privilege_fields.contains(&"tier".to_string()));
        assert!(detector.privilege_fields.len() >= 10);
    }

    #[test]
    fn test_privilege_detection() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let detector = MassAssignmentDetector::new(client, cache);
        
        let success_body = r#"{"success": true, "user": {"role": "admin"}}"#;
        assert!(detector.detect_privilege_escalation(success_body, "role", &json!("admin")));
        
        let error_body = r#"{"error": "Field is read-only"}"#;
        assert!(!detector.detect_privilege_escalation(error_body, "role", &json!("admin")));
    }
}
