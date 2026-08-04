//! MFA Bypass Detection Module
//! Detects MFA bypass via direct endpoint access, skipped steps, and response manipulation.

use crate::checks::module::{CheckModule, CheckResult, CheckMetadata, CheckCategory};
use crate::findings::finding::Finding;
use crate::session::session::Session;
use crate::http::client::HttpClient;
use crate::learning::access_cache::AccessCache;
use std::sync::Arc;

/// Common MFA-related endpoints and patterns
const MFA_PATTERNS: &[&str] = &[
    "/mfa",
    "/2fa",
    "/otp",
    "/verify",
    "/authenticate",
    "/confirm",
    "/validate",
    "/challenge",
    "/recovery",
    "/backup",
];

/// MFA bypass detector
pub struct MfaBypassDetector {
    http_client: Arc<HttpClient>,
    access_cache: Arc<AccessCache>,
}

impl MfaBypassDetector {
    pub fn new(http_client: Arc<HttpClient>, access_cache: Arc<AccessCache>) -> Self {
        Self {
            http_client,
            access_cache,
        }
    }

    /// Test direct access to protected endpoints without MFA
    async fn test_direct_access(&self, session: &Session, protected_endpoints: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for endpoint in protected_endpoints {
            // Skip if endpoint requires MFA based on session state
            if session.requires_mfa() && !session.mfa_verified() {
                let response = self.http_client
                    .get(endpoint)
                    .session(session)
                    .send()
                    .await;
                
                if response.status().is_success() {
                    let body = response.body();
                    
                    // Check if this is actually a protected resource (not the MFA page itself)
                    if !body.contains("mfa") 
                        && !body.contains("verification")
                        && !body.contains("code")
                        && !body.contains("challenge")
                    {
                        findings.push(Finding::new()
                            .with_title("MFA Bypass: Direct Access Without Verification")
                            .with_description(format!(
                                "Session without MFA verification can directly access {}",
                                endpoint
                            ))
                            .with_endpoint(endpoint)
                            .with_severity(crate::findings::severity::Severity::Critical)
                            .with_evidence(format!(
                                "Session MFA status: unverified, Response: {}",
                                &body[..body.len().min(200)]
                            )));
                    }
                }
            }
        }
        
        findings
    }

    /// Test for MFA step skipping
    async fn test_step_skipping(&self, session: &Session, mfa_flow: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if mfa_flow.len() < 2 {
            return findings;
        }
        
        // Try to access the final step without completing intermediate steps
        let final_step = mfa_flow.last().unwrap();
        
        // Create a fresh session copy without MFA completion
        let incomplete_session = session.clone_without_mfa();
        
        let response = self.http_client
            .post(final_step)
            .session(&incomplete_session)
            .json(&serde_json::json!({"skip": true, "bypass": true}))
            .send()
            .await;
        
        if response.status().is_success() {
            let body = response.body();
            
            if body.contains("success") || body.contains("verified") || body.contains("complete") {
                findings.push(Finding::new()
                    .with_title("MFA Bypass: Step Skipping Detected")
                    .with_description(format!(
                        "MFA flow step {} can be accessed without completing previous steps",
                        final_step
                    ))
                    .with_endpoint(final_step)
                    .with_severity(crate::findings::severity::Severity::Critical)
                    .with_evidence(format!(
                        "Response indicates successful bypass: {}",
                        &body[..body.len().min(200)]
                    )));
            }
        }
        
        findings
    }

    /// Test response manipulation for MFA bypass
    async fn test_response_manipulation(&self, session: &Session, verify_endpoint: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Test with manipulated response expectations
        let test_payloads = vec![
            serde_json::json!({"code": "000000", "verified": true}),
            serde_json::json!({"code": "123456", "success": true, "mfa_verified": true}),
            serde_json::json!({"token": "bypassed", "skip_mfa": true}),
            serde_json::json!({"force": true, "override": true}),
        ];
        
        for payload in test_payloads {
            let response = self.http_client
                .post(verify_endpoint)
                .session(session)
                .json(&payload)
                .send()
                .await;
            
            if response.status().is_success() {
                let body = response.body();
                
                // Check if server accepted the manipulated response
                if body.contains("success") 
                    && !body.contains("invalid")
                    && !body.contains("error")
                    && !body.contains("failed")
                {
                    findings.push(Finding::new()
                        .with_title("MFA Bypass: Response Manipulation Successful")
                        .with_description(format!(
                            "Server accepts manipulated MFA verification at {}",
                            verify_endpoint
                        ))
                        .with_endpoint(verify_endpoint)
                        .with_severity(crate::findings::severity::Severity::High)
                        .with_evidence(format!(
                            "Payload: {}, Response: {}",
                            payload,
                            &body[..body.len().min(200)]
                        )));
                    
                    break; // One finding is enough
                }
            }
        }
        
        findings
    }

    /// Test for missing MFA enforcement on sensitive actions
    async fn test_mfa_enforcement(&self, session: &Session, sensitive_endpoints: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Only test if session has MFA available but not enforced
        if session.has_mfa_available() && !session.mfa_required() {
            for endpoint in sensitive_endpoints {
                let response = self.http_client
                    .post(endpoint)
                    .session(session)
                    .send()
                    .await;
                
                if response.status().is_success() {
                    // Sensitive actions should require MFA re-verification
                    if endpoint.contains("transfer")
                        || endpoint.contains("withdraw")
                        || endpoint.contains("delete")
                        || endpoint.contains("password")
                        || endpoint.contains("email")
                    {
                        findings.push(Finding::new()
                            .with_title("MFA Enforcement Missing")
                            .with_description(format!(
                                "Sensitive action at {} does not require MFA re-verification",
                                endpoint
                            ))
                            .with_endpoint(endpoint)
                            .with_severity(crate::findings::severity::Severity::Medium)
                            .with_evidence("Action completed without MFA challenge"));
                    }
                }
            }
        }
        
        findings
    }

    /// Scan for MFA bypass vulnerabilities
    pub async fn scan(&self, sessions: &[Session], endpoints: &[String]) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        for session in sessions {
            // Identify MFA-related endpoints
            let mfa_endpoints: Vec<String> = endpoints
                .iter()
                .filter(|e| {
                    let lower = e.to_lowercase();
                    MFA_PATTERNS.iter().any(|p| lower.contains(p))
                })
                .cloned()
                .collect();
            
            // Identify protected/sensitive endpoints
            let protected_endpoints: Vec<String> = endpoints
                .iter()
                .filter(|e| {
                    let lower = e.to_lowercase();
                    lower.contains("account")
                        || lower.contains("profile")
                        || lower.contains("settings")
                        || lower.contains("admin")
                        || lower.contains("financial")
                })
                .cloned()
                .collect();
            
            // Test direct access
            let direct_findings = self.test_direct_access(session, &protected_endpoints).await;
            results.extend(direct_findings.into_iter().map(CheckResult::Finding));
            
            // Test step skipping
            if mfa_endpoints.len() >= 2 {
                let skip_findings = self.test_step_skipping(session, &mfa_endpoints).await;
                results.extend(skip_findings.into_iter().map(CheckResult::Finding));
            }
            
            // Test response manipulation
            for mfa_endpoint in &mfa_endpoints {
                if mfa_endpoint.contains("verify") || mfa_endpoint.contains("confirm") {
                    let manip_findings = self.test_response_manipulation(session, mfa_endpoint).await;
                    results.extend(manip_findings.into_iter().map(CheckResult::Finding));
                }
            }
            
            // Test MFA enforcement
            let sensitive_endpoints: Vec<String> = endpoints
                .iter()
                .filter(|e| {
                    let lower = e.to_lowercase();
                    lower.contains("transfer")
                        || lower.contains("withdraw")
                        || lower.contains("delete")
                        || lower.contains("password/change")
                })
                .cloned()
                .collect();
            
            let enforce_findings = self.test_mfa_enforcement(session, &sensitive_endpoints).await;
            results.extend(enforce_findings.into_iter().map(CheckResult::Finding));
        }
        
        results
    }
}

impl CheckModule for MfaBypassDetector {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            name: "mfa_bypass_detector".to_string(),
            category: CheckCategory::AccessControl,
            description: "Detects MFA bypass vulnerabilities".to_string(),
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
    fn test_mfa_patterns_loaded() {
        assert!(MFA_PATTERNS.contains(&"/mfa"));
        assert!(MFA_PATTERNS.contains(&"/2fa"));
        assert!(MFA_PATTERNS.contains(&"/otp"));
        assert!(MFA_PATTERNS.contains(&"/verify"));
    }
}
