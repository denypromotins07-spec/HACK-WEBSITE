//! OAuth Scope Inflation Detection Module
//!
//! Detects OAuth scope inflation by injecting unauthorized permission requests.
//! Implements bounded state machines for privilege escalation detection.

use async_trait::async_trait;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory, 
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

pub struct OAuthScopeInflationDetector {
    metadata: CheckMetadata,
}

impl OAuthScopeInflationDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "oauth/scope_inflation",
            "OAuth Scope Inflation Detection",
            "Detects OAuth scope inflation by injecting unauthorized permission requests",
            Severity::High,
            CheckCategory::BrokenAccessControl,
        )
        .with_god_mode(true)
        .with_tags(vec!["oauth", "scope-inflation", "privilege-escalation"])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1000,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 100,
            max_duration_ms: 8000,
            max_payload_size: 2048,
        });
        Self { metadata }
    }

    fn generate_scope_payloads(&self) -> &'static [&'static str] {
        &[
            "scope=admin:read admin:write",
            "scope=user:delete root:access",
            "scope=*",
            "scope=read write delete admin",
        ]
    }

    async fn test_scope_injection(
        &self,
        client: &HttpClient,
        url: &str,
        scope: &str,
    ) -> Result<(u16, bool), ModuleError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let response = client.post_with_body(url, scope, headers).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        Ok((status, body.contains("access_token")))
    }

    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Implement strict scope validation".to_string(),
            steps: vec![
                "Validate requested scopes against user's granted permissions".to_string(),
                "Reject unknown or elevated scopes silently".to_string(),
                "Log scope inflation attempts".to_string(),
            ],
            code_example: None,
            references: vec!["https://oauth.net/2/scope/".to_string()],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for OAuthScopeInflationDetector {
    async fn init(&mut self) -> Result<(), ModuleError> { Ok(()) }
    fn metadata(&self) -> &CheckMetadata { &self.metadata }
    fn should_run(&self, ctx: &CheckContext) -> bool {
        self.metadata.requires_god_mode && ctx.god_mode
    }
    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let client = HttpClient::new();
        let mut findings = Vec::new();
        let mut executed = false;

        for endpoint in ["/oauth/token", "/api/oauth/token"] {
            let url = format!("{}{}", ctx.target_url.trim_end_matches('/'), endpoint);
            for scope in self.generate_scope_payloads() {
                if let Ok((status, has_token)) = self.test_scope_injection(&client, &url, scope).await {
                    executed = true;
                    if status == 200 && has_token {
                        findings.push(Finding::new(
                            self.metadata.id.as_str(), Severity::High,
                            "OAuth Scope Inflation Successful",
                            format!("Elevated scopes accepted at {}", url), &url,
                        ).with_payload(scope.to_string()).with_confidence(80));
                    }
                }
            }
        }
        Ok(CheckResult { findings, executed, timed_out: false, resource_usage: Default::default() })
    }
}
