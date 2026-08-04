//! Session Invalidation Detection Module
//!
//! Detects session invalidation failures by reusing cookies after explicit logout.

use async_trait::async_trait;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory, 
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

pub struct SessionInvalidationDetector {
    metadata: CheckMetadata,
}

impl SessionInvalidationDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "session/invalidation",
            "Session Invalidation Detection",
            "Detects session invalidation failures by reusing cookies after explicit logout",
            Severity::High,
            CheckCategory::BrokenAuthentication,
        )
        .with_god_mode(true)
        .with_tags(vec!["session", "invalidation", "logout-bypass"])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1500,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 200,
            max_duration_ms: 10000,
            max_payload_size: 2048,
        });
        Self { metadata }
    }

    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Implement proper server-side session invalidation".to_string(),
            steps: vec![
                "Invalidate session on server upon logout".to_string(),
                "Use session token rotation after authentication events".to_string(),
                "Implement absolute session timeouts".to_string(),
            ],
            code_example: None,
            references: vec!["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html".to_string()],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for SessionInvalidationDetector {
    async fn init(&mut self) -> Result<(), ModuleError> { Ok(()) }
    fn metadata(&self) -> &CheckMetadata { &self.metadata }
    fn should_run(&self, ctx: &CheckContext) -> bool { true }
    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let client = HttpClient::new();
        let mut findings = Vec::new();
        let mut executed = false;

        // Test logout endpoint and verify session is invalidated
        let logout_url = format!("{}/logout", ctx.target_url.trim_end_matches('/'));
        let protected_url = format!("{}/api/user/profile", ctx.target_url.trim_end_matches('/'));

        // First get a session
        if let Ok(resp) = client.get(&ctx.target_url).await {
            let mut headers = reqwest::header::HeaderMap::new();
            if let Some(cookie) = resp.headers().get("Set-Cookie") {
                headers.insert(reqwest::header::COOKIE, cookie.clone());
                
                // Access protected resource before logout
                let before_status = client.get_with_headers(&protected_url, headers.clone()).await
                    .map(|r| r.status().as_u16()).unwrap_or(401);
                
                // Logout
                let _ = client.post_with_body(&logout_url, "", reqwest::header::HeaderMap::new()).await;
                
                // Try to access protected resource after logout with same cookie
                if let Ok(after_resp) = client.get_with_headers(&protected_url, headers.clone()).await {
                    executed = true;
                    let after_status = after_resp.status().as_u16();
                    
                    // If still authenticated after logout, session wasn't invalidated
                    if before_status < 300 && after_status < 300 {
                        findings.push(Finding::new(
                            self.metadata.id.as_str(), Severity::High,
                            "Session Not Invalidated After Logout",
                            format!("Session remained valid at {} after logout", protected_url),
                            &logout_url,
                        ).with_confidence(80).with_remediation(self.remediation()));
                    }
                }
            }
        }

        Ok(CheckResult { findings, executed, timed_out: false, resource_usage: Default::default() })
    }
}
