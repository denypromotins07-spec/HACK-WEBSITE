//! Remember-Me Cookie Predictability Detection Module
//!
//! Detects predictable remember-me cookie generation and cryptographic reuse.

use async_trait::async_trait;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory, 
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

pub struct RememberMeDetector {
    metadata: CheckMetadata,
}

impl RememberMeDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "session/remember_me",
            "Remember-Me Cookie Predictability Detection",
            "Detects predictable remember-me cookie generation and cryptographic reuse",
            Severity::High,
            CheckCategory::BrokenAuthentication,
        )
        .with_god_mode(true)
        .with_tags(vec!["session", "remember-me", "predictability"])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1500,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 200,
            max_duration_ms: 10000,
            max_payload_size: 2048,
        });
        Self { metadata }
    }

    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut freq = [0usize; 256];
        for &b in data { freq[b as usize] += 1; }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &c in &freq {
            if c > 0 {
                let p = c as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Use cryptographically secure remember-me tokens".to_string(),
            steps: vec![
                "Generate remember-me tokens using CSPRNG".to_string(),
                "Bind remember-me tokens to user agent and IP".to_string(),
                "Implement token rotation on use".to_string(),
            ],
            code_example: None,
            references: vec!["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html".to_string()],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for RememberMeDetector {
    async fn init(&mut self) -> Result<(), ModuleError> { Ok(()) }
    fn metadata(&self) -> &CheckMetadata { &self.metadata }
    fn should_run(&self, ctx: &CheckContext) -> bool { true }
    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let client = HttpClient::new();
        let mut findings = Vec::new();
        let mut executed = false;
        let mut tokens = Vec::new();

        // Collect remember-me tokens from multiple requests
        for _ in 0..20 {
            let login_url = format!("{}/login", ctx.target_url.trim_end_matches('/'));
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            
            let body = "username=test&password=test&remember-me=on";
            if let Ok(resp) = client.post_with_body(&login_url, body, headers).await {
                executed = true;
                if let Some(cookie) = resp.headers().get("Set-Cookie") {
                    if let Ok(cookie_str) = cookie.to_str() {
                        if let Some(pos) = cookie_str.find("remember-me=") {
                            let token = &cookie_str[pos + 12..];
                            let token_val = token.split(';').next().unwrap_or("");
                            if !token_val.is_empty() {
                                tokens.push(token_val.to_string());
                            }
                        }
                    }
                }
            }
        }

        if tokens.len() >= 5 {
            // Check for token reuse
            let unique_count = tokens.iter().collect::<std::collections::HashSet<_>>().len();
            if unique_count < tokens.len() {
                findings.push(Finding::new(
                    self.metadata.id.as_str(), Severity::Critical,
                    "Remember-Me Token Reuse Detected",
                    format!("Tokens are being reused: {}/{} unique", unique_count, tokens.len()),
                    &ctx.target_url,
                ).with_confidence(90).with_remediation(self.remediation()));
            }

            // Check entropy of tokens
            for token in &tokens {
                let entropy = Self::calculate_entropy(token.as_bytes());
                if entropy < 3.5 {
                    findings.push(Finding::new(
                        self.metadata.id.as_str(), Severity::High,
                        "Low Entropy Remember-Me Token",
                        format!("Token entropy: {:.2} bits/char (recommended: >= 4.0)", entropy),
                        &ctx.target_url,
                    ).with_payload(token.clone()).with_confidence(80).with_remediation(self.remediation()));
                    break;
                }
            }
        }

        Ok(CheckResult { findings, executed, timed_out: false, resource_usage: Default::default() })
    }
}
