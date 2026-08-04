//! OAuth Dynamic Client Registration Abuse Detection Module
//!
//! Detects OAuth 2.0 dynamic client registration abuse on open identity systems.
//! Implements bounded state machines for registration endpoint enumeration.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory, 
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum registration test payloads (bounded array)
const MAX_REG_PAYLOADS: usize = 16;

/// OAuth dynamic registration detector
pub struct OAuthDynamicRegDetector {
    metadata: CheckMetadata,
}

impl OAuthDynamicRegDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "oauth/dynamic_reg",
            "OAuth Dynamic Client Registration Abuse Detection",
            "Detects OAuth 2.0 dynamic client registration abuse on open identity systems",
            Severity::High,
            CheckCategory::BrokenAuthentication,
        )
        .with_god_mode(true)
        .with_tags(vec!["oauth", "dynamic-registration", "client-abuse"])
        .with_references(vec![
            "https://datatracker.ietf.org/doc/html/rfc7591",
            "https://cwe.mitre.org/data/definitions/287.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1000,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 100,
            max_duration_ms: 8000,
            max_payload_size: 2048,
        });

        Self { metadata }
    }

    /// Generate malicious registration payloads
    fn generate_reg_payloads(&self) -> &'static [&'static str] {
        static PAYLOADS: &[&str] = &[
            r#"{"redirect_uris":["https://evil.com/callback"],"client_name":"Malicious App"}"#,
            r#"{"redirect_uris":["http://localhost:9999"],"client_name":"Local App"}"#,
            r#"{"redirect_uris":["https://attacker.com"],"grant_types":["authorization_code","implicit"]}"#,
            r#"{"redirect_uris":["data:text/html,<script>alert(1)</script>"],"client_name":"XSS App"}"#,
        ];
        PAYLOADS
    }

    /// Test dynamic registration endpoint
    async fn test_registration(
        &self,
        client: &HttpClient,
        url: &str,
        payload: &str,
    ) -> Result<RegTestResult, ModuleError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );

        let response = client.post_with_body(url, payload, headers).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
        
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        Ok(RegTestResult {
            status,
            body_length: body.len(),
            is_success: status == 200 || status == 201,
            contains_client_id: body.contains("client_id") || body.contains("client_secret"),
            contains_error: body.contains("error") || status >= 400,
        })
    }

    /// Build evidence for finding
    fn build_evidence(&self, url: &str, successful_regs: usize) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::HttpRequestResponse {
                    request: "Malicious OAuth client registration".to_string(),
                    response: format!("Server accepted {} malicious registrations", successful_regs),
                },
                data: format!(
                    "Open dynamic registration allows attacker-controlled redirect URIs at {}",
                    url
                ),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: Some("redirect_uris".to_string()),
                    header: None,
                },
                confidence: 85,
            },
        ]
    }

    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Restrict or disable dynamic client registration".to_string(),
            steps: vec![
                "Disable dynamic registration if not required".to_string(),
                "Implement strict redirect URI validation (exact match only)".to_string(),
                "Require manual approval for new client registrations".to_string(),
                "Use allowlist for permitted redirect URI domains".to_string(),
                "Log and alert on suspicious registration patterns".to_string(),
            ],
            code_example: Some(r#"// Validate redirect URI during registration
fn validate_redirect_uri(uri: &str) -> Result<(), Error> {
    let parsed = Url::parse(uri)?;
    
    // Reject non-HTTPS
    if parsed.scheme() != "https" {
        return Err(Error::InvalidScheme);
    }
    
    // Check against allowlist
    if !ALLOWED_DOMAINS.contains(parsed.host_str().unwrap()) {
        return Err(Error::DomainNotAllowed);
    }
    
    Ok(())
}"#.to_string()),
            references: vec![
                "https://datatracker.ietf.org/doc/html/rfc7591".to_string(),
                "https://oauth.net/2/client-authentication/".to_string(),
            ],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

#[derive(Debug, Clone)]
struct RegTestResult {
    status: u16,
    body_length: usize,
    is_success: bool,
    contains_client_id: bool,
    contains_error: bool,
}

#[async_trait]
impl VulnerabilityModule for OAuthDynamicRegDetector {
    async fn init(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    fn should_run(&self, ctx: &CheckContext) -> bool {
        if self.metadata.requires_god_mode && !ctx.god_mode {
            return false;
        }
        true
    }

    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let client = HttpClient::new();
        let mut findings = Vec::new();
        let mut executed = false;

        let reg_endpoints = [
            "/connect/register",
            "/oauth/register",
            "/api/oauth/register",
            "/auth/register",
            "/.well-known/oauth-authorization-server",
        ];

        for endpoint in reg_endpoints.iter() {
            let url = format!("{}{}", ctx.target_url.trim_end_matches('/'), endpoint);
            let payloads = self.generate_reg_payloads();
            let mut successful_regs = 0;

            for payload in payloads {
                match self.test_registration(&client, &url, payload).await {
                    Ok(result) => {
                        executed = true;
                        if result.is_success && result.contains_client_id {
                            successful_regs += 1;
                        }
                    }
                    Err(_) => continue,
                }
            }

            if successful_regs > 0 {
                let mut finding = Finding::new(
                    self.metadata.id.as_str(),
                    Severity::High,
                    "OAuth Dynamic Client Registration Open to Abuse",
                    format!(
                        "The OAuth server at {} allows unrestricted dynamic client registration, enabling attackers to register malicious clients.",
                        url
                    ),
                    &url,
                )
                .with_payload(format!("Successful malicious registrations: {}", successful_regs))
                .with_confidence(85)
                .with_agent_id(ctx.agent_id)
                .with_tags(vec!["oauth", "dynamic-registration"]);

                let evidences = self.build_evidence(&url, successful_regs);
                for ev in evidences {
                    finding = finding.with_evidence(ev);
                }

                finding = finding.with_remediation(self.remediation());
                findings.push(finding);
            }
        }

        if !findings.is_empty() {
            if let Ok(cache) = LearningCache::global().await {
                cache.cache_timing_baseline(ctx.target_url.clone(), "oauth_dynamic_reg".to_string()).await;
            }
        }

        Ok(CheckResult {
            findings,
            executed,
            timed_out: false,
            resource_usage: Default::default(),
        })
    }
}
