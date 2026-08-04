//! OIDC Confusion Detection Module
//!
//! Detects OpenID Connect issuer confusion and token validation endpoint manipulation.
//! Implements bounded state machines for redirect URI and issuer validation bypasses.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory, 
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum OIDC test variants (bounded array)
const MAX_OIDC_VARIANTS: usize = 16;

/// OIDC attack types
#[derive(Debug, Clone, Copy)]
enum OidcAttackType {
    IssuerConfusion,
    RedirectUriManipulation,
    TokenEndpointSwap,
    AudienceMismatch,
}

/// Bounded OIDC variant buffer
#[derive(Debug, Clone)]
struct OidcVariantBuffer {
    variants: [OidcAttackType; MAX_OIDC_VARIANTS],
    count: usize,
}

impl OidcVariantBuffer {
    fn new() -> Self {
        Self {
            variants: [OidcAttackType::IssuerConfusion; MAX_OIDC_VARIANTS],
            count: 0,
        }
    }

    fn push(&mut self, variant: OidcAttackType) {
        if self.count < MAX_OIDC_VARIANTS {
            self.variants[self.count] = variant;
            self.count += 1;
        }
    }
}

/// OIDC confusion detector with bounded state
pub struct OidcConfusionDetector {
    metadata: CheckMetadata,
    variant_buffer: OidcVariantBuffer,
}

impl OidcConfusionDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "token/oidc_confusion",
            "OpenID Connect Confusion Detection",
            "Detects OpenID Connect issuer confusion and token validation endpoint manipulation",
            Severity::Critical,
            CheckCategory::BrokenAuthentication,
        )
        .with_god_mode(true)
        .with_tags(vec!["oidc", "openid", "issuer-confusion", "oauth"])
        .with_references(vec![
            "https://github.com/oauth2-proxy/oauth2-proxy/issues/295",
            "https://cwe.mitre.org/data/definitions/287.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1500,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 150,
            max_duration_ms: 10000,
            max_payload_size: 4096,
        });

        Self {
            metadata,
            variant_buffer: OidcVariantBuffer::new(),
        }
    }

    /// Generate OIDC confusion payloads
    fn generate_oidc_variants(&self, target_url: &str) -> Vec<(OidcAttackType, String)> {
        let mut variants = Vec::with_capacity(MAX_OIDC_VARIANTS);
        
        // Parse domain for crafting attacks
        let domain = target_url.trim_start_matches("https://").trim_start_matches("http://");
        let base_domain = domain.split('/').next().unwrap_or("example.com");

        // 1. Issuer confusion - use attacker-controlled issuer
        variants.push((
            OidcAttackType::IssuerConfusion,
            format!("https://attacker-issuer.com/.well-known/openid-configuration"),
        ));

        // 2. Redirect URI manipulation
        variants.push((
            OidcAttackType::RedirectUriManipulation,
            format!("https://{}/callback?redirect_uri=https://evil.com", base_domain),
        ));

        // 3. Token endpoint swap
        variants.push((
            OidcAttackType::TokenEndpointSwap,
            format!("https://attacker.com/oauth/token"),
        ));

        // 4. Audience mismatch
        variants.push((
            OidcAttackType::AudienceMismatch,
            format!("aud=malicious-audience&iss=trusted-issuer"),
        ));

        variants
    }

    /// Test OIDC confusion against endpoint
    async fn test_oidc_variant(
        &self,
        client: &HttpClient,
        url: &str,
        variant: &str,
    ) -> Result<OidcTestResult, ModuleError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let response = client.post_with_body(url, variant, headers).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
        
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        Ok(OidcTestResult {
            status,
            body_length: body.len(),
            is_success: status >= 200 && status < 300,
            contains_token: body.contains("access_token") || body.contains("id_token"),
            contains_error: body.contains("error") || status == 400 || status == 401,
        })
    }

    /// Analyze results for OIDC confusion indicators
    fn analyze_results(&self, results: &[OidcTestResult]) -> Option<OidcEvidence> {
        let mut successful_confusions = 0;
        let mut token_leaks = 0;

        for result in results {
            // Successful response without expected error indicates potential confusion
            if result.is_success && !result.contains_error {
                successful_confusions += 1;
            }
            if result.contains_token && !result.contains_error {
                token_leaks += 1;
            }
        }

        if successful_confusions >= 1 || token_leaks >= 1 {
            return Some(OidcEvidence {
                successful_confusions,
                token_leaks,
                total_tests: results.len(),
            });
        }

        None
    }

    /// Build evidence for OIDC finding
    fn build_evidence(&self, url: &str, evidence: &OidcEvidence) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::HttpRequestResponse {
                    request: "OIDC confusion payload".to_string(),
                    response: format!("Token leak or validation bypass: {} successful", evidence.successful_confusions),
                },
                data: format!(
                    "OIDC issuer confusion detected: {} successful out of {} tests | Token leaks: {}",
                    evidence.successful_confusions,
                    evidence.total_tests,
                    evidence.token_leaks
                ),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: Some("iss/redirect_uri".to_string()),
                    header: None,
                },
                confidence: 85,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Implement strict OIDC issuer and redirect validation".to_string(),
            steps: vec![
                "Validate issuer matches exactly (no prefix/suffix matching)".to_string(),
                "Use exact redirect URI matching (no wildcards)".to_string(),
                "Validate audience claim matches expected value".to_string(),
                "Implement issuer allowlist".to_string(),
                "Log and alert on issuer mismatches".to_string(),
            ],
            code_example: Some(r#"// Validate OIDC token with strict checks
use openidconnect::{ClientId, ClientSecret, IssuerUrl, TokenResponse};
use openidconnect::core::{CoreClient, CoreProviderConfig};

let provider_config = CoreProviderConfig::discover(IssuerUrl::new("https://trusted-issuer.com".to_string())?)?;

// Strict issuer validation
if token.issuer() != expected_issuer {
    return Err(Error::InvalidIssuer);
}

// Exact redirect URI match
if redirect_uri != registered_redirect {
    return Err(Error::InvalidRedirectUri);
}"#.to_string()),
            references: vec![
                "https://github.com/oauth2-proxy/oauth2-proxy/issues/295".to_string(),
                "https://cwe.mitre.org/data/definitions/287.html".to_string(),
            ],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

/// OIDC test result
#[derive(Debug, Clone)]
struct OidcTestResult {
    status: u16,
    body_length: usize,
    is_success: bool,
    contains_token: bool,
    contains_error: bool,
}

/// OIDC evidence summary
#[derive(Debug, Clone)]
struct OidcEvidence {
    successful_confusions: usize,
    token_leaks: usize,
    total_tests: usize,
}

#[async_trait]
impl VulnerabilityModule for OidcConfusionDetector {
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

        let test_endpoints = [
            "/oauth/callback",
            "/auth/callback",
            "/api/auth/callback",
            "/openid/callback",
            "/api/oauth/token",
        ];

        for endpoint in test_endpoints.iter() {
            let url = format!("{}{}", ctx.target_url.trim_end_matches('/'), endpoint);
            let variants = self.generate_oidc_variants(&ctx.target_url);

            let mut results = Vec::with_capacity(variants.len());

            for (attack_type, variant) in variants {
                match self.test_oidc_variant(&client, &url, &variant).await {
                    Ok(result) => {
                        results.push(result);
                        self.variant_buffer.push(attack_type);
                    }
                    Err(_) => continue,
                }
            }

            executed = true;

            if let Some(evidence) = self.analyze_results(&results) {
                let mut finding = Finding::new(
                    self.metadata.id.as_str(),
                    Severity::Critical,
                    "OpenID Connect Issuer Confusion Detected",
                    format!(
                        "The application at {} is vulnerable to OIDC issuer confusion or token validation manipulation.",
                        url
                    ),
                    &url,
                )
                .with_payload(format!(
                    "Successful confusions: {} | Token leaks: {}",
                    evidence.successful_confusions,
                    evidence.token_leaks
                ))
                .with_confidence(85)
                .with_agent_id(ctx.agent_id)
                .with_tags(vec!["oidc", "issuer-confusion", "authentication"]);

                let evidences = self.build_evidence(&url, &evidence);
                for ev in evidences {
                    finding = finding.with_evidence(ev);
                }

                finding = finding.with_remediation(self.remediation());
                findings.push(finding);
            }
        }

        // Cache OIDC confusion vectors for learning engine
        if !findings.is_empty() {
            if let Ok(cache) = LearningCache::global().await {
                cache.cache_timing_baseline(ctx.target_url.clone(), "oidc_confusion".to_string()).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_buffer_no_heap() {
        let buffer = OidcVariantBuffer::new();
        assert!(std::mem::size_of::<OidcVariantBuffer>() <= 256);
    }

    #[test]
    fn test_oidc_variant_generation() {
        let detector = OidcConfusionDetector::new();
        let variants = detector.generate_oidc_variants("https://target.com/api");
        assert!(!variants.is_empty());
        assert_eq!(variants.len(), 4);
    }
}
