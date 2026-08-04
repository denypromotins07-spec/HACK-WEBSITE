//! CAPTCHA Bypass Detection Module
//!
//! Detects CAPTCHA bypasses by removing parameters, reusing solved tokens,
//! and testing empty values. Implements bounded state for token tracking.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory,
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum CAPTCHA tokens to track (bounded)
const MAX_TOKEN_HISTORY: usize = 8;

/// Bounded token history tracker
#[derive(Debug, Clone)]
struct TokenTracker {
    tokens: [Option<String>; MAX_TOKEN_HISTORY],
    count: usize,
}

impl TokenTracker {
    fn new() -> Self {
        Self {
            tokens: [None; MAX_TOKEN_HISTORY],
            count: 0,
        }
    }

    fn add(&mut self, token: String) {
        if self.count < MAX_TOKEN_HISTORY {
            self.tokens[self.count] = Some(token);
            self.count += 1;
        }
    }

    fn contains(&self, token: &str) -> bool {
        self.tokens[..self.count].iter().any(|t| t.as_ref().map_or(false, |s| s == token))
    }

    fn get_all(&self) -> Vec<&str> {
        self.tokens[..self.count]
            .iter()
            .filter_map(|t| t.as_ref().map(|s| s.as_str()))
            .collect()
    }
}

/// CAPTCHA bypass detector
pub struct CaptchaBypassDetector {
    metadata: CheckMetadata,
    token_tracker: TokenTracker,
}

impl CaptchaBypassDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "automation/captcha",
            "CAPTCHA Bypass Detection",
            "Detects CAPTCHA bypasses via parameter removal, token reuse, and empty values",
            Severity::High,
            CheckCategory::SecurityMisconfiguration,
        )
        .with_god_mode(true)
        .with_tags(vec!["captcha", "bypass", "automation", "bot-protection"])
        .with_references(vec![
            "https://owasp.org/www-community/attacks/CAPTCHA_bypass_attack",
            "https://cwe.mitre.org/data/definitions/304.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1000,
            max_memory_bytes: 2 * 1024 * 1024,
            max_requests: 50,
            max_duration_ms: 5000,
            max_payload_size: 2048,
        });

        Self {
            metadata,
            token_tracker: TokenTracker::new(),
        }
    }

    /// Test CAPTCHA bypass by removing CAPTCHA parameter
    async fn test_parameter_removal(
        &self,
        client: &HttpClient,
        url: &str,
        captcha_param: &str,
        form_data: &[(&str, &str)],
    ) -> Result<bool, ModuleError> {
        // Filter out CAPTCHA parameter
        let filtered_data: Vec<(&str, &str)> = form_data
            .iter()
            .filter(|(k, _)| !k.to_lowercase().contains(&captcha_param.to_lowercase()))
            .cloned()
            .collect();

        let response = client.post_form(url, &filtered_data).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        // Success without CAPTCHA indicates bypass
        Ok((status == 200 || status == 201 || status == 302) 
            && !body.to_lowercase().contains("captcha"))
    }

    /// Test CAPTCHA bypass with empty value
    async fn test_empty_value(
        &self,
        client: &HttpClient,
        url: &str,
        captcha_param: &str,
        form_data: &[(&str, &str)],
    ) -> Result<bool, ModuleError> {
        let mut modified_data: Vec<(String, String)> = form_data
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        // Set CAPTCHA parameter to empty
        for (key, value) in modified_data.iter_mut() {
            if key.to_lowercase().contains(&captcha_param.to_lowercase()) {
                *value = String::new();
            }
        }

        let data_refs: Vec<(&str, &str)> = modified_data
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let response = client.post_form(url, &data_refs).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        Ok((status == 200 || status == 201 || status == 302)
            && !body.to_lowercase().contains("invalid captcha"))
    }

    /// Test CAPTCHA token reuse
    async fn test_token_reuse(
        &self,
        client: &HttpClient,
        url: &str,
        captcha_param: &str,
        token: &str,
        base_form_data: &[(&str, &str)],
    ) -> Result<bool, ModuleError> {
        // Check if we've seen this token before
        if self.token_tracker.contains(token) {
            // Token was reused, test if it still works
            let mut modified_data: Vec<(String, String)> = base_form_data
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            for (key, value) in modified_data.iter_mut() {
                if key.to_lowercase().contains(&captcha_param.to_lowercase()) {
                    *value = token.to_string();
                }
            }

            let data_refs: Vec<(&str, &str)> = modified_data
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();

            let response = client.post_form(url, &data_refs).await
                .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

            let status = response.status().as_u16();
            return Ok(status == 200 || status == 201 || status == 302);
        }

        // Store token for future reuse tests
        self.token_tracker.add(token.to_string());
        Ok(false)
    }

    /// Test numeric/predictable CAPTCHA
    async fn test_predictable_captcha(
        &self,
        client: &HttpClient,
        url: &str,
        captcha_param: &str,
        base_form_data: &[(&str, &str)],
    ) -> Result<bool, ModuleError> {
        let predictable_values = ["0000", "1234", "abcd", "test", "null", "undefined"];

        for test_value in &predictable_values {
            let mut modified_data: Vec<(String, String)> = base_form_data
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            for (key, value) in modified_data.iter_mut() {
                if key.to_lowercase().contains(&captcha_param.to_lowercase()) {
                    *value = test_value.to_string();
                }
            }

            let data_refs: Vec<(&str, &str)> = modified_data
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();

            let response = client.post_form(url, &data_refs).await
                .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

            let status = response.status().as_u16();
            if status == 200 || status == 201 || status == 302 {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Build evidence for CAPTCHA bypass
    fn build_evidence(&self, url: &str, bypass_type: &str, details: &str) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::Configuration {
                    key: "bypass_type".to_string(),
                    value: details.to_string(),
                },
                data: format!("CAPTCHA bypassed via {}", bypass_type),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: Some("captcha".to_string()),
                    header: None,
                },
                confidence: 80,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self, bypass_type: &str) -> RemediationHint {
        let (summary, steps) = match bypass_type {
            "removal" => (
                "Implement server-side CAPTCHA validation".to_string(),
                vec![
                    "Always validate CAPTCHA on the server side".to_string(),
                    "Return generic error messages for missing CAPTCHA".to_string(),
                    "Implement request rate limiting as fallback".to_string(),
                ],
            ),
            "empty" => (
                "Validate CAPTCHA parameter presence and format".to_string(),
                vec![
                    "Reject empty CAPTCHA values explicitly".to_string(),
                    "Implement strict type and format validation".to_string(),
                    "Log attempts with empty CAPTCHA values".to_string(),
                ],
            ),
            "reuse" => (
                "Implement CAPTCHA token invalidation".to_string(),
                vec![
                    "Invalidate CAPTCHA tokens after single use".to_string(),
                    "Implement short token expiration times".to_string(),
                    "Bind tokens to session or IP address".to_string(),
                ],
            ),
            "predictable" => (
                "Use cryptographically secure CAPTCHA generation".to_string(),
                vec![
                    "Generate random, unpredictable CAPTCHA values".to_string(),
                    "Use established CAPTCHA services (reCAPTCHA, hCaptcha)".to_string(),
                    "Implement additional bot detection layers".to_string(),
                ],
            ),
            _ => (
                "Review CAPTCHA implementation security".to_string(),
                vec![
                    "Follow OWASP authentication guidelines".to_string(),
                    "Implement defense in depth".to_string(),
                ],
            ),
        };

        RemediationHint {
            summary,
            steps,
            code_example: Some(r#"// Server-side CAPTCHA validation example
public bool ValidateCaptcha(string userToken, string expectedToken) {
    if (string.IsNullOrWhiteSpace(userToken)) {
        _logger.LogWarning("Empty CAPTCHA submitted");
        return false;
    }
    
    // Constant-time comparison
    return CryptographicOperations.FixedTimeEquals(
        Encoding.UTF8.GetBytes(userToken),
        Encoding.UTF8.GetBytes(expectedToken)
    );
}"#.to_string()),
            references: vec![
                "https://developers.google.com/recaptcha/docs/verify".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html".to_string(),
            ],
            estimated_effort: EffortLevel::Low,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for CaptchaBypassDetector {
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

        let base_url = ctx.target_url.trim_end_matches('/');

        // Common CAPTCHA-protected endpoints
        let test_endpoints = [
            ("/api/login", &[("username", "test"), ("password", "test"), ("captcha", "SOLVED_TOKEN")][..]),
            ("/auth/register", &[("email", "test@test.com"), ("captcha", "TOKEN")]),
            ("/api/password/reset", &[("email", "test@test.com"), ("captcha", "TOKEN")]),
            ("/contact", &[("name", "test"), ("message", "test"), ("captcha", "TOKEN")]),
        ];

        let captcha_params = ["captcha", "g-recaptcha-response", "h-captcha-response", "cf_turnstile_response"];

        for (endpoint, form_data) in test_endpoints.iter() {
            let url = format!("{}{}", base_url, endpoint);

            for captcha_param in &captcha_params {
                // Test 1: Parameter removal
                if let Ok(bypassed) = self.test_parameter_removal(&client, &url, captcha_param, form_data).await {
                    if bypassed {
                        executed = true;

                        let mut finding = Finding::new(
                            self.metadata.id.as_str(),
                            Severity::High,
                            "CAPTCHA Bypass via Parameter Removal",
                            format!("CAPTCHA at {} can be bypassed by removing the {} parameter", url, captcha_param),
                            &url,
                        )
                        .with_payload(format!("Removed parameter: {}", captcha_param))
                        .with_confidence(85)
                        .with_agent_id(ctx.agent_id)
                        .with_tags(vec!["captcha-bypass", "parameter-tampering"]);

                        let evidence = self.build_evidence(&url, "removal", captcha_param);
                        for ev in evidence {
                            finding = finding.with_evidence(ev);
                        }

                        finding = finding.with_remediation(self.remediation("removal"));
                        findings.push(finding);
                    }
                }

                // Test 2: Empty value
                if let Ok(bypassed) = self.test_empty_value(&client, &url, captcha_param, form_data).await {
                    if bypassed {
                        executed = true;

                        let mut finding = Finding::new(
                            self.metadata.id.as_str(),
                            Severity::High,
                            "CAPTCHA Bypass via Empty Value",
                            format!("CAPTCHA at {} accepts empty values", url),
                            &url,
                        )
                        .with_payload(format!("Empty {}: accepted", captcha_param))
                        .with_confidence(80)
                        .with_agent_id(ctx.agent_id)
                        .with_tags(vec!["captcha-bypass", "validation-bypass"]);

                        finding = finding.with_remediation(self.remediation("empty"));
                        findings.push(finding);
                    }
                }

                // Test 3: Predictable values
                if let Ok(bypassed) = self.test_predictable_captcha(&client, &url, captcha_param, form_data).await {
                    if bypassed {
                        executed = true;

                        let mut finding = Finding::new(
                            self.metadata.id.as_str(),
                            Severity::Critical,
                            "CAPTCHA Bypass via Predictable Value",
                            format!("CAPTCHA at {} accepts predictable values", url),
                            &url,
                        )
                        .with_payload("Predictable CAPTCHA value accepted".to_string())
                        .with_confidence(90)
                        .with_agent_id(ctx.agent_id)
                        .with_tags(vec!["captcha-bypass", "weak-validation"]);

                        finding = finding.with_remediation(self.remediation("predictable"));
                        findings.push(finding);
                    }
                }
            }
        }

        // Cache findings for learning engine
        if !findings.is_empty() {
            if let Ok(cache) = LearningCache::global().await {
                cache.cache_bypass_header(ctx.target_url.clone(), "captcha_bypass".to_string()).await;
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
    fn test_token_tracker() {
        let mut tracker = TokenTracker::new();
        assert_eq!(tracker.count, 0);

        tracker.add("token1".to_string());
        tracker.add("token2".to_string());
        
        assert!(tracker.contains("token1"));
        assert!(!tracker.contains("token3"));
        assert_eq!(tracker.count, 2);
    }

    #[test]
    fn test_bounded_history() {
        let mut tracker = TokenTracker::new();
        
        for i in 0..MAX_TOKEN_HISTORY + 5 {
            tracker.add(format!("token_{}", i));
        }

        assert_eq!(tracker.count, MAX_TOKEN_HISTORY);
    }
}
