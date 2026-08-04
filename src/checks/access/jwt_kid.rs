//! JWT kid Injection Detection Module
//! Detects JWT kid injection using path traversal and static key references.

use crate::checks::module::{CheckModule, CheckResult, CheckMetadata, CheckCategory};
use crate::findings::finding::Finding;
use crate::session::session::Session;
use crate::http::client::HttpClient;
use crate::learning::access_cache::AccessCache;
use std::sync::Arc;

/// JWT kid injection detector
pub struct JwtKidDetector {
    http_client: Arc<HttpClient>,
    access_cache: Arc<AccessCache>,
}

impl JwtKidDetector {
    pub fn new(http_client: Arc<HttpClient>, access_cache: Arc<AccessCache>) -> Self {
        Self {
            http_client,
            access_cache,
        }
    }

    /// Encode to base64url without padding
    fn encode_base64url(&self, data: &[u8]) -> String {
        base64::encode_config(data, base64::URL_SAFE_NO_PAD)
    }

    /// Decode a JWT and extract header
    fn decode_jwt_header(&self, token: &str) -> Option<serde_json::Value> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let mut padded = parts[0].to_string();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }

        let decoded = base64::decode_config(&padded, base64::URL_SAFE).ok()?;
        serde_json::from_slice(&decoded).ok()
    }

    /// Create JWT with modified kid header
    fn create_jwt_with_kid(
        &self,
        original_token: &str,
        kid_value: &str,
    ) -> Option<String> {
        let parts: Vec<&str> = original_token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        // Decode original header
        let mut padded = parts[0].to_string();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }
        let decoded = base64::decode_config(&padded, base64::URL_SAFE).ok()?;
        let mut header: serde_json::Value = serde_json::from_slice(&decoded).ok()?;

        // Modify kid
        if let Some(obj) = header.as_object_mut() {
            obj.insert("kid".to_string(), serde_json::json!(kid_value));
        }

        // Re-encode header
        let header_bytes = serde_json::to_vec(&header).unwrap();
        let new_header = self.encode_base64url(&header_bytes);

        // Keep original payload and signature
        format!("{}.{}.{}", new_header, parts[1], parts[2])
    }

    /// Test path traversal in kid parameter
    async fn test_path_traversal(
        &self,
        session: &Session,
        endpoint: &str,
        original_token: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Path traversal payloads for kid
        let traversal_payloads = vec![
            "/dev/null",
            "/etc/hosts",
            "..\\..\\..\\etc\\passwd",
            "....//....//etc/passwd",
            "/proc/self/environ",
            "file:///etc/passwd",
            "static_key",
            "jwt_secret",
            "secret",
            "key",
            "",
        ];

        for kid_value in traversal_payloads {
            if let Some(modified_token) = self.create_jwt_with_kid(original_token, kid_value) {
                let response = self.http_client
                    .get(endpoint)
                    .session(&session.clone_with_token(&modified_token))
                    .send()
                    .await;

                if response.status().is_success() {
                    let body = response.body();

                    if !body.contains("invalid")
                        && !body.contains("signature")
                        && !body.contains("unauthorized")
                        && !body.contains("forbidden")
                    {
                        findings.push(Finding::new()
                            .with_title("JWT: kid Injection - Path Traversal")
                            .with_description(format!(
                                "JWT kid parameter accepts path traversal: {} at {}",
                                kid_value, endpoint
                            ))
                            .with_endpoint(endpoint)
                            .with_severity(crate::findings::severity::Severity::Critical)
                            .with_evidence(format!(
                                "kid value: {}, Response: {}",
                                kid_value,
                                &body[..body.len().min(200)]
                            )));

                        self.access_cache.cache_jwt_weakness(
                            format!("kid_traversal_{}", kid_value),
                            endpoint.clone(),
                        );

                        break;
                    }
                }
            }
        }

        findings
    }

    /// Test static key reference injection
    async fn test_static_key_injection(
        &self,
        session: &Session,
        endpoint: &str,
        original_token: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Common static key names that might be hardcoded
        let static_keys = vec![
            "master_key",
            "default_key",
            "public_key",
            "verification_key",
            "hmac_secret",
            "signing_key",
            "test_key",
            "dev_key",
        ];

        for kid_value in static_keys {
            if let Some(modified_token) = self.create_jwt_with_kid(original_token, kid_value) {
                let response = self.http_client
                    .get(endpoint)
                    .session(&session.clone_with_token(&modified_token))
                    .send()
                    .await;

                if response.status().is_success() {
                    let body = response.body();

                    if !body.contains("invalid")
                        && !body.contains("unauthorized")
                        && !body.contains("forbidden")
                    {
                        findings.push(Finding::new()
                            .with_title("JWT: kid Injection - Static Key Reference")
                            .with_description(format!(
                                "JWT kid parameter accepts static key reference: {} at {}",
                                kid_value, endpoint
                            ))
                            .with_endpoint(endpoint)
                            .with_severity(crate::findings::severity::Severity::High)
                            .with_evidence(format!(
                                "kid value: {}, Response: {}",
                                kid_value,
                                &body[..body.len().min(200)]
                            )));

                        break;
                    }
                }
            }
        }

        findings
    }

    /// Scan for JWT kid injection vulnerabilities
    pub async fn scan(&self, sessions: &[Session], endpoints: &[String]) -> Vec<CheckResult> {
        let mut results = Vec::new();

        for session in sessions {
            if let Some(token) = session.jwt_token() {
                // Verify it's a valid JWT first
                if let Some(_header) = self.decode_jwt_header(token) {
                    for endpoint in endpoints {
                        if endpoint.contains("api")
                            || endpoint.contains("auth")
                            || endpoint.contains("user")
                            || endpoint.contains("account")
                        {
                            // Test path traversal
                            let traversal_findings = self.test_path_traversal(session, endpoint, token).await;
                            results.extend(traversal_findings.into_iter().map(CheckResult::Finding));

                            // Test static key injection
                            let static_findings = self.test_static_key_injection(session, endpoint, token).await;
                            results.extend(static_findings.into_iter().map(CheckResult::Finding));
                        }
                    }
                }
            }
        }

        results
    }
}

impl CheckModule for JwtKidDetector {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            name: "jwt_kid_detector".to_string(),
            category: CheckCategory::AccessControl,
            description: "Detects JWT kid injection vulnerabilities".to_string(),
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
    fn test_base64url_encoding() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let detector = JwtKidDetector::new(client, cache);

        let data = b"test";
        let encoded = detector.encode_base64url(data);
        assert!(!encoded.ends_with('='));
    }
}
