//! JWT Secret Bruteforce Detection Module
//! Tests weak JWT secrets using bounded dictionaries and CPU-budgeted HMAC validation.

use crate::checks::module::{CheckModule, CheckResult, CheckMetadata, CheckCategory};
use crate::findings::finding::Finding;
use crate::session::session::Session;
use crate::http::client::HttpClient;
use crate::learning::access_cache::AccessCache;
use std::sync::Arc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Common weak JWT secrets for testing (bounded dictionary)
const WEAK_SECRETS: &[&str] = &[
    "secret",
    "password",
    "123456",
    "key",
    "jwt_secret",
    "your-256-bit-secret",
    "your-secret-key",
    "changeme",
    "test",
    "admin",
    "supersecret",
    "mysecret",
    "secretkey",
    "private",
    "token_secret",
    "signing_key",
    "hmac_secret",
    "default_secret",
    "development_secret",
    "staging_secret",
    "production_secret",
    "app_secret",
    "api_secret",
];

/// Maximum number of secrets to test (CPU budget)
const MAX_SECRET_TESTS: usize = 50;

/// JWT bruteforce detector
pub struct JwtBruteforceDetector {
    http_client: Arc<HttpClient>,
    access_cache: Arc<AccessCache>,
    secret_dictionary: Vec<String>,
}

impl JwtBruteforceDetector {
    pub fn new(http_client: Arc<HttpClient>, access_cache: Arc<AccessCache>) -> Self {
        let mut dict: Vec<String> = WEAK_SECRETS.iter().map(|s| s.to_string()).collect();
        dict.truncate(MAX_SECRET_TESTS);
        
        Self {
            http_client,
            access_cache,
            secret_dictionary: dict,
        }
    }

    /// Decode base64url
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

    /// Verify JWT signature with a given secret
    fn verify_jwt_signature(&self, token: &str, secret: &str) -> bool {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return false;
        }

        let header_and_payload = format!("{}.{}", parts[0], parts[1]);
        
        let signature = match self.decode_base64url(parts[2]) {
            Some(sig) => sig,
            None => return false,
        };

        // Create HMAC
        let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(header_and_payload.as_bytes());

        mac.verify_slice(&signature).is_ok()
    }

    /// Test JWT secret strength
    async fn test_secret_strength(
        &self,
        session: &Session,
        endpoint: &str,
        original_token: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cracked_secret: Option<String> = None;

        // First, try offline verification
        for secret in &self.secret_dictionary {
            if self.verify_jwt_signature(original_token, secret) {
                cracked_secret = Some(secret.clone());
                break;
            }
        }

        // If we found a weak secret, verify by making requests
        if let Some(secret) = &cracked_secret {
            // Create a modified token with elevated privileges using the cracked secret
            let parts: Vec<&str> = original_token.split('.').collect();
            if parts.len() == 3 {
                // Decode payload
                if let Some(payload_bytes) = self.decode_base64url(parts[1]) {
                    if let Ok(mut payload) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) {
                        // Try to modify payload
                        if let Some(obj) = payload.as_object_mut() {
                            obj.insert("admin".to_string(), serde_json::json!(true));
                            obj.insert("role".to_string(), serde_json::json!("admin"));
                            
                            // Re-encode payload
                            let new_payload = serde_json::to_vec(&payload).unwrap();
                            let new_payload_b64 = self.encode_base64url(&new_payload);
                            
                            // Create new header
                            let header = r#"{"alg":"HS256","typ":"JWT"}"#;
                            let header_b64 = self.encode_base64url(header.as_bytes());
                            
                            // Sign with cracked secret
                            let message = format!("{}.{}", header_b64, new_payload_b64);
                            let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
                            mac.update(message.as_bytes());
                            let signature = mac.finalize().into_bytes();
                            let signature_b64 = self.encode_base64url(&signature);
                            
                            let forged_token = format!("{}.{}.{}", header_b64, new_payload_b64, signature_b64);
                            
                            // Test the forged token
                            let response = self.http_client
                                .get(endpoint)
                                .session(&session.clone_with_token(&forged_token))
                                .send()
                                .await;
                            
                            if response.status().is_success() {
                                let body = response.body();
                                
                                if !body.contains("unauthorized") && !body.contains("forbidden") {
                                    findings.push(Finding::new()
                                        .with_title("JWT: Weak Secret - Token Forgery Successful")
                                        .with_description(format!(
                                            "JWT signed with weak secret '{}' allows token forgery at {}",
                                            secret, endpoint
                                        ))
                                        .with_endpoint(endpoint)
                                        .with_severity(crate::findings::severity::Severity::Critical)
                                        .with_evidence(format!(
                                            "Weak secret: '{}', Forged token accepted",
                                            secret
                                        )));
                                    
                                    self.access_cache.cache_jwt_weakness(
                                        format!("weak_secret_{}", secret),
                                        endpoint.clone(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Even without forgery, weak secret is a finding
        if let Some(secret) = &cracked_secret {
            if findings.is_empty() {
                findings.push(Finding::new()
                    .with_title("JWT: Weak Secret Detected")
                    .with_description(format!(
                        "JWT uses weak/known secret: '{}' (offline verification)",
                        secret
                    ))
                    .with_endpoint(endpoint)
                    .with_severity(crate::findings::severity::Severity::High)
                    .with_evidence(format!(
                        "Secret '{}' successfully verified signature offline",
                        secret
                    )));
            }
        }

        findings
    }

    /// Scan for JWT bruteforce vulnerabilities
    pub async fn scan(&self, sessions: &[Session], endpoints: &[String]) -> Vec<CheckResult> {
        let mut results = Vec::new();

        for session in sessions {
            if let Some(token) = session.jwt_token() {
                for endpoint in endpoints {
                    if endpoint.contains("api")
                        || endpoint.contains("auth")
                        || endpoint.contains("user")
                    {
                        let findings = self.test_secret_strength(session, endpoint, token).await;
                        results.extend(findings.into_iter().map(CheckResult::Finding));
                        
                        if !results.is_empty() {
                            break; // One finding per session is enough
                        }
                    }
                }
            }
        }

        results
    }

    /// Add custom secrets to the dictionary
    pub fn add_custom_secrets(&mut self, secrets: Vec<String>) {
        for secret in secrets {
            if self.secret_dictionary.len() < MAX_SECRET_TESTS {
                self.secret_dictionary.push(secret);
            }
        }
    }
}

impl CheckModule for JwtBruteforceDetector {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            name: "jwt_bruteforce_detector".to_string(),
            category: CheckCategory::AccessControl,
            description: "Tests weak JWT secrets using bounded dictionary".to_string(),
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
    use hmac::Mac;

    #[test]
    fn test_weak_secrets_loaded() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let detector = JwtBruteforceDetector::new(client, cache);

        assert!(detector.secret_dictionary.contains(&"secret".to_string()));
        assert!(detector.secret_dictionary.contains(&"password".to_string()));
        assert!(detector.secret_dictionary.len() <= MAX_SECRET_TESTS);
    }

    #[test]
    fn test_signature_verification() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let detector = JwtBruteforceDetector::new(client, cache);

        // Create a valid HS256 token
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let payload = r#"{"sub":"1234567890","name":"John Doe"}"#;
        let secret = "test";

        let header_b64 = detector.encode_base64url(header.as_bytes());
        let payload_b64 = detector.encode_base64url(payload.as_bytes());
        let message = format!("{}.{}", header_b64, payload_b64);

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(message.as_bytes());
        let signature = mac.finalize().into_bytes();
        let signature_b64 = detector.encode_base64url(&signature);

        let token = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

        assert!(detector.verify_jwt_signature(&token, secret));
        assert!(!detector.verify_jwt_signature(&token, "wrong_secret"));
    }
}
