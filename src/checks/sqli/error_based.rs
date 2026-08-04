//! Error-Based SQL Injection Detection Module
//! Trigger controlled database errors using safe type conversion and syntax probes.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::learning::sqli_cache::SqliCache;
use crate::checks::sqli::error_signatures::ErrorSignatureDatabase;

/// Error-based SQLi detector
pub struct ErrorDetector {
    cache: SqliCache,
    http_client: HttpClient,
    signature_db: ErrorSignatureDatabase,
}

impl ErrorDetector {
    /// Create a new error-based detector
    pub fn new(cache: SqliCache, http_client: HttpClient) -> Self {
        Self {
            cache,
            http_client,
            signature_db: ErrorSignatureDatabase::new(),
        }
    }

    /// Generate safe error-triggering payloads
    fn generate_error_payloads(&self, param: &str) -> Vec<String> {
        vec![
            // Type conversion errors
            format!("{}='{}'", param, "admin' AND 1=CONVERT(int, 'SQLI')-- "),
            format!("{}='{}'", param, "admin' AND CAST('SQLI' AS int)-- "),
            
            // Division by zero
            format!("{}='{}'", param, "admin' AND 1/0-- "),
            
            // Invalid function calls
            format!("{}='{}'", param, "admin' AND SLEEP(1)-- "),
            format!("{}='{}'", param, "admin'; SELECT * FROM non_existent_table_xyz-- "),
            
            // Syntax errors
            format!("{}='{}'", param, "admin'--'"),
            format!("{}={}", param, "1'"),
            format!("{}={}", param, "1;"),
            
            // Quote escaping
            format!("{}='{}'", param, "admin''"),
            format!("{}=\"{}\"", param, "admin\"\""),
            
            // DBMS-specific error triggers
            format!("{}='{}'", param, "admin' AND EXTRACTVALUE(1, CONCAT('~', 'SQLI'))-- "), // MySQL
            format!("{}='{}'", param, "admin' AND XMLTYPE('SQLI')-- "), // Oracle
            format!("{}='{}'", param, "admin'; RAISERROR('SQLI', 16, 1)-- "), // MSSQL
        ]
    }

    /// Execute request and check for errors
    async fn test_payload(&self, request: &HttpRequest, payload: &str) -> Option<ErrorMatch> {
        let mut test_request = request.clone();

        // Inject payload into request
        if let Some(body) = test_request.body_mut() {
            if body.contains(&format!("{}=", test_request.param_name())) {
                let param = test_request.param_name();
                body.replace(&format!("{}=", param), &format!("{}={}", param, payload));
            }
        }

        match self.http_client.execute(&test_request).await {
            Ok(response) => {
                let status = response.status();
                let body = response.body();
                let headers = response.headers();

                // Check for error signatures in response
                if let Some(signature) = self.signature_db.match_error(body) {
                    return Some(ErrorMatch {
                        payload: payload.to_string(),
                        dbms: signature.dbms,
                        error_type: signature.error_type,
                        confidence: signature.confidence,
                        snippet: self.extract_snippet(body),
                        status_code: status,
                    });
                }

                // Also check for error indicators in headers
                if let Some(server_header) = headers.get("Server") {
                    if let Some(signature) = self.signature_db.identify_dbms_from_server(server_header) {
                        return Some(ErrorMatch {
                            payload: payload.to_string(),
                            dbms: signature,
                            error_type: "server_disclosure".to_string(),
                            confidence: 0.7,
                            snippet: server_header.to_string(),
                            status_code: status,
                        });
                    }
                }

                None
            }
            Err(_) => None,
        }
    }

    /// Extract relevant snippet from error message
    fn extract_snippet(&self, content: &str) -> String {
        // Find and extract the most relevant part of the error
        let keywords = ["error", "syntax", "exception", "warning", "failed"];
        
        for keyword in &keywords {
            if let Some(pos) = content.to_lowercase().find(keyword) {
                let start = pos.saturating_sub(20);
                let end = (pos + 100).min(content.len());
                return content[start..end].to_string();
            }
        }

        // Return first 200 chars if no keyword found
        content.chars().take(200).collect()
    }

    /// Detect error-based SQLi
    pub async fn detect(&mut self, request: &HttpRequest) -> Option<CheckResult> {
        let payloads = self.generate_error_payloads("id"); // Default param
        
        for payload in payloads {
            if let Some(error_match) = self.test_payload(request, &payload).await {
                // Record successful fingerprint
                self.cache.record_fingerprint(
                    crate::checks::sqli::time_based::DbmsType::Unknown,
                    &payload,
                    0,
                );

                return Some(CheckResult {
                    module: "error_based_sqli".to_string(),
                    severity: Severity::High,
                    confidence: error_match.confidence,
                    description: format!(
                        "Error-based SQLi detected via {} trigger. DBMS: {}, Error Type: {}",
                        error_match.payload, error_match.dbms, error_match.error_type
                    ),
                    evidence: format!("Error snippet: {}", error_match.snippet),
                    parameter: Some("id".to_string()),
                    remediation: "Use parameterized queries, disable verbose error messages".to_string(),
                });
            }
        }

        None
    }
}

impl CheckModule for ErrorDetector {
    fn name(&self) -> &'static str {
        "error_based_sqli"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn run(&mut self, _request: &HttpRequest) -> Vec<CheckResult> {
        vec![]
    }
}

/// Matched error information
#[derive(Debug, Clone)]
pub struct ErrorMatch {
    pub payload: String,
    pub dbms: String,
    pub error_type: String,
    pub confidence: f64,
    pub snippet: String,
    pub status_code: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_generation() {
        let cache = SqliCache::new();
        let client = HttpClient::default();
        let detector = ErrorDetector::new(cache, client);

        let payloads = detector.generate_error_payloads("id");
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("CONVERT")));
        assert!(payloads.iter().any(|p| p.contains("1/0")));
    }

    #[test]
    fn test_snippet_extraction() {
        let cache = SqliCache::new();
        let client = HttpClient::default();
        let detector = ErrorDetector::new(cache, client);

        let content = "An error occurred while processing your request. Syntax error near 'SELECT'.";
        let snippet = detector.extract_snippet(content);
        
        assert!(snippet.to_lowercase().contains("error"));
    }
}
