//! Rate Limit Bypass Detection Module
//!
//! Bypasses rate limits using X-Forwarded-For spoofing, header pollution,
//! and IP rotation matrices. Implements aggressive header pollution for
//! god-mode rate-limit testing with strict timeouts.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory,
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum headers to pollute (bounded array)
const MAX_POLLUTION_HEADERS: usize = 16;

/// IP rotation matrix size
const IP_MATRIX_SIZE: usize = 8;

/// Bounded header pollution dictionary
#[derive(Debug, Clone)]
struct HeaderPollutionMatrix {
    headers: [&'static str; MAX_POLLUTION_HEADERS],
    count: usize,
}

impl HeaderPollutionMatrix {
    fn new() -> Self {
        Self {
            headers: [
                "X-Forwarded-For",
                "X-Real-IP",
                "X-Client-IP",
                "X-Originating-IP",
                "True-Client-IP",
                "CF-Connecting-IP",
                "Fastly-Client-IP",
                "Akamai-True-Client-IP",
                "X-Cluster-Client-IP",
                "Forwarded-For",
                "Forwarded",
                "Via",
                "X-ProxyUser-Ip",
                "Client-IP",
                "Remote-Addr",
                "X-Requester-IP",
            ],
            count: MAX_POLLUTION_HEADERS,
        }
    }

    fn iter(&self) -> impl Iterator<Item = &&str> {
        self.headers[..self.count].iter()
    }
}

/// IP rotation generator (bounded)
struct IpRotationMatrix {
    ips: [String; IP_MATRIX_SIZE],
    index: usize,
}

impl IpRotationMatrix {
    fn new(base_ip: &str) -> Self {
        let mut ips = [String::new(); IP_MATRIX_SIZE];
        // Generate sequential IPs for rotation
        for i in 0..IP_MATRIX_SIZE {
            let parts: Vec<&str> = base_ip.split('.').collect();
            if parts.len() == 4 {
                if let Ok(mut last_octet) = parts[3].parse::<u32>() {
                    last_octet = (last_octet + i as u32) % 256;
                    ips[i] = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], last_octet);
                } else {
                    ips[i] = format!("10.0.0.{}", i + 1);
                }
            } else {
                ips[i] = format!("10.0.0.{}", i + 1);
            }
        }
        Self { ips, index: 0 }
    }

    fn next(&mut self) -> &str {
        let ip = &self.ips[self.index];
        self.index = (self.index + 1) % IP_MATRIX_SIZE;
        ip
    }

    fn reset(&mut self) {
        self.index = 0;
    }
}

/// Rate limit bypass detector
pub struct RateLimitBypassDetector {
    metadata: CheckMetadata,
    pollution_matrix: HeaderPollutionMatrix,
}

impl RateLimitBypassDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "automation/rate_limit",
            "Rate Limit Bypass Detection",
            "Detects rate limit bypasses via header pollution and IP spoofing",
            Severity::High,
            CheckCategory::RateLimiting,
        )
        .with_god_mode(true)
        .with_tags(vec!["rate-limit", "bypass", "header-pollution", "ip-spoofing", "automation"])
        .with_references(vec![
            "https://owasp.org/www-community/attacks/Brute_force_attack",
            "https://cwe.mitre.org/data/definitions/307.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 2000,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 200,
            max_duration_ms: 10000,
            max_payload_size: 2048,
        });

        Self {
            metadata,
            pollution_matrix: HeaderPollutionMatrix::new(),
        }
    }

    /// Test single header for rate limit bypass
    async fn test_header_bypass(
        &self,
        client: &HttpClient,
        url: &str,
        header: &str,
        ip: &str,
    ) -> Result<bool, ModuleError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            reqwest::header::HeaderValue::from_str(ip).unwrap(),
        );

        let response = client.get_with_headers(url, headers).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let status = response.status().as_u16();
        
        // Success or different rate limit response indicates bypass
        Ok(status == 200 || status == 201 || status == 302)
    }

    /// Test multiple rapid requests to trigger rate limit
    async fn test_rate_limit_trigger(
        &self,
        client: &HttpClient,
        url: &str,
        count: usize,
    ) -> Result<u16, ModuleError> {
        let mut rate_limit_status: u16 = 0;

        for _ in 0..count.min(20) {
            let response = client.get(url).await
                .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
            
            let status = response.status().as_u16();
            if status == 429 || status == 503 {
                rate_limit_status = status;
                break;
            }
        }

        Ok(rate_limit_status)
    }

    /// Test header pollution combination
    async fn test_pollution_combo(
        &self,
        client: &HttpClient,
        url: &str,
        ip: &str,
    ) -> Result<bool, ModuleError> {
        let mut headers = reqwest::header::HeaderMap::new();
        
        // Add multiple conflicting headers
        for header in self.pollution_matrix.iter().take(4) {
            headers.insert(
                reqwest::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
                reqwest::header::HeaderValue::from_str(ip).unwrap(),
            );
        }

        let response = client.get_with_headers(url, headers).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let status = response.status().as_u16();
        Ok(status == 200 || status == 201)
    }

    /// Build evidence for rate limit bypass
    fn build_evidence(&self, url: &str, bypass_header: &str, bypass_ip: &str) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::Configuration {
                    key: bypass_header.to_string(),
                    value: bypass_ip.to_string(),
                },
                data: format!("Rate limit bypassed using {} header", bypass_header),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: None,
                    header: Some(bypass_header.to_string()),
                },
                confidence: 85,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Implement robust rate limiting that ignores client-controlled headers".to_string(),
            steps: vec![
                "Use server-side IP detection, not client-provided headers".to_string(),
                "Strip or ignore X-Forwarded-For and similar headers from untrusted sources".to_string(),
                "Implement rate limiting at the load balancer or WAF level".to_string(),
                "Use token-based rate limiting (CAPTCHA, JWT)".to_string(),
                "Implement progressive delays instead of hard blocks".to_string(),
                "Monitor for header pollution attacks".to_string(),
            ],
            code_example: Some(r#"// Nginx configuration - ignore client headers
http {
    # Use real IP from connection, not headers
    set_real_ip_from 10.0.0.0/8;
    real_ip_header proxy_protocol;
    
    # Rate limit by server-determined IP
    limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
}"#.to_string()),
            references: vec![
                "https://cheatsheetseries.owasp.org/cheatsheets/Rate_Limiting_Cheat_Sheet.html".to_string(),
                "https://www.nginx.com/blog/rate-limiting-nginx/".to_string(),
            ],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for RateLimitBypassDetector {
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

        // Common rate-limited endpoints
        let test_endpoints = [
            "/api/login",
            "/auth/login",
            "/api/password/reset",
            "/register",
            "/api/otp/verify",
            "/contact",
        ];

        for endpoint in test_endpoints.iter() {
            let url = format!("{}{}", base_url, endpoint);

            // First, try to trigger rate limit without bypass
            let rate_limit_triggered = self.test_rate_limit_trigger(&client, &url, 10).await?;
            
            if rate_limit_triggered > 0 {
                // Rate limit exists, now test bypasses
                let mut ip_rotator = IpRotationMatrix::new("10.0.0.1");

                for header in self.pollution_matrix.iter() {
                    let test_ip = ip_rotator.next();
                    
                    if let Ok(bypassed) = self.test_header_bypass(&client, &url, header, test_ip).await {
                        if bypassed {
                            executed = true;

                            let mut finding = Finding::new(
                                self.metadata.id.as_str(),
                                Severity::High,
                                "Rate Limit Bypass via Header Pollution",
                                format!("Rate limit at {} can be bypassed using {} header with spoofed IP {}", url, header, test_ip),
                                &url,
                            )
                            .with_payload(format!("{}: {}", header, test_ip))
                            .with_confidence(85)
                            .with_agent_id(ctx.agent_id)
                            .with_tags(vec!["rate-limit-bypass", "header-pollution"]);

                            let evidence = self.build_evidence(&url, header, test_ip);
                            for ev in evidence {
                                finding = finding.with_evidence(ev);
                            }

                            finding = finding.with_remediation(self.remediation());
                            findings.push(finding);
                            
                            // Cache successful bypass header for learning engine
                            if let Ok(cache) = LearningCache::global().await {
                                cache.cache_bypass_header(ctx.target_url.clone(), header.to_string()).await;
                            }
                            
                            break; // Found one bypass, move to next endpoint
                        }
                    }
                }

                // Test pollution combination
                if let Ok(combo_bypassed) = self.test_pollution_combo(&client, &url, "192.168.1.100").await {
                    if combo_bypassed {
                        executed = true;

                        let mut finding = Finding::new(
                            self.metadata.id.as_str(),
                            Severity::Critical,
                            "Rate Limit Bypass via Header Pollution Combination",
                            format!("Rate limit at {} bypassed using multiple conflicting headers", url),
                            &url,
                        )
                        .with_payload("Multiple X-Forwarded-For variants".to_string())
                        .with_confidence(90)
                        .with_agent_id(ctx.agent_id)
                        .with_tags(vec!["rate-limit-bypass", "header-pollution", "combo"]);

                        finding = finding.with_remediation(self.remediation());
                        findings.push(finding);
                    }
                }
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
    fn test_header_pollution_matrix() {
        let matrix = HeaderPollutionMatrix::new();
        assert_eq!(matrix.count, MAX_POLLUTION_HEADERS);
        
        let headers: Vec<_> = matrix.iter().collect();
        assert!(headers.contains(&&"X-Forwarded-For"));
        assert!(headers.contains(&&"X-Real-IP"));
    }

    #[test]
    fn test_ip_rotation() {
        let mut rotator = IpRotationMatrix::new("192.168.1.1");
        
        let first = rotator.next();
        assert!(first.starts_with("192.168.1."));
        
        rotator.reset();
        assert_eq!(rotator.next(), first);
    }

    #[test]
    fn test_bounded_storage() {
        let matrix = HeaderPollutionMatrix::new();
        // Verify stack-friendly size
        assert!(std::mem::size_of::<HeaderPollutionMatrix>() <= 256);
    }
}
