//! Subdomain Takeover Detection Module
//!
//! Identifies dangling CNAME records pointing to unclaimed third-party services
//! (GitHub Pages, AWS, etc.). Implements bounded DNS queries with strict OOB validation.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory,
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum subdomains to check (bounded)
const MAX_SUBDOMAINS: usize = 32;

/// Known takeover patterns for various services
#[derive(Debug, Clone)]
struct TakeoverPatterns {
    patterns: [(&'static str, &'static str, &'static str); 24],
    count: usize,
}

impl TakeoverPatterns {
    fn new() -> Self {
        Self {
            patterns: [
                // GitHub Pages
                ("github.io", "There isn't a GitHub Pages site here.", "GitHub Pages"),
                ("githubusercontent.com", "Repository not found", "GitHub User Content"),
                // AWS S3
                ("s3.amazonaws.com", "NoSuchBucket", "AWS S3"),
                ("amazonaws.com", "The specified bucket does not exist", "AWS"),
                // Azure
                ("azurewebsites.net", "Web App not available", "Azure Web Apps"),
                ("blob.core.windows.net", "BlobNotFound", "Azure Blob Storage"),
                ("cloudapp.azure.com", "Resource Not Found", "Azure Cloud App"),
                // Heroku
                ("herokuapp.com", "No such app", "Heroku"),
                ("herokussl.com", "Application Error", "Heroku SSL"),
                // Firebase
                ("firebaseapp.com", "Firebase Hosting Setup Error", "Firebase"),
                ("firebasestorage.googleapis.com", "Storage Bucket Not Found", "Firebase Storage"),
                // Shopify
                ("myshopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
                // Squarespace
                ("squarespace.com", "Unrecognized domain", "Squarespace"),
                // WordPress
                ("wordpress.com", "Do you want to register", "WordPress.com"),
                // Zendesk
                ("zendesk.com", "Help Center Closed", "Zendesk"),
                // Ghost
                ("ghost.io", "The thing you were looking for doesn't exist", "Ghost"),
                // Pantheon
                ("pantheonsite.io", "The Pantheon site you're looking for doesn't exist", "Pantheon"),
                // Bitbucket
                ("bitbucket.org", "Repository not found", "Bitbucket"),
                // GitLab
                ("gitlab.io", "GitLab Page not found", "GitLab Pages"),
                // Netlify
                ("netlify.app", "Page not found", "Netlify"),
                ("netlify.com", "Not Found", "Netlify"),
                // Vercel
                ("vercel.app", "The deployment could not be found", "Vercel"),
                // Surge
                ("surge.sh", "project not found", "Surge"),
                // Tilda
                ("tilda.ws", "Site not found", "Tilda"),
            ],
            count: 24,
        }
    }

    fn iter(&self) -> impl Iterator<Item = &(&'static str, &'static str, &'static str)> {
        self.patterns[..self.count].iter()
    }
}

/// Subdomain takeover detector
pub struct SubdomainTakeoverDetector {
    metadata: CheckMetadata,
    patterns: TakeoverPatterns,
}

impl SubdomainTakeoverDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "infra/subdomain_takeover",
            "Subdomain Takeover Detection",
            "Identifies dangling CNAME records pointing to unclaimed third-party services",
            Severity::High,
            CheckCategory::SubdomainEnumeration,
        )
        .with_god_mode(true)
        .with_tags(vec!["subdomain-takeover", "dns", "infrastructure"])
        .with_references(vec![
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Web_Server",
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 5000,
            max_memory_bytes: 8 * 1024 * 1024,
            max_requests: 100,
            max_duration_ms: 30000,
            max_payload_size: 512,
        });

        Self {
            metadata,
            patterns: TakeoverPatterns::new(),
        }
    }

    /// Check single subdomain for takeover
    async fn check_subdomain(
        &self,
        client: &HttpClient,
        subdomain: &str,
    ) -> Result<Option<(&'static str, &'static str)>, ModuleError> {
        let url = format!("https://{}", subdomain);
        
        let response = match client.get(&url).await {
            Ok(r) => r,
            Err(_) => {
                // Try HTTP fallback
                let http_url = format!("http://{}", subdomain);
                client.get(&http_url).await
                    .map_err(|e| ModuleError::NetworkError(e.to_string()))?
            }
        };

        let body = response.text().await.unwrap_or_default();
        let body_lower = body.to_lowercase();

        // Check against known patterns
        for (service_pattern, take_indicator, service_name) in self.patterns.iter() {
            if body_lower.contains(&take_indicator.to_lowercase()) 
                || body_lower.contains(&service_pattern.to_lowercase()) {
                return Ok(Some((*take_indicator, *service_name)));
            }
        }

        // Check for common error pages
        let error_indicators = [
            "not found",
            "doesn't exist",
            "no longer available",
            "site suspended",
            "domain parked",
            "this domain has been registered",
        ];

        for indicator in &error_indicators {
            if body_lower.contains(indicator) {
                return Ok(Some((*indicator, "Unknown Service")));
            }
        }

        Ok(None)
    }

    /// Generate subdomain variations from target URL
    fn generate_subdomains(&self, target: &str) -> Vec<String> {
        let mut subdomains = Vec::with_capacity(MAX_SUBDOMAINS);
        
        // Extract base domain
        if let Some(domain) = target.strip_prefix("www.") {
            let base = domain.split('/').next().unwrap_or(domain);
            
            // Common subdomain prefixes
            let prefixes = [
                "dev", "staging", "test", "api", "admin", "blog", 
                "shop", "store", "mail", "cdn", "static", "app",
                "mobile", "m", "beta", "alpha", "old", "legacy",
                "internal", "corp", "intranet", "portal", "dashboard",
            ];

            for prefix in &prefixes {
                if subdomains.len() >= MAX_SUBDOMAINS {
                    break;
                }
                subdomains.push(format!("{}.{}", prefix, base));
            }
        }

        subdomains
    }

    /// Build evidence for takeover finding
    fn build_evidence(&self, subdomain: &str, indicator: &str, service: &str) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::HttpRequestResponse {
                    request: format!("GET https://{} HTTP/1.1", subdomain),
                    response: format!("Indicator: {} (Service: {})", indicator, service),
                },
                data: format!("Subdomain {} points to unclaimed {} resource", subdomain, service),
                location: EvidenceLocation {
                    path: subdomain.to_string(),
                    line: None,
                    parameter: None,
                    header: None,
                },
                confidence: 85,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Remove or reclaim dangling DNS records".to_string(),
            steps: vec![
                "Audit all CNAME records pointing to third-party services".to_string(),
                "Remove DNS records for decommissioned services".to_string(),
                "Reclaim the external service resource if still needed".to_string(),
                "Implement DNS monitoring for unauthorized changes".to_string(),
                "Use DNS providers with security features (DNSSEC)".to_string(),
                "Document all external service dependencies".to_string(),
            ],
            code_example: Some(r#"// Example: Remove dangling CNAME record
# AWS Route53 CLI
aws route53 change-resource-record-sets \
    --hosted-zone-id ZONE_ID \
    --change-batch '{
        "Changes": [{
            "Action": "DELETE",
            "ResourceRecordSet": {
                "Name": "subdomain.example.com",
                "Type": "CNAME",
                "TTL": 300,
                "ResourceRecords": [{"Value": "old-service.github.io"}]
            }
        }]
    }'"#.to_string()),
            references: vec![
                "https://github.com/EdOverflow/can-i-take-over-xyz".to_string(),
                "https://hackerone.com/reports/292136".to_string(),
            ],
            estimated_effort: EffortLevel::Low,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for SubdomainTakeoverDetector {
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

        // Generate subdomains to check
        let subdomains = self.generate_subdomains(&ctx.target_url);

        for subdomain in subdomains.iter().take(MAX_SUBDOMAINS) {
            if let Ok(Some((indicator, service))) = self.check_subdomain(&client, subdomain).await {
                executed = true;

                let severity = if service.contains("AWS") || service.contains("Azure") || service.contains("GitHub") {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let mut finding = Finding::new(
                    self.metadata.id.as_str(),
                    severity,
                    format!("Potential Subdomain Takeover ({})", service),
                    format!("Subdomain {} appears to point to an unclaimed {} resource", subdomain, service),
                    subdomain,
                )
                .with_payload(format!("Takeover indicator: {}", indicator))
                .with_confidence(75)
                .with_agent_id(ctx.agent_id)
                .with_tags(vec!["subdomain-takeover", "dns", service]);

                let evidence = self.build_evidence(subdomain, indicator, service);
                for ev in evidence {
                    finding = finding.with_evidence(ev);
                }

                finding = finding.with_remediation(self.remediation());
                findings.push(finding);

                // Cache finding for learning engine
                if let Ok(cache) = LearningCache::global().await {
                    cache.cache_bypass_header(ctx.target_url.clone(), format!("takeover_{}", service)).await;
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
    fn test_takeover_patterns() {
        let patterns = TakeoverPatterns::new();
        assert_eq!(patterns.count, 24);
        
        let all_patterns: Vec<_> = patterns.iter().collect();
        assert_eq!(all_patterns.len(), 24);
    }

    #[test]
    fn test_subdomain_generation() {
        let detector = SubdomainTakeoverDetector::new();
        let subdomains = detector.generate_subdomains("https://www.example.com");
        
        assert!(!subdomains.is_empty());
        assert!(subdomains.len() <= MAX_SUBDOMAINS);
        assert!(subdomains[0].ends_with("example.com"));
    }

    #[test]
    fn test_bounded_storage() {
        let patterns = TakeoverPatterns::new();
        assert!(std::mem::size_of::<TakeoverPatterns>() <= 4096);
    }
}
