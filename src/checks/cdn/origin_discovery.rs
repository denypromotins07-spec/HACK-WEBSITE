//! Origin Discovery Module
//! Identifies likely origin IPs using DNS history placeholders and certificate correlation.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::findings::cache_evidence::CacheEvidence;
use std::collections::HashMap;

/// Known CDN IP ranges and their providers
const CDN_IP_RANGES: &[(&str, &str)] = &[
    // Cloudflare
    ("104.16.0.0/12", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare"),
    ("131.0.72.0/22", "Cloudflare"),
    
    // Akamai
    ("23.0.0.0/12", "Akamai"),
    ("104.64.0.0/10", "Akamai"),
    
    // Fastly
    ("151.101.0.0/16", "Fastly"),
    ("199.232.0.0/16", "Fastly"),
    
    // CloudFront
    ("54.182.0.0/16", "CloudFront"),
    ("54.192.0.0/16", "CloudFront"),
    ("54.230.0.0/16", "CloudFront"),
    ("54.239.0.0/16", "CloudFront"),
    
    // Incapsula
    ("45.60.0.0/16", "Incapsula"),
    ("192.230.0.0/16", "Incapsula"),
];

/// DNS record types to check for origin discovery
const DNS_RECORD_TYPES: &[&str] = &["A", "AAAA", "MX", "TXT", "NS"];

/// Certificate fields that may reveal origin
const CERT_ORIGIN_INDICATORS: &[&str] = &[
    "Subject Alternative Name",
    "Issuer",
    "Not Before",
    "Not After",
];

pub struct OriginDiscoveryChecker {
    // In a real implementation, this would have DNS and certificate analysis tools
}

impl OriginDiscoveryChecker {
    pub fn new() -> Self {
        Self {}
    }

    /// Analyze response headers for origin leakage
    pub fn analyze_origin_leakage(&self, headers: &HashMap<String, String>) -> Vec<String> {
        let mut findings = Vec::new();
        
        // Check Server header for origin technology
        if let Some(server) = headers.get("server") {
            let server_lower = server.to_lowercase();
            
            // If server reveals non-CDN technology
            if server_lower.contains("nginx") 
                || server_lower.contains("apache")
                || server_lower.contains("iis")
                || server_lower.contains("tomcat")
            {
                // But we're behind a CDN, this might be origin leak
                if headers.contains_key("x-cache") || headers.contains_key("via") {
                    findings.push(format!(
                        "Server header '{}' may reveal origin technology behind CDN",
                        server
                    ));
                }
            }
        }
        
        // Check X-Powered-By
        if let Some(powered_by) = headers.get("x-powered-by") {
            findings.push(format!("X-Powered-By header reveals technology: {}", powered_by));
        }
        
        // Check for direct IP in redirects
        if let Some(location) = headers.get("location") {
            if location.starts_with("http://") || location.starts_with("https://") {
                let url_parts: Vec<&str> = location.split("//").collect();
                if url_parts.len() > 1 {
                    let host_part = url_parts[0];
                    if self.is_likely_ip(host_part) {
                        findings.push(format!("Redirect to IP address detected: {}", location));
                    }
                }
            }
        }
        
        findings
    }

    /// Check if a string looks like an IP address
    fn is_likely_ip(&self, s: &str) -> bool {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() == 4 {
            parts.iter().all(|p| p.parse::<u8>().is_ok())
        } else {
            false
        }
    }

    /// Identify CDN provider from headers
    pub fn identify_cdn_provider(&self, headers: &HashMap<String, String>) -> Option<&'static str> {
        // Cloudflare indicators
        if headers.contains_key("cf-ray") 
            || headers.contains_key("cf-cache-status")
            || headers.get("server").map(|s| s == "cloudflare").unwrap_or(false)
        {
            return Some("Cloudflare");
        }
        
        // Akamai indicators
        if headers.contains_key("x-akamai-transformed")
            || headers.contains_key("x-akamai-request-id")
            || headers.get("server").map(|s| s.contains("Akamai")).unwrap_or(false)
        {
            return Some("Akamai");
        }
        
        // Fastly indicators
        if headers.contains_key("x-served-by") 
            && headers.get("x-served-by").unwrap().contains("fastly")
            || headers.contains_key("fastly-cache-status")
        {
            return Some("Fastly");
        }
        
        // CloudFront indicators
        if headers.contains_key("x-amz-cf-id")
            || headers.contains_key("x-amz-cf-pop")
            || headers.get("via").map(|v| v.contains("CloudFront")).unwrap_or(false)
        {
            return Some("CloudFront");
        }
        
        // Generic CDN detection
        if headers.contains_key("x-cache") || headers.contains_key("via") {
            return Some("Unknown CDN");
        }
        
        None
    }

    /// Generate potential origin discovery techniques
    pub fn generate_origin_probes(&self, domain: &str) -> Vec<String> {
        let mut probes = Vec::new();
        
        // Common origin subdomain patterns
        let origin_patterns = [
            "origin", "origins", "origin-server", "backend", "web",
            "app", "direct", "internal", "edge-origin", "cdn-origin",
        ];
        
        for pattern in &origin_patterns {
            probes.push(format!("{}.{}", pattern, domain));
        }
        
        // Time-based probes (historical DNS)
        probes.push(format!("www.{}", domain));
        probes.push(domain.to_string());
        
        probes
    }

    /// Analyze certificate for origin information
    pub fn analyze_certificate(&self, cert_info: &HashMap<String, String>) -> Vec<String> {
        let mut findings = Vec::new();
        
        // Check SAN entries for origin domains
        if let Some(san) = cert_info.get("Subject Alternative Name") {
            let san_lower = san.to_lowercase();
            
            if san_lower.contains("origin") 
                || san_lower.contains("internal")
                || san_lower.contains("backend")
            {
                findings.push(format!("Certificate SAN may reveal origin: {}", san));
            }
            
            // Look for non-CDN domains
            for entry in san.split(',') {
                let entry = entry.trim();
                if !entry.contains("cloudflare") 
                    && !entry.contains("akamai")
                    && !entry.contains("fastly")
                    && !entry.contains("amazonaws")
                {
                    findings.push(format!("Non-CDN domain in certificate: {}", entry));
                }
            }
        }
        
        // Check issuer for self-signed or internal CA
        if let Some(issuer) = cert_info.get("Issuer") {
            if issuer.contains("Self-Signed")
                || issuer.contains("Internal")
                || issuer.contains("Development")
            {
                findings.push(format!("Certificate issued by potentially internal CA: {}", issuer));
            }
        }
        
        findings
    }

    /// Detect DNS rebinding vulnerabilities in origin discovery
    pub fn check_dns_rebinding_risk(&self, domain: &str, ip: &str) -> Option<String> {
        // Check if IP is in a private range (potential rebinding target)
        if ip.starts_with("10.") 
            || ip.starts_with("192.168.")
            || ip.starts_with("172.16.")
            || ip.starts_with("172.17.")
            || ip.starts_with("172.18.")
            || ip.starts_with("172.19.")
            || ip.starts_with("172.2")
            || ip.starts_with("172.30.")
            || ip.starts_with("172.31.")
            || ip == "127.0.0.1"
        {
            return Some(format!(
                "Domain {} resolves to private IP {} - potential DNS rebinding target",
                domain, ip
            ));
        }
        
        None
    }
}

#[async_trait::async_trait]
impl CheckModule for OriginDiscoveryChecker {
    fn name(&self) -> &'static str {
        "origin_discovery"
    }

    fn description(&self) -> &'static str {
        "Identifies origin server IPs using DNS history, certificate analysis, and header correlation"
    }

    async fn scan(&self, target: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        // Parse target domain
        let domain = target.trim_start_matches("https://").trim_start_matches("http://");
        
        // Generate origin probe suggestions
        let probes = self.generate_origin_probes(domain);
        
        results.push(CheckResult {
            check_name: self.name(),
            severity: Severity::Info,
            finding: format!("Generated {} potential origin discovery probes", probes.len()),
            evidence: serde_json::json!({
                "domain": domain,
                "probes": probes,
                "techniques": [
                    "DNS history lookup",
                    "Certificate SAN analysis",
                    "Subdomain enumeration",
                    "Email header analysis",
                    "Passive DNS correlation",
                ]
            }),
            remediation: "Ensure origin server IP is not publicly accessible. \
                          Use firewall rules to only allow CDN IP ranges. \
                          Remove origin server references from certificates.".to_string(),
        });
        
        // Note: Full origin discovery would require actual DNS lookups and certificate fetching
        // which are beyond the scope of this module without network access
        
        results
    }

    fn supported_checks(&self) -> Vec<&'static str> {
        vec![
            "origin_discovery",
            "dns_history_analysis",
            "certificate_correlation",
            "header_leakage_detection",
            "cdn_provider_identification",
        ]
    }
}

impl Default for OriginDiscoveryChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdn_ip_ranges_defined() {
        assert!(!CDN_IP_RANGES.is_empty());
        assert!(CDN_IP_RANGES.iter().any(|(_, provider)| provider == &"Cloudflare"));
    }

    #[test]
    fn test_identify_cdn_provider_cloudflare() {
        let checker = OriginDiscoveryChecker::new();
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "12345".to_string());
        
        assert_eq!(checker.identify_cdn_provider(&headers), Some("Cloudflare"));
    }

    #[test]
    fn test_is_likely_ip() {
        let checker = OriginDiscoveryChecker::new();
        assert!(checker.is_likely_ip("192.168.1.1"));
        assert!(checker.is_likely_ip("10.0.0.1"));
        assert!(!checker.is_likely_ip("example.com"));
        assert!(!checker.is_likely_ip("not-an-ip"));
    }

    #[test]
    fn test_generate_origin_probes() {
        let checker = OriginDiscoveryChecker::new();
        let probes = checker.generate_origin_probes("example.com");
        
        assert!(probes.contains(&"origin.example.com".to_string()));
        assert!(probes.contains(&"backend.example.com".to_string()));
        assert!(probes.contains(&"example.com".to_string()));
    }
}
