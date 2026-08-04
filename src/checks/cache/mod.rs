//! Cache/CDN/Proxy Module Registration
//! Registers cache/CDN/proxy modules with orchestrator and exports metadata.

// Cache checks
pub mod deception;
pub mod path_confusion;
pub mod cache_key;
pub mod poisoning;
pub mod unkeyed_headers;
pub mod vary_analysis;

// CDN checks
pub mod origin_discovery;
pub mod shield_bypass;
pub mod provider_quirks;

// Proxy checks
pub mod reverse_misconfig;
pub mod webhook_ssrf;
pub mod internal_route;

use crate::checks::module::{CheckModule, CheckRegistry};
use crate::http_client::HttpClient;

/// Register all cache/CDN/proxy check modules with the orchestrator
pub fn register_all_modules(registry: &mut CheckRegistry, http_client: HttpClient) {
    // Chapter 1: Web Cache Deception Detection
    registry.register(Box::new(deception::CacheDeceptionChecker::new(
        http_client.clone(),
        Default::default(),
    )));
    
    registry.register(Box::new(path_confusion::PathConfusionChecker::new(
        http_client.clone(),
    )));
    
    registry.register(Box::new(cache_key::CacheKeyChecker::new(
        http_client.clone(),
    )));
    
    // Chapter 2: Web Cache Poisoning and Unkeyed Inputs
    registry.register(Box::new(poisoning::CachePoisoningChecker::new(
        http_client.clone(),
    )));
    
    registry.register(Box::new(unkeyed_headers::UnkeyedHeadersChecker::new(
        http_client.clone(),
    )));
    
    registry.register(Box::new(vary_analysis::VaryAnalysisChecker::new(
        http_client.clone(),
    )));
    
    // Chapter 3: CDN Shield Bypass and Origin Discovery
    registry.register(Box::new(origin_discovery::OriginDiscoveryChecker::new()));
    
    registry.register(Box::new(shield_bypass::ShieldBypassChecker::new(
        http_client.clone(),
    )));
    
    registry.register(Box::new(provider_quirks::ProviderQuirksChecker::new(
        http_client.clone(),
    )));
    
    // Chapter 4: Reverse Proxy Misconfiguration and Webhook Abuse
    registry.register(Box::new(reverse_misconfig::ReverseMisconfigChecker::new(
        http_client.clone(),
    )));
    
    registry.register(Box::new(webhook_ssrf::WebhookSSRFChecker::new(
        http_client.clone(),
        None, // OOB callback URL would be provided by configuration
    )));
    
    registry.register(Box::new(internal_route::InternalRouteChecker::new(
        http_client.clone(),
    )));
}

/// Get metadata about all registered cache/CDN/proxy modules
pub fn get_module_metadata() -> Vec<ModuleMetadata> {
    vec![
        ModuleMetadata {
            name: "cache_deception",
            chapter: 1,
            description: "Detects Web Cache Deception by appending static extensions to authenticated pages",
            checks: vec!["cache_deception", "path_extension_abuse", "authenticated_content_caching"],
        },
        ModuleMetadata {
            name: "path_confusion",
            chapter: 1,
            description: "Tests path confusion using .css/.js suffixes, semicolons, and encoded delimiters",
            checks: vec![
                "path_confusion",
                "semicolon_truncation",
                "encoded_delimiter_abuse",
                "null_byte_injection",
                "double_encoding",
            ],
        },
        ModuleMetadata {
            name: "cache_key_analysis",
            chapter: 1,
            description: "Identifies cache key formation using query, header, and cookie variation probes",
            checks: vec![
                "cache_key_analysis",
                "unkeyed_query_params",
                "unkeyed_headers",
                "unkeyed_cookies",
                "vary_header_analysis",
            ],
        },
        ModuleMetadata {
            name: "cache_poisoning",
            chapter: 2,
            description: "Detects cache poisoning via Host, X-Forwarded-Host, and unsafe redirect generators",
            checks: vec![
                "cache_poisoning",
                "host_header_injection",
                "x_forwarded_host_poisoning",
                "redirect_poisoning",
                "dynamic_content_caching",
            ],
        },
        ModuleMetadata {
            name: "unkeyed_headers",
            chapter: 2,
            description: "Detects unkeyed header exploitation using X-Forwarded-Scheme, X-Original-URL, and custom headers",
            checks: vec![
                "unkeyed_headers",
                "x_forwarded_scheme_abuse",
                "x_original_url_manipulation",
                "custom_header_exploitation",
                "vary_header_analysis",
            ],
        },
        ModuleMetadata {
            name: "vary_analysis",
            chapter: 2,
            description: "Analyzes Vary header handling and cache normalization inconsistencies",
            checks: vec![
                "vary_analysis",
                "vary_header_validation",
                "cache_normalization",
                "encoding_differentiation",
                "language_differentiation",
            ],
        },
        ModuleMetadata {
            name: "origin_discovery",
            chapter: 3,
            description: "Identifies likely origin IPs using DNS history placeholders and certificate correlation",
            checks: vec![
                "origin_discovery",
                "dns_history_analysis",
                "certificate_correlation",
                "header_leakage_detection",
                "cdn_provider_identification",
            ],
        },
        ModuleMetadata {
            name: "shield_bypass",
            chapter: 3,
            description: "Tests direct origin access with Host header manipulation and SNI mismatches",
            checks: vec![
                "cdn_shield_bypass",
                "host_header_manipulation",
                "sni_mismatch",
                "direct_ip_access",
                "port_variation",
            ],
        },
        ModuleMetadata {
            name: "provider_quirks",
            chapter: 3,
            description: "Implements provider-specific checks for Cloudflare, Akamai, Fastly, and CloudFront",
            checks: vec![
                "provider_detection",
                "cloudflare_quirks",
                "akamai_quirks",
                "fastly_quirks",
                "cloudfront_quirks",
            ],
        },
        ModuleMetadata {
            name: "reverse_misconfig",
            chapter: 4,
            description: "Detects reverse proxy path manipulation exposing admin consoles or internal routes",
            checks: vec![
                "reverse_proxy_misconfig",
                "admin_route_exposure",
                "header_path_manipulation",
                "path_normalization_bypass",
                "backend_discovery",
            ],
        },
        ModuleMetadata {
            name: "webhook_ssrf",
            chapter: 4,
            description: "Detects SSRF via webhook endpoints using OOB callbacks and metadata markers",
            checks: vec![
                "webhook_ssrf",
                "oob_callback_abuse",
                "cloud_metadata_access",
                "internal_network_probing",
                "url_parameter_ssrf",
            ],
        },
        ModuleMetadata {
            name: "internal_route",
            chapter: 4,
            description: "Probes routing anomalies via absolute URLs, Upgrade headers, and unexpected methods",
            checks: vec![
                "internal_route_probing",
                "unexpected_methods",
                "upgrade_manipulation",
                "absolute_url_ssrf",
                "routing_path_traversal",
            ],
        },
    ]
}

/// Metadata about a single module
#[derive(Debug, Clone)]
pub struct ModuleMetadata {
    pub name: &'static str,
    pub chapter: u8,
    pub description: &'static str,
    pub checks: Vec<&'static str>,
}

/// Summary of the cache/CDN/proxy module capabilities
pub fn get_capabilities_summary() -> String {
    let metadata = get_module_metadata();
    let total_checks: usize = metadata.iter().map(|m| m.checks.len()).sum();
    
    format!(
        "Cache/CDN/Proxy Module Suite\n\
         ==========================\n\
         Chapters: 5 (Cache Deception, Cache Poisoning, CDN Bypass, Proxy Misconfig, Evidence/Learning)\n\
         Modules: {}\n\
         Total Checks: {}\n\
         \n\
         Capabilities:\n\
         - Web Cache Deception Detection\n\
         - Path Confusion Testing\n\
         - Cache Key Analysis\n\
         - Cache Poisoning Detection\n\
         - Unkeyed Header Exploitation\n\
         - Vary Header Analysis\n\
         - Origin IP Discovery\n\
         - CDN Shield Bypass\n\
         - Provider-Specific Quirks (Cloudflare, Akamai, Fastly, CloudFront)\n\
         - Reverse Proxy Misconfiguration\n\
         - Webhook SSRF Detection\n\
         - Internal Route Probing",
        metadata.len(),
        total_checks,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_metadata_complete() {
        let metadata = get_module_metadata();
        
        // Should have 12 modules (3 per chapter x 4 chapters)
        assert_eq!(metadata.len(), 12);
        
        // All modules should have at least one check
        for module in &metadata {
            assert!(!module.checks.is_empty());
            assert!(module.chapter >= 1 && module.chapter <= 5);
        }
    }

    #[test]
    fn test_capabilities_summary() {
        let summary = get_capabilities_summary();
        
        assert!(summary.contains("Cache/CDN/Proxy"));
        assert!(summary.contains("Modules:"));
        assert!(summary.contains("Total Checks:"));
        assert!(summary.contains("Cloudflare"));
        assert!(summary.contains("Akamai"));
        assert!(summary.contains("Fastly"));
        assert!(summary.contains("CloudFront"));
    }
}
