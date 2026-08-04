//! SSRF/LFI Module Registration
//!
//! Registers SSRF/LFI modules with orchestrator, exports metadata,
//! and wires learning caches.

pub mod ssrf {
    pub mod basic;
    pub mod blind;
    pub mod payloads;
    pub mod cloud_metadata;
    pub mod dns_rebinding;
    pub mod internal_services;
}

pub mod lfi {
    pub mod basic;
    pub mod wrappers;
}

pub mod rfi {
    pub mod inclusion;
}

pub mod traversal {
    pub mod basic;
    pub mod normalization;
    pub mod nginx_alias;
}

use crate::checks::{
    VulnerabilityModule, ModuleRegistry, CheckMetadata, CheckCategory, Severity, ResourceBudget,
};
use crate::learning::ssrf_lfi_cache::get_global_cache;
use std::sync::Arc;

/// Register all SSRF/LFI modules with the registry
pub fn register_modules(registry: &mut ModuleRegistry) {
    // SSRF modules
    registry.register(crate::checks::ssrf::basic::BasicSsrfModule::new(
        Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
        Arc::new(crate::analysis::AnalysisContext::new()),
        Arc::new(crate::payload::PayloadRegistry::new()),
    ));
    
    registry.register(crate::checks::ssrf::blind::BlindSsrfModule::new(
        Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
        Arc::new(crate::analysis::AnalysisContext::new()),
        Arc::new(crate::payload::PayloadRegistry::new()),
    ));
    
    registry.register(crate::checks::ssrf::cloud_metadata::CloudMetadataModule::new(
        Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
        Arc::new(crate::analysis::AnalysisContext::new()),
        Arc::new(crate::payload::PayloadRegistry::new()),
    ));
    
    registry.register(crate::checks::ssrf::dns_rebinding::DnsRebindingModule::new(
        Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
        Arc::new(crate::analysis::AnalysisContext::new()),
        Arc::new(crate::payload::PayloadRegistry::new()),
    ));
    
    registry.register(crate::checks::ssrf::internal_services::InternalServicesModule::new(
        Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
        Arc::new(crate::analysis::AnalysisContext::new()),
        Arc::new(crate::payload::PayloadRegistry::new()),
    ));
    
    // LFI modules
    registry.register(crate::checks::lfi::basic::BasicLfiModule::new(
        Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
        Arc::new(crate::analysis::AnalysisContext::new()),
        Arc::new(crate::payload::PayloadRegistry::new()),
    ));
    
    registry.register(crate::checks::lfi::wrappers::PhpWrappersModule::new(
        Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
        Arc::new(crate::analysis::AnalysisContext::new()),
        Arc::new(crate::payload::PayloadRegistry::new()),
    ));
    
    // RFI module
    registry.register(crate::checks::rfi::inclusion::RfiInclusionModule::new(
        Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
        Arc::new(crate::analysis::AnalysisContext::new()),
        Arc::new(crate::payload::PayloadRegistry::new()),
    ));
    
    // Traversal modules
    registry.register(crate::checks::traversal::basic::BasicTraversalModule::new(
        Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
        Arc::new(crate::analysis::AnalysisContext::new()),
        Arc::new(crate::payload::PayloadRegistry::new()),
    ));
    
    registry.register(crate::checks::traversal::normalization::NormalizationBypassModule::new(
        Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
        Arc::new(crate::analysis::AnalysisContext::new()),
        Arc::new(crate::payload::PayloadRegistry::new()),
    ));
    
    registry.register(crate::checks::traversal::nginx_alias::NginxAliasModule::new(
        Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
        Arc::new(crate::analysis::AnalysisContext::new()),
        Arc::new(crate::payload::PayloadRegistry::new()),
    ));
}

/// Get all SSRF/LFI module metadata
pub fn get_module_metadata() -> Vec<CheckMetadata> {
    vec![
        // SSRF modules
        crate::checks::ssrf::basic::BasicSsrfModule::new(
            Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
            Arc::new(crate::analysis::AnalysisContext::new()),
            Arc::new(crate::payload::PayloadRegistry::new()),
        ).metadata().clone(),
        crate::checks::ssrf::blind::BlindSsrfModule::new(
            Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
            Arc::new(crate::analysis::AnalysisContext::new()),
            Arc::new(crate::payload::PayloadRegistry::new()),
        ).metadata().clone(),
        crate::checks::ssrf::cloud_metadata::CloudMetadataModule::new(
            Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
            Arc::new(crate::analysis::AnalysisContext::new()),
            Arc::new(crate::payload::PayloadRegistry::new()),
        ).metadata().clone(),
        crate::checks::ssrf::dns_rebinding::DnsRebindingModule::new(
            Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
            Arc::new(crate::analysis::AnalysisContext::new()),
            Arc::new(crate::payload::PayloadRegistry::new()),
        ).metadata().clone(),
        crate::checks::ssrf::internal_services::InternalServicesModule::new(
            Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
            Arc::new(crate::analysis::AnalysisContext::new()),
            Arc::new(crate::payload::PayloadRegistry::new()),
        ).metadata().clone(),
        
        // LFI modules
        crate::checks::lfi::basic::BasicLfiModule::new(
            Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
            Arc::new(crate::analysis::AnalysisContext::new()),
            Arc::new(crate::payload::PayloadRegistry::new()),
        ).metadata().clone(),
        crate::checks::lfi::wrappers::PhpWrappersModule::new(
            Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
            Arc::new(crate::analysis::AnalysisContext::new()),
            Arc::new(crate::payload::PayloadRegistry::new()),
        ).metadata().clone(),
        
        // RFI module
        crate::checks::rfi::inclusion::RfiInclusionModule::new(
            Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
            Arc::new(crate::analysis::AnalysisContext::new()),
            Arc::new(crate::payload::PayloadRegistry::new()),
        ).metadata().clone(),
        
        // Traversal modules
        crate::checks::traversal::basic::BasicTraversalModule::new(
            Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
            Arc::new(crate::analysis::AnalysisContext::new()),
            Arc::new(crate::payload::PayloadRegistry::new()),
        ).metadata().clone(),
        crate::checks::traversal::normalization::NormalizationBypassModule::new(
            Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
            Arc::new(crate::analysis::AnalysisContext::new()),
            Arc::new(crate::payload::PayloadRegistry::new()),
        ).metadata().clone(),
        crate::checks::traversal::nginx_alias::NginxAliasModule::new(
            Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap()),
            Arc::new(crate::analysis::AnalysisContext::new()),
            Arc::new(crate::payload::PayloadRegistry::new()),
        ).metadata().clone(),
    ]
}

/// Get SSRF module IDs
pub fn get_ssrf_module_ids() -> Vec<&'static str> {
    vec![
        "basic_ssrf",
        "blind_ssrf",
        "cloud_metadata_ssrf",
        "dns_rebinding_ssrf",
        "internal_services_ssrf",
    ]
}

/// Get LFI module IDs
pub fn get_lfi_module_ids() -> Vec<&'static str> {
    vec![
        "basic_lfi",
        "php_wrappers_lfi",
    ]
}

/// Get RFI module IDs
pub fn get_rfi_module_ids() -> Vec<&'static str> {
    vec![
        "rfi_inclusion",
    ]
}

/// Get Traversal module IDs
pub fn get_traversal_module_ids() -> Vec<&'static str> {
    vec![
        "basic_traversal",
        "normalization_bypass",
        "nginx_alias_traversal",
    ]
}

/// Get all SSRF/LFI module IDs
pub fn get_all_module_ids() -> Vec<&'static str> {
    let mut ids = Vec::new();
    ids.extend(get_ssrf_module_ids());
    ids.extend(get_lfi_module_ids());
    ids.extend(get_rfi_module_ids());
    ids.extend(get_traversal_module_ids());
    ids
}

/// Initialize SSRF/LFI learning cache
pub fn init_learning_cache() -> Arc<crate::learning::ssrf_lfi_cache::SsrfLfiCache> {
    get_global_cache()
}

/// Get learning cache instance
pub fn get_learning_cache() -> Arc<crate::learning::ssrf_lfi_cache::SsrfLfiCache> {
    get_global_cache()
}

/// Module dependency graph
pub fn get_dependencies() -> HashMap<&'static str, Vec<&'static str>> {
    let mut deps = HashMap::new();
    
    // SSRF dependencies
    deps.insert("basic_ssrf", vec![]);
    deps.insert("blind_ssrf", vec!["basic_ssrf"]);
    deps.insert("cloud_metadata_ssrf", vec!["basic_ssrf"]);
    deps.insert("dns_rebinding_ssrf", vec!["basic_ssrf", "blind_ssrf"]);
    deps.insert("internal_services_ssrf", vec!["basic_ssrf"]);
    
    // LFI dependencies
    deps.insert("basic_lfi", vec![]);
    deps.insert("php_wrappers_lfi", vec!["basic_lfi"]);
    
    // RFI dependencies
    deps.insert("rfi_inclusion", vec!["basic_lfi", "php_wrappers_lfi"]);
    
    // Traversal dependencies
    deps.insert("basic_traversal", vec![]);
    deps.insert("normalization_bypass", vec!["basic_traversal"]);
    deps.insert("nginx_alias_traversal", vec!["basic_traversal", "normalization_bypass"]);
    
    deps
}

/// Module priority ordering (lower = higher priority)
pub fn get_priorities() -> HashMap<&'static str, u16> {
    let mut priorities = HashMap::new();
    
    priorities.insert("basic_ssrf", 10);
    priorities.insert("basic_lfi", 15);
    priorities.insert("basic_traversal", 12);
    priorities.insert("cloud_metadata_ssrf", 20);
    priorities.insert("internal_services_ssrf", 30);
    priorities.insert("php_wrappers_lfi", 25);
    priorities.insert("rfi_inclusion", 35);
    priorities.insert("dns_rebinding_ssrf", 40);
    priorities.insert("normalization_bypass", 45);
    priorities.insert("nginx_alias_traversal", 50);
    priorities.insert("blind_ssrf", 50);
    
    priorities
}

/// Module categories
pub fn get_categories() -> HashMap<&'static str, CheckCategory> {
    let mut categories = HashMap::new();
    
    categories.insert("basic_ssrf", CheckCategory::ServerSideRequestForgery);
    categories.insert("blind_ssrf", CheckCategory::ServerSideRequestForgery);
    categories.insert("cloud_metadata_ssrf", CheckCategory::ServerSideRequestForgery);
    categories.insert("dns_rebinding_ssrf", CheckCategory::ServerSideRequestForgery);
    categories.insert("internal_services_ssrf", CheckCategory::ServerSideRequestForgery);
    categories.insert("basic_lfi", CheckCategory::PathTraversal);
    categories.insert("php_wrappers_lfi", CheckCategory::PathTraversal);
    categories.insert("rfi_inclusion", CheckCategory::PathTraversal);
    categories.insert("basic_traversal", CheckCategory::PathTraversal);
    categories.insert("normalization_bypass", CheckCategory::PathTraversal);
    categories.insert("nginx_alias_traversal", CheckCategory::PathTraversal);
    
    categories
}

/// Module severity levels
pub fn get_severities() -> HashMap<&'static str, Severity> {
    let mut severities = HashMap::new();
    
    severities.insert("basic_ssrf", Severity::High);
    severities.insert("blind_ssrf", Severity::High);
    severities.insert("cloud_metadata_ssrf", Severity::Critical);
    severities.insert("dns_rebinding_ssrf", Severity::High);
    severities.insert("internal_services_ssrf", Severity::Critical);
    severities.insert("basic_lfi", Severity::High);
    severities.insert("php_wrappers_lfi", Severity::Critical);
    severities.insert("rfi_inclusion", Severity::Critical);
    severities.insert("basic_traversal", Severity::High);
    severities.insert("normalization_bypass", Severity::High);
    severities.insert("nginx_alias_traversal", Severity::High);
    
    severities
}

/// Module god-mode requirements
pub fn get_god_mode_requirements() -> HashMap<&'static str, bool> {
    let mut god_mode = HashMap::new();
    
    god_mode.insert("basic_ssrf", false);
    god_mode.insert("blind_ssrf", true);
    god_mode.insert("cloud_metadata_ssrf", true);
    god_mode.insert("dns_rebinding_ssrf", true);
    god_mode.insert("internal_services_ssrf", true);
    god_mode.insert("basic_lfi", false);
    god_mode.insert("php_wrappers_lfi", true);
    god_mode.insert("rfi_inclusion", true);
    god_mode.insert("basic_traversal", false);
    god_mode.insert("normalization_bypass", true);
    god_mode.insert("nginx_alias_traversal", true);
    
    god_mode
}

/// Module budget requirements
pub fn get_budgets() -> HashMap<&'static str, ResourceBudget> {
    let mut budgets = HashMap::new();
    
    budgets.insert("basic_ssrf", ResourceBudget::safe());
    budgets.insert("blind_ssrf", ResourceBudget::advanced());
    budgets.insert("cloud_metadata_ssrf", ResourceBudget::advanced());
    budgets.insert("dns_rebinding_ssrf", ResourceBudget::advanced());
    budgets.insert("internal_services_ssrf", ResourceBudget::advanced());
    budgets.insert("basic_lfi", ResourceBudget::safe());
    budgets.insert("php_wrappers_lfi", ResourceBudget::advanced());
    budgets.insert("rfi_inclusion", ResourceBudget::advanced());
    budgets.insert("basic_traversal", ResourceBudget::safe());
    budgets.insert("normalization_bypass", ResourceBudget::advanced());
    budgets.insert("nginx_alias_traversal", ResourceBudget::advanced());
    
    budgets
}

use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::ModuleRegistry;

    #[test]
    fn test_get_all_module_ids() {
        let ids = get_all_module_ids();
        assert_eq!(ids.len(), 12);
        assert!(ids.contains(&"basic_ssrf"));
        assert!(ids.contains(&"blind_ssrf"));
        assert!(ids.contains(&"cloud_metadata_ssrf"));
        assert!(ids.contains(&"dns_rebinding_ssrf"));
        assert!(ids.contains(&"internal_services_ssrf"));
        assert!(ids.contains(&"basic_lfi"));
        assert!(ids.contains(&"php_wrappers_lfi"));
        assert!(ids.contains(&"rfi_inclusion"));
        assert!(ids.contains(&"basic_traversal"));
        assert!(ids.contains(&"normalization_bypass"));
        assert!(ids.contains(&"nginx_alias_traversal"));
    }

    #[test]
    fn test_get_dependencies() {
        let deps = get_dependencies();
        
        assert_eq!(deps["basic_ssrf"], vec![]);
        assert_eq!(deps["blind_ssrf"], vec!["basic_ssrf"]);
        assert_eq!(deps["cloud_metadata_ssrf"], vec!["basic_ssrf"]);
        assert_eq!(deps["dns_rebinding_ssrf"], vec!["basic_ssrf", "blind_ssrf"]);
        assert_eq!(deps["internal_services_ssrf"], vec!["basic_ssrf"]);
        assert_eq!(deps["basic_lfi"], vec![]);
        assert_eq!(deps["php_wrappers_lfi"], vec!["basic_lfi"]);
        assert_eq!(deps["rfi_inclusion"], vec!["basic_lfi", "php_wrappers_lfi"]);
        assert_eq!(deps["basic_traversal"], vec![]);
        assert_eq!(deps["normalization_bypass"], vec!["basic_traversal"]);
        assert_eq!(deps["nginx_alias_traversal"], vec!["basic_traversal", "normalization_bypass"]);
    }

    #[test]
    fn test_get_priorities() {
        let priorities = get_priorities();
        
        // Safe checks should have higher priority (lower number)
        assert!(priorities["basic_ssrf"] < priorities["blind_ssrf"]);
        assert!(priorities["basic_lfi"] < priorities["php_wrappers_lfi"]);
        assert!(priorities["basic_traversal"] < priorities["normalization_bypass"]);
        
        // Critical checks should have reasonable priorities
        assert!(priorities["cloud_metadata_ssrf"] < priorities["dns_rebinding_ssrf"]);
    }

    #[test]
    fn test_get_categories() {
        let categories = get_categories();
        
        assert_eq!(categories["basic_ssrf"], CheckCategory::ServerSideRequestForgery);
        assert_eq!(categories["cloud_metadata_ssrf"], CheckCategory::ServerSideRequestForgery);
        assert_eq!(categories["basic_lfi"], CheckCategory::PathTraversal);
        assert_eq!(categories["php_wrappers_lfi"], CheckCategory::PathTraversal);
        assert_eq!(categories["rfi_inclusion"], CheckCategory::PathTraversal);
        assert_eq!(categories["basic_traversal"], CheckCategory::PathTraversal);
        assert_eq!(categories["normalization_bypass"], CheckCategory::PathTraversal);
        assert_eq!(categories["nginx_alias_traversal"], CheckCategory::PathTraversal);
    }

    #[test]
    fn test_get_severities() {
        let severities = get_severities();
        
        assert_eq!(severities["basic_ssrf"], Severity::High);
        assert_eq!(severities["cloud_metadata_ssrf"], Severity::Critical);
        assert_eq!(severities["internal_services_ssrf"], Severity::Critical);
        assert_eq!(severities["php_wrappers_lfi"], Severity::Critical);
        assert_eq!(severities["rfi_inclusion"], Severity::Critical);
    }

    #[test]
    fn test_get_god_mode_requirements() {
        let god_mode = get_god_mode_requirements();
        
        assert_eq!(god_mode["basic_ssrf"], false);
        assert_eq!(god_mode["basic_lfi"], false);
        assert_eq!(god_mode["basic_traversal"], false);
        assert_eq!(god_mode["blind_ssrf"], true);
        assert_eq!(god_mode["cloud_metadata_ssrf"], true);
        assert_eq!(god_mode["php_wrappers_lfi"], true);
        assert_eq!(god_mode["rfi_inclusion"], true);
    }

    #[test]
    fn test_get_budgets() {
        let budgets = get_budgets();
        
        assert_eq!(budgets["basic_ssrf"].max_requests, 10);
        assert_eq!(budgets["blind_ssrf"].max_requests, 200);
        assert_eq!(budgets["basic_lfi"].max_requests, 10);
        assert_eq!(budgets["php_wrappers_lfi"].max_requests, 200);
    }

    #[test]
    fn test_init_learning_cache() {
        let cache = init_learning_cache();
        let stats = cache.get_stats();
        assert_eq!(stats.total_ssrf_payloads, 0);
        assert_eq!(stats.total_lfi_payloads, 0);
    }
}