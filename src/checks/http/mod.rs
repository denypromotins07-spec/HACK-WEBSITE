//! HTTP Protocol Checks Module Registry
//! 
//! Registers all HTTP protocol vulnerability modules with the orchestrator
//! and exports metadata for check scheduling and execution.

use crate::checks::module::{CheckModule, CheckMetadata};
use crate::orchestrator::scheduler::CheckScheduler;

// Import all HTTP check modules
use super::smuggling_cl_te::ClTeSmugglingCheck;
use super::smuggling_te_cl::TeClSmugglingCheck;
use super::smuggling_te_te::TeTeSmugglingCheck;
use super::h2c_smuggling::H2cSmugglingCheck;
use super::h2_downgrade::H2DowngradeCheck;
use super::absolute_uri::AbsoluteUriCheck;
use super::host_header::HostHeaderCheck;
use super::response_splitting::ResponseSplittingCheck;
use super::connection_state::ConnectionStateCheck;
use super::websocket_tunnel::WebSocketTunnelCheck;
use super::proxy_route_anomaly::ProxyRouteAnomalyCheck;
use super::parser_diff::ParserDiffCheck;

/// HTTP Protocol Check Registry
/// 
/// Central registration point for all HTTP protocol vulnerability modules.
/// Provides metadata enumeration and module instantiation.
pub struct HttpCheckRegistry {
    modules: Vec<Box<dyn CheckModule + Send + Sync>>,
}

impl HttpCheckRegistry {
    /// Create new HTTP check registry with all modules
    pub fn new() -> Self {
        let mut modules: Vec<Box<dyn CheckModule + Send + Sync>> = Vec::new();

        // Chapter 1: Classic HTTP Request Smuggling
        modules.push(Box::new(ClTeSmugglingCheck::new()));
        modules.push(Box::new(TeClSmugglingCheck::new()));
        modules.push(Box::new(TeTeSmugglingCheck::new()));

        // Chapter 2: HTTP/2 and H2C Smuggling
        modules.push(Box::new(H2cSmugglingCheck::new()));
        modules.push(Box::new(H2DowngradeCheck::new()));
        modules.push(Box::new(AbsoluteUriCheck::new()));

        // Chapter 3: Host Header and Response Manipulation
        modules.push(Box::new(HostHeaderCheck::new()));
        modules.push(Box::new(ResponseSplittingCheck::new()));
        modules.push(Box::new(ConnectionStateCheck::new()));

        // Chapter 4: WebSocket and Proxy Bypass Mechanics
        modules.push(Box::new(WebSocketTunnelCheck::new()));
        modules.push(Box::new(ProxyRouteAnomalyCheck::new()));
        modules.push(Box::new(ParserDiffCheck::new()));

        Self { modules }
    }

    /// Get all registered modules
    pub fn get_modules(&self) -> &[Box<dyn CheckModule + Send + Sync>] {
        &self.modules
    }

    /// Get module by ID
    pub fn get_module_by_id(&self, id: &str) -> Option<&dyn CheckModule> {
        self.modules.iter()
            .find(|m| m.metadata().id == id)
            .map(|m| m.as_ref())
    }

    /// Get all module metadata
    pub fn get_all_metadata(&self) -> Vec<&CheckMetadata> {
        self.modules.iter()
            .map(|m| m.metadata())
            .collect()
    }

    /// Register modules with scheduler
    pub async fn register_with_scheduler(&self, scheduler: &mut CheckScheduler) {
        for module in &self.modules {
            scheduler.register_check(module.metadata().id.clone(), module.as_ref()).await;
        }
    }

    /// Get modules by severity
    pub fn get_modules_by_severity(&self, severity: crate::findings::severity::Severity) -> Vec<&dyn CheckModule> {
        self.modules.iter()
            .filter(|m| m.metadata().severity == severity)
            .map(|m| m.as_ref())
            .collect()
    }

    /// Get safe checks (non-intrusive, run first)
    pub fn get_safe_checks(&self) -> Vec<&dyn CheckModule> {
        // Safe checks are those with lower request budgets and non-intrusive payloads
        self.modules.iter()
            .filter(|m| {
                m.metadata().resource_budget.max_requests <= 5 &&
                !m.metadata().name.contains("injection") &&
                !m.metadata().name.contains("poisoning")
            })
            .map(|m| m.as_ref())
            .collect()
    }

    /// Get advanced checks (require god-mode or specific conditions)
    pub fn get_advanced_checks(&self) -> Vec<&dyn CheckModule> {
        self.modules.iter()
            .filter(|m| {
                m.metadata().resource_budget.max_requests > 8 ||
                m.metadata().severity == crate::findings::severity::Severity::Critical
            })
            .map(|m| m.as_ref())
            .collect()
    }

    /// Get total number of registered modules
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Export module summary for reporting
    pub fn export_summary(&self) -> ModuleSummary {
        let metadata: Vec<&CheckMetadata> = self.get_all_metadata();
        
        let critical_count = metadata.iter()
            .filter(|m| m.severity == crate::findings::severity::Severity::Critical)
            .count();
        let high_count = metadata.iter()
            .filter(|m| m.severity == crate::findings::severity::Severity::High)
            .count();
        let medium_count = metadata.iter()
            .filter(|m| m.severity == crate::findings::severity::Severity::Medium)
            .count();
        let low_count = metadata.iter()
            .filter(|m| m.severity == crate::findings::severity::Severity::Low)
            .count();

        let total_max_requests: u32 = metadata.iter()
            .map(|m| m.resource_budget.max_requests)
            .sum();

        ModuleSummary {
            total_modules: self.modules.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            total_max_requests,
            category: "HTTP Protocol".to_string(),
        }
    }
}

/// Summary of registered HTTP modules
#[derive(Debug, Clone)]
pub struct ModuleSummary {
    pub total_modules: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub total_max_requests: u32,
    pub category: String,
}

impl Default for HttpCheckRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = HttpCheckRegistry::new();
        assert!(registry.module_count() >= 12);
    }

    #[test]
    fn test_get_module_by_id() {
        let registry = HttpCheckRegistry::new();
        
        let module = registry.get_module_by_id("HTTP-001");
        assert!(module.is_some());
        assert_eq!(module.unwrap().metadata().id, "HTTP-001");

        let module = registry.get_module_by_id("HTTP-007");
        assert!(module.is_some());
    }

    #[test]
    fn test_get_all_metadata() {
        let registry = HttpCheckRegistry::new();
        let metadata = registry.get_all_metadata();
        
        assert_eq!(metadata.len(), registry.module_count());
        
        // Verify all IDs are unique
        let ids: Vec<&String> = metadata.iter().map(|m| &m.id).collect();
        let unique_ids: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique_ids.len());
    }

    #[test]
    fn test_export_summary() {
        let registry = HttpCheckRegistry::new();
        let summary = registry.export_summary();

        assert_eq!(summary.total_modules, registry.module_count());
        assert_eq!(
            summary.critical_count + summary.high_count + summary.medium_count + summary.low_count,
            summary.total_modules
        );
        assert_eq!(summary.category, "HTTP Protocol");
    }

    #[test]
    fn test_safe_checks() {
        let registry = HttpCheckRegistry::new();
        let safe = registry.get_safe_checks();
        
        // Should have some safe checks
        assert!(!safe.is_empty());
        
        // All should have low request budgets
        for check in &safe {
            assert!(check.metadata().resource_budget.max_requests <= 5);
        }
    }

    #[test]
    fn test_advanced_checks() {
        let registry = HttpCheckRegistry::new();
        let advanced = registry.get_advanced_checks();
        
        // Should have some advanced checks
        assert!(!advanced.is_empty());
    }
}
