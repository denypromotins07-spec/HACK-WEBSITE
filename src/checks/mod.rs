//! Vulnerability Checks Module
//! 
//! Exports the module framework and integrates with the global scanner lifecycle.
//! Provides registration macros and convenience functions for check management.

pub mod module;
pub mod metadata;

pub use module::{
    VulnerabilityModule,
    CheckContext,
    CheckResult,
    CheckAssignment,
    CheckChannel,
    ModuleRegistry,
    ModuleError,
    ResourceUsage,
};

pub use metadata::{
    CheckId,
    CheckMetadata,
    CheckCategory,
    Severity,
    ResourceBudget,
};

use std::sync::Arc;
use once_cell::sync::OnceCell;
use tokio::sync::RwLock;

/// Global module registry singleton
static MODULE_REGISTRY: OnceCell<Arc<RwLock<ModuleRegistry>>> = OnceCell::new();

/// Get or initialize the global module registry
pub fn get_registry() -> Arc<RwLock<ModuleRegistry>> {
    MODULE_REGISTRY
        .get_or_init(|| Arc::new(RwLock::new(ModuleRegistry::new())))
        .clone()
}

/// Initialize the global registry with pre-registered modules
pub async fn init_registry(registry: ModuleRegistry) {
    let _ = MODULE_REGISTRY.set(Arc::new(RwLock::new(registry)));
}

/// Register a module with the global registry
pub async fn register_module<M: VulnerabilityModule + 'static>(module: M) -> usize {
    let registry = get_registry();
    let mut reg = registry.write().await;
    reg.register(module)
}

/// Get all registered modules sorted by priority
pub async fn get_prioritized_modules() -> Vec<Arc<dyn VulnerabilityModule>> {
    let registry = get_registry();
    let reg = registry.read().await;
    reg.get_prioritized().into_iter().cloned().collect()
}

/// Get total number of registered checks
pub async fn get_check_count() -> usize {
    let registry = get_registry();
    let reg = registry.read().await;
    reg.len()
}

/// Macro to simplify vulnerability module definition
#[macro_export]
macro_rules! define_vuln_module {
    (
        $name:ident,
        id = $id:expr,
        name = $display_name:expr,
        description = $desc:expr,
        severity = $severity:expr,
        category = $category:expr,
        $(priority = $priority:expr,)?
        $(dependencies = [$($dep:expr),*],)?
        $(god_mode = $god_mode:expr,)?
    ) => {
        pub struct $name;
        
        #[async_trait::async_trait]
        impl $crate::checks::VulnerabilityModule for $name {
            async fn init(&mut self) -> Result<(), $crate::checks::ModuleError> {
                Ok(())
            }
            
            fn metadata(&self) -> &$crate::checks::CheckMetadata {
                static METADATA: std::sync::OnceLock<$crate::checks::CheckMetadata> = std::sync::OnceLock::new();
                METADATA.get_or_init(|| {
                    $crate::checks::CheckMetadata::new(
                        $id,
                        $display_name,
                        $desc,
                        $severity,
                        $category,
                    )
                    $(.with_god_mode($god_mode))?
                })
            }
            
            fn should_run(&self, ctx: &$crate::checks::CheckContext) -> bool {
                if self.metadata().requires_god_mode && !ctx.god_mode {
                    return false;
                }
                true
            }
            
            async fn run(&self, ctx: $crate::checks::CheckContext) -> Result<$crate::checks::CheckResult, $crate::checks::ModuleError> {
                // Implementation goes here
                Ok($crate::checks::CheckResult {
                    findings: vec![],
                    executed: true,
                    timed_out: false,
                    resource_usage: $crate::checks::ResourceUsage::default(),
                })
            }
            
            $(
                fn priority(&self) -> u16 {
                    $priority
                }
            )?
            
            $(
                fn dependencies(&self) -> &[&str] {
                    &[$($dep),*]
                }
            )?
        }
    };
}

/// Convenience function to create a batch of check contexts for swarm distribution
pub fn create_check_batch(
    module_ids: Vec<usize>,
    target_url: String,
    surface_map: Arc<crate::surface::SurfaceMap>,
    payloads: Arc<crate::payloads::PayloadRegistry>,
    analysis_cache: Arc<crate::analysis::AnalysisCache>,
    god_mode: bool,
) -> Vec<CheckContext> {
    module_ids
        .into_iter()
        .enumerate()
        .map(|(idx, _)| CheckContext {
            target_url: target_url.clone(),
            surface_map: surface_map.clone(),
            payloads: payloads.clone(),
            analysis_cache: analysis_cache.clone(),
            budget: ResourceBudget::default(),
            god_mode,
            agent_id: idx as u16,
        })
        .collect()
}

/// Lifecycle hook called when scanner starts
pub async fn on_scanner_start() -> Result<(), ModuleError> {
    let registry = get_registry();
    let reg = registry.read().await;
    
    // Initialize all registered modules
    for module in reg.get_prioritized() {
        // Clone Arc to call init on a mutable copy
        // In practice, modules should be initialized before registration
        tracing::debug!("Module {} ready", module.metadata().id.as_str());
    }
    
    tracing::info!("Scanner initialized with {} vulnerability checks", reg.len());
    Ok(())
}

/// Lifecycle hook called when scanner shuts down
pub async fn on_scanner_shutdown() {
    tracing::info!("Scanner shutdown complete");
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
    
    #[test]
    fn test_severity_scores() {
        assert_eq!(Severity::Info.score(), 0);
        assert_eq!(Severity::Low.score(), 25);
        assert_eq!(Severity::Medium.score(), 50);
        assert_eq!(Severity::High.score(), 75);
        assert_eq!(Severity::Critical.score(), 100);
    }
    
    #[test]
    fn test_resource_budget_defaults() {
        let budget = ResourceBudget::default();
        assert!(budget.max_memory_bytes > 0);
        assert!(budget.max_requests > 0);
        assert!(budget.max_duration_ms > 0);
    }
    
    #[test]
    fn test_safe_vs_advanced_budget() {
        let safe = ResourceBudget::safe();
        let advanced = ResourceBudget::advanced();
        
        assert!(safe.max_cpu_ms < advanced.max_cpu_ms);
        assert!(safe.max_memory_bytes < advanced.max_memory_bytes);
        assert!(safe.max_requests < advanced.max_requests);
    }
}
