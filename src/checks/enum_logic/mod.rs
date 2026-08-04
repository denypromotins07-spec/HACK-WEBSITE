//! Enumeration Logic Module Registration
//!
//! Registers enumeration and logic modules with the orchestrator and exports metadata.
//! Provides module discovery and execution coordination for Stage 19 checks.

use crate::checks::{VulnerabilityModule, CheckMetadata, CheckCategory, Severity};

// Import all enumeration and logic modules
use super::crypto::padding_oracle::PaddingOracleDetector;
use super::auth::session_fixation::SessionFixationDetector;
use super::auth::sso_saml::SamlSsoDetector;
use super::automation::rate_limit::RateLimitBypassDetector;
use super::automation::captcha::CaptchaBypassDetector;
use super::eval::server_side_eval::ServerSideEvalDetector;
use super::eval::ssi_injection::SsiInjectionDetector;
use super::enum::time_based::TimeBasedEnumDetector;
use super::infra::subdomain_takeover::SubdomainTakeoverDetector;
use super::framework::log4shell::Log4ShellDetector;

/// Maximum registered modules (bounded)
const MAX_REGISTERED_MODULES: usize = 32;

/// Module registry entry
#[derive(Debug, Clone)]
pub struct ModuleEntry {
    pub id: String,
    pub name: String,
    pub category: CheckCategory,
    pub severity: Severity,
    pub enabled: bool,
}

impl ModuleEntry {
    pub fn from_metadata(metadata: &CheckMetadata) -> Self {
        Self {
            id: metadata.id.clone(),
            name: metadata.name.clone(),
            category: metadata.category,
            severity: metadata.default_severity,
            enabled: true,
        }
    }
}

/// Bounded module registry
pub struct EnumLogicRegistry {
    entries: [Option<ModuleEntry>; MAX_REGISTERED_MODULES],
    count: usize,
}

impl EnumLogicRegistry {
    pub fn new() -> Self {
        Self {
            entries: [None; MAX_REGISTERED_MODULES],
            count: 0,
        }
    }

    pub fn register(&mut self, entry: ModuleEntry) -> bool {
        if self.count < MAX_REGISTERED_MODULES {
            self.entries[self.count] = Some(entry);
            self.count += 1;
            true
        } else {
            false
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &ModuleEntry> {
        self.entries[..self.count].iter().flatten()
    }

    pub fn get_enabled(&self) -> Vec<&ModuleEntry> {
        self.iter().filter(|e| e.enabled).collect()
    }

    pub fn get_by_category(&self, category: CheckCategory) -> Vec<&ModuleEntry> {
        self.iter()
            .filter(|e| e.category == category)
            .collect()
    }

    pub fn get_by_id(&self, id: &str) -> Option<&ModuleEntry> {
        self.iter().find(|e| e.id == id)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for EnumLogicRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Create and register all Stage 19 enumeration modules
pub fn create_enum_logic_registry() -> EnumLogicRegistry {
    let mut registry = EnumLogicRegistry::new();

    // Chapter 1: Cryptography & Authentication
    let padding_oracle = PaddingOracleDetector::new();
    registry.register(ModuleEntry::from_metadata(padding_oracle.metadata()));

    let session_fixation = SessionFixationDetector::new();
    registry.register(ModuleEntry::from_metadata(session_fixation.metadata()));

    let sso_saml = SamlSsoDetector::new();
    registry.register(ModuleEntry::from_metadata(sso_saml.metadata()));

    // Chapter 2: Rate Limiting & Automation Bypasses
    let rate_limit = RateLimitBypassDetector::new();
    registry.register(ModuleEntry::from_metadata(rate_limit.metadata()));

    let captcha = CaptchaBypassDetector::new();
    registry.register(ModuleEntry::from_metadata(captcha.metadata()));

    // Chapter 3: Server-Side Evaluation
    let server_side_eval = ServerSideEvalDetector::new();
    registry.register(ModuleEntry::from_metadata(server_side_eval.metadata()));

    let ssi_injection = SsiInjectionDetector::new();
    registry.register(ModuleEntry::from_metadata(ssi_injection.metadata()));

    // Chapter 4: Infrastructure Enumeration
    let time_based = TimeBasedEnumDetector::new();
    registry.register(ModuleEntry::from_metadata(time_based.metadata()));

    let subdomain_takeover = SubdomainTakeoverDetector::new();
    registry.register(ModuleEntry::from_metadata(subdomain_takeover.metadata()));

    let log4shell = Log4ShellDetector::new();
    registry.register(ModuleEntry::from_metadata(log4shell.metadata()));

    registry
}

/// Get all module metadata for documentation
pub fn get_all_module_metadata() -> Vec<CheckMetadata> {
    vec![
        PaddingOracleDetector::new().metadata().clone(),
        SessionFixationDetector::new().metadata().clone(),
        SamlSsoDetector::new().metadata().clone(),
        RateLimitBypassDetector::new().metadata().clone(),
        CaptchaBypassDetector::new().metadata().clone(),
        ServerSideEvalDetector::new().metadata().clone(),
        SsiInjectionDetector::new().metadata().clone(),
        TimeBasedEnumDetector::new().metadata().clone(),
        SubdomainTakeoverDetector::new().metadata().clone(),
        Log4ShellDetector::new().metadata().clone(),
    ]
}

/// Export module summary for reporting
pub fn export_module_summary() -> String {
    let mut summary = String::from("Stage 19: Enumeration & Logic Modules\n");
    summary.push_str("=====================================\n\n");

    for metadata in get_all_module_metadata() {
        summary.push_str(&format!(
            "- {} ({})\n  Category: {:?}\n  Severity: {:?}\n  God Mode: {}\n\n",
            metadata.name,
            metadata.id,
            metadata.category,
            metadata.default_severity,
            metadata.requires_god_mode
        ));
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = create_enum_logic_registry();
        assert!(!registry.is_empty());
        assert!(registry.len() > 0);
    }

    #[test]
    fn test_registry_bounds() {
        let mut registry = EnumLogicRegistry::new();
        
        for i in 0..MAX_REGISTERED_MODULES + 5 {
            let entry = ModuleEntry {
                id: format!("module_{}", i),
                name: format!("Module {}", i),
                category: CheckCategory::Other,
                severity: Severity::Low,
                enabled: true,
            };
            registry.register(entry);
        }

        assert_eq!(registry.len(), MAX_REGISTERED_MODULES);
    }

    #[test]
    fn test_get_by_category() {
        let registry = create_enum_logic_registry();
        
        let crypto_modules = registry.get_by_category(CheckCategory::SensitiveDataExposure);
        assert!(!crypto_modules.is_empty());
    }

    #[test]
    fn test_module_metadata_export() {
        let metadata_list = get_all_module_metadata();
        assert_eq!(metadata_list.len(), 10);

        let summary = export_module_summary();
        assert!(summary.contains("Stage 19"));
        assert!(summary.contains("Padding Oracle"));
    }
}
