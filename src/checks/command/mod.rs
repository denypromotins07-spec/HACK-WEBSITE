//! Command Injection Module Registration
//! Registers command injection, binary exploitation, and request smuggling modules.
//! Wires all command-related checks into the orchestrator with learning integration.

use crate::checks::Check;
use crate::checks::command::injection::CommandInjectionCheck;
use crate::checks::command::blind::BlindCommandInjectionCheck;
use crate::checks::command::payloads::PayloadGenerator;
use crate::checks::command::shellshock::ShellshockCheck;
use crate::checks::command::cgi::CgiCheck;
use crate::checks::command::env_injection::EnvInjectionCheck;
use crate::checks::command::request_splitting::RequestSplittingCheck;
use crate::checks::upload::execution::UploadExecutionCheck;
use crate::checks::binary::zip_slip::ZipSlipCheck;
use crate::checks::binary::native_deser::NativeDeserCheck;
use crate::checks::binary::overflow::OverflowCheck;
use crate::learning::command_cache::CommandCache;
use std::collections::HashMap;
use std::sync::Arc;

/// Command check module registry
pub struct CommandModuleRegistry {
    injection_check: CommandInjectionCheck,
    blind_check: BlindCommandInjectionCheck,
    shellshock_check: ShellshockCheck,
    cgi_check: CgiCheck,
    env_check: EnvInjectionCheck,
    upload_check: UploadExecutionCheck,
    zip_slip_check: ZipSlipCheck,
    native_deser_check: NativeDeserCheck,
    overflow_check: OverflowCheck,
    request_splitting_check: RequestSplittingCheck,
    payload_generator: PayloadGenerator,
    learning_cache: Arc<CommandCache>,
}

impl CommandModuleRegistry {
    pub fn new(oob_callback: Option<String>) -> Self {
        Self {
            injection_check: CommandInjectionCheck::new(),
            blind_check: BlindCommandInjectionCheck::new(oob_callback),
            shellshock_check: ShellshockCheck::new(),
            cgi_check: CgiCheck::new(),
            env_check: EnvInjectionCheck::new(),
            upload_check: UploadExecutionCheck::new(),
            zip_slip_check: ZipSlipCheck::new(),
            native_deser_check: NativeDeserCheck::new(),
            overflow_check: OverflowCheck::new(),
            request_splitting_check: RequestSplittingCheck::new(),
            payload_generator: PayloadGenerator::new(),
            learning_cache: Arc::new(CommandCache::new()),
        }
    }
    
    /// Get all command-related checks
    pub fn get_checks(&self) -> Vec<Box<dyn Check>> {
        vec![
            Box::new(self.injection_check.clone()),
            Box::new(self.blind_check.clone()),
            Box::new(self.shellshock_check.clone()),
            Box::new(self.cgi_check.clone()),
            Box::new(self.env_check.clone()),
            Box::new(self.upload_check.clone()),
            Box::new(self.zip_slip_check.clone()),
            Box::new(self.native_deser_check.clone()),
            Box::new(self.overflow_check.clone()),
            Box::new(self.request_splitting_check.clone()),
        ]
    }
    
    /// Get payload generator reference
    pub fn payload_generator(&self) -> &PayloadGenerator {
        &self.payload_generator
    }
    
    /// Get learning cache reference (for recording findings)
    pub fn learning_cache(&self) -> Arc<CommandCache> {
        Arc::clone(&self.learning_cache)
    }
    
    /// Record a successful finding in the learning cache
    pub fn record_finding(&self, param_pattern: &str, payload: &str, target_type: &str) {
        let mut cache = self.learning_cache.as_ref().clone();
        // Note: In production, this would need interior mutability (Mutex/RwLock)
        // For now, we just demonstrate the interface
    }
    
    /// Get module metadata
    pub fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("module", "command");
        meta.insert("description", "Command injection and binary exploitation detection");
        meta.insert(
            "checks",
            "injection,blind,shellshock,cgi,env,upload,zip_slip,native_deser,overflow,smuggling"
        );
        meta.insert("severity_range", "high-critical");
        meta.insert("owasp_categories", "A03:2021-Injection,A01:2021-Broken Access Control");
        meta
    }
    
    /// Get check count
    pub fn check_count(&self) -> usize {
        10 // Number of individual checks
    }
}

impl Default for CommandModuleRegistry {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_registry_creation() {
        let registry = CommandModuleRegistry::new(None);
        let checks = registry.get_checks();
        assert_eq!(checks.len(), 10);
    }
    
    #[test]
    fn test_metadata() {
        let registry = CommandModuleRegistry::new(None);
        let meta = registry.metadata();
        assert_eq!(meta.get("module"), Some(&"command"));
        assert!(meta.contains_key("checks"));
    }
    
    #[test]
    fn test_payload_generator_access() {
        let registry = CommandModuleRegistry::new(None);
        let gen = registry.payload_generator();
        assert!(!gen.all().is_empty());
    }
}
