//! Upload Module Registration
//! Registers upload checking modules with the orchestrator.
//! Wires file upload execution and polyglot detection into the scanner context.

use crate::checks::Check;
use crate::checks::upload::execution::UploadExecutionCheck;
use crate::checks::upload::polyglot::PolyglotGenerator;
use std::collections::HashMap;

/// Upload check module registry
pub struct UploadModuleRegistry {
    execution_check: UploadExecutionCheck,
    polyglot_gen: PolyglotGenerator,
}

impl UploadModuleRegistry {
    pub fn new() -> Self {
        Self {
            execution_check: UploadExecutionCheck::new(),
            polyglot_gen: PolyglotGenerator::new(),
        }
    }
    
    /// Get all upload-related checks
    pub fn get_checks(&self) -> Vec<Box<dyn Check>> {
        vec![
            Box::new(self.execution_check.clone()),
        ]
    }
    
    /// Get polyglot generator reference
    pub fn polyglot_generator(&self) -> &PolyglotGenerator {
        &self.polyglot_gen
    }
    
    /// Get module metadata
    pub fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("module", "upload");
        meta.insert("description", "File upload vulnerability detection");
        meta.insert("checks", "execution,polyglot");
        meta.insert("severity_range", "high-critical");
        meta
    }
}

impl Default for UploadModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_registry_creation() {
        let registry = UploadModuleRegistry::new();
        let checks = registry.get_checks();
        assert!(!checks.is_empty());
    }
    
    #[test]
    fn test_metadata() {
        let registry = UploadModuleRegistry::new();
        let meta = registry.metadata();
        assert_eq!(meta.get("module"), Some(&"upload"));
    }
}
