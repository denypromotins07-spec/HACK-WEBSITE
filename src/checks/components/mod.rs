//! Component Checking Module
//! Exports component checking traits and wires them into the global scanner context.

pub mod fingerprint;
pub mod registry;

pub use fingerprint::FingerprintDetector;
pub use registry::{VulnerabilityRegistry, SharedRegistry, CveEntry, Severity};

use crate::http::response::HttpResponse;
use crate::findings::evidence::Evidence;

/// Trait for component scanning operations
pub trait ComponentScanner {
    /// Scan a response for component fingerprints
    fn scan(&self, response: &HttpResponse, url: &str) -> Vec<Evidence>;
    
    /// Check if a component has known vulnerabilities
    fn check_vulnerabilities(&self, component: &str, version: &str) -> Vec<CveEntry>;
    
    /// Calculate risk score for detected components
    fn calculate_risk(&self, component: &str, version: &str) -> f32;
}

/// Combined component scanner with fingerprinting and vulnerability checking
pub struct CombinedComponentScanner {
    fingerprint_detector: FingerprintDetector,
    vulnerability_registry: SharedRegistry,
}

impl CombinedComponentScanner {
    pub fn new() -> Self {
        Self {
            fingerprint_detector: FingerprintDetector::new(),
            vulnerability_registry: SharedRegistry::new(),
        }
    }
}

impl ComponentScanner for CombinedComponentScanner {
    fn scan(&self, response: &HttpResponse, url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        
        // Generate fingerprint evidence
        if let Some(evidence) = self.fingerprint_detector.generate_evidence(response, url) {
            evidences.push(evidence);
        }
        
        evidences
    }

    fn check_vulnerabilities(&self, component: &str, version: &str) -> Vec<CveEntry> {
        self.vulnerability_registry.check(component, version)
    }

    fn calculate_risk(&self, component: &str, version: &str) -> f32 {
        self.vulnerability_registry.risk_score(component, version)
    }
}

/// Module metadata for orchestrator registration
pub fn module_metadata() -> crate::orchestrator::ModuleMetadata {
    crate::orchestrator::ModuleMetadata {
        name: "components".to_string(),
        version: "1.0.0".to_string(),
        description: "Component fingerprinting and vulnerability detection".to_string(),
        enabled: true,
        priority: 50,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combined_scanner_creation() {
        let scanner = CombinedComponentScanner::new();
        assert_eq!(scanner.calculate_risk("jQuery", "3.4.1") > 0.0, true);
    }
}
