//! Access Control Module Registration
//! Registers access-control modules with orchestrator and exports metadata.

pub mod idor;
pub mod bola;
pub mod object_map;
pub mod mass_assignment;
pub mod function_auth;
pub mod privilege_fields;
pub mod mfa_bypass;
pub mod race_conditions;
pub mod business_logic;
pub mod jwt_none;
pub mod jwt_kid;
pub mod jwt_bruteforce;

pub use idor::IdorDetector;
pub use bola::BolaDetector;
pub use object_map::ObjectIdentifierMap;
pub use mass_assignment::MassAssignmentDetector;
pub use function_auth::FunctionAuthDetector;
pub use privilege_fields::PrivilegeFieldsDictionary;
pub use mfa_bypass::MfaBypassDetector;
pub use race_conditions::RaceConditionDetector;
pub use business_logic::BusinessLogicDetector;
pub use jwt_none::JwtNoneDetector;
pub use jwt_kid::JwtKidDetector;
pub use jwt_bruteforce::JwtBruteforceDetector;

use crate::checks::module::{CheckModule, CheckMetadata, CheckCategory};
use std::sync::Arc;

/// Registry of all access control check modules
pub struct AccessControlRegistry {
    modules: Vec<Box<dyn CheckModule + Send + Sync>>,
}

impl AccessControlRegistry {
    pub fn new(
        http_client: Arc<crate::http::client::HttpClient>,
        access_cache: Arc<crate::learning::access_cache::AccessCache>,
    ) -> Self {
        let mut modules: Vec<Box<dyn CheckModule + Send + Sync>> = Vec::new();
        
        // Chapter 1: IDOR and BOLA Detection
        modules.push(Box::new(IdorDetector::new(Arc::clone(&http_client), Arc::clone(&access_cache))));
        modules.push(Box::new(BolaDetector::new(Arc::clone(&http_client), Arc::clone(&access_cache))));
        
        // Chapter 2: Mass Assignment and Function-Level Authorization
        modules.push(Box::new(MassAssignmentDetector::new(Arc::clone(&http_client), Arc::clone(&access_cache))));
        modules.push(Box::new(FunctionAuthDetector::new(Arc::clone(&http_client), Arc::clone(&access_cache))));
        
        // Chapter 3: MFA Bypass, Race Conditions, and Business Logic
        modules.push(Box::new(MfaBypassDetector::new(Arc::clone(&http_client), Arc::clone(&access_cache))));
        modules.push(Box::new(RaceConditionDetector::new(Arc::clone(&http_client), Arc::clone(&access_cache))));
        modules.push(Box::new(BusinessLogicDetector::new(Arc::clone(&http_client), Arc::clone(&access_cache))));
        
        // Chapter 4: JWT Attack Modules
        modules.push(Box::new(JwtNoneDetector::new(Arc::clone(&http_client), Arc::clone(&access_cache))));
        modules.push(Box::new(JwtKidDetector::new(Arc::clone(&http_client), Arc::clone(&access_cache))));
        modules.push(Box::new(JwtBruteforceDetector::new(Arc::clone(&http_client), Arc::clone(&access_cache))));
        
        Self { modules }
    }

    /// Get all registered modules
    pub fn get_modules(&self) -> &[Box<dyn CheckModule + Send + Sync>] {
        &self.modules
    }

    /// Get module metadata for all modules
    pub fn get_metadata(&self) -> Vec<CheckMetadata> {
        self.modules.iter().map(|m| m.metadata()).collect()
    }

    /// Get modules by category
    pub fn get_by_category(&self, category: CheckCategory) -> Vec<&dyn CheckModule> {
        self.modules
            .iter()
            .filter(|m| m.metadata().category == category)
            .map(|m| m.as_ref())
            .collect()
    }

    /// Get access control specific metadata
    pub fn get_access_control_info() -> AccessControlInfo {
        AccessControlInfo {
            total_modules: 10,
            chapters: vec![
                ChapterInfo {
                    name: "IDOR and BOLA Detection".to_string(),
                    modules: vec!["idor", "bola", "object_map"],
                },
                ChapterInfo {
                    name: "Mass Assignment and Function-Level Authorization".to_string(),
                    modules: vec!["mass_assignment", "function_auth", "privilege_fields"],
                },
                ChapterInfo {
                    name: "MFA Bypass, Race Conditions, and Business Logic".to_string(),
                    modules: vec!["mfa_bypass", "race_conditions", "business_logic"],
                },
                ChapterInfo {
                    name: "JWT Attack Modules".to_string(),
                    modules: vec!["jwt_none", "jwt_kid", "jwt_bruteforce"],
                },
                ChapterInfo {
                    name: "Evidence, Learning, and Module Registration".to_string(),
                    modules: vec!["access_evidence", "access_cache", "mod"],
                },
            ],
            detection_capabilities: vec![
                "Insecure Direct Object References (IDOR)",
                "Broken Object Level Authorization (BOLA)",
                "Mass Assignment vulnerabilities",
                "Broken Function Level Authorization (BFLA)",
                "MFA bypass techniques",
                "Race conditions in concurrent operations",
                "Business logic abuse",
                "JWT alg=none bypass",
                "JWT kid injection",
                "JWT weak secret bruteforce",
            ],
        }
    }
}

/// Information about access control capabilities
pub struct AccessControlInfo {
    pub total_modules: usize,
    pub chapters: Vec<ChapterInfo>,
    pub detection_capabilities: Vec<&'static str>,
}

/// Chapter information
pub struct ChapterInfo {
    pub name: String,
    pub modules: Vec<&'static str>,
}

impl std::fmt::Display for AccessControlInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Access Control Module Registry")?;
        writeln!(f, "===============================")?;
        writeln!(f, "Total Modules: {}", self.total_modules)?;
        writeln!(f)?;
        
        for chapter in &self.chapters {
            writeln!(f, "Chapter: {}", chapter.name)?;
            writeln!(f, "  Modules: {}", chapter.modules.join(", "))?;
        }
        
        writeln!(f)?;
        writeln!(f, "Detection Capabilities:")?;
        for cap in &self.detection_capabilities {
            writeln!(f, "  - {}", cap)?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let http_client = Arc::new(crate::http::client::HttpClient::default());
        let access_cache = Arc::new(crate::learning::access_cache::AccessCache::new(100));
        
        let registry = AccessControlRegistry::new(http_client, access_cache);
        
        assert_eq!(registry.get_modules().len(), 10);
    }

    #[test]
    fn test_metadata_collection() {
        let http_client = Arc::new(crate::http::client::HttpClient::default());
        let access_cache = Arc::new(crate::learning::access_cache::AccessCache::new(100));
        
        let registry = AccessControlRegistry::new(http_client, access_cache);
        let metadata = registry.get_metadata();
        
        assert_eq!(metadata.len(), 10);
        
        // Verify all modules have AccessControl category
        for meta in &metadata {
            assert_eq!(meta.category, CheckCategory::AccessControl);
        }
    }

    #[test]
    fn test_access_control_info() {
        let info = AccessControlRegistry::get_access_control_info();
        
        assert_eq!(info.total_modules, 10);
        assert_eq!(info.chapters.len(), 5);
        assert!(!info.detection_capabilities.is_empty());
    }

    #[test]
    fn test_display_format() {
        let info = AccessControlRegistry::get_access_control_info();
        let display = format!("{}", info);
        
        assert!(display.contains("Access Control Module Registry"));
        assert!(display.contains("Total Modules: 10"));
        assert!(display.contains("IDOR and BOLA Detection"));
    }
}
