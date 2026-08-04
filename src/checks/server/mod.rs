//! Server Management Module
//! Registers server management modules with the orchestrator and exports metadata.

pub mod tomcat;
pub mod admin_panels;

pub use tomcat::TomcatScanner;
pub use admin_panels::AdminPanelScanner;

use crate::http::client::HttpClient;
use crate::findings::evidence::Evidence;

/// Trait for server scanning operations
pub trait ServerScanner {
    /// Scan for exposed management interfaces
    fn scan(&self, base_url: &str) -> Vec<Evidence>;
    
    /// Quick check if management interface exists
    fn has_management_interface(&self, base_url: &str) -> bool;
}

/// Combined server scanner
pub struct CombinedServerScanner {
    tomcat_scanner: TomcatScanner,
    admin_panel_scanner: AdminPanelScanner,
}

impl CombinedServerScanner {
    pub fn new(client: HttpClient) -> Self {
        Self {
            tomcat_scanner: TomcatScanner::new(client.clone()),
            admin_panel_scanner: AdminPanelScanner::new(client),
        }
    }
}

impl ServerScanner for CombinedServerScanner {
    fn scan(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        
        // Tomcat manager scan
        let tomcat_evidences = self.tomcat_scanner.scan(base_url);
        evidences.extend(tomcat_evidences);
        
        // Admin panel scan
        let admin_evidences = self.admin_panel_scanner.scan(base_url);
        evidences.extend(admin_evidences);
        
        evidences
    }

    fn has_management_interface(&self, base_url: &str) -> bool {
        self.tomcat_scanner.is_tomcat_manager(base_url)
            || self.admin_panel_scanner.has_admin_panel(base_url)
    }
}

/// Module metadata for orchestrator registration
pub fn module_metadata() -> crate::orchestrator::ModuleMetadata {
    crate::orchestrator::ModuleMetadata {
        name: "server".to_string(),
        version: "1.0.0".to_string(),
        description: "Server management console and admin panel exposure detection".to_string(),
        enabled: true,
        priority: 60,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combined_scanner_creation() {
        let client = HttpClient::new();
        let _scanner = CombinedServerScanner::new(client);
    }
}
