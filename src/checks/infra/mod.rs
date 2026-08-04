//! Infrastructure Module
//! Registers infrastructure modules with the orchestrator, exports metadata, and wires learning caches.

pub mod git_svn;
pub mod env_leak;
pub mod daemon_sockets;

pub use git_svn::GitSvnScanner;
pub use env_leak::EnvLeakScanner;
pub use daemon_sockets::DaemonSocketScanner;

use crate::http::client::HttpClient;
use crate::findings::evidence::Evidence;

/// Trait for infrastructure scanning operations
pub trait InfraScanner {
    /// Scan for infrastructure exposures
    fn scan(&self, base_url: &str) -> Vec<Evidence>;
    
    /// Quick check if any infrastructure exposure exists
    fn has_exposure(&self, base_url: &str) -> bool;
}

/// Combined infrastructure scanner
pub struct CombinedInfraScanner {
    git_svn_scanner: GitSvnScanner,
    env_leak_scanner: EnvLeakScanner,
    daemon_socket_scanner: DaemonSocketScanner,
}

impl CombinedInfraScanner {
    pub fn new(client: HttpClient) -> Self {
        Self {
            git_svn_scanner: GitSvnScanner::new(client.clone()),
            env_leak_scanner: EnvLeakScanner::new(client.clone()),
            daemon_socket_scanner: DaemonSocketScanner::new(client),
        }
    }
}

impl InfraScanner for CombinedInfraScanner {
    fn scan(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        
        // Git/SVN exposure scan
        let git_evidences = self.git_svn_scanner.scan(base_url);
        evidences.extend(git_evidences);
        
        // Environment leak scan
        let env_evidences = self.env_leak_scanner.scan(base_url);
        evidences.extend(env_evidences);
        
        // Daemon socket scan
        let daemon_evidences = self.daemon_socket_scanner.scan(base_url);
        evidences.extend(daemon_evidences);
        
        evidences
    }

    fn has_exposure(&self, base_url: &str) -> bool {
        self.git_svn_scanner.check_git_exposure(base_url).await.is_empty() == false
            || self.env_leak_scanner.has_leak(base_url).await
            || self.daemon_socket_scanner.has_container_exposure(base_url).await
    }
}

/// Module metadata for orchestrator registration
pub fn module_metadata() -> crate::orchestrator::ModuleMetadata {
    crate::orchestrator::ModuleMetadata {
        name: "infrastructure".to_string(),
        version: "1.0.0".to_string(),
        description: "Source code exposure, environment leaks, and container API detection".to_string(),
        enabled: true,
        priority: 70,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combined_scanner_creation() {
        let client = HttpClient::new();
        let _scanner = CombinedInfraScanner::new(client);
    }
}
