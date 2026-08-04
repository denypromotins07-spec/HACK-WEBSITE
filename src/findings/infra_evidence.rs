//! Infrastructure Evidence Container
//! Builds evidence containers for infrastructure leaks with exposed file hashes and versions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Evidence types for infrastructure findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InfraEvidence {
    /// Git repository exposure
    GitExposure {
        file_path: String,
        url: String,
        info: String,
        confidence: u8,
        remediation: String,
    },
    
    /// Multiple Git files exposed (directory reconstruction possible)
    GitDirectoryExposed {
        files_found: Vec<String>,
        base_url: String,
        confidence: u8,
        remediation: String,
    },
    
    /// SVN repository exposure
    SvnExposure {
        file_path: String,
        url: String,
        size_hint: usize,
        confidence: u8,
        remediation: String,
    },
    
    /// Multiple SVN files exposed
    SvnDirectoryExposed {
        files_found: Vec<String>,
        base_url: String,
        confidence: u8,
        remediation: String,
    },
    
    /// Environment/configuration file leak
    EnvironmentLeak {
        file_path: String,
        url: String,
        severity: String,
        exposed_keys: Vec<String>,
        confidence: u8,
        remediation: String,
    },
    
    /// Multiple sensitive files leaked
    MultipleLeaks {
        count: usize,
        files: Vec<String>,
        base_url: String,
        confidence: u8,
        remediation: String,
    },
    
    /// Exposed container API endpoint
    ExposedContainerApi {
        endpoint: String,
        service: String,
        url: String,
        severity: String,
        info: String,
        confidence: u8,
        remediation: String,
    },
    
    /// Critical container exposure summary
    CriticalContainerExposure {
        container_type: String,
        endpoints_found: usize,
        base_url: String,
        confidence: u8,
        remediation: String,
    },
}

impl InfraEvidence {
    /// Get confidence score
    pub fn confidence(&self) -> u8 {
        match self {
            InfraEvidence::GitExposure { confidence, .. } => *confidence,
            InfraEvidence::GitDirectoryExposed { confidence, .. } => *confidence,
            InfraEvidence::SvnExposure { confidence, .. } => *confidence,
            InfraEvidence::SvnDirectoryExposed { confidence, .. } => *confidence,
            InfraEvidence::EnvironmentLeak { confidence, .. } => *confidence,
            InfraEvidence::MultipleLeaks { confidence, .. } => *confidence,
            InfraEvidence::ExposedContainerApi { confidence, .. } => *confidence,
            InfraEvidence::CriticalContainerExposure { confidence, .. } => *confidence,
        }
    }
    
    /// Get remediation guidance
    pub fn remediation(&self) -> &str {
        match self {
            InfraEvidence::GitExposure { remediation, .. } => remediation,
            InfraEvidence::GitDirectoryExposed { remediation, .. } => remediation,
            InfraEvidence::SvnExposure { remediation, .. } => remediation,
            InfraEvidence::SvnDirectoryExposed { remediation, .. } => remediation,
            InfraEvidence::EnvironmentLeak { remediation, .. } => remediation,
            InfraEvidence::MultipleLeaks { remediation, .. } => remediation,
            InfraEvidence::ExposedContainerApi { remediation, .. } => remediation,
            InfraEvidence::CriticalContainerExposure { remediation, .. } => remediation,
        }
    }
    
    /// Get affected URL
    pub fn url(&self) -> &str {
        match self {
            InfraEvidence::GitExposure { url, .. } => url,
            InfraEvidence::GitDirectoryExposed { base_url, .. } => base_url,
            InfraEvidence::SvnExposure { url, .. } => url,
            InfraEvidence::SvnDirectoryExposed { base_url, .. } => base_url,
            InfraEvidence::EnvironmentLeak { url, .. } => url,
            InfraEvidence::MultipleLeaks { base_url, .. } => base_url,
            InfraEvidence::ExposedContainerApi { url, .. } => url,
            InfraEvidence::CriticalContainerExposure { base_url, .. } => base_url,
        }
    }
    
    /// Calculate severity score (0-100)
    pub fn severity_score(&self) -> u8 {
        let confidence = self.confidence() as u32;
        
        let base_severity = match self {
            InfraEvidence::GitDirectoryExposed { .. } => 100,
            InfraEvidence::SvnDirectoryExposed { .. } => 100,
            InfraEvidence::CriticalContainerExposure { .. } => 100,
            InfraEvidence::EnvironmentLeak { severity, .. } => {
                match severity.as_str() {
                    "Critical" => 95,
                    "High" => 80,
                    "Medium" => 60,
                    _ => 40,
                }
            },
            InfraEvidence::ExposedContainerApi { severity, .. } => {
                match severity.as_str() {
                    "Critical" => 95,
                    "High" => 80,
                    "Medium" => 60,
                    _ => 40,
                }
            },
            InfraEvidence::GitExposure { .. } => 85,
            InfraEvidence::SvnExposure { .. } => 85,
            InfraEvidence::MultipleLeaks { .. } => 90,
        };
        
        ((base_severity as u32 * confidence) / 100) as u8
    }
    
    /// Generate a unique fingerprint for deduplication
    pub fn fingerprint(&self) -> String {
        format!("{:?}:{}", std::mem::discriminant(self), self.url())
    }
}

/// Builder for infrastructure evidence
pub struct InfraEvidenceBuilder {
    findings: Vec<InfraEvidence>,
}

impl InfraEvidenceBuilder {
    pub fn new() -> Self {
        Self { findings: Vec::new() }
    }
    
    pub fn add_git_exposure(mut self, file_path: String, url: String, info: String) -> Self {
        self.findings.push(InfraEvidence::GitExposure {
            file_path,
            url,
            info,
            confidence: 95,
            remediation: "Remove .git directory from production or block access via web server configuration.".to_string(),
        });
        self
    }
    
    pub fn add_git_directory_exposed(mut self, files: Vec<String>, base_url: String) -> Self {
        self.findings.push(InfraEvidence::GitDirectoryExposed {
            files_found: files,
            base_url,
            confidence: 100,
            remediation: "CRITICAL: Entire repository may be reconstructable. Remove .git immediately.".to_string(),
        });
        self
    }
    
    pub fn add_env_leak(mut self, file_path: String, url: String, severity: String, keys: Vec<String>) -> Self {
        self.findings.push(InfraEvidence::EnvironmentLeak {
            file_path,
            url,
            severity,
            exposed_keys: keys,
            confidence: 90,
            remediation: "Remove sensitive files from web-accessible directories.".to_string(),
        });
        self
    }
    
    pub fn add_container_api_exposure(mut self, endpoint: String, service: String, url: String, severity: String) -> Self {
        self.findings.push(InfraEvidence::ExposedContainerApi {
            endpoint,
            service,
            url,
            severity,
            info: "Endpoint accessible".to_string(),
            confidence: 85,
            remediation: "Restrict access to container management interfaces.".to_string(),
        });
        self
    }
    
    pub fn build(self) -> Vec<InfraEvidence> {
        self.findings
    }
}

impl Default for InfraEvidenceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_builder() {
        let evidence = InfraEvidenceBuilder::new()
            .add_git_exposure("/.git/HEAD".to_string(), "http://example.com/.git/HEAD".to_string(), "HEAD accessible".to_string())
            .build();
        
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].confidence(), 95);
    }
    
    #[test]
    fn test_severity_scoring() {
        let evidence = InfraEvidence::GitDirectoryExposed {
            files_found: vec!["/.git/HEAD".to_string()],
            base_url: "http://example.com".to_string(),
            confidence: 100,
            remediation: "test".to_string(),
        };
        
        assert!(evidence.severity_score() >= 90);
    }
}
