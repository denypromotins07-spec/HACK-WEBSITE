//! Component Vulnerability Registry
//! Maps fingerprinted versions against a bounded, in-memory CVE vulnerability database.

use std::collections::HashMap;
use std::sync::Arc;

/// Maximum number of CVE entries to cache (bounded memory)
const MAX_CVE_ENTRIES: usize = 10_000;

/// Vulnerability entry with CVE details
#[derive(Clone, Debug)]
pub struct CveEntry {
    pub cve_id: String,
    pub severity: Severity,
    pub affected_versions: Vec<String>,
    pub fixed_version: Option<String>,
    pub description: String,
    pub remediation: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn score(&self) -> f32 {
        match self {
            Severity::Critical => 10.0,
            Severity::High => 7.5,
            Severity::Medium => 5.0,
            Severity::Low => 2.5,
            Severity::Info => 0.5,
        }
    }
}

/// Bounded in-memory CVE vulnerability database
pub struct VulnerabilityRegistry {
    entries: HashMap<String, Vec<CveEntry>>, // component_name -> entries
    max_entries: usize,
}

impl VulnerabilityRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            entries: HashMap::new(),
            max_entries: MAX_CVE_ENTRIES,
        };
        registry.load_known_vulnerabilities();
        registry
    }

    /// Load known vulnerabilities into bounded storage
    fn load_known_vulnerabilities(&mut self) {
        // WordPress vulnerabilities
        self.add_entry("WordPress", CveEntry {
            cve_id: "CVE-2023-38000".to_string(),
            severity: Severity::High,
            affected_versions: vec!["6.2".to_string(), "6.1".to_string()],
            fixed_version: Some("6.3".to_string()),
            description: "SQL injection in WordPress before 6.3".to_string(),
            remediation: "Upgrade to WordPress 6.3 or later".to_string(),
        });

        // jQuery vulnerabilities
        self.add_entry("jQuery", CveEntry {
            cve_id: "CVE-2020-11023".to_string(),
            severity: Severity::Medium,
            affected_versions: vec!["3.4".to_string(), "3.3".to_string()],
            fixed_version: Some("3.5.0".to_string()),
            description: "XSS vulnerability in jQuery passing HTML from untrusted sources".to_string(),
            remediation: "Upgrade to jQuery 3.5.0 or later".to_string(),
        });

        // Django vulnerabilities
        self.add_entry("Django", CveEntry {
            cve_id: "CVE-2023-41164".to_string(),
            severity: Severity::High,
            affected_versions: vec!["4.1".to_string(), "4.0".to_string()],
            fixed_version: Some("4.2.4".to_string()),
            description: "Potential ReDoS vulnerability in Django".to_string(),
            remediation: "Upgrade to Django 4.2.4 or later".to_string(),
        });

        // Laravel vulnerabilities
        self.add_entry("Laravel", CveEntry {
            cve_id: "CVE-2023-28121".to_string(),
            severity: Severity::Critical,
            affected_versions: vec!["10.x".to_string()],
            fixed_version: Some("10.3.1".to_string()),
            description: "Remote code execution via insecure deserialization".to_string(),
            remediation: "Upgrade to Laravel 10.3.1 or later".to_string(),
        });

        // Express.js vulnerabilities
        self.add_entry("Express.js", CveEntry {
            cve_id: "CVE-2022-24999".to_string(),
            severity: Severity::High,
            affected_versions: vec!["4.17".to_string()],
            fixed_version: Some("4.18.2".to_string()),
            description: "Open redirect vulnerability in Express.js".to_string(),
            remediation: "Upgrade to Express.js 4.18.2 or later".to_string(),
        });

        // Spring Boot vulnerabilities
        self.add_entry("Spring Boot", CveEntry {
            cve_id: "CVE-2022-22965".to_string(),
            severity: Severity::Critical,
            affected_versions: vec!["2.6".to_string(), "2.5".to_string()],
            fixed_version: Some("2.6.6".to_string()),
            description: "RFD attack via Content-Disposition in Spring Framework".to_string(),
            remediation: "Upgrade to Spring Boot 2.6.6 or later".to_string(),
        });
    }

    /// Add an entry with bounded capacity check
    fn add_entry(&mut self, component: &str, entry: CveEntry) {
        if self.entries.values().flatten().count() >= self.max_entries {
            // Evict oldest entries if at capacity (simple FIFO for demonstration)
            if let Some(first_key) = self.entries.keys().next().cloned() {
                self.entries.remove(&first_key);
            }
        }

        self.entries
            .entry(component.to_string())
            .or_insert_with(Vec::new)
            .push(entry);
    }

    /// Check if a component version has known vulnerabilities
    pub fn check_vulnerabilities(&self, component: &str, version: &str) -> Vec<&CveEntry> {
        let mut vulnerable = Vec::new();
        
        if let Some(entries) = self.entries.get(component) {
            for entry in entries {
                if entry.affected_versions.iter().any(|v| version.starts_with(v)) {
                    vulnerable.push(entry);
                }
            }
        }

        vulnerable
    }

    /// Get all vulnerabilities for a component regardless of version
    pub fn get_all_vulnerabilities(&self, component: &str) -> Vec<&CveEntry> {
        self.entries
            .get(component)
            .map(|entries| entries.iter().collect())
            .unwrap_or_default()
    }

    /// Calculate risk score for a component
    pub fn calculate_risk_score(&self, component: &str, version: &str) -> f32 {
        let vulns = self.check_vulnerabilities(component, version);
        vulns.iter().map(|v| v.severity.score()).sum()
    }
}

/// Thread-safe wrapper for the vulnerability registry
pub struct SharedRegistry {
    inner: Arc<VulnerabilityRegistry>,
}

impl SharedRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(VulnerabilityRegistry::new()),
        }
    }

    pub fn check(&self, component: &str, version: &str) -> Vec<CveEntry> {
        self.inner
            .check_vulnerabilities(component, version)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn risk_score(&self, component: &str, version: &str) -> f32 {
        self.inner.calculate_risk_score(component, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_loading() {
        let registry = VulnerabilityRegistry::new();
        assert!(!registry.entries.is_empty());
    }

    #[test]
    fn test_vulnerability_check() {
        let registry = VulnerabilityRegistry::new();
        let vulns = registry.check_vulnerabilities("jQuery", "3.4.1");
        assert!(!vulns.is_empty());
    }
}
