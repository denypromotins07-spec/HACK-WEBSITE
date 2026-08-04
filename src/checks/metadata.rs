//! Vulnerability Check Metadata
//! 
//! Defines metadata model for vulnerability checks including ID, severity,
//! category, timeout, and resource budget constraints.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Unique identifier for a vulnerability check
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckId(pub String);

impl CheckId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Severity levels for vulnerability classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    /// Get numeric score for priority calculations
    pub fn score(self) -> u16 {
        match self {
            Severity::Info => 0,
            Severity::Low => 25,
            Severity::Medium => 50,
            Severity::High => 75,
            Severity::Critical => 100,
        }
    }
    
    /// Get human-readable label
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
    
    /// Get CVSS range for this severity
    pub fn cvss_range(self) -> (f32, f32) {
        match self {
            Severity::Info => (0.0, 0.0),
            Severity::Low => (0.1, 3.9),
            Severity::Medium => (4.0, 6.9),
            Severity::High => (7.0, 8.9),
            Severity::Critical => (9.0, 10.0),
        }
    }
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Info
    }
}

/// Category of vulnerability check
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CheckCategory {
    // OWASP Top 10 categories
    Injection,
    BrokenAuthentication,
    SensitiveDataExposure,
    XmlExternalEntities,
    BrokenAccessControl,
    SecurityMisconfiguration,
    CrossSiteScripting,
    InsecureDeserialization,
    UsingComponentsWithKnownVulnerabilities,
    InsufficientLoggingMonitoring,
    
    // Advanced categories
    ServerSideRequestForgery,
    RemoteCodeExecution,
    FileUpload,
    PathTraversal,
    CommandInjection,
    SqlInjection,
    NoSqlInjection,
    LdapInjection,
    XpathInjection,
    SSTI,
    CSRF,
    SSRF,
    XXE,
    
    // Infrastructure
    Network,
    TLS,
    Headers,
    Cookies,
    CORS,
    CSP,
    
    // Business Logic
    RateLimiting,
    Idor,
    ParameterTampering,
    SessionManagement,
    
    // Information Gathering
    SubdomainEnumeration,
    DirectoryBruteforce,
    TechnologyDetection,
    VersionDisclosure,
    
    Custom(String),
}

impl CheckCategory {
    pub fn as_str(&self) -> &str {
        match self {
            CheckCategory::Injection => "injection",
            CheckCategory::BrokenAuthentication => "auth",
            CheckCategory::SensitiveDataExposure => "data_exposure",
            CheckCategory::XmlExternalEntities => "xxe",
            CheckCategory::BrokenAccessControl => "access_control",
            CheckCategory::SecurityMisconfiguration => "misconfig",
            CheckCategory::CrossSiteScripting => "xss",
            CheckCategory::InsecureDeserialization => "deserialization",
            CheckCategory::UsingComponentsWithKnownVulnerabilities => "known_vulns",
            CheckCategory::InsufficientLoggingMonitoring => "logging",
            CheckCategory::ServerSideRequestForgery => "ssrf",
            CheckCategory::RemoteCodeExecution => "rce",
            CheckCategory::FileUpload => "file_upload",
            CheckCategory::PathTraversal => "path_traversal",
            CheckCategory::CommandInjection => "cmd_injection",
            CheckCategory::SqlInjection => "sqli",
            CheckCategory::NoSqlInjection => "nosqli",
            CheckCategory::LdapInjection => "ldapi",
            CheckCategory::XpathInjection => "xpathi",
            CheckCategory::SSTI => "ssti",
            CheckCategory::CSRF => "csrf",
            CheckCategory::SSRF => "ssrf",
            CheckCategory::XXE => "xxe",
            CheckCategory::Network => "network",
            CheckCategory::TLS => "tls",
            CheckCategory::Headers => "headers",
            CheckCategory::Cookies => "cookies",
            CheckCategory::CORS => "cors",
            CheckCategory::CSP => "csp",
            CheckCategory::RateLimiting => "rate_limiting",
            CheckCategory::Idor => "idor",
            CheckCategory::ParameterTampering => "param_tampering",
            CheckCategory::SessionManagement => "session",
            CheckCategory::SubdomainEnumeration => "subdomain_enum",
            CheckCategory::DirectoryBruteforce => "dir_brute",
            CheckCategory::TechnologyDetection => "tech_detect",
            CheckCategory::VersionDisclosure => "version_disclosure",
            CheckCategory::Custom(s) => s,
        }
    }
}

/// Resource budget constraints for a check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceBudget {
    /// Maximum CPU time in milliseconds
    pub max_cpu_ms: u64,
    /// Maximum memory usage in bytes
    pub max_memory_bytes: u64,
    /// Maximum number of HTTP requests allowed
    pub max_requests: u32,
    /// Maximum execution duration in milliseconds
    pub max_duration_ms: u64,
    /// Maximum payload size in bytes
    pub max_payload_size: usize,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            max_cpu_ms: 500,
            max_memory_bytes: 10 * 1024 * 1024, // 10MB per check
            max_requests: 50,
            max_duration_ms: 2000,
            max_payload_size: 4096,
        }
    }
}

impl ResourceBudget {
    /// Create a tight budget for safe checks
    pub fn safe() -> Self {
        Self {
            max_cpu_ms: 100,
            max_memory_bytes: 2 * 1024 * 1024,
            max_requests: 10,
            max_duration_ms: 500,
            max_payload_size: 1024,
        }
    }
    
    /// Create an expanded budget for advanced checks (god-mode only)
    pub fn advanced() -> Self {
        Self {
            max_cpu_ms: 2000,
            max_memory_bytes: 50 * 1024 * 1024,
            max_requests: 200,
            max_duration_ms: 10000,
            max_payload_size: 16384,
        }
    }
    
    /// Convert to Duration
    pub fn as_duration(&self) -> Duration {
        Duration::from_millis(self.max_duration_ms)
    }
}

/// Metadata for a vulnerability check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckMetadata {
    /// Unique identifier
    pub id: CheckId,
    /// Human-readable name
    pub name: String,
    /// Description of what the check does
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Category classification
    pub category: CheckCategory,
    /// Resource budget constraints
    pub budget: ResourceBudget,
    /// Whether this check requires god-mode
    pub requires_god_mode: bool,
    /// Whether this check is safe to run without authentication
    pub is_safe: bool,
    /// Tags for filtering and grouping
    pub tags: Vec<String>,
    /// References (CVE, CWE, URLs)
    pub references: Vec<String>,
    /// Minimum confidence threshold to report
    pub min_confidence: u8,
    /// Version of the check
    pub version: String,
    /// Author of the check
    pub author: Option<String>,
}

impl CheckMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        category: CheckCategory,
    ) -> Self {
        Self {
            id: CheckId::new(id),
            name: name.into(),
            description: description.into(),
            severity,
            category,
            budget: ResourceBudget::default(),
            requires_god_mode: false,
            is_safe: true,
            tags: Vec::new(),
            references: Vec::new(),
            min_confidence: 50,
            version: "1.0.0".to_string(),
            author: None,
        }
    }
    
    /// Set this check as requiring god-mode
    pub fn with_god_mode(mut self, required: bool) -> Self {
        self.requires_god_mode = required;
        self
    }
    
    /// Set safety flag
    pub fn with_safety(mut self, safe: bool) -> Self {
        self.is_safe = safe;
        self
    }
    
    /// Add tags
    pub fn with_tags(mut self, tags: Vec<&str>) -> Self {
        self.tags = tags.into_iter().map(|s| s.to_string()).collect();
        self
    }
    
    /// Set custom budget
    pub fn with_budget(mut self, budget: ResourceBudget) -> Self {
        self.budget = budget;
        self
    }
    
    /// Add references
    pub fn with_references(mut self, refs: Vec<&str>) -> Self {
        self.references = refs.into_iter().map(|s| s.to_string()).collect();
        self
    }
}
