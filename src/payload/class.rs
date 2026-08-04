//! Payload Classification - Vulnerability categories and severity definitions
//!
//! Defines the taxonomy of payload classes used throughout the scanner,
//! including injection attacks, XSS, SSRF, path traversal, deserialization
//! vulnerabilities, and protocol abuse patterns.

use std::fmt;
use serde::{Serialize, Deserialize};

/// Primary vulnerability class for payload categorization
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PayloadClass {
    /// SQL Injection variants (union-based, blind, error-based, time-based)
    SqlInjection,
    /// Cross-Site Scripting (reflected, stored, DOM-based)
    Xss,
    /// Server-Side Request Forgery
    Ssrf,
    /// Path/Directory Traversal
    PathTraversal,
    /// Command/OS Injection
    CommandInjection,
    /// LDAP Injection
    LdapInjection,
    /// XPath Injection
    XpathInjection,
    /// XML External Entity (XXE)
    Xxe,
    /// Deserialization vulnerabilities (unsafe deserial, RCE via unserialize)
    Deserialization,
    /// Template Injection (SSTI, expression language injection)
    TemplateInjection,
    /// HTTP Header Injection / Response Splitting
    HeaderInjection,
    /// Protocol-specific attacks (SMTP, DNS, etc.)
    ProtocolAbuse,
    /// Authentication bypass / Session fixation
    AuthBypass,
    /// File Upload vulnerabilities
    FileUpload,
    /// Business Logic abuse
    LogicFlaw,
    /// Information Disclosure
    InfoDisclosure,
    /// Custom/Unknown class
    Custom(String),
}

impl fmt::Display for PayloadClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadClass::SqlInjection => write!(f, "SQL Injection"),
            PayloadClass::Xss => write!(f, "Cross-Site Scripting"),
            PayloadClass::Ssrf => write!(f, "Server-Side Request Forgery"),
            PayloadClass::PathTraversal => write!(f, "Path Traversal"),
            PayloadClass::CommandInjection => write!(f, "Command Injection"),
            PayloadClass::LdapInjection => write!(f, "LDAP Injection"),
            PayloadClass::XpathInjection => write!(f, "XPath Injection"),
            PayloadClass::Xxe => write!(f, "XML External Entity"),
            PayloadClass::Deserialization => write!(f, "Deserialization"),
            PayloadClass::TemplateInjection => write!(f, "Template Injection"),
            PayloadClass::HeaderInjection => write!(f, "Header Injection"),
            PayloadClass::ProtocolAbuse => write!(f, "Protocol Abuse"),
            PayloadClass::AuthBypass => write!(f, "Authentication Bypass"),
            PayloadClass::FileUpload => write!(f, "File Upload"),
            PayloadClass::LogicFlaw => write!(f, "Logic Flaw"),
            PayloadClass::InfoDisclosure => write!(f, "Information Disclosure"),
            PayloadClass::Custom(s) => write!(f, "Custom: {}", s),
        }
    }
}

/// Severity level for vulnerability classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Informational - no direct exploit potential
    Info,
    /// Low - minimal impact, requires specific conditions
    Low,
    /// Medium - moderate impact, may require user interaction
    Medium,
    /// High - significant impact, direct exploit possible
    High,
    /// Critical - remote code execution, full system compromise
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Info
    }
}

/// Safety level indicating whether payload execution is safe for production
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SafetyLevel {
    /// Completely safe - canary strings, math checks, no side effects
    Safe,
    /// Low risk - read-only operations, no data modification
    LowRisk,
    /// Moderate risk - may cause minor side effects
    ModerateRisk,
    /// Unsafe - potential for data modification or system impact
    Unsafe,
    /// Dangerous - requires explicit god-mode authorization
    Dangerous,
}

impl fmt::Display for SafetyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SafetyLevel::Safe => write!(f, "SAFE"),
            SafetyLevel::LowRisk => write!(f, "LOW_RISK"),
            SafetyLevel::ModerateRisk => write!(f, "MODERATE_RISK"),
            SafetyLevel::Unsafe => write!(f, "UNSAFE"),
            SafetyLevel::Dangerous => write!(f, "DANGEROUS"),
        }
    }
}

impl Default for SafetyLevel {
    fn default() -> Self {
        SafetyLevel::Safe
    }
}

/// Granular vulnerability tags for fine-grained filtering
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VulnerabilityTag {
    // SQL Injection subtypes
    SqlUnionBased,
    SqlBlindBoolean,
    SqlBlindTime,
    SqlErrorBased,
    SqlStackedQueries,
    
    // XSS subtypes
    XssReflected,
    XssStored,
    XssDom,
    XssAngular,
    XssReact,
    
    // SSRF variants
    SsrfInternal,
    SsrfCloudMetadata,
    SsrfFileRead,
    SsrfPortScan,
    
    // Injection contexts
    ContextHtml,
    ContextJavascript,
    ContextSql,
    ContextLdap,
    ContextXpath,
    ContextShell,
    ContextHeader,
    ContextJson,
    ContextXml,
    
    // Encoding types
    EncUrl,
    EncHtml,
    EncUnicode,
    EncBase64,
    EncHex,
    EncDouble,
    
    // Detection methods
    DetectReflection,
    DetectTimeBased,
    DetectOobDns,
    DetectOobHttp,
    DetectError,
    DetectBoolBased,
    
    // Target technologies
    TechMysql,
    TechPostgres,
    TechMssql,
    TechOracle,
    TechMongo,
    TechRedis,
    TechApache,
    TechNginx,
    TechIis,
    TechTomcat,
    TechNodejs,
    TechPhp,
    TechJava,
    TechDotnet,
    TechPython,
    
    // CWE mappings
    Cwe89,  // SQL Injection
    Cwe79,  // XSS
    Cwe918, // SSRF
    Cwe22,  // Path Traversal
    Cwe78,  // OS Command Injection
    Cwe502, // Deserialization
    Cwe94,  // Code Injection
    Cwe116, // Improper Encoding
    
    // Custom tag
    Custom(String),
}

impl fmt::Display for VulnerabilityTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VulnerabilityTag::SqlUnionBased => write!(f, "sql:union"),
            VulnerabilityTag::SqlBlindBoolean => write!(f, "sql:blind-bool"),
            VulnerabilityTag::SqlBlindTime => write!(f, "sql:blind-time"),
            VulnerabilityTag::SqlErrorBased => write!(f, "sql:error"),
            VulnerabilityTag::SqlStackedQueries => write!(f, "sql:stacked"),
            VulnerabilityTag::XssReflected => write!(f, "xss:reflected"),
            VulnerabilityTag::XssStored => write!(f, "xss:stored"),
            VulnerabilityTag::XssDom => write!(f, "xss:dom"),
            VulnerabilityTag::XssAngular => write!(f, "xss:angular"),
            VulnerabilityTag::XssReact => write!(f, "xss:react"),
            VulnerabilityTag::SsrfInternal => write!(f, "ssrf:internal"),
            VulnerabilityTag::SsrfCloudMetadata => write!(f, "ssrf:cloud-meta"),
            VulnerabilityTag::SsrfFileRead => write!(f, "ssrf:file-read"),
            VulnerabilityTag::SsrfPortScan => write!(f, "ssrf:port-scan"),
            VulnerabilityTag::ContextHtml => write!(f, "ctx:html"),
            VulnerabilityTag::ContextJavascript => write!(f, "ctx:js"),
            VulnerabilityTag::ContextSql => write!(f, "ctx:sql"),
            VulnerabilityTag::ContextLdap => write!(f, "ctx:ldap"),
            VulnerabilityTag::ContextXpath => write!(f, "ctx:xpath"),
            VulnerabilityTag::ContextShell => write!(f, "ctx:shell"),
            VulnerabilityTag::ContextHeader => write!(f, "ctx:header"),
            VulnerabilityTag::ContextJson => write!(f, "ctx:json"),
            VulnerabilityTag::ContextXml => write!(f, "ctx:xml"),
            VulnerabilityTag::EncUrl => write!(f, "enc:url"),
            VulnerabilityTag::EncHtml => write!(f, "enc:html"),
            VulnerabilityTag::EncUnicode => write!(f, "enc:unicode"),
            VulnerabilityTag::EncBase64 => write!(f, "enc:base64"),
            VulnerabilityTag::EncHex => write!(f, "enc:hex"),
            VulnerabilityTag::EncDouble => write!(f, "enc:double"),
            VulnerabilityTag::DetectReflection => write!(f, "detect:reflection"),
            VulnerabilityTag::DetectTimeBased => write!(f, "detect:time"),
            VulnerabilityTag::DetectOobDns => write!(f, "detect:oob-dns"),
            VulnerabilityTag::DetectOobHttp => write!(f, "detect:oob-http"),
            VulnerabilityTag::DetectError => write!(f, "detect:error"),
            VulnerabilityTag::DetectBoolBased => write!(f, "detect:bool"),
            VulnerabilityTag::TechMysql => write!(f, "tech:mysql"),
            VulnerabilityTag::TechPostgres => write!(f, "tech:postgres"),
            VulnerabilityTag::TechMssql => write!(f, "tech:mssql"),
            VulnerabilityTag::TechOracle => write!(f, "tech:oracle"),
            VulnerabilityTag::TechMongo => write!(f, "tech:mongo"),
            VulnerabilityTag::TechRedis => write!(f, "tech:redis"),
            VulnerabilityTag::TechApache => write!(f, "tech:apache"),
            VulnerabilityTag::TechNginx => write!(f, "tech:nginx"),
            VulnerabilityTag::TechIis => write!(f, "tech:iis"),
            VulnerabilityTag::TechTomcat => write!(f, "tech:tomcat"),
            VulnerabilityTag::TechNodejs => write!(f, "tech:nodejs"),
            VulnerabilityTag::TechPhp => write!(f, "tech:php"),
            VulnerabilityTag::TechJava => write!(f, "tech:java"),
            VulnerabilityTag::TechDotnet => write!(f, "tech:dotnet"),
            VulnerabilityTag::TechPython => write!(f, "tech:python"),
            VulnerabilityTag::Cwe89 => write!(f, "cwe:89"),
            VulnerabilityTag::Cwe79 => write!(f, "cwe:79"),
            VulnerabilityTag::Cwe918 => write!(f, "cwe:918"),
            VulnerabilityTag::Cwe22 => write!(f, "cwe:22"),
            VulnerabilityTag::Cwe78 => write!(f, "cwe:78"),
            VulnerabilityTag::Cwe502 => write!(f, "cwe:502"),
            VulnerabilityTag::Cwe94 => write!(f, "cwe:94"),
            VulnerabilityTag::Cwe116 => write!(f, "cwe:116"),
            VulnerabilityTag::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

/// Builder pattern for creating payload classifications
#[derive(Debug, Default)]
pub struct ClassificationBuilder {
    class: Option<PayloadClass>,
    severity: Severity,
    safety: SafetyLevel,
    tags: Vec<VulnerabilityTag>,
}

impl ClassificationBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn class(mut self, class: PayloadClass) -> Self {
        self.class = Some(class);
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn safety(mut self, safety: SafetyLevel) -> Self {
        self.safety = safety;
        self
    }

    pub fn tag(mut self, tag: VulnerabilityTag) -> Self {
        self.tags.push(tag);
        self
    }

    pub fn tags(mut self, tags: Vec<VulnerabilityTag>) -> Self {
        self.tags.extend(tags);
        self
    }

    pub fn build(self) -> Option<(PayloadClass, Severity, SafetyLevel, Vec<VulnerabilityTag>)> {
        self.class.map(|c| (c, self.severity, self.safety, self.tags))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classification_builder() {
        let result = ClassificationBuilder::new()
            .class(PayloadClass::SqlInjection)
            .severity(Severity::High)
            .safety(SafetyLevel::Safe)
            .tag(VulnerabilityTag::SqlUnionBased)
            .tag(VulnerabilityTag::Cwe89)
            .build();

        assert!(result.is_some());
        let (class, severity, safety, tags) = result.unwrap();
        assert_eq!(class, PayloadClass::SqlInjection);
        assert_eq!(severity, Severity::High);
        assert_eq!(safety, SafetyLevel::Safe);
        assert_eq!(tags.len(), 2);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
