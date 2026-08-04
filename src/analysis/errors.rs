//! Error Signature Database
//! 
//! Comprehensive, zero-allocation database of backend error signatures 
//! for SQL, LDAP, XPath, and other injection types.

use std::sync::atomic::{AtomicU64, Ordering};
use bytes::Bytes;

/// Type of error signature
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorType {
    SqlInjection,
    LdapInjection,
    XpathInjection,
    CommandInjection,
    FileInclusion,
    Deserialization,
    TemplateInjection,
    XmlInjection,
}

/// Matched error signature
#[derive(Debug, Clone)]
pub struct ErrorMatch {
    pub error_type: ErrorType,
    pub signature_id: u32,
    pub matched_text: String,
    pub confidence: f64,
    pub severity: Severity,
}

/// Severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn score(&self) -> f64 {
        match self {
            Self::Low => 0.25,
            Self::Medium => 0.5,
            Self::High => 0.75,
            Self::Critical => 1.0,
        }
    }
}

/// Error signature entry (stored as static data for zero allocation)
pub struct ErrorSignature {
    pub id: u32,
    pub pattern: &'static str,
    pub error_type: ErrorType,
    pub severity: Severity,
    pub description: &'static str,
}

/// Error database with pre-compiled patterns
pub struct ErrorDatabase {
    signatures: &'static [ErrorSignature],
    matches_found: AtomicU64,
    false_positives_filtered: AtomicU64,
}

impl ErrorDatabase {
    /// Create new error database with built-in signatures
    pub fn new() -> Self {
        Self {
            signatures: Self::build_signatures(),
            matches_found: AtomicU64::new(0),
            false_positives_filtered: AtomicU64::new(0),
        }
    }
    
    /// Build the static signature database
    const fn build_signatures() -> &'static [ErrorSignature] {
        &[
            // SQL Injection errors
            ErrorSignature {
                id: 1001,
                pattern: "SQL syntax",
                error_type: ErrorType::SqlInjection,
                severity: Severity::High,
                description: "Generic SQL syntax error",
            },
            ErrorSignature {
                id: 1002,
                pattern: "mysql_fetch",
                error_type: ErrorType::SqlInjection,
                severity: Severity::High,
                description: "MySQL fetch error",
            },
            ErrorSignature {
                id: 1003,
                pattern: "ORA-",
                error_type: ErrorType::SqlInjection,
                severity: Severity::High,
                description: "Oracle database error",
            },
            ErrorSignature {
                id: 1004,
                pattern: "PostgreSQL",
                error_type: ErrorType::SqlInjection,
                severity: Severity::High,
                description: "PostgreSQL error",
            },
            ErrorSignature {
                id: 1005,
                pattern: "SQLite",
                error_type: ErrorType::SqlInjection,
                severity: Severity::High,
                description: "SQLite error",
            },
            ErrorSignature {
                id: 1006,
                pattern: "unclosed quotation mark",
                error_type: ErrorType::SqlInjection,
                severity: Severity::High,
                description: "SQL string termination error",
            },
            ErrorSignature {
                id: 1007,
                pattern: "ODBC",
                error_type: ErrorType::SqlInjection,
                severity: Severity::Medium,
                description: "ODBC driver error",
            },
            ErrorSignature {
                id: 1008,
                pattern: "syntax error near",
                error_type: ErrorType::SqlInjection,
                severity: Severity::High,
                description: "SQL syntax error location",
            },
            // LDAP Injection errors
            ErrorSignature {
                id: 2001,
                pattern: "LDAP",
                error_type: ErrorType::LdapInjection,
                severity: Severity::High,
                description: "LDAP operation error",
            },
            ErrorSignature {
                id: 2002,
                pattern: "javax.naming",
                error_type: ErrorType::LdapInjection,
                severity: Severity::High,
                description: "Java LDAP naming error",
            },
            ErrorSignature {
                id: 2003,
                pattern: "search filter",
                error_type: ErrorType::LdapInjection,
                severity: Severity::Medium,
                description: "LDAP search filter error",
            },
            // XPath Injection errors
            ErrorSignature {
                id: 3001,
                pattern: "XPath",
                error_type: ErrorType::XpathInjection,
                severity: Severity::High,
                description: "XPath evaluation error",
            },
            ErrorSignature {
                id: 3002,
                pattern: "System.Xml.XPath",
                error_type: ErrorType::XpathInjection,
                severity: Severity::High,
                description: ".NET XPath error",
            },
            ErrorSignature {
                id: 3003,
                pattern: "invalid expression",
                error_type: ErrorType::XpathInjection,
                severity: Severity::Medium,
                description: "XPath invalid expression",
            },
            // Command Injection errors
            ErrorSignature {
                id: 4001,
                pattern: "sh: ",
                error_type: ErrorType::CommandInjection,
                severity: Severity::Critical,
                description: "Shell command error",
            },
            ErrorSignature {
                id: 4002,
                pattern: "bash:",
                error_type: ErrorType::CommandInjection,
                severity: Severity::Critical,
                description: "Bash command error",
            },
            ErrorSignature {
                id: 4003,
                pattern: "Permission denied",
                error_type: ErrorType::CommandInjection,
                severity: Severity::Medium,
                description: "Command permission error",
            },
            ErrorSignature {
                id: 4004,
                pattern: "not found",
                error_type: ErrorType::CommandInjection,
                severity: Severity::Low,
                description: "Command not found",
            },
            // File Inclusion errors
            ErrorSignature {
                id: 5001,
                pattern: "failed to open stream",
                error_type: ErrorType::FileInclusion,
                severity: Severity::High,
                description: "PHP file inclusion error",
            },
            ErrorSignature {
                id: 5002,
                pattern: "include()",
                error_type: ErrorType::FileInclusion,
                severity: Severity::High,
                description: "PHP include error",
            },
            ErrorSignature {
                id: 5003,
                pattern: "require()",
                error_type: ErrorType::FileInclusion,
                severity: Severity::High,
                description: "PHP require error",
            },
            ErrorSignature {
                id: 5004,
                pattern: "No such file or directory",
                error_type: ErrorType::FileInclusion,
                severity: Severity::Medium,
                description: "File not found error",
            },
            // Deserialization errors
            ErrorSignature {
                id: 6001,
                pattern: "java.io.InvalidClassException",
                error_type: ErrorType::Deserialization,
                severity: Severity::Critical,
                description: "Java deserialization error",
            },
            ErrorSignature {
                id: 6002,
                pattern: "pickle.UnpicklingError",
                error_type: ErrorType::Deserialization,
                severity: Severity::Critical,
                description: "Python pickle error",
            },
            ErrorSignature {
                id: 6003,
                pattern: "yaml.YAMLError",
                error_type: ErrorType::Deserialization,
                severity: Severity::High,
                description: "YAML parsing error",
            },
            // Template Injection errors
            ErrorSignature {
                id: 7001,
                pattern: "TemplateSyntaxError",
                error_type: ErrorType::TemplateInjection,
                severity: Severity::High,
                description: "Template syntax error",
            },
            ErrorSignature {
                id: 7002,
                pattern: "Jinja2",
                error_type: ErrorType::TemplateInjection,
                severity: Severity::High,
                description: "Jinja2 template error",
            },
            // XML Injection errors
            ErrorSignature {
                id: 8001,
                pattern: "XML parsing error",
                error_type: ErrorType::XmlInjection,
                severity: Severity::High,
                description: "XML parsing error",
            },
            ErrorSignature {
                id: 8002,
                pattern: "SAXParseException",
                error_type: ErrorType::XmlInjection,
                severity: Severity::High,
                description: "XML SAX parsing error",
            },
        ]
    }
    
    /// Scan content for error signatures (zero-allocation where possible)
    pub fn scan(&self, content: &Bytes) -> Vec<ErrorMatch> {
        let content_str = String::from_utf8_lossy(content);
        let content_lower = content_str.to_lowercase();
        let mut matches = Vec::new();
        
        for sig in self.signatures {
            if content_lower.contains(&sig.pattern.to_lowercase()) {
                self.matches_found.fetch_add(1, Ordering::Relaxed);
                
                matches.push(ErrorMatch {
                    error_type: sig.error_type,
                    signature_id: sig.id,
                    matched_text: sig.pattern.to_string(),
                    confidence: 0.8,
                    severity: sig.severity,
                });
            }
        }
        
        // Sort by severity (highest first)
        matches.sort_by(|a, b| {
            b.severity.score().partial_cmp(&a.severity.score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        
        matches
    }
    
    /// Check if content contains any error signatures
    pub fn has_errors(&self, content: &Bytes) -> bool {
        let content_str = String::from_utf8_lossy(content);
        let content_lower = content_str.to_lowercase();
        
        self.signatures.iter().any(|sig| {
            content_lower.contains(&sig.pattern.to_lowercase())
        })
    }
    
    /// Get statistics
    pub fn stats(&self) -> ErrorStats {
        ErrorStats {
            signature_count: self.signatures.len(),
            matches_found: self.matches_found.load(Ordering::Relaxed),
            false_positives_filtered: self.false_positives_filtered.load(Ordering::Relaxed),
        }
    }
    
    /// Record a false positive for learning
    pub fn record_false_positive(&self, signature_id: u32) {
        self.false_positives_filtered.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for ErrorDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for error database
#[derive(Debug, Clone)]
pub struct ErrorStats {
    pub signature_count: usize,
    pub matches_found: u64,
    pub false_positives_filtered: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_database_creation() {
        let db = ErrorDatabase::new();
        let stats = db.stats();
        assert!(stats.signature_count > 0);
    }
    
    #[test]
    fn test_scan_sql_error() {
        let db = ErrorDatabase::new();
        let content = Bytes::from("Error: SQL syntax error near 'SELECT'");
        
        let matches = db.scan(&content);
        
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.error_type == ErrorType::SqlInjection));
    }
    
    #[test]
    fn test_has_errors() {
        let db = ErrorDatabase::new();
        let clean = Bytes::from("<html><body>Hello</body></html>");
        let error = Bytes::from("ORA-01756: quoted string not properly terminated");
        
        assert!(!db.has_errors(&clean));
        assert!(db.has_errors(&error));
    }
}
