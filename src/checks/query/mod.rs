//! Query Language Injection Module Registration
//! Registers query-language modules with orchestrator and exposes metadata.
//! Provides unified interface for NoSQL, ORM, SSTI, EL, XPath, and LDAP injection detection.

pub mod payloads;

// Re-export payload generators
pub use payloads::QueryPayloads;

/// Metadata for query injection modules
#[derive(Debug, Clone)]
pub struct QueryModuleMetadata {
    /// Module name
    pub name: &'static str,
    /// Module description
    pub description: &'static str,
    /// Supported injection types
    pub injection_types: &'static [&'static str],
    /// Risk level
    pub risk_level: &'static str,
    /// Default enabled state
    pub enabled_by_default: bool,
}

/// Registry of all query injection modules
pub struct QueryModuleRegistry {
    modules: Vec<QueryModuleMetadata>,
}

impl QueryModuleRegistry {
    /// Create a new registry with all modules registered
    pub fn new() -> Self {
        let mut registry = Self {
            modules: Vec::new(),
        };
        registry.register_all();
        registry
    }

    /// Register all query injection modules
    fn register_all(&mut self) {
        // NoSQL Injection Module
        self.modules.push(QueryModuleMetadata {
            name: "nosql_injection",
            description: "Detects NoSQL injection in MongoDB, CouchDB, and similar databases",
            injection_types: &["nosql_syntax", "nosql_operator"],
            risk_level: "Critical",
            enabled_by_default: true,
        });

        // ORM Injection Module
        self.modules.push(QueryModuleMetadata {
            name: "orm_injection",
            description: "Detects ORM injection in Hibernate, Prisma, Entity Framework",
            injection_types: &["orm_hql", "orm_prisma", "orm_ef"],
            risk_level: "Critical",
            enabled_by_default: true,
        });

        // SSTI Module
        self.modules.push(QueryModuleMetadata {
            name: "ssti",
            description: "Detects Server-Side Template Injection in various template engines",
            injection_types: &["ssti_twig", "ssti_jinja2", "ssti_freemarker", "ssti_thymeleaf"],
            risk_level: "Critical",
            enabled_by_default: true,
        });

        // Expression Language Module
        self.modules.push(QueryModuleMetadata {
            name: "el_injection",
            description: "Detects Expression Language injection (Java EL, SpEL, OGNL)",
            injection_types: &["el_java", "el_spel", "el_ognl"],
            risk_level: "Critical",
            enabled_by_default: true,
        });

        // XPath Injection Module
        self.modules.push(QueryModuleMetadata {
            name: "xpath_injection",
            description: "Detects XPath injection via boolean and error-based techniques",
            injection_types: &["xpath_boolean", "xpath_error", "xpath_blind"],
            risk_level: "High",
            enabled_by_default: true,
        });

        // LDAP Injection Module
        self.modules.push(QueryModuleMetadata {
            name: "ldap_injection",
            description: "Detects LDAP filter injection via wildcard and parenthesis manipulation",
            injection_types: &["ldap_parenthesis", "ldap_wildcard", "ldap_attribute"],
            risk_level: "High",
            enabled_by_default: true,
        });
    }

    /// Get all registered modules
    pub fn get_modules(&self) -> &[QueryModuleMetadata] {
        &self.modules
    }

    /// Get module by name
    pub fn get_module(&self, name: &str) -> Option<&QueryModuleMetadata> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// Check if a module is enabled by default
    pub fn is_enabled_by_default(&self, name: &str) -> bool {
        self.get_module(name)
            .map(|m| m.enabled_by_default)
            .unwrap_or(false)
    }

    /// Get total number of registered modules
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Get modules by risk level
    pub fn get_by_risk_level(&self, risk: &str) -> Vec<&QueryModuleMetadata> {
        self.modules
            .iter()
            .filter(|m| m.risk_level == risk)
            .collect()
    }

    /// Generate summary report of all modules
    pub fn summary(&self) -> String {
        let mut output = String::from("Query Language Injection Modules:\n");
        output.push_str(&"=".repeat(50));
        output.push('\n');

        for module in &self.modules {
            output.push_str(&format!(
                "\n[{}] {}\n  Description: {}\n  Types: {:?}\n  Risk: {}\n",
                if module.enabled_by_default { "✓" } else { "○" },
                module.name,
                module.description,
                module.injection_types,
                module.risk_level,
            ));
        }

        output.push_str(&"\n".to_owned());
        output.push_str(&format!("Total modules: {}", self.modules.len()));
        output
    }
}

impl Default for QueryModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Orchestrator binding interface for query injection checks
pub trait QueryInjectionCheck {
    /// Get the check name
    fn name(&self) -> &'static str;
    
    /// Run the check against provided input
    fn run(&self, target: &str, param: &str, value: &str) -> Vec<QueryCheckResult>;
    
    /// Get supported injection types
    fn supported_types(&self) -> &'static [&'static str];
}

/// Result from a query injection check
#[derive(Debug, Clone)]
pub struct QueryCheckResult {
    /// Injection type detected
    pub injection_type: &'static str,
    /// Parameter affected
    pub parameter: String,
    /// Payload that triggered detection
    pub payload: String,
    /// Confidence score
    pub confidence: f64,
    /// Evidence details
    pub evidence: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = QueryModuleRegistry::new();
        assert_eq!(registry.module_count(), 6);
    }

    #[test]
    fn test_get_module() {
        let registry = QueryModuleRegistry::new();
        
        let module = registry.get_module("nosql_injection");
        assert!(module.is_some());
        assert_eq!(module.unwrap().risk_level, "Critical");
    }

    #[test]
    fn test_get_by_risk_level() {
        let registry = QueryModuleRegistry::new();
        
        let critical = registry.get_by_risk_level("Critical");
        assert!(critical.len() >= 4);
        
        let high = registry.get_by_risk_level("High");
        assert!(high.len() >= 2);
    }

    #[test]
    fn test_summary_generation() {
        let registry = QueryModuleRegistry::new();
        let summary = registry.summary();
        
        assert!(summary.contains("Query Language Injection Modules"));
        assert!(summary.contains("Total modules: 6"));
    }
}
