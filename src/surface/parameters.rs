//! Parameter classification for query, body, header, cookie, and path parameters.
//!
//! This module categorizes discovered parameters for mutation engines.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Parameter location types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParamLocation {
    Query,
    Path,
    Header,
    Body,
    Cookie,
}

/// Parameter data type hints
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParamDataType {
    String,
    Integer,
    Float,
    Boolean,
    Array,
    Object,
    File,
    DateTime,
    Email,
    Url,
    Uuid,
    Unknown,
}

/// Security-relevant parameter categories
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParamSecurityCategory {
    Authentication,
    Authorization,
    Session,
    InputData,
    Control,
    FileOperation,
    CommandInjection,
    SqlRelated,
    XssRelated,
    SsrFRelated,
    None,
}

/// Discovered parameter with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredParameter {
    /// Parameter name
    pub name: String,
    /// Location in request
    pub location: ParamLocation,
    /// Inferred data type
    pub data_type: ParamDataType,
    /// Security category
    pub security_category: ParamSecurityCategory,
    /// Whether parameter is required
    pub required: bool,
    /// Observed values
    pub observed_values: Vec<String>,
    /// Default value if any
    pub default_value: Option<String>,
    /// Min/max length constraints
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    /// Numeric constraints
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    /// Pattern/regex constraint
    pub pattern: Option<String>,
    /// Associated routes
    pub routes: Vec<String>,
    /// Whether parameter appears sensitive
    pub is_sensitive: bool,
}

impl DiscoveredParameter {
    pub fn new(name: String, location: ParamLocation) -> Self {
        let security_category = Self::infer_security_category(&name);
        let data_type = Self::infer_data_type(&name);
        
        Self {
            name,
            location,
            data_type,
            security_category,
            required: false,
            observed_values: Vec::new(),
            default_value: None,
            min_length: None,
            max_length: None,
            min_value: None,
            max_value: None,
            pattern: None,
            routes: Vec::new(),
            is_sensitive: matches!(security_category, 
                ParamSecurityCategory::Authentication 
                | ParamSecurityCategory::Authorization 
                | ParamSecurityCategory::Session),
        }
    }

    /// Infer security category from parameter name
    fn infer_security_category(name: &str) -> ParamSecurityCategory {
        let lower = name.to_lowercase();
        
        // Authentication related
        if lower.contains("password") || lower.contains("passwd") || lower.contains("pwd") {
            return ParamSecurityCategory::Authentication;
        }
        if lower.contains("token") || lower.contains("auth") || lower.contains("api_key") || lower.contains("apikey") {
            return ParamSecurityCategory::Authentication;
        }
        
        // Authorization related
        if lower.contains("role") || lower.contains("permission") || lower.contains("scope") {
            return ParamSecurityCategory::Authorization;
        }
        
        // Session related
        if lower.contains("session") || lower.contains("sid") || lower.contains("cookie") {
            return ParamSecurityCategory::Session;
        }
        
        // SQL related
        if lower.contains("sql") || lower.contains("query") || lower.contains("select") {
            return ParamSecurityCategory::SqlRelated;
        }
        
        // XSS related
        if lower.contains("html") || lower.contains("script") || lower.contains("content") {
            return ParamSecurityCategory::XssRelated;
        }
        
        // SSRF related
        if lower.contains("url") || lower.contains("uri") || lower.contains("redirect") || lower.contains("fetch") {
            return ParamSecurityCategory::SsrFRelated;
        }
        
        // Command injection
        if lower.contains("cmd") || lower.contains("exec") || lower.contains("shell") {
            return ParamSecurityCategory::CommandInjection;
        }
        
        // File operations
        if lower.contains("file") || lower.contains("path") || lower.contains("upload") {
            return ParamSecurityCategory::FileOperation;
        }
        
        // Control parameters
        if lower.contains("action") || lower.contains("op") || lower.contains("do") {
            return ParamSecurityCategory::Control;
        }
        
        ParamSecurityCategory::None
    }

    /// Infer data type from parameter name and context
    fn infer_data_type(name: &str) -> ParamDataType {
        let lower = name.to_lowercase();
        
        if lower.contains("email") {
            return ParamDataType::Email;
        }
        if lower.contains("url") || lower.contains("uri") {
            return ParamDataType::Url;
        }
        if lower.contains("id") && !lower.contains("valid") {
            return ParamDataType::Uuid; // Could be integer or UUID
        }
        if lower.contains("count") || lower.contains("num") || lower.contains("amount") {
            return ParamDataType::Integer;
        }
        if lower.contains("price") || lower.contains("rate") || lower.contains("ratio") {
            return ParamDataType::Float;
        }
        if lower.contains("date") || lower.contains("time") || lower.contains("created") {
            return ParamDataType::DateTime;
        }
        if lower.contains("flag") || lower.contains("enabled") || lower.contains("active") {
            return ParamDataType::Boolean;
        }
        if lower.ends_with("s") || lower.contains("list") || lower.contains("array") {
            return ParamDataType::Array;
        }
        
        ParamDataType::String
    }

    /// Add an observed value
    pub fn observe_value(&mut self, value: String) {
        if !self.observed_values.contains(&value) {
            self.observed_values.push(value);
            
            // Update type inference based on value
            self.update_type_from_value(&value);
        }
    }

    /// Update type inference from observed value
    fn update_type_from_value(&mut self, value: &str) {
        // Try to detect UUID
        if value.len() == 36 && value.chars().filter(|c| *c == '-').count() == 4 {
            self.data_type = ParamDataType::Uuid;
        }
        
        // Try to detect integer
        if value.parse::<i64>().is_ok() && self.data_type == ParamDataType::Unknown {
            self.data_type = ParamDataType::Integer;
        }
        
        // Try to detect float
        if value.parse::<f64>().is_ok() && self.data_type == ParamDataType::Unknown {
            self.data_type = ParamDataType::Float;
        }
        
        // Try to detect boolean
        if matches!(value.to_lowercase().as_str(), "true" | "false" | "1" | "0") {
            self.data_type = ParamDataType::Boolean;
        }
        
        // Detect email
        if value.contains('@') && value.contains('.') {
            self.data_type = ParamDataType::Email;
        }
        
        // Detect URL
        if value.starts_with("http://") || value.starts_with("https://") {
            self.data_type = ParamDataType::Url;
        }
    }

    /// Generate mutation payloads for this parameter
    pub fn mutation_payloads(&self) -> Vec<MutationPayload> {
        let mut payloads = Vec::new();
        
        match self.security_category {
            ParamSecurityCategory::Authentication => {
                payloads.extend(self.auth_mutations());
            }
            ParamSecurityCategory::SqlRelated => {
                payloads.extend(self.sql_mutations());
            }
            ParamSecurityCategory::XssRelated => {
                payloads.extend(self.xss_mutations());
            }
            ParamSecurityCategory::SsrFRelated => {
                payloads.extend(self.ssrf_mutations());
            }
            ParamSecurityCategory::CommandInjection => {
                payloads.extend(self.cmd_mutations());
            }
            _ => {
                payloads.extend(self.generic_mutations());
            }
        }
        
        payloads
    }

    /// Authentication-focused mutations
    fn auth_mutations(&self) -> Vec<MutationPayload> {
        vec![
            MutationPayload::new(&self.name, "' OR '1'='1"),
            MutationPayload::new(&self.name, "admin"),
            MutationPayload::new(&self.name, "root"),
            MutationPayload::new(&self.name, "' OR 1=1 --"),
            MutationPayload::new(&self.name, "{{7*7}}"), // SSTI
        ]
    }

    /// SQL injection mutations
    fn sql_mutations(&self) -> Vec<MutationPayload> {
        vec![
            MutationPayload::new(&self.name, "' OR '1'='1"),
            MutationPayload::new(&self.name, "1; DROP TABLE users--"),
            MutationPayload::new(&self.name, "1 UNION SELECT NULL--"),
            MutationPayload::new(&self.name, "1' AND '1'='1"),
            MutationPayload::new(&self.name, "admin'--"),
        ]
    }

    /// XSS mutations
    fn xss_mutations(&self) -> Vec<MutationPayload> {
        vec![
            MutationPayload::new(&self.name, "<script>alert(1)</script>"),
            MutationPayload::new(&self.name, "<img src=x onerror=alert(1)>"),
            MutationPayload::new(&self.name, "\"><script>alert(1)</script>"),
            MutationPayload::new(&self.name, "javascript:alert(1)"),
        ]
    }

    /// SSRF mutations
    fn ssrf_mutations(&self) -> Vec<MutationPayload> {
        vec![
            MutationPayload::new(&self.name, "http://127.0.0.1"),
            MutationPayload::new(&self.name, "http://localhost"),
            MutationPayload::new(&self.name, "http://169.254.169.254"), // AWS metadata
            MutationPayload::new(&self.name, "file:///etc/passwd"),
            MutationPayload::new(&self.name, "gopher://127.0.0.1:6379/_"),
        ]
    }

    /// Command injection mutations
    fn cmd_mutations(&self) -> Vec<MutationPayload> {
        vec![
            MutationPayload::new(&self.name, "; id"),
            MutationPayload::new(&self.name, "| id"),
            MutationPayload::new(&self.name, "`id`"),
            MutationPayload::new(&self.name, "$(id)"),
            MutationPayload::new(&self.name, "&& id"),
        ]
    }

    /// Generic mutations for unknown parameters
    fn generic_mutations(&self) -> Vec<MutationPayload> {
        vec![
            MutationPayload::new(&self.name, ""),
            MutationPayload::new(&self.name, "null"),
            MutationPayload::new(&self.name, "undefined"),
            MutationPayload::new(&self.name, "{}"),
            MutationPayload::new(&self.name, "[]"),
            MutationPayload::new(&self.name, "'"),
            MutationPayload::new(&self.name, "\""),
            MutationPayload::new(&self.name, "<>"),
            MutationPayload::new(&self.name, "%00"), // Null byte
        ]
    }
}

/// Mutation payload for testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationPayload {
    pub param_name: String,
    pub test_value: String,
    pub attack_type: String,
    pub description: String,
}

impl MutationPayload {
    pub fn new(param_name: &str, test_value: &str) -> Self {
        Self {
            param_name: param_name.to_string(),
            test_value: test_value.to_string(),
            attack_type: "generic".to_string(),
            description: format!("Test {} with {}", param_name, test_value),
        }
    }

    pub fn with_type(mut self, attack_type: &str) -> Self {
        self.attack_type = attack_type.to_string();
        self
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }
}

/// Parameter catalog for organizing discovered parameters
#[derive(Debug, Default)]
pub struct ParameterCatalog {
    parameters: HashMap<String, DiscoveredParameter>,
    by_location: HashMap<ParamLocation, Vec<String>>,
    by_security: HashMap<ParamSecurityCategory, Vec<String>>,
}

impl ParameterCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a parameter
    pub fn add(&mut self, param: DiscoveredParameter) {
        let key = format!("{:?}:{}", param.location, param.name);
        
        self.by_location.entry(param.location).or_default().push(key.clone());
        self.by_security.entry(param.security_category.clone()).or_default().push(key.clone());
        
        self.parameters.insert(key, param);
    }

    /// Get all parameters
    pub fn all_parameters(&self) -> Vec<&DiscoveredParameter> {
        self.parameters.values().collect()
    }

    /// Get sensitive parameters
    pub fn sensitive_parameters(&self) -> Vec<&DiscoveredParameter> {
        self.parameters.values()
            .filter(|p| p.is_sensitive)
            .collect()
    }

    /// Get parameters by security category
    pub fn by_security_category(&self, category: &ParamSecurityCategory) -> Vec<&DiscoveredParameter> {
        self.by_security.get(category)
            .map(|keys| keys.iter().filter_map(|k| self.parameters.get(k)).collect())
            .unwrap_or_default()
    }

    /// Get statistics
    pub fn stats(&self) -> ParameterStats {
        ParameterStats {
            total: self.parameters.len(),
            query_params: self.by_location.get(&ParamLocation::Query).map(|v| v.len()).unwrap_or(0),
            path_params: self.by_location.get(&ParamLocation::Path).map(|v| v.len()).unwrap_or(0),
            header_params: self.by_location.get(&ParamLocation::Header).map(|v| v.len()).unwrap_or(0),
            body_params: self.by_location.get(&ParamLocation::Body).map(|v| v.len()).unwrap_or(0),
            cookie_params: self.by_location.get(&ParamLocation::Cookie).map(|v| v.len()).unwrap_or(0),
            sensitive_count: self.sensitive_parameters().len(),
        }
    }
}

/// Parameter statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParameterStats {
    pub total: usize,
    pub query_params: usize,
    pub path_params: usize,
    pub header_params: usize,
    pub body_params: usize,
    pub cookie_params: usize,
    pub sensitive_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_category_inference() {
        assert_eq!(
            DiscoveredParameter::infer_security_category("password"),
            ParamSecurityCategory::Authentication
        );
        assert_eq!(
            DiscoveredParameter::infer_security_category("user_id"),
            ParamSecurityCategory::None
        );
        assert_eq!(
            DiscoveredParameter::infer_security_category("redirect_url"),
            ParamSecurityCategory::SsrFRelated
        );
    }

    #[test]
    fn test_parameter_creation() {
        let param = DiscoveredParameter::new("username".to_string(), ParamLocation::Body);
        assert_eq!(param.name, "username");
        assert_eq!(param.location, ParamLocation::Body);
    }

    #[test]
    fn test_mutation_payloads() {
        let mut param = DiscoveredParameter::new("search".to_string(), ParamLocation::Query);
        param.observe_value("test".to_string());
        
        let payloads = param.mutation_payloads();
        assert!(!payloads.is_empty());
    }
}
