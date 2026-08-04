//! Parameter Injection - Targeted mutations for various parameter types
//!
//! Generates mutations specifically tailored for query parameters, body parameters,
//! cookies, headers, path segments, and multipart form data.

use crate::payload::{GeneratedPayload, PayloadClass, Severity, SafetyLevel, InjectionContext};
use std::collections::HashMap;

/// Parameter location types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamLocation {
    Query,
    BodyForm,
    BodyJson,
    BodyXml,
    Header,
    Cookie,
    Path,
    Multipart,
}

impl ParamLocation {
    pub fn as_str(&self) -> &'static str {
        match self {
            ParamLocation::Query => "query",
            ParamLocation::BodyForm => "body_form",
            ParamLocation::BodyJson => "body_json",
            ParamLocation::BodyXml => "body_xml",
            ParamLocation::Header => "header",
            ParamLocation::Cookie => "cookie",
            ParamLocation::Path => "path",
            ParamLocation::Multipart => "multipart",
        }
    }

    pub fn to_injection_context(&self) -> InjectionContext {
        match self {
            ParamLocation::Query => InjectionContext::UrlQuery,
            ParamLocation::BodyForm => InjectionContext::BodyForm,
            ParamLocation::BodyJson => InjectionContext::BodyJson,
            ParamLocation::BodyXml => InjectionContext::BodyXml,
            ParamLocation::Header => InjectionContext::Header,
            ParamLocation::Cookie => InjectionContext::Cookie,
            ParamLocation::Path => InjectionContext::UrlPath,
            ParamLocation::Multipart => InjectionContext::BodyMultipart,
        }
    }
}

/// Parameter definition with metadata
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub value: String,
    pub location: ParamLocation,
    pub param_type: ParamType,
    pub constraints: Vec<ParamConstraint>,
}

impl Parameter {
    pub fn new(name: impl Into<String>, value: impl Into<String>, location: ParamLocation) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            location,
            param_type: ParamType::String,
            constraints: Vec::new(),
        }
    }

    pub fn with_type(mut self, param_type: ParamType) -> Self {
        self.param_type = param_type;
        self
    }

    pub fn with_constraint(mut self, constraint: ParamConstraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    pub fn get_context(&self) -> InjectionContext {
        self.location.to_injection_context()
    }
}

/// Parameter data types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    String,
    Integer,
    Float,
    Boolean,
    Array,
    Object,
    File,
}

/// Parameter constraints
#[derive(Debug, Clone)]
pub enum ParamConstraint {
    MinLength(usize),
    MaxLength(usize),
    MinValue(f64),
    MaxValue(f64),
    Pattern(String),
    Enum(Vec<String>),
    Required,
}

/// Parameter mutator for generating targeted payloads
#[derive(Debug, Default)]
pub struct ParameterMutator {
    /// Custom payloads per parameter name
    custom_payloads: HashMap<String, Vec<GeneratedPayload>>,
}

impl ParameterMutator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate payloads for a specific parameter
    pub fn generate_for_parameter(&self, param: &Parameter) -> Vec<GeneratedPayload> {
        let mut payloads = Vec::new();

        // Check for custom payloads first
        if let Some(custom) = self.custom_payloads.get(&param.name) {
            payloads.extend(custom.clone());
        }

        // Generate based on parameter type
        match param.param_type {
            ParamType::Integer => payloads.extend(self.integer_payloads(&param.name)),
            ParamType::Float => payloads.extend(self.float_payloads(&param.name)),
            ParamType::Boolean => payloads.extend(self.boolean_payloads(&param.name)),
            ParamType::String => payloads.extend(self.string_payloads(param)),
            ParamType::Array => payloads.extend(self.array_payloads(&param.name)),
            ParamType::Object => payloads.extend(self.object_payloads(&param.name)),
            ParamType::File => payloads.extend(self.file_payloads(&param.name)),
        }

        // Apply location-specific transformations
        for payload in &mut payloads {
            payload.context = param.get_context();
        }

        payloads
    }

    /// Generate integer boundary payloads
    fn integer_payloads(&self, param_name: &str) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(format!("{}-int-0", param_name), "0", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-int-1", param_name), "1", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-int-neg", param_name), "-1", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-int-max", param_name), "2147483647", PayloadClass::LogicFlaw, Severity::Medium, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-int-min", param_name), "-2147483648", PayloadClass::LogicFlaw, Severity::Medium, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-int-overflow", param_name), "9223372036854775808", PayloadClass::LogicFlaw, Severity::Medium, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-int-null", param_name), "null", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-int-empty", param_name), "", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
        ]
    }

    /// Generate float boundary payloads
    fn float_payloads(&self, param_name: &str) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(format!("{}-float-zero", param_name), "0.0", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-float-nan", param_name), "NaN", PayloadClass::LogicFlaw, Severity::Medium, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-float-inf", param_name), "Infinity", PayloadClass::LogicFlaw, Severity::Medium, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-float-neginf", param_name), "-Infinity", PayloadClass::LogicFlaw, Severity::Medium, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-float-scientific", param_name), "1e308", PayloadClass::LogicFlaw, Severity::Medium, SafetyLevel::Safe),
        ]
    }

    /// Generate boolean manipulation payloads
    fn boolean_payloads(&self, param_name: &str) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(format!("{}-bool-true", param_name), "true", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-bool-false", param_name), "false", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-bool-1", param_name), "1", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-bool-0", param_name), "0", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-bool-yes", param_name), "yes", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-bool-no", param_name), "no", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-bool-on", param_name), "on", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-bool-off", param_name), "off", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
        ]
    }

    /// Generate string injection payloads
    fn string_payloads(&self, param: &Parameter) -> Vec<GeneratedPayload> {
        let name = &param.name;
        
        // Include SQL injection variants
        let mut payloads = vec![
            GeneratedPayload::new(format!("{}-sqli-1", name), "' OR '1'='1", PayloadClass::SqlInjection, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new(format!("{}-sqli-2", name), "'; DROP TABLE test--", PayloadClass::SqlInjection, Severity::Critical, SafetyLevel::Dangerous),
            GeneratedPayload::new(format!("{}-sqli-3", name), "1 UNION SELECT NULL", PayloadClass::SqlInjection, Severity::High, SafetyLevel::Unsafe),
            
            // XSS variants
            GeneratedPayload::new(format!("{}-xss-1", name), "<script>alert(1)</script>", PayloadClass::Xss, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new(format!("{}-xss-2", name), "<img src=x onerror=alert(1)>", PayloadClass::Xss, Severity::High, SafetyLevel::Unsafe),
            
            // Path traversal
            GeneratedPayload::new(format!("{}-traversal-1", name), "../../../etc/passwd", PayloadClass::PathTraversal, Severity::High, SafetyLevel::Unsafe),
            
            // Command injection
            GeneratedPayload::new(format!("{}-cmdi-1", name), "; ls", PayloadClass::CommandInjection, Severity::High, SafetyLevel::Unsafe),
        ];

        // Set context based on parameter location
        for payload in &mut payloads {
            payload.context = param.get_context();
        }

        payloads
    }

    /// Generate array manipulation payloads
    fn array_payloads(&self, param_name: &str) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(format!("{}-arr-empty", param_name), "[]", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-arr-null", param_name), "null", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-arr-string", param_name), "[\"test\"]", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-arr-mixed", param_name), "[1,\"test\",null,true]", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-arr-nested", param_name), "[[[]]]", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
        ]
    }

    /// Generate object manipulation payloads
    fn object_payloads(&self, param_name: &str) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(format!("{}-obj-empty", param_name), "{}", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-obj-null", param_name), "null", PayloadClass::LogicFlaw, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-obj-proto", param_name), "{\"__proto__\":{}}", PayloadClass::Deserialization, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new(format!("{}-obj-constructor", param_name), "{\"constructor\":{\"prototype\":{\"polluted\":true}}}", PayloadClass::Deserialization, Severity::High, SafetyLevel::Unsafe),
        ]
    }

    /// Generate file upload payloads
    fn file_payloads(&self, param_name: &str) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(format!("{}-file-null", param_name), "null", PayloadClass::FileUpload, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-file-empty", param_name), "", PayloadClass::FileUpload, Severity::Low, SafetyLevel::Safe),
            GeneratedPayload::new(format!("{}-file-traversal", param_name), "../../../etc/passwd", PayloadClass::PathTraversal, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new(format!("{}-file-php", param_name), "shell.php", PayloadClass::FileUpload, Severity::Critical, SafetyLevel::Dangerous),
        ]
    }

    /// Register custom payloads for a parameter name
    pub fn register_custom(&mut self, param_name: &str, payloads: Vec<GeneratedPayload>) {
        self.custom_payloads.insert(param_name.to_string(), payloads);
    }

    /// Generate header injection payloads
    pub fn generate_header_payloads(&self, header_name: &str) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(format!("hdr-{}", header_name), "test\r\nX-Injected: true", PayloadClass::HeaderInjection, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new(format!("hdr-crlf-{}", header_name), "test%0d%0aX-Injected: true", PayloadClass::HeaderInjection, Severity::High, SafetyLevel::Unsafe),
        ]
    }

    /// Generate cookie manipulation payloads
    pub fn generate_cookie_payloads(&self, cookie_name: &str) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(format!("cookie-{}", cookie_name), "deleted", PayloadClass::AuthBypass, Severity::Medium, SafetyLevel::LowRisk),
            GeneratedPayload::new(format!("cookie-overflow-{}", cookie_name), "A".repeat(10000), PayloadClass::LogicFlaw, Severity::Medium, SafetyLevel::Safe),
            GeneratedPayload::new(format!("cookie-json-{}", cookie_name), "{\"admin\":true}", PayloadClass::Deserialization, Severity::High, SafetyLevel::Unsafe),
        ]
    }
}

/// Request builder for parameter injection
#[derive(Debug, Default)]
pub struct RequestBuilder {
    parameters: Vec<Parameter>,
}

impl RequestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_parameter(mut self, param: Parameter) -> Self {
        self.parameters.push(param);
        self
    }

    pub fn add_query_param(mut self, name: &str, value: &str) -> Self {
        self.parameters.push(Parameter::new(name, value, ParamLocation::Query));
        self
    }

    pub fn add_header(mut self, name: &str, value: &str) -> Self {
        self.parameters.push(Parameter::new(name, value, ParamLocation::Header));
        self
    }

    pub fn add_cookie(mut self, name: &str, value: &str) -> Self {
        self.parameters.push(Parameter::new(name, value, ParamLocation::Cookie));
        self
    }

    pub fn get_parameters(&self) -> &[Parameter] {
        &self.parameters
    }

    pub fn clear(&mut self) {
        self.parameters.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_creation() {
        let param = Parameter::new("id", "1", ParamLocation::Query)
            .with_type(ParamType::Integer);
        
        assert_eq!(param.name, "id");
        assert_eq!(param.param_type, ParamType::Integer);
    }

    #[test]
    fn test_integer_payloads() {
        let mutator = ParameterMutator::new();
        let payloads = mutator.integer_payloads("count");
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.raw == "0"));
        assert!(payloads.iter().any(|p| p.raw == "-1"));
    }

    #[test]
    fn test_boolean_payloads() {
        let mutator = ParameterMutator::new();
        let payloads = mutator.boolean_payloads("enabled");
        
        assert!(payloads.iter().any(|p| p.raw == "true"));
        assert!(payloads.iter().any(|p| p.raw == "false"));
    }

    #[test]
    fn test_request_builder() {
        let builder = RequestBuilder::new()
            .add_query_param("id", "1")
            .add_header("X-Custom", "value")
            .add_cookie("session", "abc123");
        
        assert_eq!(builder.get_parameters().len(), 3);
    }
}
