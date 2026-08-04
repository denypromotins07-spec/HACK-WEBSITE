//! SAML/SSO Security Detection Module
//!
//! Detects SAML assertion forgery, XML comment injection, and signature stripping.
//! Uses bounded XML parsers to prevent Billion Laughs DoS during testing.
//! Implements strict validation for SAML assertions and SSO flows.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory,
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum XML entity expansion depth (prevents Billion Laughs)
const MAX_XML_DEPTH: usize = 4;

/// Maximum XML entity count (bounded parser constraint)
const MAX_XML_ENTITIES: usize = 64;

/// Maximum SAML assertion size in bytes
const MAX_SAML_SIZE: usize = 8192;

/// Bounded XML parser state
#[derive(Debug, Clone)]
struct BoundedXmlParser {
    depth: usize,
    entity_count: usize,
    total_size: usize,
}

impl BoundedXmlParser {
    fn new() -> Self {
        Self {
            depth: 0,
            entity_count: 0,
            total_size: 0,
        }
    }

    fn validate(&self, xml: &str) -> Result<(), &'static str> {
        if xml.len() > MAX_SAML_SIZE {
            return Err("XML exceeds maximum size limit");
        }

        // Count nested elements for depth
        let mut current_depth = 0;
        let mut max_depth = 0;
        for ch in xml.chars() {
            match ch {
                '<' => current_depth += 1,
                '>' => current_depth = current_depth.saturating_sub(1),
                _ => {}
            }
            max_depth = max_depth.max(current_depth);
        }

        if max_depth > MAX_XML_DEPTH {
            return Err("XML nesting depth exceeds limit (possible Billion Laughs)");
        }

        // Count entity references
        let entity_count = xml.matches("&").count();
        if entity_count > MAX_XML_ENTITIES {
            return Err("Too many entity references (possible XXE attack)");
        }

        Ok(())
    }

    /// Detect XML comment injection patterns
    fn detect_comment_injection(&self, xml: &str) -> Option<&'static str> {
        let patterns = [
            ("<!--", "XML comment start detected"),
            ("-->", "XML comment end detected"),
            ("<!ENTITY", "Entity declaration detected"),
            ("SYSTEM", "External entity reference detected"),
            ("PUBLIC", "Public entity reference detected"),
        ];

        for (pattern, desc) in &patterns {
            if xml.contains(pattern) {
                return Some(*desc);
            }
        }

        None
    }

    /// Detect signature stripping attempts
    fn detect_signature_issues(&self, xml: &str) -> Option<&'static str> {
        // Check for missing or malformed signatures
        if !xml.contains("<ds:Signature") && !xml.contains("<Signature") {
            return Some("Missing XML signature");
        }

        // Check for commented-out signatures
        if xml.contains("<!--") && xml.contains("Signature") {
            return Some("Signature may be commented out");
        }

        // Check for signature wrapping
        if xml.matches("<Signature").count() > 1 {
            return Some("Multiple signatures detected (possible signature wrapping)");
        }

        None
    }
}

/// SAML/SSO security detector
pub struct SamlSsoDetector {
    metadata: CheckMetadata,
    parser: BoundedXmlParser,
}

impl SamlSsoDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "auth/sso_saml",
            "SAML/SSO Security Detection",
            "Detects SAML assertion forgery, XML comment injection, and signature stripping",
            Severity::Critical,
            CheckCategory::BrokenAuthentication,
        )
        .with_god_mode(true)
        .with_tags(vec!["saml", "sso", "xml-injection", "signature-wrapping", "authentication"])
        .with_references(vec![
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_SAML",
            "https://cwe.mitre.org/data/definitions/347.html",
            "https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-somorovsky.pdf",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1000,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 50,
            max_duration_ms: 5000,
            max_payload_size: 8192,
        });

        Self {
            metadata,
            parser: BoundedXmlParser::new(),
        }
    }

    /// Generate SAML assertion forgery payloads (bounded dictionary)
    fn generate_saml_payloads(&self) -> &'static [&'static str] {
        static PAYLOADS: &[&str] = &[
            // Comment injection
            r#"<saml:Assertion><!-- COMMENT --><saml:Subject>admin</saml:Subject></saml:Assertion>"#,
            // Entity expansion (Billion Lauchs lite)
            r#"<!DOCTYPE foo [<!ENTITY xxe "test">]><foo>&xxe;</foo>"#,
            // Signature wrapping
            r#"<Response><Assertion ID="legit"><Signature>valid</Signature></Assertion><Assertion ID="evil">injected</Assertion></Response>"#,
            // Missing signature
            r#"<saml:Assertion><saml:Subject>attacker</saml:Subject></saml:Assertion>"#,
            // Algorithm confusion
            r#"<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#none"/>"#,
        ];
        PAYLOADS
    }

    /// Test SAML endpoint with forged assertion
    async fn test_saml_endpoint(
        &self,
        client: &HttpClient,
        url: &str,
        payload: &str,
    ) -> Result<Option<&'static str>, ModuleError> {
        // Validate payload with bounded parser first
        if let Err(e) = self.parser.validate(payload) {
            return Ok(Some(e)); // Parser detected issue
        }

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/saml+xml"),
        );

        let response = client.post_raw_with_headers(url, headers, payload.as_bytes()).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        // Analyze response for vulnerabilities
        if status == 200 || status == 302 {
            // Successful authentication with potentially forged SAML
            if let Some(issue) = self.parser.detect_signature_issues(payload) {
                return Ok(Some(issue));
            }
        }

        // Check error messages for information disclosure
        let body_lower = body.to_lowercase();
        if body_lower.contains("signature") || body_lower.contains("invalid assertion") {
            return Ok(Some("Verbose error message reveals SAML validation logic"));
        }

        Ok(None)
    }

    /// Test for XML comment injection
    async fn test_comment_injection(
        &self,
        client: &HttpClient,
        url: &str,
    ) -> Result<bool, ModuleError> {
        let comment_payload = r#"<saml:Assertion><!--<saml:Condition>valid</saml:Condition>--><saml:Subject>admin</saml:Subject></saml:Assertion>"#;
        
        if let Err(e) = self.parser.validate(comment_payload) {
            return Ok(false); // Parser blocked it
        }

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/saml+xml"),
        );

        let response = client.post_raw_with_headers(url, headers, comment_payload.as_bytes()).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let body = response.text().await.unwrap_or_default();
        
        // If comment was processed (not reflected), potential vulnerability
        Ok(!body.contains("<!--") && response.status().is_success())
    }

    /// Build evidence for SAML finding
    fn build_evidence(&self, url: &str, issue: &str, payload: &str) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::HttpRequestResponse {
                    request: format!("POST {} HTTP/1.1\nContent-Type: application/saml+xml\n\n{}", url, payload),
                    response: format!("Issue: {}", issue),
                },
                data: issue.to_string(),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: None,
                    header: Some("SAML Assertion".to_string()),
                },
                confidence: 80,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self, issue_type: &str) -> RemediationHint {
        let (summary, steps) = match issue_type {
            "signature" => (
                "Implement proper SAML signature validation".to_string(),
                vec![
                    "Validate XML signatures using a trusted library".to_string(),
                    "Ensure signature is present and valid before processing".to_string(),
                    "Implement signature wrapping detection".to_string(),
                    "Use allowlists for acceptable signature algorithms".to_string(),
                ],
            ),
            "comment" => (
                "Sanitize XML input and reject comments".to_string(),
                vec![
                    "Strip or reject XML comments in SAML assertions".to_string(),
                    "Use a secure XML parser that disables DTDs".to_string(),
                    "Implement strict schema validation".to_string(),
                ],
            ),
            "xxe" => (
                "Disable external entity processing".to_string(),
                vec![
                    "Configure XML parser to disable DTDs and external entities".to_string(),
                    "Use entity expansion limits".to_string(),
                    "Implement input size limits".to_string(),
                ],
            ),
            _ => (
                "Review SAML implementation security".to_string(),
                vec![
                    "Use established SAML libraries".to_string(),
                    "Follow OWASP SAML security guidelines".to_string(),
                    "Implement comprehensive logging".to_string(),
                ],
            ),
        };

        RemediationHint {
            summary,
            steps,
            code_example: Some(r#"// Java XML Security Example
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);"#.to_string()),
            references: vec![
                "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html".to_string(),
                "https://owasp.org/www-project-web-security-testing-guide/".to_string(),
            ],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for SamlSsoDetector {
    async fn init(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    fn should_run(&self, ctx: &CheckContext) -> bool {
        if self.metadata.requires_god_mode && !ctx.god_mode {
            return false;
        }
        true
    }

    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let client = HttpClient::new();
        let mut findings = Vec::new();
        let mut executed = false;

        let base_url = ctx.target_url.trim_end_matches('/');

        // Common SAML endpoints
        let saml_endpoints = [
            "/saml/acs",
            "/saml/SAMLConsumerService",
            "/api/saml/validate",
            "/auth/saml",
            "/sso/saml",
            "/identity/saml",
        ];

        for endpoint in saml_endpoints.iter() {
            let url = format!("{}{}", base_url, endpoint);

            // Test with forged SAML payloads
            for payload in self.generate_saml_payloads() {
                if let Ok(Some(issue)) = self.test_saml_endpoint(&client, &url, payload).await {
                    executed = true;

                    let severity = if issue.contains("Missing") || issue.contains("wrapping") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    let issue_type = if issue.contains("signature") || issue.contains("Signature") {
                        "signature"
                    } else if issue.contains("comment") || issue.contains("COMMENT") {
                        "comment"
                    } else if issue.contains("entity") || issue.contains("XXE") {
                        "xxe"
                    } else {
                        "other"
                    };

                    let mut finding = Finding::new(
                        self.metadata.id.as_str(),
                        severity,
                        format!("SAML Vulnerability: {}", issue),
                        format!("SAML assertion vulnerability detected at {}: {}", url, issue),
                        &url,
                    )
                    .with_payload(payload[..payload.len().min(200)].to_string())
                    .with_confidence(75)
                    .with_agent_id(ctx.agent_id)
                    .with_tags(vec!["saml", "sso", "authentication-bypass"]);

                    let evidence = self.build_evidence(&url, issue, payload);
                    for ev in evidence {
                        finding = finding.with_evidence(ev);
                    }

                    finding = finding.with_remediation(self.remediation(issue_type));
                    findings.push(finding);
                }
            }

            // Test comment injection specifically
            if let Ok(is_vulnerable) = self.test_comment_injection(&client, &url).await {
                if is_vulnerable {
                    executed = true;

                    let mut finding = Finding::new(
                        self.metadata.id.as_str(),
                        Severity::High,
                        "XML Comment Injection in SAML",
                        format!("SAML endpoint at {} processes XML comments", url),
                        &url,
                    )
                    .with_confidence(70)
                    .with_agent_id(ctx.agent_id)
                    .with_tags(vec!["xml-injection", "saml"]);

                    finding = finding.with_remediation(self.remediation("comment"));
                    findings.push(finding);
                }
            }
        }

        // Cache successful bypasses for learning engine
        if !findings.is_empty() {
            if let Ok(cache) = LearningCache::global().await {
                cache.cache_bypass_header(ctx.target_url.clone(), "saml_forgery".to_string()).await;
            }
        }

        Ok(CheckResult {
            findings,
            executed,
            timed_out: false,
            resource_usage: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_xml_parser() {
        let parser = BoundedXmlParser::new();
        
        // Valid small XML
        assert!(parser.validate("<root><child/></root>").is_ok());
        
        // Too deep nesting
        let deep_xml = "<a>".repeat(MAX_XML_DEPTH + 2) + &"</a>".repeat(MAX_XML_DEPTH + 2);
        assert!(parser.validate(&deep_xml).is_err());
        
        // Too many entities
        let many_entities: String = "&amp;".repeat(MAX_XML_ENTITIES + 1);
        assert!(parser.validate(&many_entities).is_err());
    }

    #[test]
    fn test_comment_detection() {
        let parser = BoundedXmlParser::new();
        
        assert!(parser.detect_comment_injection("<!-- comment -->").is_some());
        assert!(parser.detect_comment_injection("<!ENTITY xxe 'test'>").is_some());
        assert!(parser.detect_comment_injection("<root>safe</root>").is_none());
    }

    #[test]
    fn test_signature_detection() {
        let parser = BoundedXmlParser::new();
        
        assert!(parser.detect_signature_issues("<root>no signature</root>").is_some());
        assert!(parser.detect_signature_issues("<Signature>one</Signature>").is_none());
    }
}
