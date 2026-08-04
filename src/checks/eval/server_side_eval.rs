//! Server-Side Code Evaluation Detection Module
//!
//! Detects server-side code evaluation via math equation injection (e.g., print(7*7))
//! and safe canaries. Implements bounded payload execution with strict timeouts.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory,
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum evaluation payloads (bounded)
const MAX_EVAL_PAYLOADS: usize = 24;

/// Math-based evaluation payloads for different languages
#[derive(Debug, Clone)]
struct EvalPayloadSet {
    payloads: [(&'static str, &'static str, &'static str); MAX_EVAL_PAYLOADS],
    count: usize,
}

impl EvalPayloadSet {
    fn new() -> Self {
        Self {
            payloads: [
                // PHP
                ("{{7*7}}", "49", "PHP template"),
                ("${7*7}", "49", "PHP variable expansion"),
                ("<?php print(7*7); ?>", "49", "PHP code"),
                ("<?=7*7?>", "49", "PHP short tag"),
                // Python
                ("{{7*7}}", "49", "Python Jinja2"),
                ("${7*7}", "49", "Python string format"),
                ("__import__('os').popen('id').read()", "", "Python RCE"),
                ("eval('7*7')", "49", "Python eval"),
                // Java
                ("${7*7}", "49", "Java EL"),
                ("#{7*7}", "49", "Java OGNL"),
                ("<%= 7*7 %>", "49", "JSP expression"),
                // Ruby
                ("<%= 7*7 %>", "49", "ERB template"),
                ("#{7*7}", "49", "Ruby interpolation"),
                // JavaScript/Node
                ("{{7*7}}", "49", "Handlebars"),
                ("${7*7}", "49", "Template literal"),
                ("require('child_process').exec('id')", "", "Node RCE"),
                // .NET
                ("@{7*7}", "49", "Razor"),
                ("<%= 7*7 %>", "49", "ASP.NET"),
                // Generic
                ("7*7", "49", "Math expression"),
                ("print(7*7)", "49", "Print function"),
                ("echo 7*7", "49", "Echo command"),
                ("expr 7 \\* 7", "49", "Shell expr"),
                // Time-based (for blind detection)
                ("sleep(5)", "", "Time delay"),
                ("ping -c 5 127.0.0.1", "", "Ping delay"),
            ],
            count: MAX_EVAL_PAYLOADS,
        }
    }

    fn iter(&self) -> impl Iterator<Item = &(&'static str, &'static str, &'static str)> {
        self.payloads[..self.count].iter()
    }
}

/// Server-side evaluation detector
pub struct ServerSideEvalDetector {
    metadata: CheckMetadata,
    payload_set: EvalPayloadSet,
}

impl ServerSideEvalDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "eval/server_side_eval",
            "Server-Side Code Evaluation Detection",
            "Detects server-side code evaluation via math equation injection and safe canaries",
            Severity::Critical,
            CheckCategory::RemoteCodeExecution,
        )
        .with_god_mode(true)
        .with_tags(vec!["rce", "ssti", "code-injection", "evaluation"])
        .with_references(vec![
            "https://owasp.org/www-community/attacks/Code_Injection",
            "https://cwe.mitre.org/data/definitions/94.html",
            "https://portswigger.net/web-security/server-side-template-injection",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 2000,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 100,
            max_duration_ms: 10000,
            max_payload_size: 2048,
        });

        Self {
            metadata,
            payload_set: EvalPayloadSet::new(),
        }
    }

    /// Test single evaluation payload
    async fn test_eval_payload(
        &self,
        client: &HttpClient,
        url: &str,
        param: &str,
        payload: &str,
        expected: &str,
    ) -> Result<Option<&'static str>, ModuleError> {
        let mut form_data = Vec::new();
        form_data.push((param, payload));

        let response = client.post_form(url, &form_data).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let body = response.text().await.unwrap_or_default();
        let status = response.status().as_u16();

        // Check if expected result appears in response
        if !expected.is_empty() && body.contains(expected) {
            return Ok(Some("Direct output reflection"));
        }

        // Check for error patterns indicating evaluation
        let error_patterns = [
            "syntax error",
            "parse error",
            "unexpected token",
            "undefined method",
            "nameerror",
            "typeerror",
        ];

        let body_lower = body.to_lowercase();
        for pattern in &error_patterns {
            if body_lower.contains(pattern) {
                return Ok(Some("Error message reveals code evaluation"));
            }
        }

        // Status code analysis
        if status == 500 && !body.is_empty() {
            return Ok(Some("Server error on evaluation payload"));
        }

        Ok(None)
    }

    /// Test time-based blind evaluation
    async fn test_time_based(
        &self,
        client: &HttpClient,
        url: &str,
        param: &str,
        payload: &str,
    ) -> Result<bool, ModuleError> {
        use std::time::Instant;

        let mut form_data = Vec::new();
        form_data.push((param, payload));

        let start = Instant::now();
        let _ = client.post_form(url, &form_data).await;
        let elapsed = start.elapsed().as_millis();

        // Significant delay indicates time-based execution
        Ok(elapsed > 4000)
    }

    /// Build evidence for eval finding
    fn build_evidence(&self, url: &str, payload: &str, result: &str) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::HttpRequestResponse {
                    request: format!("POST {} HTTP/1.1\n\n{}", url, payload),
                    response: format!("Result: {}", result),
                },
                data: result.to_string(),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: Some("input".to_string()),
                    header: None,
                },
                confidence: 85,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Avoid dynamic code evaluation and implement input sanitization".to_string(),
            steps: vec![
                "Never pass user input to eval(), exec(), or similar functions".to_string(),
                "Use template engines with auto-escaping enabled".to_string(),
                "Implement strict input validation and whitelisting".to_string(),
                "Use parameterized queries instead of string concatenation".to_string(),
                "Run application with minimal privileges".to_string(),
                "Implement Content Security Policy headers".to_string(),
            ],
            code_example: Some(r#"// Safe template rendering (Python Jinja2)
from jinja2 import Environment, FileSystemLoader

env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=True  # Critical: enable auto-escaping
)

template = env.get_template('safe_template.html')
# User input will be escaped
output = template.render(user_input=request.args.get('input'))"#.to_string()),
            references: vec![
                "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html".to_string(),
                "https://portswigger.net/web-security/server-side-template-injection".to_string(),
            ],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for ServerSideEvalDetector {
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

        // Common endpoints that might evaluate input
        let test_endpoints = [
            "/api/search",
            "/api/template/render",
            "/api/preview",
            "/search",
            "/render",
            "/preview",
            "/api/comment",
            "/feedback",
        ];

        let test_params = ["q", "query", "input", "data", "template", "content", "message"];

        for endpoint in test_endpoints.iter() {
            let url = format!("{}{}", base_url, endpoint);

            for param in test_params.iter() {
                for (payload, expected, lang) in self.payload_set.iter() {
                    // Skip time-based payloads for direct testing
                    if payload.contains("sleep") || payload.contains("ping") {
                        continue;
                    }

                    if let Ok(Some(result)) = self.test_eval_payload(&client, &url, param, payload, expected).await {
                        if !result.is_empty() {
                            executed = true;

                            let severity = if payload.contains("RCE") || payload.contains("__import__") || payload.contains("require(" {
                                Severity::Critical
                            } else {
                                Severity::High
                            };

                            let mut finding = Finding::new(
                                self.metadata.id.as_str(),
                                severity,
                                format!("Server-Side Code Evaluation ({})", lang),
                                format!("Code evaluation vulnerability detected at {} via parameter '{}'", url, param),
                                &url,
                            )
                            .with_payload(payload.to_string())
                            .with_confidence(80)
                            .with_agent_id(ctx.agent_id)
                            .with_tags(vec!["rce", "code-evaluation", lang]);

                            let evidence = self.build_evidence(&url, payload, result);
                            for ev in evidence {
                                finding = finding.with_evidence(ev);
                            }

                            finding = finding.with_remediation(self.remediation());
                            findings.push(finding);
                            
                            // Cache successful payload for learning engine
                            if let Ok(cache) = LearningCache::global().await {
                                cache.cache_timing_baseline(ctx.target_url.clone(), format!("eval_{}", lang)).await;
                            }
                            
                            break; // Found vulnerability, move to next endpoint
                        }
                    }
                }

                // Test time-based blind evaluation
                for (payload, _, _) in self.payload_set.iter() {
                    if payload.contains("sleep") || payload.contains("ping") {
                        if let Ok(is_vulnerable) = self.test_time_based(&client, &url, param, payload).await {
                            if is_vulnerable {
                                executed = true;

                                let mut finding = Finding::new(
                                    self.metadata.id.as_str(),
                                    Severity::Critical,
                                    "Blind Server-Side Code Evaluation (Time-Based)",
                                    format!("Time-based code execution detected at {}", url),
                                    &url,
                                )
                                .with_payload(payload.to_string())
                                .with_confidence(75)
                                .with_agent_id(ctx.agent_id)
                                .with_tags(vec!["rce", "blind", "time-based"]);

                                finding = finding.with_remediation(self.remediation());
                                findings.push(finding);
                                break;
                            }
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
    fn test_payload_set_bounds() {
        let set = EvalPayloadSet::new();
        assert_eq!(set.count, MAX_EVAL_PAYLOADS);
        
        let all_payloads: Vec<_> = set.iter().collect();
        assert_eq!(all_payloads.len(), MAX_EVAL_PAYLOADS);
    }

    #[test]
    fn test_bounded_storage() {
        let set = EvalPayloadSet::new();
        assert!(std::mem::size_of::<EvalPayloadSet>() <= 2048);
    }
}
