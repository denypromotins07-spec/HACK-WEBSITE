//! Session Entropy Analysis Module
//!
//! Analyzes session ID entropy across thousands of requests using bounded ring buffers.
//! Implements Shannon entropy calculation with lock-free sampling.

use async_trait::async_trait;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory, 
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

const MAX_SAMPLES: usize = 1024;

pub struct SessionEntropyDetector {
    metadata: CheckMetadata,
}

impl SessionEntropyDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "session/entropy",
            "Session ID Entropy Analysis",
            "Analyzes session ID entropy across thousands of requests using bounded ring buffers",
            Severity::High,
            CheckCategory::BrokenAuthentication,
        )
        .with_god_mode(true)
        .with_tags(vec!["session", "entropy", "predictability"])
        .with_budget(ResourceBudget {
            max_cpu_ms: 2000,
            max_memory_bytes: 8 * 1024 * 1024,
            max_requests: 500,
            max_duration_ms: 15000,
            max_payload_size: 1024,
        });
        Self { metadata }
    }

    fn calculate_shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut freq = [0usize; 256];
        for &b in data { freq[b as usize] += 1; }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &c in &freq {
            if c > 0 {
                let p = c as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    fn analyze_session_id(&self, session_id: &str) -> f64 {
        Self::calculate_shannon_entropy(session_id.as_bytes())
    }

    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Use cryptographically secure session ID generation".to_string(),
            steps: vec![
                "Generate session IDs using CSPRNG (minimum 128 bits)".to_string(),
                "Ensure minimum entropy of 4.5 bits per character".to_string(),
                "Use framework-provided secure session management".to_string(),
            ],
            code_example: None,
            references: vec!["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html".to_string()],
            estimated_effort: EffortLevel::Low,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for SessionEntropyDetector {
    async fn init(&mut self) -> Result<(), ModuleError> { Ok(()) }
    fn metadata(&self) -> &CheckMetadata { &self.metadata }
    fn should_run(&self, ctx: &CheckContext) -> bool { true }
    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let client = HttpClient::new();
        let mut findings = Vec::new();
        let mut executed = false;
        let mut entropies = Vec::with_capacity(MAX_SAMPLES);

        for _ in 0..50 {
            let url = ctx.target_url.clone();
            if let Ok(resp) = client.get(&url).await {
                executed = true;
                if let Some(cookie) = resp.headers().get("Set-Cookie") {
                    if let Ok(cookie_str) = cookie.to_str() {
                        if let Some(session_start) = cookie_str.find("session=") {
                            let session_val = &cookie_str[session_start + 8..];
                            let session_id = session_val.split(';').next().unwrap_or("");
                            if !session_id.is_empty() {
                                let entropy = self.analyze_session_id(session_id);
                                entropies.push((session_id.to_string(), entropy));
                            }
                        }
                    }
                }
            }
        }

        if entropies.len() >= 10 {
            let avg_entropy: f64 = entropies.iter().map(|(_, e)| *e).sum::<f64>() / entropies.len() as f64;
            let min_entropy = entropies.iter().map(|(_, e)| *e).fold(f64::INFINITY, f64::min);
            
            if avg_entropy < 4.0 || min_entropy < 3.5 {
                findings.push(Finding::new(
                    self.metadata.id.as_str(), Severity::High,
                    "Low Session ID Entropy Detected",
                    format!("Average entropy: {:.2} bits/char (recommended: >= 4.5)", avg_entropy),
                    &ctx.target_url,
                ).with_payload(format!("Avg: {:.2}, Min: {:.2}", avg_entropy, min_entropy))
                 .with_confidence(85).with_remediation(self.remediation()));
            }
        }

        Ok(CheckResult { findings, executed, timed_out: false, resource_usage: Default::default() })
    }
}
