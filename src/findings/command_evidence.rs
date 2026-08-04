//! Command Injection and Memory Corruption Evidence Container
//! Builds evidence containers for command injection and memory corruption findings.
//! Stores payloads, response deltas, and remediation guidance with zero-copy optimization.

use std::collections::HashMap;
use std::time::SystemTime;

/// Maximum evidence entries (bounded)
const MAX_EVIDENCE_ENTRIES: usize = 100;

/// Evidence severity levels
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Low = 3,
    Medium = 5,
    High = 8,
    Critical = 10,
}

/// Evidence type classification
#[derive(Debug, Clone)]
pub enum EvidenceType {
    CommandInjection,
    BlindCommandInjection,
    Shellshock,
    CgiVulnerability,
    EnvInjection,
    FileUploadExecution,
    ZipSlip,
    NativeDeserialization,
    Overflow,
    RequestSmuggling,
}

/// Command injection evidence container
#[derive(Debug, Clone)]
pub struct CommandEvidence {
    pub finding_type: String,
    pub evidence_type: EvidenceType,
    pub url: String,
    pub payload: String,
    pub parameter: Option<String>,
    pub header: Option<String>,
    pub severity: Severity,
    pub response_delta: Vec<u8>,
    pub timing_delta_ms: Option<u128>,
    pub edge_headers: HashMap<String, String>,
    pub normalized_key: String,
    pub timestamp: SystemTime,
    pub remediation: String,
    pub cwe: Option<String>,
    pub cve: Option<String>,
}

impl CommandEvidence {
    pub fn new(
        finding_type: &str,
        evidence_type: EvidenceType,
        url: &str,
        payload: &str,
        severity: Severity,
    ) -> Self {
        Self {
            finding_type: finding_type.to_string(),
            evidence_type,
            url: url.to_string(),
            payload: payload.to_string(),
            parameter: None,
            header: None,
            severity,
            response_delta: Vec::new(),
            timing_delta_ms: None,
            edge_headers: HashMap::new(),
            normalized_key: Self::normalize_url(url),
            timestamp: SystemTime::now(),
            remediation: String::new(),
            cwe: None,
            cve: None,
        }
    }
    
    /// Set the vulnerable parameter
    pub fn with_parameter(mut self, param: &str) -> Self {
        self.parameter = Some(param.to_string());
        self
    }
    
    /// Set the vulnerable header
    pub fn with_header(mut self, header: &str) -> Self {
        self.header = Some(header.to_string());
        self
    }
    
    /// Set response delta (zero-copy slice stored as owned Vec)
    pub fn with_response_delta(mut self, delta: &[u8]) -> Self {
        // Truncate to bounded size
        let truncate_len = delta.len().min(4096);
        self.response_delta = delta[..truncate_len].to_vec();
        self
    }
    
    /// Set timing delta for blind detection
    pub fn with_timing_delta(mut self, ms: u128) -> Self {
        self.timing_delta_ms = Some(ms);
        self
    }
    
    /// Add edge headers from CDN/proxy
    pub fn with_edge_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.edge_headers = headers;
        self
    }
    
    /// Set remediation guidance
    pub fn with_remediation(mut self, guidance: &str) -> Self {
        self.remediation = guidance.to_string();
        self
    }
    
    /// Set CWE identifier
    pub fn with_cwe(mut self, cwe: &str) -> Self {
        self.cwe = Some(cwe.to_string());
        self
    }
    
    /// Set CVE identifier
    pub fn with_cve(mut self, cve: &str) -> Self {
        self.cve = Some(cve.to_string());
        self
    }
    
    /// Normalize URL for deduplication
    fn normalize_url(url: &str) -> String {
        // Remove query parameters for normalization
        if let Some(base) = url.split('?').next() {
            base.to_string()
        } else {
            url.to_string()
        }
    }
    
    /// Get evidence summary
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} at {} - Payload: {}",
            self.severity_as_str(),
            self.finding_type,
            self.url,
            self.payload.chars().take(50).collect::<String>()
        )
    }
    
    /// Convert severity to string
    fn severity_as_str(&self) -> &'static str {
        match self.severity {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
    
    /// Serialize to JSON-like format for reporting
    pub fn to_report_json(&self) -> String {
        format!(
            r#"{{"type":"{}","evidence":"{:?}","url":"{}","payload":"{}","severity":"{}","cwe":"{}","cve":"{}"}}"#,
            self.finding_type,
            self.evidence_type,
            self.url,
            self.payload.replace('"', "\\\""),
            self.severity_as_str(),
            self.cwe.as_deref().unwrap_or(""),
            self.cve.as_deref().unwrap_or("")
        )
    }
}

/// Evidence collector for aggregating findings
#[derive(Debug)]
pub struct CommandEvidenceCollector {
    entries: Vec<CommandEvidence>,
    max_entries: usize,
}

impl CommandEvidenceCollector {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_EVIDENCE_ENTRIES),
            max_entries: MAX_EVIDENCE_ENTRIES,
        }
    }
    
    /// Add evidence entry (bounded)
    pub fn add(&mut self, evidence: CommandEvidence) {
        if self.entries.len() < self.max_entries {
            self.entries.push(evidence);
        }
    }
    
    /// Get all entries
    pub fn entries(&self) -> &[CommandEvidence] {
        &self.entries
    }
    
    /// Get count of critical findings
    pub fn critical_count(&self) -> usize {
        self.entries.iter()
            .filter(|e| e.severity == Severity::Critical)
            .count()
    }
    
    /// Get count by evidence type
    pub fn count_by_type(&self, evidence_type: &EvidenceType) -> usize {
        self.entries.iter()
            .filter(|e| matches!(&e.evidence_type, t if std::mem::discriminant(t) == std::mem::discriminant(evidence_type)))
            .count()
    }
    
    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for CommandEvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_evidence_creation() {
        let evidence = CommandEvidence::new(
            "OS_COMMAND_INJECTION",
            EvidenceType::CommandInjection,
            "http://example.com/test",
            ";id",
            Severity::Critical,
        );
        
        assert_eq!(evidence.finding_type, "OS_COMMAND_INJECTION");
        assert_eq!(evidence.severity, Severity::Critical);
    }
    
    #[test]
    fn test_evidence_builder() {
        let evidence = CommandEvidence::new(
            "BLIND_INJECTION",
            EvidenceType::BlindCommandInjection,
            "http://example.com/api",
            ";sleep 5",
            Severity::High,
        )
        .with_parameter("cmd")
        .with_timing_delta(5100)
        .with_cwe("CWE-78");
        
        assert_eq!(evidence.parameter, Some("cmd".to_string()));
        assert_eq!(evidence.timing_delta_ms, Some(5100));
        assert_eq!(evidence.cwe, Some("CWE-78".to_string()));
    }
    
    #[test]
    fn test_collector_bounds() {
        let mut collector = CommandEvidenceCollector::new();
        
        for i in 0..MAX_EVIDENCE_ENTRIES + 10 {
            collector.add(CommandEvidence::new(
                &format!("TEST_{}", i),
                EvidenceType::CommandInjection,
                "http://test.com",
                "test",
                Severity::Low,
            ));
        }
        
        assert_eq!(collector.entries().len(), MAX_EVIDENCE_ENTRIES);
    }
}
