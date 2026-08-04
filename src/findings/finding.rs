//! Normalized Finding Object
//! 
//! Creates normalized finding objects with evidence, endpoint, payload,
//! and remediation hints for vulnerability reporting.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::findings::severity::Severity;

/// Unique identifier for a finding
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingId(pub String);

impl FindingId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    
    pub fn generate() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(format!("finding_{}", timestamp))
    }
}

/// Evidence supporting a vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Type of evidence
    pub evidence_type: EvidenceType,
    /// The actual evidence data
    pub data: String,
    /// Location where evidence was found
    pub location: EvidenceLocation,
    /// Confidence level (0-100)
    pub confidence: u8,
}

/// Types of evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EvidenceType {
    /// HTTP request/response pair
    HttpRequestResponse {
        request: String,
        response: String,
    },
    /// File content
    FileContent {
        path: String,
        content: String,
    },
    /// Network traffic
    NetworkTraffic {
        protocol: String,
        data: String,
    },
    /// Configuration value
    Configuration {
        key: String,
        value: String,
    },
    /// Error message revealing information
    ErrorMessage {
        message: String,
        stack_trace: Option<String>,
    },
    /// Timing-based evidence
    Timing {
        baseline_ms: u64,
        observed_ms: u64,
        difference_ms: u64,
    },
}

/// Location of evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLocation {
    /// URL or file path
    pub path: String,
    /// Line number if applicable
    pub line: Option<usize>,
    /// Parameter name if applicable
    pub parameter: Option<String>,
    /// Header name if applicable
    pub header: Option<String>,
}

/// Remediation hint for fixing a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationHint {
    /// Short description of the fix
    pub summary: String,
    /// Detailed remediation steps
    pub steps: Vec<String>,
    /// Code example (if applicable)
    pub code_example: Option<String>,
    /// References to documentation
    pub references: Vec<String>,
    /// Estimated effort to fix
    pub estimated_effort: EffortLevel,
}

/// Effort level for remediation
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EffortLevel {
    Trivial,
    Low,
    Medium,
    High,
    VeryHigh,
}

impl EffortLevel {
    pub fn description(&self) -> &'static str {
        match self {
            EffortLevel::Trivial => "Minutes - configuration change",
            EffortLevel::Low => "Hours - minor code change",
            EffortLevel::Medium => "Days - moderate refactoring",
            EffortLevel::High => "Weeks - significant changes",
            EffortLevel::VeryHigh => "Months - architectural changes",
        }
    }
}

/// A normalized vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier
    pub id: FindingId,
    /// Vulnerability module that found this
    pub module_id: String,
    /// Severity classification
    pub severity: Severity,
    /// Title/summary
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Affected endpoint/URL
    pub endpoint: String,
    /// HTTP method if applicable
    pub method: Option<String>,
    /// Payload that triggered the finding
    pub payload: Option<String>,
    /// Evidence supporting the finding
    pub evidence: Vec<Evidence>,
    /// Remediation guidance
    pub remediation: Option<RemediationHint>,
    /// CWE identifier if applicable
    pub cwe_id: Option<String>,
    /// CVE identifier if applicable
    pub cve_id: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Timestamp when finding was created
    pub created_at: u64,
    /// Agent ID that found this
    pub agent_id: u16,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// Whether this is a false positive
    pub is_false_positive: bool,
    /// False positive reason if marked
    pub false_positive_reason: Option<String>,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        module_id: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            id: FindingId::generate(),
            module_id: module_id.into(),
            severity,
            title: title.into(),
            description: description.into(),
            endpoint: endpoint.into(),
            method: None,
            payload: None,
            evidence: Vec::new(),
            remediation: None,
            cwe_id: None,
            cve_id: None,
            tags: Vec::new(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            agent_id: 0,
            confidence: 50,
            is_false_positive: false,
            false_positive_reason: None,
        }
    }
    
    /// Set HTTP method
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }
    
    /// Set payload
    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = Some(payload.into());
        self
    }
    
    /// Add evidence
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }
    
    /// Set remediation
    pub fn with_remediation(mut self, remediation: RemediationHint) -> Self {
        self.remediation = Some(remediation);
        self
    }
    
    /// Set CWE ID
    pub fn with_cwe(mut self, cwe_id: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe_id.into());
        self
    }
    
    /// Set confidence
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }
    
    /// Add tags
    pub fn with_tags(mut self, tags: Vec<&str>) -> Self {
        self.tags = tags.into_iter().map(|s| s.to_string()).collect();
        self
    }
    
    /// Set agent ID
    pub fn with_agent_id(mut self, agent_id: u16) -> Self {
        self.agent_id = agent_id;
        self
    }
    
    /// Mark as false positive
    pub fn mark_false_positive(mut self, reason: impl Into<String>) -> Self {
        self.is_false_positive = true;
        self.false_positive_reason = Some(reason.into());
        self
    }
    
    /// Get a hashable key for deduplication
    pub fn dedupe_key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.module_id,
            self.endpoint,
            self.severity as u8,
            self.payload.as_deref().unwrap_or("")
        )
    }
}

/// Builder for creating findings with fluent API
pub struct FindingBuilder {
    module_id: String,
    severity: Severity,
    title: String,
    description: String,
    endpoint: String,
}

impl FindingBuilder {
    pub fn new(
        module_id: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            module_id: module_id.into(),
            severity,
            title: title.into(),
            description: description.into(),
            endpoint: endpoint.into(),
        }
    }
    
    pub fn build(self) -> Finding {
        Finding::new(
            self.module_id,
            self.severity,
            self.title,
            self.description,
            self.endpoint,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_finding_creation() {
        let finding = Finding::new(
            "test_module",
            Severity::High,
            "Test Vulnerability",
            "Description of the vulnerability",
            "https://example.com/vulnerable",
        );
        
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.module_id, "test_module");
        assert!(!finding.id.0.is_empty());
    }
    
    #[test]
    fn test_finding_builder_pattern() {
        let finding = Finding::new(
            "sqli_check",
            Severity::Critical,
            "SQL Injection",
            "Classic SQL injection vulnerability",
            "/api/users",
        )
        .with_method("POST")
        .with_payload("' OR '1'='1")
        .with_confidence(95)
        .with_cwe("CWE-89")
        .with_tags(vec!["owasp-top-10", "injection"]);
        
        assert_eq!(finding.method, Some("POST".to_string()));
        assert_eq!(finding.confidence, 95);
        assert_eq!(finding.cwe_id, Some("CWE-89".to_string()));
        assert!(finding.tags.contains(&"owasp-top-10".to_string()));
    }
    
    #[test]
    fn test_dedupe_key() {
        let finding1 = Finding::new(
            "xss_check",
            Severity::Medium,
            "XSS",
            "Cross-site scripting",
            "/search",
        )
        .with_payload("<script>alert(1)</script>");
        
        let finding2 = Finding::new(
            "xss_check",
            Severity::Medium,
            "XSS",
            "Cross-site scripting (different desc)",
            "/search",
        )
        .with_payload("<script>alert(1)</script>");
        
        // Same dedupe key despite different descriptions
        assert_eq!(finding1.dedupe_key(), finding2.dedupe_key());
    }
    
    #[test]
    fn test_evidence_types() {
        let http_evidence = Evidence {
            evidence_type: EvidenceType::HttpRequestResponse {
                request: "GET /test HTTP/1.1".to_string(),
                response: "HTTP/1.1 200 OK".to_string(),
            },
            data: "response contains sensitive info".to_string(),
            location: EvidenceLocation {
                path: "/test".to_string(),
                line: None,
                parameter: Some("id".to_string()),
                header: None,
            },
            confidence: 90,
        };
        
        assert!(matches!(
            http_evidence.evidence_type,
            EvidenceType::HttpRequestResponse { .. }
        ));
    }
}
