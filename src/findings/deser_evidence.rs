//! Deserialization Evidence Container
//! Creates deserialization evidence containers with stack trace and callback correlation.

use std::time::{Duration, Instant};

/// Container for deserialization vulnerability evidence
#[derive(Debug, Clone)]
pub struct DeserializationEvidence {
    /// Target endpoint that was tested
    pub target_endpoint: String,
    /// Framework/language detected (Java, PHP, Python, Node.js)
    pub framework: String,
    /// Gadget chain or exploitation method identified
    pub gadget_chain: Option<String>,
    /// Stack trace if available
    pub stack_trace: Option<String>,
    /// Timing information in milliseconds
    pub timing_ms: Option<u64>,
    /// Whether OOB callback was validated
    pub callback_validated: bool,
    /// Out-of-band callback URL if used
    pub oob_callback: Option<String>,
    /// Severity score (1-100)
    pub severity: u8,
}

impl DeserializationEvidence {
    /// Create new evidence with required fields
    pub fn new(
        target_endpoint: &str,
        framework: &str,
        severity: u8,
    ) -> Self {
        Self {
            target_endpoint: target_endpoint.to_string(),
            framework: framework.to_string(),
            gadget_chain: None,
            stack_trace: None,
            timing_ms: None,
            callback_validated: false,
            oob_callback: None,
            severity: severity.min(100),
        }
    }

    /// Set the gadget chain information
    pub fn with_gadget_chain(mut self, chain: &str) -> Self {
        self.gadget_chain = Some(chain.to_string());
        self
    }

    /// Set stack trace information
    pub fn with_stack_trace(mut self, trace: &str) -> Self {
        self.stack_trace = Some(trace.to_string());
        self
    }

    /// Set timing information
    pub fn with_timing(mut self, ms: u64) -> Self {
        self.timing_ms = Some(ms);
        self
    }

    /// Set OOB callback information
    pub fn with_oob_callback(mut self, url: &str, validated: bool) -> Self {
        self.oob_callback = Some(url.to_string());
        self.callback_validated = validated;
        self
    }

    /// Calculate confidence score based on evidence quality
    pub fn confidence_score(&self) -> u8 {
        let mut score = 0u16;

        // Base score for having evidence
        score += 20;

        // Gadget chain adds significant confidence
        if self.gadget_chain.is_some() {
            score += 25;
        }

        // Stack trace adds high confidence
        if self.stack_trace.is_some() {
            score += 30;
        }

        // Timing data adds moderate confidence
        if self.timing_ms.is_some() {
            score += 10;
        }

        // Validated OOB callback adds highest confidence
        if self.callback_validated {
            score += 35;
        } else if self.oob_callback.is_some() {
            score += 15;
        }

        (score.min(100) as u8)
    }

    /// Check if evidence is strong enough to report
    pub fn is_reportable(&self) -> bool {
        self.confidence_score() >= 50
    }

    /// Get a summary description of the evidence
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        
        parts.push(format!("Framework: {}", self.framework));
        parts.push(format!("Endpoint: {}", self.target_endpoint));
        
        if let Some(ref chain) = self.gadget_chain {
            parts.push(format!("Gadget: {}", chain));
        }
        
        parts.push(format!("Severity: {}/100", self.severity));
        parts.push(format!("Confidence: {}/100", self.confidence_score()));

        parts.join(" | ")
    }

    /// Export evidence as JSON-like string
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"target":"{}","framework":"{}","gadget_chain":{},"severity":{},"confidence":{}}}"#,
            self.target_endpoint,
            self.framework,
            self.gadget_chain
                .as_ref()
                .map(|s| format!("\"{}\"", s))
                .unwrap_or_else(|| "null".to_string()),
            self.severity,
            self.confidence_score()
        )
    }
}

/// Correlator for multiple pieces of evidence
#[derive(Debug)]
pub struct EvidenceCorrelator {
    /// Collected evidence items
    evidence_list: Vec<DeserializationEvidence>,
    /// Correlation window duration
    correlation_window: Duration,
    /// Start time for correlation
    start_time: Instant,
}

impl EvidenceCorrelator {
    /// Create a new correlator
    pub fn new() -> Self {
        Self {
            evidence_list: Vec::new(),
            correlation_window: Duration::from_secs(60),
            start_time: Instant::now(),
        }
    }

    /// Add evidence to the correlator
    pub fn add_evidence(&mut self, evidence: DeserializationEvidence) {
        self.evidence_list.push(evidence);
    }

    /// Correlate evidence from same endpoint within time window
    pub fn correlate_by_endpoint(&self, endpoint: &str) -> Vec<&DeserializationEvidence> {
        self.evidence_list
            .iter()
            .filter(|e| e.target_endpoint == endpoint)
            .collect()
    }

    /// Correlate evidence by framework
    pub fn correlate_by_framework(&self, framework: &str) -> Vec<&DeserializationEvidence> {
        self.evidence_list
            .iter()
            .filter(|e| e.framework == framework)
            .collect()
    }

    /// Get all correlated evidence with high confidence
    pub fn get_high_confidence(&self) -> Vec<&DeserializationEvidence> {
        self.evidence_list
            .iter()
            .filter(|e| e.is_reportable())
            .collect()
    }

    /// Get total evidence count
    pub fn count(&self) -> usize {
        self.evidence_list.len()
    }

    /// Clear all evidence
    pub fn clear(&mut self) {
        self.evidence_list.clear();
        self.start_time = Instant::now();
    }

    /// Set correlation window
    pub fn with_correlation_window(mut self, duration: Duration) -> Self {
        self.correlation_window = duration;
        self
    }
}

impl Default for EvidenceCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_creation() {
        let evidence = DeserializationEvidence::new("/api/test", "Java", 80);
        assert_eq!(evidence.target_endpoint, "/api/test");
        assert_eq!(evidence.framework, "Java");
        assert_eq!(evidence.severity, 80);
    }

    #[test]
    fn test_evidence_builder() {
        let evidence = DeserializationEvidence::new("/api/test", "Java", 70)
            .with_gadget_chain("CommonsCollections")
            .with_timing(150)
            .with_oob_callback("http://callback.com", true);

        assert!(evidence.gadget_chain.is_some());
        assert!(evidence.timing_ms.is_some());
        assert!(evidence.callback_validated);
    }

    #[test]
    fn test_confidence_score() {
        let evidence = DeserializationEvidence::new("/api/test", "Java", 50)
            .with_gadget_chain("TestChain")
            .with_stack_trace("java.io.ObjectInputStream.readObject()")
            .with_oob_callback("http://callback.com", true);

        assert!(evidence.confidence_score() >= 80);
        assert!(evidence.is_reportable());
    }

    #[test]
    fn test_correlator() {
        let mut correlator = EvidenceCorrelator::new();
        
        let evidence1 = DeserializationEvidence::new("/api/test", "Java", 70);
        let evidence2 = DeserializationEvidence::new("/api/test", "Java", 80);
        
        correlator.add_evidence(evidence1);
        correlator.add_evidence(evidence2);

        assert_eq!(correlator.count(), 2);
        assert_eq!(correlator.correlate_by_endpoint("/api/test").len(), 2);
    }
}
