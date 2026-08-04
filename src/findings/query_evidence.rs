//! Query Language Injection Evidence Container
//! Builds evidence containers for query-language injection with request/response deltas.
//! Implements zero-copy evidence storage for memory efficiency.

use std::borrow::Cow;
use std::time::Instant;

/// Evidence container for query-language injection findings
#[derive(Debug, Clone)]
pub struct QueryEvidence {
    /// Parameter that was exploited
    pub parameter: String,
    /// Type of injection (xpath, ldap, nosql, orm, ssti, el)
    pub evidence_type: Cow<'static, str>,
    /// Payload used in the attack
    pub payload: Option<Cow<'static, str>>,
    /// Original request/response before injection
    pub original: Option<Cow<'static, str>>,
    /// Mutated response after injection
    pub mutated: Option<Cow<'static, str>>,
    /// Response time delta in nanoseconds
    pub timing_delta_ns: Option<u128>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Template/engine type if applicable
    pub template_engine: Option<Cow<'static, str>>,
    /// Expression language type if applicable
    pub expression_language: Option<Cow<'static, str>>,
    /// Timestamp when evidence was collected
    pub timestamp: Instant,
    /// Additional metadata
    pub metadata: Vec<(Cow<'static, str>, Cow<'static, str>)>,
}

impl QueryEvidence {
    /// Create a new empty evidence container
    pub fn new() -> Self {
        Self {
            parameter: String::new(),
            evidence_type: Cow::Borrowed("unknown"),
            payload: None,
            original: None,
            mutated: None,
            timing_delta_ns: None,
            confidence: 0.0,
            template_engine: None,
            expression_language: None,
            timestamp: Instant::now(),
            metadata: Vec::new(),
        }
    }

    /// Set the affected parameter
    pub fn with_parameter(mut self, parameter: String) -> Self {
        self.parameter = parameter;
        self
    }

    /// Set the evidence type
    pub fn with_evidence_type(mut self, evidence_type: &'static str) -> Self {
        self.evidence_type = Cow::Borrowed(evidence_type);
        self
    }

    /// Set the payload used
    pub fn with_payload(mut self, payload: Cow<'static, str>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Set the original response
    pub fn with_original(mut self, original: Cow<'static, str>) -> Self {
        self.original = Some(original);
        self
    }

    /// Set the mutated response
    pub fn with_mutated(mut self, mutated: Cow<'static, str>) -> Self {
        self.mutated = Some(mutated);
        self
    }

    /// Set the timing delta
    pub fn with_timing_delta_ns(mut self, delta_ns: u128) -> Self {
        self.timing_delta_ns = Some(delta_ns);
        self
    }

    /// Set the confidence score
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set the template engine type
    pub fn with_template_engine(mut self, engine: Cow<'static, str>) -> Self {
        self.template_engine = Some(engine);
        self
    }

    /// Set the expression language type
    pub fn with_expression_language(mut self, lang: Cow<'static, str>) -> Self {
        self.expression_language = Some(lang);
        self
    }

    /// Add metadata key-value pair
    pub fn with_metadata(mut self, key: &'static str, value: &'static str) -> Self {
        self.metadata.push((Cow::Borrowed(key), Cow::Borrowed(value)));
        self
    }

    /// Calculate response differential (length-based)
    pub fn response_delta(&self) -> i32 {
        let orig_len = self.original.as_ref().map(|s| s.len()).unwrap_or(0);
        let mut_len = self.mutated.as_ref().map(|s| s.len()).unwrap_or(0);
        mut_len as i32 - orig_len as i32
    }

    /// Calculate response differential ratio
    pub fn response_delta_ratio(&self) -> f64 {
        let orig_len = self.original.as_ref().map(|s| s.len()).unwrap_or(0);
        let mut_len = self.mutated.as_ref().map(|s| s.len()).unwrap_or(0);
        
        if orig_len == 0 {
            return if mut_len > 0 { 1.0 } else { 0.0 };
        }
        
        (mut_len as i32 - orig_len as i32).abs() as f64 / orig_len as f64
    }

    /// Get a summary of the evidence
    pub fn summary(&self) -> String {
        format!(
            "QueryEvidence[type={}, param={}, confidence={:.2}, delta={}]",
            self.evidence_type,
            self.parameter,
            self.confidence,
            self.response_delta()
        )
    }

    /// Clear large data for memory management
    pub fn clear_responses(&mut self) {
        self.original = None;
        self.mutated = None;
    }
}

impl Default for QueryEvidence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_creation() {
        let evidence = QueryEvidence::new()
            .with_parameter("id".to_string())
            .with_evidence_type("xpath_injection")
            .with_confidence(0.85);

        assert_eq!(evidence.parameter, "id");
        assert_eq!(evidence.evidence_type, "xpath_injection");
        assert_eq!(evidence.confidence, 0.85);
    }

    #[test]
    fn test_response_delta() {
        let evidence = QueryEvidence::new()
            .with_original(Cow::Borrowed("short"))
            .with_mutated(Cow::Borrowed("much longer response"));

        assert_eq!(evidence.response_delta(), 14);
    }

    #[test]
    fn test_response_delta_ratio() {
        let evidence = QueryEvidence::new()
            .with_original(Cow::Borrowed("100"))
            .with_mutated(Cow::Borrowed("200"));

        assert!((evidence.response_delta_ratio() - 0.0).abs() < 0.01);
    }
}
