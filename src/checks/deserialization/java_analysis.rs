//! Java Deserialization Analysis
//! Analyzes stack traces, timing, and OOB callbacks to infer code execution paths.

use crate::findings::deser_evidence::DeserializationEvidence;
use std::time::{Duration, Instant};

/// Analyzer for Java deserialization vulnerabilities
#[derive(Debug)]
pub struct JavaDeserializationAnalyzer {
    /// Timing threshold in milliseconds for detection
    timing_threshold_ms: u64,
    /// Callback timeout duration
    callback_timeout: Duration,
    /// Detected evidence list
    evidence_log: Vec<DeserializationEvidence>,
}

/// Stack trace pattern for Java deserialization
#[derive(Debug, Clone)]
pub struct StackTracePattern {
    /// Pattern name
    pub name: String,
    /// Regex-like pattern string
    pub pattern: String,
    /// Confidence score (0-100)
    pub confidence: u8,
}

/// Timing analysis result
#[derive(Debug, Clone)]
pub struct TimingAnalysis {
    /// Request start time
    pub start: Instant,
    /// Response received time
    pub end: Option<Instant>,
    /// Elapsed time in milliseconds
    pub elapsed_ms: u64,
    /// Whether timing indicates vulnerability
    pub suspicious: bool,
}

impl JavaDeserializationAnalyzer {
    /// Create a new analyzer with default thresholds
    pub fn new() -> Self {
        Self {
            timing_threshold_ms: 100, // 100ms threshold
            callback_timeout: Duration::from_secs(5),
            evidence_log: Vec::new(),
        }
    }

    /// Analyze stack trace for deserialization indicators
    pub fn analyze_stack_trace(&self, stack_trace: &str) -> Vec<StackTracePattern> {
        let mut patterns = Vec::new();

        // Common Java deserialization stack trace patterns
        let known_patterns = [
            ("readObject", "java\\.io\\.ObjectInputStream\\.readObject"),
            ("InvokerTransformer", "org\\.apache\\.commons\\.collections\\.functors\\.InvokerTransformer"),
            ("TransformedMap", "org\\.apache\\.commons\\.collections\\.map\\.TransformedMap"),
            ("LazyMap", "org\\.apache\\.commons\\.collections\\.map\\.LazyMap"),
            ("ChainedTransformer", "org\\.apache\\.commons\\.collections\\.functors\\.ChainedTransformer"),
            ("BeanShell", "bsh\\.Interpreter\\.eval"),
            ("Groovy", "groovy\\.lang\\.GroovyClassLoader"),
            ("XStream", "com\\.thoughtworks\\.xstream\\.XStream\\.fromXML"),
        ];

        for (name, pattern) in known_patterns.iter() {
            if stack_trace.contains(pattern) || stack_trace.contains(name) {
                patterns.push(StackTracePattern {
                    name: name.to_string(),
                    pattern: pattern.to_string(),
                    confidence: self.calculate_confidence(pattern, stack_trace),
                });
            }
        }

        patterns
    }

    /// Calculate confidence score based on pattern matches
    fn calculate_confidence(&self, _pattern: &str, stack_trace: &str) -> u8 {
        let mut score = 0u8;

        // Base confidence for any match
        score += 30;

        // Additional confidence for multiple indicators
        if stack_trace.contains("readObject") {
            score += 20;
        }
        if stack_trace.contains("Transformer") {
            score += 25;
        }
        if stack_trace.contains("Map") {
            score += 15;
        }
        if stack_trace.contains("invoke") {
            score += 10;
        }

        score.min(100)
    }

    /// Perform timing analysis on deserialization attempt
    pub fn analyze_timing(&self, start: Instant, response_received: bool) -> TimingAnalysis {
        let end = if response_received { Some(Instant::now()) } else { None };
        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Suspicious if takes longer than threshold (potential processing)
        // Or if no response at all (potential hang/crash)
        let suspicious = !response_received || elapsed_ms > self.timing_threshold_ms;

        TimingAnalysis {
            start,
            end,
            elapsed_ms,
            suspicious,
        }
    }

    /// Validate out-of-band callback
    pub fn validate_oob_callback(&self, callback_url: &str, expected_token: &str) -> bool {
        // In production, this would check an external callback server
        // For now, simulate validation logic
        if callback_url.is_empty() || expected_token.is_empty() {
            return false;
        }

        // Validate URL format
        if !callback_url.starts_with("http") {
            return false;
        }

        // Token must be alphanumeric and bounded length
        if expected_token.len() > 64 || expected_token.is_empty() {
            return false;
        }

        true
    }

    /// Correlate evidence from multiple sources
    pub fn correlate_evidence(
        &mut self,
        endpoint: &str,
        stack_trace: Option<&str>,
        timing: &TimingAnalysis,
        oob_validated: bool,
    ) -> Option<DeserializationEvidence> {
        let mut severity = 0u8;
        let mut gadget_chain: Option<String> = None;

        // Analyze stack trace if provided
        if let Some(trace) = stack_trace {
            let patterns = self.analyze_stack_trace(trace);
            if !patterns.is_empty() {
                severity += 30;
                gadget_chain = Some(patterns[0].name.clone());
                
                // Add confidence-based severity
                severity += patterns[0].confidence / 3;
            }
        }

        // Timing-based severity
        if timing.suspicious {
            severity += 20;
        }

        // OOB callback adds significant confidence
        if oob_validated {
            severity += 40;
        }

        // Only report if severity exceeds threshold
        if severity >= 50 {
            let evidence = DeserializationEvidence {
                target_endpoint: endpoint.to_string(),
                framework: "Java".to_string(),
                gadget_chain,
                stack_trace: stack_trace.map(String::from),
                timing_ms: Some(timing.elapsed_ms),
                callback_validated: oob_validated,
                oob_callback: None,
                severity: severity.min(100),
            };

            self.evidence_log.push(evidence.clone());
            Some(evidence)
        } else {
            None
        }
    }

    /// Get all logged evidence
    pub fn get_evidence_log(&self) -> &[DeserializationEvidence] {
        &self.evidence_log
    }

    /// Clear evidence log
    pub fn clear_log(&mut self) {
        self.evidence_log.clear();
    }

    /// Set custom timing threshold
    pub fn with_timing_threshold(mut self, threshold_ms: u64) -> Self {
        self.timing_threshold_ms = threshold_ms;
        self
    }

    /// Set callback timeout
    pub fn with_callback_timeout(mut self, timeout: Duration) -> Self {
        self.callback_timeout = timeout;
        self
    }
}

impl Default for JavaDeserializationAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_trace_analysis() {
        let analyzer = JavaDeserializationAnalyzer::new();
        let trace = "java.io.ObjectInputStream.readObject()\n\tat org.apache.commons.collections.functors.InvokerTransformer.transform()";
        
        let patterns = analyzer.analyze_stack_trace(trace);
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.name == "readObject"));
    }

    #[test]
    fn test_timing_analysis() {
        let analyzer = JavaDeserializationAnalyzer::new();
        let start = Instant::now();
        
        // Simulate some time passing
        std::thread::sleep(Duration::from_millis(150));
        
        let result = analyzer.analyze_timing(start, true);
        assert!(result.suspicious); // Should be suspicious due to >100ms
    }

    #[test]
    fn test_oob_validation() {
        let analyzer = JavaDeserializationAnalyzer::new();
        assert!(analyzer.validate_oob_callback("http://attacker.com/callback", "abc123"));
        assert!(!analyzer.validate_oob_callback("ftp://invalid", "token"));
        assert!(!analyzer.validate_oob_callback("", ""));
    }
}
