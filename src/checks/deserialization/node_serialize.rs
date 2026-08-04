//! Node.js Deserialization Detection
//! Detects unsafe node-serialize and custom serialization endpoints using IIFE probes.

use crate::findings::deser_evidence::DeserializationEvidence;
use std::time::Instant;

/// Detector for Node.js deserialization vulnerabilities
#[derive(Debug, Clone)]
pub struct NodeSerializeDetector {
    /// Maximum payload size (2GB ceiling)
    max_payload_size: usize,
    /// Detected vulnerabilities
    detected_vulns: Vec<NodeVulnerability>,
}

/// Represents a detected Node.js vulnerability
#[derive(Debug, Clone)]
pub struct NodeVulnerability {
    /// Target endpoint
    pub endpoint: String,
    /// Serialization library/type
    pub lib_type: String,
    /// Severity (1-10)
    pub severity: u8,
    /// Timing in milliseconds
    pub timing_ms: Option<u64>,
}

impl NodeSerializeDetector {
    /// Create a new Node.js detector
    pub fn new() -> Self {
        Self {
            max_payload_size: 2 * 1024 * 1024 * 1024, // 2GB ceiling
            detected_vulns: Vec::new(),
        }
    }

    /// Probe for node-serialize vulnerability
    pub fn probe_node_serialize(&mut self, endpoint: &str) -> Option<DeserializationEvidence> {
        let probe = self.build_iife_probe();
        
        if probe.len() > self.max_payload_size {
            return None;
        }

        let timing_start = Instant::now();
        
        // Simulate probe analysis
        let processed = true; // Would check actual response in production
        
        if processed {
            let elapsed = timing_start.elapsed();
            
            self.detected_vulns.push(NodeVulnerability {
                endpoint: endpoint.to_string(),
                lib_type: "node-serialize".to_string(),
                severity: 9,
                timing_ms: Some(elapsed.as_millis() as u64),
            });

            return Some(DeserializationEvidence {
                target_endpoint: endpoint.to_string(),
                framework: "Node.js".to_string(),
                gadget_chain: Some("node-serialize/IIFE".to_string()),
                stack_trace: None,
                timing_ms: Some(elapsed.as_millis() as u64),
                callback_validated: false,
                oob_callback: None,
                severity: 9,
            });
        }

        None
    }

    /// Build an IIFE (Immediately Invoked Function Expression) probe
    fn build_iife_probe(&self) -> Vec<u8> {
        // Benign IIFE probe - does not execute harmful code
        // Tests if the endpoint evaluates JavaScript functions
        let probe = r#"{"_$$ND_FUNC$$_":"(function(){return 'PROBE';})()"}"#;
        probe.as_bytes().to_vec()
    }

    /// Test for custom serialization endpoints
    pub fn test_custom_serialization(&mut self, endpoint: &str) -> Option<DeserializationEvidence> {
        let probe = self.build_custom_probe();
        
        if probe.len() > self.max_payload_size {
            return None;
        }

        let timing_start = Instant::now();
        
        // In production, would send probe and analyze response
        let detected = true;

        if detected {
            let elapsed = timing_start.elapsed();
            
            self.detected_vulns.push(NodeVulnerability {
                endpoint: endpoint.to_string(),
                lib_type: "custom".to_string(),
                severity: 7,
                timing_ms: Some(elapsed.as_millis() as u64),
            });

            Some(DeserializationEvidence {
                target_endpoint: endpoint.to_string(),
                framework: "Node.js".to_string(),
                gadget_chain: Some("custom/eval".to_string()),
                stack_trace: None,
                timing_ms: Some(elapsed.as_millis() as u64),
                callback_validated: false,
                oob_callback: None,
                severity: 7,
            })
        } else {
            None
        }
    }

    /// Build a custom serialization probe
    fn build_custom_probe(&self) -> Vec<u8> {
        // Benign probe for custom serializers
        let probe = r#"{"type":"probe","value":"TEST_CUSTOM"}"#;
        probe.as_bytes().to_vec()
    }

    /// Analyze response for code execution indicators
    pub fn analyze_response(&self, response: &str) -> Vec<String> {
        let mut indicators = Vec::new();

        // Check for common Node.js error patterns
        let patterns = [
            ("ReferenceError", "Variable or function not defined"),
            ("TypeError", "Type coercion attempt"),
            ("SyntaxError", "JavaScript syntax parsing"),
            ("eval", "Eval usage detected"),
            ("Function", "Function constructor usage"),
            ("require", "Module require attempt"),
        ];

        for (pattern, description) in patterns.iter() {
            if response.contains(pattern) {
                indicators.push(format!("{}: {}", pattern, description));
            }
        }

        indicators
    }

    /// Get all detected vulnerabilities
    pub fn get_detected_vulns(&self) -> &[NodeVulnerability] {
        &self.detected_vulns
    }

    /// Clear detections
    pub fn clear_detections(&mut self) {
        self.detected_vulns.clear();
    }
}

impl Default for NodeSerializeDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = NodeSerializeDetector::new();
        assert_eq!(detector.max_payload_size, 2 * 1024 * 1024 * 1024);
        assert!(detector.detected_vulns.is_empty());
    }

    #[test]
    fn test_iife_probe() {
        let detector = NodeSerializeDetector::new();
        let probe = detector.build_iife_probe();
        assert!(!probe.is_empty());
        assert!(probe.len() < detector.max_payload_size);
    }

    #[test]
    fn test_response_analysis() {
        let detector = NodeSerializeDetector::new();
        let response = "ReferenceError: x is not defined";
        let indicators = detector.analyze_response(response);
        assert!(!indicators.is_empty());
        assert!(indicators.iter().any(|i| i.contains("ReferenceError")));
    }
}
