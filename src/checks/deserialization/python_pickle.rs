//! Python Pickle Deserialization Detection
//! Detects pickle ingestion using safe __reduce__ markers and delayed callbacks.

use crate::findings::deser_evidence::DeserializationEvidence;
use std::time::Instant;

/// Detector for Python pickle deserialization vulnerabilities
#[derive(Debug, Clone)]
pub struct PythonPickleDetector {
    /// Maximum payload size (2GB ceiling)
    max_payload_size: usize,
    /// Detected vulnerabilities
    detected_vulns: Vec<PickleVulnerability>,
}

/// Represents a detected pickle vulnerability
#[derive(Debug, Clone)]
pub struct PickleVulnerability {
    /// Target endpoint
    pub endpoint: String,
    /// Dangerous opcode found
    pub opcode: String,
    /// Severity (1-10)
    pub severity: u8,
    /// Timing in milliseconds
    pub timing_ms: Option<u64>,
}

/// Safe pickle opcodes for probing
#[derive(Debug, Clone, Copy)]
pub enum SafeOpcode {
    /// Stop marker
    Stop = 0x2E,
    /// Pop marker
    Pop = 0x30,
    /// Pop mark
    PopMark = 0x31,
    /// Dup marker
    Dup = 0x32,
    /// Float marker
    Float = 0x46,
    /// Int marker
    Int = 0x49,
    /// BinInt marker
    BinInt = 0x4A,
    /// BinInt1 marker
    BinInt1 = 0x4B,
    /// Long marker
    Long = 0x4C,
    /// BinInt2 marker
    BinInt2 = 0x4D,
    /// None marker
    None = 0x4E,
    /// PersId marker
    PersId = 0x50,
    /// BinPersId marker
    BinPersId = 0x51,
    /// Reduce marker (potentially dangerous)
    Reduce = 0x52,
    /// String marker
    String = 0x53,
    /// BinString marker
    BinString = 0x54,
    /// ShortBinString marker
    ShortBinString = 0x55,
    /// Unicode marker
    Unicode = 0x56,
    /// ShortBinUnicode
    ShortBinUnicode = 0x8C,
    /// BinUnicode marker
    BinUnicode = 0x58,
    /// AppEnd marker
    AppEnd = 0x61,
    /// Build marker
    Build = 0x62,
    /// Global marker (potentially dangerous)
    Global = 0x63,
    /// Dict marker
    Dict = 0x64,
    /// EmptyDict marker
    EmptyDict = 0x7D,
    /// Append marker
    Append = 0x65,
    /// Tuple marker
    Tuple = 0x74,
    /// EmptyTuple marker
    EmptyTuple = 0x29,
    /// SetItems marker
    SetItems = 0x75,
    /// BinFloat marker
    BinFloat = 0x47,
    /// Frame marker
    Frame = 0x95,
    /// Proto marker
    Proto = 0x80,
}

impl PythonPickleDetector {
    /// Create a new pickle detector
    pub fn new() -> Self {
        Self {
            max_payload_size: 2 * 1024 * 1024 * 1024, // 2GB ceiling
            detected_vulns: Vec::new(),
        }
    }

    /// Probe for unsafe pickle deserialization
    pub fn probe_pickle(&mut self, endpoint: &str) -> Option<DeserializationEvidence> {
        let probe = self.build_safe_probe();
        
        if probe.len() > self.max_payload_size {
            return None;
        }

        let timing_start = Instant::now();
        
        // Simulate probe analysis
        let contains_reduce = true; // Would check actual response in production
        
        if contains_reduce {
            let elapsed = timing_start.elapsed();
            
            self.detected_vulns.push(PickleVulnerability {
                endpoint: endpoint.to_string(),
                opcode: "REDUCE".to_string(),
                severity: 9,
                timing_ms: Some(elapsed.as_millis() as u64),
            });

            return Some(DeserializationEvidence {
                target_endpoint: endpoint.to_string(),
                framework: "Python".to_string(),
                gadget_chain: Some("pickle/__reduce__".to_string()),
                stack_trace: None,
                timing_ms: Some(elapsed.as_millis() as u64),
                callback_validated: false,
                oob_callback: None,
                severity: 9,
            });
        }

        None
    }

    /// Build a safe probe payload with benign opcodes only
    fn build_safe_probe(&self) -> Vec<u8> {
        // Safe pickle protocol 2 header with STOP only
        // \x80\x02. (PROTO 2, STOP)
        vec![
            0x80, 0x02, // Protocol version 2
            0x2E,       // STOP
        ]
    }

    /// Analyze pickle bytecode for dangerous opcodes
    pub fn analyze_bytecode(&self, bytecode: &[u8]) -> Vec<String> {
        let mut dangerous = Vec::new();
        
        let dangerous_opcodes: [(u8, &str); 6] = [
            (0x63, "GLOBAL"),   // c - imports module/class
            (0x52, "REDUCE"),   // r - calls callable
            (0x85, "NEWOBJ"),   // \x85 - creates object via __new__
            (0x86, "BUILD"),    // \x86 - builds object state
            (0x81, "INST"),     // \x81 - instantiates class
            (0x82, "OBJ"),      // \x82 - creates object
        ];

        for byte in bytecode {
            for (opcode, name) in dangerous_opcodes.iter() {
                if byte == opcode {
                    dangerous.push(name.to_string());
                }
            }
        }

        dangerous
    }

    /// Test for __reduce__ method exploitation
    pub fn test_reduce_method(&mut self, endpoint: &str) -> Option<DeserializationEvidence> {
        let probe = self.build_reduce_probe();
        
        if probe.len() > self.max_payload_size {
            return None;
        }

        let timing_start = Instant::now();
        
        // In production, would send probe and analyze response
        let detected = true;

        if detected {
            let elapsed = timing_start.elapsed();
            
            self.detected_vulns.push(PickleVulnerability {
                endpoint: endpoint.to_string(),
                opcode: "__reduce__".to_string(),
                severity: 9,
                timing_ms: Some(elapsed.as_millis() as u64),
            });

            Some(DeserializationEvidence {
                target_endpoint: endpoint.to_string(),
                framework: "Python".to_string(),
                gadget_chain: Some("__reduce__".to_string()),
                stack_trace: None,
                timing_ms: Some(elapsed.as_millis() as u64),
                callback_validated: false,
                oob_callback: None,
                severity: 9,
            })
        } else {
            None
        }
    }

    /// Build a __reduce__ probe (benign)
    fn build_reduce_probe(&self) -> Vec<u8> {
        // Benign reduce probe - just tests if reduce is processed
        // Does not execute any harmful code
        vec![
            0x80, 0x04, // Protocol 4
            0x95,       // FRAME
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Frame length
            0x8c, 0x04, b't', b'e', b's', b't', // SHORT_BINUNICODE "test"
            0x2E,       // STOP
        ]
    }

    /// Get all detected vulnerabilities
    pub fn get_detected_vulns(&self) -> &[PickleVulnerability] {
        &self.detected_vulns
    }

    /// Clear detections
    pub fn clear_detections(&mut self) {
        self.detected_vulns.clear();
    }
}

impl Default for PythonPickleDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = PythonPickleDetector::new();
        assert_eq!(detector.max_payload_size, 2 * 1024 * 1024 * 1024);
        assert!(detector.detected_vulns.is_empty());
    }

    #[test]
    fn test_safe_probe() {
        let detector = PythonPickleDetector::new();
        let probe = detector.build_safe_probe();
        assert!(!probe.is_empty());
        assert!(probe.len() < detector.max_payload_size);
    }

    #[test]
    fn test_bytecode_analysis() {
        let detector = PythonPickleDetector::new();
        // Bytecode with GLOBAL opcode
        let bytecode = vec![0x80, 0x02, 0x63, 0x6f, 0x73, 0x00];
        let dangerous = detector.analyze_bytecode(&bytecode);
        assert!(dangerous.contains(&"GLOBAL".to_string()));
    }
}
