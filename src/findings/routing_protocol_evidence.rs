//! Routing and Protocol Evidence Containers
//! Builds evidence containers with raw frame dumps, TLS handshake diffs, and timing logs.
//! Uses zero-copy byte buffers and bounded storage (Stage 1 memory constraints).

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum evidence entries per finding (bounded)
const MAX_EVIDENCE_ENTRIES: usize = 32;

/// Maximum raw frame dump size (bounded to 4KB)
const MAX_FRAME_DUMP_SIZE: usize = 4096;

#[derive(Debug, Clone)]
pub struct RoutingProtocolEvidence {
    pub check_name: String,
    pub target: String,
    pub severity: String,
    pub timestamp: Instant,
    pub raw_frame_dump: Vec<u8>,
    pub tls_handshake_diff: Option<TlsHandshakeDiff>,
    pub timing_logs: Vec<TimingLog>,
    pub response_delta: ResponseDelta,
    pub remediation: String,
    pub payload_used: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TlsHandshakeDiff {
    pub expected_sni: String,
    pub actual_sni: String,
    pub expected_alpn: Vec<String>,
    pub actual_alpn: Vec<String>,
    pub cipher_mismatch: bool,
    pub version_downgrade: bool,
}

#[derive(Debug, Clone)]
pub struct TimingLog {
    pub operation: String,
    pub duration_ns: u64,
    pub variance_ns: u64,
    pub sample_count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ResponseDelta {
    pub status_code_diff: Option<(u16, u16)>,
    pub header_count_diff: Option<(usize, usize)>,
    pub body_size_diff: Option<(usize, usize)>,
    pub content_hash_diff: Option<(String, String)>,
}

impl RoutingProtocolEvidence {
    pub fn new(
        check_name: &str,
        target: &str,
        severity: &str,
        remediation: &str,
    ) -> Self {
        Self {
            check_name: check_name.to_string(),
            target: target.to_string(),
            severity: severity.to_string(),
            timestamp: Instant::now(),
            raw_frame_dump: Vec::with_capacity(MAX_FRAME_DUMP_SIZE),
            tls_handshake_diff: None,
            timing_logs: Vec::with_capacity(16),
            response_delta: ResponseDelta::default(),
            remediation: remediation.to_string(),
            payload_used: None,
        }
    }

    /// Add raw frame dump (bounded)
    pub fn add_frame_dump(&mut self, data: &[u8]) {
        let len = std::cmp::min(data.len(), MAX_FRAME_DUMP_SIZE);
        self.raw_frame_dump.clear();
        self.raw_frame_dump.extend_from_slice(&data[..len]);
    }

    /// Set TLS handshake diff
    pub fn set_tls_diff(
        &mut self,
        expected_sni: &str,
        actual_sni: &str,
        expected_alpn: Vec<String>,
        actual_alpn: Vec<String>,
        cipher_mismatch: bool,
        version_downgrade: bool,
    ) {
        self.tls_handshake_diff = Some(TlsHandshakeDiff {
            expected_sni: expected_sni.to_string(),
            actual_sni: actual_sni.to_string(),
            expected_alpn,
            actual_alpn,
            cipher_mismatch,
            version_downgrade,
        });
    }

    /// Add timing log entry
    pub fn add_timing_log(&mut self, operation: &str, duration_ns: u64) {
        if self.timing_logs.len() >= MAX_EVIDENCE_ENTRIES {
            return; // Bounded capacity
        }

        self.timing_logs.push(TimingLog {
            operation: operation.to_string(),
            duration_ns,
            variance_ns: 0,
            sample_count: 1,
        });
    }

    /// Calculate timing statistics
    pub fn calculate_timing_stats(&mut self) {
        if self.timing_logs.is_empty() {
            return;
        }

        let avg = self.timing_logs.iter()
            .map(|t| t.duration_ns)
            .sum::<u64>() / self.timing_logs.len() as u64;

        for log in self.timing_logs.iter_mut() {
            log.variance_ns = log.duration_ns.saturating_sub(avg);
            log.sample_count = self.timing_logs.len() as u32;
        }
    }

    /// Set response delta
    pub fn set_response_delta(
        &mut self,
        status_before: u16,
        status_after: u16,
        headers_before: usize,
        headers_after: usize,
        body_before: usize,
        body_after: usize,
    ) {
        self.response_delta.status_code_diff = Some((status_before, status_after));
        self.response_delta.header_count_diff = Some((headers_before, headers_after));
        self.response_delta.body_size_diff = Some((body_before, body_after));
    }

    /// Serialize evidence to JSON-like format (bounded)
    pub fn to_bounded_json(&self) -> String {
        let mut json = String::with_capacity(2048);
        json.push_str("{\n");
        json.push_str(&format!("  \"check\": \"{}\",\n", self.check_name));
        json.push_str(&format!("  \"target\": \"{}\",\n", self.target));
        json.push_str(&format!("  \"severity\": \"{}\",\n", self.severity));
        json.push_str(&format!("  \"frame_size\": {},\n", self.raw_frame_dump.len()));
        
        if let Some(ref tls) = self.tls_handshake_diff {
            json.push_str(&format!("  \"sni_expected\": \"{}\",\n", tls.expected_sni));
            json.push_str(&format!("  \"sni_actual\": \"{}\",\n", tls.actual_sni));
        }
        
        json.push_str(&format!("  \"timing_entries\": {},\n", self.timing_logs.len()));
        json.push_str(&format!("  \"remediation\": \"{}\"\n", self.remediation));
        json.push_str("}\n");
        
        json
    }
}

/// Evidence container builder with bounded storage
pub struct EvidenceBuilder {
    evidences: Vec<RoutingProtocolEvidence>,
    max_evidences: usize,
}

impl EvidenceBuilder {
    pub fn new(max_evidences: usize) -> Self {
        Self {
            evidences: Vec::with_capacity(std::cmp::min(max_evidences, MAX_EVIDENCE_ENTRIES)),
            max_evidences: std::cmp::min(max_evidences, MAX_EVIDENCE_ENTRIES),
        }
    }

    pub fn add_evidence(&mut self, evidence: RoutingProtocolEvidence) {
        if self.evidences.len() < self.max_evidences {
            self.evidences.push(evidence);
        }
    }

    pub fn build(self) -> Vec<RoutingProtocolEvidence> {
        self.evidences
    }

    pub fn count(&self) -> usize {
        self.evidences.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_creation() {
        let mut evidence = RoutingProtocolEvidence::new(
            "sni_routing",
            "https://example.com",
            "HIGH",
            "Enforce SNI validation"
        );
        
        evidence.add_frame_dump(b"\x16\x03\x01");
        assert_eq!(evidence.raw_frame_dump.len(), 3);
    }

    #[test]
    fn test_evidence_builder() {
        let mut builder = EvidenceBuilder::new(10);
        
        for i in 0..15 {
            builder.add_evidence(RoutingProtocolEvidence::new(
                &format!("check_{}", i),
                "target",
                "MEDIUM",
                "Fix it"
            ));
        }
        
        assert_eq!(builder.count(), 10); // Bounded to max
    }
}
