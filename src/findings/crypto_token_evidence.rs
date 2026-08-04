//! Crypto and Token Evidence Container Module
//!
//! Builds evidence containers with ciphertext diffs, token payloads, and entropy graphs.

use serde::{Serialize, Deserialize};
use crate::findings::finding::{Evidence, EvidenceType};

/// Cryptographic diff evidence for bit-flip and padding oracle attacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoDiff {
    pub original_hex: String,
    pub mutated_hex: String,
    pub diff_bytes: Vec<u8>,
    pub plaintext_shift: Option<String>,
}

/// Token payload evidence for JWT/OIDC attacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPayload {
    pub header: String,
    pub claims: String,
    pub signature_status: SignatureStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureStatus {
    Valid,
    Stripped,
    Invalid,
    AlgorithmNone,
}

/// Entropy graph data for session analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyGraph {
    pub samples: Vec<f64>,
    pub average: f64,
    pub minimum: f64,
    pub maximum: f64,
    pub threshold: f64,
}

impl CryptoDiff {
    pub fn new(original: &[u8], mutated: &[u8]) -> Self {
        let diff_bytes: Vec<u8> = original.iter()
            .zip(mutated.iter())
            .map(|(&a, &b)| a ^ b)
            .collect();
        
        Self {
            original_hex: hex::encode(original),
            mutated_hex: hex::encode(mutated),
            diff_bytes,
            plaintext_shift: None,
        }
    }

    pub fn with_plaintext_shift(mut self, shift: String) -> Self {
        self.plaintext_shift = Some(shift);
        self
    }
}

impl TokenPayload {
    pub fn new(header: String, claims: String, status: SignatureStatus) -> Self {
        Self { header, claims, signature_status: status }
    }
}

impl EntropyGraph {
    pub fn new(samples: Vec<f64>, threshold: f64) -> Self {
        let avg = samples.iter().sum::<f64>() / samples.len().max(1) as f64;
        let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        Self { samples, average: avg, minimum: min, maximum: max, threshold }
    }

    pub fn below_threshold(&self) -> bool {
        self.average < self.threshold
    }
}

/// Builder for crypto/token evidence
pub struct CryptoTokenEvidenceBuilder {
    evidences: Vec<Evidence>,
}

impl CryptoTokenEvidenceBuilder {
    pub fn new() -> Self {
        Self { evidences: Vec::new() }
    }

    pub fn add_crypto_diff(mut self, diff: &CryptoDiff, location: &str) -> Self {
        self.evidences.push(Evidence {
            evidence_type: EvidenceType::NetworkTraffic {
                protocol: "CRYPTO".to_string(),
                data: format!("Original: {} | Mutated: {}", diff.original_hex, diff.mutated_hex),
            },
            data: format!("Bit-flip diff: {} bytes changed", diff.diff_bytes.iter().filter(|&&b| b != 0).count()),
            location: crate::findings::finding::EvidenceLocation {
                path: location.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 85,
        });
        self
    }

    pub fn add_token_payload(mut self, payload: &TokenPayload, location: &str) -> Self {
        self.evidences.push(Evidence {
            evidence_type: EvidenceType::HttpRequestResponse {
                request: format!("JWT Header: {}", payload.header),
                response: format!("Claims: {}", payload.claims),
            },
            data: format!("Signature status: {:?}", payload.signature_status),
            location: crate::findings::finding::EvidenceLocation {
                path: location.to_string(),
                line: None,
                parameter: Some("Authorization".to_string()),
                header: None,
            },
            confidence: 90,
        });
        self
    }

    pub fn add_entropy_graph(mut self, graph: &EntropyGraph, location: &str) -> Self {
        self.evidences.push(Evidence {
            evidence_type: EvidenceType::Configuration {
                key: "session_entropy".to_string(),
                value: format!("avg={:.2}, min={:.2}, max={:.2}", graph.average, graph.minimum, graph.maximum),
            },
            data: if graph.below_threshold() {
                "Session entropy below secure threshold".to_string()
            } else {
                "Session entropy within acceptable range".to_string()
            },
            location: crate::findings::finding::EvidenceLocation {
                path: location.to_string(),
                line: None,
                parameter: Some("Set-Cookie".to_string()),
                header: None,
            },
            confidence: 80,
        });
        self
    }

    pub fn build(self) -> Vec<Evidence> {
        self.evidences
    }
}

impl Default for CryptoTokenEvidenceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_diff_creation() {
        let original = vec![0x41, 0x42, 0x43];
        let mutated = vec![0x41, 0x43, 0x43];
        let diff = CryptoDiff::new(&original, &mutated);
        assert_eq!(diff.diff_bytes.len(), 3);
        assert_eq!(diff.diff_bytes[1], 0x01);
    }

    #[test]
    fn test_entropy_graph_threshold() {
        let samples = vec![2.0, 2.5, 3.0];
        let graph = EntropyGraph::new(samples, 4.0);
        assert!(graph.below_threshold());
    }
}
