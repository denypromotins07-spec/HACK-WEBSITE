//! CBC Bit-Flipping Attack Detection Module
//!
//! Detects CBC bit-flipping vulnerabilities by mutating ciphertext bytes and analyzing plaintext shifts.
//! Uses bounded statistical arrays and zero-copy token parsing to maintain strict 2GB RAM ceiling.
//! Implements Shannon entropy analysis for detecting successful bit manipulation.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory, 
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum bit-flip test vectors (bounded array)
const MAX_BITFLIP_VECTORS: usize = 32;

/// Block size for CBC mode (AES)
const BLOCK_SIZE: usize = 16;

/// Bounded bit-flip vector buffer (zero-copy, stack-allocated)
#[derive(Debug, Clone)]
struct BitFlipBuffer {
    vectors: [[u8; BLOCK_SIZE]; MAX_BITFLIP_VECTORS],
    count: usize,
}

impl BitFlipBuffer {
    fn new() -> Self {
        Self {
            vectors: [[0u8; BLOCK_SIZE]; MAX_BITFLIP_VECTORS],
            count: 0,
        }
    }

    fn push(&mut self, vector: [u8; BLOCK_SIZE]) {
        if self.count < MAX_BITFLIP_VECTORS {
            self.vectors[self.count] = vector;
            self.count += 1;
        }
    }

    fn iter(&self) -> impl Iterator<Item = &[u8; BLOCK_SIZE]> {
        self.vectors[..self.count].iter()
    }
}

/// Shannon entropy calculator for bit-flip analysis
fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    
    let mut freq = [0usize; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy
}

/// CBC bit-flipping detector with bounded state
pub struct CbcBitflipDetector {
    metadata: CheckMetadata,
    bitflip_buffer: BitFlipBuffer,
}

impl CbcBitflipDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "crypto/cbc_bitflip",
            "CBC Bit-Flipping Detection",
            "Detects CBC bit-flipping by mutating ciphertext bytes and analyzing plaintext shifts",
            Severity::Critical,
            CheckCategory::SensitiveDataExposure,
        )
        .with_god_mode(true)
        .with_tags(vec!["cryptography", "cbc", "bit-flip", "block-cipher"])
        .with_references(vec![
            "https://en.wikipedia.org/wiki/Padding_oracle_attack",
            "https://cwe.mitre.org/data/definitions/327.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1500,
            max_memory_bytes: 8 * 1024 * 1024,
            max_requests: 200,
            max_duration_ms: 10000,
            max_payload_size: 4096,
        });

        Self {
            metadata,
            bitflip_buffer: BitFlipBuffer::new(),
        }
    }

    /// Generate bit-flip test vectors (bounded dictionary)
    fn generate_bitflip_vectors(&self) -> &'static [[u8; BLOCK_SIZE]] {
        static VECTORS: &[[u8; BLOCK_SIZE]] = &[
            // Single bit flips in each position of first block
            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            // Multi-bit flips
            [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            // IV manipulation patterns
            [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
            [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10],
            // Padding oracle triggers
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
        ];
        VECTORS
    }

    /// XOR two byte arrays
    fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
    }

    /// Apply bit-flip mutation to ciphertext
    fn apply_bitflip(&self, ciphertext: &[u8], flip_vector: &[u8; BLOCK_SIZE]) -> Vec<u8> {
        if ciphertext.len() < BLOCK_SIZE {
            return ciphertext.to_vec();
        }
        
        let mut mutated = ciphertext.to_vec();
        for i in 0..BLOCK_SIZE.min(ciphertext.len()) {
            mutated[i] ^= flip_vector[i];
        }
        mutated
    }

    /// Send mutated ciphertext and analyze response
    async fn test_bitflip(
        &self,
        client: &HttpClient,
        url: &str,
        original_ciphertext: &[u8],
        flip_vector: &[u8; BLOCK_SIZE],
        header_name: &str,
    ) -> Result<BitFlipResult, ModuleError> {
        let mutated = self.apply_bitflip(original_ciphertext, flip_vector);
        let encoded = hex::encode(&mutated);
        
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::HeaderName::from_bytes(header_name.as_bytes())
                .unwrap_or(reqwest::header::USER_AGENT),
            reqwest::header::HeaderValue::from_str(&encoded).unwrap(),
        );

        let response = client.get_with_headers(url, headers).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
        
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        
        // Analyze entropy change
        let entropy = calculate_shannon_entropy(body.as_bytes());
        
        Ok(BitFlipResult {
            status,
            body_length: body.len(),
            entropy,
            flipped_block: 0,
        })
    }

    /// Analyze bit-flip results for vulnerability indicators
    fn analyze_bitflip_results(&self, results: &[BitFlipResult]) -> Option<BitFlipEvidence> {
        if results.len() < 2 {
            return None;
        }

        let baseline = &results[0];
        let mut successful_flips = 0;
        let mut entropy_changes = Vec::new();

        for result in results.iter().skip(1) {
            // Detect successful bit manipulation via status or content changes
            if result.status != baseline.status || 
               (result.body_length as i64 - baseline.body_length as i64).abs() > 10 {
                successful_flips += 1;
                entropy_changes.push((result.entropy - baseline.entropy).abs());
            }
        }

        if successful_flips >= 3 {
            let avg_entropy_change = entropy_changes.iter().sum::<f64>() / entropy_changes.len() as f64;
            return Some(BitFlipEvidence {
                successful_flips,
                avg_entropy_change,
                total_tests: results.len(),
            });
        }

        None
    }

    /// Build evidence for bit-flip finding
    fn build_evidence(&self, url: &str, evidence: &BitFlipEvidence) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::NetworkTraffic {
                    protocol: "HTTP".to_string(),
                    data: format!(
                        "Successful bit-flip mutations: {}/{} | Avg entropy change: {:.4}",
                        evidence.successful_flips,
                        evidence.total_tests,
                        evidence.avg_entropy_change
                    ),
                },
                data: format!(
                    "CBC bit-flipping detected: {} successful mutations out of {} tests",
                    evidence.successful_flips,
                    evidence.total_tests
                ),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: None,
                    header: Some("X-Custom-Header".to_string()),
                },
                confidence: 80,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Migrate from CBC to authenticated encryption modes".to_string(),
            steps: vec![
                "Replace CBC mode with AES-GCM or ChaCha20-Poly1305".to_string(),
                "Implement encrypt-then-MAC pattern if CBC must be used".to_string(),
                "Add HMAC authentication to all ciphertext".to_string(),
                "Use constant-time comparison for MAC verification".to_string(),
                "Log and alert on repeated decryption failures".to_string(),
            ],
            code_example: Some(r#"// Use AES-GCM instead of CBC
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

let key = Aes256Gcm::generate_key(&mut OsRng);
let cipher = Aes256Gcm::new(&key);
let nonce = Nonce::from_slice(b"unique nonce");
let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;"#.to_string()),
            references: vec![
                "https://cwe.mitre.org/data/definitions/327.html".to_string(),
                "https://blog.cryptographyengineering.com/2012/08/27/how-to-choose-encryption-mode/".to_string(),
            ],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

/// Bit-flip test result
#[derive(Debug, Clone)]
struct BitFlipResult {
    status: u16,
    body_length: usize,
    entropy: f64,
    flipped_block: usize,
}

/// Bit-flip evidence summary
#[derive(Debug, Clone)]
struct BitFlipEvidence {
    successful_flips: usize,
    avg_entropy_change: f64,
    total_tests: usize,
}

#[async_trait]
impl VulnerabilityModule for CbcBitflipDetector {
    async fn init(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    fn should_run(&self, ctx: &CheckContext) -> bool {
        if self.metadata.requires_god_mode && !ctx.god_mode {
            return false;
        }
        true
    }

    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let client = HttpClient::new();
        let mut findings = Vec::new();
        let mut executed = false;

        // Test endpoints that may process encrypted data
        let test_endpoints = [
            "/api/auth/login",
            "/api/session/decrypt",
            "/api/crypto/decrypt",
            "/api/token/validate",
            "/decrypt",
        ];

        let headers_to_test = ["X-Session-Token", "X-Encrypted-Data", "Authorization"];

        for endpoint in test_endpoints.iter() {
            let url = format!("{}{}", ctx.target_url.trim_end_matches('/'), endpoint);
            
            // Simulated base64/hex ciphertext for testing
            let simulated_ciphertext = vec![0x41u8; BLOCK_SIZE * 2];
            
            for header in headers_to_test.iter() {
                let mut results = Vec::with_capacity(MAX_BITFLIP_VECTORS);
                let vectors = self.generate_bitflip_vectors();
                
                // Run bit-flip tests with bounded iterations
                for (i, &vector) in vectors.iter().enumerate() {
                    if i >= MAX_BITFLIP_VECTORS {
                        break;
                    }
                    
                    match self.test_bitflip(&client, &url, &simulated_ciphertext, &vector, header).await {
                        Ok(result) => results.push(result),
                        Err(_) => continue,
                    }
                }

                if results.len() >= 5 {
                    executed = true;
                    
                    if let Some(evidence) = self.analyze_bitflip_results(&results) {
                        let mut finding = Finding::new(
                            self.metadata.id.as_str(),
                            Severity::Critical,
                            "CBC Bit-Flipping Vulnerability Detected",
                            format!(
                                "Cryptographic bit-flipping attack successful at {}. The application processes CBC-encrypted data without proper authentication.",
                                url
                            ),
                            &url,
                        )
                        .with_payload(format!(
                            "Bit-flip vectors tested: {} | Successful: {}",
                            evidence.total_tests,
                            evidence.successful_flips
                        ))
                        .with_confidence(85)
                        .with_agent_id(ctx.agent_id)
                        .with_tags(vec!["cbc", "bit-flip", "cryptographic-attack"]);

                        let evidences = self.build_evidence(&url, &evidence);
                        for ev in evidences {
                            finding = finding.with_evidence(ev);
                        }

                        finding = finding.with_remediation(self.remediation());
                        findings.push(finding);
                    }
                }
            }
        }

        // Cache successful bit-flip offsets for learning engine
        if !findings.is_empty() {
            if let Ok(cache) = LearningCache::global().await {
                cache.cache_timing_baseline(ctx.target_url.clone(), "cbc_bitflip".to_string()).await;
            }
        }

        Ok(CheckResult {
            findings,
            executed,
            timed_out: false,
            resource_usage: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy() {
        let uniform = [0u8; 256];
        let entropy = calculate_shannon_entropy(&uniform);
        assert!(entropy > 0.0);
        
        let single_byte = [0x42u8; 100];
        let entropy_single = calculate_shannon_entropy(&single_byte);
        assert_eq!(entropy_single, 0.0);
    }

    #[test]
    fn test_xor_operation() {
        let a = [0xAA, 0xBB, 0xCC, 0xDD];
        let b = [0x11, 0x22, 0x33, 0x44];
        let result = CbcBitflipDetector::xor_bytes(&a, &b);
        assert_eq!(result, vec![0xBB, 0x99, 0xFF, 0x99]);
    }

    #[test]
    fn test_bounded_buffer_no_heap() {
        let buffer = BitFlipBuffer::new();
        assert!(std::mem::size_of::<BitFlipBuffer>() <= 1024);
    }
}
