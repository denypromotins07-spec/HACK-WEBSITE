//! RSA Bleichenbacher Padding Oracle Detection Module
//!
//! Detects RSA padding oracle vulnerabilities via strict timing and error message analysis.
//! Implements bounded state machines for PKCS#1 v1.5 padding validation detection.
//! Uses nanosecond-precision timing arrays with zero-copy semantics.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::{Duration, Instant};
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory, 
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum timing samples per oracle test (bounded array)
const MAX_TIMING_SAMPLES: usize = 24;

/// Timing differential threshold in nanoseconds for Bleichenbacher detection
const BLEICHENBACHER_THRESHOLD_NS: u128 = 100_000_000; // 100ms

/// Bounded timing sample buffer (zero-copy, stack-allocated)
#[derive(Debug, Clone)]
struct TimingBuffer {
    samples: [u128; MAX_TIMING_SAMPLES],
    count: usize,
}

impl TimingBuffer {
    fn new() -> Self {
        Self {
            samples: [0; MAX_TIMING_SAMPLES],
            count: 0,
        }
    }

    fn push(&mut self, sample: u128) {
        if self.count < MAX_TIMING_SAMPLES {
            self.samples[self.count] = sample;
            self.count += 1;
        }
    }

    fn mean(&self) -> u128 {
        if self.count == 0 {
            return 0;
        }
        let sum: u128 = self.samples[..self.count].iter().sum();
        sum / self.count as u128
    }

    fn variance(&self) -> u128 {
        if self.count < 2 {
            return 0;
        }
        let mean = self.mean();
        let sum_sq: u128 = self.samples[..self.count]
            .iter()
            .map(|&x| (x as i128 - mean as i128).abs() as u128)
            .sum();
        sum_sq / (self.count - 1) as u128
    }
}

/// Bleichenbacher oracle detector with bounded state
pub struct BleichenbacherDetector {
    metadata: CheckMetadata,
    timing_buffer: TimingBuffer,
}

impl BleichenbacherDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "crypto/bleichenbacher",
            "RSA Bleichenbacher Padding Oracle Detection",
            "Detects RSA padding oracle vulnerabilities via strict timing and error message analysis",
            Severity::Critical,
            CheckCategory::SensitiveDataExposure,
        )
        .with_god_mode(true)
        .with_tags(vec!["cryptography", "rsa", "bleichenbacher", "padding-oracle"])
        .with_references(vec![
            "https://en.wikipedia.org/wiki/Bleichenbacher_attack",
            "https://cwe.mitre.org/data/definitions/696.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 2000,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 150,
            max_duration_ms: 15000,
            max_payload_size: 2048,
        });

        Self {
            metadata,
            timing_buffer: TimingBuffer::new(),
        }
    }

    /// Generate PKCS#1 v1.5 test payloads (bounded dictionary)
    fn generate_rsa_payloads(&self) -> &'static [&'static [u8]] {
        static PAYLOADS: &[&[u8]] = &[
            // Valid PKCS#1 v1.5 padding structure (00 02 [random non-zero] 00 [data])
            b"\x00\x02\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00",
            b"\x00\x02\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x00",
            // Invalid padding - wrong version byte
            b"\x00\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00",
            b"\x00\x03\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00",
            // Invalid padding - missing separator
            b"\x00\x02\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
            b"\x00\x02\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
            // Edge cases
            b"\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ];
        PAYLOADS
    }

    /// Send request and measure timing with nanosecond precision
    async fn measure_timing(
        &self,
        client: &HttpClient,
        url: &str,
        payload: &[u8],
        header_name: &str,
    ) -> Result<(u128, String, u16), ModuleError> {
        let start = Instant::now();
        
        let mut headers = reqwest::header::HeaderMap::new();
        let header_value = format!("{}", hex::encode(payload));
        headers.insert(
            reqwest::header::HeaderName::from_bytes(header_name.as_bytes())
                .unwrap_or(reqwest::header::USER_AGENT),
            reqwest::header::HeaderValue::from_str(&header_value).unwrap(),
        );

        let response = client.get_with_headers(url, headers).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
        
        let elapsed = start.elapsed().as_nanos();
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        Ok((elapsed, body, status))
    }

    /// Analyze error messages for Bleichenbacher oracle indicators
    fn detect_error_patterns(&self, body: &str, status: u16) -> Option<&'static str> {
        static ORACLE_PATTERNS: &[(&str, &str)] = &[
            ("pkcs", "PKCS#1 parsing error"),
            ("rsa.*pad", "RSA padding error"),
            ("decrypt.*fail", "Decryption failed"),
            ("invalid.*cipher", "Invalid ciphertext"),
            ("malformed.*pkcs", "Malformed PKCS#1 block"),
            ("bad.*format", "Bad format exception"),
            ("padding.*byte", "Padding byte error"),
            ("version.*byte", "Version byte mismatch"),
        ];

        let body_lower = body.to_lowercase();
        for (pattern, description) in ORACLE_PATTERNS {
            if body_lower.contains(pattern) {
                return Some(description);
            }
        }

        // Status-based detection
        match status {
            500 | 503 => Some("Internal server error on malformed RSA input"),
            400 => Some("Bad request indicating RSA input validation"),
            _ => None
        }
    }

    /// Detect timing-based Bleichenbacher oracle
    async fn detect_timing_oracle(
        &self,
        client: &HttpClient,
        url: &str,
        header: &str,
    ) -> Result<Option<(u128, u128)>, ModuleError> {
        let payloads = self.generate_rsa_payloads();
        let mut valid_padding_times = TimingBuffer::new();
        let mut invalid_padding_times = TimingBuffer::new();

        for (i, &payload) in payloads.iter().enumerate() {
            if i >= MAX_TIMING_SAMPLES {
                break;
            }

            let (timing, _, status) = self.measure_timing(client, url, payload, header).await?;
            
            // Classify based on padding validity heuristic
            // Valid PKCS#1 v1.5 starts with 00 02 and has at least 8 non-zero bytes before 00
            let is_valid_padding = payload.len() >= 17 && 
                payload[0] == 0x00 && 
                payload[1] == 0x02 &&
                payload[2..10].iter().all(|&b| b != 0x00) &&
                payload[payload.len() - 1] == 0x00;

            if is_valid_padding && status == 200 {
                valid_padding_times.push(timing);
            } else {
                invalid_padding_times.push(timing);
            }
        }

        let valid_mean = valid_padding_times.mean();
        let invalid_mean = invalid_padding_times.mean();

        if valid_mean > 0 && invalid_mean > 0 {
            let diff = (valid_mean as i128 - invalid_mean as i128).unsigned_abs();
            if diff > BLEICHENBACHER_THRESHOLD_NS {
                return Ok(Some((diff, valid_mean.max(invalid_mean))));
            }
        }

        Ok(None)
    }

    /// Build evidence for Bleichenbacher finding
    fn build_evidence(
        &self,
        url: &str,
        timing_diff: u128,
        error_pattern: Option<&str>,
    ) -> Vec<Evidence> {
        let mut evidence = Vec::with_capacity(2);

        if timing_diff > 0 {
            evidence.push(Evidence {
                evidence_type: EvidenceType::Timing {
                    baseline_ms: 0,
                    observed_ms: timing_diff / 1_000_000,
                    difference_ms: timing_diff / 1_000_000,
                },
                data: format!("Timing differential: {}ns (threshold: {}ns)", 
                    timing_diff, BLEICHENBACHER_THRESHOLD_NS),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: None,
                    header: Some("X-Custom-Header".to_string()),
                },
                confidence: 85,
            });
        }

        if let Some(pattern) = error_pattern {
            evidence.push(Evidence {
                evidence_type: EvidenceType::ErrorMessage {
                    message: pattern.to_string(),
                    stack_trace: None,
                },
                data: "Error message reveals RSA padding validation".to_string(),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: None,
                    header: None,
                },
                confidence: 90,
            });
        }

        evidence
    }

    /// Generate remediation hint for Bleichenbacher
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Use RSA-OAEP padding instead of PKCS#1 v1.5".to_string(),
            steps: vec![
                "Migrate from PKCS#1 v1.5 to OAEP padding scheme".to_string(),
                "Implement constant-time RSA decryption".to_string(),
                "Use RSA-PSS for signatures instead of PKCS#1 v1.5".to_string(),
                "Add rate limiting on decryption endpoints".to_string(),
                "Log and alert on repeated RSA errors".to_string(),
            ],
            code_example: Some(r#"// Use RSA-OAEP instead of PKCS#1 v1.5
use rsa::{RsaPrivateKey, Pkcs1v15Encrypt, Oaep};
use sha2::Sha256;

let private_key = RsaPrivateKey::new(&mut OsRng, 2048)?;
let padding = Oaep::new::<Sha256>();
let decrypted = private_key.decrypt(padding, &ciphertext)?;"#.to_string()),
            references: vec![
                "https://cwe.mitre.org/data/definitions/696.html".to_string(),
                "https://blog.cryptographyengineering.com/2013/01/30/how-do-you-know-if-encryption-is/".to_string(),
            ],
            estimated_effort: EffortLevel::High,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for BleichenbacherDetector {
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

        // Test endpoints that may perform RSA operations
        let test_endpoints = [
            "/api/auth/decrypt",
            "/api/crypto/rsa-decrypt",
            "/api/key/unwrap",
            "/api/token/decrypt",
            "/decrypt",
            "/api/jwt/verify",
        ];

        let headers_to_test = ["X-Encrypted-Key", "X-RSA-Payload", "Authorization"];

        for endpoint in test_endpoints.iter() {
            let url = format!("{}{}", ctx.target_url.trim_end_matches('/'), endpoint);
            
            for header in headers_to_test.iter() {
                // Timing-based detection
                if let Ok(Some((diff, avg_time))) = self.detect_timing_oracle(&client, &url, header).await {
                    executed = true;
                    
                    let mut finding = Finding::new(
                        self.metadata.id.as_str(),
                        Severity::Critical,
                        "RSA Bleichenbacher Oracle Detected (Timing-Based)",
                        format!("RSA padding oracle vulnerability detected at {} via timing analysis", url),
                        &url,
                    )
                    .with_payload(format!("PKCS#1 v1.5 padding test via {}", header))
                    .with_confidence(85)
                    .with_agent_id(ctx.agent_id)
                    .with_tags(vec!["bleichenbacher", "timing-attack", "rsa"]);

                    let evidence = self.build_evidence(&url, diff, None);
                    for ev in evidence {
                        finding = finding.with_evidence(ev);
                    }

                    finding = finding.with_remediation(self.remediation());
                    findings.push(finding);
                }

                // Error message-based detection (single probe)
                let (_, body, status) = self.measure_timing(&client, &url, b"\x00\x01\xFF", header).await?;
                if let Some(pattern) = self.detect_error_patterns(&body, status) {
                    executed = true;

                    let mut finding = Finding::new(
                        self.metadata.id.as_str(),
                        Severity::High,
                        "RSA Bleichenbacher Oracle Detected (Error-Based)",
                        format!("RSA padding oracle detected via error message analysis at {}", url),
                        &url,
                    )
                    .with_payload(format!("Invalid PKCS#1 padding via {}", header))
                    .with_confidence(75)
                    .with_agent_id(ctx.agent_id)
                    .with_tags(vec!["bleichenbacher", "error-based", "rsa"]);

                    let evidence = self.build_evidence(&url, 0, Some(pattern));
                    for ev in evidence {
                        finding = finding.with_evidence(ev);
                    }

                    finding = finding.with_remediation(self.remediation());
                    findings.push(finding);
                }
            }
        }

        // Cache successful timing baselines for learning engine
        if !findings.is_empty() {
            if let Ok(cache) = LearningCache::global().await {
                cache.cache_timing_baseline(ctx.target_url.clone(), "bleichenbacher".to_string()).await;
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
    fn test_timing_buffer() {
        let mut buffer = TimingBuffer::new();
        assert_eq!(buffer.count, 0);
        
        buffer.push(100_000_000);
        buffer.push(150_000_000);
        buffer.push(200_000_000);
        
        assert_eq!(buffer.count, 3);
        assert_eq!(buffer.mean(), 150_000_000);
    }

    #[test]
    fn test_bounded_array_no_heap() {
        let buffer = TimingBuffer::new();
        assert!(std::mem::size_of::<TimingBuffer>() <= 256);
    }
}
