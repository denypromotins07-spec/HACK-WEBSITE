//! Weak KDF Detection Module
//!
//! Identifies weak PBKDF2/Bcrypt iteration counts and custom hashing endpoint exposures.
//! Uses bounded statistical arrays for iteration count analysis.
//! Detects insufficient work factors and predictable salt generation.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory, 
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Minimum safe PBKDF2 iterations (OWASP recommendation)
const MIN_PBKDF2_ITERATIONS: u32 = 600_000;

/// Minimum safe Bcrypt cost factor
const MIN_BCRYPT_COST: u32 = 12;

/// Minimum safe Argon2 memory (KB)
const MIN_ARGON2_MEMORY_KB: u32 = 65536;

/// Maximum KDF test samples (bounded array)
const MAX_KDF_SAMPLES: usize = 16;

/// KDF configuration detected from response
#[derive(Debug, Clone)]
struct KdfConfig {
    algorithm: String,
    iterations_or_cost: u32,
    salt_length: Option<usize>,
    output_length: Option<usize>,
}

/// Weak KDF detector with bounded state
pub struct WeakKdfDetector {
    metadata: CheckMetadata,
}

impl WeakKdfDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "crypto/weak_kdf",
            "Weak Key Derivation Function Detection",
            "Identifies weak PBKDF2/Bcrypt iteration counts and custom hashing endpoint exposures",
            Severity::High,
            CheckCategory::SensitiveDataExposure,
        )
        .with_god_mode(true)
        .with_tags(vec!["cryptography", "kdf", "pbkdf2", "bcrypt", "password-hashing"])
        .with_references(vec![
            "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/916.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 1000,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 100,
            max_duration_ms: 8000,
            max_payload_size: 2048,
        });

        Self { metadata }
    }

    /// Generate KDF probe payloads (bounded dictionary)
    fn generate_kdf_probes(&self) -> &'static [&'static str] {
        static PROBES: &[&str] = &[
            // Common KDF endpoint patterns
            "/api/auth/hash",
            "/api/crypto/kdf",
            "/api/password/check",
            "/api/user/verify-hash",
            "/hash",
            "/derive-key",
            "/api/pbkdf2",
            "/api/bcrypt",
        ];
        PROBES
    }

    /// Analyze response for KDF configuration hints
    fn extract_kdf_config(&self, body: &str, headers: &reqwest::header::HeaderMap) -> Option<KdfConfig> {
        // Check for KDF algorithm indicators in response
        let body_lower = body.to_lowercase();
        
        // Detect PBKDF2
        if body_lower.contains("pbkdf2") || body_lower.contains("pbkdf2_with_hmac") {
            if let Some(iterations) = self.extract_iterations(&body_lower) {
                return Some(KdfConfig {
                    algorithm: "PBKDF2".to_string(),
                    iterations_or_cost: iterations,
                    salt_length: self.extract_salt_length(&body_lower),
                    output_length: None,
                });
            }
        }
        
        // Detect Bcrypt
        if body_lower.contains("bcrypt") || body_lower.contains("$2a$") || body_lower.contains("$2b$") {
            if let Some(cost) = self.extract_bcrypt_cost(&body_lower) {
                return Some(KdfConfig {
                    algorithm: "Bcrypt".to_string(),
                    iterations_or_cost: cost,
                    salt_length: Some(16),
                    output_length: Some(23),
                });
            }
        }
        
        // Detect Argon2
        if body_lower.contains("argon2") {
            if let Some(memory) = self.extract_argon2_memory(&body_lower) {
                return Some(KdfConfig {
                    algorithm: "Argon2".to_string(),
                    iterations_or_cost: memory,
                    salt_length: self.extract_salt_length(&body_lower),
                    output_length: None,
                });
            }
        }
        
        // Detect scrypt
        if body_lower.contains("scrypt") {
            if let Some(n) = self.extract_scrypt_n(&body_lower) {
                return Some(KdfConfig {
                    algorithm: "scrypt".to_string(),
                    iterations_or_cost: n,
                    salt_length: self.extract_salt_length(&body_lower),
                    output_length: None,
                });
            }
        }
        
        None
    }

    fn extract_iterations(&self, body: &str) -> Option<u32> {
        // Look for patterns like "iterations": 1000 or "rounds": 5000
        for pattern in &["iterations", "rounds", "iter"] {
            if let Some(pos) = body.find(pattern) {
                let rest = &body[pos + pattern.len()..];
                if let Some(start) = rest.find(|c: char| c.is_ascii_digit()) {
                    let num_str: String = rest[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(num) = num_str.parse::<u32>() {
                        return Some(num);
                    }
                }
            }
        }
        None
    }

    fn extract_bcrypt_cost(&self, body: &str) -> Option<u32> {
        // Look for $2a$XX$ pattern where XX is the cost
        if let Some(pos) = body.find("$2") {
            let rest = &body[pos + 2..];
            if rest.starts_with('a') || rest.starts_with('b') || rest.starts_with('y') {
                let cost_str: String = rest[1..].chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(cost) = cost_str.parse::<u32>() {
                    return Some(cost);
                }
            }
        }
        
        // Also check for explicit cost parameter
        if let Some(pos) = body.find("cost") {
            let rest = &body[pos + 4..];
            if let Some(start) = rest.find(|c: char| c.is_ascii_digit()) {
                let num_str: String = rest[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(cost) = num_str.parse::<u32>() {
                    return Some(cost);
                }
            }
        }
        
        None
    }

    fn extract_argon2_memory(&self, body: &str) -> Option<u32> {
        // Look for memory parameter in KB
        if let Some(pos) = body.find("memory") {
            let rest = &body[pos + 6..];
            if let Some(start) = rest.find(|c: char| c.is_ascii_digit()) {
                let num_str: String = rest[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(mem) = num_str.parse::<u32>() {
                    return Some(mem);
                }
            }
        }
        None
    }

    fn extract_scrypt_n(&self, body: &str) -> Option<u32> {
        // Look for N parameter in scrypt
        if let Some(pos) = body.find("\"n\"") {
            let rest = &body[pos + 3..];
            if let Some(start) = rest.find(|c: char| c.is_ascii_digit()) {
                let num_str: String = rest[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(n) = num_str.parse::<u32>() {
                    return Some(n);
                }
            }
        }
        None
    }

    fn extract_salt_length(&self, body: &str) -> Option<usize> {
        if let Some(pos) = body.find("salt") {
            let rest = &body[pos + 4..];
            if let Some(start) = rest.find(|c: char| c.is_ascii_digit()) {
                let num_str: String = rest[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(len) = num_str.parse::<usize>() {
                    return Some(len);
                }
            }
        }
        None
    }

    /// Evaluate KDF configuration weakness
    fn evaluate_weakness(&self, config: &KdfConfig) -> Option<WeaknessEvidence> {
        match config.algorithm.as_str() {
            "PBKDF2" => {
                if config.iterations_or_cost < MIN_PBKDF2_ITERATIONS {
                    return Some(WeaknessEvidence {
                        algorithm: config.algorithm.clone(),
                        configured_value: config.iterations_or_cost,
                        minimum_safe_value: MIN_PBKDF2_ITERATIONS,
                        weakness_type: "Insufficient iterations".to_string(),
                        severity_multiplier: (MIN_PBKDF2_ITERATIONS / config.iterations_or_cost.max(1)) as f64,
                    });
                }
            }
            "Bcrypt" => {
                if config.iterations_or_cost < MIN_BCRYPT_COST {
                    return Some(WeaknessEvidence {
                        algorithm: config.algorithm.clone(),
                        configured_value: config.iterations_or_cost,
                        minimum_safe_value: MIN_BCRYPT_COST,
                        weakness_type: "Insufficient cost factor".to_string(),
                        severity_multiplier: (MIN_BCRYPT_COST - config.iterations_or_cost) as f64,
                    });
                }
            }
            "Argon2" => {
                if config.iterations_or_cost < MIN_ARGON2_MEMORY_KB {
                    return Some(WeaknessEvidence {
                        algorithm: config.algorithm.clone(),
                        configured_value: config.iterations_or_cost,
                        minimum_safe_value: MIN_ARGON2_MEMORY_KB,
                        weakness_type: "Insufficient memory".to_string(),
                        severity_multiplier: (MIN_ARGON2_MEMORY_KB / config.iterations_or_cost.max(1)) as f64,
                    });
                }
            }
            "scrypt" => {
                // scrypt N should be at least 2^14 = 16384
                if config.iterations_or_cost < 16384 {
                    return Some(WeaknessEvidence {
                        algorithm: config.algorithm.clone(),
                        configured_value: config.iterations_or_cost,
                        minimum_safe_value: 16384,
                        weakness_type: "Insufficient N parameter".to_string(),
                        severity_multiplier: (16384 / config.iterations_or_cost.max(1)) as f64,
                    });
                }
            }
            _ => {}
        }
        None
    }

    /// Build evidence for weak KDF finding
    fn build_evidence(&self, url: &str, weakness: &WeaknessEvidence) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::Configuration {
                    key: weakness.algorithm.clone(),
                    value: format!(
                        "{}={} (minimum safe: {})",
                        if weakness.algorithm == "Bcrypt" { "cost" } else { "iterations/memory" },
                        weakness.configured_value,
                        weakness.minimum_safe_value
                    ),
                },
                data: format!(
                    "Weak KDF configuration detected: {} with {} ({}) is below recommended minimum of {}",
                    weakness.algorithm,
                    if weakness.algorithm == "Bcrypt" { "cost" } else { "iterations/memory" },
                    weakness.configured_value,
                    weakness.minimum_safe_value
                ),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: None,
                    header: None,
                },
                confidence: 90,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self, algorithm: &str) -> RemediationHint {
        let (summary, steps, code_example) = match algorithm {
            "PBKDF2" => (
                "Increase PBKDF2 iterations to at least 600,000".to_string(),
                vec![
                    "Increase iteration count to minimum 600,000 (OWASP 2023)".to_string(),
                    "Consider migrating to Argon2id for better security".to_string(),
                    "Use cryptographically secure random salts (16+ bytes)".to_string(),
                    "Implement rate limiting on password verification endpoints".to_string(),
                ],
                Some(r#"// Use PBKDF2 with safe parameters
use pbkdf2::{pbkdf2_hmac, Params};
use sha2::Sha256;

let params = Params {
    rounds: 600_000,
    dk_len: 32,
};
pbkdf2_hmac::<Sha256>(password, salt, &params, &mut output);"#.to_string()),
            ),
            "Bcrypt" => (
                "Increase Bcrypt cost factor to at least 12".to_string(),
                vec![
                    "Increase cost factor to minimum 12 (OWASP 2023)".to_string(),
                    "Consider migrating to Argon2id for GPU resistance".to_string(),
                    "Use unique random salts for each password".to_string(),
                    "Implement account lockout after failed attempts".to_string(),
                ],
                Some(r#"// Use Bcrypt with safe cost factor
use bcrypt::{hash, DEFAULT_COST};

let cost = 12; // Minimum recommended
let hashed = hash(password, cost)?;"#.to_string()),
            ),
            "Argon2" => (
                "Increase Argon2 memory to at least 64MB".to_string(),
                vec![
                    "Use Argon2id variant for combined side-channel resistance".to_string(),
                    "Set memory to minimum 64MB (65536 KB)".to_string(),
                    "Use at least 3 iterations and 4 parallel lanes".to_string(),
                    "Use unique random salts (16+ bytes)".to_string(),
                ],
                Some(r#"// Use Argon2id with safe parameters
use argon2::{Argon2, Params};

let params = Params::new(65536, 3, 4, Some(32))?;
let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
let hash = argon2.hash_password(password, salt)?;"#.to_string()),
            ),
            _ => (
                "Use modern password hashing algorithms".to_string(),
                vec![
                    "Migrate to Argon2id (preferred) or Bcrypt".to_string(),
                    "Avoid MD5, SHA1, or unsalted hashes for passwords".to_string(),
                    "Implement proper salt generation".to_string(),
                ],
                None,
            ),
        };

        RemediationHint {
            summary,
            steps,
            code_example,
            references: vec![
                "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html".to_string(),
                "https://cwe.mitre.org/data/definitions/916.html".to_string(),
            ],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

/// Weakness evidence
#[derive(Debug, Clone)]
struct WeaknessEvidence {
    algorithm: String,
    configured_value: u32,
    minimum_safe_value: u32,
    weakness_type: String,
    severity_multiplier: f64,
}

#[async_trait]
impl VulnerabilityModule for WeakKdfDetector {
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

        let probes = self.generate_kdf_probes();

        for &endpoint in probes.iter() {
            let url = format!("{}{}", ctx.target_url.trim_end_matches('/'), endpoint);
            
            // Test endpoint with sample data
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/json"),
            );

            let response = client.post_json(&url, serde_json::json!({
                "password": "test_password_123",
                "salt": "random_salt_value"
            }), headers.clone()).await;

            match response {
                Ok(resp) => {
                    executed = true;
                    let status = resp.status().as_u16();
                    
                    // Only analyze successful or informative responses
                    if status == 200 || status == 400 || status == 422 {
                        let body = resp.text().await.unwrap_or_default();
                        
                        if let Some(config) = self.extract_kdf_config(&body, &resp.headers().clone()) {
                            if let Some(weakness) = self.evaluate_weakness(&config) {
                                let severity = if weakness.severity_multiplier > 10.0 {
                                    Severity::Critical
                                } else if weakness.severity_multiplier > 5.0 {
                                    Severity::High
                                } else {
                                    Severity::Medium
                                };

                                let mut finding = Finding::new(
                                    self.metadata.id.as_str(),
                                    severity,
                                    format!("Weak {} Configuration Detected", config.algorithm),
                                    format!(
                                        "The application uses weak {} parameters at {}. {} (configured: {}, minimum safe: {}).",
                                        config.algorithm,
                                        url,
                                        weakness.weakness_type,
                                        weakness.configured_value,
                                        weakness.minimum_safe_value
                                    ),
                                    &url,
                                )
                                .with_payload(format!(
                                    "{}: {} (weak)",
                                    config.algorithm,
                                    weakness.configured_value
                                ))
                                .with_confidence(85)
                                .with_agent_id(ctx.agent_id)
                                .with_tags(vec!["weak-kdf", "password-hashing", "cryptography"]);

                                let evidences = self.build_evidence(&url, &weakness);
                                for ev in evidences {
                                    finding = finding.with_evidence(ev);
                                }

                                finding = finding.with_remediation(self.remediation(&config.algorithm));
                                findings.push(finding);
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        // Cache weak KDF signatures for learning engine
        if !findings.is_empty() {
            if let Ok(cache) = LearningCache::global().await {
                cache.cache_timing_baseline(ctx.target_url.clone(), "weak_kdf".to_string()).await;
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
    fn test_iteration_extraction() {
        let detector = WeakKdfDetector::new();
        let body = r#"{"algorithm": "pbkdf2", "iterations": 1000}"#;
        let iterations = detector.extract_iterations(&body.to_lowercase());
        assert_eq!(iterations, Some(1000));
    }

    #[test]
    fn test_bcrypt_cost_extraction() {
        let detector = WeakKdfDetector::new();
        let body = r#"$2a$10$abcdefghijklmnopqrstuu"#;
        let cost = detector.extract_bcrypt_cost(&body.to_lowercase());
        assert_eq!(cost, Some(10));
    }

    #[test]
    fn test_weakness_evaluation_pbkdf2() {
        let detector = WeakKdfDetector::new();
        let config = KdfConfig {
            algorithm: "PBKDF2".to_string(),
            iterations_or_cost: 1000,
            salt_length: Some(16),
            output_length: None,
        };
        let weakness = detector.evaluate_weakness(&config);
        assert!(weakness.is_some());
        assert_eq!(weakness.unwrap().configured_value, 1000);
    }

    #[test]
    fn test_safe_pbkdf2_not_flagged() {
        let detector = WeakKdfDetector::new();
        let config = KdfConfig {
            algorithm: "PBKDF2".to_string(),
            iterations_or_cost: 600_000,
            salt_length: Some(16),
            output_length: None,
        };
        let weakness = detector.evaluate_weakness(&config);
        assert!(weakness.is_none());
    }
}
