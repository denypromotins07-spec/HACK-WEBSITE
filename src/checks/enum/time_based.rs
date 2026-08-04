//! Time-Based User Enumeration Detection Module
//!
//! Detects user enumeration via nanosecond-level timing differentials on login
//! and password reset portals. Implements strict nanosecond-precision timing arrays.

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

/// Maximum timing samples (bounded array)
const MAX_TIMING_SAMPLES: usize = 32;

/// Nanosecond timing threshold for enumeration detection
const ENUM_THRESHOLD_NS: u128 = 10_000_000; // 10ms

/// Bounded timing sample buffer
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

    fn stddev(&self) -> u128 {
        if self.count < 2 {
            return 0;
        }
        let mean = self.mean();
        let variance: u128 = self.samples[..self.count]
            .iter()
            .map(|&x| {
                let diff = x as i128 - mean as i128;
                (diff * diff) as u128
            })
            .sum::<u128>() / (self.count - 1) as u128;
        
        // Integer square root approximation
        let mut sqrt = variance / 2;
        if sqrt > 0 {
            sqrt = (sqrt + variance / sqrt) / 2;
        }
        sqrt
    }
}

/// Known username lists for testing (bounded)
const KNOWN_USERNAMES: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "user",
    "test",
    "guest",
    "info",
    "support",
];

const UNKNOWN_USERNAMES: &[&str] = &[
    "nonexistent_user_xyz123",
    "fake_account_abc789",
    "random_user_qwe456",
];

/// Time-based enumeration detector
pub struct TimeBasedEnumDetector {
    metadata: CheckMetadata,
    valid_user_buffer: TimingBuffer,
    invalid_user_buffer: TimingBuffer,
}

impl TimeBasedEnumDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "enum/time_based",
            "Time-Based User Enumeration Detection",
            "Detects user enumeration via nanosecond-level timing differentials on login and password reset portals",
            Severity::Medium,
            CheckCategory::BrokenAuthentication,
        )
        .with_god_mode(true)
        .with_tags(vec!["user-enumeration", "timing-attack", "authentication"])
        .with_references(vec![
            "https://owasp.org/www-community/attacks/User_enumeration",
            "https://cwe.mitre.org/data/definitions/204.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 2000,
            max_memory_bytes: 4 * 1024 * 1024,
            max_requests: 200,
            max_duration_ms: 10000,
            max_payload_size: 1024,
        });

        Self {
            metadata,
            valid_user_buffer: TimingBuffer::new(),
            invalid_user_buffer: TimingBuffer::new(),
        }
    }

    /// Measure request timing with nanosecond precision
    async fn measure_timing(
        &self,
        client: &HttpClient,
        url: &str,
        username: &str,
        password: &str,
    ) -> Result<(u128, u16), ModuleError> {
        let start = Instant::now();
        
        let form_data = [("username", username), ("password", password)];
        let response = client.post_form(url, &form_data).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
        
        let elapsed = start.elapsed().as_nanos();
        let status = response.status().as_u16();

        Ok((elapsed, status))
    }

    /// Test password reset endpoint timing
    async fn measure_reset_timing(
        &self,
        client: &HttpClient,
        url: &str,
        email: &str,
    ) -> Result<(u128, u16), ModuleError> {
        let start = Instant::now();
        
        let form_data = [("email", email)];
        let response = client.post_form(url, &form_data).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
        
        let elapsed = start.elapsed().as_nanos();
        let status = response.status().as_u16();

        Ok((elapsed, status))
    }

    /// Detect timing-based enumeration on login endpoint
    async fn detect_login_enumeration(
        &self,
        client: &HttpClient,
        url: &str,
    ) -> Result<Option<(u128, u128)>, ModuleError> {
        let mut valid_times = TimingBuffer::new();
        let mut invalid_times = TimingBuffer::new();

        // Collect timing samples for known users
        for username in KNOWN_USERNAMES.iter().take(MAX_TIMING_SAMPLES / 2) {
            let (timing, _) = self.measure_timing(client, url, username, "wrong_password").await?;
            valid_times.push(timing);
        }

        // Collect timing samples for unknown users
        for username in UNKNOWN_USERNAMES.iter().take(MAX_TIMING_SAMPLES / 2) {
            let (timing, _) = self.measure_timing(client, url, username, "any_password").await?;
            invalid_times.push(timing);
        }

        let valid_mean = valid_times.mean();
        let invalid_mean = invalid_times.mean();

        if valid_mean > 0 && invalid_mean > 0 {
            let diff = (valid_mean as i128 - invalid_mean as i128).unsigned_abs();
            if diff > ENUM_THRESHOLD_NS {
                return Ok(Some((diff, valid_mean.max(invalid_mean))));
            }
        }

        Ok(None)
    }

    /// Detect timing-based enumeration on password reset
    async fn detect_reset_enumeration(
        &self,
        client: &HttpClient,
        url: &str,
    ) -> Result<Option<(u128, u128)>, ModuleError> {
        let mut valid_times = TimingBuffer::new();
        let mut invalid_times = TimingBuffer::new();

        // Test with common emails
        let valid_emails = ["admin@example.com", "test@example.com", "user@example.com"];
        let invalid_emails = ["nonexistent_xyz@example.com", "fake_abc@example.com"];

        for email in &valid_emails {
            let (timing, _) = self.measure_reset_timing(client, url, email).await?;
            valid_times.push(timing);
        }

        for email in &invalid_emails {
            let (timing, _) = self.measure_reset_timing(client, url, email).await?;
            invalid_times.push(timing);
        }

        let valid_mean = valid_times.mean();
        let invalid_mean = invalid_times.mean();

        if valid_mean > 0 && invalid_mean > 0 {
            let diff = (valid_mean as i128 - invalid_mean as i128).unsigned_abs();
            if diff > ENUM_THRESHOLD_NS {
                return Ok(Some((diff, valid_mean.max(invalid_mean))));
            }
        }

        Ok(None)
    }

    /// Build evidence for enumeration finding
    fn build_evidence(&self, url: &str, timing_diff: u128, avg_time: u128) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::Timing {
                    baseline_ms: 0,
                    observed_ms: avg_time / 1_000_000,
                    difference_ms: timing_diff / 1_000_000,
                },
                data: format!(
                    "Timing differential: {}ns (threshold: {}ns, avg: {}ms)",
                    timing_diff,
                    ENUM_THRESHOLD_NS,
                    avg_time / 1_000_000
                ),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: Some("username".to_string()),
                    header: None,
                },
                confidence: 80,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Implement constant-time authentication responses".to_string(),
            steps: vec![
                "Use constant-time comparison for username and password lookups".to_string(),
                "Add artificial delay to normalize response times".to_string(),
                "Return identical error messages for all auth failures".to_string(),
                "Implement rate limiting to slow down enumeration attempts".to_string(),
                "Use generic messages like 'Invalid credentials' for all failures".to_string(),
            ],
            code_example: Some(r#"// Constant-time authentication example
public bool Authenticate(string username, string password) {
    // Always query the database even for non-existent users
    var user = _userRepository.GetByUsername(username);
    
    // Use constant-time comparison
    bool validUser = user != null;
    bool validPassword = validUser && CryptographicOperations.FixedTimeEquals(
        HashPassword(password),
        user.PasswordHash
    );
    
    // Return same result structure regardless
    return validUser && validPassword;
}"#.to_string()),
            references: vec![
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html".to_string(),
                "https://cwe.mitre.org/data/definitions/204.html".to_string(),
            ],
            estimated_effort: EffortLevel::Medium,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for TimeBasedEnumDetector {
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

        let base_url = ctx.target_url.trim_end_matches('/');

        // Common login endpoints
        let login_endpoints = [
            "/login",
            "/auth/login",
            "/api/auth/login",
            "/api/login",
            "/signin",
            "/authenticate",
        ];

        // Common password reset endpoints
        let reset_endpoints = [
            "/password/reset",
            "/forgot-password",
            "/auth/password-reset",
            "/api/password/reset",
            "/reset",
        ];

        // Test login endpoints
        for endpoint in login_endpoints.iter() {
            let url = format!("{}{}", base_url, endpoint);
            
            if let Ok(Some((diff, avg))) = self.detect_login_enumeration(&client, &url).await {
                executed = true;

                let mut finding = Finding::new(
                    self.metadata.id.as_str(),
                    Severity::Medium,
                    "Time-Based User Enumeration (Login)",
                    format!("Login endpoint at {} reveals user existence via timing analysis ({}ns difference)", url, diff),
                    &url,
                )
                .with_payload("Timing analysis on username field".to_string())
                .with_confidence(80)
                .with_agent_id(ctx.agent_id)
                .with_tags(vec!["user-enumeration", "timing-attack"]);

                let evidence = self.build_evidence(&url, diff, avg);
                for ev in evidence {
                    finding = finding.with_evidence(ev);
                }

                finding = finding.with_remediation(self.remediation());
                findings.push(finding);

                // Cache timing baseline for learning engine
                if let Ok(cache) = LearningCache::global().await {
                    cache.cache_timing_baseline(ctx.target_url.clone(), "login_enum".to_string()).await;
                }
            }
        }

        // Test password reset endpoints
        for endpoint in reset_endpoints.iter() {
            let url = format!("{}{}", base_url, endpoint);
            
            if let Ok(Some((diff, avg))) = self.detect_reset_enumeration(&client, &url).await {
                executed = true;

                let mut finding = Finding::new(
                    self.metadata.id.as_str(),
                    Severity::Medium,
                    "Time-Based User Enumeration (Password Reset)",
                    format!("Password reset endpoint at {} reveals user existence via timing ({}ns difference)", url, diff),
                    &url,
                )
                .with_payload("Timing analysis on email field".to_string())
                .with_confidence(75)
                .with_agent_id(ctx.agent_id)
                .with_tags(vec!["user-enumeration", "timing-attack"]);

                let evidence = self.build_evidence(&url, diff, avg);
                for ev in evidence {
                    finding = finding.with_evidence(ev);
                }

                finding = finding.with_remediation(self.remediation());
                findings.push(finding);
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
        assert!(std::mem::size_of::<TimingBuffer>() <= 512);
    }
}
