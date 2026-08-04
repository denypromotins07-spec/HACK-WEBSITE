//! SQL Injection Detection Modules
//! Register SQLi modules, export metadata, and bind to orchestrator.

pub mod time_based;
pub mod time_analysis;
pub mod time_payloads;

pub mod boolean_based;
pub mod boolean_oracle;
pub mod boolean_payloads;

pub mod error_based;
pub mod error_signatures;
pub mod error_extraction;

pub mod oob_sqli;
pub mod dns_exfil;
pub mod http_exfil;

pub mod second_order;

// Re-export main detector types for convenience
pub use time_based::{DbmsType, TimeBasedDetector, TimeProbe};
pub use time_analysis::{TimeAnalyzer, TimingStats, DifferentialResult, PrecisionTimer};
pub use time_payloads::{TimePayloadGenerator, EncodedPayload, PayloadCategory};

pub use boolean_based::{BooleanDetector, BooleanComparison, StrippedContent};
pub use boolean_oracle::{BooleanOracle, InferenceResult, BinaryResponse, ResponseShiftDetector};
pub use boolean_payloads::{BooleanPayloadGenerator, BooleanPayload, EncodingType, CommentStyle};

pub use error_based::{ErrorDetector, ErrorMatch};
pub use error_signatures::{ErrorSignatureDatabase, ErrorSignature};
pub use error_extraction::{MetadataExtractor, DbmsMetadata, MetadataAggregator};

pub use oob_sqli::{OobDetector, CorrelationToken, OobChannel};
pub use dns_exfil::{DnsExfiltrationProbe, DnsQuery, DnsQueryType, DnsPayloadEncoder};
pub use http_exfil::{HttpExfiltrationProbe, HttpCallback, HttpCallbackHandler};

pub use second_order::{SecondOrderDetector, StoredPayload, CrossEndpointTracker, Correlation};

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::http::request::HttpRequest;

/// SQLi detection orchestrator that coordinates all detection modules
pub struct SqliOrchestrator {
    time_detector: Option<TimeBasedDetector>,
    boolean_detector: Option<BooleanDetector>,
    error_detector: Option<ErrorDetector>,
    oob_detector: Option<OobDetector>,
    second_order_detector: Option<SecondOrderDetector>,
    enabled_checks: Vec<SqliCheckType>,
}

/// Types of SQLi checks available
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliCheckType {
    TimeBased,
    BooleanBased,
    ErrorBased,
    OutOfBand,
    SecondOrder,
}

impl SqliOrchestrator {
    /// Create a new SQLi orchestrator with all detectors
    pub fn new(
        cache: crate::learning::sqli_cache::SqliCache,
        http_client: crate::http::client::HttpClient,
    ) -> Self {
        Self {
            time_detector: Some(TimeBasedDetector::new(cache.clone(), http_client.clone())),
            boolean_detector: Some(BooleanDetector::new(cache.clone(), http_client.clone())),
            error_detector: Some(ErrorDetector::new(cache.clone(), http_client.clone())),
            oob_detector: Some(OobDetector::new(cache.clone(), http_client.clone())),
            second_order_detector: None, // Requires special setup
            enabled_checks: vec![
                SqliCheckType::TimeBased,
                SqliCheckType::BooleanBased,
                SqliCheckType::ErrorBased,
                SqliCheckType::OutOfBand,
            ],
        }
    }

    /// Enable specific check types
    pub fn enable_checks(&mut self, checks: Vec<SqliCheckType>) {
        self.enabled_checks = checks;
    }

    /// Add a check type to enabled list
    pub fn add_check(&mut self, check: SqliCheckType) {
        if !self.enabled_checks.contains(&check) {
            self.enabled_checks.push(check);
        }
    }

    /// Remove a check type from enabled list
    pub fn remove_check(&mut self, check: SqliCheckType) {
        self.enabled_checks.retain(|c| c != &check);
    }

    /// Run all enabled SQLi checks on a request
    pub async fn run_checks(&mut self, request: &HttpRequest) -> Vec<CheckResult> {
        let mut results = Vec::new();

        for check in &self.enabled_checks {
            match check {
                SqliCheckType::TimeBased => {
                    if let Some(ref mut detector) = self.time_detector {
                        if let Some(result) = detector.detect(request, "id").await {
                            results.push(result);
                        }
                    }
                }
                SqliCheckType::BooleanBased => {
                    if let Some(ref mut detector) = self.boolean_detector {
                        if let Some(result) = detector.detect(request, "id").await {
                            results.push(result);
                        }
                    }
                }
                SqliCheckType::ErrorBased => {
                    if let Some(ref mut detector) = self.error_detector {
                        if let Some(result) = detector.detect(request).await {
                            results.push(result);
                        }
                    }
                }
                SqliCheckType::OutOfBand => {
                    if let Some(ref mut detector) = self.oob_detector {
                        if let Some(result) = detector.detect(request).await {
                            results.push(result);
                        }
                    }
                }
                SqliCheckType::SecondOrder => {
                    // Second-order requires special multi-request handling
                    // Not run automatically
                }
            }
        }

        results
    }

    /// Get metadata about all SQLi modules
    pub fn get_metadata() -> SqliMetadata {
        SqliMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
            modules: vec![
                ModuleInfo {
                    name: "time_based",
                    description: "Time-based blind SQL injection detection",
                    severity: Severity::High,
                },
                ModuleInfo {
                    name: "boolean_based",
                    description: "Boolean-based blind SQL injection detection",
                    severity: Severity::High,
                },
                ModuleInfo {
                    name: "error_based",
                    description: "Error-based SQL injection detection",
                    severity: Severity::High,
                },
                ModuleInfo {
                    name: "oob",
                    description: "Out-of-band SQL injection detection",
                    severity: Severity::Critical,
                },
                ModuleInfo {
                    name: "second_order",
                    description: "Second-order SQL injection detection",
                    severity: Severity::Critical,
                },
            ],
            supported_dbms: vec![
                "MySQL".to_string(),
                "PostgreSQL".to_string(),
                "MSSQL".to_string(),
                "Oracle".to_string(),
                "SQLite".to_string(),
                "MariaDB".to_string(),
            ],
        }
    }

    /// Get enabled check types
    pub fn get_enabled_checks(&self) -> &[SqliCheckType] {
        &self.enabled_checks
    }
}

/// Metadata about SQLi detection modules
#[derive(Debug, Clone)]
pub struct SqliMetadata {
    pub version: String,
    pub modules: Vec<ModuleInfo>,
    pub supported_dbms: Vec<String>,
}

/// Information about a single module
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
}

/// Builder for creating configured SQLi orchestrators
pub struct SqliOrchestratorBuilder {
    cache: Option<crate::learning::sqli_cache::SqliCache>,
    http_client: Option<crate::http::client::HttpClient>,
    enabled_checks: Vec<SqliCheckType>,
    custom_timeout_secs: Option<u64>,
}

impl SqliOrchestratorBuilder {
    pub fn new() -> Self {
        Self {
            cache: None,
            http_client: None,
            enabled_checks: Vec::new(),
            custom_timeout_secs: None,
        }
    }

    pub fn with_cache(mut self, cache: crate::learning::sqli_cache::SqliCache) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn with_http_client(mut self, client: crate::http::client::HttpClient) -> Self {
        self.http_client = Some(client);
        self
    }

    pub fn with_checks(mut self, checks: Vec<SqliCheckType>) -> Self {
        self.enabled_checks = checks;
        self
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.custom_timeout_secs = Some(timeout_secs);
        self
    }

    pub fn build(self) -> SqliOrchestrator {
        let cache = self.cache.unwrap_or_else(crate::learning::sqli_cache::SqliCache::new);
        let http_client = self.http_client.unwrap_or_else(crate::http::client::HttpClient::default);

        let mut orchestrator = SqliOrchestrator::new(cache, http_client);

        if !self.enabled_checks.is_empty() {
            orchestrator.enable_checks(self.enabled_checks);
        }

        orchestrator
    }
}

impl Default for SqliOrchestratorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata() {
        let metadata = SqliOrchestrator::get_metadata();
        assert!(!metadata.version.is_empty());
        assert_eq!(metadata.modules.len(), 5);
        assert!(metadata.supported_dbms.contains(&"MySQL".to_string()));
    }

    #[test]
    fn test_builder() {
        let orchestrator = SqliOrchestratorBuilder::new()
            .with_checks(vec![SqliCheckType::TimeBased, SqliCheckType::ErrorBased])
            .build();

        let enabled = orchestrator.get_enabled_checks();
        assert_eq!(enabled.len(), 2);
        assert!(enabled.contains(&SqliCheckType::TimeBased));
    }

    #[test]
    fn test_check_type_enum() {
        let all_checks = vec![
            SqliCheckType::TimeBased,
            SqliCheckType::BooleanBased,
            SqliCheckType::ErrorBased,
            SqliCheckType::OutOfBand,
            SqliCheckType::SecondOrder,
        ];

        assert_eq!(all_checks.len(), 5);
    }
}
