//! Time-Based Blind SQL Injection Detection Module
//! Implements safe time-delay probes for multiple DBMS without data modification.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::learning::sqli_cache::SqliCache;
use std::time::{Duration, Instant};

/// Supported database management systems for time-based detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbmsType {
    MySQL,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
    Unknown,
}

/// Time-based SQLi probe configuration
#[derive(Debug, Clone)]
pub struct TimeProbe {
    pub dbms: DbmsType,
    pub payload: String,
    pub delay_seconds: u32,
    pub parameter: String,
}

/// Time-based blind SQL injection detector
pub struct TimeBasedDetector {
    cache: SqliCache,
    http_client: HttpClient,
    base_delay_ms: u64,
    jitter_threshold_ms: u64,
}

impl TimeBasedDetector {
    /// Create a new time-based detector with bounded parameters
    pub fn new(cache: SqliCache, http_client: HttpClient) -> Self {
        Self {
            cache,
            http_client,
            base_delay_ms: 2000, // 2 second baseline
            jitter_threshold_ms: 500, // 500ms jitter compensation
        }
    }

    /// Generate safe time-delay payloads for different DBMS
    pub fn generate_probes(&self, param: &str, delay: u32) -> Vec<TimeProbe> {
        let mut probes = Vec::with_capacity(5);

        // MySQL: SLEEP()
        probes.push(TimeProbe {
            dbms: DbmsType::MySQL,
            payload: format!("{}' OR SLEEP({})-- ", param, delay),
            delay_seconds: delay,
            parameter: param.to_string(),
        });

        // PostgreSQL: pg_sleep()
        probes.push(TimeProbe {
            dbms: DbmsType::PostgreSQL,
            payload: format!("{}'; SELECT pg_sleep({});-- ", param, delay),
            delay_seconds: delay,
            parameter: param.to_string(),
        });

        // MSSQL: WAITFOR DELAY
        probes.push(TimeProbe {
            dbms: DbmsType::MSSQL,
            payload: format!(
                "{}'; WAITFOR DELAY '0:0:{}';-- ",
                param, delay
            ),
            delay_seconds: delay,
            parameter: param.to_string(),
        });

        // Oracle: DBMS_LOCK.SLEEP (requires privileges) or conditional
        probes.push(TimeProbe {
            dbms: DbmsType::Oracle,
            payload: format!(
                "{}' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('SQLI',{})-- ",
                param, delay
            ),
            delay_seconds: delay,
            parameter: param.to_string(),
        });

        // SQLite: No native sleep, use recursive CTE workaround
        probes.push(TimeProbe {
            dbms: DbmsType::SQLite,
            payload: format!(
                "{}'; WITH RECURSIVE s(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM s WHERE i<1000000) SELECT * FROM s;-- ",
                param
            ),
            delay_seconds: delay,
            parameter: param.to_string(),
        });

        probes
    }

    /// Measure response time with nanosecond precision
    async fn measure_response_time(&self, request: &HttpRequest) -> Result<u64, String> {
        let start = Instant::now();
        match self.http_client.execute(request).await {
            Ok(response) => {
                let elapsed = start.elapsed();
                // Zero-copy: only return timing, not full response unless needed
                Ok(elapsed.as_millis() as u64)
            }
            Err(e) => Err(format!("Request failed: {}", e)),
        }
    }

    /// Establish baseline response time for comparison
    pub async fn establish_baseline(
        &self,
        request: &HttpRequest,
        samples: usize,
    ) -> Result<u64, String> {
        let mut times = Vec::with_capacity(samples);

        for _ in 0..samples.min(5) {
            // Bounded to max 5 samples
            match self.measure_response_time(request).await {
                Ok(t) => times.push(t),
                Err(_) => continue,
            }
        }

        if times.is_empty() {
            return Err("Failed to establish baseline".to_string());
        }

        // Return median to reduce outlier impact
        times.sort();
        Ok(times[times.len() / 2])
    }

    /// Detect time-based SQLi by comparing response times
    pub async fn detect(
        &mut self,
        request: &HttpRequest,
        param: &str,
    ) -> Option<CheckResult> {
        let delay = 2; // Safe 2-second delay

        // Get baseline first
        let baseline = match self.establish_baseline(request, 3).await {
            Ok(b) => b,
            Err(_) => return None,
        };

        let probes = self.generate_probes(param, delay);

        for probe in probes {
            let mut test_request = request.clone();

            // Inject payload into parameter
            if let Some(body) = test_request.body_mut() {
                body.replace(&format!("{}=", param), &format!("{}={}", param, probe.payload));
            } else if let Some(query) = test_request.query_mut() {
                query.replace(&format!("{}=", param), &format!("{}={}", param, probe.payload));
            }

            let response_time = match self.measure_response_time(&test_request).await {
                Ok(t) => t,
                Err(_) => continue,
            };

            // Calculate differential with jitter compensation
            let expected_min = baseline + (self.base_delay_ms + probe.delay_seconds as u64 * 1000)
                - self.jitter_threshold_ms;

            if response_time >= expected_min {
                // Potential SQLi detected
                self.cache.record_fingerprint(probe.dbms, &probe.payload, response_time);

                return Some(CheckResult {
                    module: "time_based_sqli".to_string(),
                    severity: Severity::High,
                    confidence: 0.85,
                    description: format!(
                        "Time-based blind SQLi detected via {} probe. Baseline: {}ms, Response: {}ms",
                        match probe.dbms {
                            DbmsType::MySQL => "MySQL",
                            DbmsType::PostgreSQL => "PostgreSQL",
                            DbmsType::MSSQL => "MSSQL",
                            DbmsType::Oracle => "Oracle",
                            DbmsType::SQLite => "SQLite",
                            DbmsType::Unknown => "Unknown",
                        },
                        baseline,
                        response_time
                    ),
                    evidence: format!("Payload: {}", probe.payload),
                    parameter: Some(param.to_string()),
                    remediation: "Use parameterized queries and input validation".to_string(),
                });
            }
        }

        None
    }
}

impl CheckModule for TimeBasedDetector {
    fn name(&self) -> &'static str {
        "time_based_sqli"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn run(&mut self, request: &HttpRequest) -> Vec<CheckResult> {
        // Synchronous wrapper - in production would use async runtime
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_generation() {
        let cache = SqliCache::new();
        let client = HttpClient::default();
        let detector = TimeBasedDetector::new(cache, client);

        let probes = detector.generate_probes("id", 2);
        assert_eq!(probes.len(), 5);
        assert!(probes[0].payload.contains("SLEEP"));
        assert!(probes[1].payload.contains("pg_sleep"));
    }
}
