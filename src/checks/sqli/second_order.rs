//! Second-Order SQL Injection Detection Module
//! Detect stored payloads executed later by tracking delayed effects across endpoints.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::learning::sqli_cache::SqliCache;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Maximum stored payloads to track (bounded memory)
const MAX_STORED_PAYLOADS: usize = 300;

/// Default delay between injection and detection attempts
const DETECTION_DELAY_SECS: u64 = 5;

/// Stored payload record
#[derive(Debug, Clone)]
pub struct StoredPayload {
    pub id: String,
    pub payload: String,
    pub injection_endpoint: String,
    pub injection_time: Instant,
    pub target_endpoints: Vec<String>,
    pub triggered: bool,
    pub trigger_endpoint: Option<String>,
    pub trigger_time: Option<Instant>,
}

/// Effect signature for detecting payload execution
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EffectSignature {
    pub pattern: String,
    pub location: EffectLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectLocation {
    ResponseBody,
    ResponseHeader,
    ErrorPage,
    LogFile,
    Notification,
}

/// Second-order SQLi detector
pub struct SecondOrderDetector {
    cache: SqliCache,
    http_client: HttpClient,
    stored_payloads: HashMap<String, StoredPayload>,
    effect_signatures: HashSet<EffectSignature>,
    baseline_hashes: HashMap<String, u64>,
    detection_delay: Duration,
}

impl SecondOrderDetector {
    /// Create a new second-order detector
    pub fn new(cache: SqliCache, http_client: HttpClient) -> Self {
        Self {
            cache,
            http_client,
            stored_payloads: HashMap::with_capacity(MAX_STORED_PAYLOADS),
            effect_signatures: HashSet::new(),
            baseline_hashes: HashMap::new(),
            detection_delay: Duration::from_secs(DETECTION_DELAY_SECS),
        }
    }

    /// Generate unique payload markers
    fn generate_marker() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let random_suffix = rand::random::<u32>();
        format!("SQLI_MARKER_{}_{}", timestamp, random_suffix)
    }

    /// Generate second-order SQLi payloads with unique markers
    fn generate_payloads(&self, param: &str) -> Vec<(String, String)> {
        let marker = Self::generate_marker();
        let mut payloads = Vec::new();

        // Payloads that store data for later retrieval
        payloads.push((
            marker.clone(),
            format!("{}'; INSERT INTO logs VALUES ('{}', 'test');-- ", param, marker),
        ));

        payloads.push((
            marker.clone(),
            format!(
                "{}'; UPDATE users SET comment='{}' WHERE id=1;-- ",
                param, marker
            ),
        ));

        payloads.push((
            marker.clone(),
            format!(
                "{}'; INSERT INTO feedback VALUES (NULL, '{}', NOW());-- ",
                param, marker
            ),
        ));

        // Payloads that modify session/application state
        payloads.push((
            marker.clone(),
            format!("{}'; UPDATE config SET value='{}' WHERE key='app_name';-- ", param, marker),
        ));

        // Payloads using UNION for data staging
        payloads.push((
            marker.clone(),
            format!(
                "{}' UNION SELECT '{}', 'staged', NOW() INTO OUTFILE '/tmp/sqli_stage.txt';-- ",
                param, marker
            ),
        ));

        payloads
    }

    /// Calculate content hash for change detection
    fn calculate_hash(&self, content: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        hasher.finish()
    }

    /// Register a payload injection for tracking
    pub fn register_injection(
        &mut self,
        endpoint: &str,
        payload: &str,
        marker: &str,
        target_endpoints: Vec<String>,
    ) {
        if self.stored_payloads.len() >= MAX_STORED_PAYLOADS {
            // Remove oldest untriggered payload
            self.stored_payloads.retain(|_, p| p.triggered);
        }

        let stored = StoredPayload {
            id: marker.to_string(),
            payload: payload.to_string(),
            injection_endpoint: endpoint.to_string(),
            injection_time: Instant::now(),
            target_endpoints,
            triggered: false,
            trigger_endpoint: None,
            trigger_time: None,
        };

        self.stored_payloads.insert(marker.to_string(), stored);
    }

    /// Establish baseline for an endpoint
    pub fn establish_baseline(&mut self, endpoint: &str, content_hash: u64) {
        self.baseline_hashes.insert(endpoint.to_string(), content_hash);
    }

    /// Check for payload triggers on target endpoints
    pub async fn check_triggers(&mut self, endpoint: &str, content: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        let content_hash = self.calculate_hash(content);

        // Check if content differs from baseline
        let baseline_changed = if let Some(&baseline) = self.baseline_hashes.get(endpoint) {
            baseline != content_hash
        } else {
            false
        };

        // Check for marker presence in content
        for (marker, stored) in self.stored_payloads.iter_mut() {
            if !stored.triggered && stored.target_endpoints.contains(&endpoint.to_string()) {
                // Check if marker appears in content
                if content.contains(marker) {
                    stored.triggered = true;
                    stored.trigger_endpoint = Some(endpoint.to_string());
                    stored.trigger_time = Some(Instant::now());

                    results.push(CheckResult {
                        module: "second_order_sqli".to_string(),
                        severity: Severity::Critical,
                        confidence: 0.9,
                        description: format!(
                            "Second-order SQLi detected. Payload injected at '{}' triggered at '{}'",
                            stored.injection_endpoint, endpoint
                        ),
                        evidence: format!("Marker '{}' found in response", marker),
                        parameter: None,
                        remediation: "Sanitize all input, use parameterized queries everywhere".to_string(),
                    });
                }
            }
        }

        // Also check for baseline changes as potential indicator
        if baseline_changed && !results.is_empty() {
            // Enhance confidence if baseline changed
            for result in &mut results {
                result.confidence = 0.95;
                result.description.push_str(" (confirmed by content change)");
            }
        }

        results
    }

    /// Inject payloads and schedule detection
    pub async fn inject_and_detect(
        &mut self,
        injection_request: &HttpRequest,
        param: &str,
        detection_requests: Vec<HttpRequest>,
    ) -> Vec<CheckResult> {
        let payloads = self.generate_payloads(param);
        let mut results = Vec::new();

        for (marker, payload) in payloads {
            // Inject payload
            let mut inject_request = injection_request.clone();
            if let Some(body) = inject_request.body_mut() {
                body.replace(&format!("{}=", param), &format!("{}={}", param, payload));
            }

            match self.http_client.execute(&inject_request).await {
                Ok(_) => {
                    // Register the injection
                    self.register_injection(
                        injection_request.url(),
                        &payload,
                        &marker,
                        detection_requests.iter().map(|r| r.url().to_string()).collect(),
                    );

                    // Wait for detection delay
                    tokio::time::sleep(self.detection_delay).await;

                    // Check each detection endpoint
                    for detect_request in &detection_requests {
                        match self.http_client.execute(detect_request).await {
                            Ok(response) => {
                                let content = response.body();
                                let triggers = self.check_triggers(detect_request.url(), content).await;
                                results.extend(triggers);
                            }
                            Err(_) => continue,
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        results
    }

    /// Get statistics about stored payloads
    pub fn get_stats(&self) -> SecondOrderStats {
        let total = self.stored_payloads.len();
        let triggered = self.stored_payloads.values().filter(|p| p.triggered).count();
        let pending = total - triggered;

        SecondOrderStats {
            total_payloads: total,
            triggered_payloads: triggered,
            pending_payloads: pending,
            tracked_endpoints: self.baseline_hashes.len(),
        }
    }

    /// Clear all tracking data
    pub fn clear(&mut self) {
        self.stored_payloads.clear();
        self.effect_signatures.clear();
        self.baseline_hashes.clear();
    }
}

impl CheckModule for SecondOrderDetector {
    fn name(&self) -> &'static str {
        "second_order_sqli"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn run(&mut self, _request: &HttpRequest) -> Vec<CheckResult> {
        vec![]
    }
}

/// Statistics about second-order detection
#[derive(Debug, Clone)]
pub struct SecondOrderStats {
    pub total_payloads: usize,
    pub triggered_payloads: usize,
    pub pending_payloads: usize,
    pub tracked_endpoints: usize,
}

/// Cross-endpoint tracker for multi-request analysis
pub struct CrossEndpointTracker {
    injections: HashMap<String, Vec<String>>, // endpoint -> markers
    detections: HashMap<String, HashSet<String>>, // endpoint -> found markers
}

impl CrossEndpointTracker {
    pub fn new() -> Self {
        Self {
            injections: HashMap::new(),
            detections: HashMap::new(),
        }
    }

    /// Track an injection at an endpoint
    pub fn track_injection(&mut self, endpoint: &str, marker: &str) {
        self.injections
            .entry(endpoint.to_string())
            .or_insert_with(Vec::new)
            .push(marker.to_string());
    }

    /// Record marker detection at an endpoint
    pub fn record_detection(&mut self, endpoint: &str, marker: &str) {
        self.detections
            .entry(endpoint.to_string())
            .or_insert_with(HashSet::new)
            .insert(marker.to_string());
    }

    /// Find correlations between injections and detections
    pub fn find_correlations(&self) -> Vec<Correlation> {
        let mut correlations = Vec::new();

        for (inject_endpoint, markers) in &self.injections {
            for (detect_endpoint, found_markers) in &self.detections {
                if inject_endpoint != detect_endpoint {
                    let common: Vec<_> = markers
                        .iter()
                        .filter(|m| found_markers.contains(*m))
                        .collect();

                    if !common.is_empty() {
                        correlations.push(Correlation {
                            injection_endpoint: inject_endpoint.clone(),
                            detection_endpoint: detect_endpoint.clone(),
                            matching_markers: common.into_iter().cloned().collect(),
                        });
                    }
                }
            }
        }

        correlations
    }
}

impl Default for CrossEndpointTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Correlation between injection and detection
#[derive(Debug, Clone)]
pub struct Correlation {
    pub injection_endpoint: String,
    pub detection_endpoint: String,
    pub matching_markers: Vec<String>,
}

// Note: Requires rand and tokio crates
// [dependencies]
// rand = "0.8"
// tokio = { version = "1", features = ["time", "macros"] }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_generation() {
        let cache = SqliCache::new();
        let client = HttpClient::default();
        let detector = SecondOrderDetector::new(cache, client);

        let payloads = detector.generate_payloads("id");
        assert!(!payloads.is_empty());
        assert!(payloads.iter().all(|(m, p)| p.contains(m)));
    }

    #[test]
    fn test_hash_calculation() {
        let cache = SqliCache::new();
        let client = HttpClient::default();
        let detector = SecondOrderDetector::new(cache, client);

        let hash1 = detector.calculate_hash("Hello World");
        let hash2 = detector.calculate_hash("Hello World");
        let hash3 = detector.calculate_hash("Different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_tracker_correlations() {
        let mut tracker = CrossEndpointTracker::new();

        tracker.track_injection("/api/login", "marker1");
        tracker.track_injection("/api/login", "marker2");
        tracker.record_detection("/api/profile", "marker1");

        let correlations = tracker.find_correlations();
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].matching_markers.len(), 1);
    }
}
