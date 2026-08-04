//! Response Analysis Module
//! 
//! Exports analysis traits and wires the fingerprinting engine 
//! into the global scanner context.

pub mod fingerprint;
pub mod normalize;
pub mod differential;
pub mod timing;
pub mod variance;
pub mod oob;
pub mod interact;
pub mod correlate;
pub mod blind;
pub mod errors;
pub mod reflection;

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::RwLock;

pub use fingerprint::{ResponseFingerprint, FingerprintCache, quick_hash, bounded_levenshtein};
pub use normalize::{BodyNormalizer, NormalizedBody, NormalizeConfig, StreamingNormalizer, compare_normalized};
pub use differential::{DifferentialEngine, DifferentialResult, ComparisonMode};
pub use timing::{TimingAnalyzer, TimingResult, TimingThresholds};
pub use variance::{VarianceModel, VarianceStats, StructuralShift};
pub use oob::{OobListener, OobCallback, OobType};
pub use interact::{InteractionServer, InteractionEvent, Protocol};
pub use correlate::{CorrelationEngine, CorrelationMatch};
pub use blind::{BlindDetector, BlindState, BlindConfidence};
pub use errors::{ErrorSignature, ErrorDatabase, ErrorMatch};
pub use reflection::{ReflectionTracker, ReflectionPoint, ReflectionMap};

/// Global analysis context shared across the 100-agent swarm
pub struct AnalysisContext {
    pub fingerprint_cache: Arc<FingerprintCache>,
    pub differential_engine: Arc<DifferentialEngine>,
    pub timing_analyzer: Arc<TimingAnalyzer>,
    pub oob_listener: Arc<RwLock<OobListener>>,
    pub correlation_engine: Arc<CorrelationEngine>,
    pub blind_detector: Arc<BlindDetector>,
    pub error_database: Arc<ErrorDatabase>,
    pub reflection_tracker: Arc<ReflectionTracker>,
    pub normalizer: Arc<BodyNormalizer>,
}

impl AnalysisContext {
    /// Create a new analysis context with default configurations
    pub fn new() -> Self {
        Self {
            fingerprint_cache: Arc::new(FingerprintCache::new(10000)),
            differential_engine: Arc::new(DifferentialEngine::new()),
            timing_analyzer: Arc::new(TimingAnalyzer::new(TimingThresholds::default())),
            oob_listener: Arc::new(RwLock::new(OobListener::new())),
            correlation_engine: Arc::new(CorrelationEngine::new()),
            blind_detector: Arc::new(BlindDetector::new()),
            error_database: Arc::new(ErrorDatabase::new()),
            reflection_tracker: Arc::new(ReflectionTracker::new()),
            normalizer: Arc::new(BodyNormalizer::with_default_config()),
        }
    }
    
    /// Analyze a response for vulnerabilities
    pub async fn analyze_response(
        &self,
        request_id: u64,
        body: &Bytes,
        headers: &[(String, String)],
        status_code: u16,
        content_type: &str,
        elapsed_ns: u64,
        baseline_fingerprint: Option<&ResponseFingerprint>,
    ) -> AnalysisResult {
        let start = Instant::now();
        
        // Create fingerprint
        let fingerprint = ResponseFingerprint::new(
            body,
            headers,
            status_code,
            content_type,
            elapsed_ns,
        );
        
        // Normalize body
        let normalized = self.normalizer.normalize(body);
        
        // Perform differential analysis if baseline exists
        let differential = if let Some(baseline) = baseline_fingerprint {
            self.differential_engine.compare(baseline, &fingerprint, &normalized.data)
        } else {
            DifferentialResult::no_baseline()
        };
        
        // Analyze timing
        let timing_result = self.timing_analyzer.analyze(elapsed_ns);
        
        // Check for error signatures
        let error_matches = self.error_database.scan(body);
        
        // Track reflections
        let reflections = self.reflection_tracker.find_reflections(body, headers);
        
        let analysis_duration_ns = start.elapsed().as_nanos() as u64;
        
        AnalysisResult {
            request_id,
            fingerprint,
            normalized,
            differential,
            timing_result,
            error_matches,
            reflections,
            analysis_duration_ns,
        }
    }
    
    /// Register an OOB callback expectation
    pub async fn register_oob_expectation(
        &self,
        request_id: u64,
        oob_type: OobType,
        timeout_ms: u64,
    ) {
        let mut listener = self.oob_listener.write().await;
        listener.register_expectation(request_id, oob_type, timeout_ms);
    }
    
    /// Check for OOB callbacks matching a request
    pub async fn check_oob_callback(&self, request_id: u64) -> Option<OobCallback> {
        let listener = self.oob_listener.read().await;
        listener.get_callback(request_id)
    }
}

impl Default for AnalysisContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of response analysis
#[derive(Debug)]
pub struct AnalysisResult {
    pub request_id: u64,
    pub fingerprint: ResponseFingerprint,
    pub normalized: NormalizedBody,
    pub differential: DifferentialResult,
    pub timing_result: TimingResult,
    pub error_matches: Vec<ErrorMatch>,
    pub reflections: Vec<ReflectionPoint>,
    pub analysis_duration_ns: u64,
}

impl AnalysisResult {
    /// Determine if this response indicates a potential vulnerability
    pub fn is_suspicious(&self) -> bool {
        // Check differential score
        if self.differential.byte_variance > 0.1 {
            return true;
        }
        
        // Check timing anomalies
        if self.timing_result.is_anomalous {
            return true;
        }
        
        // Check for error signatures
        if !self.error_matches.is_empty() {
            return true;
        }
        
        // Check for reflections
        if !self.reflections.is_empty() {
            return true;
        }
        
        false
    }
    
    /// Calculate overall suspicion score (0.0 to 1.0)
    pub fn suspicion_score(&self) -> f64 {
        let mut score = 0.0;
        
        // Differential contribution (max 0.3)
        score += (self.differential.byte_variance.min(1.0)) * 0.3;
        
        // Timing contribution (max 0.3)
        if self.timing_result.is_anomalous {
            score += 0.3;
        }
        
        // Error signature contribution (max 0.2)
        if !self.error_matches.is_empty() {
            score += 0.2;
        }
        
        // Reflection contribution (max 0.2)
        if !self.reflections.is_empty() {
            score += 0.2;
        }
        
        score.min(1.0)
    }
}

/// High-level analysis trait for extensibility
pub trait ResponseAnalyzer: Send + Sync {
    fn analyze(&self, data: &[u8]) -> AnalysisSummary;
    fn name(&self) -> &str;
}

/// Summary of analysis results
#[derive(Debug, Clone)]
pub struct AnalysisSummary {
    pub is_modified: bool,
    pub has_errors: bool,
    pub has_reflection: bool,
    pub timing_anomaly: bool,
    pub confidence: f64,
}

impl AnalysisSummary {
    pub fn negative() -> Self {
        Self {
            is_modified: false,
            has_errors: false,
            has_reflection: false,
            timing_anomaly: false,
            confidence: 0.0,
        }
    }
    
    pub fn positive(confidence: f64) -> Self {
        Self {
            is_modified: true,
            has_errors: false,
            has_reflection: false,
            timing_anomaly: false,
            confidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_analysis_context_creation() {
        let ctx = AnalysisContext::new();
        assert!(Arc::strong_count(&ctx.fingerprint_cache) >= 1);
    }
    
    #[tokio::test]
    async fn test_analyze_response() {
        let ctx = AnalysisContext::new();
        let body = Bytes::from("<html><body>Hello World</body></html>");
        let headers = vec![("Content-Type".to_string(), "text/html".to_string())];
        
        let result = ctx.analyze_response(
            1,
            &body,
            &headers,
            200,
            "text/html",
            1000,
            None,
        ).await;
        
        assert_eq!(result.request_id, 1);
        assert_eq!(result.fingerprint.status_code, 200);
    }
}
