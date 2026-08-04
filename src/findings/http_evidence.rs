//! HTTP Protocol-Specific Evidence Container
//! 
//! Builds protocol-specific evidence containers with request/response timing snapshots.
//! Provides detailed forensic data for HTTP vulnerability findings.

use crate::findings::finding::Finding;
use crate::findings::severity::Severity;
use std::time::{Duration, Instant};

/// HTTP Evidence Container
/// 
/// Captures detailed protocol-level evidence including:
/// - Raw request/response bytes
/// - Timing information
/// - Header analysis
/// - Differential comparison data
#[derive(Debug, Clone)]
pub struct HttpEvidence {
    /// Unique identifier for this evidence instance
    pub id: String,
    
    /// The check ID that generated this evidence
    pub check_id: String,
    
    /// Raw HTTP request bytes
    pub request_raw: Vec<u8>,
    
    /// Raw HTTP response bytes  
    pub response_raw: Vec<u8>,
    
    /// Request timing snapshot
    pub request_timing: RequestTiming,
    
    /// Response timing snapshot
    pub response_timing: ResponseTiming,
    
    /// Parsed headers from request
    pub request_headers: Vec<(String, String)>,
    
    /// Parsed headers from response
    pub response_headers: Vec<(String, String)>,
    
    /// Evidence confidence score (0.0 - 1.0)
    pub confidence: f64,
    
    /// Additional context about the evidence
    pub context: Option<String>,
    
    /// Related findings
    pub related_findings: Vec<Finding>,
}

/// Request timing snapshot
#[derive(Debug, Clone)]
pub struct RequestTiming {
    /// Time to establish connection
    pub connect_time: Duration,
    
    /// Time to send request
    pub send_time: Duration,
    
    /// Total request time
    pub total_time: Duration,
    
    /// Timestamp of request
    pub timestamp: u64,
}

impl RequestTiming {
    pub fn new(connect: Duration, send: Duration, total: Duration) -> Self {
        Self {
            connect_time: connect,
            send_time: send,
            total_time: total,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_millis() as u64,
        }
    }
}

/// Response timing snapshot
#[derive(Debug, Clone)]
pub struct ResponseTiming {
    /// Time to first byte
    pub ttfb: Duration,
    
    /// Time to download complete response
    pub download_time: Duration,
    
    /// Total response time
    pub total_time: Duration,
}

impl ResponseTiming {
    pub fn new(ttfb: Duration, download: Duration, total: Duration) -> Self {
        Self {
            ttfb,
            download_time: download,
            total_time: total,
        }
    }
}

impl HttpEvidence {
    /// Create new HTTP evidence container
    pub fn new(check_id: String) -> Self {
        Self {
            id: format!("evidence_{}", chrono_lite_id()),
            check_id,
            request_raw: Vec::new(),
            response_raw: Vec::new(),
            request_timing: RequestTiming::new(
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
            ),
            response_timing: ResponseTiming::new(
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
            ),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            confidence: 0.0,
            context: None,
            related_findings: Vec::new(),
        }
    }

    /// Set raw request data
    pub fn with_request(mut self, raw: &[u8]) -> Self {
        self.request_raw = raw.to_vec();
        self
    }

    /// Set raw response data
    pub fn with_response(mut self, raw: &[u8]) -> Self {
        self.response_raw = raw.to_vec();
        self
    }

    /// Set request timing
    pub fn with_request_timing(mut self, timing: RequestTiming) -> Self {
        self.request_timing = timing;
        self
    }

    /// Set response timing
    pub fn with_response_timing(mut self, timing: ResponseTiming) -> Self {
        self.response_timing = timing;
        self
    }

    /// Add parsed headers
    pub fn with_headers(mut self, request: Vec<(String, String)>, response: Vec<(String, String)>) -> Self {
        self.request_headers = request;
        self.response_headers = response;
        self
    }

    /// Set confidence score
    pub fn with_confidence(mut self, score: f64) -> Self {
        self.confidence = score.clamp(0.0, 1.0);
        self
    }

    /// Add context
    pub fn with_context(mut self, ctx: String) -> Self {
        self.context = Some(ctx);
        self
    }

    /// Add related finding
    pub fn add_finding(&mut self, finding: Finding) {
        self.related_findings.push(finding);
    }

    /// Convert to a normalized Finding
    pub fn to_finding(&self, severity: Severity, title: String, description: String) -> Finding {
        Finding::new(
            self.check_id.clone(),
            severity,
            title,
            self.evidence_summary(),
            description,
        )
    }

    /// Generate human-readable evidence summary
    pub fn evidence_summary(&self) -> String {
        let mut summary = String::new();
        
        summary.push_str(&format!("Check ID: {}\n", self.check_id));
        summary.push_str(&format!("Confidence: {:.2}\n", self.confidence));
        
        if let Some(ctx) = &self.context {
            summary.push_str(&format!("Context: {}\n", ctx));
        }

        // Request summary
        if !self.request_raw.is_empty() {
            let req_preview = String::from_utf8_lossy(&self.request_raw[..self.request_raw.len().min(200)]);
            summary.push_str(&format!("\nRequest Preview:\n{}\n", req_preview));
        }

        // Response summary
        if !self.response_raw.is_empty() {
            let resp_preview = String::from_utf8_lossy(&self.response_raw[..self.response_raw.len().min(500)]);
            summary.push_str(&format!("\nResponse Preview:\n{}\n", resp_preview));
        }

        // Timing summary
        summary.push_str(&format!(
            "\nTiming: Request={:?}, TTFB={:?}",
            self.request_timing.total_time,
            self.response_timing.ttfb,
        ));

        summary
    }

    /// Check if evidence meets threshold for reporting
    pub fn meets_threshold(&self, min_confidence: f64) -> bool {
        self.confidence >= min_confidence
    }
}

/// Builder for creating HttpEvidence with fluent API
pub struct HttpEvidenceBuilder {
    evidence: HttpEvidence,
}

impl HttpEvidenceBuilder {
    pub fn new(check_id: String) -> Self {
        Self {
            evidence: HttpEvidence::new(check_id),
        }
    }

    pub fn request(mut self, raw: &[u8]) -> Self {
        self.evidence.request_raw = raw.to_vec();
        self
    }

    pub fn response(mut self, raw: &[u8]) -> Self {
        self.evidence.response_raw = raw.to_vec();
        self
    }

    pub fn confidence(mut self, score: f64) -> Self {
        self.evidence.confidence = score.clamp(0.0, 1.0);
        self
    }

    pub fn context(mut self, ctx: String) -> Self {
        self.evidence.context = Some(ctx);
        self
    }

    pub fn build(self) -> HttpEvidence {
        self.evidence
    }
}

/// Simple ID generator (placeholder for actual implementation)
fn chrono_lite_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{:x}", duration.as_nanos() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_creation() {
        let evidence = HttpEvidence::new("HTTP-001".to_string());
        assert_eq!(evidence.check_id, "HTTP-001");
        assert!(evidence.id.starts_with("evidence_"));
        assert_eq!(evidence.confidence, 0.0);
    }

    #[test]
    fn test_evidence_builder() {
        let evidence = HttpEvidenceBuilder::new("HTTP-002".to_string())
            .request(b"GET / HTTP/1.1\r\n")
            .response(b"HTTP/1.1 200 OK\r\n")
            .confidence(0.95)
            .context("Test context".to_string())
            .build();

        assert_eq!(evidence.check_id, "HTTP-002");
        assert!(!evidence.request_raw.is_empty());
        assert!(!evidence.response_raw.is_empty());
        assert_eq!(evidence.confidence, 0.95);
        assert_eq!(evidence.context, Some("Test context".to_string()));
    }

    #[test]
    fn test_threshold_check() {
        let evidence = HttpEvidence::new("HTTP-003".to_string())
            .with_confidence(0.85);
        
        assert!(evidence.meets_threshold(0.8));
        assert!(!evidence.meets_threshold(0.9));
    }

    #[test]
    fn test_evidence_summary() {
        let evidence = HttpEvidence::new("HTTP-004".to_string())
            .with_request(b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .with_response(b"HTTP/1.1 200 OK\r\n\r\nBody content")
            .with_context("Test scenario".to_string());

        let summary = evidence.evidence_summary();
        assert!(summary.contains("HTTP-004"));
        assert!(summary.contains("GET /test"));
        assert!(summary.contains("200 OK"));
    }
}
