//! Out-of-Band (OOB) Callback Listener
//! 
//! Asynchronous OOB listener and callback verifier for blind SSRF and XXE detection.
//! Uses bounded queues to maintain 2GB RAM ceiling.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tokio::time::timeout;

/// Type of OOB interaction
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OobType {
    DnsLookup,
    HttpGet,
    HttpPost,
    SmtpConnection,
    LdapConnection,
    FtpConnection,
    SmbConnection,
}

impl OobType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DnsLookup => "dns",
            Self::HttpGet => "http_get",
            Self::HttpPost => "http_post",
            Self::SmtpConnection => "smtp",
            Self::LdapConnection => "ldap",
            Self::FtpConnection => "ftp",
            Self::SmbConnection => "smb",
        }
    }
}

/// OOB callback record
#[derive(Debug, Clone)]
pub struct OobCallback {
    pub request_id: u64,
    pub oob_type: OobType,
    pub callback_ip: String,
    pub callback_data: Option<String>,
    pub received_at: Instant,
    pub latency_ms: u64,
}

/// Expectation for an OOB callback
struct OobExpectation {
    request_id: u64,
    oob_type: OobType,
    expected_domain: String,
    created_at: Instant,
    timeout_ms: u64,
    fulfilled: bool,
}

/// OOB Listener for tracking out-of-band interactions
pub struct OobListener {
    expectations: HashMap<u64, OobExpectation>,
    callbacks: HashMap<u64, OobCallback>,
    total_received: AtomicU64,
    total_expired: AtomicU64,
    max_expectations: usize,
}

impl OobListener {
    pub fn new() -> Self {
        Self {
            expectations: HashMap::new(),
            callbacks: HashMap::new(),
            total_received: AtomicU64::new(0),
            total_expired: AtomicU64::new(0),
            max_expectations: 10000, // Bounded to limit memory
        }
    }
    
    /// Register an expectation for an OOB callback
    pub fn register_expectation(
        &mut self,
        request_id: u64,
        oob_type: OobType,
        timeout_ms: u64,
    ) -> String {
        // Generate unique domain for this expectation
        let unique_id = format!("{:x}", request_id.wrapping_mul(0x5DEECE66D).wrapping_add(0xB));
        let expected_domain = format!("{}.oob.internal", unique_id);
        
        // Clean up old expectations if at capacity
        if self.expectations.len() >= self.max_expectations {
            self.cleanup_expired();
        }
        
        let expectation = OobExpectation {
            request_id,
            oob_type: oob_type.clone(),
            expected_domain: expected_domain.clone(),
            created_at: Instant::now(),
            timeout_ms,
            fulfilled: false,
        };
        
        self.expectations.insert(request_id, expectation);
        
        expected_domain
    }
    
    /// Record a received OOB callback
    pub fn record_callback(
        &mut self,
        domain: &str,
        callback_ip: &str,
        callback_data: Option<String>,
    ) -> Option<OobCallback> {
        // Find matching expectation
        let matching_request_id = self.expectations.iter().find_map(|(request_id, exp)| {
            if domain.contains(&exp.expected_domain) && !exp.fulfilled {
                Some(*request_id)
            } else {
                None
            }
        });
        
        if let Some(request_id) = matching_request_id {
            if let Some(expectation) = self.expectations.get(&request_id) {
                let latency_ms = expectation.created_at.elapsed().as_millis() as u64;
                
                let callback = OobCallback {
                    request_id,
                    oob_type: expectation.oob_type.clone(),
                    callback_ip: callback_ip.to_string(),
                    callback_data,
                    received_at: Instant::now(),
                    latency_ms,
                };
                
                // Mark expectation as fulfilled
                if let Some(exp) = self.expectations.get_mut(&request_id) {
                    exp.fulfilled = true;
                }
                
                self.callbacks.insert(request_id, callback.clone());
                self.total_received.fetch_add(1, Ordering::Relaxed);
                
                return Some(callback);
            }
        }
        
        None
    }
    
    /// Get callback for a specific request
    pub fn get_callback(&self, request_id: u64) -> Option<OobCallback> {
        self.callbacks.get(&request_id).cloned()
    }
    
    /// Check if expectation was fulfilled
    pub fn is_fulfilled(&self, request_id: u64) -> bool {
        self.expectations.get(&request_id).map_or(false, |e| e.fulfilled)
    }
    
    /// Wait for callback with timeout
    pub async fn wait_for_callback(
        &self,
        request_id: u64,
        timeout_duration: Duration,
    ) -> Option<OobCallback> {
        timeout(timeout_duration, async {
            loop {
                if let Some(callback) = self.get_callback(request_id) {
                    return Some(callback);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.ok().flatten()
    }
    
    /// Clean up expired expectations
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let mut expired_count = 0u64;
        
        self.expectations.retain(|_, exp| {
            let elapsed = now.duration_since(exp.created_at).as_millis() as u64;
            if elapsed > exp.timeout_ms {
                expired_count += 1;
                false
            } else {
                true
            }
        });
        
        self.total_expired.fetch_add(expired_count, Ordering::Relaxed);
    }
    
    /// Get statistics
    pub fn stats(&self) -> OobStats {
        OobStats {
            pending_expectations: self.expectations.values().filter(|e| !e.fulfilled).count(),
            fulfilled_expectations: self.expectations.values().filter(|e| e.fulfilled).count(),
            stored_callbacks: self.callbacks.len(),
            total_received: self.total_received.load(Ordering::Relaxed),
            total_expired: self.total_expired.load(Ordering::Relaxed),
        }
    }
    
    /// Reset state
    pub fn reset(&mut self) {
        self.expectations.clear();
        self.callbacks.clear();
    }
}

impl Default for OobListener {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for OOB listener
#[derive(Debug, Clone)]
pub struct OobStats {
    pub pending_expectations: usize,
    pub fulfilled_expectations: usize,
    pub stored_callbacks: usize,
    pub total_received: u64,
    pub total_expired: u64,
}

impl OobStats {
    pub fn fulfillment_rate(&self) -> f64 {
        let total = self.pending_expectations + self.fulfilled_expectations;
        if total == 0 {
            return 0.0;
        }
        self.fulfilled_expectations as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_oob_listener_creation() {
        let listener = OobListener::new();
        let stats = listener.stats();
        assert_eq!(stats.pending_expectations, 0);
    }
    
    #[test]
    fn test_register_expectation() {
        let mut listener = OobListener::new();
        let domain = listener.register_expectation(1, OobType::DnsLookup, 5000);
        
        assert!(domain.contains("oob.internal"));
        assert!(!listener.is_fulfilled(1));
    }
    
    #[test]
    fn test_record_callback() {
        let mut listener = OobListener::new();
        let domain = listener.register_expectation(1, OobType::DnsLookup, 5000);
        
        let callback = listener.record_callback(&domain, "127.0.0.1", Some("data".to_string()));
        
        assert!(callback.is_some());
        assert!(listener.is_fulfilled(1));
    }
}
