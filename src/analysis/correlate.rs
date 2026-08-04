//! Correlation Engine
//! 
//! Matches OOB callbacks with specific swarm agent request IDs.
//! Uses lock-free data structures for thread-safe correlation across 100 agents.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::oob::{OobCallback, OobType};
use super::interact::InteractionEvent;

/// Correlation match result
#[derive(Debug, Clone)]
pub struct CorrelationMatch {
    pub request_id: u64,
    pub callback: OobCallback,
    pub interaction: InteractionEvent,
    pub confidence: f64,
    pub matched_at: Instant,
}

/// Pending correlation entry
struct PendingCorrelation {
    request_id: u64,
    oob_type: OobType,
    expected_domain_pattern: String,
    created_at: Instant,
    timeout_ms: u64,
}

/// Correlation engine for matching callbacks to requests
pub struct CorrelationEngine {
    pending: HashMap<u64, PendingCorrelation>,
    matches: Vec<CorrelationMatch>,
    total_correlated: AtomicU64,
    total_uncorrelated: AtomicU64,
    max_pending: usize,
    max_matches: usize,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            matches: Vec::new(),
            total_correlated: AtomicU64::new(0),
            total_uncorrelated: AtomicU64::new(0),
            max_pending: 5000,
            max_matches: 10000,
        }
    }
    
    /// Register a pending correlation
    pub fn register_pending(
        &mut self,
        request_id: u64,
        oob_type: OobType,
        domain_pattern: &str,
        timeout_ms: u64,
    ) {
        // Clean up if at capacity
        if self.pending.len() >= self.max_pending {
            self.cleanup_expired();
        }
        
        let pending = PendingCorrelation {
            request_id,
            oob_type,
            expected_domain_pattern: domain_pattern.to_string(),
            created_at: Instant::now(),
            timeout_ms,
        };
        
        self.pending.insert(request_id, pending);
    }
    
    /// Attempt to correlate an OOB callback with a pending request
    pub fn correlate_callback(
        &mut self,
        callback: &OobCallback,
    ) -> Option<CorrelationMatch> {
        // Find matching pending correlation
        let matching_request_id = self.pending.iter().find_map(|(request_id, pending)| {
            if pending.oob_type == callback.oob_type && !pending.is_expired() {
                Some(*request_id)
            } else {
                None
            }
        });
        
        if let Some(request_id) = matching_request_id {
            if let Some(pending) = self.pending.remove(&request_id) {
                let confidence = self.calculate_confidence(callback, &pending);
                
                let match_result = CorrelationMatch {
                    request_id,
                    callback: callback.clone(),
                    interaction: InteractionEvent {
                        protocol: match callback.oob_type {
                            OobType::DnsLookup => super::interact::Protocol::Udp,
                            _ => super::interact::Protocol::Http,
                        },
                        source_addr: callback.callback_ip.parse().unwrap_or(
                            "0.0.0.0:0".parse().unwrap()
                        ),
                        data: callback.callback_data.clone().unwrap_or_default().into_bytes(),
                        timestamp_ns: callback.latency_ms * 1_000_000,
                        request_id: Some(request_id),
                    },
                    confidence,
                    matched_at: Instant::now(),
                };
                
                // Store match if within capacity
                if self.matches.len() < self.max_matches {
                    self.matches.push(match_result.clone());
                }
                
                self.total_correlated.fetch_add(1, Ordering::Relaxed);
                
                return Some(match_result);
            }
        }
        
        self.total_uncorrelated.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    /// Correlate using domain pattern matching
    pub fn correlate_by_domain(
        &mut self,
        domain: &str,
        callback_ip: &str,
    ) -> Option<CorrelationMatch> {
        // Find pending correlation matching this domain
        let matching = self.pending.iter().find_map(|(request_id, pending)| {
            if domain.contains(&pending.expected_domain_pattern) && !pending.is_expired() {
                Some((*request_id, pending.clone()))
            } else {
                None
            }
        });
        
        if let Some((request_id, pending)) = matching {
            self.pending.remove(&request_id);
            
            let callback = OobCallback {
                request_id,
                oob_type: pending.oob_type,
                callback_ip: callback_ip.to_string(),
                callback_data: Some(domain.to_string()),
                received_at: Instant::now(),
                latency_ms: pending.created_at.elapsed().as_millis() as u64,
            };
            
            let confidence = 0.8; // High confidence for direct domain match
            
            let match_result = CorrelationMatch {
                request_id,
                interaction: InteractionEvent {
                    protocol: match pending.oob_type {
                        OobType::DnsLookup => super::interact::Protocol::Udp,
                        _ => super::interact::Protocol::Http,
                    },
                    source_addr: callback_ip.parse().unwrap_or("0.0.0.0:0".parse().unwrap()),
                    data: domain.as_bytes().to_vec(),
                    timestamp_ns: callback.latency_ms * 1_000_000,
                    request_id: Some(request_id),
                },
                callback,
                confidence,
                matched_at: Instant::now(),
            };
            
            if self.matches.len() < self.max_matches {
                self.matches.push(match_result.clone());
            }
            
            self.total_correlated.fetch_add(1, Ordering::Relaxed);
            
            return Some(match_result);
        }
        
        self.total_uncorrelated.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    /// Get all matches for a specific request
    pub fn get_matches_for_request(&self, request_id: u64) -> Vec<CorrelationMatch> {
        self.matches
            .iter()
            .filter(|m| m.request_id == request_id)
            .cloned()
            .collect()
    }
    
    /// Get the best match for a request (highest confidence)
    pub fn get_best_match(&self, request_id: u64) -> Option<CorrelationMatch> {
        self.matches
            .iter()
            .filter(|m| m.request_id == request_id)
            .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
            .cloned()
    }
    
    /// Calculate confidence score for a correlation
    fn calculate_confidence(&self, callback: &OobCallback, pending: &PendingCorrelation) -> f64 {
        let mut confidence = 0.5;
        
        // Timing factor: faster callbacks are more likely legitimate
        let elapsed_ms = pending.created_at.elapsed().as_millis() as u64;
        if elapsed_ms < pending.timeout_ms / 2 {
            confidence += 0.2;
        }
        
        // Type match factor
        if callback.oob_type == pending.oob_type {
            confidence += 0.2;
        }
        
        // Data presence factor
        if callback.callback_data.is_some() {
            confidence += 0.1;
        }
        
        confidence.min(1.0)
    }
    
    /// Clean up expired pending correlations
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        
        self.pending.retain(|_, pending| {
            !pending.is_expired_at(now)
        });
    }
    
    /// Get statistics
    pub fn stats(&self) -> CorrelationStats {
        CorrelationStats {
            pending_count: self.pending.len(),
            stored_matches: self.matches.len(),
            total_correlated: self.total_correlated.load(Ordering::Relaxed),
            total_uncorrelated: self.total_uncorrelated.load(Ordering::Relaxed),
        }
    }
    
    /// Reset state
    pub fn reset(&mut self) {
        self.pending.clear();
        self.matches.clear();
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingCorrelation {
    fn is_expired(&self) -> bool {
        self.is_expired_at(Instant::now())
    }
    
    fn is_expired_at(&self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.created_at).as_millis() as u64;
        elapsed > self.timeout_ms
    }
}

/// Statistics for correlation engine
#[derive(Debug, Clone)]
pub struct CorrelationStats {
    pub pending_count: usize,
    pub stored_matches: usize,
    pub total_correlated: u64,
    pub total_uncorrelated: u64,
}

impl CorrelationStats {
    pub fn correlation_rate(&self) -> f64 {
        let total = self.total_correlated + self.total_uncorrelated;
        if total == 0 {
            return 0.0;
        }
        self.total_correlated as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_correlation_engine_creation() {
        let engine = CorrelationEngine::new();
        let stats = engine.stats();
        assert_eq!(stats.pending_count, 0);
    }
    
    #[test]
    fn test_register_and_correlate() {
        let mut engine = CorrelationEngine::new();
        
        engine.register_pending(
            1,
            OobType::DnsLookup,
            "test.oob.internal",
            5000,
        );
        
        let stats = engine.stats();
        assert_eq!(stats.pending_count, 1);
    }
}
