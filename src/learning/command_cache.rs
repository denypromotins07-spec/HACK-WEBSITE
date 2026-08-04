//! Command Injection Learning Cache
//! Caches successful command injection vectors and binary exploitation signatures.
//! Implements bounded LRU cache for self-learning across scans.

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, Duration};

/// Maximum cache entries (bounded)
const MAX_CACHE_ENTRIES: usize = 500;

/// Cache entry TTL (1 hour)
const ENTRY_TTL: Duration = Duration::from_secs(3600);

/// Command injection vector signature
#[derive(Debug, Clone)]
pub struct InjectionVector {
    pub payload: String,
    pub parameter_pattern: String,
    pub success_count: u32,
    pub last_success: SystemTime,
    pub target_types: Vec<String>,
}

/// Binary exploitation signature
#[derive(Debug, Clone)]
pub struct ExploitSignature {
    pub signature: String,
    pub vulnerability_type: String,
    pub detection_pattern: String,
    pub false_positive_rate: f32,
}

/// Cached domain reputation for command injection targets
#[derive(Debug, Clone)]
pub struct DomainReputation {
    pub domain: String,
    pub injection_likelihood: f32,
    pub previous_findings: u32,
    pub last_scan: SystemTime,
}

/// Command injection learning cache
pub struct CommandCache {
    /// Successful injection vectors by parameter pattern
    vectors: HashMap<String, InjectionVector>,
    /// Binary exploitation signatures
    signatures: HashMap<String, ExploitSignature>,
    /// Domain reputation scores
    domain_reputation: HashMap<String, DomainReputation>,
    /// LRU queue for eviction
    lru_queue: VecDeque<String>,
    /// Max entries limit
    max_entries: usize,
}

impl CommandCache {
    pub fn new() -> Self {
        Self {
            vectors: HashMap::with_capacity(MAX_CACHE_ENTRIES / 2),
            signatures: HashMap::with_capacity(MAX_CACHE_ENTRIES / 4),
            domain_reputation: HashMap::with_capacity(MAX_CACHE_ENTRIES / 4),
            lru_queue: VecDeque::with_capacity(MAX_CACHE_ENTRIES),
            max_entries: MAX_CACHE_ENTRIES,
        }
    }
    
    /// Record a successful command injection
    pub fn record_injection(&mut self, param_pattern: &str, payload: &str, target_type: &str) {
        let key = param_pattern.to_string();
        
        if let Some(vector) = self.vectors.get_mut(&key) {
            vector.success_count += 1;
            vector.last_success = SystemTime::now();
            if !vector.target_types.contains(&target_type.to_string()) {
                vector.target_types.push(target_type.to_string());
            }
        } else {
            // Evict if at capacity
            if self.vectors.len() >= self.max_entries / 2 {
                self.evict_oldest();
            }
            
            self.vectors.insert(key.clone(), InjectionVector {
                payload: payload.to_string(),
                parameter_pattern: param_pattern.to_string(),
                success_count: 1,
                last_success: SystemTime::now(),
                target_types: vec![target_type.to_string()],
            });
        }
        
        // Update LRU queue
        self.update_lru(&key);
    }
    
    /// Get recommended payloads for a parameter pattern
    pub fn get_payloads_for_pattern(&self, param_pattern: &str) -> Vec<&String> {
        let mut results = Vec::new();
        
        // Find similar patterns
        for (pattern, vector) in self.vectors.iter() {
            if pattern.contains(param_pattern) || param_pattern.contains(pattern) {
                results.push(&vector.payload);
            }
        }
        
        results
    }
    
    /// Record an exploit signature
    pub fn record_signature(&mut self, vuln_type: &str, signature: &str, pattern: &str) {
        let key = format!("{}:{}", vuln_type, signature);
        
        if self.signatures.len() >= self.max_entries / 4 {
            // Simple eviction - remove oldest signature
            if let Some((old_key, _)) = self.signatures.iter().next() {
                let old_key = old_key.clone();
                self.signatures.remove(&old_key);
            }
        }
        
        self.signatures.insert(key, ExploitSignature {
            signature: signature.to_string(),
            vulnerability_type: vuln_type.to_string(),
            detection_pattern: pattern.to_string(),
            false_positive_rate: 0.0,
        });
    }
    
    /// Check if a signature is known
    pub fn is_known_signature(&self, vuln_type: &str, signature: &str) -> bool {
        let key = format!("{}:{}", vuln_type, signature);
        self.signatures.contains_key(&key)
    }
    
    /// Update domain reputation after finding
    pub fn update_domain_reputation(&mut self, domain: &str, found_vulnerability: bool) {
        if let Some(rep) = self.domain_reputation.get_mut(domain) {
            if found_vulnerability {
                rep.previous_findings += 1;
                rep.injection_likelihood = (rep.injection_likelihood + 0.1).min(1.0);
            } else {
                rep.injection_likelihood = (rep.injection_likelihood - 0.05).max(0.0);
            }
            rep.last_scan = SystemTime::now();
        } else {
            if self.domain_reputation.len() >= self.max_entries / 4 {
                // Evict oldest domain
                if let Some((old_key, _)) = self.domain_reputation.iter().next() {
                    let old_key = old_key.clone();
                    self.domain_reputation.remove(&old_key);
                }
            }
            
            self.domain_reputation.insert(domain.to_string(), DomainReputation {
                domain: domain.to_string(),
                injection_likelihood: if found_vulnerability { 0.5 } else { 0.1 },
                previous_findings: if found_vulnerability { 1 } else { 0 },
                last_scan: SystemTime::now(),
            });
        }
    }
    
    /// Get domain injection likelihood
    pub fn get_domain_likelihood(&self, domain: &str) -> f32 {
        self.domain_reputation.get(domain)
            .map(|r| r.injection_likelihood)
            .unwrap_or(0.1) // Default low likelihood
    }
    
    /// Update LRU queue
    fn update_lru(&mut self, key: &str) {
        // Remove existing entry
        if let Some(pos) = self.lru_queue.iter().position(|k| k == key) {
            self.lru_queue.remove(pos);
        }
        
        // Add to front
        self.lru_queue.push_front(key.to_string());
        
        // Trim if over capacity
        while self.lru_queue.len() > self.max_entries {
            self.lru_queue.pop_back();
        }
    }
    
    /// Evict oldest entry
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self.lru_queue.pop_back() {
            self.vectors.remove(&oldest_key);
        }
    }
    
    /// Clear expired entries
    pub fn clear_expired(&mut self) {
        let now = SystemTime::now();
        
        self.vectors.retain(|_, v| {
            v.last_success.elapsed().unwrap_or(Duration::MAX) < ENTRY_TTL
        });
        
        self.domain_reputation.retain(|_, r| {
            r.last_scan.elapsed().unwrap_or(Duration::MAX) < ENTRY_TTL
        });
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            vector_count: self.vectors.len(),
            signature_count: self.signatures.len(),
            domain_count: self.domain_reputation.len(),
            total_entries: self.vectors.len() + self.signatures.len() + self.domain_reputation.len(),
        }
    }
}

impl Default for CommandCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug)]
pub struct CacheStats {
    pub vector_count: usize,
    pub signature_count: usize,
    pub domain_count: usize,
    pub total_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_record_injection() {
        let mut cache = CommandCache::new();
        cache.record_injection("cmd", ";id", "linux");
        
        assert!(cache.vectors.contains_key("cmd"));
        let vector = cache.vectors.get("cmd").unwrap();
        assert_eq!(vector.success_count, 1);
    }
    
    #[test]
    fn test_payload_recommendation() {
        let mut cache = CommandCache::new();
        cache.record_injection("command", ";whoami", "linux");
        cache.record_injection("cmd", "|id", "linux");
        
        let payloads = cache.get_payloads_for_pattern("cmd");
        assert!(!payloads.is_empty());
    }
    
    #[test]
    fn test_domain_reputation() {
        let mut cache = CommandCache::new();
        cache.update_domain_reputation("example.com", true);
        cache.update_domain_reputation("example.com", true);
        
        let likelihood = cache.get_domain_likelihood("example.com");
        assert!(likelihood > 0.5);
    }
    
    #[test]
    fn test_cache_bounds() {
        let mut cache = CommandCache::new();
        
        for i in 0..MAX_CACHE_ENTRIES + 100 {
            cache.record_injection(&format!("param_{}", i), &format!("payload_{}", i), "linux");
        }
        
        assert!(cache.vectors.len() <= MAX_CACHE_ENTRIES / 2);
    }
}
