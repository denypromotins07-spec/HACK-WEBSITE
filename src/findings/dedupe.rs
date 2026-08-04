//! Finding Deduplication
//! 
//! Builds deduplication to merge duplicate findings across agents
//! and repeated checks during vulnerability scanning.

use std::collections::{HashMap, HashSet};
use crate::findings::finding::Finding;

/// Deduplication strategy
#[derive(Debug, Clone, Copy)]
pub enum DedupeStrategy {
    /// Keep the first finding only
    FirstWins,
    /// Keep the finding with highest confidence
    HighestConfidence,
    /// Keep the finding with most evidence
    MostEvidence,
    /// Merge all evidence into one finding
    MergeAll,
}

impl Default for DedupeStrategy {
    fn default() -> Self {
        DedupeStrategy::HighestConfidence
    }
}

/// Result of deduplication processing
#[derive(Debug, Clone)]
pub struct DedupeResult {
    /// Unique findings after deduplication
    pub findings: Vec<Finding>,
    /// Number of duplicates removed
    pub duplicates_removed: usize,
    /// Map of dedupe keys to merged findings
    pub merge_map: HashMap<String, Vec<String>>,
}

/// Deduplicator for vulnerability findings
pub struct FindingDeduplicator {
    strategy: DedupeStrategy,
    seen_keys: HashMap<String, Finding>,
    merge_map: HashMap<String, Vec<String>>,
    duplicate_count: usize,
}

impl FindingDeduplicator {
    /// Create a new deduplicator with default strategy
    pub fn new() -> Self {
        Self {
            strategy: DedupeStrategy::default(),
            seen_keys: HashMap::new(),
            merge_map: HashMap::new(),
            duplicate_count: 0,
        }
    }
    
    /// Create with custom strategy
    pub fn with_strategy(strategy: DedupeStrategy) -> Self {
        Self {
            strategy,
            seen_keys: HashMap::new(),
            merge_map: HashMap::new(),
            duplicate_count: 0,
        }
    }
    
    /// Process a single finding
    pub fn process(&mut self, finding: Finding) -> Option<Finding> {
        let key = finding.dedupe_key();
        
        match self.seen_keys.get(&key) {
            None => {
                // New finding
                self.seen_keys.insert(key.clone(), finding.clone());
                Some(finding)
            }
            Some(existing) => {
                // Duplicate found
                self.duplicate_count += 1;
                
                // Track the merge
                self.merge_map
                    .entry(key.clone())
                    .or_default()
                    .push(finding.id.0.clone());
                
                match self.strategy {
                    DedupeStrategy::FirstWins => None,
                    
                    DedupeStrategy::HighestConfidence => {
                        if finding.confidence > existing.confidence {
                            self.seen_keys.insert(key, finding.clone());
                            Some(finding)
                        } else {
                            None
                        }
                    }
                    
                    DedupeStrategy::MostEvidence => {
                        if finding.evidence.len() > existing.evidence.len() {
                            self.seen_keys.insert(key, finding.clone());
                            Some(finding)
                        } else {
                            None
                        }
                    }
                    
                    DedupeStrategy::MergeAll => {
                        // Merge evidence from both findings
                        let mut merged = existing.clone();
                        for evidence in &finding.evidence {
                            if !merged.evidence.iter().any(|e| e.data == evidence.data) {
                                merged.evidence.push(evidence.clone());
                            }
                        }
                        merged.confidence = merged.confidence.max(finding.confidence);
                        self.seen_keys.insert(key, merged.clone());
                        Some(merged)
                    }
                }
            }
        }
    }
    
    /// Process multiple findings at once
    pub fn process_batch(&mut self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter_map(|f| self.process(f))
            .collect()
    }
    
    /// Get all unique findings
    pub fn get_unique_findings(&self) -> Vec<Finding> {
        self.seen_keys.values().cloned().collect()
    }
    
    /// Get count of duplicates
    pub fn duplicate_count(&self) -> usize {
        self.duplicate_count
    }
    
    /// Get count of unique findings
    pub fn unique_count(&self) -> usize {
        self.seen_keys.len()
    }
    
    /// Clear all state
    pub fn clear(&mut self) {
        self.seen_keys.clear();
        self.merge_map.clear();
        self.duplicate_count = 0;
    }
    
    /// Finalize and return results
    pub fn finalize(self) -> DedupeResult {
        DedupeResult {
            findings: self.seen_keys.into_values().collect(),
            duplicates_removed: self.duplicate_count,
            merge_map: self.merge_map,
        }
    }
}

impl Default for FindingDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

/// Global deduplication registry for cross-agent deduplication
pub struct GlobalDedupRegistry {
    seen_hashes: std::sync::Mutex<HashSet<String>>,
    findings_cache: std::sync::Mutex<HashMap<String, Finding>>,
    stats: std::sync::Mutex<DedupeStats>,
}

#[derive(Debug, Clone, Default)]
pub struct DedupeStats {
    pub total_processed: u64,
    pub duplicates_found: u64,
    pub unique_findings: u64,
}

impl GlobalDedupRegistry {
    /// Create a new global registry
    pub fn new() -> Self {
        Self {
            seen_hashes: std::sync::Mutex::new(HashSet::new()),
            findings_cache: std::sync::Mutex::new(HashMap::new()),
            stats: std::sync::Mutex::new(DedupeStats::default()),
        }
    }
    
    /// Try to register a finding (returns false if duplicate)
    pub fn try_register(&self, finding: Finding) -> bool {
        let key = finding.dedupe_key();
        let hash = self.hash_key(&key);
        
        let mut seen = self.seen_hashes.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();
        
        stats.total_processed += 1;
        
        if seen.contains(&hash) {
            stats.duplicates_found += 1;
            false
        } else {
            seen.insert(hash);
            
            let mut cache = self.findings_cache.lock().unwrap();
            cache.insert(finding.id.0.clone(), finding);
            stats.unique_findings += 1;
            
            true
        }
    }
    
    /// Check if a finding is a duplicate without registering
    pub fn is_duplicate(&self, finding: &Finding) -> bool {
        let key = finding.dedupe_key();
        let hash = self.hash_key(&key);
        let seen = self.seen_hashes.lock().unwrap();
        seen.contains(&hash)
    }
    
    /// Get a finding by ID
    pub fn get_finding(&self, id: &str) -> Option<Finding> {
        let cache = self.findings_cache.lock().unwrap();
        cache.get(id).cloned()
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> DedupeStats {
        self.stats.lock().unwrap().clone()
    }
    
    /// Generate hash for a key
    fn hash_key(&self, key: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }
    
    /// Clear the registry
    pub fn clear(&self) {
        self.seen_hashes.lock().unwrap().clear();
        self.findings_cache.lock().unwrap().clear();
        *self.stats.lock().unwrap() = DedupeStats::default();
    }
}

impl Default for GlobalDedupRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::severity::Severity;
    
    #[test]
    fn test_deduplicator_first_wins() {
        let mut deduper = FindingDeduplicator::with_strategy(DedupeStrategy::FirstWins);
        
        let f1 = Finding::new("mod1", Severity::High, "Vuln", "Desc", "/endpoint")
            .with_confidence(50);
        let f2 = Finding::new("mod1", Severity::High, "Vuln", "Desc2", "/endpoint")
            .with_confidence(90);
        
        let result1 = deduper.process(f1.clone());
        let result2 = deduper.process(f2);
        
        assert!(result1.is_some());
        assert!(result2.is_none());
        assert_eq!(deduper.duplicate_count(), 1);
    }
    
    #[test]
    fn test_deduplicator_highest_confidence() {
        let mut deduper = FindingDeduplicator::with_strategy(DedupeStrategy::HighestConfidence);
        
        let f1 = Finding::new("mod1", Severity::High, "Vuln", "Desc", "/endpoint")
            .with_confidence(50);
        let f2 = Finding::new("mod1", Severity::High, "Vuln", "Desc2", "/endpoint")
            .with_confidence(90);
        
        let result1 = deduper.process(f1);
        let result2 = deduper.process(f2.clone());
        
        assert!(result1.is_some());
        assert!(result2.is_some()); // Higher confidence replaces
        
        let findings = deduper.get_unique_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, 90);
    }
    
    #[test]
    fn test_deduplicator_merge_all() {
        let mut deduper = FindingDeduplicator::with_strategy(DedupeStrategy::MergeAll);
        
        use crate::findings::finding::Evidence;
        use crate::findings::finding::EvidenceType;
        use crate::findings::finding::EvidenceLocation;
        
        let e1 = Evidence {
            evidence_type: EvidenceType::ErrorMessage {
                message: "Error 1".to_string(),
                stack_trace: None,
            },
            data: "data1".to_string(),
            location: EvidenceLocation {
                path: "/test".to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 80,
        };
        
        let e2 = Evidence {
            evidence_type: EvidenceType::ErrorMessage {
                message: "Error 2".to_string(),
                stack_trace: None,
            },
            data: "data2".to_string(),
            location: EvidenceLocation {
                path: "/test".to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 70,
        };
        
        let f1 = Finding::new("mod1", Severity::High, "Vuln", "Desc", "/endpoint")
            .with_evidence(e1)
            .with_confidence(80);
        let f2 = Finding::new("mod1", Severity::High, "Vuln", "Desc", "/endpoint")
            .with_evidence(e2)
            .with_confidence(70);
        
        deduper.process(f1);
        deduper.process(f2);
        
        let findings = deduper.get_unique_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.len(), 2); // Both evidences merged
    }
    
    #[test]
    fn test_global_registry() {
        let registry = GlobalDedupRegistry::new();
        
        let f1 = Finding::new("mod1", Severity::High, "Vuln", "Desc", "/endpoint");
        let f2 = Finding::new("mod1", Severity::High, "Vuln", "Desc", "/endpoint");
        
        assert!(registry.try_register(f1));
        assert!(!registry.try_register(f2)); // Duplicate
        
        let stats = registry.get_stats();
        assert_eq!(stats.total_processed, 2);
        assert_eq!(stats.duplicates_found, 1);
        assert_eq!(stats.unique_findings, 1);
    }
}
