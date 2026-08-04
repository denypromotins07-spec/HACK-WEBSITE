//! Fuzz Cache - Persist successful mutation patterns locally
//!
//! Caches successful payload patterns and mutation sequences for reuse
//! in future scans, enabling learning across scan sessions.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cached mutation pattern with success metrics
#[derive(Debug, Clone)]
pub struct CachedPattern {
    /// Original payload template
    pub template: String,
    /// Mutation applied
    pub mutation: String,
    /// Resulting payload
    pub result: String,
    /// Vulnerability class it worked for
    pub vuln_class: String,
    /// Number of successful uses
    pub success_count: u64,
    /// Number of failed uses
    pub failure_count: u64,
    /// Last used timestamp
    pub last_used: u64,
    /// Target patterns where it succeeded
    pub successful_targets: HashSet<String>,
}

impl CachedPattern {
    pub fn new(template: impl Into<String>, mutation: impl Into<String>, vuln_class: impl Into<String>) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Self {
            template: template.into(),
            mutation: mutation.into(),
            result: String::new(),
            vuln_class: vuln_class.into(),
            success_count: 0,
            failure_count: 0,
            last_used: now,
            successful_targets: HashSet::new(),
        }
    }

    pub fn record_success(&mut self, target_id: &str) {
        self.success_count += 1;
        self.successful_targets.insert(target_id.to_string());
        self.last_used = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            0.0
        } else {
            self.success_count as f64 / total as f64
        }
    }

    pub fn is_worth_retry(&self) -> bool {
        // Retry if success rate > 50% or not enough data yet
        self.success_rate() > 0.5 || (self.success_count + self.failure_count) < 5
    }
}

/// Persistent cache for fuzzing patterns
#[derive(Debug)]
pub struct FuzzCache {
    /// Cached patterns by ID
    patterns: HashMap<String, CachedPattern>,
    /// Patterns indexed by vulnerability class
    by_vuln_class: HashMap<String, Vec<String>>,
    /// Persistence file path
    persist_path: Option<PathBuf>,
    /// Maximum cache size
    max_size: usize,
}

impl FuzzCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create cache with persistence
    pub fn with_persistence(path: impl Into<PathBuf>) -> Self {
        let mut cache = Self::default();
        cache.persist_path = Some(path.into());
        cache
    }

    /// Set maximum cache size
    pub fn with_max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }

    /// Add a pattern to the cache
    pub fn add_pattern(&mut self, id: &str, pattern: CachedPattern) {
        // Enforce max size by removing oldest entries
        if self.patterns.len() >= self.max_size {
            self.evict_oldest();
        }

        let vuln_class = pattern.vuln_class.clone();
        self.patterns.insert(id.to_string(), pattern);
        
        self.by_vuln_class
            .entry(vuln_class)
            .or_default()
            .push(id.to_string());
    }

    /// Record a successful pattern application
    pub fn record_success(&mut self, pattern_id: &str, target_id: &str) {
        if let Some(pattern) = self.patterns.get_mut(pattern_id) {
            pattern.record_success(target_id);
        }
    }

    /// Record a failed pattern application
    pub fn record_failure(&mut self, pattern_id: &str) {
        if let Some(pattern) = self.patterns.get_mut(pattern_id) {
            pattern.record_failure();
        }
    }

    /// Get patterns for a vulnerability class
    pub fn get_patterns_for_class(&self, vuln_class: &str) -> Vec<&CachedPattern> {
        let ids = self.by_vuln_class.get(vuln_class).map(|v| v.as_slice()).unwrap_or(&[]);
        ids.iter()
            .filter_map(|id| self.patterns.get(id))
            .collect()
    }

    /// Get best patterns by success rate
    pub fn get_best_patterns(&self, min_successes: u64) -> Vec<&CachedPattern> {
        let mut patterns: Vec<&CachedPattern> = self.patterns.values().collect();
        patterns.retain(|p| p.success_count >= min_successes);
        patterns.sort_by(|a, b| {
            b.success_rate().partial_cmp(&a.success_rate()).unwrap_or(std::cmp::Ordering::Equal)
        });
        patterns
    }

    /// Get patterns that should be retried
    pub fn get_retry_candidates(&self) -> Vec<&CachedPattern> {
        self.patterns.values().filter(|p| p.is_worth_retry()).collect()
    }

    /// Check if a pattern exists
    pub fn contains(&self, id: &str) -> bool {
        self.patterns.contains_key(id)
    }

    /// Get pattern by ID
    pub fn get(&self, id: &str) -> Option<&CachedPattern> {
        self.patterns.get(id)
    }

    /// Get mutable reference to pattern
    pub fn get_mut(&mut self, id: &str) -> Option<&mut CachedPattern> {
        self.patterns.get_mut(id)
    }

    /// Remove a pattern from cache
    pub fn remove(&mut self, id: &str) -> Option<CachedPattern> {
        if let Some(pattern) = self.patterns.remove(id) {
            // Also remove from index
            if let Some(ids) = self.by_vuln_class.get_mut(&pattern.vuln_class) {
                ids.retain(|i| i != id);
            }
            Some(pattern)
        } else {
            None
        }
    }

    /// Clear all patterns
    pub fn clear(&mut self) {
        self.patterns.clear();
        self.by_vuln_class.clear();
    }

    /// Evict oldest patterns (by last_used)
    fn evict_oldest(&mut self) {
        let mut entries: Vec<(&String, &CachedPattern)> = self.patterns.iter().collect();
        entries.sort_by(|a, b| a.1.last_used.cmp(&b.1.last_used));
        
        // Remove oldest 10%
        let remove_count = (self.patterns.len() / 10).max(1);
        for (id, _) in entries.into_iter().take(remove_count) {
            self.remove(id);
        }
    }

    /// Save cache to disk
    pub fn save(&self) -> Result<(), std::io::Error> {
        if let Some(ref path) = self.persist_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            
            let mut file = File::create(path)?;
            
            for (id, pattern) in &self.patterns {
                writeln!(file, "PATTERN:{}", id)?;
                writeln!(file, "TEMPLATE:{}", pattern.template.replace('\n', "\\n"))?;
                writeln!(file, "MUTATION:{}", pattern.mutation.replace('\n', "\\n"))?;
                writeln!(file, "RESULT:{}", pattern.result.replace('\n', "\\n"))?;
                writeln!(file, "CLASS:{}", pattern.vuln_class)?;
                writeln!(file, "SUCCESS:{}", pattern.success_count)?;
                writeln!(file, "FAILURE:{}", pattern.failure_count)?;
                writeln!(file, "LAST_USED:{}", pattern.last_used)?;
                writeln!(file, "TARGETS:{}", pattern.successful_targets.iter().cloned().collect::<Vec<_>>().join(","))?;
                writeln!(file, "END_PATTERN")?;
            }
        }
        Ok(())
    }

    /// Load cache from disk
    pub fn load(&mut self) -> Result<(), std::io::Error> {
        if let Some(ref path) = self.persist_path {
            if !path.exists() {
                return Ok(());
            }

            let file = File::open(path)?;
            let reader = BufReader::new(file);
            
            let mut current_id: Option<String> = None;
            let mut current_pattern: Option<CachedPattern> = None;
            
            for line in reader.lines() {
                let line = line?;
                
                if line.starts_with("PATTERN:") {
                    current_id = Some(line[8..].to_string());
                } else if line.starts_with("TEMPLATE:") && current_pattern.is_some() {
                    if let Some(ref mut p) = current_pattern {
                        p.template = line[9..].replace("\\n", "\n");
                    }
                } else if line.starts_with("MUTATION:") && current_pattern.is_some() {
                    if let Some(ref mut p) = current_pattern {
                        p.mutation = line[9..].replace("\\n", "\n");
                    }
                } else if line.starts_with("RESULT:") && current_pattern.is_some() {
                    if let Some(ref mut p) = current_pattern {
                        p.result = line[7..].replace("\\n", "\n");
                    }
                } else if line.starts_with("CLASS:") && current_pattern.is_some() {
                    if let Some(ref mut p) = current_pattern {
                        p.vuln_class = line[6..].to_string();
                    }
                } else if line.starts_with("SUCCESS:") && current_pattern.is_some() {
                    if let Ok(count) = line[8..].parse::<u64>() {
                        if let Some(ref mut p) = current_pattern {
                            p.success_count = count;
                        }
                    }
                } else if line.starts_with("FAILURE:") && current_pattern.is_some() {
                    if let Ok(count) = line[8..].parse::<u64>() {
                        if let Some(ref mut p) = current_pattern {
                            p.failure_count = count;
                        }
                    }
                } else if line.starts_with("LAST_USED:") && current_pattern.is_some() {
                    if let Ok(ts) = line[10..].parse::<u64>() {
                        if let Some(ref mut p) = current_pattern {
                            p.last_used = ts;
                        }
                    }
                } else if line.starts_with("TARGETS:") && current_pattern.is_some() {
                    if let Some(ref mut p) = current_pattern {
                        p.successful_targets = line[8..]
                            .split(',')
                            .filter(|s| !s.is_empty())
                            .map(String::from)
                            .collect();
                    }
                } else if line == "END_PATTERN" {
                    if let (Some(id), Some(pattern)) = (current_id.take(), current_pattern.take()) {
                        self.add_pattern(&id, pattern);
                    }
                } else if current_id.is_some() && current_pattern.is_none() {
                    // Starting a new pattern entry
                    current_pattern = Some(CachedPattern::new("", "", ""));
                }
            }
        }
        Ok(())
    }

    /// Get cache statistics
    pub fn stats(&self) -> FuzzCacheStats {
        let total_patterns = self.patterns.len();
        let total_successes: u64 = self.patterns.values().map(|p| p.success_count).sum();
        let total_failures: u64 = self.patterns.values().map(|p| p.failure_count).sum();
        let avg_success_rate = if total_patterns > 0 {
            self.patterns.values().map(|p| p.success_rate()).sum::<f64>() / total_patterns as f64
        } else {
            0.0
        };

        FuzzCacheStats {
            total_patterns,
            total_successes,
            total_failures,
            avg_success_rate,
        }
    }
}

impl Default for FuzzCache {
    fn default() -> Self {
        Self {
            patterns: HashMap::new(),
            by_vuln_class: HashMap::new(),
            persist_path: None,
            max_size: 10000,
        }
    }
}

/// Cache statistics
#[derive(Debug, Default)]
pub struct FuzzCacheStats {
    pub total_patterns: usize,
    pub total_successes: u64,
    pub total_failures: u64,
    pub avg_success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_pattern_success_rate() {
        let mut pattern = CachedPattern::new("template", "mutation", "SqlInjection");
        
        pattern.record_success("target1");
        pattern.record_success("target2");
        pattern.record_failure();
        
        assert!(pattern.success_rate() > 0.6);
        assert!(pattern.is_worth_retry());
    }

    #[test]
    fn test_fuzz_cache_basic() {
        let mut cache = FuzzCache::new();
        
        let pattern = CachedPattern::new("SELECT * FROM", "' OR '1'='1", "SqlInjection");
        cache.add_pattern("sqli-001", pattern);
        
        assert!(cache.contains("sqli-001"));
        assert_eq!(cache.get("sqli-001").unwrap().success_count, 0);
    }

    #[test]
    fn test_fuzz_cache_recording() {
        let mut cache = FuzzCache::new();
        
        let pattern = CachedPattern::new("template", "mutation", "Xss");
        cache.add_pattern("xss-001", pattern);
        
        cache.record_success("xss-001", "target1");
        cache.record_success("xss-001", "target2");
        cache.record_failure("xss-001");
        
        let p = cache.get("xss-001").unwrap();
        assert_eq!(p.success_count, 2);
        assert_eq!(p.failure_count, 1);
    }

    #[test]
    fn test_get_patterns_by_class() {
        let mut cache = FuzzCache::new();
        
        cache.add_pattern("sqli-001", CachedPattern::new("t", "m", "SqlInjection"));
        cache.add_pattern("sqli-002", CachedPattern::new("t", "m", "SqlInjection"));
        cache.add_pattern("xss-001", CachedPattern::new("t", "m", "Xss"));
        
        let sqli_patterns = cache.get_patterns_for_class("SqlInjection");
        assert_eq!(sqli_patterns.len(), 2);
    }

    #[test]
    fn test_cache_stats() {
        let mut cache = FuzzCache::new();
        
        let mut pattern = CachedPattern::new("t", "m", "SqlInjection");
        pattern.record_success("target1");
        cache.add_pattern("p1", pattern);
        
        let stats = cache.stats();
        assert_eq!(stats.total_patterns, 1);
        assert_eq!(stats.total_successes, 1);
    }
}
