//! Schedule Cache for Learning-Driven Optimization
//! 
//! Caches optimal check order and disabled noisy modules
//! for future scans to improve efficiency.

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use crate::learning::check_scores::{CheckScoresStore, TechFingerprint, CheckPerformance};

/// Cached schedule for a specific target profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSchedule {
    /// Target technology fingerprint
    pub tech_fingerprint: TechFingerprint,
    /// Ordered list of module IDs (optimal execution order)
    pub ordered_modules: Vec<String>,
    /// Modules to skip (noisy/low-value)
    pub skipped_modules: HashSet<String>,
    /// Average scan duration in ms
    pub avg_scan_duration_ms: u64,
    /// Number of times this schedule was used
    pub usage_count: u32,
    /// Last used timestamp
    pub last_used: u64,
    /// Effectiveness score (findings per minute)
    pub effectiveness_score: f64,
}

impl CachedSchedule {
    pub fn new(tech_fingerprint: TechFingerprint) -> Self {
        Self {
            tech_fingerprint,
            ordered_modules: Vec::new(),
            skipped_modules: HashSet::new(),
            avg_scan_duration_ms: 0,
            usage_count: 0,
            last_used: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            effectiveness_score: 0.0,
        }
    }
    
    /// Record a schedule usage
    pub fn record_usage(&mut self, findings_count: u32, duration_ms: u64) {
        self.usage_count += 1;
        self.last_used = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Update average duration
        let alpha = 0.3;
        self.avg_scan_duration_ms = (self.avg_scan_duration_ms as f64 * (1.0 - alpha)
            + duration_ms as f64 * alpha) as u64;
        
        // Calculate effectiveness (findings per minute)
        if duration_ms > 0 {
            self.effectiveness_score = (findings_count as f64 / duration_ms as f64) * 60_000.0;
        }
    }
    
    /// Check if this schedule is stale
    pub fn is_stale(&self, max_age_seconds: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now - self.last_used > max_age_seconds
    }
}

/// Schedule cache for learning-driven optimization
pub struct ScheduleCache {
    /// Cached schedules by tech fingerprint key
    schedules: HashMap<String, CachedSchedule>,
    /// Global module disable list (across all targets)
    globally_disabled: HashSet<String>,
    /// Maximum number of cached schedules (bounded storage)
    max_schedules: usize,
    /// Maximum age of cached entries in seconds
    max_age_seconds: u64,
}

impl ScheduleCache {
    pub fn new(max_schedules: usize, max_age_seconds: u64) -> Self {
        Self {
            schedules: HashMap::new(),
            globally_disabled: HashSet::new(),
            max_schedules,
            max_age_seconds,
        }
    }
    
    /// Get or create a schedule for a tech fingerprint
    pub fn get_or_create_schedule(&mut self, tech: &TechFingerprint) -> &mut CachedSchedule {
        let key = tech.to_key();
        
        // Bounded storage - prune if needed
        if self.schedules.len() >= self.max_schedules && !self.schedules.contains_key(&key) {
            self.prune_old_entries();
            
            // If still at limit, remove least effective
            if self.schedules.len() >= self.max_schedules {
                if let Some(least_effective) = self.schedules
                    .iter()
                    .min_by(|(_, a), (_, b)| {
                        a.effectiveness_score.partial_cmp(&b.effectiveness_score)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|(k, _)| k.clone())
                {
                    self.schedules.remove(&least_effective);
                }
            }
        }
        
        self.schedules.entry(key).or_insert_with(|| {
            CachedSchedule::new(tech.clone())
        })
    }
    
    /// Get schedule for a tech fingerprint
    pub fn get_schedule(&self, tech: &TechFingerprint) -> Option<&CachedSchedule> {
        self.schedules.get(&tech.to_key())
    }
    
    /// Get mutable schedule
    pub fn get_schedule_mut(&mut self, tech: &TechFingerprint) -> Option<&mut CachedSchedule> {
        self.schedules.get_mut(&tech.to_key())
    }
    
    /// Mark a module as noisy for a specific tech profile
    pub fn mark_module_noisy(&mut self, tech: &TechFingerprint, module_id: &str) {
        let schedule = self.get_or_create_schedule(tech);
        schedule.skipped_modules.insert(module_id.to_string());
    }
    
    /// Globally disable a module
    pub fn globally_disable_module(&mut self, module_id: &str) {
        self.globally_disabled.insert(module_id.to_string());
    }
    
    /// Check if a module should be skipped
    pub fn should_skip_module(&self, tech: &TechFingerprint, module_id: &str) -> bool {
        // Check global disable first
        if self.globally_disabled.contains(module_id) {
            return true;
        }
        
        // Check tech-specific disable
        self.schedules
            .get(&tech.to_key())
            .map(|s| s.skipped_modules.contains(module_id))
            .unwrap_or(false)
    }
    
    /// Get optimized module order for a tech profile
    pub fn get_optimized_order(&self, tech: &TechFingerprint, all_modules: &[String]) -> Vec<String> {
        if let Some(schedule) = self.schedules.get(&tech.to_key()) {
            // Use cached order, filtering out disabled modules
            schedule.ordered_modules
                .iter()
                .filter(|m| !self.should_skip_module(tech, m))
                .cloned()
                .collect()
        } else {
            // No cached schedule - use default order
            all_modules
                .iter()
                .filter(|m| !self.should_skip_module(tech, m))
                .cloned()
                .collect()
        }
    }
    
    /// Update schedule with scan results
    pub fn update_schedule(
        &mut self,
        tech: &TechFingerprint,
        findings_count: u32,
        duration_ms: u64,
        module_order: Vec<String>,
    ) {
        let schedule = self.get_or_create_schedule(tech);
        schedule.record_usage(findings_count, duration_ms);
        schedule.ordered_modules = module_order;
    }
    
    /// Prune old entries
    pub fn prune_old_entries(&mut self) {
        self.schedules.retain(|_, v| !v.is_stale(self.max_age_seconds));
    }
    
    /// Clear all caches
    pub fn clear(&mut self) {
        self.schedules.clear();
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> CacheStats {
        CacheStats {
            total_schedules: self.schedules.len(),
            globally_disabled_count: self.globally_disabled.len(),
            avg_effectiveness: if self.schedules.is_empty() {
                0.0
            } else {
                self.schedules.values().map(|s| s.effectiveness_score).sum::<f64>()
                    / self.schedules.len() as f64
            },
        }
    }
    
    /// Export for persistence
    pub fn export(&self) -> ScheduleCacheExport {
        ScheduleCacheExport {
            schedules: self.schedules.clone(),
            globally_disabled: self.globally_disabled.clone(),
        }
    }
    
    /// Import from persistence
    pub fn import(&mut self, export: ScheduleCacheExport) {
        self.schedules = export.schedules;
        self.globally_disabled = export.globally_disabled;
    }
}

impl Default for ScheduleCache {
    fn default() -> Self {
        Self::new(100, 7 * 24 * 60 * 60) // 100 schedules, 7 days max age
    }
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub total_schedules: usize,
    pub globally_disabled_count: usize,
    pub avg_effectiveness: f64,
}

/// Serializable export format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleCacheExport {
    pub schedules: HashMap<String, CachedSchedule>,
    pub globally_disabled: HashSet<String>,
}

/// Builder for creating optimized schedules based on scores
pub struct ScheduleOptimizer {
    scores_store: CheckScoresStore,
    min_success_rate: f64,
    prefer_fast_checks: bool,
}

impl ScheduleOptimizer {
    pub fn new(scores_store: CheckScoresStore) -> Self {
        Self {
            scores_store,
            min_success_rate: 0.1,
            prefer_fast_checks: true,
        }
    }
    
    pub fn with_min_success_rate(mut self, rate: f64) -> Self {
        self.min_success_rate = rate;
        self
    }
    
    pub fn with_fast_check_preference(mut self, prefer: bool) -> Self {
        self.prefer_fast_checks = prefer;
        self
    }
    
    /// Generate optimized module order
    pub fn optimize(&self, modules: &[String], tech: Option<&TechFingerprint>) -> Vec<String> {
        let mut scored_modules: Vec<(String, f64)> = modules
            .iter()
            .map(|id| {
                let score = if let Some(t) = tech {
                    self.scores_store
                        .get_for_tech(id, t)
                        .map(|p| p.weighted_score())
                        .unwrap_or(50.0)
                } else {
                    self.scores_store
                        .get_global(id)
                        .map(|p| p.weighted_score())
                        .unwrap_or(50.0)
                };
                (id.clone(), score)
            })
            .collect();
        
        // Sort by score (descending)
        scored_modules.sort_by(|a, b| {
            b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Filter out low-performing modules
        scored_modules
            .into_iter()
            .filter(|(_, score)| *score >= self.min_success_rate * 100.0)
            .map(|(id, _)| id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_schedule_cache_creation() {
        let cache = ScheduleCache::new(50, 86400);
        assert_eq!(cache.get_stats().total_schedules, 0);
    }
    
    #[test]
    fn test_schedule_usage_recording() {
        let mut cache = ScheduleCache::default();
        let tech = TechFingerprint::new().with_server("nginx");
        
        let schedule = cache.get_or_create_schedule(&tech);
        assert_eq!(schedule.usage_count, 0);
        
        // Record some usages
        drop(schedule);
        cache.update_schedule(&tech, 5, 30000, vec!["mod1".to_string()]);
        
        let schedule = cache.get_schedule(&tech).unwrap();
        assert_eq!(schedule.usage_count, 1);
        assert_eq!(schedule.ordered_modules, vec!["mod1"]);
    }
    
    #[test]
    fn test_module_disabling() {
        let mut cache = ScheduleCache::default();
        let tech = TechFingerprint::new();
        
        // Mark module as noisy for specific tech
        cache.mark_module_noisy(&tech, "noisy_module");
        assert!(cache.should_skip_module(&tech, "noisy_module"));
        assert!(!cache.should_skip_module(&tech, "other_module"));
        
        // Global disable
        cache.globally_disable_module("global_bad");
        assert!(cache.should_skip_module(&tech, "global_bad"));
    }
    
    #[test]
    fn test_schedule_optimizer() {
        let scores = CheckScoresStore::new(100);
        let optimizer = ScheduleOptimizer::new(scores)
            .with_min_success_rate(0.2);
        
        let modules = vec!["mod1".to_string(), "mod2".to_string(), "mod3".to_string()];
        let tech = TechFingerprint::new();
        
        let optimized = optimizer.optimize(&modules, Some(&tech));
        // All modules should be included (no history yet)
        assert_eq!(optimized.len(), 3);
    }
}
