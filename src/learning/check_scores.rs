//! Check Performance Scores
//! 
//! Stores historical success rates for each vulnerability module
//! per target technology to optimize future scans.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Technology fingerprint for targeted learning
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct TechFingerprint {
    pub server: Option<String>,
    pub framework: Option<String>,
    pub language: Option<String>,
    pub database: Option<String>,
    pub os: Option<String>,
}

impl TechFingerprint {
    pub fn new() -> Self {
        Self {
            server: None,
            framework: None,
            language: None,
            database: None,
            os: None,
        }
    }
    
    pub fn with_server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }
    
    pub fn with_framework(mut self, framework: impl Into<String>) -> Self {
        self.framework = Some(framework.into());
        self
    }
    
    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }
    
    /// Generate a hashable key for this fingerprint
    pub fn to_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.server.as_deref().unwrap_or("*"),
            self.framework.as_deref().unwrap_or("*"),
            self.language.as_deref().unwrap_or("*"),
            self.database.as_deref().unwrap_or("*"),
            self.os.as_deref().unwrap_or("*"),
        )
    }
    
    /// Parse from key string
    pub fn from_key(key: &str) -> Self {
        let parts: Vec<&str> = key.split('|').collect();
        Self {
            server: if parts[0] != "*" { Some(parts[0].to_string()) } else { None },
            framework: if parts[1] != "*" { Some(parts[1].to_string()) } else { None },
            language: if parts[2] != "*" { Some(parts[2].to_string()) } else { None },
            database: if parts[3] != "*" { Some(parts[3].to_string()) } else { None },
            os: if parts[4] != "*" { Some(parts[4].to_string()) } else { None },
        }
    }
}

impl Default for TechFingerprint {
    fn default() -> Self {
        Self::new()
    }
}

/// Performance metrics for a check module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckPerformance {
    /// Module ID
    pub module_id: String,
    /// Total executions
    pub total_runs: u64,
    /// Successful findings count
    pub findings_count: u64,
    /// False positive count
    pub false_positives: u64,
    /// Average execution time in ms
    pub avg_execution_ms: f64,
    /// Total execution time in ms
    pub total_execution_ms: u64,
    /// Last run timestamp (Unix epoch seconds)
    pub last_run: u64,
    /// Success rate (findings / runs)
    pub success_rate: f64,
    /// Precision (true positives / all positives)
    pub precision: f64,
}

impl CheckPerformance {
    pub fn new(module_id: impl Into<String>) -> Self {
        Self {
            module_id: module_id.into(),
            total_runs: 0,
            findings_count: 0,
            false_positives: 0,
            avg_execution_ms: 0.0,
            total_execution_ms: 0,
            last_run: 0,
            success_rate: 0.5, // Default neutral
            precision: 1.0,
        }
    }
    
    /// Record a completed run
    pub fn record_run(&mut self, had_finding: bool, execution_ms: u64) {
        self.total_runs += 1;
        self.total_execution_ms += execution_ms;
        
        // Exponential moving average for execution time
        let alpha = 0.3;
        self.avg_execution_ms = self.avg_execution_ms * (1.0 - alpha) 
            + execution_ms as f64 * alpha;
        
        if had_finding {
            self.findings_count += 1;
        }
        
        self.last_run = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.update_rates();
    }
    
    /// Record a false positive
    pub fn record_false_positive(&mut self) {
        self.false_positives += 1;
        self.update_rates();
    }
    
    /// Update calculated rates
    fn update_rates(&mut self) {
        if self.total_runs > 0 {
            self.success_rate = self.findings_count as f64 / self.total_runs as f64;
            
            let true_positives = self.findings_count.saturating_sub(self.false_positives);
            let all_positives = self.findings_count.max(1);
            self.precision = true_positives as f64 / all_positives as f64;
        }
    }
    
    /// Get weighted score for prioritization
    pub fn weighted_score(&self) -> f64 {
        // Higher score = should run earlier
        // Balance between success rate and precision
        let finding_weight = 0.6;
        let precision_weight = 0.4;
        
        (self.success_rate * finding_weight + self.precision * precision_weight) * 100.0
    }
    
    /// Check if this check is worth running based on history
    pub fn is_worth_running(&self, min_runs: u64, min_success_rate: f64) -> bool {
        if self.total_runs < min_runs {
            return true; // Not enough data, assume worth running
        }
        self.success_rate >= min_success_rate
    }
}

/// Storage for check scores organized by technology
pub struct CheckScoresStore {
    /// Global scores (technology-agnostic)
    global_scores: HashMap<String, CheckPerformance>,
    /// Technology-specific scores
    tech_scores: HashMap<String, HashMap<String, CheckPerformance>>,
    /// Maximum entries to keep per module (bounded storage)
    max_entries_per_module: usize,
}

impl CheckScoresStore {
    pub fn new(max_entries_per_module: usize) -> Self {
        Self {
            global_scores: HashMap::new(),
            tech_scores: HashMap::new(),
            max_entries_per_module,
        }
    }
    
    /// Record a run globally
    pub fn record_global_run(&mut self, module_id: &str, had_finding: bool, execution_ms: u64) {
        let perf = self.global_scores.entry(module_id.to_string()).or_insert_with(|| {
            CheckPerformance::new(module_id)
        });
        perf.record_run(had_finding, execution_ms);
    }
    
    /// Record a run for specific technology
    pub fn record_tech_run(
        &mut self,
        module_id: &str,
        tech: &TechFingerprint,
        had_finding: bool,
        execution_ms: u64,
    ) {
        let tech_key = tech.to_key();
        
        let tech_map = self.tech_scores.entry(module_id.to_string()).or_default();
        
        // Bounded storage - remove oldest if over limit
        if tech_map.len() >= self.max_entries_per_module {
            if let Some(oldest_key) = tech_map
                .iter()
                .min_by_key(|(_, v)| v.last_run)
                .map(|(k, _)| k.clone())
            {
                tech_map.remove(&oldest_key);
            }
        }
        
        let perf = tech_map.entry(tech_key).or_insert_with(|| {
            CheckPerformance::new(module_id)
        });
        perf.record_run(had_finding, execution_ms);
    }
    
    /// Get global performance for a module
    pub fn get_global(&self, module_id: &str) -> Option<&CheckPerformance> {
        self.global_scores.get(module_id)
    }
    
    /// Get technology-specific performance
    pub fn get_for_tech(&self, module_id: &str, tech: &TechFingerprint) -> Option<&CheckPerformance> {
        self.tech_scores
            .get(module_id)
            .and_then(|m| m.get(&tech.to_key()))
    }
    
    /// Get best performing technology for a module
    pub fn get_best_tech(&self, module_id: &str) -> Option<(&str, &CheckPerformance)> {
        self.tech_scores
            .get(module_id)
            .and_then(|m| {
                m.iter()
                    .max_by(|(_, a), (_, b)| {
                        a.weighted_score().partial_cmp(&b.weighted_score())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|(k, v)| (k.as_str(), v))
            })
    }
    
    /// Get all modules sorted by global performance
    pub fn get_modules_by_performance(&self) -> Vec<&CheckPerformance> {
        let mut modules: Vec<_> = self.global_scores.values().collect();
        modules.sort_by(|a, b| {
            b.weighted_score()
                .partial_cmp(&a.weighted_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        modules
    }
    
    /// Get underperforming modules
    pub fn get_underperformers(&self, max_success_rate: f64, min_runs: u64) -> Vec<&str> {
        self.global_scores
            .iter()
            .filter(|(_, p)| p.total_runs >= min_runs && p.success_rate < max_success_rate)
            .map(|(k, _)| k.as_str())
            .collect()
    }
    
    /// Clear old entries (older than specified seconds)
    pub fn prune_old_entries(&mut self, max_age_seconds: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Prune global scores
        self.global_scores.retain(|_, v| now - v.last_run < max_age_seconds);
        
        // Prune tech scores
        for tech_map in self.tech_scores.values_mut() {
            tech_map.retain(|_, v| now - v.last_run < max_age_seconds);
        }
    }
    
    /// Export scores for persistence
    pub fn export(&self) -> CheckScoresExport {
        CheckScoresExport {
            global: self.global_scores.clone(),
            tech_specific: self.tech_scores.clone(),
        }
    }
    
    /// Import scores from persistence
    pub fn import(&mut self, export: CheckScoresExport) {
        self.global_scores = export.global;
        self.tech_scores = export.tech_specific;
    }
}

impl Default for CheckScoresStore {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// Serializable export format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckScoresExport {
    pub global: HashMap<String, CheckPerformance>,
    pub tech_specific: HashMap<String, HashMap<String, CheckPerformance>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tech_fingerprint_key() {
        let fp = TechFingerprint::new()
            .with_server("nginx")
            .with_framework("express");
        
        let key = fp.to_key();
        assert!(key.contains("nginx"));
        assert!(key.contains("express"));
        
        let parsed = TechFingerprint::from_key(&key);
        assert_eq!(parsed.server, Some("nginx".to_string()));
        assert_eq!(parsed.framework, Some("express".to_string()));
    }
    
    #[test]
    fn test_check_performance_tracking() {
        let mut perf = CheckPerformance::new("test_module");
        
        perf.record_run(true, 100);
        perf.record_run(false, 50);
        perf.record_run(true, 75);
        
        assert_eq!(perf.total_runs, 3);
        assert_eq!(perf.findings_count, 2);
        assert!((perf.success_rate - 0.667).abs() < 0.01);
    }
    
    #[test]
    fn test_weighted_score() {
        let mut perf = CheckPerformance::new("test");
        perf.success_rate = 0.8;
        perf.precision = 0.9;
        
        let score = perf.weighted_score();
        assert!(score > 0.0 && score <= 100.0);
    }
    
    #[test]
    fn test_scores_store_bounded_storage() {
        let mut store = CheckScoresStore::new(3);
        let tech = TechFingerprint::new().with_server("apache");
        
        // Add more than max entries
        for i in 0..5 {
            std::thread::sleep(std::time::Duration::from_millis(1));
            let mut t = tech.clone();
            t.os = Some(format!("os_{}", i));
            store.record_tech_run("module1", &t, true, 100);
        }
        
        // Should be bounded
        let tech_map = store.tech_scores.get("module1").unwrap();
        assert!(tech_map.len() <= 3);
    }
}
