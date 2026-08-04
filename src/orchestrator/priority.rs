//! Priority Scoring for Vulnerability Checks
//! 
//! Creates priority scoring using severity, confidence, and historical
//! learning cache to optimize check execution order.

use std::collections::HashMap;
use crate::checks::{VulnerabilityModule, CheckContext, Severity};

/// Weight configuration for priority calculation
#[derive(Debug, Clone)]
pub struct PriorityWeights {
    /// Weight for severity score (0.0 - 1.0)
    pub severity_weight: f32,
    /// Weight for confidence score (0.0 - 1.0)
    pub confidence_weight: f32,
    /// Weight for historical success rate (0.0 - 1.0)
    pub history_weight: f32,
    /// Weight for dependency criticality (0.0 - 1.0)
    pub dependency_weight: f32,
    /// Weight for target relevance (0.0 - 1.0)
    pub relevance_weight: f32,
}

impl Default for PriorityWeights {
    fn default() -> Self {
        Self {
            severity_weight: 0.35,
            confidence_weight: 0.15,
            history_weight: 0.20,
            dependency_weight: 0.10,
            relevance_weight: 0.20,
        }
    }
}

/// Historical performance data for a module
#[derive(Debug, Clone, Default)]
pub struct ModuleHistory {
    /// Total executions
    pub total_runs: u32,
    /// Successful findings count
    pub findings_count: u32,
    /// False positive count
    pub false_positives: u32,
    /// Average execution time in ms
    pub avg_execution_ms: f32,
    /// Success rate (findings / runs)
    pub success_rate: f32,
    /// Last executed timestamp
    pub last_run: Option<u64>,
}

impl ModuleHistory {
    /// Calculate success rate
    pub fn calculate_success_rate(&mut self) {
        if self.total_runs > 0 {
            self.success_rate = self.findings_count as f32 / self.total_runs as f32;
        } else {
            self.success_rate = 0.5; // Default neutral value
        }
    }
    
    /// Record a completed run
    pub fn record_run(&mut self, had_finding: bool, execution_ms: u64) {
        self.total_runs += 1;
        if had_finding {
            self.findings_count += 1;
        }
        
        // Exponential moving average for execution time
        let alpha = 0.3;
        self.avg_execution_ms = self.avg_execution_ms * (1.0 - alpha) 
            + execution_ms as f32 * alpha;
        
        self.calculate_success_rate();
    }
    
    /// Record a false positive
    pub fn record_false_positive(&mut self) {
        self.false_positives += 1;
    }
    
    /// Get confidence adjusted for false positives
    pub fn adjusted_confidence(&self, base_confidence: u8) -> f32 {
        if self.total_runs == 0 {
            return base_confidence as f32 / 100.0;
        }
        
        let fp_rate = self.false_positives as f32 / self.total_runs as f32;
        let base = base_confidence as f32 / 100.0;
        
        // Reduce confidence based on false positive rate
        base * (1.0 - fp_rate.min(0.5))
    }
}

/// Priority scorer for vulnerability checks
pub struct PriorityScorer {
    weights: PriorityWeights,
    history: HashMap<String, ModuleHistory>,
}

impl PriorityScorer {
    /// Create a new priority scorer with default weights
    pub fn new() -> Self {
        Self {
            weights: PriorityWeights::default(),
            history: HashMap::new(),
        }
    }
    
    /// Create with custom weights
    pub fn with_weights(weights: PriorityWeights) -> Self {
        Self {
            weights,
            history: HashMap::new(),
        }
    }
    
    /// Calculate priority score for a module
    /// Lower score = higher priority (runs earlier)
    pub fn calculate_priority(&self, module: &dyn VulnerabilityModule, ctx: &CheckContext) -> u32 {
        let metadata = module.metadata();
        
        // Severity component (inverted so critical = low score = high priority)
        let severity_score = 100.0 - metadata.severity.score() as f32;
        
        // Confidence component
        let base_confidence = metadata.min_confidence;
        let history_key = metadata.id.as_str().to_string();
        let adjusted_confidence = self.history
            .get(&history_key)
            .map(|h| h.adjusted_confidence(base_confidence))
            .unwrap_or(base_confidence as f32 / 100.0);
        let confidence_score = 100.0 * (1.0 - adjusted_confidence);
        
        // History component (prefer modules with good track records)
        let history_score = self.history
            .get(&history_key)
            .map(|h| 100.0 * (1.0 - h.success_rate))
            .unwrap_or(50.0);
        
        // Dependency component (dependencies run first)
        let dependency_score = if module.dependencies().is_empty() {
            0.0
        } else {
            50.0 * module.dependencies().len() as f32
        };
        
        // Relevance component (based on target technology)
        let relevance_score = self.calculate_relevance(module, ctx);
        
        // Weighted sum
        let total = 
            severity_score * self.weights.severity_weight +
            confidence_score * self.weights.confidence_weight +
            history_score * self.weights.history_weight +
            dependency_score * self.weights.dependency_weight +
            relevance_score * self.weights.relevance_weight;
        
        total as u32
    }
    
    /// Calculate relevance score based on target context
    fn calculate_relevance(&self, module: &dyn VulnerabilityModule, ctx: &CheckContext) -> f32 {
        // Safe checks are always relevant
        if module.metadata().is_safe {
            return 20.0; // Low score = high relevance
        }
        
        // God-mode checks need explicit enablement
        if module.metadata().requires_god_mode && !ctx.god_mode {
            return 100.0; // High score = low relevance (won't run)
        }
        
        // TODO: Add technology-specific relevance based on surface map
        // For now, return neutral score
        50.0
    }
    
    /// Update history for a module after execution
    pub fn update_history(&mut self, module_id: &str, had_finding: bool, execution_ms: u64) {
        let history = self.history.entry(module_id.to_string()).or_default();
        history.record_run(had_finding, execution_ms);
    }
    
    /// Record a false positive for a module
    pub fn record_false_positive(&mut self, module_id: &str) {
        if let Some(history) = self.history.get_mut(module_id) {
            history.record_false_positive();
        }
    }
    
    /// Get history for a module
    pub fn get_history(&self, module_id: &str) -> Option<&ModuleHistory> {
        self.history.get(module_id)
    }
    
    /// Get all module histories
    pub fn get_all_histories(&self) -> &HashMap<String, ModuleHistory> {
        &self.history
    }
    
    /// Clear history for a specific module
    pub fn clear_history(&mut self, module_id: &str) {
        self.history.remove(module_id);
    }
    
    /// Clear all history
    pub fn clear_all_history(&mut self) {
        self.history.clear();
    }
    
    /// Get top performing modules by success rate
    pub fn get_top_performers(&self, min_runs: u32, limit: usize) -> Vec<(&str, &ModuleHistory)> {
        let mut performers: Vec<_> = self.history
            .iter()
            .filter(|(_, h)| h.total_runs >= min_runs)
            .collect();
        
        performers.sort_by(|a, b| {
            b.1.success_rate.partial_cmp(&a.1.success_rate).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        performers.truncate(limit);
        performers.into_iter().map(|(k, v)| (k.as_str(), v)).collect()
    }
    
    /// Get underperforming modules (low success rate)
    pub fn get_underperformers(&self, max_rate: f32, min_runs: u32) -> Vec<&str> {
        self.history
            .iter()
            .filter(|(_, h)| h.total_runs >= min_runs && h.success_rate < max_rate)
            .map(|(k, _)| k.as_str())
            .collect()
    }
}

impl Default for PriorityScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_weights_sum_to_one() {
        let weights = PriorityWeights::default();
        let total = weights.severity_weight 
            + weights.confidence_weight 
            + weights.history_weight 
            + weights.dependency_weight 
            + weights.relevance_weight;
        
        assert!((total - 1.0).abs() < 0.01);
    }
    
    #[test]
    fn test_module_history_success_rate() {
        let mut history = ModuleHistory::default();
        
        // Record some runs with findings
        history.record_run(true, 100);
        history.record_run(false, 50);
        history.record_run(true, 75);
        
        assert_eq!(history.total_runs, 3);
        assert_eq!(history.findings_count, 2);
        assert!((history.success_rate - 0.667).abs() < 0.01);
    }
    
    #[test]
    fn test_adjusted_confidence() {
        let mut history = ModuleHistory::default();
        history.total_runs = 10;
        history.false_positives = 2;
        
        let adjusted = history.adjusted_confidence(80);
        
        // Should be reduced due to false positives
        assert!(adjusted < 0.8);
        assert!(adjusted > 0.5);
    }
    
    #[test]
    fn test_priority_scorer_creation() {
        let scorer = PriorityScorer::new();
        assert_eq!(scorer.history.len(), 0);
        
        let custom_weights = PriorityWeights {
            severity_weight: 0.5,
            ..Default::default()
        };
        let scorer = PriorityScorer::with_weights(custom_weights);
        assert!((scorer.weights.severity_weight - 0.5).abs() < 0.001);
    }
}
