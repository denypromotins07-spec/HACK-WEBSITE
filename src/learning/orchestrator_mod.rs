//! Learning-Driven Orchestrator Module
//! 
//! Wires learning-driven optimization into the orchestrator startup
//! for intelligent, adaptive vulnerability scanning.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, warn};

use crate::learning::check_scores::{CheckScoresStore, TechFingerprint};
use crate::learning::schedule_cache::{ScheduleCache, ScheduleOptimizer};
use crate::orchestrator::priority::PriorityScorer;
use crate::checks::{ModuleRegistry, VulnerabilityModule};

/// Configuration for learning-driven orchestration
#[derive(Debug, Clone)]
pub struct LearningConfig {
    /// Enable learning from scan results
    pub enabled: bool,
    /// Minimum runs before using historical data
    pub min_historical_runs: u64,
    /// Minimum success rate to keep a module enabled
    pub min_success_rate: f64,
    /// Auto-disable noisy modules
    pub auto_disable_noisy: bool,
    /// Number of consecutive failures before disabling
    pub failure_threshold: u32,
    /// Path to persist learning data
    pub persistence_path: Option<String>,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_historical_runs: 5,
            min_success_rate: 0.05, // 5% minimum success rate
            auto_disable_noisy: true,
            failure_threshold: 10,
            persistence_path: None,
        }
    }
}

/// Learning state for the orchestrator
pub struct LearningState {
    /// Check performance scores
    pub scores_store: CheckScoresStore,
    /// Schedule cache
    pub schedule_cache: ScheduleCache,
    /// Priority scorer with history
    pub priority_scorer: PriorityScorer,
    /// Module failure counts
    pub failure_counts: std::collections::HashMap<String, u32>,
    /// Technology fingerprint of current target
    pub current_target_tech: Option<TechFingerprint>,
}

impl LearningState {
    pub fn new() -> Self {
        Self {
            scores_store: CheckScoresStore::new(1000),
            schedule_cache: ScheduleCache::default(),
            priority_scorer: PriorityScorer::new(),
            failure_counts: std::collections::HashMap::new(),
            current_target_tech: None,
        }
    }
    
    pub fn with_config(config: &LearningConfig) -> Self {
        Self {
            scores_store: CheckScoresStore::new(1000),
            schedule_cache: ScheduleCache::new(100, 7 * 24 * 60 * 60),
            priority_scorer: PriorityScorer::new(),
            failure_counts: std::collections::HashMap::new(),
            current_target_tech: None,
        }
    }
}

impl Default for LearningState {
    fn default() -> Self {
        Self::new()
    }
}

/// Learning-driven orchestrator wrapper
pub struct LearningOrchestrator {
    config: LearningConfig,
    state: Arc<RwLock<LearningState>>,
    registry: Arc<RwLock<ModuleRegistry>>,
}

impl LearningOrchestrator {
    /// Create a new learning orchestrator
    pub fn new(
        config: LearningConfig,
        registry: Arc<RwLock<ModuleRegistry>>,
    ) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(LearningState::with_config(&config))),
            registry,
        }
    }
    
    /// Initialize the orchestrator (called at scanner startup)
    pub async fn initialize(&self) -> Result<(), String> {
        info!("Initializing learning-driven orchestrator");
        
        if !self.config.enabled {
            info!("Learning is disabled, using default behavior");
            return Ok(());
        }
        
        let state = self.state.read().await;
        
        // Load persisted data if available
        if let Some(path) = &self.config.persistence_path {
            // TODO: Load from disk
            debug!("Would load learning data from {}", path);
        }
        
        info!(
            "Learning orchestrator initialized with {} cached schedules",
            state.schedule_cache.get_stats().total_schedules
        );
        
        Ok(())
    }
    
    /// Record scan completion and update learning state
    pub async fn record_scan_complete(
        &self,
        tech: &TechFingerprint,
        findings_count: u32,
        duration_ms: u64,
        module_results: Vec<(&str, bool, u64)>, // (module_id, had_finding, execution_ms)
    ) {
        if !self.config.enabled {
            return;
        }
        
        let mut state = self.state.write().await;
        
        // Update scores for each module
        for (module_id, had_finding, execution_ms) in module_results {
            state.scores_store.record_tech_run(
                module_id,
                tech,
                had_finding,
                *execution_ms,
            );
            
            state.priority_scorer.update_history(
                module_id,
                had_finding,
                *execution_ms,
            );
            
            // Track failures
            if !had_finding {
                let count = state.failure_counts.entry(module_id.to_string()).or_insert(0);
                *count += 1;
                
                // Auto-disable if threshold reached
                if self.config.auto_disable_noisy && *count >= self.config.failure_threshold {
                    state.schedule_cache.mark_module_noisy(tech, module_id);
                    warn!(
                        "Module {} marked as noisy after {} consecutive failures",
                        module_id, count
                    );
                }
            } else {
                // Reset failure count on success
                state.failure_counts.remove(module_id);
            }
        }
        
        // Get module order for caching
        let reg = self.registry.read().await;
        let module_ids: Vec<String> = reg.get_prioritized()
            .iter()
            .map(|m| m.metadata().id.as_str().to_string())
            .collect();
        
        // Update schedule cache
        state.schedule_cache.update_schedule(
            tech,
            findings_count,
            duration_ms,
            module_ids,
        );
        
        debug!(
            "Recorded scan results: {} findings in {}ms",
            findings_count, duration_ms
        );
    }
    
    /// Get optimized module order for a target
    pub async fn get_optimized_order(&self, tech: &TechFingerprint) -> Vec<String> {
        if !self.config.enabled {
            // Return all modules in default order
            let reg = self.registry.read().await;
            return reg.get_prioritized()
                .iter()
                .map(|m| m.metadata().id.as_str().to_string())
                .collect();
        }
        
        let state = self.state.read().await;
        
        // Get all module IDs
        let reg = self.registry.read().await;
        let all_modules: Vec<String> = reg.get_prioritized()
            .iter()
            .map(|m| m.metadata().id.as_str().to_string())
            .collect();
        
        // Use optimizer
        let optimizer = ScheduleOptimizer::new(state.scores_store.clone())
            .with_min_success_rate(self.config.min_success_rate);
        
        optimizer.optimize(&all_modules, Some(tech))
    }
    
    /// Check if a module should be skipped
    pub async fn should_skip_module(&self, tech: &TechFingerprint, module_id: &str) -> bool {
        if !self.config.enabled {
            return false;
        }
        
        let state = self.state.read().await;
        
        // Check cache first
        if state.schedule_cache.should_skip_module(tech, module_id) {
            return true;
        }
        
        // Check historical performance
        if let Some(perf) = state.scores_store.get_for_tech(module_id, tech) {
            if perf.total_runs >= self.config.min_historical_runs
                && perf.success_rate < self.config.min_success_rate
            {
                debug!(
                    "Skipping module {} due to low success rate ({:.2})",
                    module_id, perf.success_rate
                );
                return true;
            }
        }
        
        false
    }
    
    /// Set current target technology
    pub async fn set_target_tech(&self, tech: TechFingerprint) {
        let mut state = self.state.write().await;
        state.current_target_tech = Some(tech);
    }
    
    /// Get current target technology
    pub async fn get_target_tech(&self) -> Option<TechFingerprint> {
        let state = self.state.read().await;
        state.current_target_tech.clone()
    }
    
    /// Persist learning data to disk
    pub async fn persist(&self) -> Result<(), String> {
        if let Some(path) = &self.config.persistence_path {
            let state = self.state.read().await;
            
            // Export data
            let scores_export = state.scores_store.export();
            let schedule_export = state.schedule_cache.export();
            
            // TODO: Serialize and write to disk
            debug!("Would persist learning data to {}", path);
            
            Ok(())
        } else {
            Err("No persistence path configured".to_string())
        }
    }
    
    /// Get learning statistics
    pub async fn get_stats(&self) -> LearningStats {
        let state = self.state.read().await;
        
        LearningStats {
            total_modules_tracked: state.scores_store.get_modules_by_performance().len(),
            cached_schedules: state.schedule_cache.get_stats().total_schedules,
            globally_disabled: state.schedule_cache.get_stats().globally_disabled_count,
            avg_effectiveness: state.schedule_cache.get_stats().avg_effectiveness,
        }
    }
}

/// Learning statistics
#[derive(Debug, Clone, Default)]
pub struct LearningStats {
    pub total_modules_tracked: usize,
    pub cached_schedules: usize,
    pub globally_disabled: usize,
    pub avg_effectiveness: f64,
}

/// Builder for LearningOrchestrator
pub struct LearningOrchestratorBuilder {
    config: LearningConfig,
}

impl LearningOrchestratorBuilder {
    pub fn new() -> Self {
        Self {
            config: LearningConfig::default(),
        }
    }
    
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }
    
    pub fn with_min_success_rate(mut self, rate: f64) -> Self {
        self.config.min_success_rate = rate;
        self
    }
    
    pub fn with_auto_disable(mut self, auto_disable: bool) -> Self {
        self.config.auto_disable_noisy = auto_disable;
        self
    }
    
    pub fn with_persistence(mut self, path: impl Into<String>) -> Self {
        self.config.persistence_path = Some(path.into());
        self
    }
    
    pub fn build(self, registry: Arc<RwLock<ModuleRegistry>>) -> LearningOrchestrator {
        LearningOrchestrator::new(self.config, registry)
    }
}

impl Default for LearningOrchestratorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_learning_orchestrator_creation() {
        let registry = Arc::new(RwLock::new(ModuleRegistry::new()));
        let orchestrator = LearningOrchestrator::new(
            LearningConfig::default(),
            registry,
        );
        
        assert!(orchestrator.initialize().await.is_ok());
        
        let stats = orchestrator.get_stats().await;
        assert_eq!(stats.cached_schedules, 0);
    }
    
    #[tokio::test]
    async fn test_builder_pattern() {
        let registry = Arc::new(RwLock::new(ModuleRegistry::new()));
        let orchestrator = LearningOrchestratorBuilder::new()
            .with_enabled(true)
            .with_min_success_rate(0.1)
            .with_auto_disable(true)
            .with_persistence("/tmp/learning.json")
            .build(registry);
        
        assert!(orchestrator.config.enabled);
        assert!((orchestrator.config.min_success_rate - 0.1).abs() < 0.001);
    }
}
