//! Check Scheduler
//! 
//! Async scheduler that assigns vulnerability checks to swarm agents
//! based on route and parameter context from the surface map.

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::checks::{
    VulnerabilityModule,
    CheckContext,
    CheckAssignment,
    CheckResult,
    ModuleRegistry,
    ResourceBudget,
};
use crate::orchestrator::graph::DependencyGraph;
use crate::orchestrator::priority::PriorityScorer;

/// Scheduler configuration
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Number of concurrent agents
    pub agent_count: u16,
    /// Enable god-mode for advanced checks
    pub god_mode: bool,
    /// Respect dependency ordering
    pub respect_dependencies: bool,
    /// Use learning-based prioritization
    pub use_learning: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            agent_count: 100,
            god_mode: false,
            respect_dependencies: true,
            use_learning: true,
        }
    }
}

/// Task representing a scheduled check
#[derive(Clone)]
pub struct ScheduledTask {
    pub module_id: usize,
    pub priority: u32,
    pub assigned_agent: Option<u16>,
    pub status: TaskStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running(u16), // agent_id
    Completed,
    Failed(String),
    Skipped(String),
}

/// Main scheduler for orchestrating vulnerability checks
pub struct CheckScheduler {
    config: SchedulerConfig,
    registry: Arc<RwLock<ModuleRegistry>>,
    dependency_graph: DependencyGraph,
    priority_scorer: PriorityScorer,
    task_queue: RwLock<Vec<ScheduledTask>>,
    active_agents: RwLock<Vec<u16>>,
    result_tx: mpsc::Sender<(usize, CheckResult)>,
    result_rx: mpsc::Receiver<(usize, CheckResult)>,
}

impl CheckScheduler {
    /// Create a new scheduler with the given configuration
    pub fn new(
        config: SchedulerConfig,
        registry: Arc<RwLock<ModuleRegistry>>,
    ) -> Self {
        let (result_tx, result_rx) = mpsc::channel(1000);
        
        Self {
            config,
            registry,
            dependency_graph: DependencyGraph::new(),
            priority_scorer: PriorityScorer::new(),
            task_queue: RwLock::new(Vec::new()),
            active_agents: RwLock::new(Vec::new()),
            result_tx,
            result_rx,
        }
    }
    
    /// Build the dependency graph from registered modules
    pub async fn build_dependency_graph(&mut self) {
        let reg = self.registry.read().await;
        self.dependency_graph.build_from_modules(&*reg);
    }
    
    /// Schedule all checks for execution
    pub async fn schedule_all(&self, ctx: CheckContext) -> Vec<ScheduledTask> {
        let reg = self.registry.read().await;
        let mut tasks = Vec::with_capacity(reg.len());
        
        for (module_id, module) in reg.get_prioritized().iter().enumerate() {
            // Check if module should run
            if !module.should_run(&ctx) {
                continue;
            }
            
            // Calculate priority score
            let priority = if self.config.use_learning {
                self.priority_scorer.calculate_priority(module.as_ref(), &ctx)
            } else {
                module.priority() as u32
            };
            
            tasks.push(ScheduledTask {
                module_id,
                priority,
                assigned_agent: None,
                status: TaskStatus::Pending,
            });
        }
        
        // Sort by priority (lower = higher priority)
        tasks.sort_by_key(|t| t.priority);
        
        // Apply dependency ordering if enabled
        if self.config.respect_dependencies {
            tasks = self.dependency_graph.topological_sort(tasks);
        }
        
        *self.task_queue.write().await = tasks.clone();
        tasks
    }
    
    /// Get next available agent ID
    pub async fn get_available_agent(&self) -> Option<u16> {
        let active = self.active_agents.read().await;
        let available: Vec<u16> = (0..self.config.agent_count)
            .filter(|id| !active.contains(id))
            .collect();
        available.first().copied()
    }
    
    /// Assign a task to an agent
    pub async fn assign_task(&self, task_idx: usize, agent_id: u16) -> Option<CheckAssignment> {
        let mut queue = self.task_queue.write().await;
        let task = queue.get_mut(task_idx)?;
        
        if task.status != TaskStatus::Pending {
            return None;
        }
        
        task.status = TaskStatus::Running(agent_id);
        
        // Mark agent as active
        {
            let mut active = self.active_agents.write().await;
            active.push(agent_id);
        }
        
        debug!("Assigned task {} to agent {}", task.module_id, agent_id);
        
        Some(CheckAssignment {
            module_id: task.module_id,
            agent_id,
            context: CheckContext {
                agent_id,
                ..task.clone().into() // Would need proper context passing
            },
            response_tx: self.result_tx.clone(),
        })
    }
    
    /// Mark a task as completed
    pub async fn complete_task(&self, task_idx: usize, agent_id: u16) {
        if let Some(task) = self.task_queue.write().await.get_mut(task_idx) {
            task.status = TaskStatus::Completed;
        }
        
        // Free the agent
        let mut active = self.active_agents.write().await;
        if let Some(pos) = active.iter().position(|&id| id == agent_id) {
            active.remove(pos);
        }
    }
    
    /// Mark a task as failed
    pub async fn fail_task(&self, task_idx: usize, agent_id: u16, error: String) {
        if let Some(task) = self.task_queue.write().await.get_mut(task_idx) {
            task.status = TaskStatus::Failed(error);
        }
        self.complete_task(task_idx, agent_id).await;
    }
    
    /// Get pending tasks count
    pub async fn pending_count(&self) -> usize {
        let queue = self.task_queue.read().await;
        queue.iter().filter(|t| t.status == TaskStatus::Pending).count()
    }
    
    /// Get running tasks count
    pub async fn running_count(&self) -> usize {
        let queue = self.task_queue.read().await;
        queue.iter().filter(|t| matches!(t.status, TaskStatus::Running(_))).count()
    }
    
    /// Get completed tasks count
    pub async fn completed_count(&self) -> usize {
        let queue = self.task_queue.read().await;
        queue.iter().filter(|t| t.status == TaskStatus::Completed).count()
    }
    
    /// Check if all tasks are done
    pub async fn is_complete(&self) -> bool {
        let queue = self.task_queue.read().await;
        queue.iter().all(|t| {
            matches!(
                t.status,
                TaskStatus::Completed | TaskStatus::Failed(_) | TaskStatus::Skipped(_)
            )
        })
    }
    
    /// Receive results from completed checks
    pub async fn recv_result(&mut self) -> Option<(usize, CheckResult)> {
        self.result_rx.recv().await
    }
    
    /// Try to receive a result without waiting
    pub fn try_recv_result(&mut self) -> Option<(usize, CheckResult)> {
        self.result_rx.try_recv().ok()
    }
}

/// Builder for creating schedulers with custom configuration
pub struct SchedulerBuilder {
    config: SchedulerConfig,
}

impl SchedulerBuilder {
    pub fn new() -> Self {
        Self {
            config: SchedulerConfig::default(),
        }
    }
    
    pub fn with_agent_count(mut self, count: u16) -> Self {
        self.config.agent_count = count;
        self
    }
    
    pub fn with_god_mode(mut self, enabled: bool) -> Self {
        self.config.god_mode = enabled;
        self
    }
    
    pub fn with_dependencies(mut self, enabled: bool) -> Self {
        self.config.respect_dependencies = enabled;
        self
    }
    
    pub fn with_learning(mut self, enabled: bool) -> Self {
        self.config.use_learning = enabled;
        self
    }
    
    pub fn build(self, registry: Arc<RwLock<ModuleRegistry>>) -> CheckScheduler {
        CheckScheduler::new(self.config, registry)
    }
}

impl Default for SchedulerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_scheduler_creation() {
        let registry = Arc::new(RwLock::new(ModuleRegistry::new()));
        let scheduler = CheckScheduler::new(SchedulerConfig::default(), registry);
        
        assert_eq!(scheduler.pending_count().await, 0);
        assert_eq!(scheduler.running_count().await, 0);
    }
    
    #[tokio::test]
    async fn test_builder_pattern() {
        let registry = Arc::new(RwLock::new(ModuleRegistry::new()));
        let scheduler = SchedulerBuilder::new()
            .with_agent_count(50)
            .with_god_mode(true)
            .with_dependencies(false)
            .build(registry);
        
        assert_eq!(scheduler.config.agent_count, 50);
        assert!(scheduler.config.god_mode);
        assert!(!scheduler.config.respect_dependencies, "Dependencies disabled");
    }
}
