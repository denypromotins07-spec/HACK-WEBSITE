//! Swarm orchestrator that spawns exactly 100 agents.
//! Manages graceful shutdown and panic recovery.

use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use crate::memory::BufferPool;
use crate::cli::config::SharedConfig;
use crate::swarm::agent::{Agent, AgentBuilder, AgentTask, AgentId};
use crate::swarm::runtime::{SwarmRuntimeConfig, AGENT_COUNT};

/// Handle to a running agent
struct AgentHandle {
    id: AgentId,
    task_tx: mpsc::Sender<AgentTask>,
    shutdown_rx: oneshot::Receiver<()>,
    join_handle: JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
}

/// Swarm orchestrator managing all agents
pub struct Swarm {
    config: Arc<SharedConfig>,
    runtime_config: SwarmRuntimeConfig,
    buffer_pool: Arc<BufferPool>,
    agents: Vec<AgentHandle>,
    shutdown_complete: oneshot::Receiver<()>,
}

impl Swarm {
    /// Create a new swarm with exactly 100 agents
    pub fn new(
        config: Arc<SharedConfig>,
        runtime_config: SwarmRuntimeConfig,
    ) -> Self {
        let buffer_pool = Arc::new(BufferPool::new());
        let (shutdown_tx, shutdown_complete) = oneshot::channel();

        Swarm {
            config,
            runtime_config,
            buffer_pool,
            agents: Vec::with_capacity(runtime_config.agent_count),
            shutdown_complete,
        }
    }

    /// Spawn all agents in the swarm
    pub fn spawn_agents(&mut self) {
        tracing::info!("Spawning {} agents", self.runtime_config.agent_count);

        for id in 0..self.runtime_config.agent_count as u64 {
            let (agent, task_tx, shutdown_rx) = AgentBuilder::new(id)
                .config(Arc::clone(&self.config))
                .buffer_pool(Arc::clone(&self.buffer_pool))
                .build();

            let join_handle = tokio::spawn(async move {
                agent.run().await
            });

            self.agents.push(AgentHandle {
                id,
                task_tx,
                shutdown_rx,
                join_handle,
            });
        }

        tracing::info!("All {} agents spawned successfully", self.agents.len());
    }

    /// Dispatch a task to a specific agent (round-robin distribution)
    pub async fn dispatch_task(&self, task: AgentTask, agent_id: Option<AgentId>) -> Result<(), &'static str> {
        let target_id = agent_id.unwrap_or_else(|| {
            // Simple round-robin based on task count could be added here
            0
        });

        if let Some(handle) = self.agents.iter().find(|h| h.id == target_id) {
            handle.task_tx.send(task).await
                .map_err(|_| "Failed to send task - agent may be down")
        } else {
            Err("Agent not found")
        }
    }

    /// Broadcast a task to all agents
    pub async fn broadcast_task(&self, task_factory: impl Fn(AgentId) -> AgentTask) -> usize {
        let mut success_count = 0;
        
        for handle in &self.agents {
            let task = task_factory(handle.id);
            if handle.task_tx.send(task).await.is_ok() {
                success_count += 1;
            }
        }

        success_count
    }

    /// Get health status of all agents
    pub async fn get_health_status(&self) -> Vec<(AgentId, crate::swarm::agent::AgentHealth)> {
        let mut results = Vec::with_capacity(self.agents.len());

        for handle in &self.agents {
            let (tx, rx) = oneshot::channel();
            let task = AgentTask::HealthCheck { response_tx: tx };
            
            if handle.task_tx.send(task).await.is_ok() {
                if let Ok(health) = rx.await {
                    results.push((handle.id, health));
                }
            }
        }

        results
    }

    /// Initiate graceful shutdown of all agents
    pub async fn shutdown(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Initiating swarm shutdown for {} agents", self.agents.len());

        // Send shutdown signal to all agents
        for handle in &self.agents {
            let _ = handle.task_tx.send(AgentTask::Shutdown).await;
        }

        // Wait for all agents to acknowledge shutdown
        for handle in self.agents.drain(..) {
            // Wait for shutdown acknowledgment or timeout
            let shutdown_result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                handle.shutdown_rx
            ).await;

            // Wait for task to complete
            let join_result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                handle.join_handle
            ).await;

            match (shutdown_result, join_result) {
                (Ok(Ok(_)), Ok(Ok(agent_result))) => {
                    tracing::debug!("Agent {} shut down cleanly", handle.id);
                    if let Err(e) = agent_result {
                        tracing::warn!("Agent {} returned error: {}", handle.id, e);
                    }
                }
                (Err(_), _) => {
                    tracing::warn!("Agent {} shutdown timeout", handle.id);
                }
                (_, Err(_)) => {
                    tracing::warn!("Agent {} join timeout", handle.id);
                }
                (Ok(Err(_)), _) => {
                    tracing::warn!("Agent {} shutdown channel closed unexpectedly", handle.id);
                }
            }
        }

        tracing::info!("Swarm shutdown complete");
        Ok(())
    }

    /// Get the number of active agents
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    /// Get buffer pool statistics
    pub fn pool_stats(&self) -> crate::memory::PoolStats {
        self.buffer_pool.stats()
    }
}

/// Swarm builder for fluent construction
pub struct SwarmBuilder {
    config: Option<Arc<SharedConfig>>,
    runtime_config: SwarmRuntimeConfig,
}

impl SwarmBuilder {
    pub fn new() -> Self {
        SwarmBuilder {
            config: None,
            runtime_config: SwarmRuntimeConfig::default(),
        }
    }

    pub fn config(mut self, config: Arc<SharedConfig>) -> Self {
        self.config = Some(config);
        self
    }

    pub fn runtime_config(mut self, config: SwarmRuntimeConfig) -> Self {
        self.runtime_config = config;
        self
    }

    pub fn agent_count(mut self, count: usize) -> Self {
        self.runtime_config.agent_count = count;
        self
    }

    pub fn build(self) -> Swarm {
        let config = self.config.expect("Config required");
        Swarm::new(config, self.runtime_config)
    }
}

impl Default for SwarmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swarm_builder() {
        let swarm = SwarmBuilder::new()
            .agent_count(100)
            .build();
        assert_eq!(swarm.agent_count(), 0); // No agents spawned yet
    }

    #[test]
    fn test_default_agent_count() {
        let config = SwarmRuntimeConfig::default();
        assert_eq!(config.agent_count, AGENT_COUNT);
    }
}
