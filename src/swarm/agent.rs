//! Core Agent struct with internal state machine and bounded MPSC channels.
//! Handles inter-agent communication and task distribution.

use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use crate::memory::{PooledBuffer, BufferPool};
use crate::cli::config::SharedConfig;

/// Maximum channel capacity for bounded MPSC (prevents memory explosion)
const CHANNEL_CAPACITY: usize = 1024;

/// Agent unique identifier
pub type AgentId = u64;

/// Task types an agent can execute
#[derive(Debug, Clone)]
pub enum AgentTask {
    /// HTTP request task
    Request {
        url: String,
        method: String,
        response_tx: oneshot::Sender<TaskResult>,
    },
    /// Health check task
    HealthCheck {
        response_tx: oneshot::Sender<AgentHealth>,
    },
    /// Shutdown signal
    Shutdown,
}

/// Result of task execution
#[derive(Debug, Clone)]
pub enum TaskResult {
    Success { status: u16, bytes: Vec<u8> },
    Error { code: u16, message: String },
    Timeout,
}

/// Agent health status
#[derive(Debug, Clone, PartialEq)]
pub enum AgentHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Internal agent state machine
#[derive(Debug, Clone, PartialEq)]
pub enum AgentState {
    /// Agent is idle, waiting for tasks
    Idle,
    /// Agent is processing a task
    Processing,
    /// Agent encountered an error
    Error(String),
    /// Agent is shutting down
    ShuttingDown,
    /// Agent has stopped
    Stopped,
}

/// Core Agent struct
pub struct Agent {
    pub id: AgentId,
    pub state: AgentState,
    pub config: Arc<SharedConfig>,
    pub buffer_pool: Arc<BufferPool>,
    task_rx: mpsc::Receiver<AgentTask>,
    shutdown_tx: oneshot::Sender<()>,
}

impl Agent {
    /// Create a new agent with bounded channels
    pub fn new(
        id: AgentId,
        config: Arc<SharedConfig>,
        buffer_pool: Arc<BufferPool>,
    ) -> (Self, mpsc::Sender<AgentTask>, oneshot::Receiver<()>) {
        let (task_tx, task_rx) = mpsc::channel::<AgentTask>(CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let agent = Agent {
            id,
            state: AgentState::Idle,
            config,
            buffer_pool,
            task_rx,
            shutdown_tx,
        };

        (agent, task_tx, shutdown_rx)
    }

    /// Run the agent's main loop
    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Agent {} starting", self.id);

        loop {
            match self.task_rx.recv().await {
                Some(task) => {
                    self.state = AgentState::Processing;
                    
                    match task {
                        AgentTask::Request { url, method, response_tx } => {
                            let result = self.execute_request(&url, &method).await;
                            let _ = response_tx.send(result);
                        }
                        AgentTask::HealthCheck { response_tx } => {
                            let health = self.check_health();
                            let _ = response_tx.send(health);
                        }
                        AgentTask::Shutdown => {
                            tracing::info!("Agent {} received shutdown signal", self.id);
                            self.state = AgentState::ShuttingDown;
                            break;
                        }
                    }

                    self.state = AgentState::Idle;
                }
                None => {
                    // Channel closed, shutdown
                    tracing::warn!("Agent {} task channel closed", self.id);
                    break;
                }
            }
        }

        self.state = AgentState::Stopped;
        let _ = self.shutdown_tx.send(());
        tracing::info!("Agent {} stopped", self.id);

        Ok(())
    }

    /// Execute an HTTP request using pooled resources
    async fn execute_request(&self, url: &str, method: &str) -> TaskResult {
        // Check memory pressure before proceeding
        if crate::memory::check_memory_pressure() {
            return TaskResult::Error {
                code: 503,
                message: "Memory pressure too high".to_string(),
            };
        }

        // Acquire pooled buffer for zero-copy operation
        let mut buffer = self.buffer_pool.acquire();

        // In production, this would use reqwest to make the actual request
        // For now, simulate with a delay
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        TaskResult::Success {
            status: 200,
            bytes: buffer.as_ref().to_vec(),
        }
    }

    /// Check agent health
    fn check_health(&self) -> AgentHealth {
        if matches!(self.state, AgentState::Error(_)) {
            AgentHealth::Unhealthy
        } else if crate::memory::check_memory_pressure() {
            AgentHealth::Degraded
        } else {
            AgentHealth::Healthy
        }
    }

    /// Get current agent state
    pub fn state(&self) -> &AgentState {
        &self.state
    }
}

/// Agent builder for fluent construction
pub struct AgentBuilder {
    id: AgentId,
    config: Option<Arc<SharedConfig>>,
    buffer_pool: Option<Arc<BufferPool>>,
}

impl AgentBuilder {
    pub fn new(id: AgentId) -> Self {
        AgentBuilder {
            id,
            config: None,
            buffer_pool: None,
        }
    }

    pub fn config(mut self, config: Arc<SharedConfig>) -> Self {
        self.config = Some(config);
        self
    }

    pub fn buffer_pool(mut self, pool: Arc<BufferPool>) -> Self {
        self.buffer_pool = Some(pool);
        self
    }

    pub fn build(self) -> (Agent, mpsc::Sender<AgentTask>, oneshot::Receiver<()>) {
        let config = self.config.expect("Config required");
        let buffer_pool = self.buffer_pool.expect("Buffer pool required");
        Agent::new(self.id, config, buffer_pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_state_transitions() {
        let mut state = AgentState::Idle;
        state = AgentState::Processing;
        state = AgentState::Idle;
        assert_eq!(state, AgentState::Idle);
    }

    #[test]
    fn test_agent_health_variants() {
        assert_eq!(AgentHealth::Healthy != AgentHealth::Unhealthy, true);
    }
}
