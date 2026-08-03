//! Global read-only configuration struct populated from CLI.
//! Utilizes Arc for safe, zero-copy sharing across the swarm.

use std::sync::Arc;
use crate::cli::args::{Args, OutputFormat};

/// Shared configuration accessible by all agents
#[derive(Debug, Clone)]
pub struct SharedConfig {
    /// Target URL for operations
    pub target: Option<Arc<str>>,
    
    /// God mode enabled (unrestricted operations)
    pub god_mode: bool,
    
    /// Number of concurrent agents
    pub agent_count: u32,
    
    /// Maximum requests per second
    pub rate_limit: u32,
    
    /// Request timeout in seconds
    pub timeout_secs: u64,
    
    /// Verbose logging enabled
    pub verbose: bool,
    
    /// Output format
    pub output_format: OutputFormat,
    
    /// Memory limit in bytes (2GB hard ceiling)
    pub memory_limit_bytes: usize,
    
    /// Build timestamp for this config
    pub created_at: std::time::Instant,
}

impl SharedConfig {
    /// Create configuration from CLI arguments
    pub fn from_args(args: &Args) -> Self {
        SharedConfig {
            target: args.target.as_ref().map(|s| s.as_str().into()),
            god_mode: args.god_mode,
            agent_count: args.agents,
            rate_limit: args.rate_limit,
            timeout_secs: args.timeout,
            verbose: args.verbose,
            output_format: args.output_format,
            memory_limit_bytes: 2 * 1024 * 1024 * 1024, // 2GB hard limit
            created_at: std::time::Instant::now(),
        }
    }

    /// Create configuration with custom values
    pub fn new(
        target: Option<String>,
        god_mode: bool,
        agent_count: u32,
        rate_limit: u32,
        timeout_secs: u64,
    ) -> Self {
        SharedConfig {
            target: target.map(|s| s.into()),
            god_mode,
            agent_count,
            rate_limit,
            timeout_secs,
            verbose: false,
            output_format: OutputFormat::Json,
            memory_limit_bytes: 2 * 1024 * 1024 * 1024,
            created_at: std::time::Instant::now(),
        }
    }

    /// Check if a target is configured
    pub fn has_target(&self) -> bool {
        self.target.is_some()
    }

    /// Get target URL as string slice
    pub fn target_str(&self) -> Option<&str> {
        self.target.as_ref().map(|s| s.as_ref())
    }

    /// Check if god mode is active
    pub fn is_god_mode(&self) -> bool {
        self.god_mode
    }

    /// Get elapsed time since config creation
    pub fn elapsed(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Validate configuration constraints
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.agent_count == 0 {
            return Err(ConfigError::InvalidAgentCount);
        }
        
        if self.agent_count > 1000 {
            return Err(ConfigError::AgentCountTooHigh);
        }

        if self.rate_limit == 0 {
            return Err(ConfigError::InvalidRateLimit);
        }

        if self.timeout_secs == 0 {
            return Err(ConfigError::InvalidTimeout);
        }

        Ok(())
    }
}

/// Configuration errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Agent count must be greater than 0")]
    InvalidAgentCount,
    
    #[error("Agent count cannot exceed 1000")]
    AgentCountTooHigh,
    
    #[error("Rate limit must be greater than 0")]
    InvalidRateLimit,
    
    #[error("Timeout must be greater than 0")]
    InvalidTimeout,
    
    #[error("Invalid target URL: {0}")]
    InvalidTarget(String),
}

/// Builder for SharedConfig with fluent API
pub struct ConfigBuilder {
    target: Option<String>,
    god_mode: bool,
    agent_count: u32,
    rate_limit: u32,
    timeout_secs: u64,
    verbose: bool,
    output_format: OutputFormat,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        ConfigBuilder {
            target: None,
            god_mode: false,
            agent_count: 100,
            rate_limit: 10000,
            timeout_secs: 30,
            verbose: false,
            output_format: OutputFormat::Json,
        }
    }

    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn god_mode(mut self, enabled: bool) -> Self {
        self.god_mode = enabled;
        self
    }

    pub fn agent_count(mut self, count: u32) -> Self {
        self.agent_count = count;
        self
    }

    pub fn rate_limit(mut self, limit: u32) -> Self {
        self.rate_limit = limit;
        self
    }

    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn verbose(mut self, enabled: bool) -> Self {
        self.verbose = enabled;
        self
    }

    pub fn output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }

    pub fn build(self) -> Result<SharedConfig, ConfigError> {
        let config = SharedConfig {
            target: self.target.map(|s| s.into()),
            god_mode: self.god_mode,
            agent_count: self.agent_count,
            rate_limit: self.rate_limit,
            timeout_secs: self.timeout_secs,
            verbose: self.verbose,
            output_format: self.output_format,
            memory_limit_bytes: 2 * 1024 * 1024 * 1024,
            created_at: std::time::Instant::now(),
        };

        config.validate()?;
        Ok(config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_args() {
        let args = Args::parse_from(["swarm-engine", "--target", "https://example.com"]);
        let config = SharedConfig::from_args(&args);
        assert!(config.has_target());
        assert_eq!(config.agent_count, 100);
    }

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new()
            .target("https://example.com")
            .god_mode(true)
            .agent_count(50)
            .build()
            .unwrap();
        
        assert!(config.is_god_mode());
        assert_eq!(config.agent_count, 50);
    }

    #[test]
    fn test_config_validation() {
        let config = ConfigBuilder::new()
            .agent_count(0)
            .build();
        assert!(config.is_err());
    }
}
