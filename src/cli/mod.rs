//! CLI module for argument parsing and configuration.

pub mod args;
pub mod config;

pub use args::{Args, Commands, OutputFormat};
pub use config::{ConfigBuilder, ConfigError, SharedConfig};
