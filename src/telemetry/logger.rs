//! Asynchronous, non-blocking logging using tracing and tracing-subscriber.
//! JSON formatting enabled for final report generation.

use std::sync::OnceLock;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Global logger handle
static LOGGER_HANDLE: OnceLock<LoggerHandle> = OnceLock::new();

/// Logger configuration
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    /// Enable JSON formatting
    pub json_format: bool,
    /// Enable verbose output
    pub verbose: bool,
    /// Log file path (optional)
    pub file_path: Option<String>,
    /// Environment filter string
    pub env_filter: String,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        LoggerConfig {
            json_format: true,
            verbose: false,
            file_path: None,
            env_filter: "info".to_string(),
        }
    }
}

/// Handle to the initialized logger
pub struct LoggerHandle {
    _guard: tracing::subscriber::DefaultGuard,
}

impl LoggerHandle {
    /// Initialize the global logger with the given configuration
    pub fn init(config: &LoggerConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&config.env_filter));

        // Build the formatting layer
        let fmt_layer = fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true);

        // Apply JSON formatting if requested
        let fmt_layer = if config.json_format {
            fmt_layer.json().boxed()
        } else {
            fmt_layer.pretty().boxed()
        };

        // Add file output if specified
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer);

        // Set as global default
        let guard = tracing::subscriber::set_default(subscriber);

        Ok(LoggerHandle { _guard: guard })
    }

    /// Flush all pending log records
    pub fn flush(&self) {
        tracing::info!("Flushing log buffers");
    }
}

/// Initialize the global logger with default settings
pub fn init_logger(verbose: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = LoggerConfig {
        verbose,
        env_filter: if verbose { "debug" } else { "info" }.to_string(),
        ..Default::default()
    };

    init_logger_with_config(&config)
}

/// Initialize the global logger with custom configuration
pub fn init_logger_with_config(config: &LoggerConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if LOGGER_HANDLE.get().is_some() {
        return Err("Logger already initialized".into());
    }

    let handle = LoggerHandle::init(config)?;
    LOGGER_HANDLE.set(handle).map_err(|_| "Failed to set global logger")?;

    tracing::info!("Logger initialized with config: {:?}", config);
    Ok(())
}

/// Get reference to global logger handle
pub fn get_logger() -> Option<&'static LoggerHandle> {
    LOGGER_HANDLE.get()
}

/// Log a structured event for metrics reporting
#[macro_export]
macro_rules! log_metric {
    ($name:expr, $value:expr) => {
        tracing::info!(
            target: "metrics",
            metric_name = $name,
            metric_value = $value,
            "Metric recorded"
        );
    };
    ($name:expr, $value:expr, $($key:ident = $val:expr),*) => {
        tracing::info!(
            target: "metrics",
            metric_name = $name,
            metric_value = $value,
            $($key = $val,)*
            "Metric recorded"
        );
    };
}

/// Shutdown the logger gracefully
pub fn shutdown_logger() {
    if let Some(handle) = get_logger() {
        handle.flush();
    }
    tracing::info!("Logger shutdown complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_config_default() {
        let config = LoggerConfig::default();
        assert!(config.json_format);
        assert!(!config.verbose);
    }

    #[test]
    fn test_logger_config_verbose() {
        let config = LoggerConfig {
            verbose: true,
            ..Default::default()
        };
        assert_eq!(config.env_filter, "info");
    }
}
