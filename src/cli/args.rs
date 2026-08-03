//! CLI argument definitions using clap.
//! Includes --god-mode and --target flags with strict URL validation.

use clap::{Parser, Subcommand};

/// Swarm Engine - High-performance async agent swarm
#[derive(Parser, Debug)]
#[command(name = "swarm-engine")]
#[command(author = "Swarm Team")]
#[command(version = "0.1.0")]
#[command(about = "High-performance async agent swarm with 2GB memory ceiling", long_about = None)]
pub struct Args {
    /// Target URL to scan/test (must be valid HTTP/HTTPS URL)
    #[arg(short, long, value_parser = validate_url)]
    pub target: Option<String>,

    /// Enable god mode (unrestricted operations)
    #[arg(long, default_value_t = false)]
    pub god_mode: bool,

    /// Number of concurrent agents (default: 100)
    #[arg(short = 'n', long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub agents: u32,

    /// Maximum requests per second
    #[arg(short = 'r', long, default_value_t = 10000)]
    pub rate_limit: u32,

    /// Timeout in seconds for each request
    #[arg(short = 't', long, default_value_t = 30)]
    pub timeout: u64,

    /// Enable verbose logging
    #[arg(short = 'v', long, default_value_t = false)]
    pub verbose: bool,

    /// Output format for results
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Json)]
    pub output_format: OutputFormat,

    /// Optional subcommands
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Output format options
#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// JSON format for machine parsing
    Json,
    /// Human-readable text format
    Text,
    /// CSV format for spreadsheet import
    Csv,
}

/// Additional CLI commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a health check on the swarm
    Health,
    /// Display configuration information
    Config,
    /// Run benchmark tests
    Benchmark {
        /// Duration of benchmark in seconds
        #[arg(short, long, default_value_t = 60)]
        duration: u64,
    },
    /// Shutdown running swarm gracefully
    Shutdown,
}

/// Validate URL format
fn validate_url(url: &str) -> Result<String, String> {
    // Strict URL validation: must start with http:// or https://
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("URL must start with http:// or https://".to_string());
    }

    // Basic URL structure validation
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    // Ensure scheme is http or https
    match parsed.scheme() {
        "http" | "https" => Ok(url.to_string()),
        _ => Err("Only HTTP and HTTPS URLs are supported".to_string()),
    }
}

impl Args {
    /// Check if god mode is enabled
    pub fn is_god_mode(&self) -> bool {
        self.god_mode
    }

    /// Get target URL if provided
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Check if verbose logging is enabled
    pub fn is_verbose(&self) -> bool {
        self.verbose
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_validation_valid() {
        assert!(validate_url("http://example.com").is_ok());
        assert!(validate_url("https://example.com/path?query=1").is_ok());
    }

    #[test]
    fn test_url_validation_invalid() {
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("example.com").is_err());
        assert!(validate_url("not-a-url").is_err());
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["swarm-engine"]);
        assert_eq!(args.agents, 100);
        assert!(!args.god_mode);
    }
}
