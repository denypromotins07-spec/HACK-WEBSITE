//! Vulnerability Module Framework
//! 
//! Defines the core trait for vulnerability modules with init, run, analyze,
//! and remediation hooks. Enables lock-free module registration and execution.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::checks::metadata::{CheckMetadata, CheckCategory, Severity};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;

/// Result of a vulnerability check execution
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub findings: Vec<Finding>,
    pub executed: bool,
    pub timed_out: bool,
    pub resource_usage: ResourceUsage,
}

/// Resource usage metrics for a check execution
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    pub cpu_ms: u64,
    pub memory_bytes: u64,
    pub request_count: u32,
    pub duration_ms: u64,
}

/// Context passed to vulnerability modules during execution
#[derive(Clone)]
pub struct CheckContext {
    pub target_url: String,
    pub surface_map: Arc<crate::surface::SurfaceMap>,
    pub payloads: Arc<crate::payloads::PayloadRegistry>,
    pub analysis_cache: Arc<crate::analysis::AnalysisCache>,
    pub budget: ResourceBudget,
    pub god_mode: bool,
    pub agent_id: u16,
}

/// Core trait for all vulnerability modules
/// 
/// Modules must be lightweight, lock-free, and respect resource spm://resource budgets.
/// Safe checks run first; advanced checks require god-mode authorization.
#[async_trait]
pub trait VulnerabilityModule: Send + Sync {
    /// Initialize the module with configuration and dependencies
    /// Called once at scanner startup or when module is first loaded
    async fn init(&mut self) -> Result<(), ModuleError>;
    
    /// Return static metadata about this check
    fn metadata(&self) -> &CheckMetadata;
    
    /// Determine if this check should run given current context
    /// Used for dependency-based scheduling and technology filtering
    fn should_run(&self, ctx: &CheckContext) -> bool;
    
    /// Execute the vulnerability check
    /// Must complete within budget timeout and respect resource 限额
    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError>;
    
    /// Analyze raw results and normalize findings
    /// Can be overridden for custom analysis logic
    async fn analyze(&self, result: CheckResult, ctx: &CheckContext) -> Result<CheckResult, ModuleError> {
        Ok(result)
    }
    
    /// Generate remediation hints for discovered vulnerabilities
    /// Returns human-readable guidance for fixing identified issues
    fn remediation_hints(&self, finding: &Finding) -> Option<String> {
        None
    }
    
    /// Get module priority (lower = higher priority)
    /// Safe checks should return lower values than advanced checks
    fn priority(&self) -> u16 {
        100
    }
    
    /// List of module IDs this check depends on
    /// Dependencies must complete before this check runs
    fn dependencies(&self) -> &[&str] {
        &[]
    }
}

/// Error types for vulnerability module operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum ModuleError {
    #[error("Initialization failed: {0}")]
    InitFailed(String),
    
    #[error("Execution timeout after {0}ms")]
    Timeout(u64),
    
    #[error("Resource budget exceeded: {0}")]
    BudgetExceeded(String),
    
    #[error("Dependency not satisfied: {0}")]
    DependencyNotMet(String),
    
    #[error("Invalid payload: {0}")]
    InvalidPayload(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Analysis error: {0}")]
    AnalysisError(String),
    
    #[error("Module panic: {0}")]
    Panic(String),
}

/// Registry for managing vulnerability modules
pub struct ModuleRegistry {
    modules: Vec<Arc<dyn VulnerabilityModule>>,
    by_category: std::collections::HashMap<CheckCategory, Vec<usize>>,
    by_priority: std::collections::BTreeMap<u16, Vec<usize>>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            by_category: std::collections::HashMap::new(),
            by_priority: std::collections::BTreeMap::new(),
        }
    }
    
    /// Register a new vulnerability module
    pub fn register<M: VulnerabilityModule + 'static>(&mut self, module: M) -> usize {
        let id = self.modules.len();
        let arc_module: Arc<dyn VulnerabilityModule> = Arc::new(module);
        
        // Index by category
        let category = arc_module.metadata().category.clone();
        self.by_category.entry(category).or_default().push(id);
        
        // Index by priority
        let priority = arc_module.priority();
        self.by_priority.entry(priority).or_default().push(id);
        
        self.modules.push(arc_module);
        id
    }
    
    /// Get all modules sorted by priority (safe checks first)
    pub fn get_prioritized(&self) -> Vec<&Arc<dyn VulnerabilityModule>> {
        let mut result = Vec::with_capacity(self.modules.len());
        for (_, ids) in self.by_priority.iter() {
            for &id in ids {
                result.push(&self.modules[id]);
            }
        }
        result
    }
    
    /// Get modules by category
    pub fn get_by_category(&self, category: &CheckCategory) -> Vec<&Arc<dyn VulnerabilityModule>> {
        self.by_category
            .get(category)
            .map(|ids| ids.iter().map(|&id| &self.modules[id]).collect())
            .unwrap_or_default()
    }
    
    /// Get module by ID
    pub fn get(&self, id: usize) -> Option<&Arc<dyn VulnerabilityModule>> {
        self.modules.get(id)
    }
    
    /// Total registered modules
    pub fn len(&self) -> usize {
        self.modules.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Channel for sending check assignments to swarm agents
pub type CheckChannel = mpsc::Sender<CheckAssignment>;

/// Assignment sent to a swarm agent for execution
#[derive(Clone)]
pub struct CheckAssignment {
    pub module_id: usize,
    pub agent_id: u16,
    pub context: CheckContext,
    pub response_tx: mpsc::Sender<CheckResult>,
}
