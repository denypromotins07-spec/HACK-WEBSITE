//! Dependency Graph for Vulnerability Checks
//! 
//! Implements a dependency graph for sequential checks such as auth,
//! SSRF, and second-order flaws. Ensures proper execution ordering.

use std::collections::{HashMap, HashSet, VecDeque};
use crate::checks::{ModuleRegistry, VulnerabilityModule};

/// Node in the dependency graph
#[derive(Debug, Clone)]
struct GraphNode {
    module_id: usize,
    dependencies: Vec<usize>,
    dependents: Vec<usize>,
    in_degree: usize,
}

/// Dependency graph for ordering vulnerability checks
pub struct DependencyGraph {
    nodes: HashMap<usize, GraphNode>,
    adjacency: HashMap<usize, Vec<usize>>,
    reverse_adjacency: HashMap<usize, Vec<usize>>,
}

impl DependencyGraph {
    /// Create a new empty dependency graph
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            adjacency: HashMap::new(),
            reverse_adjacency: HashMap::new(),
        }
    }
    
    /// Build the graph from registered modules
    pub fn build_from_modules(&mut self, registry: &ModuleRegistry) {
        // First pass: create all nodes
        for (id, module) in registry.get_prioritized().iter().enumerate() {
            let deps: Vec<usize> = module
                .dependencies()
                .iter()
                .filter_map(|dep_name| {
                    // Find module by name/ID
                    self.find_module_by_id(registry, dep_name)
                })
                .collect();
            
            let node = GraphNode {
                module_id: id,
                dependencies: deps.clone(),
                dependents: Vec::new(),
                in_degree: deps.len(),
            };
            
            self.nodes.insert(id, node);
            self.adjacency.insert(id, Vec::new());
            self.reverse_adjacency.insert(id, Vec::new());
        }
        
        // Second pass: build edges
        for (&id, node) in &self.nodes {
            for &dep_id in &node.dependencies {
                if let Some(dep_node) = self.nodes.get_mut(&dep_id) {
                    dep_node.dependents.push(id);
                }
                if let Some(adj) = self.adjacency.get_mut(&dep_id) {
                    adj.push(id);
                }
                if let Some(rev) = self.reverse_adjacency.get_mut(&id) {
                    rev.push(dep_id);
                }
            }
        }
    }
    
    /// Find module ID by string identifier
    fn find_module_by_id(&self, registry: &ModuleRegistry, id_str: &str) -> Option<usize> {
        // This would need access to module IDs - simplified for now
        // In production, this would lookup by CheckId
        None
    }
    
    /// Perform topological sort on tasks
    /// Returns tasks in dependency-respecting order
    pub fn topological_sort<T: Clone>(&self, mut tasks: Vec<T>) -> Vec<T>
    where
        T: HasModuleId,
    {
        // Kahn's algorithm for topological sorting
        let mut in_degree: HashMap<usize, usize> = HashMap::new();
        let mut sorted = Vec::with_capacity(tasks.len());
        let mut queue = VecDeque::new();
        
        // Calculate in-degrees
        for task in &tasks {
            let module_id = task.module_id();
            let deps_count = self
                .nodes
                .get(&module_id)
                .map(|n| n.dependencies.len())
                .unwrap_or(0);
            in_degree.insert(module_id, deps_count);
            
            if deps_count == 0 {
                queue.push_back(module_id);
            }
        }
        
        // Create lookup for quick task access
        let task_map: HashMap<usize, Vec<T>> = {
            let mut map: HashMap<usize, Vec<T>> = HashMap::new();
            for task in &tasks {
                map.entry(task.module_id())
                    .or_default()
                    .push(task.clone());
            }
            map
        };
        
        while let Some(module_id) = queue.pop_front() {
            if let Some(task_list) = task_map.get(&module_id) {
                for task in task_list {
                    sorted.push(task.clone());
                }
            }
            
            if let Some(adjacent) = self.adjacency.get(&module_id) {
                for &next_id in adjacent {
                    if let Some(degree) = in_degree.get_mut(&next_id) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(next_id);
                        }
                    }
                }
            }
        }
        
        // Add any remaining tasks (cycles or no dependencies)
        for task in tasks {
            if !sorted.iter().any(|t: &T| t.module_id() == task.module_id()) {
                sorted.push(task);
            }
        }
        
        sorted
    }
    
    /// Check if a module has unsatisfied dependencies
    pub fn has_unmet_dependencies(&self, module_id: usize, completed: &HashSet<usize>) -> bool {
        self.nodes
            .get(&module_id)
            .map(|node| node.dependencies.iter().any(|d| !completed.contains(d)))
            .unwrap_or(false)
    }
    
    /// Get modules that depend on the given module
    pub fn get_dependents(&self, module_id: usize) -> Vec<usize> {
        self.nodes
            .get(&module_id)
            .map(|node| node.dependents.clone())
            .unwrap_or_default()
    }
    
    /// Get modules that the given module depends on
    pub fn get_dependencies(&self, module_id: usize) -> Vec<usize> {
        self.nodes
            .get(&module_id)
            .map(|node| node.dependencies.clone())
            .unwrap_or_default()
    }
    
    /// Detect cycles in the dependency graph
    pub fn has_cycles(&self) -> bool {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        
        for &node_id in self.nodes.keys() {
            if !visited.contains(&node_id) {
                if self.dfs_cycle_check(node_id, &mut visited, &mut rec_stack) {
                    return true;
                }
            }
        }
        
        false
    }
    
    fn dfs_cycle_check(
        &self,
        node_id: usize,
        visited: &mut HashSet<usize>,
        rec_stack: &mut HashSet<usize>,
    ) -> bool {
        visited.insert(node_id);
        rec_stack.insert(node_id);
        
        if let Some(adjacent) = self.adjacency.get(&node_id) {
            for &next_id in adjacent {
                if !visited.contains(&next_id) {
                    if self.dfs_cycle_check(next_id, visited, rec_stack) {
                        return true;
                    }
                } else if rec_stack.contains(&next_id) {
                    return true;
                }
            }
        }
        
        rec_stack.remove(&node_id);
        false
    }
    
    /// Get execution layers (modules that can run in parallel)
    pub fn get_execution_layers(&self) -> Vec<Vec<usize>> {
        let mut layers = Vec::new();
        let mut completed = HashSet::new();
        let mut remaining: HashSet<usize> = self.nodes.keys().copied().collect();
        
        while !remaining.is_empty() {
            let mut layer = Vec::new();
            
            for &module_id in &remaining {
                if !self.has_unmet_dependencies(module_id, &completed) {
                    layer.push(module_id);
                }
            }
            
            if layer.is_empty() {
                // Cycle detected or error
                break;
            }
            
            for &id in &layer {
                completed.insert(id);
                remaining.remove(&id);
            }
            
            layers.push(layer);
        }
        
        layers
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for types that have a module ID
pub trait HasModuleId {
    fn module_id(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_empty_graph() {
        let graph = DependencyGraph::new();
        assert!(!graph.has_cycles());
        assert!(graph.get_execution_layers().is_empty());
    }
    
    #[test]
    fn test_topological_sort_interface() {
        // Test that the interface works correctly
        let graph = DependencyGraph::new();
        let tasks: Vec<MockTask> = vec![
            MockTask { id: 0 },
            MockTask { id: 1 },
            MockTask { id: 2 },
        ];
        let sorted = graph.topological_sort(tasks);
        assert_eq!(sorted.len(), 3);
    }
    
    #[derive(Clone)]
    struct MockTask {
        id: usize,
    }
    
    impl HasModuleId for MockTask {
        fn module_id(&self) -> usize {
            self.id
        }
    }
}
