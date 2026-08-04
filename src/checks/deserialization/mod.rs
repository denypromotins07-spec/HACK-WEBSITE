//! Deserialization Module Registration
//! Registers deserialization modules with orchestrator and exports metadata.

pub mod java_gadgets;
pub mod java_payloads;
pub mod java_analysis;

pub mod php_object;
pub mod php_magic_methods;
pub mod php_payloads;

pub mod python_pickle;
pub mod python_reduce;
pub mod python_payloads;

pub mod node_serialize;
pub mod node_iife;
pub mod node_payloads;

use crate::findings::deser_evidence::DeserializationEvidence;

/// Metadata for deserialization module
#[derive(Debug, Clone)]
pub struct DeserializationModuleMetadata {
    /// Module name
    pub name: String,
    /// Module description
    pub description: String,
    /// Target framework/language
    pub framework: String,
    /// Version of the module
    pub version: String,
    /// Whether module is enabled
    pub enabled: bool,
    /// Risk level of detections (1-10)
    pub risk_level: u8,
    /// Supported detection methods
    pub detection_methods: Vec<String>,
}

/// Registry for all deserialization modules
#[derive(Debug)]
pub struct DeserializationRegistry {
    /// Registered modules
    modules: Vec<DeserializationModuleMetadata>,
    /// Maximum concurrent probes
    max_probes: usize,
    /// God mode enabled (intrusive validation)
    god_mode: bool,
}

impl DeserializationRegistry {
    /// Create a new registry with default modules
    pub fn new() -> Self {
        let mut registry = Self {
            modules: Vec::new(),
            max_probes: 10,
            god_mode: false,
        };

        // Register all deserialization modules
        registry.register_default_modules();
        registry
    }

    /// Register default deserialization modules
    fn register_default_modules(&mut self) {
        // Java modules
        self.modules.push(DeserializationModuleMetadata {
            name: "java_gadgets".to_string(),
            description: "Java gadget chain detection using harmless serialized markers".to_string(),
            framework: "Java".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 9,
            detection_methods: vec![
                "CommonsCollections".to_string(),
                "JRE8u20".to_string(),
                "BeanShell".to_string(),
            ],
        });

        self.modules.push(DeserializationModuleMetadata {
            name: "java_payloads".to_string(),
            description: "Bounded Java serialized payload builder".to_string(),
            framework: "Java".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 8,
            detection_methods: vec!["payload_generation".to_string()],
        });

        self.modules.push(DeserializationModuleMetadata {
            name: "java_analysis".to_string(),
            description: "Stack trace and timing analysis for Java".to_string(),
            framework: "Java".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 7,
            detection_methods: vec!["stack_trace".to_string(), "timing".to_string(), "oob_callback".to_string()],
        });

        // PHP modules
        self.modules.push(DeserializationModuleMetadata {
            name: "php_object".to_string(),
            description: "PHP unserialize() vulnerability detection".to_string(),
            framework: "PHP".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 8,
            detection_methods: vec!["unserialize_probe".to_string(), "magic_method".to_string()],
        });

        self.modules.push(DeserializationModuleMetadata {
            name: "php_magic_methods".to_string(),
            description: "PHP magic method mapping and POP chains".to_string(),
            framework: "PHP".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 8,
            detection_methods: vec!["wakeup".to_string(), "destruct".to_string(), "toString".to_string()],
        });

        self.modules.push(DeserializationModuleMetadata {
            name: "php_payloads".to_string(),
            description: "PHP serialized payload generator with canaries".to_string(),
            framework: "PHP".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 7,
            detection_methods: vec!["object_graph".to_string(), "canary_tracking".to_string()],
        });

        // Python modules
        self.modules.push(DeserializationModuleMetadata {
            name: "python_pickle".to_string(),
            description: "Python pickle deserialization detection".to_string(),
            framework: "Python".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 9,
            detection_methods: vec!["pickle_probe".to_string(), "opcode_analysis".to_string()],
        });

        self.modules.push(DeserializationModuleMetadata {
            name: "python_reduce".to_string(),
            description: "Python __reduce__ payload builder".to_string(),
            framework: "Python".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 8,
            detection_methods: vec!["reduce_probe".to_string(), "safety_analysis".to_string()],
        });

        self.modules.push(DeserializationModuleMetadata {
            name: "python_payloads".to_string(),
            description: "Versioned pickle payload generator".to_string(),
            framework: "Python".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 7,
            detection_methods: vec!["versioned_payloads".to_string(), "opcode_bounded".to_string()],
        });

        // Node.js modules
        self.modules.push(DeserializationModuleMetadata {
            name: "node_serialize".to_string(),
            description: "Node.js node-serialize vulnerability detection".to_string(),
            framework: "Node.js".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 9,
            detection_methods: vec!["iife_probe".to_string(), "custom_serialization".to_string()],
        });

        self.modules.push(DeserializationModuleMetadata {
            name: "node_iife".to_string(),
            description: "Safe IIFE builder for timing and OOB validation".to_string(),
            framework: "Node.js".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 8,
            detection_methods: vec!["timing_iife".to_string(), "oob_iife".to_string()],
        });

        self.modules.push(DeserializationModuleMetadata {
            name: "node_payloads".to_string(),
            description: "JSON and JS object payload generator".to_string(),
            framework: "Node.js".to_string(),
            version: "1.0.0".to_string(),
            enabled: true,
            risk_level: 7,
            detection_methods: vec!["json_function".to_string(), "proto_pollution".to_string()],
        });
    }

    /// Get all registered modules
    pub fn get_modules(&self) -> &[DeserializationModuleMetadata] {
        &self.modules
    }

    /// Get module by name
    pub fn get_module(&self, name: &str) -> Option<&DeserializationModuleMetadata> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// Enable/disable a module
    pub fn set_module_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(module) = self.modules.iter_mut().find(|m| m.name == name) {
            module.enabled = enabled;
        }
    }

    /// Get all enabled modules
    pub fn get_enabled_modules(&self) -> Vec<&DeserializationModuleMetadata> {
        self.modules.iter().filter(|m| m.enabled).collect()
    }

    /// Get modules by framework
    pub fn get_modules_by_framework(&self, framework: &str) -> Vec<&DeserializationModuleMetadata> {
        self.modules
            .iter()
            .filter(|m| m.framework == framework)
            .collect()
    }

    /// Set maximum concurrent probes
    pub fn with_max_probes(mut self, max: usize) -> Self {
        self.max_probes = max;
        self
    }

    /// Enable god mode (intrusive validation with strict timeouts)
    pub fn enable_god_mode(&mut self) {
        self.god_mode = true;
    }

    /// Disable god mode
    pub fn disable_god_mode(&mut self) {
        self.god_mode = false;
    }

    /// Check if god mode is enabled
    pub fn is_god_mode(&self) -> bool {
        self.god_mode
    }

    /// Export registry metadata as JSON-like string
    pub fn export_metadata(&self) -> String {
        let mut json = String::from("{\n  \"modules\": [\n");
        
        for (i, module) in self.modules.iter().enumerate() {
            json.push_str(&format!(
                "    {{\"name\":\"{}\",\"framework\":\"{}\",\"enabled\":{},\"risk_level\":{}}}",
                module.name,
                module.framework,
                module.enabled,
                module.risk_level
            ));
            
            if i < self.modules.len() - 1 {
                json.push(',');
            }
            json.push('\n');
        }
        
        json.push_str("  ]\n}");
        json
    }

    /// Get total module count
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }
}

impl Default for DeserializationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Orchestrator integration for deserialization checks
pub struct DeserializationOrchestrator {
    /// Module registry
    registry: DeserializationRegistry,
    /// Evidence collector
    evidence: Vec<DeserializationEvidence>,
}

impl DeserializationOrchestrator {
    /// Create a new orchestrator
    pub fn new() -> Self {
        Self {
            registry: DeserializationRegistry::new(),
            evidence: Vec::new(),
        }
    }

    /// Run all enabled deserialization checks
    pub fn run_checks(&mut self, _target: &str) -> Vec<DeserializationEvidence> {
        // In production, this would coordinate with Stage 2 HTTP
        // and Stage 5 mutator to run actual checks
        self.evidence.clone()
    }

    /// Add evidence from a check
    pub fn add_evidence(&mut self, evidence: DeserializationEvidence) {
        self.evidence.push(evidence);
    }

    /// Get the module registry
    pub fn registry(&self) -> &DeserializationRegistry {
        &self.registry
    }
}

impl Default for DeserializationOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = DeserializationRegistry::new();
        assert_eq!(registry.module_count(), 12); // 4 frameworks * 3 modules each
    }

    #[test]
    fn test_get_module() {
        let registry = DeserializationRegistry::new();
        let module = registry.get_module("java_gadgets");
        assert!(module.is_some());
        assert_eq!(module.unwrap().framework, "Java");
    }

    #[test]
    fn test_enable_disable_module() {
        let mut registry = DeserializationRegistry::new();
        registry.set_module_enabled("java_gadgets", false);
        
        let enabled = registry.get_enabled_modules();
        assert!(!enabled.iter().any(|m| m.name == "java_gadgets"));
    }

    #[test]
    fn test_god_mode() {
        let mut registry = DeserializationRegistry::new();
        assert!(!registry.is_god_mode());
        
        registry.enable_god_mode();
        assert!(registry.is_god_mode());
        
        registry.disable_god_mode();
        assert!(!registry.is_god_mode());
    }
}
