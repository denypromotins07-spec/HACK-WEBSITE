//! PHP Magic Methods Mapping
//! Maps __wakeup, __destruct, __toString, and property-oriented programming chains.

/// Registry of PHP magic methods and their characteristics
#[derive(Debug, Clone)]
pub struct PhpMagicMethodRegistry {
    /// Registered magic methods
    methods: Vec<MagicMethodInfo>,
}

/// Information about a specific magic method
#[derive(Debug, Clone)]
pub struct MagicMethodInfo {
    /// Method name (e.g., "__wakeup")
    pub name: String,
    /// Trigger condition
    pub trigger: String,
    /// Common vulnerability patterns
    pub vuln_patterns: Vec<String>,
    /// Risk level (1-10)
    pub risk_level: u8,
    /// Detection signature
    pub signature: String,
}

/// Property-oriented programming chain
#[derive(Debug, Clone)]
pub struct PopChain {
    /// Chain identifier
    pub id: String,
    /// Starting class
    pub start_class: String,
    /// Method sequence
    pub method_sequence: Vec<String>,
    /// Sink function
    pub sink: String,
    /// Framework/library source
    pub framework: Option<String>,
}

impl PhpMagicMethodRegistry {
    /// Create a new registry with known magic methods
    pub fn new() -> Self {
        let mut registry = Self {
            methods: Vec::new(),
        };
        
        // Register common magic methods
        registry.register_default_methods();
        registry
    }

    /// Register default magic methods
    fn register_default_methods(&mut self) {
        self.methods.push(MagicMethodInfo {
            name: "__wakeup".to_string(),
            trigger: "Called when unserialize() is called".to_string(),
            vuln_patterns: vec![
                "property_injection".to_string(),
                "object_instantiation".to_string(),
            ],
            risk_level: 8,
            signature: "O:".to_string(),
        });

        self.methods.push(MagicMethodInfo {
            name: "__destruct".to_string(),
            trigger: "Called when object goes out of scope".to_string(),
            vuln_patterns: vec![
                "file_operations".to_string(),
                "command_execution".to_string(),
                "sql_injection".to_string(),
            ],
            risk_level: 9,
            signature: "O:".to_string(),
        });

        self.methods.push(MagicMethodInfo {
            name: "__toString".to_string(),
            trigger: "Called when object is converted to string".to_string(),
            vuln_patterns: vec![
                "echo_injection".to_string(),
                "string_concatenation".to_string(),
            ],
            risk_level: 7,
            signature: "O:".to_string(),
        });

        self.methods.push(MagicMethodInfo {
            name: "__invoke".to_string(),
            trigger: "Called when object is called as function".to_string(),
            vuln_patterns: vec![
                "callback_execution".to_string(),
                "callable_injection".to_string(),
            ],
            risk_level: 8,
            signature: "O:".to_string(),
        });

        self.methods.push(MagicMethodInfo {
            name: "__get".to_string(),
            trigger: "Called when accessing inaccessible property".to_string(),
            vuln_patterns: vec![
                "property_read".to_string(),
                "getter_injection".to_string(),
            ],
            risk_level: 6,
            signature: "O:".to_string(),
        });

        self.methods.push(MagicMethodInfo {
            name: "__set".to_string(),
            trigger: "Called when setting inaccessible property".to_string(),
            vuln_patterns: vec![
                "property_write".to_string(),
                "setter_injection".to_string(),
            ],
            risk_level: 7,
            signature: "O:".to_string(),
        });

        self.methods.push(MagicMethodInfo {
            name: "__call".to_string(),
            trigger: "Called when calling inaccessible method".to_string(),
            vuln_patterns: vec![
                "method_injection".to_string(),
                "callable_chain".to_string(),
            ],
            risk_level: 8,
            signature: "O:".to_string(),
        });

        self.methods.push(MagicMethodInfo {
            name: "__autoload".to_string(),
            trigger: "Called when loading undefined class".to_string(),
            vuln_patterns: vec![
                "lfi_injection".to_string(),
                "path_traversal".to_string(),
            ],
            risk_level: 9,
            signature: "spl_autoload_register".to_string(),
        });
    }

    /// Get information about a specific magic method
    pub fn get_method(&self, name: &str) -> Option<&MagicMethodInfo> {
        self.methods.iter().find(|m| m.name == name)
    }

    /// Get all registered methods
    pub fn get_all_methods(&self) -> &[MagicMethodInfo] {
        &self.methods
    }

    /// Build a POP chain for testing
    pub fn build_pop_chain(
        &self,
        start_class: &str,
        sink: &str,
    ) -> Option<PopChain> {
        // Validate inputs are benign
        if start_class.len() > 100 || sink.len() > 100 {
            return None;
        }

        Some(PopChain {
            id: format!("POP_{}_{}", start_class, sink),
            start_class: start_class.to_string(),
            method_sequence: vec!["__wakeup".to_string(), "__get".to_string()],
            sink: sink.to_string(),
            framework: None,
        })
    }

    /// Analyze a serialized payload for magic method usage
    pub fn analyze_payload(&self, payload: &str) -> Vec<String> {
        let mut detected = Vec::new();

        // Check for object serialization markers
        if payload.starts_with("O:") {
            detected.push("object_serialization".to_string());
        }

        // Check for array with potential properties
        if payload.contains("a:") {
            detected.push("array_structure".to_string());
        }

        // Check for string properties
        if payload.contains("s:") {
            detected.push("string_properties".to_string());
        }

        detected
    }
}

impl Default for PhpMagicMethodRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for PHP serialized objects with canary properties
#[derive(Debug)]
pub struct PhpObjectBuilder {
    /// Class name
    class_name: String,
    /// Properties
    properties: Vec<(String, String)>,
    /// Canary value for tracking
    canary: Option<String>,
}

impl PhpObjectBuilder {
    /// Create a new object builder
    pub fn new(class_name: &str) -> Self {
        Self {
            class_name: class_name.to_string(),
            properties: Vec::new(),
            canary: None,
        }
    }

    /// Add a property (bounded)
    pub fn with_property(mut self, name: &str, value: &str) -> Option<Self> {
        if name.len() > 255 || value.len() > 1000 {
            return None; // Enforce bounds
        }
        
        self.properties.push((name.to_string(), value.to_string()));
        Some(self)
    }

    /// Set a canary value for tracking
    pub fn with_canary(mut self, canary: &str) -> Self {
        self.canary = Some(canary.to_string());
        self
    }

    /// Build the serialized object string
    pub fn build(self) -> String {
        let prop_count = self.properties.len();
        let mut result = format!("O:{}:\"{}\":{}:{{", 
            self.class_name.len(), 
            self.class_name, 
            prop_count
        );

        for (name, value) in self.properties {
            result.push_str(&format!(
                "s:{}:\"{}\";s:{}:\"{}\";",
                name.len(),
                name,
                value.len(),
                value
            ));
        }

        result.push('}');
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = PhpMagicMethodRegistry::new();
        assert!(!registry.get_all_methods().is_empty());
    }

    #[test]
    fn test_get_method() {
        let registry = PhpMagicMethodRegistry::new();
        let method = registry.get_method("__wakeup");
        assert!(method.is_some());
        assert_eq!(method.unwrap().name, "__wakeup");
    }

    #[test]
    fn test_object_builder() {
        let obj = PhpObjectBuilder::new("TestClass")
            .with_property("name", "value")
            .unwrap()
            .with_canary("CANARY123")
            .build();
        
        assert!(obj.starts_with("O:"));
        assert!(obj.contains("TestClass"));
    }
}
