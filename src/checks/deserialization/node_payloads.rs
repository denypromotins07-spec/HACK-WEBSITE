//! Node.js Deserialization Payload Generator
//! Generates JSON and JavaScript object payloads with controlled function markers.

/// Generator for Node.js deserialization test payloads
#[derive(Debug, Clone)]
pub struct NodePayloadGenerator {
    /// Maximum payload size (2GB ceiling)
    max_payload_size: usize,
    /// Function marker prefix
    marker_prefix: String,
}

/// A generated Node.js payload
#[derive(Debug, Clone)]
pub struct NodePayload {
    /// Payload string (JSON or JS)
    pub content: String,
    /// Payload type
    pub payload_type: NodePayloadType,
    /// Marker embedded
    pub marker: Option<String>,
    /// Size in bytes
    pub size: usize,
}

/// Type of Node.js payload
#[derive(Debug, Clone, PartialEq)]
pub enum NodePayloadType {
    /// Plain JSON object
    JsonObject,
    /// JSON with function wrapper
    JsonWithFunction,
    /// Serialized function
    SerializedFunction,
    /// Prototype pollution test
    ProtoPollution,
    /// node-serialize format
    NodeSerialize,
}

impl NodePayloadGenerator {
    /// Create a new payload generator
    pub fn new() -> Self {
        Self {
            max_payload_size: 2 * 1024 * 1024 * 1024, // 2GB ceiling
            marker_prefix: "MARKER_".to_string(),
        }
    }

    /// Generate a plain JSON object payload
    pub fn generate_json_object(&self, data: &str) -> Option<NodePayload> {
        if data.len() > 1_000_000 {
            return None; // Enforce reasonable bound
        }

        let content = format!("{{\"data\":\"{}\"}}", data);

        if content.len() > self.max_payload_size {
            return None;
        }

        Some(NodePayload {
            content,
            payload_type: NodePayloadType::JsonObject,
            marker: None,
            size: content.len(),
        })
    }

    /// Generate a JSON payload with function marker
    pub fn generate_json_with_function(&self, marker: &str) -> Option<NodePayload> {
        // Validate marker is safe
        if marker.len() > 64 || marker.is_empty() {
            return None;
        }

        // Only alphanumeric and underscore allowed
        if !marker.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }

        // Benign function that just returns the marker
        let content = format!(
            r#"{{"_$$ND_FUNC$$_":"(function(){{return \"{}\";}})()","data":"test"}}"#,
            marker
        );

        if content.len() > self.max_payload_size {
            return None;
        }

        Some(NodePayload {
            content,
            payload_type: NodePayloadType::JsonWithFunction,
            marker: Some(marker.to_string()),
            size: content.len(),
        })
    }

    /// Generate a serialized function payload (node-serialize format)
    pub fn generate_node_serialize(&self, func_body: &str) -> Option<NodePayload> {
        // Only allow safe function bodies
        let safe_bodies = [
            "return 'test';",
            "return 1+1;",
            "return true;",
            "return Date.now();",
        ];

        if !safe_bodies.contains(&func_body) {
            return None;
        }

        let content = format!(r#"{{"_$$ND_FUNC$$_":"(function(){{{}}})()"}}"#, func_body);

        if content.len() > self.max_payload_size {
            return None;
        }

        Some(NodePayload {
            content,
            payload_type: NodePayloadType::NodeSerialize,
            marker: None,
            size: content.len(),
        })
    }

    /// Generate a prototype pollution test payload
    pub fn generate_proto_pollution_test(&self, key: &str, value: &str) -> Option<NodePayload> {
        // Validate inputs are safe
        if key.len() > 32 || value.len() > 64 {
            return None;
        }

        // Only allow safe test keys
        let safe_keys = ["__proto__", "constructor", "prototype"];
        if !safe_keys.contains(&key) {
            return None;
        }

        let content = format!(
            r#"{{"{}":{{"pollution_test":"{}"}}}}"#,
            key, value
        );

        if content.len() > self.max_payload_size {
            return None;
        }

        Some(NodePayload {
            content,
            payload_type: NodePayloadType::ProtoPollution,
            marker: Some(value.to_string()),
            size: content.len(),
        })
    }

    /// Generate an IIFE-based verification payload
    pub fn generate_iife_verify(&self, token: &str) -> Option<NodePayload> {
        if token.len() > 64 || token.is_empty() {
            return None;
        }

        if !token.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }

        let content = format!(
            r#"{{"verify":"(function(){{return \"{}\";}})()"}}"#,
            token
        );

        if content.len() > self.max_payload_size {
            return None;
        }

        Some(NodePayload {
            content,
            payload_type: NodePayloadType::SerializedFunction,
            marker: Some(token.to_string()),
            size: content.len(),
        })
    }

    /// Validate payload safety
    pub fn validate_safety(&self, content: &str) -> SafetyReport {
        let mut report = SafetyReport {
            is_safe: true,
            dangerous_patterns: Vec::new(),
            warnings: Vec::new(),
        };

        // Check for dangerous patterns
        let dangerous: [(&str, &str); 10] = [
            ("require(", "Module loading"),
            ("eval(", "Eval execution"),
            ("exec(", "Command execution"),
            ("spawn(", "Process spawning"),
            ("fs.read", "File read access"),
            ("fs.write", "File write access"),
            ("child_process", "Child process module"),
            ("net.connect", "Network connection"),
            ("dns.lookup", "DNS lookup"),
            ("vm.run", "VM execution"),
        ];

        for (pattern, description) in dangerous.iter() {
            if content.contains(pattern) {
                report.is_safe = false;
                report.dangerous_patterns.push(format!("{}: {}", pattern, description));
            }
        }

        // Check for base64 encoded payloads (potential obfuscation)
        if content.contains("Buffer.from") || content.contains("atob(") {
            report.warnings.push("Possible encoded payload detected".to_string());
        }

        // Check payload size
        if content.len() > 100000 {
            report.warnings.push("Large payload size".to_string());
        }

        report
    }

    /// Set custom marker prefix
    pub fn with_marker_prefix(mut self, prefix: &str) -> Self {
        self.marker_prefix = prefix.to_string();
        self
    }

    /// Get maximum payload size
    pub fn max_payload_size(&self) -> usize {
        self.max_payload_size
    }
}

impl Default for NodePayloadGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Safety analysis report
#[derive(Debug, Clone)]
pub struct SafetyReport {
    /// Whether payload is considered safe
    pub is_safe: bool,
    /// List of dangerous patterns found
    pub dangerous_patterns: Vec<String>,
    /// Additional warnings
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_creation() {
        let gen = NodePayloadGenerator::new();
        assert_eq!(gen.max_payload_size(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_json_object_generation() {
        let gen = NodePayloadGenerator::new();
        let payload = gen.generate_json_object("test data");
        
        assert!(payload.is_some());
        let p = payload.unwrap();
        assert_eq!(p.payload_type, NodePayloadType::JsonObject);
        assert!(p.content.contains("test data"));
    }

    #[test]
    fn test_function_payload() {
        let gen = NodePayloadGenerator::new();
        let payload = gen.generate_json_with_function("TEST_MARKER");
        
        assert!(payload.is_some());
        assert_eq!(payload.unwrap().payload_type, NodePayloadType::JsonWithFunction);
    }

    #[test]
    fn test_node_serialize() {
        let gen = NodePayloadGenerator::new();
        let payload = gen.generate_node_serialize("return 'test';");
        
        assert!(payload.is_some());
        assert_eq!(payload.unwrap().payload_type, NodePayloadType::NodeSerialize);
    }

    #[test]
    fn test_safety_validation() {
        let gen = NodePayloadGenerator::new();
        
        // Safe content
        let safe = r#"{"data":"hello"}"#;
        let report = gen.validate_safety(safe);
        assert!(report.is_safe);

        // Dangerous content
        let dangerous = r#"{"code":"require('child_process').exec('ls')"}"#;
        let report = gen.validate_safety(dangerous);
        assert!(!report.is_safe);
    }
}
