//! PHP Deserialization Payload Generator
//! Generates PHP serialized strings with bounded object graphs and canary properties.

/// Generator for PHP deserialization test payloads
#[derive(Debug, Clone)]
pub struct PhpPayloadGenerator {
    /// Maximum payload size (2GB ceiling)
    max_payload_size: usize,
    /// Canary prefix for tracking
    canary_prefix: String,
}

/// A generated PHP payload with metadata
#[derive(Debug, Clone)]
pub struct PhpPayload {
    /// Serialized string
    pub serialized: String,
    /// Payload type
    pub payload_type: PayloadType,
    /// Canary value embedded
    pub canary: Option<String>,
    /// Size in bytes
    pub size: usize,
}

/// Type of PHP payload
#[derive(Debug, Clone, PartialEq)]
pub enum PayloadType {
    /// Simple object
    SimpleObject,
    /// Nested object graph
    NestedObject,
    /// Array with objects
    ObjectArray,
    /// Magic method trigger
    MagicTrigger,
    /// POP chain simulation
    PopChain,
}

impl PhpPayloadGenerator {
    /// Create a new payload generator
    pub fn new() -> Self {
        Self {
            max_payload_size: 2 * 1024 * 1024 * 1024, // 2GB ceiling
            canary_prefix: "CANARY_".to_string(),
        }
    }

    /// Generate a simple object payload
    pub fn generate_simple_object(&self, class_name: &str, canary: &str) -> Option<PhpPayload> {
        if class_name.len() > 255 || canary.len() > 64 {
            return None; // Enforce bounds
        }

        let serialized = format!(
            "O:{}:\"{}\":1{{s:{}:\"canary\";s:{}:\"{}\";}}",
            class_name.len(),
            class_name,
            "canary".len(),
            canary.len(),
            canary
        );

        if serialized.len() > self.max_payload_size {
            return None;
        }

        Some(PhpPayload {
            serialized,
            payload_type: PayloadType::SimpleObject,
            canary: Some(canary.to_string()),
            size: serialized.len(),
        })
    }

    /// Generate a nested object graph payload
    pub fn generate_nested_object(
        &self,
        outer_class: &str,
        inner_class: &str,
        depth: u8,
    ) -> Option<PhpPayload> {
        // Limit depth to prevent excessive nesting
        if depth > 10 {
            return None;
        }

        if outer_class.len() > 100 || inner_class.len() > 100 {
            return None;
        }

        let mut serialized = String::new();
        
        // Build nested structure
        serialized.push_str(&format!("O:{}:\"{}\":1{{s:{}:\"inner\";", 
            outer_class.len(), outer_class, "inner".len()));
        
        // Add inner object
        serialized.push_str(&format!("O:{}:\"{}\":0{{}}", 
            inner_class.len(), inner_class));
        
        serialized.push('}');

        if serialized.len() > self.max_payload_size {
            return None;
        }

        Some(PhpPayload {
            serialized,
            payload_type: PayloadType::NestedObject,
            canary: None,
            size: serialized.len(),
        })
    }

    /// Generate an array containing objects
    pub fn generate_object_array(&self, class_name: &str, count: u8) -> Option<PhpPayload> {
        // Limit array size
        if count > 20 {
            return None;
        }

        if class_name.len() > 100 {
            return None;
        }

        let mut serialized = format!("a:{}{{", count);
        
        for i in 0..count {
            serialized.push_str(&format!(
                "i:{};O:{}:\"{}\":0{{}};",
                i,
                class_name.len(),
                class_name
            ));
        }
        
        serialized.push('}');

        if serialized.len() > self.max_payload_size {
            return None;
        }

        Some(PhpPayload {
            serialized,
            payload_type: PayloadType::ObjectArray,
            canary: None,
            size: serialized.len(),
        })
    }

    /// Generate a magic method trigger payload
    pub fn generate_magic_trigger(&self, method: &str, class_name: &str) -> Option<PhpPayload> {
        let valid_methods = ["__wakeup", "__destruct", "__toString", "__invoke"];
        if !valid_methods.contains(&method) {
            return None;
        }

        if class_name.len() > 100 {
            return None;
        }

        // Benign trigger object
        let serialized = format!("O:{}:\"{}\":0{{}}", class_name.len(), class_name);

        if serialized.len() > self.max_payload_size {
            return None;
        }

        Some(PhpPayload {
            serialized,
            payload_type: PayloadType::MagicTrigger,
            canary: None,
            size: serialized.len(),
        })
    }

    /// Generate a POP chain simulation payload
    pub fn generate_pop_chain(
        &self,
        classes: &[&str],
        canary: &str,
    ) -> Option<PhpPayload> {
        // Limit chain length
        if classes.is_empty() || classes.len() > 10 {
            return None;
        }

        if canary.len() > 64 {
            return None;
        }

        let mut serialized = String::new();
        let mut current = String::new();

        // Build chain from inside out
        for (i, class) in classes.iter().rev().enumerate() {
            if class.len() > 100 {
                return None;
            }

            if i == 0 {
                // Innermost object with canary
                current = format!(
                    "O:{}:\"{}\":1{{s:{}:\"canary\";s:{}:\"{}\";}}",
                    class.len(),
                    class,
                    "canary".len(),
                    canary.len(),
                    canary
                );
            } else {
                // Wrap in outer object
                current = format!(
                    "O:{}:\"{}\":1{{s:{}:\"wrapped\";{}}}",
                    class.len(),
                    class,
                    "wrapped".len(),
                    current
                );
            }
        }

        serialized = current;

        if serialized.len() > self.max_payload_size {
            return None;
        }

        Some(PhpPayload {
            serialized,
            payload_type: PayloadType::PopChain,
            canary: Some(canary.to_string()),
            size: serialized.len(),
        })
    }

    /// Validate a PHP serialized string format
    pub fn validate_serialized(&self, input: &str) -> bool {
        if input.is_empty() || input.len() > self.max_payload_size {
            return false;
        }

        // Basic format validation
        if !input.starts_with(['O', 'a', 's', 'i', 'd', 'b', 'N']) {
            return false;
        }

        // Check for balanced braces
        let brace_count = input.chars().filter(|&c| c == '{' || c == '}').count();
        if brace_count % 2 != 0 {
            return false;
        }

        true
    }

    /// Set custom canary prefix
    pub fn with_canary_prefix(mut self, prefix: &str) -> Self {
        self.canary_prefix = prefix.to_string();
        self
    }

    /// Get maximum payload size
    pub fn max_payload_size(&self) -> usize {
        self.max_payload_size
    }
}

impl Default for PhpPayloadGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_creation() {
        let gen = PhpPayloadGenerator::new();
        assert_eq!(gen.max_payload_size(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_simple_object_generation() {
        let gen = PhpPayloadGenerator::new();
        let payload = gen.generate_simple_object("TestClass", "TRACK123");
        
        assert!(payload.is_some());
        let p = payload.unwrap();
        assert_eq!(p.payload_type, PayloadType::SimpleObject);
        assert!(p.serialized.starts_with("O:"));
    }

    #[test]
    fn test_nested_object_generation() {
        let gen = PhpPayloadGenerator::new();
        let payload = gen.generate_nested_object("Outer", "Inner", 1);
        
        assert!(payload.is_some());
        assert_eq!(payload.unwrap().payload_type, PayloadType::NestedObject);
    }

    #[test]
    fn test_validation() {
        let gen = PhpPayloadGenerator::new();
        assert!(gen.validate_serialized("O:4:\"Test\":0:{}"));
        assert!(!gen.validate_serialized("invalid"));
        assert!(!gen.validate_serialized(""));
    }
}
