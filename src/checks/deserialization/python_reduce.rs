//! Python Reduce-style Payload Builder
//! Builds controlled reduce-style payloads that verify execution without destructive commands.

/// Builder for Python __reduce__ style payloads
#[derive(Debug, Clone)]
pub struct PythonReduceBuilder {
    /// Maximum payload size (2GB ceiling)
    max_payload_size: usize,
    /// Protocol version to use
    protocol_version: u8,
}

/// A generated reduce payload
#[derive(Debug, Clone)]
pub struct ReducePayload {
    /// Pickle bytecode
    pub bytecode: Vec<u8>,
    /// Callable reference
    pub callable: String,
    /// Arguments (benign only)
    pub arguments: Vec<String>,
    /// Size in bytes
    pub size: usize,
}

impl PythonReduceBuilder {
    /// Create a new reduce builder
    pub fn new() -> Self {
        Self {
            max_payload_size: 2 * 1024 * 1024 * 1024, // 2GB ceiling
            protocol_version: 4,
        }
    }

    /// Build a benign reduce payload for verification
    pub fn build_verify_payload(&self, marker: &str) -> Option<ReducePayload> {
        // Only allow safe markers
        let safe_markers = ["PING", "PONG", "TEST", "VERIFY", "CHECK"];
        if !safe_markers.contains(&marker) || marker.len() > 32 {
            return None;
        }

        let mut bytecode = Vec::new();

        // Protocol header
        bytecode.push(0x80);
        bytecode.push(self.protocol_version);

        // Frame indicator (protocol 4+)
        bytecode.push(0x95);
        bytecode.extend_from_slice(&[0x00; 8]); // Frame length placeholder

        // Push the marker string using SHORT_BINUNICODE
        bytecode.push(0x8C);
        bytecode.push(marker.len() as u8);
        bytecode.extend_from_slice(marker.as_bytes());

        // STOP
        bytecode.push(0x2E);

        if bytecode.len() > self.max_payload_size {
            return None;
        }

        Some(ReducePayload {
            bytecode,
            callable: "builtins.str".to_string(),
            arguments: vec![marker.to_string()],
            size: bytecode.len(),
        })
    }

    /// Build a timing-based verification payload
    pub fn build_timing_payload(&self) -> Option<ReducePayload> {
        let mut bytecode = Vec::new();

        // Protocol header
        bytecode.push(0x80);
        bytecode.push(self.protocol_version);

        // Push integer 1 + 1 (benign computation)
        bytecode.push(0x4B); // BININT1
        bytecode.push(0x01);

        bytecode.push(0x4B); // BININT1
        bytecode.push(0x01);

        bytecode.push(0x4B); // BININT1
        bytecode.push(0x02);

        // TUPLE of three items
        bytecode.push(0x86); // TUPLE3
        bytecode.push(0x52); // REDUCE - but with benign args

        bytecode.push(0x2E); // STOP

        if bytecode.len() > self.max_payload_size {
            return None;
        }

        Some(ReducePayload {
            bytecode,
            callable: "operator.add".to_string(),
            arguments: vec!["1".to_string(), "1".to_string()],
            size: bytecode.len(),
        })
    }

    /// Build a callback verification payload (OOB)
    pub fn build_callback_payload(&self, callback_token: &str) -> Option<ReducePayload> {
        // Validate token is safe
        if callback_token.len() > 64 || callback_token.is_empty() {
            return None;
        }

        // Only alphanumeric tokens allowed
        if !callback_token.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }

        let mut bytecode = Vec::new();

        // Protocol header
        bytecode.push(0x80);
        bytecode.push(self.protocol_version);

        // Push callback token
        bytecode.push(0x8C);
        bytecode.push(callback_token.len() as u8);
        bytecode.extend_from_slice(callback_token.as_bytes());

        bytecode.push(0x2E); // STOP

        if bytecode.len() > self.max_payload_size {
            return None;
        }

        Some(ReducePayload {
            bytecode,
            callable: "callback.verify".to_string(),
            arguments: vec![callback_token.to_string()],
            size: bytecode.len(),
        })
    }

    /// Analyze a reduce payload for safety
    pub fn analyze_safety(&self, bytecode: &[u8]) -> SafetyReport {
        let mut report = SafetyReport {
            is_safe: true,
            dangerous_opcodes: Vec::new(),
            warnings: Vec::new(),
        };

        let dangerous: [(u8, &str); 8] = [
            (0x63, "GLOBAL"),   // Can import arbitrary modules
            (0x52, "REDUCE"),   // Can call arbitrary functions
            (0x85, "NEWOBJ"),   // Creates objects via __new__
            (0x81, "INST"),     // Instantiates classes
            (0x82, "OBJ"),      // Creates objects
            (0x87, "STACK_GLOBAL"), // Stack-based global lookup
            (0x93, "MEMOIZE"),  // Can be used in complex attacks
            (0x84, "TUPLE"),    // Used in chain construction
        ];

        for byte in bytecode {
            for (opcode, name) in dangerous.iter() {
                if byte == opcode {
                    report.is_safe = false;
                    report.dangerous_opcodes.push(name.to_string());
                }
            }
        }

        // Check for os.system patterns
        let system_patterns = [b"os\nsystem", b"subprocess", b"exec(", b"eval("];
        for pattern in system_patterns.iter() {
            if bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                report.warnings.push("Potential command execution pattern".to_string());
            }
        }

        report
    }

    /// Set protocol version
    pub fn with_protocol(mut self, version: u8) -> Self {
        self.protocol_version = version.min(5); // Max protocol 5
        self
    }

    /// Get maximum payload size
    pub fn max_payload_size(&self) -> usize {
        self.max_payload_size
    }
}

impl Default for PythonReduceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Safety analysis report
#[derive(Debug, Clone)]
pub struct SafetyReport {
    /// Whether payload is considered safe
    pub is_safe: bool,
    /// List of dangerous opcodes found
    pub dangerous_opcodes: Vec<String>,
    /// Additional warnings
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = PythonReduceBuilder::new();
        assert_eq!(builder.max_payload_size(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_verify_payload() {
        let builder = PythonReduceBuilder::new();
        let payload = builder.build_verify_payload("PING");
        
        assert!(payload.is_some());
        let p = payload.unwrap();
        assert!(!p.bytecode.is_empty());
        assert_eq!(p.callable, "builtins.str");
    }

    #[test]
    fn test_safety_analysis() {
        let builder = PythonReduceBuilder::new();
        // Safe bytecode
        let safe_bc = vec![0x80, 0x04, 0x2E];
        let report = builder.analyze_safety(&safe_bc);
        assert!(report.is_safe);

        // Dangerous bytecode with GLOBAL
        let dangerous_bc = vec![0x80, 0x04, 0x63, 0x6f, 0x73, 0x00];
        let report = builder.analyze_safety(&dangerous_bc);
        assert!(!report.is_safe);
        assert!(report.dangerous_opcodes.contains(&"GLOBAL".to_string()));
    }
}
