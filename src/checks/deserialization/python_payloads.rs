//! Python Pickle Payload Generator
//! Generates versioned pickle payloads with bounded opcode sequences.

/// Generator for Python pickle payloads
#[derive(Debug, Clone)]
pub struct PythonPickleGenerator {
    /// Maximum payload size (2GB ceiling)
    max_payload_size: usize,
    /// Default protocol version
    default_protocol: u8,
}

/// A generated pickle payload with metadata
#[derive(Debug, Clone)]
pub struct PicklePayload {
    /// Pickle bytecode
    pub bytecode: Vec<u8>,
    /// Protocol version used
    pub protocol: u8,
    /// Payload type
    pub payload_type: PicklePayloadType,
    /// Size in bytes
    pub size: usize,
    /// Opcode count
    pub opcode_count: usize,
}

/// Type of pickle payload
#[derive(Debug, Clone, PartialEq)]
pub enum PicklePayloadType {
    /// Simple data payload
    SimpleData,
    /// Tuple-based payload
    Tuple,
    /// Dict-based payload
    Dict,
    /// List-based payload
    List,
    /// Object instantiation simulation
    ObjectSim,
    /// Verification marker
    VerifyMarker,
}

impl PythonPickleGenerator {
    /// Create a new pickle generator
    pub fn new() -> Self {
        Self {
            max_payload_size: 2 * 1024 * 1024 * 1024, // 2GB ceiling
            default_protocol: 4,
        }
    }

    /// Generate a simple string payload
    pub fn generate_string(&self, content: &str) -> Option<PicklePayload> {
        if content.len() > 1_000_000 {
            return None; // Enforce reasonable bound
        }

        let mut bytecode = Vec::new();

        // Protocol header
        bytecode.push(0x80);
        bytecode.push(self.default_protocol);

        // String encoding depends on length
        if content.len() <= 255 {
            // SHORT_BINUNICODE
            bytecode.push(0x8C);
            bytecode.push(content.len() as u8);
        } else if content.len() <= 65535 {
            // BINUNICODE
            bytecode.push(0x58);
            bytecode.extend_from_slice(&(content.len() as u32).to_le_bytes());
        } else {
            return None; // Too long for safe generation
        }

        bytecode.extend_from_slice(content.as_bytes());
        bytecode.push(0x2E); // STOP

        if bytecode.len() > self.max_payload_size {
            return None;
        }

        Some(PicklePayload {
            bytecode,
            protocol: self.default_protocol,
            payload_type: PicklePayloadType::SimpleData,
            size: bytecode.len(),
            opcode_count: Self::count_opcodes(&bytecode),
        })
    }

    /// Generate an integer payload
    pub fn generate_int(&self, value: i32) -> Option<PicklePayload> {
        let mut bytecode = Vec::new();

        // Protocol header
        bytecode.push(0x80);
        bytecode.push(self.default_protocol);

        // Choose appropriate integer encoding
        if value >= 0 && value <= 255 {
            bytecode.push(0x4B); // BININT1
            bytecode.push(value as u8);
        } else if value >= -32768 && value <= 32767 {
            bytecode.push(0x4D); // BININT2
            bytecode.extend_from_slice(&(value as u16).to_le_bytes());
        } else {
            bytecode.push(0x4A); // BININT
            bytecode.extend_from_slice(&value.to_le_bytes());
        }

        bytecode.push(0x2E); // STOP

        if bytecode.len() > self.max_payload_size {
            return None;
        }

        Some(PicklePayload {
            bytecode,
            protocol: self.default_protocol,
            payload_type: PicklePayloadType::SimpleData,
            size: bytecode.len(),
            opcode_count: Self::count_opcodes(&bytecode),
        })
    }

    /// Generate a tuple payload
    pub fn generate_tuple(&self, items: &[&str]) -> Option<PicklePayload> {
        if items.is_empty() || items.len() > 100 {
            return None;
        }

        let mut bytecode = Vec::new();

        // Protocol header
        bytecode.push(0x80);
        bytecode.push(self.default_protocol);

        // Push each item
        for item in items {
            if item.len() > 255 {
                return None;
            }
            bytecode.push(0x8C); // SHORT_BINUNICODE
            bytecode.push(item.len() as u8);
            bytecode.extend_from_slice(item.as_bytes());
        }

        // Build tuple
        match items.len() {
            0 => bytecode.push(0x29), // EMPTYTUPLE
            1 => bytecode.push(0x85), // TUPLE1
            2 => bytecode.push(0x86), // TUPLE2
            3 => bytecode.push(0x87), // TUPLE3
            _ => {
                // Use MARK + TUPLE for larger tuples
                bytecode.push(0x28); // MARK
                bytecode.push(0x74); // TUPLE
            }
        }

        bytecode.push(0x2E); // STOP

        if bytecode.len() > self.max_payload_size {
            return None;
        }

        Some(PicklePayload {
            bytecode,
            protocol: self.default_protocol,
            payload_type: PicklePayloadType::Tuple,
            size: bytecode.len(),
            opcode_count: Self::count_opcodes(&bytecode),
        })
    }

    /// Generate a dict payload
    pub fn generate_dict(&self, entries: &[(&str, &str)]) -> Option<PicklePayload> {
        if entries.is_empty() || entries.len() > 50 {
            return None;
        }

        let mut bytecode = Vec::new();

        // Protocol header
        bytecode.push(0x80);
        bytecode.push(self.default_protocol);

        bytecode.push(0x7D); // EMPTYDICT or MARK for building

        for (key, value) in entries {
            if key.len() > 255 || value.len() > 255 {
                return None;
            }

            // Push key
            bytecode.push(0x8C);
            bytecode.push(key.len() as u8);
            bytecode.extend_from_slice(key.as_bytes());

            // Push value
            bytecode.push(0x8C);
            bytecode.push(value.len() as u8);
            bytecode.extend_from_slice(value.as_bytes());

            // SETITEM
            bytecode.push(0x73);
        }

        bytecode.push(0x2E); // STOP

        if bytecode.len() > self.max_payload_size {
            return None;
        }

        Some(PicklePayload {
            bytecode,
            protocol: self.default_protocol,
            payload_type: PicklePayloadType::Dict,
            size: bytecode.len(),
            opcode_count: Self::count_opcodes(&bytecode),
        })
    }

    /// Generate a verification marker payload
    pub fn generate_verify_marker(&self, marker: &str) -> Option<PicklePayload> {
        // Validate marker is safe
        if marker.len() > 64 || marker.is_empty() {
            return None;
        }

        // Only alphanumeric and underscore allowed
        if !marker.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }

        let mut bytecode = Vec::new();

        // Protocol header
        bytecode.push(0x80);
        bytecode.push(self.default_protocol);

        // Marker string
        bytecode.push(0x8C);
        bytecode.push(marker.len() as u8);
        bytecode.extend_from_slice(marker.as_bytes());

        bytecode.push(0x2E); // STOP

        if bytecode.len() > self.max_payload_size {
            return None;
        }

        Some(PicklePayload {
            bytecode,
            protocol: self.default_protocol,
            payload_type: PicklePayloadType::VerifyMarker,
            size: bytecode.len(),
            opcode_count: Self::count_opcodes(&bytecode),
        })
    }

    /// Count opcodes in bytecode
    fn count_opcodes(bytecode: &[u8]) -> usize {
        let mut count = 0;
        let mut i = 0;

        while i < bytecode.len() {
            match bytecode[i] {
                // Single byte opcodes
                0x28..=0x32 | 0x35..=0x39 | 0x41..=0x44 | 0x46..=0x49 |
                0x4B..=0x4E | 0x50..=0x58 | 0x5A..=0x5D | 0x61..=0x65 |
                0x67..=0x6F | 0x71..=0x75 | 0x77..=0x7A | 0x7C..=0x7E |
                0x81..=0x87 | 0x89..=0x8D | 0x8F..=0x95 | 0x97..=0x9C => {
                    count += 1;
                    i += 1;
                }
                // Opcodes with arguments handled by skipping known patterns
                _ => {
                    i += 1;
                }
            }
        }

        count
    }

    /// Set default protocol version
    pub fn with_protocol(mut self, version: u8) -> Self {
        self.default_protocol = version.min(5);
        self
    }

    /// Get maximum payload size
    pub fn max_payload_size(&self) -> usize {
        self.max_payload_size
    }
}

impl Default for PythonPickleGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_creation() {
        let gen = PythonPickleGenerator::new();
        assert_eq!(gen.max_payload_size(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_string_generation() {
        let gen = PythonPickleGenerator::new();
        let payload = gen.generate_string("hello world");
        
        assert!(payload.is_some());
        let p = payload.unwrap();
        assert_eq!(p.payload_type, PicklePayloadType::SimpleData);
        assert!(!p.bytecode.is_empty());
    }

    #[test]
    fn test_int_generation() {
        let gen = PythonPickleGenerator::new();
        let payload = gen.generate_int(42);
        
        assert!(payload.is_some());
        assert_eq!(payload.unwrap().protocol, 4);
    }

    #[test]
    fn test_tuple_generation() {
        let gen = PythonPickleGenerator::new();
        let payload = gen.generate_tuple(&["a", "b", "c"]);
        
        assert!(payload.is_some());
        assert_eq!(payload.unwrap().payload_type, PicklePayloadType::Tuple);
    }

    #[test]
    fn test_verify_marker() {
        let gen = PythonPickleGenerator::new();
        let payload = gen.generate_verify_marker("TEST_MARKER");
        
        assert!(payload.is_some());
        assert_eq!(payload.unwrap().payload_type, PicklePayloadType::VerifyMarker);
    }
}
