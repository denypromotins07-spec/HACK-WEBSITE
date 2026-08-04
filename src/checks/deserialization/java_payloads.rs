//! Java Deserialization Payload Builder
//! Builds bounded Java serialized payloads for CommonsCollections and related libraries.

/// Marker for safe gadget chain probing
#[derive(Debug, Clone)]
pub struct GadgetMarker {
    /// Name of the gadget chain
    chain_name: String,
    /// Serialized bytes (bounded)
    serialized_data: Vec<u8>,
    /// Maximum payload size
    max_payload_size: usize,
}

impl GadgetMarker {
    /// Maximum payload size (2GB ceiling)
    const MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024 * 1024;

    /// Create a new gadget marker with bounded data
    pub fn new(chain_name: &str, data: Vec<u8>) -> Option<Self> {
        if data.len() > Self::MAX_PAYLOAD_SIZE {
            return None; // Enforce 2GB ceiling
        }
        Some(Self {
            chain_name: chain_name.to_string(),
            serialized_data: data,
            max_payload_size: Self::MAX_PAYLOAD_SIZE,
        })
    }

    /// Create a CommonsCollections probe marker (benign)
    pub fn commons_collections_probe() -> Self {
        // Benign marker - harmless serialized object header
        // AC ED 00 05 = Serialization magic
        // 73 72 = TC_OBJECT, TC_CLASSDESC
        let marker_bytes = vec![
            0xAC, 0xED, // Serialization magic
            0x00, 0x05, // Version
            0x73, 0x72, // TC_OBJECT, TC_CLASSDESC
            0x00, 0x12, // Class name length
            b'J', b'a', b'v', b'a', b'S', b'e', b'r', b'i', 
            b'a', b'l', b'I', b'z', b'e', b'd', 0x00, // Marker class
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // serialVersionUID
        ];
        
        Self {
            chain_name: "CommonsCollections".to_string(),
            serialized_data: marker_bytes,
            max_payload_size: Self::MAX_PAYLOAD_SIZE,
        }
    }

    /// Create a JRE8u20 probe marker (benign)
    pub fn jre8u20_probe() -> Self {
        // Benign marker for JRE8u20 detection
        let marker_bytes = vec![
            0xAC, 0xED, // Serialization magic
            0x00, 0x05, // Version
            0x74, 0x00, // TC_STRING
            0x04, b'P', b'R', b'O', b'B', // Probe string
        ];

        Self {
            chain_name: "JRE8u20".to_string(),
            serialized_data: marker_bytes,
            max_payload_size: Self::MAX_PAYLOAD_SIZE,
        }
    }

    /// Get the serialized bytes (zero-copy reference)
    pub fn get_serialized_bytes(&self) -> &[u8] {
        &self.serialized_data
    }

    /// Get the chain name
    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }

    /// Check if payload exceeds bounds
    pub fn is_within_bounds(&self) -> bool {
        self.serialized_data.len() <= self.max_payload_size
    }

    /// Build a bounded payload for CommonsCollections1
    pub fn build_commonscollections1(target_class: &str) -> Option<Vec<u8>> {
        // Benign payload structure - no actual exploitation
        // This creates a bounded, safe probe payload
        let mut payload = Vec::with_capacity(256); // Bounded capacity
        
        // Serialization header
        payload.extend_from_slice(&[0xAC, 0xED, 0x00, 0x05]);
        
        // Object array marker
        payload.extend_from_slice(&[0x75, 0x72]);
        
        // Array type descriptor
        payload.extend_from_slice(&[0x00, 0x02]);
        payload.push(b'[' as u8);
        payload.push(b'L' as u8);
        
        // Target class name (bounded)
        let class_bytes = target_class.as_bytes();
        if class_bytes.len() > 200 {
            return None; // Enforce reasonable bound
        }
        
        payload.extend_from_slice(&[(class_bytes.len() >> 8) as u8, (class_bytes.len() & 0xFF) as u8]);
        payload.extend_from_slice(class_bytes);
        payload.push(0x00); // Null terminator
        
        // Instance count
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        
        Some(payload)
    }

    /// Build a bounded payload for BeanShell1 gadget
    pub fn build_beanshell1(script_snippet: &str) -> Option<Vec<u8>> {
        // Benign BeanShell probe - only validation scripts
        let valid_scripts = ["print(\"test\")", "1+1", "true"];
        if !valid_scripts.contains(&script_snippet) {
            return None; // Only allow benign scripts
        }

        let mut payload = Vec::with_capacity(128);
        
        // Header
        payload.extend_from_slice(&[0xAC, 0xED, 0x00, 0x05]);
        
        // Script marker
        payload.extend_from_slice(&[0x73, 0x63, 0x72]); // TC_OBJECT, marker
        
        let script_bytes = script_snippet.as_bytes();
        if script_bytes.len() > 100 {
            return None;
        }
        
        payload.extend_from_slice(&[(script_bytes.len() >> 8) as u8]);
        payload.extend_from_slice(&[(script_bytes.len() & 0xFF) as u8]);
        payload.extend_from_slice(script_bytes);
        
        Some(payload)
    }
}

/// Builder for Java deserialization test cases
#[derive(Debug)]
pub struct JavaPayloadBuilder {
    /// Current payload buffer
    buffer: Vec<u8>,
    /// Maximum buffer size
    max_size: usize,
}

impl JavaPayloadBuilder {
    /// Create a new payload builder
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            max_size: 2 * 1024 * 1024 * 1024, // 2GB ceiling
        }
    }

    /// Add a serialization header
    pub fn with_header(mut self) -> Self {
        self.buffer.extend_from_slice(&[0xAC, 0xED, 0x00, 0x05]);
        self
    }

    /// Add a class descriptor (bounded)
    pub fn with_class_descriptor(mut self, class_name: &str) -> Option<Self> {
        let bytes = class_name.as_bytes();
        if bytes.len() > 255 || self.buffer.len() + bytes.len() + 3 > self.max_size {
            return None;
        }
        
        self.buffer.push(0x73); // TC_OBJECT
        self.buffer.push(0x72); // TC_CLASSDESC
        self.buffer.extend_from_slice(&[(bytes.len() >> 8) as u8, (bytes.len() & 0xFF) as u8]);
        self.buffer.extend_from_slice(bytes);
        
        Some(self)
    }

    /// Build the final payload
    pub fn build(self) -> Vec<u8> {
        self.buffer
    }

    /// Get current buffer size
    pub fn current_size(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for JavaPayloadBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gadget_marker_creation() {
        let marker = GadgetMarker::commons_collections_probe();
        assert_eq!(marker.chain_name(), "CommonsCollections");
        assert!(marker.is_within_bounds());
    }

    #[test]
    fn test_bounded_payload() {
        let payload = GadgetMarker::build_commonscollections1("java.lang.String");
        assert!(payload.is_some());
        assert!(!payload.unwrap().is_empty());
    }

    #[test]
    fn test_payload_builder() {
        let builder = JavaPayloadBuilder::new()
            .with_header()
            .with_class_descriptor("test.Class")
            .unwrap();
        
        let payload = builder.build();
        assert!(!payload.is_empty());
    }
}
