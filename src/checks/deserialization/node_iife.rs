//! Node.js IIFE Builder
//! Builds safe immediately-invoked function expressions for timing and OOB validation.

/// Builder for safe IIFE (Immediately Invoked Function Expression) payloads
#[derive(Debug, Clone)]
pub struct NodeIifeBuilder {
    /// Maximum payload size (2GB ceiling)
    max_payload_size: usize,
    /// Callback URL for OOB testing
    callback_url: Option<String>,
}

/// A generated IIFE payload
#[derive(Debug, Clone)]
pub struct IifePayload {
    /// JavaScript code string
    pub code: String,
    /// Payload type
    pub payload_type: IifeType,
    /// Expected result (benign)
    pub expected_result: String,
    /// Size in bytes
    pub size: usize,
}

/// Type of IIFE payload
#[derive(Debug, Clone, PartialEq)]
pub enum IifeType {
    /// Timing-based verification
    Timing,
    /// OOB callback verification
    OobCallback,
    /// Simple return value
    ReturnValue,
    /// Error trigger (safe)
    ErrorTrigger,
}

impl NodeIifeBuilder {
    /// Create a new IIFE builder
    pub fn new() -> Self {
        Self {
            max_payload_size: 2 * 1024 * 1024 * 1024, // 2GB ceiling
            callback_url: None,
        }
    }

    /// Build a timing-based IIFE payload
    pub fn build_timing_payload(&self) -> Option<IifePayload> {
        // Safe timing probe - measures execution time without side effects
        let code = r#"(function(){var start=Date.now();for(var i=0;i<1000;i++){Math.sqrt(i);}return Date.now()-start;})()"#.to_string();

        if code.len() > self.max_payload_size {
            return None;
        }

        Some(IifePayload {
            code: code.clone(),
            payload_type: IifeType::Timing,
            expected_result: "number".to_string(),
            size: code.len(),
        })
    }

    /// Build an OOB callback verification payload
    pub fn build_oob_payload(&self, token: &str) -> Option<IifePayload> {
        // Validate token is safe
        if token.len() > 64 || token.is_empty() {
            return None;
        }

        // Only alphanumeric tokens allowed
        if !token.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }

        let callback = self.callback_url.as_deref().unwrap_or("http://localhost");
        
        // Benign callback - just fetches a URL with token
        // Does not execute any harmful commands
        let code = format!(
            r#"(function(){{var t="{}";fetch("{}?token="+t).catch(()=>{{}});return "sent";}})()"#,
            token,
            callback
        );

        if code.len() > self.max_payload_size {
            return None;
        }

        Some(IifePayload {
            code,
            payload_type: IifeType::OobCallback,
            expected_result: "sent".to_string(),
            size: code.len(),
        })
    }

    /// Build a simple return value payload
    pub fn build_return_payload(&self, value: &str) -> Option<IifePayload> {
        // Only allow safe return values
        let safe_values = ["true", "false", "null", "undefined", "0", "1", "-1"];
        if !safe_values.contains(&value) && value.len() > 32 {
            return None;
        }

        // Validate alphanumeric only for custom values
        if !safe_values.contains(&value) {
            if !value.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return None;
            }
        }

        let code = format!(r#"(function(){{return "{}";}})()"#, value);

        if code.len() > self.max_payload_size {
            return None;
        }

        Some(IifePayload {
            code,
            payload_type: IifeType::ReturnValue,
            expected_result: value.to_string(),
            size: code.len(),
        })
    }

    /// Build a safe error-triggering payload
    pub fn build_error_payload(&self) -> Option<IifePayload> {
        // Safe error that doesn't cause system issues
        let code = r#"(function(){try{throw new Error("SAFE_ERROR_TEST");}catch(e){return e.message;}})()"#.to_string();

        if code.len() > self.max_payload_size {
            return None;
        }

        Some(IifePayload {
            code,
            payload_type: IifeType::ErrorTrigger,
            expected_result: "SAFE_ERROR_TEST".to_string(),
            size: code.len(),
        })
    }

    /// Analyze IIFE payload for safety
    pub fn analyze_safety(&self, code: &str) -> SafetyReport {
        let mut report = SafetyReport {
            is_safe: true,
            dangerous_patterns: Vec::new(),
            warnings: Vec::new(),
        };

        // Check for dangerous patterns
        let dangerous: [(&str, &str); 12] = [
            ("require(", "Module loading"),
            ("eval(", "Eval execution"),
            ("Function(", "Function constructor"),
            ("child_process", "Child process access"),
            ("exec(", "Command execution"),
            ("execSync(", "Sync command execution"),
            ("spawn(", "Process spawning"),
            ("fs.", "Filesystem access"),
            ("readFileSync", "Sync file read"),
            ("writeFileSync", "Sync file write"),
            ("http.request", "HTTP request"),
            ("https.request", "HTTPS request"),
        ];

        for (pattern, description) in dangerous.iter() {
            if code.contains(pattern) {
                report.is_safe = false;
                report.dangerous_patterns.push(format!("{}: {}", pattern, description));
            }
        }

        // Check for obfuscation attempts
        if code.contains("\\x") || code.contains("\\u") {
            report.warnings.push("Possible encoding/obfuscation detected".to_string());
        }

        // Check for very long code (potential payload hiding)
        if code.len() > 10000 {
            report.warnings.push("Unusually large payload".to_string());
        }

        report
    }

    /// Set callback URL for OOB tests
    pub fn with_callback_url(mut self, url: &str) -> Self {
        self.callback_url = Some(url.to_string());
        self
    }

    /// Get maximum payload size
    pub fn max_payload_size(&self) -> usize {
        self.max_payload_size
    }
}

impl Default for NodeIifeBuilder {
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
    fn test_builder_creation() {
        let builder = NodeIifeBuilder::new();
        assert_eq!(builder.max_payload_size(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_timing_payload() {
        let builder = NodeIifeBuilder::new();
        let payload = builder.build_timing_payload();
        
        assert!(payload.is_some());
        let p = payload.unwrap();
        assert_eq!(p.payload_type, IifeType::Timing);
        assert!(p.code.starts_with("(function()"));
    }

    #[test]
    fn test_return_payload() {
        let builder = NodeIifeBuilder::new();
        let payload = builder.build_return_payload("true");
        
        assert!(payload.is_some());
        assert_eq!(payload.unwrap().expected_result, "true");
    }

    #[test]
    fn test_safety_analysis() {
        let builder = NodeIifeBuilder::new();
        
        // Safe code
        let safe_code = r#"(function(){return "hello";})()"#;
        let report = builder.analyze_safety(safe_code);
        assert!(report.is_safe);

        // Dangerous code
        let dangerous_code = r#"(function(){require('child_process').exec('ls');})()"#;
        let report = builder.analyze_safety(dangerous_code);
        assert!(!report.is_safe);
        assert!(report.dangerous_patterns.iter().any(|p| p.contains("require")));
    }
}
