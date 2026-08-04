//! Redaction utilities for preventing secret exposure.
//!
//! Provides mechanisms to sanitize logs, reports, and debug output
//! by removing or masking sensitive information.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Default patterns to redact from output.
const DEFAULT_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "private_key",
    "access_token",
    "refresh_token",
    "bearer",
];

/// Sensitive header names to redact.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
    "www-authenticate",
];

/// Redaction state shared across threads.
#[derive(Clone, Debug)]
pub struct Redactor {
    /// Patterns to match for redaction.
    patterns: Arc<RwLock<HashSet<String>>>,
    /// Custom replacement string.
    replacement: Arc<RwLock<String>>,
    /// Enable/disable redaction.
    enabled: Arc<RwLock<bool>>,
}

impl Default for Redactor {
    fn default() -> Self {
        let patterns: HashSet<String> = DEFAULT_PATTERNS.iter().map(|s| s.to_string()).collect();
        Self {
            patterns: Arc::new(RwLock::new(patterns)),
            replacement: Arc::new(RwLock::new("[REDACTED]".to_string())),
            enabled: Arc::new(RwLock::new(true)),
        }
    }
}

impl Redactor {
    /// Create a new redactor with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pattern to redact.
    pub fn add_pattern(&self, pattern: &str) {
        if let Ok(mut patterns) = self.patterns.write() {
            patterns.insert(pattern.to_lowercase());
        }
    }

    /// Remove a pattern from redaction.
    pub fn remove_pattern(&self, pattern: &str) {
        if let Ok(mut patterns) = self.patterns.write() {
            patterns.remove(&pattern.to_lowercase());
        }
    }

    /// Set the replacement string for redacted content.
    pub fn set_replacement(&self, replacement: &str) {
        if let Ok(mut repl) = self.replacement.write() {
            *repl = replacement.to_string();
        }
    }

    /// Enable or disable redaction.
    pub fn set_enabled(&self, enabled: bool) {
        if let Ok(mut e) = self.enabled.write() {
            *e = enabled;
        }
    }

    /// Check if redaction is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.read().map(|e| *e).unwrap_or(true)
    }

    /// Redact a string value.
    pub fn redact(&self, input: &str) -> String {
        if !self.is_enabled() {
            return input.to_string();
        }

        let patterns = self.patterns.read().ok().map(|p| p.clone()).unwrap_or_default();
        let replacement = self.replacement.read().ok().map(|r| r.clone()).unwrap_or_else(|| "[REDACTED]".to_string());
        
        let mut result = input.to_string();
        
        for pattern in &patterns {
            // Case-insensitive replacement
            let lower_result = result.to_lowercase();
            if let Some(pos) = lower_result.find(pattern) {
                // Find the actual substring in original case
                if let Some(actual_pattern) = extract_sensitive_value(&result, pos, pattern.len()) {
                    result = result.replace(&actual_pattern, &replacement);
                }
            }
        }
        
        // Also redact common value patterns (API keys, tokens, etc.)
        result = redact_common_patterns(&result, &replacement);
        
        result
    }

    /// Redact sensitive headers from a header map representation.
    pub fn redact_headers(&self, headers: &[(String, String)]) -> Vec<(String, String)> {
        let sensitive: HashSet<String> = SENSITIVE_HEADERS.iter().map(|s| s.to_lowercase()).collect();
        let replacement = self.replacement.read().ok().map(|r| r.clone()).unwrap_or_else(|| "[REDACTED]".to_string());
        
        headers
            .iter()
            .map(|(key, value)| {
                if sensitive.contains(&key.to_lowercase()) {
                    (key.clone(), replacement.clone())
                } else {
                    (key.clone(), self.redact(value))
                }
            })
            .collect()
    }

    /// Redact query parameters that might contain secrets.
    pub fn redact_query(&self, query: &str) -> String {
        let replacement = self.replacement.read().ok().map(|r| r.clone()).unwrap_or_else(|| "[REDACTED]".to_string());
        let patterns = self.patterns.read().ok().map(|p| p.clone()).unwrap_or_default();
        
        query
            .split('&')
            .map(|pair| {
                if let Some((key, _)) = pair.split_once('=') {
                    if patterns.contains(&key.to_lowercase()) 
                        || key.to_lowercase().contains("token")
                        || key.to_lowercase().contains("key")
                        || key.to_lowercase().contains("secret")
                        || key.to_lowercase().contains("password")
                    {
                        return format!("{}={}", key, replacement);
                    }
                }
                pair.to_string()
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    /// Create a sanitized version of a URL.
    pub fn redact_url(&self, url: &str) -> String {
        if let Some((base, query)) = url.split_once('?') {
            format!("{}?{}", base, self.redact_query(query))
        } else {
            url.to_string()
        }
    }

    /// Sanitize a log message.
    pub fn sanitize_log(&self, message: &str) -> String {
        self.redact(message)
    }
}

/// Extract the actual sensitive value from the string at the given position.
fn extract_sensitive_value(s: &str, start: usize, pattern_len: usize) -> Option<String> {
    let bytes = s.as_bytes();
    if start + pattern_len > bytes.len() {
        return None;
    }
    
    // Look for the value after '=' or ':' or whitespace
    let search_start = start.saturating_sub(1);
    let search_end = (start + pattern_len + 64).min(bytes.len()); // Assume value is within 64 chars
    
    // Simple heuristic: find quoted strings or values until whitespace/special char
    let substring = &s[search_start..search_end];
    
    // Try to extract value after common delimiters
    for delimiter in ['=', ':', ' '] {
        if let Some(val_start) = substring.find(delimiter) {
            let val_part = &substring[val_start + 1..];
            let val_trimmed = val_part.trim_start();
            
            // Check for quoted value
            if val_trimmed.starts_with('"') || val_trimmed.starts_with('\'') {
                let quote = val_trimmed.chars().next()?;
                if let Some(end_quote) = val_trimmed[1..].find(quote) {
                    return Some(val_trimmed[1..end_quote + 1].to_string());
                }
            }
            
            // Unquoted value until whitespace or special char
            let end_pos = val_trimmed.find(|c: char| c.is_whitespace() || c == '&' || c == '"' || c == '\'')
                .unwrap_or(val_trimmed.len());
            
            if end_pos > 0 && end_pos <= 64 {
                return Some(val_trimmed[..end_pos].to_string());
            }
        }
    }
    
    None
}

/// Redact common patterns like API keys, JWT tokens, etc.
fn redact_common_patterns(input: &str, replacement: &str) -> String {
    let mut result = input.to_string();
    
    // Redact JWT tokens (three base64 segments separated by dots)
    let jwt_pattern = regex_lite::Regex::new(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")
        .unwrap();
    result = jwt_pattern.replace_all(&result, replacement).to_string();
    
    // Redact UUID-like patterns that might be API keys
    let uuid_pattern = regex_lite::Regex::new(r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")
        .unwrap();
    result = uuid_pattern.replace_all(&result, replacement).to_string();
    
    // Redact long alphanumeric strings that look like API keys (32+ chars)
    let api_key_pattern = regex_lite::Regex::new(r"[a-zA-Z0-9_\-]{32,}")
        .unwrap();
    result = api_key_pattern.replace_all(&result, replacement).to_string();
    
    result
}

/// Global redactor instance for convenience.
lazy_static::lazy_static! {
    pub static ref GLOBAL_REDACTOR: Redactor = Redactor::default();
}

/// Convenience function to redact using the global redactor.
pub fn redact(input: &str) -> String {
    GLOBAL_REDACTOR.redact(input)
}

/// Convenience function to redact a URL using the global redactor.
pub fn redact_url(url: &str) -> String {
    GLOBAL_REDACTOR.redact_url(url)
}

/// Minimal regex implementation without heavy dependencies.
mod regex_lite {
    use std::fmt;
    
    pub struct Regex {
        pattern: String,
    }
    
    impl Regex {
        pub fn new(pattern: &str) -> Result<Self, ()> {
            Ok(Self {
                pattern: pattern.to_string(),
            })
        }
        
        pub fn replace_all(&self, text: &str, replacement: &str) -> CowStr {
            // Simple pattern matching for common cases
            if self.pattern.contains("eyJ") && self.pattern.contains('.') {
                // JWT pattern - match base64url sequences with dots
                return replace_jwt(text, replacement);
            }
            
            if self.pattern.contains("[a-fA-F0-9]") && self.pattern.contains('-') {
                // UUID pattern
                return replace_uuid(text, replacement);
            }
            
            if self.pattern.contains("[a-zA-Z0-9]") && self.pattern.contains("{32,}") {
                // Long alphanumeric pattern
                return replace_long_alphanumeric(text, replacement);
            }
            
            CowStr::Borrowed(text)
        }
    }
    
    impl fmt::Debug for Regex {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Regex({})", self.pattern)
        }
    }
    
    pub enum CowStr {
        Borrowed(&'static str),
        Owned(String),
    }
    
    impl CowStr {
        pub fn to_string(&self) -> String {
            match self {
                CowStr::Borrowed(s) => s.to_string(),
                CowStr::Owned(s) => s.clone(),
            }
        }
    }
    
    fn replace_jwt(text: &str, replacement: &str) -> CowStr {
        let mut result = String::new();
        let mut last_end = 0;
        
        for (i, byte) in text.bytes().enumerate() {
            if byte == b'e' && i + 2 < text.len() && &text[i..i+3] == "eyJ" {
                // Found potential JWT start, look for two dots
                if let Some(end) = find_jwt_end(&text[i..]) {
                    if i > last_end {
                        result.push_str(&text[last_end..i]);
                    }
                    result.push_str(replacement);
                    last_end = i + end;
                }
            }
        }
        
        if last_end > 0 {
            result.push_str(&text[last_end..]);
            CowStr::Owned(result)
        } else {
            CowStr::Borrowed(text)
        }
    }
    
    fn find_jwt_end(text: &str) -> Option<usize> {
        let mut dot_count = 0;
        let mut i = 0;
        
        for c in text.chars() {
            if c == '.' {
                dot_count += 1;
                if dot_count == 2 {
                    // Continue until non-base64url char
                    i += c.len_utf8();
                    while i < text.len() {
                        let ch = text[i..].chars().next()?;
                        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' {
                            return Some(i);
                        }
                        i += ch.len_utf8();
                    }
                    return Some(text.len());
                }
            } else if !c.is_ascii_alphanumeric() && c != '_' && c != '-' {
                return None;
            }
            i += c.len_utf8();
        }
        
        None
    }
    
    fn replace_uuid(text: &str, replacement: &str) -> CowStr {
        let uuid_pattern = |s: &str| -> bool {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() != 5 {
                return false;
            }
            parts[0].len() == 8 && parts[1].len() == 4 && parts[2].len() == 4
                && parts[3].len() == 4 && parts[4].len() == 12
                && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
        };
        
        let mut result = String::new();
        let mut last_end = 0;
        let chars: Vec<char> = text.chars().collect();
        let uuid_len = 36; // 8+1+4+1+4+1+4+1+12
        
        for i in 0..chars.len().saturating_sub(uuid_len - 1) {
            let candidate: String = chars[i..i + uuid_len].iter().collect();
            if uuid_pattern(&candidate) {
                if i > last_end {
                    result.push_str(&text[last_end..i]);
                }
                result.push_str(replacement);
                last_end = i + uuid_len;
            }
        }
        
        if last_end > 0 {
            result.push_str(&text[last_end..]);
            CowStr::Owned(result)
        } else {
            CowStr::Borrowed(text)
        }
    }
    
    fn replace_long_alphanumeric(text: &str, replacement: &str) -> CowStr {
        let mut result = String::new();
        let mut current_run = String::new();
        
        for c in text.chars() {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                current_run.push(c);
            } else {
                if current_run.len() >= 32 {
                    result.push_str(replacement);
                } else {
                    result.push_str(&current_run);
                }
                result.push(c);
                current_run.clear();
            }
        }
        
        if current_run.len() >= 32 {
            result.push_str(replacement);
        } else {
            result.push_str(&current_run);
        }
        
        CowStr::Owned(result)
    }
}
