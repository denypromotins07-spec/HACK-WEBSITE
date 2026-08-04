//! Payload Encoder - URL, HTML, JSON, Unicode, hex, and double-encoding transformers
//!
//! Provides encoding transformations for payloads to bypass input validation
//! and WAF filters. Supports multiple encoding schemes with composable pipelines.

use std::fmt;

/// Supported encoding types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingType {
    /// URL encoding (%XX)
    Url,
    /// HTML entity encoding (&#xXX; or &name;)
    Html,
    /// HTML attribute encoding (quotes escaped)
    HtmlAttr,
    /// JavaScript Unicode escaping (\uXXXX)
    JavascriptUnicode,
    /// JavaScript hex escaping (\xXX)
    JavascriptHex,
    /// Base64 encoding
    Base64,
    /// Hex encoding (0x or raw hex)
    Hex,
    /// Unicode normalization forms
    UnicodeNfc,
    UnicodeNfd,
    UnicodeNfkc,
    UnicodeNfkd,
    /// Double encoding (encode twice)
    DoubleUrl,
    DoubleHtml,
    /// UTF-7 encoding
    Utf7,
    /// Overlong UTF-8 encoding
    OverlongUtf8,
    /// Custom encoding passthrough
    Passthrough,
}

impl fmt::Display for EncodingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodingType::Url => write!(f, "url"),
            EncodingType::Html => write!(f, "html"),
            EncodingType::HtmlAttr => write!(f, "html-attr"),
            EncodingType::JavascriptUnicode => write!(f, "js-unicode"),
            EncodingType::JavascriptHex => write!(f, "js-hex"),
            EncodingType::Base64 => write!(f, "base64"),
            EncodingType::Hex => write!(f, "hex"),
            EncodingType::UnicodeNfc => write!(f, "unicode-nfc"),
            EncodingType::UnicodeNfd => write!(f, "unicode-nfd"),
            EncodingType::UnicodeNfkc => write!(f, "unicode-nfkc"),
            EncodingType::UnicodeNfkd => write!(f, "unicode-nfkd"),
            EncodingType::DoubleUrl => write!(f, "double-url"),
            EncodingType::DoubleHtml => write!(f, "double-html"),
            EncodingType::Utf7 => write!(f, "utf7"),
            EncodingType::OverlongUtf8 => write!(f, "overlong-utf8"),
            EncodingType::Passthrough => write!(f, "passthrough"),
        }
    }
}

/// Encoder error types
#[derive(Debug, thiserror::Error)]
pub enum EncoderError {
    #[error("Invalid UTF-8 sequence")]
    InvalidUtf8,
    #[error("Encoding overflow")]
    Overflow,
    #[error("Unsupported encoding: {0}")]
    Unsupported(String),
    #[error("Encoding pipeline failed at step {step}: {reason}")]
    PipelineFailed { step: usize, reason: String },
}

/// Payload encoder with composable transformations
#[derive(Debug, Default)]
pub struct PayloadEncoder {
    encoding_chain: Vec<EncodingType>,
}

impl PayloadEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create encoder with a single encoding type
    pub fn with_encoding(encoding: EncodingType) -> Self {
        Self {
            encoding_chain: vec![encoding],
        }
    }

    /// Chain multiple encodings together
    pub fn chain(mut self, encodings: Vec<EncodingType>) -> Self {
        self.encoding_chain = encodings;
        self
    }

    /// Add an encoding to the chain
    pub fn add_encoding(mut self, encoding: EncodingType) -> Self {
        self.encoding_chain.push(encoding);
        self
    }

    /// Encode a payload through the encoding chain
    pub fn encode(&self, input: &str) -> Result<String, EncoderError> {
        let mut result = input.to_string();
        
        for (i, &encoding) in self.encoding_chain.iter().enumerate() {
            result = self.apply_encoding(&result, encoding)
                .map_err(|reason| EncoderError::PipelineFailed {
                    step: i,
                    reason,
                })?;
        }
        
        Ok(result)
    }

    /// Apply a single encoding transformation
    fn apply_encoding(&self, input: &str, encoding: EncodingType) -> Result<String, String> {
        match encoding {
            EncodingType::Url => Ok(url_encode(input)),
            EncodingType::Html => Ok(html_encode(input)),
            EncodingType::HtmlAttr => Ok(html_attr_encode(input)),
            EncodingType::JavascriptUnicode => Ok(js_unicode_encode(input)),
            EncodingType::JavascriptHex => Ok(js_hex_encode(input)),
            EncodingType::Base64 => Ok(base64_encode(input)),
            EncodingType::Hex => Ok(hex_encode(input)),
            EncodingType::UnicodeNfc => Ok(normalize_nfc(input)),
            EncodingType::UnicodeNfd => Ok(normalize_nfd(input)),
            EncodingType::UnicodeNfkc => Ok(normalize_nfkc(input)),
            EncodingType::UnicodeNfkd => Ok(normalize_nfkd(input)),
            EncodingType::DoubleUrl => Ok(url_encode(&url_encode(input))),
            EncodingType::DoubleHtml => Ok(html_encode(&html_encode(input))),
            EncodingType::Utf7 => Ok(utf7_encode(input)),
            EncodingType::OverlongUtf8 => Ok(overlong_utf8_encode(input)),
            EncodingType::Passthrough => Ok(input.to_string()),
        }
    }

    /// Encode for SQL injection context
    pub fn encode_for_sql(&self, input: &str) -> Result<String, EncoderError> {
        // SQL contexts often benefit from URL encoding and case variation
        self.encode(&input.to_uppercase())
    }

    /// Encode for XSS/HTML context
    pub fn encode_for_xss(&self, input: &str) -> Result<String, EncoderError> {
        // Try multiple encodings for XSS bypass
        let encoded = html_encode(input);
        let encoded = js_unicode_encode(&encoded);
        Ok(encoded)
    }

    /// Encode for command injection context
    pub fn encode_for_command(&self, input: &str) -> Result<String, EncoderError> {
        // Command injection often uses backslash escaping
        Ok(input.replace(' ', "${IFS}").replace('\'', "\\'"))
    }

    /// Encode for LDAP context
    pub fn encode_for_ldap(&self, input: &str) -> Result<String, EncoderError> {
        // LDAP special characters: * ( ) \ NUL
        let mut result = String::new();
        for c in input.chars() {
            match c {
                '*' => result.push_str("\\2a"),
                '(' => result.push_str("\\28"),
                ')' => result.push_str("\\29"),
                '\\' => result.push_str("\\5c"),
                '\0' => result.push_str("\\00"),
                _ => result.push(c),
            }
        }
        Ok(result)
    }

    /// Encode for XPath context
    pub fn encode_for_xpath(&self, input: &str) -> Result<String, EncoderError> {
        // XPath uses concat() for quote breaking
        Ok(input.replace('\'', "\',\"'\",'"))
    }

    /// Generate all encoding variants of a payload
    pub fn generate_variants(&self, input: &str) -> Vec<(EncodingType, String)> {
        use EncodingType::*;
        
        let encodings = vec![
            Url, Html, HtmlAttr, JavascriptUnicode, JavascriptHex,
            Base64, Hex, DoubleUrl, DoubleHtml, Utf7,
        ];
        
        encodings.into_iter()
            .filter_map(|enc| {
                self.encode_with_type(input, enc).ok().map(|s| (enc, s))
            })
            .collect()
    }

    /// Encode with a specific type (bypassing the chain)
    pub fn encode_with_type(&self, input: &str, encoding: EncodingType) -> Result<String, EncoderError> {
        self.apply_encoding(input, encoding)
            .map_err(|reason| EncoderError::Unsupported(reason))
    }
}

/// URL encode a string
fn url_encode(s: &str) -> String {
    let mut encoded = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => encoded.push(c),
            ' ' => encoded.push('+'),
            _ => {
                for byte in c.to_string().as_bytes() {
                    encoded.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    encoded
}

/// HTML entity encode a string
fn html_encode(s: &str) -> String {
    let mut encoded = String::new();
    for c in s.chars() {
        match c {
            '&' => encoded.push_str("&amp;"),
            '<' => encoded.push_str("&lt;"),
            '>' => encoded.push_str("&gt;"),
            '"' => encoded.push_str("&quot;"),
            '\'' => encoded.push_str("&#x27;"),
            '/' => encoded.push_str("&#x2F;"),
            '`' => encoded.push_str("&#x60;"),
            '=' => encoded.push_str("&#x3D;"),
            c if c.is_ascii_control() => {
                encoded.push_str(&format!("&#x{:02X};", c as u8));
            }
            _ => encoded.push(c),
        }
    }
    encoded
}

/// HTML attribute encode (stricter than body encoding)
fn html_attr_encode(s: &str) -> String {
    let mut encoded = String::new();
    for c in s.chars() {
        match c {
            '&' => encoded.push_str("&amp;"),
            '<' => encoded.push_str("&lt;"),
            '>' => encoded.push_str("&gt;"),
            '"' => encoded.push_str("&quot;"),
            '\'' => encoded.push_str("&#x27;"),
            '\n' => encoded.push_str("&#xA;"),
            '\r' => encoded.push_str("&#xD;"),
            '\t' => encoded.push_str("&#x9;"),
            _ => encoded.push(c),
        }
    }
    encoded
}

/// JavaScript Unicode escape encoding
fn js_unicode_encode(s: &str) -> String {
    let mut encoded = String::new();
    for c in s.chars() {
        match c {
            '\\' => encoded.push_str("\\\\"),
            '"' => encoded.push_str("\\\""),
            '\'' => encoded.push_str("\\'"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            c if c.is_ascii() && c < ' ' || c >= '\x7F' => {
                encoded.push_str(&format!("\\u{:04X}", c as u32));
            }
            _ => encoded.push(c),
        }
    }
    encoded
}

/// JavaScript hex escape encoding
fn js_hex_encode(s: &str) -> String {
    let mut encoded = String::new();
    for c in s.chars() {
        match c {
            '\\' => encoded.push_str("\\\\"),
            '"' => encoded.push_str("\\\""),
            '\'' => encoded.push_str("\\'"),
            c if c.is_ascii() && (c < ' ' || c >= '\x7F') => {
                encoded.push_str(&format!("\\x{:02X}", c as u8));
            }
            _ => encoded.push(c),
        }
    }
    encoded
}

/// Base64 encode a string
fn base64_encode(s: &str) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(s.as_bytes())
}

/// Hex encode a string
fn hex_encode(s: &str) -> String {
    s.bytes().fold(String::new(), |mut acc, b| {
        acc.push_str(&format!("{:02x}", b));
        acc
    })
}

/// Unicode normalization NFC
fn normalize_nfc(s: &str) -> String {
    // In production, use unicode-normalization crate
    s.to_string()
}

/// Unicode normalization NFD
fn normalize_nfd(s: &str) -> String {
    s.to_string()
}

/// Unicode normalization NFKC
fn normalize_nfkc(s: &str) -> String {
    s.to_string()
}

/// Unicode normalization NFKD
fn normalize_nfkd(s: &str) -> String {
    s.to_string()
}

/// UTF-7 encoding
fn utf7_encode(s: &str) -> String {
    // Simplified UTF-7 encoding
    let mut encoded = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == ' ' {
            encoded.push(c);
        } else {
            // Convert to UTF-16BE and base64
            let utf16: Vec<u16> = vec![c as u16];
            let bytes: Vec<u8> = utf16.iter().flat_map(|&u| u.to_be_bytes()).collect();
            use base64::{Engine, engine::general_purpose::STANDARD};
            encoded.push('+');
            encoded.push_str(&STANDARD.encode(&bytes).trim_end_matches('='));
            encoded.push('-');
        }
    }
    encoded
}

/// Overlong UTF-8 encoding (for bypass attempts)
fn overlong_utf8_encode(s: &str) -> String {
    // This is a simplified version - real overlong encoding is more complex
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encoding() {
        let encoder = PayloadEncoder::with_encoding(EncodingType::Url);
        let result = encoder.encode("<script>").unwrap();
        assert!(result.contains("%3C"));
        assert!(result.contains("%3E"));
    }

    #[test]
    fn test_html_encoding() {
        let encoder = PayloadEncoder::with_encoding(EncodingType::Html);
        let result = encoder.encode("<script>alert('XSS')</script>").unwrap();
        assert!(result.contains("&lt;"));
        assert!(result.contains("&gt;"));
        assert!(result.contains("&#x27;"));
    }

    #[test]
    fn test_double_encoding() {
        let encoder = PayloadEncoder::with_encoding(EncodingType::DoubleUrl);
        let result = encoder.encode("' OR 1=1 --").unwrap();
        // Double encoded should have %% patterns
        assert!(result.contains("%%") || result.len() > url_encode("' OR 1=1 --").len());
    }

    #[test]
    fn test_encoding_chain() {
        let encoder = PayloadEncoder::new()
            .chain(vec![EncodingType::Html, EncodingType::Url]);
        
        let result = encoder.encode("<img>").unwrap();
        // Should be HTML encoded then URL encoded
        assert!(!result.is_empty());
    }

    #[test]
    fn test_generate_variants() {
        let encoder = PayloadEncoder::new();
        let variants = encoder.generate_variants("<script>");
        
        assert!(!variants.is_empty());
        // Should have multiple encoding variants
        assert!(variants.len() >= 5);
    }

    #[test]
    fn test_base64_encoding() {
        let encoder = PayloadEncoder::with_encoding(EncodingType::Base64);
        let result = encoder.encode("hello").unwrap();
        assert_eq!(result, "aGVsbG8=");
    }
}
