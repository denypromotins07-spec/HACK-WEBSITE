//! XSS Context Module
//! 
//! Defines output contexts for XSS vulnerability classification.

/// XSS output context enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XssContext {
    /// HTML body context (needs HTML entity encoding)
    Html,
    /// JavaScript code context (needs JS escaping)
    JavaScript,
    /// HTML attribute context (needs attribute encoding)
    Attribute,
    /// URL context (needs URL encoding)
    Url,
    /// Event handler context (needs special handling)
    EventHandler,
    /// CSS context (needs CSS escaping)
    Css,
}

impl XssContext {
    /// Check if this context is dangerous for XSS
    pub fn is_dangerous(&self) -> bool {
        matches!(
            self,
            XssContext::JavaScript | XssContext::EventHandler | XssContext::Attribute
        )
    }

    /// Get recommended encoding strategy for this context
    pub fn get_encoding_strategy(&self) -> &'static str {
        match self {
            XssContext::Html => "HTML entity encoding (&#x26;)",
            XssContext::JavaScript => "JavaScript Unicode escaping (\\uXXXX)",
            XssContext::Attribute => "HTML entity encoding with quote escaping",
            XssContext::Url => "URL percent encoding",
            XssContext::EventHandler => "JavaScript escaping + HTML entity encoding",
            XssContext::Css => "CSS hex escaping (\\XX)",
        }
    }
}
