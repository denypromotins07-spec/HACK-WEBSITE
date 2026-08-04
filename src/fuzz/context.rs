//! Fuzz Context - Injection context mapping for payload placement
//!
//! Maps payloads to appropriate injection contexts including HTML, JavaScript,
//! SQL, LDAP, XPath, shell commands, and HTTP headers.

use std::fmt;
use crate::payload::{InjectionContext, PayloadClass};

/// Detailed injection context with escaping rules
#[derive(Debug, Clone)]
pub struct InjectionContextDetail {
    pub name: &'static str,
    pub open_delimiter: &'static str,
    pub close_delimiter: &'static str,
    pub escape_char: &'static str,
    pub comment_start: &'static str,
    pub case_sensitive: bool,
    pub null_terminates: bool,
}

impl InjectionContextDetail {
    pub const fn new(
        name: &'static str,
        open: &'static str,
        close: &'static str,
        escape: &'static str,
        comment: &'static str,
        case_sensitive: bool,
        null_term: bool,
    ) -> Self {
        Self {
            name,
            open_delimiter: open,
            close_delimiter: close,
            escape_char: escape,
            comment_start: comment,
            case_sensitive,
            null_terminates: null_term,
        }
    }

    /// Get context detail from InjectionContext enum
    pub fn from_context(ctx: &InjectionContext) -> Option<Self> {
        match ctx {
            InjectionContext::HtmlBody => Some(Self::HTML_BODY),
            InjectionContext::HtmlAttribute => Some(Self::HTML_ATTR),
            InjectionContext::Javascript => Some(Self::JAVASCRIPT),
            InjectionContext::SqlQuery => Some(Self::SQL),
            InjectionContext::LdapQuery => Some(Self::LDAP),
            InjectionContext::XpathQuery => Some(Self::XPATH),
            InjectionContext::ShellCommand => Some(Self::SHELL),
            InjectionContext::Header => Some(Self::HEADER),
            _ => None,
        }
    }

    // Pre-defined context details
    pub const HTML_BODY: Self = Self::new("html-body", "", "", "", "<!--", false, false);
    pub const HTML_ATTR: Self = Self::new("html-attr", "\"", "\"", "\\", "<!--", false, false);
    pub const JAVASCRIPT: Self = Self::new("javascript", "'", "'", "\\", "//", true, false);
    pub const SQL: Self = Self::new("sql", "'", "'", "'", "--", false, false);
    pub const LDAP: Self = Self::new("ldap", "", "", "\\", "*", false, false);
    pub const XPATH: Self = Self::new("xpath", "'", "'", "'", "(:", false, false);
    pub const SHELL: Self = Self::new("shell", "", "", "\\", "#", true, true);
    pub const HEADER: Self = Self::new("header", "", "", "", "", true, false);
}

/// Context-aware payload wrapper
#[derive(Debug, Clone)]
pub struct ContextualPayload {
    pub original: String,
    pub contextualized: String,
    pub context: InjectionContext,
    pub break_out: bool,
}

impl ContextualPayload {
    pub fn new(payload: impl Into<String>, context: InjectionContext) -> Self {
        let original = payload.into();
        let contextualized = Self::apply_context(&original, &context);
        
        Self {
            original,
            contextualized,
            context,
            break_out: false,
        }
    }

    pub fn with_breakout(mut self, breakout: bool) -> Self {
        self.break_out = breakout;
        if breakout {
            self.contextualized = Self::break_out_of_context(&self.original, &self.context);
        }
        self
    }

    fn apply_context(payload: &str, context: &InjectionContext) -> String {
        match context {
            InjectionContext::UrlQuery => url_encode(payload),
            InjectionContext::UrlPath => path_encode(payload),
            InjectionContext::Header => header_encode(payload),
            InjectionContext::Cookie => cookie_encode(payload),
            InjectionContext::BodyJson => json_escape(payload),
            InjectionContext::BodyXml => xml_escape(payload),
            InjectionContext::BodyForm => payload.to_string(),
            InjectionContext::BodyMultipart => payload.to_string(),
            InjectionContext::HtmlBody => html_body_escape(payload),
            InjectionContext::HtmlAttribute => html_attr_escape(payload),
            InjectionContext::Javascript => js_escape(payload),
            InjectionContext::SqlQuery => sql_escape(payload),
            InjectionContext::LdapQuery => ldap_escape(payload),
            InjectionContext::XpathQuery => xpath_escape(payload),
            InjectionContext::ShellCommand => shell_escape(payload),
            InjectionContext::FilePath => payload.to_string(),
            InjectionContext::Unknown => payload.to_string(),
        }
    }

    fn break_out_of_context(payload: &str, context: &InjectionContext) -> String {
        match context {
            InjectionContext::HtmlBody => format!("</div>{}", payload),
            InjectionContext::HtmlAttribute => format!("\" onclick=\"alert(1)//{}", payload),
            InjectionContext::Javascript => format!("';alert(1);//{}", payload),
            InjectionContext::SqlQuery => format!("'; {} --", payload),
            InjectionContext::LdapQuery => format!(")(|({})", payload),
            InjectionContext::XpathQuery => format!("' or '1'='1{}", payload),
            InjectionContext::ShellCommand => format!("; {}", payload),
            InjectionContext::Header => format!("\r\nX-Injected: {}", payload),
            _ => payload.to_string(),
        }
    }
}

/// URL encode for query parameters
fn url_encode(s: &str) -> String {
    s.chars().flat_map(|c| {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => vec![c],
            ' ' => vec!['+'],
            _ => {
                let mut result = Vec::new();
                for byte in c.to_string().as_bytes() {
                    let hex = format!("%{:02X}", byte);
                    result.extend(hex.chars());
                }
                result
            }
        }
    }).collect()
}

/// Path encode for URL paths
fn path_encode(s: &str) -> String {
    s.chars().flat_map(|c| {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' | '/' => vec![c],
            _ => {
                let mut result = Vec::new();
                for byte in c.to_string().as_bytes() {
                    let hex = format!("%{:02X}", byte);
                    result.extend(hex.chars());
                }
                result
            }
        }
    }).collect()
}

/// Header value encoding
fn header_encode(s: &str) -> String {
    s.replace('\r', "%0D").replace('\n', "%0A")
}

/// Cookie value encoding
fn cookie_encode(s: &str) -> String {
    s.replace(';', "%3B").replace(',', "%2C")
}

/// JSON string escaping
fn json_escape(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            _ => result.push(c),
        }
    }
    result
}

/// XML entity escaping
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// HTML body content (minimal escaping needed)
fn html_body_escape(s: &str) -> String {
    s.to_string()
}

/// HTML attribute escaping
fn html_attr_escape(s: &str) -> String {
    s.replace('"', "&quot;")
        .replace('\'', "&#x27;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// JavaScript string escaping
fn js_escape(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '\'' => result.push_str("\\'"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '<' => result.push_str("\\x3C"),
            '>' => result.push_str("\\x3E"),
            _ => result.push(c),
        }
    }
    result
}

/// SQL string escaping (for safe payloads)
fn sql_escape(s: &str) -> String {
    s.replace('\'', "''")
}

/// LDAP filter escaping
fn ldap_escape(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            '*' => result.push_str("\\2a"),
            '(' => result.push_str("\\28"),
            ')' => result.push_str("\\29"),
            '\\' => result.push_str("\\5c"),
            '\0' => result.push_str("\\00"),
            _ => result.push(c),
        }
    }
    result
}

/// XPath string escaping
fn xpath_escape(s: &str) -> String {
    // XPath uses concat() for quotes
    if s.contains('\'') {
        format!("concat('{}')", s.replace('\'', "',\"'\",'"))
    } else {
        format!("'{}'", s)
    }
}

/// Shell command escaping
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Detect likely injection context from input location
pub fn infer_context(param_name: &str, param_value: &str, location: &str) -> InjectionContext {
    let name_lower = param_name.to_lowercase();
    
    // Check common parameter names
    if name_lower.contains("file") || name_lower.contains("path") {
        return InjectionContext::FilePath;
    }
    if name_lower.contains("cmd") || name_lower.contains("command") || name_lower.contains("exec") {
        return InjectionContext::ShellCommand;
    }
    if name_lower.contains("query") || name_lower.contains("search") || name_lower.contains("q") {
        return InjectionContext::SqlQuery;
    }
    if name_lower.contains("callback") || name_lower.contains("jsonp") {
        return InjectionContext::Javascript;
    }
    
    // Check value patterns
    if param_value.starts_with('{') || param_value.starts_with('[') {
        return InjectionContext::BodyJson;
    }
    if param_value.starts_with('<') {
        return InjectionContext::BodyXml;
    }
    
    // Check location
    match location {
        "header" => InjectionContext::Header,
        "cookie" => InjectionContext::Cookie,
        "path" => InjectionContext::UrlPath,
        "query" => InjectionContext::UrlQuery,
        "body" => InjectionContext::BodyForm,
        _ => InjectionContext::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contextual_payload_html() {
        let payload = ContextualPayload::new("<script>", InjectionContext::HtmlAttribute);
        assert!(payload.contextualized.contains("&lt;"));
    }

    #[test]
    fn test_contextual_payload_json() {
        let payload = ContextualPayload::new("\"test\"", InjectionContext::BodyJson);
        assert!(payload.contextualized.contains("\\\""));
    }

    #[test]
    fn test_breakout_sql() {
        let payload = ContextualPayload::new("1=1", InjectionContext::SqlQuery)
            .with_breakout(true);
        assert!(payload.contextualized.contains("';"));
    }

    #[test]
    fn test_ldap_escape() {
        let escaped = ldap_escape("user*admin");
        assert!(escaped.contains("\\2a"));
    }

    #[test]
    fn test_infer_context() {
        let ctx = infer_context("file", "/etc/passwd", "query");
        assert_eq!(ctx, InjectionContext::FilePath);
        
        let ctx = infer_context("cmd", "ls", "query");
        assert_eq!(ctx, InjectionContext::ShellCommand);
    }
}
