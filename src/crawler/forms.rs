//! Form extraction - actions, input names, encodings, and implicit HTTP method expectations.
//!
//! This module parses HTML forms for security testing preparation.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// HTTP methods for form submission
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FormMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

impl Default for FormMethod {
    fn default() -> Self {
        FormMethod::Get
    }
}

impl From<&str> for FormMethod {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "post" => FormMethod::Post,
            "put" => FormMethod::Put,
            "delete" => FormMethod::Delete,
            "patch" => FormMethod::Patch,
            _ => FormMethod::Get,
        }
    }
}

/// Input field types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InputType {
    Text,
    Password,
    Email,
    Number,
    Tel,
    Url,
    Search,
    Date,
    Time,
    DateTimeLocal,
    Month,
    Week,
    Color,
    File,
    Hidden,
    Checkbox,
    Radio,
    Range,
    Submit,
    Reset,
    Button,
    Image,
    Unknown,
}

impl Default for InputType {
    fn default() -> Self {
        InputType::Text
    }
}

impl From<&str> for InputType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "password" => InputType::Password,
            "email" => InputType::Email,
            "number" => InputType::Number,
            "tel" => InputType::Tel,
            "url" => InputType::Url,
            "search" => InputType::Search,
            "date" => InputType::Date,
            "time" => InputType::Time,
            "datetime-local" => InputType::DateTimeLocal,
            "month" => InputType::Month,
            "week" => InputType::Week,
            "color" => InputType::Color,
            "file" => InputType::File,
            "hidden" => InputType::Hidden,
            "checkbox" => InputType::Checkbox,
            "radio" => InputType::Radio,
            "range" => InputType::Range,
            "submit" => InputType::Submit,
            "reset" => InputType::Reset,
            "button" => InputType::Button,
            "image" => InputType::Image,
            _ => InputType::Unknown,
        }
    }
}

/// Form input field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormInput {
    /// Input name
    pub name: Option<String>,
    /// Input type
    pub input_type: InputType,
    /// Default value
    pub value: Option<String>,
    /// Placeholder text
    pub placeholder: Option<String>,
    /// Whether field is required
    pub required: bool,
    /// Whether field is readonly
    pub readonly: bool,
    /// Whether field is disabled
    pub disabled: bool,
    /// Maximum length
    pub maxlength: Option<usize>,
    /// Pattern (regex)
    pub pattern: Option<String>,
    /// Autocomplete attribute
    pub autocomplete: Option<String>,
    /// Additional attributes
    pub attributes: HashMap<String, String>,
}

impl FormInput {
    pub fn new(name: Option<String>, input_type: InputType) -> Self {
        Self {
            name,
            input_type,
            value: None,
            placeholder: None,
            required: false,
            readonly: false,
            disabled: false,
            maxlength: None,
            pattern: None,
            autocomplete: None,
            attributes: HashMap::new(),
        }
    }

    /// Check if this input is likely to contain sensitive data
    pub fn is_sensitive(&self) -> bool {
        matches!(self.input_type, InputType::Password | InputType::File)
            || self.name.as_ref().map(|n| {
                let lower = n.to_lowercase();
                lower.contains("password") 
                    || lower.contains("secret")
                    || lower.contains("token")
                    || lower.contains("key")
                    || lower.contains("credit")
                    || lower.contains("ssn")
            }).unwrap_or(false)
    }

    /// Check if this is a submittable input
    pub fn is_submittable(&self) -> bool {
        !self.disabled 
            && self.name.is_some()
            && !matches!(self.input_type, InputType::Submit | InputType::Reset | InputType::Button)
    }
}

/// Discovered HTML form
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredForm {
    /// Form action URL
    pub action: String,
    /// Source page URL
    pub source_url: String,
    /// HTTP method
    pub method: FormMethod,
    /// Encoding type
    pub enctype: String,
    /// Form inputs
    pub inputs: Vec<FormInput>,
    /// Form ID if present
    pub form_id: Option<String>,
    /// Form classes
    pub classes: Vec<String>,
    /// Whether form has file upload
    pub has_file_upload: bool,
    /// Whether form uses multipart encoding
    pub is_multipart: bool,
    /// CSRF token field name (if detected)
    pub csrf_field: Option<String>,
    /// Additional attributes
    pub attributes: HashMap<String, String>,
}

impl DiscoveredForm {
    pub fn new(action: String, source_url: String) -> Self {
        Self {
            action,
            source_url,
            method: FormMethod::default(),
            enctype: "application/x-www-form-urlencoded".to_string(),
            inputs: Vec::new(),
            form_id: None,
            classes: Vec::new(),
            has_file_upload: false,
            is_multipart: false,
            csrf_field: None,
            attributes: HashMap::new(),
        }
    }

    /// Add an input to the form
    pub fn add_input(&mut self, input: FormInput) {
        // Detect file uploads
        if input.input_type == InputType::File {
            self.has_file_upload = true;
        }
        
        // Detect potential CSRF tokens
        if let Some(ref name) = input.name {
            let lower = name.to_lowercase();
            if lower.contains("csrf") 
                || lower.contains("token") 
                || lower.contains("_token")
                || lower == "authenticity_token"
                || lower == "xsrf-token"
            {
                self.csrf_field = Some(name.clone());
            }
        }
        
        self.inputs.push(input);
    }

    /// Get all submittable inputs
    pub fn submittable_inputs(&self) -> Vec<&FormInput> {
        self.inputs.iter().filter(|i| i.is_submittable()).collect()
    }

    /// Get sensitive inputs
    pub fn sensitive_inputs(&self) -> Vec<&FormInput> {
        self.inputs.iter().filter(|i| i.is_sensitive()).collect()
    }

    /// Build mutation payload structure
    pub fn mutation_template(&self) -> FormMutationTemplate {
        let mut fields = HashMap::new();
        
        for input in self.submittable_inputs() {
            if let Some(ref name) = input.name {
                let template = MutationFieldTemplate {
                    input_type: input.input_type.clone(),
                    required: input.required,
                    pattern: input.pattern.clone(),
                    maxlength: input.maxlength,
                    current_value: input.value.clone(),
                };
                fields.insert(name.clone(), template);
            }
        }
        
        FormMutationTemplate {
            action: self.action.clone(),
            method: self.method,
            enctype: self.enctype.clone(),
            fields,
        }
    }

    /// Check if form looks like a login form
    pub fn is_login_form(&self) -> bool {
        let has_username = self.inputs.iter().any(|i| {
            i.name.as_ref().map(|n| {
                let lower = n.to_lowercase();
                lower.contains("user") || lower.contains("login") || lower.contains("email")
            }).unwrap_or(false)
        });
        
        let has_password = self.inputs.iter().any(|i| {
            i.input_type == InputType::Password
        });
        
        has_username && has_password
    }

    /// Check if form looks like a registration form
    pub fn is_registration_form(&self) -> bool {
        let indicators = ["register", "signup", "sign-up", "create", "join"];
        
        self.form_id.as_ref().map(|id| {
            let lower = id.to_lowercase();
            indicators.iter().any(|i| lower.contains(i))
        }).unwrap_or(false)
            || self.classes.iter().any(|c| {
                let lower = c.to_lowercase();
                indicators.iter().any(|i| lower.contains(i))
            })
    }

    /// Check if form looks like a search form
    pub fn is_search_form(&self) -> bool {
        self.inputs.iter().any(|i| {
            i.name.as_ref().map(|n| {
                let lower = n.to_lowercase();
                lower == "q" || lower == "query" || lower == "search"
            }).unwrap_or(false)
        })
    }
}

/// Template for form mutation testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormMutationTemplate {
    pub action: String,
    pub method: FormMethod,
    pub enctype: String,
    pub fields: HashMap<String, MutationFieldTemplate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationFieldTemplate {
    pub input_type: InputType,
    pub required: bool,
    pub pattern: Option<String>,
    pub maxlength: Option<usize>,
    pub current_value: Option<String>,
}

/// Form extractor parser
pub struct FormExtractor;

impl FormExtractor {
    /// Extract forms from HTML content
    pub fn extract(html: &str, source_url: &str) -> Vec<DiscoveredForm> {
        let mut forms = Vec::new();
        
        // Find form tags
        let form_starts: Vec<usize> = find_all_case_insensitive(html, "<form");
        
        for start in form_starts {
            if let Some(form_html) = extract_tag_content(html, start, "</form>") {
                if let Some(mut form) = parse_form(&form_html, source_url) {
                    // Extract inputs within this form
                    form.inputs = Self::extract_inputs(&form_html);
                    forms.push(form);
                }
            }
        }
        
        forms
    }

    /// Extract inputs from HTML
    fn extract_inputs(html: &str) -> Vec<FormInput> {
        let mut inputs = Vec::new();
        
        // Find input tags
        let input_starts: Vec<usize> = find_all_case_insensitive(html, "<input");
        
        for start in input_starts {
            if let Some(tag_html) = extract_self_closing_tag(html, start) {
                if let Some(input) = parse_input(&tag_html) {
                    inputs.push(input);
                }
            }
        }
        
        // Find textarea tags
        let textarea_starts: Vec<usize> = find_all_case_insensitive(html, "<textarea");
        
        for start in textarea_starts {
            if let Some(tag_html) = extract_tag_content(html, start, "</textarea>") {
                if let Some(input) = parse_textarea(&tag_html) {
                    inputs.push(input);
                }
            }
        }
        
        // Find select tags
        let select_starts: Vec<usize> = find_all_case_insensitive(html, "<select");
        
        for start in select_starts {
            if let Some(tag_html) = extract_tag_content(html, start, "</select>") {
                if let Some(input) = parse_select(&tag_html) {
                    inputs.push(input);
                }
            }
        }
        
        inputs
    }
}

/// Parse a form tag
fn parse_form(html: &str, source_url: &str) -> Option<DiscoveredForm> {
    // Extract action attribute
    let action = extract_attr(html, "action")
        .unwrap_or_else(|| "/".to_string());
    
    // Resolve relative action against source
    let resolved_action = resolve_url(&action, source_url);
    
    let mut form = DiscoveredForm::new(resolved_action, source_url.to_string());
    
    // Extract method
    if let Some(method) = extract_attr(html, "method") {
        form.method = FormMethod::from(method.as_str());
    }
    
    // Extract enctype
    if let Some(enctype) = extract_attr(html, "enctype") {
        form.enctype = enctype;
        form.is_multipart = enctype.contains("multipart");
    }
    
    // Extract id
    form.form_id = extract_attr(html, "id");
    
    // Extract class
    if let Some(classes) = extract_attr(html, "class") {
        form.classes = classes.split_whitespace().map(String::from).collect();
    }
    
    Some(form)
}

/// Parse an input tag
fn parse_input(html: &str) -> Option<FormInput> {
    let name = extract_attr(html, "name");
    let input_type = extract_attr(html, "type")
        .map(|t| InputType::from(t.as_str()))
        .unwrap_or_default();
    
    let mut input = FormInput::new(name, input_type);
    
    input.value = extract_attr(html, "value");
    input.placeholder = extract_attr(html, "placeholder");
    input.required = has_attr(html, "required");
    input.readonly = has_attr(html, "readonly");
    input.disabled = has_attr(html, "disabled");
    
    if let Some(maxlen) = extract_attr(html, "maxlength") {
        input.maxlength = maxlen.parse().ok();
    }
    
    input.pattern = extract_attr(html, "pattern");
    input.autocomplete = extract_attr(html, "autocomplete");
    
    Some(input)
}

/// Parse a textarea tag
fn parse_textarea(html: &str) -> Option<FormInput> {
    let name = extract_attr(html, "name");
    let mut input = FormInput::new(name, InputType::Text);
    
    input.placeholder = extract_attr(html, "placeholder");
    input.required = has_attr(html, "required");
    input.readonly = has_attr(html, "readonly");
    input.disabled = has_attr(html, "disabled");
    
    if let Some(maxlen) = extract_attr(html, "maxlength") {
        input.maxlength = maxlen.parse().ok();
    }
    
    // Extract content as value
    if let Some(close_pos) = html.find("</textarea>") {
        let content = html[..close_pos].trim();
        if let Some(>pos) = content.find('>') {
            let value = content[>pos + 1..].trim();
            if !value.is_empty() {
                input.value = Some(value.to_string());
            }
        }
    }
    
    Some(input)
}

/// Parse a select tag
fn parse_select(html: &str) -> Option<FormInput> {
    let name = extract_attr(html, "name");
    let mut input = FormInput::new(name, InputType::Unknown); // Select doesn't map directly
    
    input.required = has_attr(html, "required");
    input.disabled = has_attr(html, "disabled");
    
    Some(input)
}

/// Extract attribute value from HTML tag
fn extract_attr(html: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{}=", attr_name);
    let html_lower = html.to_lowercase();
    let pattern_lower = pattern.to_lowercase();
    
    if let Some(pos) = html_lower.find(&pattern_lower) {
        let after_eq = pos + pattern.len();
        let rest = &html[after_eq..];
        
        // Skip whitespace
        let rest = rest.trim_start();
        
        if rest.starts_with('"') {
            if let Some(end) = rest[1..].find('"') {
                return Some(rest[1..end + 1].to_string());
            }
        } else if rest.starts_with('\'') {
            if let Some(end) = rest[1..].find('\'') {
                return Some(rest[1..end + 1].to_string());
            }
        } else {
            // Unquoted attribute
            let end = rest.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(rest.len());
            return Some(rest[..end].to_string());
        }
    }
    
    None
}

/// Check if attribute exists (boolean attributes)
fn has_attr(html: &str, attr_name: &str) -> bool {
    let html_lower = html.to_lowercase();
    let attr_lower = attr_name.to_lowercase();
    
    // Check for attr= or just attr followed by space/>
    html_lower.contains(&format!("{}=", attr_lower))
        || html_lower.contains(&format!(" {}>", attr_lower))
        || html_lower.contains(&format!(" {}/>", attr_lower))
}

/// Find all occurrences of a substring (case-insensitive)
fn find_all_case_insensitive(haystack: &str, needle: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let haystack_lower = haystack.to_lowercase();
    let needle_lower = needle.to_lowercase();
    
    let mut start = 0;
    while let Some(pos) = haystack_lower[start..].find(&needle_lower) {
        positions.push(start + pos);
        start += pos + 1;
    }
    
    positions
}

/// Extract content between opening tag at position and closing tag
fn extract_tag_content(html: &str, open_pos: usize, close_tag: &str) -> Option<&str> {
    // Find the end of opening tag
    let tag_end = html[open_pos..].find('>')? + open_pos + 1;
    
    // Find closing tag
    let close_pos = html[tag_end..].find(close_tag)? + tag_end;
    
    Some(&html[tag_end..close_pos])
}

/// Extract self-closing tag content
fn extract_self_closing_tag(html: &str, start: usize) -> Option<&str> {
    let end = html[start..].find('>')? + start + 1;
    Some(&html[start..end])
}

/// Resolve URL against base
fn resolve_url(url: &str, base: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        return url.to_string();
    }
    
    if let Ok(base_parsed) = url::Url::parse(base) {
        if let Ok(resolved) = base_parsed.join(url) {
            return resolved.to_string();
        }
    }
    
    if url.starts_with('/') {
        // Absolute path - try to get base origin
        if let Ok(base_parsed) = url::Url::parse(base) {
            if let Some(host) = base_parsed.host_str() {
                return format!("{}://{}{}", base_parsed.scheme(), host, url);
            }
        }
        return url.to_string();
    }
    
    // Relative path - append to base path
    if let Ok(base_parsed) = url::Url::parse(base) {
        if let Some(mut segments) = base_parsed.path_segments() {
            let mut path = String::new();
            for seg in &mut segments {
                path.push('/');
                path.push_str(seg);
            }
            path.push('/');
            path.push_str(url);
            return path;
        }
    }
    
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_simple_form() {
        let html = r#"
            <form action="/login" method="post">
                <input type="text" name="username" required>
                <input type="password" name="password" required>
                <input type="submit" value="Login">
            </form>
        "#;
        
        let forms = FormExtractor::extract(html, "http://example.com");
        
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, FormMethod::Post);
        assert!(forms[0].is_login_form());
    }

    #[test]
    fn test_detect_csrf_token() {
        let html = r#"
            <form action="/submit" method="post">
                <input type="hidden" name="_csrf_token" value="abc123">
                <input type="text" name="data">
            </form>
        "#;
        
        let forms = FormExtractor::extract(html, "http://example.com");
        
        assert_eq!(forms.len(), 1);
        assert!(forms[0].csrf_field.is_some());
    }

    #[test]
    fn test_form_method_parsing() {
        assert_eq!(FormMethod::from("GET"), FormMethod::Get);
        assert_eq!(FormMethod::from("POST"), FormMethod::Post);
        assert_eq!(FormMethod::from("post"), FormMethod::Post);
        assert_eq!(FormMethod::from("PUT"), FormMethod::Put);
    }

    #[test]
    fn test_sensitive_input_detection() {
        let input = FormInput::new(Some("password".to_string()), InputType::Password);
        assert!(input.is_sensitive());
        
        let input2 = FormInput::new(Some("credit_card".to_string()), InputType::Text);
        assert!(input2.is_sensitive());
        
        let input3 = FormInput::new(Some("username".to_string()), InputType::Text);
        assert!(!input3.is_sensitive());
    }
}
