//! Link extraction from HTML, JavaScript, JSON, XML, and CSS using zero-copy slices.
//!
//! This module provides high-performance parsing for discovering URLs and endpoints
//! in various content types encountered during crawling.

use std::borrow::Cow;
use memchr::memmem;

/// Extraction result containing discovered URLs and metadata
#[derive(Debug, Clone)]
pub struct ExtractionResult {
    /// Discovered URLs
    pub urls: Vec<String>,
    /// Form actions
    pub form_actions: Vec<String>,
    /// Script sources
    pub script_sources: Vec<String>,
    /// API endpoints found in JS/JSON
    pub api_endpoints: Vec<String>,
    /// Asset URLs (images, CSS, etc.)
    pub assets: Vec<String>,
}

impl Default for ExtractionResult {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtractionResult {
    pub fn new() -> Self {
        Self {
            urls: Vec::new(),
            form_actions: Vec::new(),
            script_sources: Vec::new(),
            api_endpoints: Vec::new(),
            assets: Vec::new(),
        }
    }

    pub fn url_count(&self) -> usize {
        self.urls.len() + self.form_actions.len() + self.api_endpoints.len()
    }
}

/// High-performance link extractor
pub struct LinkExtractor {
    /// Base URL for resolving relative links
    base_url: Option<url::Url>,
}

impl LinkExtractor {
    pub fn new() -> Self {
        Self { base_url: None }
    }

    /// Set base URL for relative link resolution
    pub fn with_base_url(mut self, base: &str) -> Self {
        self.base_url = url::Url::parse(base).ok();
        self
    }

    /// Extract links from content based on content type
    pub fn extract(&self, base_url: &str, content: &str) -> ExtractionResult {
        let mut result = ExtractionResult::new();
        
        // Try to set base URL
        let base = url::Url::parse(base_url).ok().or_else(|| self.base_url.clone());

        // Extract HTML links
        self.extract_html_links(content, &base, &mut result);
        
        // Extract JavaScript URLs
        self.extract_js_urls(content, &base, &mut result);
        
        // Extract JSON endpoints
        self.extract_json_urls(content, &base, &mut result);
        
        // Extract CSS URLs
        self.extract_css_urls(content, &base, &mut result);
        
        // Extract XML links
        self.extract_xml_urls(content, &base, &mut result);

        result
    }

    /// Extract links from HTML content
    fn extract_html_links(&self, content: &str, base: &Option<url::Url>, result: &mut ExtractionResult) {
        // href attributes
        for href in find_attr_values(content, "href") {
            if let Some(url) = self.resolve_url(&href, base) {
                if !is_asset_extension(&url) || is_navigable(&url) {
                    result.urls.push(url);
                }
            }
        }

        // action attributes (forms)
        for action in find_attr_values(content, "action") {
            if let Some(url) = self.resolve_url(&action, base) {
                result.form_actions.push(url);
            }
        }

        // src attributes (scripts, images, etc.)
        for src in find_attr_values(content, "src") {
            if let Some(url) = self.resolve_url(&src, base) {
                if src.ends_with(".js") || src.contains("/script") {
                    result.script_sources.push(url);
                } else {
                    result.assets.push(url);
                }
            }
        }

        // data attributes (potential endpoints)
        for data_url in find_attr_values(content, "data-url") {
            if let Some(url) = self.resolve_url(&data_url, base) {
                result.urls.push(url);
            }
        }

        // data-api attributes
        for api_url in find_attr_values(content, "data-api") {
            if let Some(url) = self.resolve_url(&api_url, base) {
                result.api_endpoints.push(url);
            }
        }

        // Open Graph / Twitter card URLs
        for og_url in find_attr_values(content, "content") {
            if og_url.starts_with("http") {
                result.assets.push(og_url.to_string());
            }
        }
    }

    /// Extract URLs from JavaScript content
    fn extract_js_urls(&self, content: &str, base: &Option<url::Url>, result: &mut ExtractionResult) {
        // Pattern: fetch('url') or fetch("url")
        for cap in find_fetch_calls(content) {
            if let Some(url) = self.resolve_url(&cap, base) {
                result.api_endpoints.push(url);
            }
        }

        // Pattern: axios.get('url') or similar
        for cap in find_xhr_urls(content) {
            if let Some(url) = self.resolve_url(&cap, base) {
                result.api_endpoints.push(url);
            }
        }

        // Pattern: "/api/..." or '/api/...' string literals
        for path in find_api_paths(content) {
            if let Some(base_url) = base {
                if let Ok(resolved) = base_url.join(&path) {
                    result.api_endpoints.push(resolved.to_string());
                }
            } else if path.starts_with('/') {
                result.api_endpoints.push(path);
            }
        }

        // Pattern: endpoint: '...' or url: '...'
        for url in find_object_urls(content) {
            if url.starts_with("http") {
                result.api_endpoints.push(url);
            }
        }
    }

    /// Extract URLs from JSON content
    fn extract_json_urls(&self, content: &str, base: &Option<url::Url>, result: &mut ExtractionResult) {
        // Look for URL-like values in JSON
        for url in find_json_urls(content) {
            if url.starts_with("http") {
                result.api_endpoints.push(url);
            } else if url.starts_with('/') {
                if let Some(base_url) = base {
                    if let Ok(resolved) = base_url.join(&url) {
                        result.api_endpoints.push(resolved.to_string());
                    }
                }
            }
        }

        // Look for common JSON API patterns
        for endpoint in find_json_endpoints(content) {
            result.api_endpoints.push(endpoint);
        }
    }

    /// Extract URLs from CSS content
    fn extract_css_urls(&self, content: &str, base: &Option<url::Url>, result: &mut ExtractionResult) {
        // Pattern: url('...') or url("...")
        for url in find_css_urls(content) {
            if let Some(resolved) = self.resolve_url(&url, base) {
                result.assets.push(resolved);
            }
        }

        // Pattern: @import '...' or @import "..."
        for import in find_css_imports(content) {
            if let Some(resolved) = self.resolve_url(&import, base) {
                result.assets.push(resolved);
            }
        }
    }

    /// Extract URLs from XML content
    fn extract_xml_urls(&self, content: &str, base: &Option<url::Url>, result: &mut ExtractionResult) {
        // XML uses similar attribute patterns to HTML
        self.extract_html_links(content, base, result);

        // Also look for xlink:href attributes
        for href in find_attr_values(content, "xlink:href") {
            if let Some(url) = self.resolve_url(&href, base) {
                result.urls.push(url);
            }
        }
    }

    /// Resolve a potentially relative URL against a base
    fn resolve_url(&self, url_str: &str, base: &Option<url::Url>) -> Option<String> {
        let trimmed = url_str.trim();
        
        // Skip javascript:, mailto:, tel:, data: schemes
        if trimmed.starts_with("javascript:") 
            || trimmed.starts_with("mailto:")
            || trimmed.starts_with("tel:")
            || trimmed.starts_with("data:")
            || trimmed.is_empty()
            || trimmed == "#"
        {
            return None;
        }

        // Already absolute
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            return Some(trimmed.to_string());
        }

        // Resolve against base
        if let Some(base_url) = base {
            match base_url.join(trimmed) {
                Ok(resolved) => Some(resolved.to_string()),
                Err(_) => None,
            }
        } else if trimmed.starts_with('/') {
            // Can't resolve without base, but keep absolute paths
            Some(trimmed.to_string())
        } else {
            None
        }
    }
}

/// Find attribute values in HTML/XML content
fn find_attr_values(content: &str, attr_name: &str) -> Vec<String> {
    let mut results = Vec::new();
    let pattern = format!("{}=", attr_name);
    
    let bytes = content.as_bytes();
    let mut search_start = 0;

    while let Some(pos) = memmem::find(&bytes[search_start..], pattern.as_bytes()) {
        let start = search_start + pos + pattern.len();
        
        // Skip whitespace
        let value_start = bytes[start..]
            .iter()
            .position(|&b| !b.is_ascii_whitespace())
            .map(|p| start + p)
            .unwrap_or(start);

        if value_start >= bytes.len() {
            break;
        }

        // Get quote character
        let quote = bytes[value_start];
        if quote == b'"' || quote == b'\'' {
            let value_begin = value_start + 1;
            if let Some(end_rel) = memmem::find(&bytes[value_begin..], &[quote]) {
                let value_end = value_begin + end_rel;
                if let Ok(s) = std::str::from_utf8(&bytes[value_begin..value_end]) {
                    results.push(s.to_string());
                }
                search_start = value_end + 1;
            } else {
                break;
            }
        } else {
            // Unquoted attribute value
            let value_end = bytes[value_start..]
                .iter()
                .position(|&b| b.is_ascii_whitespace() || b == b'>')
                .map(|p| value_start + p)
                .unwrap_or(bytes.len());
            
            if let Ok(s) = std::str::from_utf8(&bytes[value_start..value_end]) {
                results.push(s.to_string());
            }
            search_start = value_end;
        }
    }

    results
}

/// Find fetch() calls in JavaScript
fn find_fetch_calls(content: &str) -> Vec<String> {
    let mut results = Vec::new();
    let bytes = content.as_bytes();
    
    // Simple pattern matching for fetch('url') or fetch("url")
    let fetch_pattern = b"fetch(";
    let mut search_start = 0;

    while let Some(pos) = memmem::find(&bytes[search_start..], fetch_pattern) {
        let start = search_start + pos + fetch_pattern.len();
        
        // Skip whitespace
        let arg_start = bytes[start..]
            .iter()
            .position(|&b| !b.is_ascii_whitespace())
            .map(|p| start + p)
            .unwrap_or(start);

        if arg_start >= bytes.len() {
            break;
        }

        let quote = bytes[arg_start];
        if quote == b'"' || quote == b'\'' {
            let value_begin = arg_start + 1;
            if let Some(end_rel) = memmem::find(&bytes[value_begin..], &[quote]) {
                let value_end = value_begin + end_rel;
                if let Ok(s) = std::str::from_utf8(&bytes[value_begin..value_end]) {
                    results.push(s.to_string());
                }
                search_start = value_end + 1;
            } else {
                break;
            }
        } else {
            search_start = arg_start + 1;
        }
    }

    results
}

/// Find XHR/AJAX URLs in JavaScript
fn find_xhr_urls(content: &str) -> Vec<String> {
    let mut results = Vec::new();
    
    // Patterns: open('GET', 'url'), .get('url'), .post('url')
    let patterns = ["open(", ".get(", ".post(", ".put(", ".delete(", ".patch("];
    
    for pattern in &patterns {
        let bytes = content.as_bytes();
        let mut search_start = 0;
        
        while let Some(pos) = memmem::find(&bytes[search_start..], pattern.as_bytes()) {
            let start = search_start + pos + pattern.len();
            
            // For open(), skip first argument (method)
            if *pattern == "open(" {
                // Find comma and skip to second argument
                if let Some(comma) = memmem::find(&bytes[start..], b",") {
                    let after_comma = start + comma + 1;
                    let arg_start = bytes[after_comma..]
                        .iter()
                        .position(|&b| !b.is_ascii_whitespace())
                        .map(|p| after_comma + p)
                        .unwrap_or(after_comma);
                    
                    if arg_start < bytes.len() {
                        let quote = bytes[arg_start];
                        if quote == b'"' || quote == b'\'' {
                            let value_begin = arg_start + 1;
                            if let Some(end_rel) = memmem::find(&bytes[value_begin..], &[quote]) {
                                let value_end = value_begin + end_rel;
                                if let Ok(s) = std::str::from_utf8(&bytes[value_begin..value_end]) {
                                    results.push(s.to_string());
                                }
                                search_start = value_end + 1;
                                continue;
                            }
                        }
                    }
                }
            } else {
                // Direct URL argument
                if let Some(quote_pos) = bytes[start..].iter().position(|&b| *b == b'"' || *b == b'\'') {
                    let arg_start = start + quote_pos;
                    let quote = bytes[arg_start];
                    let value_begin = arg_start + 1;
                    
                    if let Some(end_rel) = memmem::find(&bytes[value_begin..], &[quote]) {
                        let value_end = value_begin + end_rel;
                        if let Ok(s) = std::str::from_utf8(&bytes[value_begin..value_end]) {
                            results.push(s.to_string());
                        }
                        search_start = value_end + 1;
                        continue;
                    }
                }
            }
            
            search_start = start + 1;
        }
    }

    results
}

/// Find API path strings in JavaScript
fn find_api_paths(content: &str) -> Vec<String> {
    let mut results = Vec::new();
    let bytes = content.as_bytes();
    
    // Look for patterns like '/api/', '/v1/', '/graphql'
    let api_patterns = ["/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/endpoint"];
    
    for pattern in &api_patterns {
        let mut search_start = 0;
        while let Some(pos) = memmem::find(&bytes[search_start..], pattern.as_bytes()) {
            let start = search_start + pos;
            
            // Find the opening quote
            let quote_start = bytes[..start]
                .iter()
                .rposition(|&b| *b == b'"' || *b == b'\'' || *b == b'`')
                .map(|p| p + 1);
            
            if let Some(qs) = quote_start {
                if qs > 0 && bytes[qs - 1] != b'\\' {
                    let quote = bytes[qs];
                    // Find closing quote after our pattern
                    if let Some(end_rel) = memmem::find(&bytes[start..], &[quote]) {
                        let end = start + end_rel;
                        if let Ok(s) = std::str::from_utf8(&bytes[qs + 1..end]) {
                            if s.starts_with('/') && s.len() < 500 {
                                results.push(s.to_string());
                            }
                        }
                        search_start = end + 1;
                        continue;
                    }
                }
            }
            
            search_start = start + 1;
        }
    }

    results
}

/// Find URL values in JavaScript objects
fn find_object_urls(content: &str) -> Vec<String> {
    let mut results = Vec::new();
    
    // Patterns: url: '...', endpoint: '...', apiUrl: '...'
    let key_patterns = ["url:", "endpoint:", "apiUrl:", "baseUrl:", "host:"];
    
    for key in &key_patterns {
        let bytes = content.as_bytes();
        let mut search_start = 0;
        
        while let Some(pos) = memmem::find(&bytes[search_start..], key.as_bytes()) {
            let start = search_start + pos + key.len();
            
            // Skip whitespace
            let value_start = bytes[start..]
                .iter()
                .position(|&b| !b.is_ascii_whitespace())
                .map(|p| start + p)
                .unwrap_or(start);

            if value_start >= bytes.len() {
                break;
            }

            let quote = bytes[value_start];
            if quote == b'"' || quote == b'\'' {
                let value_begin = value_start + 1;
                if let Some(end_rel) = memmem::find(&bytes[value_begin..], &[quote]) {
                    let value_end = value_begin + end_rel;
                    if let Ok(s) = std::str::from_utf8(&bytes[value_begin..value_end]) {
                        results.push(s.to_string());
                    }
                    search_start = value_end + 1;
                } else {
                    break;
                }
            } else {
                search_start = value_start + 1;
            }
        }
    }

    results
}

/// Find URLs in JSON content
fn find_json_urls(content: &str) -> Vec<String> {
    let mut results = Vec::new();
    let bytes = content.as_bytes();
    
    // Look for "url": "..." or similar patterns
    let url_keys = ["\"url\"", "\"endpoint\"", "\"href\"", "\"src\"", "\"api\""];
    
    for key in &url_keys {
        let mut search_start = 0;
        while let Some(pos) = memmem::find(&bytes[search_start..], key.as_bytes()) {
            let after_key = search_start + pos + key.len();
            
            // Skip : and whitespace
            let value_start = bytes[after_key..]
                .iter()
                .position(|&b| b == b'"' || b == b'\'')
                .map(|p| after_key + p)
                .unwrap_or(after_key);

            if value_start >= bytes.len() {
                break;
            }

            let quote = bytes[value_start];
            let value_begin = value_start + 1;
            if let Some(end_rel) = memmem::find(&bytes[value_begin..], &[quote]) {
                let value_end = value_begin + end_rel;
                if let Ok(s) = std::str::from_utf8(&bytes[value_begin..value_end]) {
                    if s.starts_with("http") || s.starts_with('/') {
                        results.push(s.to_string());
                    }
                }
                search_start = value_end + 1;
            } else {
                break;
            }
        }
    }

    results
}

/// Find potential API endpoints in JSON
fn find_json_endpoints(content: &str) -> Vec<String> {
    let mut results = Vec::new();
    
    // Look for paths that might be endpoints
    if content.contains("\"/api/") {
        let parts: Vec<&str> = content.split('"').collect();
        for (i, part) in parts.iter().enumerate() {
            if part.starts_with("/api/") && part.len() < 200 {
                results.push(part.to_string());
            }
            // Check next part might be the value
            if i + 1 < parts.len() && (*part == "url" || *part == "endpoint" || *part == "path") {
                let next = parts[i + 1];
                if next.starts_with('/') && next.len() < 200 {
                    results.push(next.to_string());
                }
            }
        }
    }

    results
}

/// Find CSS url() patterns
fn find_css_urls(content: &str) -> Vec<String> {
    let mut results = Vec::new();
    let bytes = content.as_bytes();
    
    let pattern = b"url(";
    let mut search_start = 0;

    while let Some(pos) = memmem::find(&bytes[search_start..], pattern) {
        let start = search_start + pos + pattern.len();
        
        // Skip whitespace and optional quotes
        let value_start = bytes[start..]
            .iter()
            .position(|&b| !b.is_ascii_whitespace() && b != b'"' && b != b'\'')
            .map(|p| start + p)
            .unwrap_or(start);

        if value_start >= bytes.len() {
            break;
        }

        // Find closing paren or quote
        let end = bytes[value_start..]
            .iter()
            .position(|&b| b == b')' || b == b'"' || b == b'\'')
            .map(|p| value_start + p)
            .unwrap_or(bytes.len());

        if let Ok(s) = std::str::from_utf8(&bytes[value_start..end]) {
            let trimmed = s.trim();
            if !trimmed.is_empty() && !trimmed.starts_with("data:") {
                results.push(trimmed.to_string());
            }
        }
        
        search_start = end + 1;
    }

    results
}

/// Find CSS @import statements
fn find_css_imports(content: &str) -> Vec<String> {
    let mut results = Vec::new();
    let bytes = content.as_bytes();
    
    let pattern = b"@import";
    let mut search_start = 0;

    while let Some(pos) = memmem::find(&bytes[search_start..], pattern) {
        let start = search_start + pos + pattern.len();
        
        // Skip whitespace
        let value_start = bytes[start..]
            .iter()
            .position(|&b| !b.is_ascii_whitespace())
            .map(|p| start + p)
            .unwrap_or(start);

        if value_start >= bytes.len() {
            break;
        }

        let quote = bytes[value_start];
        if quote == b'"' || quote == b'\'' {
            let value_begin = value_start + 1;
            if let Some(end_rel) = memmem::find(&bytes[value_begin..], &[quote]) {
                let value_end = value_begin + end_rel;
                if let Ok(s) = std::str::from_utf8(&bytes[value_begin..value_end]) {
                    results.push(s.to_string());
                }
                search_start = value_end + 1;
            } else {
                break;
            }
        } else {
            search_start = value_start + 1;
        }
    }

    results
}

/// Check if URL points to a navigable resource (not just an asset)
fn is_navigable(url: &str) -> bool {
    let lower = url.to_lowercase();
    !lower.ends_with(".jpg") 
        && !lower.ends_with(".jpeg")
        && !lower.ends_with(".png")
        && !lower.ends_with(".gif")
        && !lower.ends_with(".svg")
        && !lower.ends_with(".ico")
        && !lower.ends_with(".woff")
        && !lower.ends_with(".woff2")
        && !lower.ends_with(".ttf")
        && !lower.ends_with(".eot")
}

/// Check if URL has an asset extension
fn is_asset_extension(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.ends_with(".css")
        || lower.ends_with(".js")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".png")
        || lower.ends_with(".gif")
        || lower.ends_with(".svg")
        || lower.ends_with(".ico")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2")
        || lower.ends_with(".ttf")
        || lower.ends_with(".eot")
        || lower.ends_with(".mp4")
        || lower.ends_with(".webm")
        || lower.ends_with(".mp3")
        || lower.ends_with(".wav")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_html_links() {
        let html = r#"
            <a href="http://example.com/page1">Link</a>
            <a href="/page2">Relative</a>
            <form action="/submit">
            <script src="/app.js"></script>
        "#;
        
        let extractor = LinkExtractor::new();
        let result = extractor.extract("http://example.com", html);
        
        assert!(result.urls.iter().any(|u| u.contains("page1")));
        assert!(result.urls.iter().any(|u| u.contains("page2")));
        assert!(!result.form_actions.is_empty());
    }

    #[test]
    fn test_extract_js_fetch() {
        let js = r#"
            fetch('/api/users');
            fetch("http://api.example.com/data");
            axios.get('/api/posts');
        "#;
        
        let extractor = LinkExtractor::new();
        let result = extractor.extract("http://example.com", js);
        
        assert!(!result.api_endpoints.is_empty());
    }

    #[test]
    fn test_filter_javascript_urls() {
        let extractor = LinkExtractor::new();
        
        assert!(extractor.resolve_url("javascript:void(0)", &None).is_none());
        assert!(extractor.resolve_url("mailto:test@example.com", &None).is_none());
        assert!(extractor.resolve_url("http://valid.com", &None).is_some());
    }
}
