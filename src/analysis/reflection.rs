//! Reflection Tracker
//! 
//! Maps exact payload injection points within DOM and HTTP headers.
//! Uses zero-copy slicing for memory efficiency.

use std::sync::atomic::{AtomicU64, Ordering};
use bytes::Bytes;

/// Location of reflected payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReflectionLocation {
    HtmlBody,
    HtmlAttribute,
    HtmlTag,
    JavaScript,
    Css,
    HttpHeader(String),
    UrlPath,
    QueryParameter(String),
    ResponseCookie(String),
}

/// Reflection point in response
#[derive(Debug, Clone)]
pub struct ReflectionPoint {
    pub location: ReflectionLocation,
    pub offset: usize,
    pub length: usize,
    pub encoded: bool,
    pub encoding_type: Option<EncodingType>,
    pub context: InjectionContext,
}

/// Type of encoding detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingType {
    HtmlEntity,
    UrlEncoded,
    Base64,
    Hex,
    Unicode,
    JsonEscaped,
}

/// Injection context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionContext {
    HtmlText,
    HtmlAttributeDoubleQuote,
    HtmlAttributeSingleQuote,
    HtmlAttributeUnquoted,
    JavaScriptString,
    JavaScriptCode,
    CssValue,
    UrlPath,
    Header,
    Unknown,
}

/// Map of all reflections found
#[derive(Debug, Clone)]
pub struct ReflectionMap {
    pub points: Vec<ReflectionPoint>,
    pub total_reflections: usize,
    pub encoded_count: usize,
    pub unencoded_count: usize,
}

impl ReflectionMap {
    pub fn new() -> Self {
        Self {
            points: Vec::new(),
            total_reflections: 0,
            encoded_count: 0,
            unencoded_count: 0,
        }
    }
    
    pub fn add_point(&mut self, point: ReflectionPoint) {
        if point.encoded {
            self.encoded_count += 1;
        } else {
            self.unencoded_count += 1;
        }
        self.total_reflections += 1;
        self.points.push(point);
    }
    
    pub fn has_unencoded_reflection(&self) -> bool {
        self.unencoded_count > 0
    }
    
    pub fn is_reflected(&self) -> bool {
        self.total_reflections > 0
    }
}

impl Default for ReflectionMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Lock-free reflection tracker
pub struct ReflectionTracker {
    total_tracked: AtomicU64,
    dangerous_reflections: AtomicU64,
    safe_reflections: AtomicU64,
}

impl ReflectionTracker {
    pub fn new() -> Self {
        Self {
            total_tracked: AtomicU64::new(0),
            dangerous_reflections: AtomicU64::new(0),
            safe_reflections: AtomicU64::new(0),
        }
    }
    
    /// Find all reflections of a payload in the response
    pub fn find_reflections(
        &self,
        body: &Bytes,
        headers: &[(String, String)],
    ) -> Vec<ReflectionPoint> {
        // Note: In actual usage, the payload would be passed in
        // For now, we track general reflection patterns
        
        let mut points = Vec::new();
        
        // Scan body for potential reflection patterns
        let body_str = String::from_utf8_lossy(body);
        
        // Look for common reflection indicators
        self.scan_html_body(&body_str, &mut points);
        self.scan_javascript(&body_str, &mut points);
        self.scan_headers(headers, &mut points);
        
        if !points.is_empty() {
            self.total_tracked.fetch_add(points.len() as u64, Ordering::Relaxed);
            
            // Count dangerous vs safe
            let dangerous = points.iter().filter(|p| !p.encoded).count();
            let safe = points.iter().filter(|p| p.encoded).count();
            
            self.dangerous_reflections.fetch_add(dangerous as u64, Ordering::Relaxed);
            self.safe_reflections.fetch_add(safe as u64, Ordering::Relaxed);
        }
        
        points
    }
    
    /// Find specific payload reflections
    pub fn find_payload_reflections(
        &self,
        payload: &str,
        body: &Bytes,
        headers: &[(String, String)],
    ) -> ReflectionMap {
        let mut map = ReflectionMap::new();
        let body_str = String::from_utf8_lossy(body);
        
        // Search for exact payload
        let mut search_start = 0;
        while let Some(offset) = body_str[search_start..].find(payload) {
            let actual_offset = search_start + offset;
            
            // Determine context
            let context = self.determine_context(&body_str, actual_offset);
            let encoded = self.check_encoding(&body_str, actual_offset, payload);
            
            map.add_point(ReflectionPoint {
                location: ReflectionLocation::HtmlBody,
                offset: actual_offset,
                length: payload.len(),
                encoded,
                encoding_type: if encoded { Some(EncodingType::HtmlEntity) } else { None },
                context,
            });
            
            search_start = actual_offset + 1;
        }
        
        // Check headers
        for (name, value) in headers {
            if value.contains(payload) {
                if let Some(offset) = value.find(payload) {
                    map.add_point(ReflectionPoint {
                        location: ReflectionLocation::HttpHeader(name.clone()),
                        offset,
                        length: payload.len(),
                        encoded: false,
                        encoding_type: None,
                        context: InjectionContext::Header,
                    });
                }
            }
        }
        
        if map.total_reflections > 0 {
            self.total_tracked.fetch_add(map.total_reflections as u64, Ordering::Relaxed);
            if map.has_unencoded_reflection() {
                self.dangerous_reflections.fetch_add(map.unencoded_count as u64, Ordering::Relaxed);
            } else {
                self.safe_reflections.fetch_add(map.encoded_count as u64, Ordering::Relaxed);
            }
        }
        
        map
    }
    
    /// Scan HTML body for reflection patterns
    fn scan_html_body(&self, content: &str, points: &mut Vec<ReflectionPoint>) {
        // Look for user input patterns in HTML
        let patterns = [
            (r"<[^>]*>[^<]*", ReflectionLocation::HtmlTag, InjectionContext::HtmlText),
        ];
        
        // Simple heuristic: find text between tags
        let mut in_tag = false;
        let mut tag_start = 0;
        
        for (i, ch) in content.chars().enumerate() {
            if ch == '<' {
                in_tag = true;
                tag_start = i;
            } else if ch == '>' && in_tag {
                in_tag = false;
                
                // Check if this is a script or style tag
                let tag_content = &content[tag_start..i];
                if tag_content.to_lowercase().contains("script") {
                    points.push(ReflectionPoint {
                        location: ReflectionLocation::HtmlTag,
                        offset: tag_start,
                        length: i - tag_start + 1,
                        encoded: false,
                        encoding_type: None,
                        context: InjectionContext::JavaScriptCode,
                    });
                }
            }
        }
    }
    
    /// Scan for JavaScript reflections
    fn scan_javascript(&self, content: &str, points: &mut Vec<ReflectionPoint>) {
        // Look for JavaScript variable assignments
        if let Ok(re) = regex::Regex::new(r"(?i)<script[^>]*>([\s\S]*?)</script>") {
            for cap in re.captures_iter(content) {
                if let Some(js_content) = cap.get(1) {
                    points.push(ReflectionPoint {
                        location: ReflectionLocation::JavaScript,
                        offset: js_content.start(),
                        length: js_content.end() - js_content.start(),
                        encoded: false,
                        encoding_type: None,
                        context: InjectionContext::JavaScriptCode,
                    });
                }
            }
        }
    }
    
    /// Scan headers for reflections
    fn scan_headers(&self, headers: &[(String, String)], points: &mut Vec<ReflectionPoint>) {
        for (name, value) in headers {
            // Check for reflected values in headers
            if value.len() > 50 {
                points.push(ReflectionPoint {
                    location: ReflectionLocation::HttpHeader(name.clone()),
                    offset: 0,
                    length: value.len(),
                    encoded: false,
                    encoding_type: None,
                    context: InjectionContext::Header,
                });
            }
        }
    }
    
    /// Determine injection context at a given offset
    fn determine_context(&self, content: &str, offset: usize) -> InjectionContext {
        // Look backwards to find context
        let before = &content[..offset.min(content.len())];
        
        if before.ends_with("\"") {
            return InjectionContext::HtmlAttributeDoubleQuote;
        } else if before.ends_with("'") {
            return InjectionContext::HtmlAttributeSingleQuote;
        } else if before.ends_with("=") {
            return InjectionContext::HtmlAttributeUnquoted;
        }
        
        InjectionContext::HtmlText
    }
    
    /// Check if payload appears to be encoded
    fn check_encoding(&self, content: &str, offset: usize, payload: &str) -> bool {
        // Check for HTML entity encoding
        let html_encoded = payload
            .chars()
            .any(|c| c == '<' || c == '>' || c == '"' || c == '\'');
        
        if html_encoded {
            // Check if these are encoded in the content
            let after = &content[offset..];
            if after.contains("&lt;") || after.contains("&gt;") || 
               after.contains("&quot;") || after.contains("&#x27;") {
                return true;
            }
        }
        
        // Check for URL encoding
        if payload.contains(' ') || payload.contains('?') || payload.contains('&') {
            let after = &content[offset..];
            if after.contains("%20") || after.contains("%3F") || after.contains("%26") {
                return true;
            }
        }
        
        false
    }
    
    /// Get statistics
    pub fn stats(&self) -> ReflectionStats {
        ReflectionStats {
            total_tracked: self.total_tracked.load(Ordering::Relaxed),
            dangerous_reflections: self.dangerous_reflections.load(Ordering::Relaxed),
            safe_reflections: self.safe_reflections.load(Ordering::Relaxed),
        }
    }
    
    /// Reset statistics
    pub fn reset_stats(&self) {
        self.total_tracked.store(0, Ordering::Relaxed);
        self.dangerous_reflections.store(0, Ordering::Relaxed);
        self.safe_reflections.store(0, Ordering::Relaxed);
    }
}

impl Default for ReflectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for reflection tracking
#[derive(Debug, Clone)]
pub struct ReflectionStats {
    pub total_tracked: u64,
    pub dangerous_reflections: u64,
    pub safe_reflections: u64,
}

impl ReflectionStats {
    pub fn danger_ratio(&self) -> f64 {
        let total = self.dangerous_reflections + self.safe_reflections;
        if total == 0 {
            return 0.0;
        }
        self.dangerous_reflections as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_reflection_tracker_creation() {
        let tracker = ReflectionTracker::new();
        let stats = tracker.stats();
        assert_eq!(stats.total_tracked, 0);
    }
    
    #[test]
    fn test_find_reflections() {
        let tracker = ReflectionTracker::new();
        let body = Bytes::from("<html><body>Hello <script>alert(1)</script></body></html>");
        let headers = vec![];
        
        let points = tracker.find_reflections(&body, &headers);
        
        // Should find at least the script tag
        assert!(!points.is_empty());
    }
    
    #[test]
    fn test_reflection_map() {
        let mut map = ReflectionMap::new();
        
        map.add_point(ReflectionPoint {
            location: ReflectionLocation::HtmlBody,
            offset: 0,
            length: 5,
            encoded: false,
            encoding_type: None,
            context: InjectionContext::HtmlText,
        });
        
        assert!(map.is_reflected());
        assert!(map.has_unencoded_reflection());
    }
}
