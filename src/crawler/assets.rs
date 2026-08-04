//! Asset discovery for scripts, forms, iframes, images, manifests, and API route hints.
//!
//! This module categorizes discovered assets for attack surface mapping.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Types of discovered assets
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetType {
    /// JavaScript file
    Script,
    /// CSS stylesheet
    Stylesheet,
    /// Image resource
    Image,
    /// Font resource
    Font,
    /// Media (video/audio)
    Media,
    /// iframe source
    Iframe,
    /// Form endpoint
    Form,
    /// API endpoint
    ApiEndpoint,
    /// WebSocket endpoint
    WebSocket,
    /// Server-Sent Events endpoint
    SSE,
    /// Manifest file (PWA)
    Manifest,
    /// Service Worker
    ServiceWorker,
    /// Redirect target
    Redirect,
    /// Unknown/other
    Other,
}

/// Discovered asset with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    /// Asset URL
    pub url: String,
    /// Type of asset
    pub asset_type: AssetType,
    /// Source location (for attribution)
    pub source_url: String,
    /// HTTP method if applicable
    pub method: Option<String>,
    /// Additional attributes
    pub attributes: HashMap<String, String>,
    /// Whether this is an external asset
    pub is_external: bool,
    /// Integrity hash if present
    pub integrity: Option<String>,
    /// CORS attribute if present
    pub crossorigin: Option<String>,
}

impl DiscoveredAsset {
    pub fn new(url: String, asset_type: AssetType, source_url: String) -> Self {
        let is_external = url.starts_with("http") && !source_url.starts_with(url.split('/').take(3).collect::<String>().as_str());
        
        Self {
            url,
            asset_type,
            source_url,
            method: None,
            attributes: HashMap::new(),
            is_external,
            integrity: None,
            crossorigin: None,
        }
    }

    pub fn with_method(mut self, method: &str) -> Self {
        self.method = Some(method.to_string());
        self
    }

    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_integrity(mut self, hash: &str) -> Self {
        self.integrity = Some(hash.to_string());
        self
    }

    pub fn with_crossorigin(mut self, mode: &str) -> Self {
        self.crossorigin = Some(mode.to_string());
        self
    }
}

/// Asset catalog for organizing discovered resources
#[derive(Debug, Default)]
pub struct AssetCatalog {
    /// Scripts by source
    pub scripts: Vec<DiscoveredAsset>,
    /// Stylesheets
    pub stylesheets: Vec<DiscoveredAsset>,
    /// Images
    pub images: Vec<DiscoveredAsset>,
    /// Fonts
    pub fonts: Vec<DiscoveredAsset>,
    /// Media files
    pub media: Vec<DiscoveredAsset>,
    /// Iframes
    pub iframes: Vec<DiscoveredAsset>,
    /// Forms
    pub forms: Vec<DiscoveredAsset>,
    /// API endpoints
    pub api_endpoints: Vec<DiscoveredAsset>,
    /// WebSocket endpoints
    pub websockets: Vec<DiscoveredAsset>,
    /// SSE endpoints
    pub sse_endpoints: Vec<DiscoveredAsset>,
    /// Manifests
    pub manifests: Vec<DiscoveredAsset>,
    /// Service workers
    pub service_workers: Vec<DiscoveredAsset>,
}

impl AssetCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an asset to the appropriate category
    pub fn add(&mut self, asset: DiscoveredAsset) {
        match &asset.asset_type {
            AssetType::Script => self.scripts.push(asset),
            AssetType::Stylesheet => self.stylesheets.push(asset),
            AssetType::Image => self.images.push(asset),
            AssetType::Font => self.fonts.push(asset),
            AssetType::Media => self.media.push(asset),
            AssetType::Iframe => self.iframes.push(asset),
            AssetType::Form => self.forms.push(asset),
            AssetType::ApiEndpoint => self.api_endpoints.push(asset),
            AssetType::WebSocket => self.websockets.push(asset),
            AssetType::SSE => self.sse_endpoints.push(asset),
            AssetType::Manifest => self.manifests.push(asset),
            AssetType::ServiceWorker => self.service_workers.push(asset),
            AssetType::Redirect | AssetType::Other => {} // Not stored in catalog
        }
    }

    /// Get total asset count
    pub fn total_count(&self) -> usize {
        self.scripts.len()
            + self.stylesheets.len()
            + self.images.len()
            + self.fonts.len()
            + self.media.len()
            + self.iframes.len()
            + self.forms.len()
            + self.api_endpoints.len()
            + self.websockets.len()
            + self.sse_endpoints.len()
            + self.manifests.len()
            + self.service_workers.len()
    }

    /// Get external asset count
    pub fn external_count(&self) -> usize {
        self.scripts.iter().filter(|a| a.is_external).count()
            + self.stylesheets.iter().filter(|a| a.is_external).count()
            + self.images.iter().filter(|a| a.is_external).count()
            + self.fonts.iter().filter(|a| a.is_external).count()
            + self.media.iter().filter(|a| a.is_external).count()
            + self.iframes.iter().filter(|a| a.is_external).count()
    }

    /// Get all unique URLs
    pub fn all_urls(&self) -> Vec<&str> {
        let mut urls = Vec::new();
        
        for a in &self.scripts { urls.push(a.url.as_str()); }
        for a in &self.stylesheets { urls.push(a.url.as_str()); }
        for a in &self.images { urls.push(a.url.as_str()); }
        for a in &self.fonts { urls.push(a.url.as_str()); }
        for a in &self.media { urls.push(a.url.as_str()); }
        for a in &self.iframes { urls.push(a.url.as_str()); }
        for a in &self.forms { urls.push(a.url.as_str()); }
        for a in &self.api_endpoints { urls.push(a.url.as_str()); }
        for a in &self.websockets { urls.push(a.url.as_str()); }
        for a in &self.sse_endpoints { urls.push(a.url.as_str()); }
        for a in &self.manifests { urls.push(a.url.as_str()); }
        for a in &self.service_workers { urls.push(a.url.as_str()); }
        
        urls
    }

    /// Find potential security-relevant assets
    pub fn security_relevant(&self) -> Vec<&DiscoveredAsset> {
        let mut relevant = Vec::new();
        
        // External scripts are high priority
        for script in &self.scripts {
            if script.is_external || script.integrity.is_none() {
                relevant.push(script);
            }
        }
        
        // Iframes can be attack vectors
        for iframe in &self.iframes {
            relevant.push(iframe);
        }
        
        // Forms with external actions
        for form in &self.forms {
            if form.is_external {
                relevant.push(form);
            }
        }
        
        // API endpoints
        for api in &self.api_endpoints {
            relevant.push(api);
        }
        
        relevant
    }

    /// Get statistics about the catalog
    pub fn stats(&self) -> AssetStats {
        AssetStats {
            total: self.total_count(),
            scripts: self.scripts.len(),
            stylesheets: self.stylesheets.len(),
            images: self.images.len(),
            fonts: self.fonts.len(),
            media: self.media.len(),
            iframes: self.iframes.len(),
            forms: self.forms.len(),
            api_endpoints: self.api_endpoints.len(),
            websockets: self.websockets.len(),
            sse_endpoints: self.sse_endpoints.len(),
            manifests: self.manifests.len(),
            service_workers: self.service_workers.len(),
            external: self.external_count(),
        }
    }
}

/// Statistics about discovered assets
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetStats {
    pub total: usize,
    pub scripts: usize,
    pub stylesheets: usize,
    pub images: usize,
    pub fonts: usize,
    pub media: usize,
    pub iframes: usize,
    pub forms: usize,
    pub api_endpoints: usize,
    pub websockets: usize,
    pub sse_endpoints: usize,
    pub manifests: usize,
    pub service_workers: usize,
    pub external: usize,
}

/// Asset fingerprinting for tracking changes
#[derive(Debug, Clone)]
pub struct AssetFingerprint {
    pub url: String,
    pub content_hash: u64,
    pub size: usize,
    pub mime_type: String,
}

impl AssetFingerprint {
    pub fn new(url: &str, content: &[u8], mime_type: &str) -> Self {
        let content_hash = Self::compute_hash(content);
        Self {
            url: url.to_string(),
            content_hash,
            size: content.len(),
            mime_type: mime_type.to_string(),
        }
    }

    fn compute_hash(content: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        hasher.finish()
    }
}

/// Detect asset type from URL and context
pub fn detect_asset_type(url: &str, content_type: Option<&str>) -> AssetType {
    let lower = url.to_lowercase();
    
    // Check URL patterns first
    if lower.ends_with(".js") || lower.contains("/script") || lower.contains(".js?") {
        return AssetType::Script;
    }
    if lower.ends_with(".css") || lower.contains("/style") || lower.contains(".css?") {
        return AssetType::Stylesheet;
    }
    if lower.ends_with(".json") && (lower.contains("/api/") || lower.contains("endpoint")) {
        return AssetType::ApiEndpoint;
    }
    if lower.starts_with("ws://") || lower.starts_with("wss://") {
        return AssetType::WebSocket;
    }
    if lower.contains("/sse") || lower.contains("event-stream") {
        return AssetType::SSE;
    }
    if lower.ends_with(".manifest") || lower.ends_with(".webmanifest") || lower.contains("manifest.json") {
        return AssetType::Manifest;
    }
    if lower.contains("sw.js") || lower.contains("service-worker") {
        return AssetType::ServiceWorker;
    }
    
    // Check content-type header
    if let Some(ct) = content_type {
        let ct_lower = ct.to_lowercase();
        if ct_lower.contains("javascript") {
            return AssetType::Script;
        }
        if ct_lower.contains("css") {
            return AssetType::Stylesheet;
        }
        if ct_lower.contains("json") {
            if ct_lower.contains("api") || ct_lower.contains("application/json") {
                return AssetType::ApiEndpoint;
            }
        }
        if ct_lower.contains("text/event-stream") {
            return AssetType::SSE;
        }
    }
    
    // Image extensions
    if lower.ends_with(".jpg") || lower.ends_with(".jpeg") 
        || lower.ends_with(".png") || lower.ends_with(".gif")
        || lower.ends_with(".svg") || lower.ends_with(".webp")
        || lower.ends_with(".ico") {
        return AssetType::Image;
    }
    
    // Font extensions
    if lower.ends_with(".woff") || lower.ends_with(".woff2")
        || lower.ends_with(".ttf") || lower.ends_with(".eot")
        || lower.ends_with(".otf") {
        return AssetType::Font;
    }
    
    // Media extensions
    if lower.ends_with(".mp4") || lower.ends_with(".webm")
        || lower.ends_with(".mp3") || lower.ends_with(".wav")
        || lower.ends_with(".ogg") {
        return AssetType::Media;
    }
    
    AssetType::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_asset_type_from_url() {
        assert_eq!(detect_asset_type("/app.js", None), AssetType::Script);
        assert_eq!(detect_asset_type("/styles.css", None), AssetType::Stylesheet);
        assert_eq!(detect_asset_type("/logo.png", None), AssetType::Image);
        assert_eq!(detect_asset_type("wss://example.com/ws", None), AssetType::WebSocket);
    }

    #[test]
    fn test_detect_asset_type_from_content_type() {
        assert_eq!(detect_asset_type("/unknown", Some("application/javascript")), AssetType::Script);
        assert_eq!(detect_asset_type("/unknown", Some("text/css")), AssetType::Stylesheet);
    }

    #[test]
    fn test_asset_catalog() {
        let mut catalog = AssetCatalog::new();
        
        catalog.add(DiscoveredAsset::new(
            "http://example.com/app.js".to_string(),
            AssetType::Script,
            "http://example.com".to_string(),
        ));
        
        catalog.add(DiscoveredAsset::new(
            "http://example.com/api/users".to_string(),
            AssetType::ApiEndpoint,
            "http://example.com".to_string(),
        ));
        
        assert_eq!(catalog.total_count(), 2);
        assert_eq!(catalog.scripts.len(), 1);
        assert_eq!(catalog.api_endpoints.len(), 1);
    }

    #[test]
    fn test_asset_fingerprint() {
        let fp = AssetFingerprint::new("/test.js", b"console.log('hi')", "application/javascript");
        
        assert_eq!(fp.url, "/test.js");
        assert_eq!(fp.size, 18);
        assert!(!fp.mime_type.is_empty());
    }
}
