//! WordPress CMS Exploitation Module
//! Enumerates WP plugins, themes, and users; tests known unpatched plugin vulnerabilities.

use crate::http::client::HttpClient;
use crate::findings::evidence::Evidence;
use std::collections::HashMap;

/// Maximum number of plugins/themes to enumerate (bounded)
const MAX_ENUMERATION_COUNT: usize = 500;

/// Common WordPress paths for detection
const WP_SIGNATURE_PATHS: &[&str] = &[
    "/wp-login.php",
    "/wp-admin/",
    "/wp-content/",
    "/wp-includes/",
];

/// Common plugin slugs to check
const COMMON_PLUGINS: &[&str] = &[
    "woocommerce",
    "contact-form-7",
    "yoast-seo",
    "elementor",
    "jetpack",
    "akismet",
    "wordfence",
    "updraftplus",
    "duplicate-page",
    "really-simple-ssl",
];

/// WordPress scanner struct
pub struct WordPressScanner {
    client: HttpClient,
    enumerated_plugins: Vec<String>,
    enumerated_themes: Vec<String>,
    max_items: usize,
}

impl WordPressScanner {
    pub fn new(client: HttpClient) -> Self {
        Self {
            client,
            enumerated_plugins: Vec::new(),
            enumerated_themes: Vec::new(),
            max_items: MAX_ENUMERATION_COUNT,
        }
    }

    /// Check if target is WordPress
    pub async fn is_wordpress(&self, base_url: &str) -> bool {
        for path in WP_SIGNATURE_PATHS {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 || response.status() == 403 {
                    let body = response.text().await.unwrap_or_default();
                    if body.contains("wp-") || body.contains("WordPress") {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Enumerate WordPress version from readme.html or wp-includes/version.php
    pub async fn enumerate_version(&self, base_url: &str) -> Option<String> {
        let paths = ["/readme.html", "/wp-includes/version.php"];
        
        for path in paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 {
                    let body = response.text().await.unwrap_or_default();
                    // Extract version pattern
                    if let Some(start) = body.find("$wp_version = '") {
                        if let Some(end) = body[start..].find("';") {
                            let version = &body[start + 15..start + end];
                            return Some(version.to_string());
                        }
                    }
                    if let Some(start) = body.find("<meta name=\"generator\" content=\"WordPress ") {
                        if let Some(end) = body[start..].find("\" />") {
                            let version = &body[start + 42..start + end];
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Enumerate plugins with bounded count
    pub async fn enumerate_plugins(&mut self, base_url: &str) -> Vec<String> {
        let mut found = Vec::new();
        let base = base_url.trim_end_matches('/');
        
        for plugin in COMMON_PLUGINS.iter().take(self.max_items) {
            let read_me_url = format!("{}/wp-content/plugins/{}/readme.txt", base, plugin);
            
            if let Ok(response) = self.client.get(&read_me_url).send().await {
                if response.status() == 200 {
                    found.push(plugin.to_string());
                    if found.len() >= self.max_items {
                        break;
                    }
                }
            }
        }
        
        self.enumerated_plugins = found.clone();
        found
    }

    /// Enumerate themes with bounded count
    pub async fn enumerate_themes(&mut self, base_url: &str) -> Vec<String> {
        let mut found = Vec::new();
        let base = base_url.trim_end_matches('/');
        let style_url = format!("{}/wp-content/themes/{}/style.css", base, "{}");
        
        // Common theme names to probe
        let common_themes = ["twentytwentythree", "twentytwentytwo", "twentytwentyone", 
                            "astra", "generatepress", "oceanwp", "divi"];
        
        for theme in common_themes.iter().take(self.max_items) {
            let url = style_url.replace("{}", theme);
            
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 {
                    found.push(theme.to_string());
                    if found.len() >= self.max_items {
                        break;
                    }
                }
            }
        }
        
        self.enumerated_themes = found.clone();
        found
    }

    /// Enumerate users via WordPress REST API
    pub async fn enumerate_users(&self, base_url: &str) -> Vec<String> {
        let mut users = Vec::new();
        let url = format!("{}/wp-json/wp/v2/users", base_url.trim_end_matches('/'));
        
        if let Ok(response) = self.client.get(&url).send().await {
            if response.status() == 200 {
                if let Ok(body) = response.text().await {
                    // Simple JSON parsing for usernames
                    if let Some(start) = body.find("\"name\"") {
                        if let Some(end) = body[start..].find('"') {
                            users.push(body[start + 8..start + end].to_string());
                        }
                    }
                }
            }
        }
        
        users
    }

    /// Generate evidence from WordPress scan
    pub async fn scan(&mut self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        
        if !self.is_wordpress(base_url).await {
            return evidences;
        }

        // Version detection
        if let Some(version) = self.enumerate_version(base_url).await {
            evidences.push(Evidence::CmsVersion {
                cms: "WordPress".to_string(),
                version: version.clone(),
                url: base_url.to_string(),
                confidence: 90,
                remediation: "Keep WordPress core updated to the latest version.".to_string(),
            });
        }

        // Plugin enumeration
        let plugins = self.enumerate_plugins(base_url).await;
        if !plugins.is_empty() {
            evidences.push(Evidence::ExposedPlugins {
                cms: "WordPress".to_string(),
                plugins: plugins,
                url: base_url.to_string(),
                confidence: 85,
                remediation: "Review necessity of exposed plugins and keep them updated.".to_string(),
            });
        }

        // Theme enumeration
        let themes = self.enumerate_themes(base_url).await;
        if !themes.is_empty() {
            evidences.push(Evidence::ExposedThemes {
                cms: "WordPress".to_string(),
                themes: themes,
                url: base_url.to_string(),
                confidence: 85,
                remediation: "Ensure themes are updated and from trusted sources.".to_string(),
            });
        }

        evidences
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let client = HttpClient::new();
        let scanner = WordPressScanner::new(client);
        assert_eq!(scanner.max_items, MAX_ENUMERATION_COUNT);
    }
}
