//! Infrastructure Learning Cache
//! Caches successful CMS paths, exposed admin URLs, and default credential hits.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use dashmap::DashMap;

/// Maximum number of entries in each cache (bounded memory)
const MAX_CMS_PATHS: usize = 5000;
const MAX_ADMIN_URLS: usize = 2000;
const MAX_CRED_HITS: usize = 500;

/// Cached CMS path entry
#[derive(Debug, Clone)]
pub struct CachedCmsPath {
    pub cms_type: String,
    pub path: String,
    pub success_count: u32,
    pub last_seen: u64,
}

/// Cached admin URL entry
#[derive(Debug, Clone)]
pub struct CachedAdminUrl {
    pub service: String,
    pub url: String,
    pub status_code: u16,
    pub success_count: u32,
    pub last_seen: u64,
}

/// Cached credential hit
#[derive(Debug, Clone)]
pub struct CachedCredHit {
    pub service: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub last_seen: u64,
}

/// Infrastructure learning cache
pub struct InfraCache {
    /// Successful CMS paths by domain
    cms_paths: DashMap<String, Vec<CachedCmsPath>>,
    
    /// Exposed admin URLs by domain
    admin_urls: DashMap<String, Vec<CachedAdminUrl>>,
    
    /// Default credential hits by service
    cred_hits: DashMap<String, Vec<CachedCredHit>>,
    
    /// Domain reputation scores (learned from scans)
    domain_reputation: DashMap<String, i32>,
    
    /// Bounded limits
    max_cms_paths: usize,
    max_admin_urls: usize,
    max_cred_hits: usize,
}

impl InfraCache {
    pub fn new() -> Self {
        Self {
            cms_paths: DashMap::new(),
            admin_urls: DashMap::new(),
            cred_hits: DashMap::new(),
            domain_reputation: DashMap::new(),
            max_cms_paths: MAX_CMS_PATHS,
            max_admin_urls: MAX_ADMIN_URLS,
            max_cred_hits: MAX_CRED_HITS,
        }
    }

    /// Cache a successful CMS path detection
    pub fn cache_cms_path(&self, domain: &str, cms_type: &str, path: &str) {
        let mut paths = self.cms_paths.entry(domain.to_string()).or_insert_with(Vec::new);
        
        // Check if already cached
        if let Some(pos) = paths.iter().position(|p| p.path == path) {
            paths[pos].success_count += 1;
            paths[pos].last_seen = current_timestamp();
        } else {
            // Enforce bounded size
            if paths.len() >= self.max_cms_paths {
                paths.remove(0); // Remove oldest
            }
            
            paths.push(CachedCmsPath {
                cms_type: cms_type.to_string(),
                path: path.to_string(),
                success_count: 1,
                last_seen: current_timestamp(),
            });
        }
    }

    /// Cache an exposed admin URL
    pub fn cache_admin_url(&self, domain: &str, service: &str, url: &str, status_code: u16) {
        let mut urls = self.admin_urls.entry(domain.to_string()).or_insert_with(Vec::new);
        
        if let Some(pos) = urls.iter().position(|u| u.url == url) {
            urls[pos].success_count += 1;
            urls[pos].last_seen = current_timestamp();
        } else {
            if urls.len() >= self.max_admin_urls {
                urls.remove(0);
            }
            
            urls.push(CachedAdminUrl {
                service: service.to_string(),
                url: url.to_string(),
                status_code,
                success_count: 1,
                last_seen: current_timestamp(),
            });
        }
    }

    /// Cache a default credential hit
    pub fn cache_cred_hit(&self, service: &str, username: &str, password: &str, url: &str) {
        let key = format!("{}:{}", service, url);
        let mut hits = self.cred_hits.entry(key).or_insert_with(Vec::new);
        
        // Check for duplicate
        if !hits.iter().any(|h| h.username == username && h.password == password) {
            if hits.len() >= self.max_cred_hits {
                hits.remove(0);
            }
            
            hits.push(CachedCredHit {
                service: service.to_string(),
                username: username.to_string(),
                password: password.to_string(),
                url: url.to_string(),
                last_seen: current_timestamp(),
            });
        }
    }

    /// Update domain reputation score
    pub fn update_domain_reputation(&self, domain: &str, delta: i32) {
        let mut score = self.domain_reputation.entry(domain.to_string()).or_insert(0);
        *score += delta;
        
        // Clamp score
        if *score > 100 {
            *score = 100;
        } else if *score < -100 {
            *score = -100;
        }
    }

    /// Get cached CMS paths for a domain
    pub fn get_cms_paths(&self, domain: &str) -> Vec<CachedCmsPath> {
        self.cms_paths
            .get(domain)
            .map(|paths| paths.clone())
            .unwrap_or_default()
    }

    /// Get cached admin URLs for a domain
    pub fn get_admin_urls(&self, domain: &str) -> Vec<CachedAdminUrl> {
        self.admin_urls
            .get(domain)
            .map(|urls| urls.clone())
            .unwrap_or_default()
    }

    /// Get credential hits for a service
    pub fn get_cred_hits(&self, service: &str, url: &str) -> Vec<CachedCredHit> {
        let key = format!("{}:{}", service, url);
        self.cred_hits
            .get(&key)
            .map(|hits| hits.clone())
            .unwrap_or_default()
    }

    /// Get domain reputation score
    pub fn get_domain_reputation(&self, domain: &str) -> i32 {
        *self.domain_reputation.get(domain).unwrap_or(&0)
    }

    /// Check if a path is likely to exist based on cache
    pub fn is_likely_cms_path(&self, domain: &str, path: &str) -> bool {
        self.cms_paths
            .get(domain)
            .map(|paths| paths.iter().any(|p| p.path == path && p.success_count > 1))
            .unwrap_or(false)
    }

    /// Check if admin URL is likely accessible
    pub fn is_likely_admin_url(&self, domain: &str, url: &str) -> bool {
        self.admin_urls
            .get(domain)
            .map(|urls| urls.iter().any(|u| u.url == url && u.success_count > 1))
            .unwrap_or(false)
    }

    /// Export cache statistics
    pub fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("cms_paths", self.cms_paths.len());
        stats.insert("admin_urls", self.admin_urls.len());
        stats.insert("cred_hits", self.cred_hits.len());
        stats.insert("domain_reputations", self.domain_reputation.len());
        stats
    }

    /// Clear all caches
    pub fn clear(&self) {
        self.cms_paths.clear();
        self.admin_urls.clear();
        self.cred_hits.clear();
        self.domain_reputation.clear();
    }
}

/// Thread-safe shared cache
pub type SharedInfraCache = Arc<InfraCache>;

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl Default for InfraCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_cms_path() {
        let cache = InfraCache::new();
        cache.cache_cms_path("example.com", "WordPress", "/wp-admin/");
        
        let paths = cache.get_cms_paths("example.com");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].cms_type, "WordPress");
    }

    #[test]
    fn test_bounded_size() {
        let cache = InfraCache::new();
        
        // Add more than max entries
        for i in 0..MAX_CMS_PATHS + 100 {
            cache.cache_cms_path("test.com", "Test", &format!("/path/{}/", i));
        }
        
        let paths = cache.get_cms_paths("test.com");
        assert!(paths.len() <= MAX_CMS_PATHS);
    }

    #[test]
    fn test_domain_reputation() {
        let cache = InfraCache::new();
        
        cache.update_domain_reputation("good.com", 50);
        cache.update_domain_reputation("bad.com", -50);
        
        assert!(cache.get_domain_reputation("good.com") > 0);
        assert!(cache.get_domain_reputation("bad.com") < 0);
    }
}
