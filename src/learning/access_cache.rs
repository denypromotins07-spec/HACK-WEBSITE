//! Access Control Learning Cache Module
//! Caches successful privilege escalation paths, ID patterns, and JWT weaknesses.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Cached IDOR pattern
#[derive(Debug, Clone)]
pub struct IdorPattern {
    pub endpoint: String,
    pub object_id_pattern: String,
    pub attacker_session_id: String,
    pub first_seen: Instant,
    pub hit_count: u32,
}

/// Cached BOLA pattern
#[derive(Debug, Clone)]
pub struct BolaPattern {
    pub endpoint: String,
    pub method: String,
    pub object_id: String,
    pub first_seen: Instant,
}

/// Cached mass assignment pattern
#[derive(Debug, Clone)]
pub struct MassAssignmentPattern {
    pub endpoint: String,
    pub field: String,
    pub injected_value: String,
    pub first_seen: Instant,
}

/// Cached JWT weakness
#[derive(Debug, Clone)]
pub struct JwtWeakness {
    pub weakness_type: String,
    pub endpoint: String,
    pub first_seen: Instant,
}

/// Cached race condition pattern
#[derive(Debug, Clone)]
pub struct RaceConditionPattern {
    pub endpoint: String,
    pub operation_type: String,
    pub first_seen: Instant,
}

/// Cached protected function (for negative caching)
#[derive(Debug, Clone)]
pub struct ProtectedFunction {
    pub endpoint: String,
    pub method: String,
    pub verified_at: Instant,
}

/// Access control learning cache with bounded storage
pub struct AccessCache {
    /// IDOR patterns that succeeded
    idor_patterns: RwLock<HashMap<String, IdorPattern>>,
    /// BOLA patterns that succeeded
    bola_patterns: RwLock<HashMap<String, BolaPattern>>,
    /// Mass assignment exploitation patterns
    mass_assignment_patterns: RwLock<HashMap<String, MassAssignmentPattern>>,
    /// JWT weaknesses discovered
    jwt_weaknesses: RwLock<HashMap<String, JwtWeakness>>,
    /// Race condition patterns
    race_condition_patterns: RwLock<HashMap<String, RaceConditionPattern>>,
    /// Protected functions (negative cache - properly secured)
    protected_functions: RwLock<HashSet<String>>,
    /// Privilege escalation paths
    privilege_escalation_paths: RwLock<HashMap<String, Vec<String>>>,
    /// Maximum entries per category (bounded)
    max_entries_per_category: usize,
    /// Cache entry TTL
    entry_ttl: Duration,
}

impl AccessCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            idor_patterns: RwLock::new(HashMap::new()),
            bola_patterns: RwLock::new(HashMap::new()),
            mass_assignment_patterns: RwLock::new(HashMap::new()),
            jwt_weaknesses: RwLock::new(HashMap::new()),
            race_condition_patterns: RwLock::new(HashMap::new()),
            protected_functions: RwLock::new(HashSet::new()),
            privilege_escalation_paths: RwLock::new(HashMap::new()),
            max_entries_per_category: max_entries,
            entry_ttl: Duration::from_secs(3600), // 1 hour default
        }
    }

    /// Cache a successful IDOR pattern
    pub fn cache_idor_pattern(&self, endpoint: String, object_id: String, attacker_id: String) {
        let mut patterns = self.idor_patterns.write().unwrap();
        
        if patterns.len() >= self.max_entries_per_category {
            self.evict_old_entries(&mut patterns, &self.entry_ttl);
        }
        
        let key = format!("{}:{}", endpoint, object_id);
        if let Some(pattern) = patterns.get_mut(&key) {
            pattern.hit_count += 1;
        } else {
            patterns.insert(key, IdorPattern {
                endpoint,
                object_id_pattern: object_id,
                attacker_session_id: attacker_id,
                first_seen: Instant::now(),
                hit_count: 1,
            });
        }
    }

    /// Cache a successful BOLA pattern
    pub fn cache_bola_pattern(&self, endpoint: String, method: String, object_id: String) {
        let mut patterns = self.bola_patterns.write().unwrap();
        
        if patterns.len() >= self.max_entries_per_category {
            self.evict_old_entries(&mut patterns, &self.entry_ttl);
        }
        
        let key = format!("{}:{}:{}", endpoint, method, object_id);
        patterns.insert(key, BolaPattern {
            endpoint,
            method,
            object_id,
            first_seen: Instant::now(),
        });
    }

    /// Cache a successful mass assignment pattern
    pub fn cache_mass_assignment_pattern(&self, endpoint: String, field: String, value: String) {
        let mut patterns = self.mass_assignment_patterns.write().unwrap();
        
        if patterns.len() >= self.max_entries_per_category {
            self.evict_old_entries(&mut patterns, &self.entry_ttl);
        }
        
        let key = format!("{}:{}", endpoint, field);
        patterns.insert(key, MassAssignmentPattern {
            endpoint,
            field,
            injected_value: value,
            first_seen: Instant::now(),
        });
    }

    /// Cache a JWT weakness
    pub fn cache_jwt_weakness(&self, weakness_type: String, endpoint: String) {
        let mut weaknesses = self.jwt_weaknesses.write().unwrap();
        
        if weaknesses.len() >= self.max_entries_per_category {
            self.evict_old_entries(&mut weaknesses, &self.entry_ttl);
        }
        
        weaknesses.insert(format!("{}:{}", weakness_type, endpoint), JwtWeakness {
            weakness_type,
            endpoint,
            first_seen: Instant::now(),
        });
    }

    /// Cache a race condition pattern
    pub fn cache_race_condition_pattern(&self, endpoint: String, operation_type: String) {
        let mut patterns = self.race_condition_patterns.write().unwrap();
        
        if patterns.len() >= self.max_entries_per_category {
            self.evict_old_entries(&mut patterns, &self.entry_ttl);
        }
        
        patterns.insert(format!("{}:{}", endpoint, operation_type), RaceConditionPattern {
            endpoint,
            operation_type,
            first_seen: Instant::now(),
        });
    }

    /// Cache a protected function (negative cache)
    pub fn cache_protected_function(&self, endpoint: String, method: String) {
        let mut functions = self.protected_functions.write().unwrap();
        
        if functions.len() >= self.max_entries_per_category * 2 {
            functions.clear(); // Clear all if too many
        }
        
        functions.insert(format!("{}:{}", method, endpoint));
    }

    /// Cache a privilege escalation path
    pub fn cache_privilege_escalation_path(&self, from_role: &str, path: Vec<String>) {
        let mut paths = self.privilege_escalation_paths.write().unwrap();
        paths.insert(from_role.to_string(), path);
    }

    /// Check if an IDOR pattern is known
    pub fn has_idor_pattern(&self, endpoint: &str, object_id: &str) -> bool {
        let patterns = self.idor_patterns.read().unwrap();
        patterns.contains_key(&format!("{}:{}", endpoint, object_id))
    }

    /// Check if a BOLA pattern is known
    pub fn has_bola_pattern(&self, endpoint: &str, method: &str, object_id: &str) -> bool {
        let patterns = self.bola_patterns.read().unwrap();
        patterns.contains_key(&format!("{}:{}:{}", endpoint, method, object_id))
    }

    /// Check if a JWT weakness is known
    pub fn has_jwt_weakness(&self, weakness_type: &str, endpoint: &str) -> bool {
        let weaknesses = self.jwt_weaknesses.read().unwrap();
        weaknesses.contains_key(&format!("{}:{}", weakness_type, endpoint))
    }

    /// Check if a function is known to be protected
    pub fn is_protected_function(&self, endpoint: &str, method: &str) -> bool {
        let functions = self.protected_functions.read().unwrap();
        functions.contains(&format!("{}:{}", method, endpoint))
    }

    /// Get all cached IDOR patterns
    pub fn get_idor_patterns(&self) -> Vec<IdorPattern> {
        self.idor_patterns.read().unwrap().values().cloned().collect()
    }

    /// Get all cached BOLA patterns
    pub fn get_bola_patterns(&self) -> Vec<BolaPattern> {
        self.bola_patterns.read().unwrap().values().cloned().collect()
    }

    /// Get all cached JWT weaknesses
    pub fn get_jwt_weaknesses(&self) -> Vec<JwtWeakness> {
        self.jwt_weaknesses.read().unwrap().values().cloned().collect()
    }

    /// Get statistics about the cache
    pub fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("idor_patterns", self.idor_patterns.read().unwrap().len());
        stats.insert("bola_patterns", self.bola_patterns.read().unwrap().len());
        stats.insert("mass_assignment_patterns", self.mass_assignment_patterns.read().unwrap().len());
        stats.insert("jwt_weaknesses", self.jwt_weaknesses.read().unwrap().len());
        stats.insert("race_condition_patterns", self.race_condition_patterns.read().unwrap().len());
        stats.insert("protected_functions", self.protected_functions.read().unwrap().len());
        stats.insert("privilege_escalation_paths", self.privilege_escalation_paths.read().unwrap().len());
        stats
    }

    /// Clear all caches
    pub fn clear(&self) {
        self.idor_patterns.write().unwrap().clear();
        self.bola_patterns.write().unwrap().clear();
        self.mass_assignment_patterns.write().unwrap().clear();
        self.jwt_weaknesses.write().unwrap().clear();
        self.race_condition_patterns.write().unwrap().clear();
        self.protected_functions.write().unwrap().clear();
        self.privilege_escalation_paths.write().unwrap().clear();
    }

    /// Evict old entries based on TTL
    fn evict_old_entries<T>(&self, map: &mut HashMap<String, T>, ttl: &Duration)
    where
        T: HasInstant,
    {
        let now = Instant::now();
        let keys_to_remove: Vec<String> = map
            .iter()
            .filter(|(_, v)| now.duration_since(v.instant()) > *ttl)
            .map(|(k, _)| k.clone())
            .collect();
        
        for key in keys_to_remove {
            map.remove(&key);
        }
    }
}

/// Trait for types that have an instant
trait HasInstant {
    fn instant(&self) -> Instant;
}

impl HasInstant for IdorPattern {
    fn instant(&self) -> Instant {
        self.first_seen
    }
}

impl HasInstant for BolaPattern {
    fn instant(&self) -> Instant {
        self.first_seen
    }
}

impl HasInstant for MassAssignmentPattern {
    fn instant(&self) -> Instant {
        self.first_seen
    }
}

impl HasInstant for JwtWeakness {
    fn instant(&self) -> Instant {
        self.first_seen
    }
}

impl HasInstant for RaceConditionPattern {
    fn instant(&self) -> Instant {
        self.first_seen
    }
}

impl Default for AccessCache {
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_idor_pattern() {
        let cache = AccessCache::new(100);
        
        cache.cache_idor_pattern("/api/users/1".to_string(), "1".to_string(), "attacker1".to_string());
        
        assert!(cache.has_idor_pattern("/api/users/1", "1"));
        assert!(!cache.has_idor_pattern("/api/users/2", "2"));
    }

    #[test]
    fn test_cache_bola_pattern() {
        let cache = AccessCache::new(100);
        
        cache.cache_bola_pattern("/api/posts/1".to_string(), "GET".to_string(), "1".to_string());
        
        assert!(cache.has_bola_pattern("/api/posts/1", "GET", "1"));
    }

    #[test]
    fn test_cache_stats() {
        let cache = AccessCache::new(100);
        
        cache.cache_idor_pattern("/api/test/1".to_string(), "1".to_string(), "attacker".to_string());
        cache.cache_jwt_weakness("alg_none".to_string(), "/api/auth".to_string());
        
        let stats = cache.stats();
        assert_eq!(stats.get("idor_patterns"), Some(&1));
        assert_eq!(stats.get("jwt_weaknesses"), Some(&1));
    }

    #[test]
    fn test_bounded_cache() {
        let cache = AccessCache::new(5);
        
        // Add more than max entries
        for i in 0..10 {
            cache.cache_idor_pattern(
                format!("/api/test/{}", i),
                i.to_string(),
                "attacker".to_string(),
            );
        }
        
        let stats = cache.stats();
        assert!(stats.get("idor_patterns").unwrap() <= &5);
    }
}
