//! Payload Registry - Global mapping of payload IDs to vulnerability classes and tags
//! 
//! This module provides a thread-safe registry for managing payloads categorized by
//! vulnerability class, severity level, and safety classification. Designed for the
//! 100-agent swarm with deterministic, learnable payload generation.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use crate::payload::class::{PayloadClass, Severity, SafetyLevel, VulnerabilityTag};

/// Unique identifier for a payload
pub type PayloadId = String;

/// Metadata associated with each payload
#[derive(Debug, Clone)]
pub struct PayloadMeta {
    pub id: PayloadId,
    pub class: PayloadClass,
    pub severity: Severity,
    pub safety: SafetyLevel,
    pub tags: HashSet<VulnerabilityTag>,
    pub description: String,
    pub cwe_ids: Vec<String>,
    pub created_at: u64,
}

impl PayloadMeta {
    pub fn new(
        id: impl Into<String>,
        class: PayloadClass,
        severity: Severity,
        safety: SafetyLevel,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            class,
            severity,
            safety,
            tags: HashSet::new(),
            description: description.into(),
            cwe_ids: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn with_tags(mut self, tags: Vec<VulnerabilityTag>) -> Self {
        self.tags.extend(tags);
        self
    }

    pub fn with_cwe(mut self, cwe_ids: Vec<&str>) -> Self {
        self.cwe_ids = cwe_ids.into_iter().map(String::from).collect();
        self
    }
}

/// Thread-safe payload registry for the scanner core
#[derive(Debug, Default)]
pub struct PayloadRegistry {
    inner: Arc<RwLock<RegistryInner>>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    payloads: HashMap<PayloadId, PayloadMeta>,
    by_class: HashMap<PayloadClass, HashSet<PayloadId>>,
    by_severity: HashMap<Severity, HashSet<PayloadId>>,
    by_safety: HashMap<SafetyLevel, HashSet<PayloadId>>,
    by_tag: HashMap<VulnerabilityTag, HashSet<PayloadId>>,
}

impl PayloadRegistry {
    /// Create a new empty payload registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new payload with metadata
    pub fn register(&self, meta: PayloadMeta) -> Result<(), RegistryError> {
        let mut inner = self.inner.write().map_err(|_| RegistryError::Poisoned)?;
        
        let id = meta.id.clone();
        
        // Index by class
        inner.by_class
            .entry(meta.class.clone())
            .or_default()
            .insert(id.clone());
        
        // Index by severity
        inner.by_severity
            .entry(meta.severity)
            .or_default()
            .insert(id.clone());
        
        // Index by safety level
        inner.by_safety
            .entry(meta.safety)
            .or_default()
            .insert(id.clone());
        
        // Index by tags
        for tag in &meta.tags {
            inner.by_tag
                .entry(tag.clone())
                .or_default()
                .insert(id.clone());
        }
        
        inner.payloads.insert(id, meta);
        Ok(())
    }

    /// Get payload metadata by ID
    pub fn get(&self, id: &str) -> Option<PayloadMeta> {
        let inner = self.inner.read().ok()?;
        inner.payloads.get(id).cloned()
    }

    /// Get all payloads for a specific class
    pub fn get_by_class(&self, class: &PayloadClass) -> Vec<PayloadMeta> {
        let inner = self.inner.read().ok().unwrap();
        let ids = inner.by_class.get(class).map(|s| s.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        drop(inner);
        
        ids.into_iter()
            .filter_map(|id| self.get(&id))
            .collect()
    }

    /// Get payloads filtered by safety level
    pub fn get_safe_payloads(&self) -> Vec<PayloadMeta> {
        self.get_by_safety(&SafetyLevel::Safe)
    }

    /// Get payloads by safety level
    pub fn get_by_safety(&self, safety: &SafetyLevel) -> Vec<PayloadMeta> {
        let inner = self.inner.read().ok().unwrap();
        let ids = inner.by_safety.get(safety).map(|s| s.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        drop(inner);
        
        ids.into_iter()
            .filter_map(|id| self.get(&id))
            .collect()
    }

    /// Get payloads by severity
    pub fn get_by_severity(&self, severity: &Severity) -> Vec<PayloadMeta> {
        let inner = self.inner.read().ok().unwrap();
        let ids = inner.by_severity.get(severity).map(|s| s.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        drop(inner);
        
        ids.into_iter()
            .filter_map(|id| self.get(&id))
            .collect()
    }

    /// Search payloads by tag
    pub fn get_by_tag(&self, tag: &VulnerabilityTag) -> Vec<PayloadMeta> {
        let inner = self.inner.read().ok().unwrap();
        let ids = inner.by_tag.get(tag).map(|s| s.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        drop(inner);
        
        ids.into_iter()
            .filter_map(|id| self.get(&id))
            .collect()
    }

    /// Get all registered payload IDs
    pub fn all_ids(&self) -> Vec<PayloadId> {
        let inner = self.inner.read().ok().unwrap();
        inner.payloads.keys().cloned().collect()
    }

    /// Get total payload count
    pub fn count(&self) -> usize {
        let inner = self.inner.read().ok().unwrap();
        inner.payloads.len()
    }

    /// Check if a payload ID exists
    pub fn contains(&self, id: &str) -> bool {
        let inner = self.inner.read().ok().unwrap();
        inner.payloads.contains_key(id)
    }

    /// Remove a payload from the registry
    pub fn remove(&self, id: &str) -> Option<PayloadMeta> {
        let mut inner = self.inner.write().ok()?;
        
        if let Some(meta) = inner.payloads.remove(id) {
            // Remove from secondary indices
            if let Some(set) = inner.by_class.get_mut(&meta.class) {
                set.remove(id);
            }
            if let Some(set) = inner.by_severity.get_mut(&meta.severity) {
                set.remove(id);
            }
            if let Some(set) = inner.by_safety.get_mut(&meta.safety) {
                set.remove(id);
            }
            for tag in &meta.tags {
                if let Some(set) = inner.by_tag.get_mut(tag) {
                    set.remove(id);
                }
            }
            return Some(meta);
        }
        None
    }
}

/// Registry operation errors
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("Registry lock poisoned")]
    Poisoned,
    #[error("Payload already exists: {0}")]
    Duplicate(String),
}

/// Global singleton registry instance for the scanner
lazy_static::lazy_static! {
    pub static ref GLOBAL_PAYLOAD_REGISTRY: PayloadRegistry = PayloadRegistry::new();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_basic_operations() {
        let registry = PayloadRegistry::new();
        
        let meta = PayloadMeta::new(
            "test-sqli-001",
            PayloadClass::SqlInjection,
            Severity::High,
            SafetyLevel::Safe,
            "Basic SQL injection test payload",
        );
        
        assert!(registry.register(meta).is_ok());
        assert!(registry.contains("test-sqli-001"));
        assert_eq!(registry.count(), 1);
        
        let retrieved = registry.get("test-sqli-001").unwrap();
        assert_eq!(retrieved.class, PayloadClass::SqlInjection);
        assert_eq!(retrieved.severity, Severity::High);
    }

    #[test]
    fn test_registry_filtering() {
        let registry = PayloadRegistry::new();
        
        registry.register(PayloadMeta::new(
            "xss-001",
            PayloadClass::Xss,
            Severity::Medium,
            SafetyLevel::Safe,
            "XSS test",
        )).unwrap();
        
        registry.register(PayloadMeta::new(
            "sqli-001",
            PayloadClass::SqlInjection,
            Severity::High,
            SafetyLevel::Unsafe,
            "SQLi test",
        )).unwrap();
        
        let safe_payloads = registry.get_safe_payloads();
        assert_eq!(safe_payloads.len(), 1);
        assert_eq!(safe_payloads[0].id, "xss-001");
        
        let high_severity = registry.get_by_severity(&Severity::High);
        assert_eq!(high_severity.len(), 1);
    }
}
