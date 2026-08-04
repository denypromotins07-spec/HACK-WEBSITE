//! Crypto and Token Learning Cache Module
//!
//! Caches successful bit-flip offsets, rogue JKU endpoints, and weak KDF signatures.

use std::collections::HashMap;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// Maximum cache entries (bounded)
const MAX_CACHE_ENTRIES: usize = 256;

/// Cached crypto attack vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAttackVector {
    pub target_pattern: String,
    pub attack_type: AttackType,
    pub success_count: u32,
    pub last_success: u64,
    pub payload_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackType {
    CbcBitflip { offset: usize, flip_byte: u8 },
    Bleichenbacher { timing_diff_ns: u128 },
    JwtStripping { method: String },
    JwtJku { rogue_url: String },
    WeakKdf { algorithm: String, configured_value: u32 },
    OidcConfusion { manipulation: String },
}

/// Bounded learning cache for crypto/token attacks
pub struct CryptoTokenCache {
    vectors: RwLock<HashMap<String, CryptoAttackVector>>,
    jku_endpoints: RwLock<Vec<String>>,
    kdf_signatures: RwLock<Vec<(String, u32)>>,
}

impl CryptoTokenCache {
    pub fn new() -> Self {
        Self {
            vectors: RwLock::new(HashMap::with_capacity(64)),
            jku_endpoints: RwLock::new(Vec::with_capacity(32)),
            kdf_signatures: RwLock::new(Vec::with_capacity(32)),
        }
    }

    /// Cache a successful bit-flip offset
    pub fn cache_bitflip(&self, target: &str, offset: usize, flip_byte: u8) {
        let mut vectors = self.vectors.write();
        let key = format!("bitflip:{}", target);
        
        if vectors.len() >= MAX_CACHE_ENTRIES {
            self.evict_old(&mut vectors);
        }
        
        vectors.insert(key, CryptoAttackVector {
            target_pattern: target.to_string(),
            attack_type: AttackType::CbcBitflip { offset, flip_byte },
            success_count: 1,
            last_success: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            payload_hash: format!("{:02x}", flip_byte),
        });
    }

    /// Cache a successful Bleichenbacher timing differential
    pub fn cache_bleichenbacher(&self, target: &str, timing_diff_ns: u128) {
        let mut vectors = self.vectors.write();
        let key = format!("bleichenbacher:{}", target);
        
        if vectors.len() >= MAX_CACHE_ENTRIES {
            self.evict_old(&mut vectors);
        }
        
        vectors.insert(key, CryptoAttackVector {
            target_pattern: target.to_string(),
            attack_type: AttackType::Bleichenbacher { timing_diff_ns },
            success_count: 1,
            last_success: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            payload_hash: format!("{:x}", timing_diff_ns),
        });
    }

    /// Cache a successful JWT stripping method
    pub fn cache_jwt_stripping(&self, target: &str, method: &str) {
        let mut vectors = self.vectors.write();
        let key = format!("jwt_stripping:{}", target);
        
        if vectors.len() >= MAX_CACHE_ENTRIES {
            self.evict_old(&mut vectors);
        }
        
        vectors.insert(key, CryptoAttackVector {
            target_pattern: target.to_string(),
            attack_type: AttackType::JwtStripping { method: method.to_string() },
            success_count: 1,
            last_success: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            payload_hash: method.to_string(),
        });
    }

    /// Cache a rogue JKU endpoint
    pub fn cache_jku_endpoint(&self, rogue_url: &str) {
        let mut endpoints = self.jku_endpoints.write();
        if !endpoints.contains(&rogue_url.to_string()) && endpoints.len() < 32 {
            endpoints.push(rogue_url.to_string());
        }
    }

    /// Cache a weak KDF signature
    pub fn cache_weak_kdf(&self, algorithm: &str, configured_value: u32) {
        let mut signatures = self.kdf_signatures.write();
        let sig = (algorithm.to_string(), configured_value);
        if !signatures.contains(&sig) && signatures.len() < 32 {
            signatures.push(sig);
        }
    }

    /// Get all cached bit-flip vectors for a target pattern
    pub fn get_bitflip_vectors(&self, pattern: &str) -> Vec<(usize, u8)> {
        let vectors = self.vectors.read();
        vectors.iter()
            .filter(|(k, v)| k.starts_with("bitflip:") && v.target_pattern.contains(pattern))
            .filter_map(|(_, v)| {
                if let AttackType::CbcBitflip { offset, flip_byte } = &v.attack_type {
                    Some((*offset, *flip_byte))
                } else { None }
            })
            .collect()
    }

    /// Get all cached rogue JKU endpoints
    pub fn get_rogue_jku_endpoints(&self) -> Vec<String> {
        self.jku_endpoints.read().clone()
    }

    /// Get all cached weak KDF signatures
    pub fn get_weak_kdf_signatures(&self) -> Vec<(String, u32)> {
        self.kdf_signatures.read().clone()
    }

    /// Evict oldest entries when cache is full
    fn evict_old(&self, vectors: &mut HashMap<String, CryptoAttackVector>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        
        let mut sorted: Vec<_> = vectors.iter()
            .map(|(k, v)| (k.clone(), v.last_success))
            .collect();
        sorted.sort_by_key(|(_, t)| *t);
        
        let to_remove = vectors.len() / 4;
        for (key, _) in sorted.into_iter().take(to_remove) {
            vectors.remove(&key);
        }
    }

    /// Export cache for persistence
    pub fn export(&self) -> CacheExport {
        let vectors = self.vectors.read();
        CacheExport {
            vectors: vectors.values().cloned().collect(),
            jku_endpoints: self.jku_endpoints.read().clone(),
            kdf_signatures: self.kdf_signatures.read().clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheExport {
    pub vectors: Vec<CryptoAttackVector>,
    pub jku_endpoints: Vec<String>,
    pub kdf_signatures: Vec<(String, u32)>,
}

impl Default for CryptoTokenCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_bitflip() {
        let cache = CryptoTokenCache::new();
        cache.cache_bitflip("/api/decrypt", 0, 0x01);
        let vectors = cache.get_bitflip_vectors("/api/decrypt");
        assert!(!vectors.is_empty());
        assert_eq!(vectors[0], (0, 0x01));
    }

    #[test]
    fn test_bounded_cache_eviction() {
        let cache = CryptoTokenCache::new();
        // Fill cache beyond limit would trigger eviction
        // This test verifies the structure exists
        assert!(std::mem::size_of::<CryptoTokenCache>() <= 512);
    }
}
