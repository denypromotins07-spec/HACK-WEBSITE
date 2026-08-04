//! Privilege Fields Dictionary Module
//! Maintains a bounded dictionary of sensitive fields and API privilege verbs.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// Default sensitive fields that indicate privilege escalation potential
const DEFAULT_SENSITIVE_FIELDS: &[&str] = &[
    // Role/Permission fields
    "role",
    "roles",
    "permission",
    "permissions",
    "privilege",
    "privileges",
    "access_level",
    "scope",
    "scopes",
    
    // Admin flags
    "is_admin",
    "admin",
    "is_superuser",
    "superuser",
    "is_staff",
    "staff",
    "is_moderator",
    "moderator",
    
    // Account status
    "verified",
    "is_verified",
    "email_verified",
    "phone_verified",
    "active",
    "is_active",
    "enabled",
    "status",
    "account_status",
    
    // User type/classification
    "user_type",
    "account_type",
    "tier",
    "subscription_tier",
    "membership_level",
    "class",
    "group",
    "groups",
    
    // Financial/Resource fields
    "balance",
    "credits",
    "currency",
    "limit",
    "quota",
    "rate_limit",
    
    // Security fields
    "mfa_enabled",
    "two_factor",
    "password",
    "password_hash",
    "secret",
    "api_key",
    "token",
    
    // Ownership/control
    "owner",
    "owner_id",
    "created_by",
    "controlled_by",
];

/// Privilege-related API verbs/actions
const PRIVILEGE_VERBS: &[&str] = &[
    "grant",
    "revoke",
    "assign",
    "remove",
    "elevate",
    "promote",
    "demote",
    "approve",
    "reject",
    "enable",
    "disable",
    "activate",
    "deactivate",
    "suspend",
    "unsuspend",
    "lock",
    "unlock",
    "delete",
    "purge",
    "reset",
    "override",
    "bypass",
    "impersonate",
];

/// Bounded dictionary of sensitive fields and privilege verbs
pub struct PrivilegeFieldsDictionary {
    /// Sensitive field names
    sensitive_fields: RwLock<HashSet<String>>,
    /// Field aliases/mappings
    field_aliases: RwLock<HashMap<String, String>>,
    /// Privilege verbs for API endpoints
    privilege_verbs: RwLock<HashSet<String>>,
    /// Custom user-added fields
    custom_fields: RwLock<HashSet<String>>,
    /// Maximum bounded size
    max_entries: usize,
}

impl PrivilegeFieldsDictionary {
    pub fn new(max_entries: usize) -> Self {
        let mut sensitive_fields = HashSet::new();
        for field in DEFAULT_SENSITIVE_FIELDS {
            sensitive_fields.insert(field.to_string());
        }
        
        let mut privilege_verbs = HashSet::new();
        for verb in PRIVILEGE_VERBS {
            privilege_verbs.insert(verb.to_string());
        }
        
        Self {
            sensitive_fields: RwLock::new(sensitive_fields),
            field_aliases: RwLock::new(HashMap::new()),
            privilege_verbs: RwLock::new(privilege_verbs),
            custom_fields: RwLock::new(HashSet::new()),
            max_entries,
        }
    }

    /// Check if a field name is considered sensitive
    pub fn is_sensitive(&self, field_name: &str) -> bool {
        let lower = field_name.to_lowercase();
        let sensitive = self.sensitive_fields.read().unwrap();
        let custom = self.custom_fields.read().unwrap();
        
        sensitive.contains(&lower) || custom.contains(&lower)
    }

    /// Get all sensitive fields
    pub fn get_sensitive_fields(&self) -> HashSet<String> {
        let sensitive = self.sensitive_fields.read().unwrap();
        let custom = self.custom_fields.read().unwrap();
        
        let mut result = sensitive.clone();
        result.extend(custom.iter().cloned());
        result
    }

    /// Add a custom sensitive field
    pub fn add_custom_field(&self, field: String) {
        let mut custom = self.custom_fields.write().unwrap();
        if custom.len() < self.max_entries {
            custom.insert(field.to_lowercase());
        }
    }

    /// Register a field alias (e.g., "isAdmin" -> "is_admin")
    pub fn register_alias(&self, alias: String, canonical: String) {
        let mut aliases = self.field_aliases.write().unwrap();
        if aliases.len() < self.max_entries {
            aliases.insert(alias.to_lowercase(), canonical.to_lowercase());
        }
    }

    /// Get the canonical name for a field (or return the original)
    pub fn get_canonical(&self, field: &str) -> String {
        let aliases = self.field_aliases.read().unwrap();
        aliases.get(&field.to_lowercase()).cloned().unwrap_or_else(|| field.to_string())
    }

    /// Check if a verb indicates a privileged operation
    pub fn is_privilege_verb(&self, verb: &str) -> bool {
        let verbs = self.privilege_verbs.read().unwrap();
        verbs.contains(&verb.to_lowercase())
    }

    /// Get all privilege verbs
    pub fn get_privilege_verbs(&self) -> HashSet<String> {
        self.privilege_verbs.read().unwrap().clone()
    }

    /// Add a custom privilege verb
    pub fn add_privilege_verb(&self, verb: String) {
        let mut verbs = self.privilege_verbs.write().unwrap();
        if verbs.len() < self.max_entries {
            verbs.insert(verb.to_lowercase());
        }
    }

    /// Score a field based on sensitivity level
    pub fn sensitivity_score(&self, field: &str) -> u8 {
        let lower = field.to_lowercase();
        
        // Critical fields (direct privilege escalation)
        if ["is_admin", "admin", "role", "roles", "permissions"].contains(&lower.as_str()) {
            return 100;
        }
        
        // High sensitivity (security-related)
        if ["is_superuser", "is_staff", "privilege", "access_level"].contains(&lower.as_str()) {
            return 80;
        }
        
        // Medium sensitivity (status/type fields)
        if ["verified", "active", "status", "user_type", "tier"].contains(&lower.as_str()) {
            return 60;
        }
        
        // Low sensitivity (general fields that could be abused)
        if self.is_sensitive(&lower) {
            return 40;
        }
        
        0
    }

    /// Analyze a JSON object for sensitive fields
    pub fn analyze_json(&self, json: &serde_json::Value) -> Vec<(String, u8)> {
        let mut results = Vec::new();
        self.analyze_json_recursive(json, "", &mut results);
        results
    }

    fn analyze_json_recursive(
        &self,
        value: &serde_json::Value,
        path: &str,
        results: &mut Vec<(String, u8)>,
    ) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    
                    if self.is_sensitive(key) {
                        let score = self.sensitivity_score(key);
                        results.push((new_path, score));
                    }
                    
                    self.analyze_json_recursive(val, &new_path, results);
                }
            }
            serde_json::Value::Array(arr) => {
                for (idx, item) in arr.iter().enumerate() {
                    let new_path = format!("{}[{}]", path, idx);
                    self.analyze_json_recursive(item, &new_path, results);
                }
            }
            _ => {}
        }
    }

    /// Clear custom fields (for memory management)
    pub fn clear_custom(&self) {
        self.custom_fields.write().unwrap().clear();
    }

    /// Get statistics about the dictionary
    pub fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("sensitive_fields", self.sensitive_fields.read().unwrap().len());
        stats.insert("custom_fields", self.custom_fields.read().unwrap().len());
        stats.insert("privilege_verbs", self.privilege_verbs.read().unwrap().len());
        stats.insert("field_aliases", self.field_aliases.read().unwrap().len());
        stats
    }
}

impl Default for PrivilegeFieldsDictionary {
    fn default() -> Self {
        Self::new(500)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_default_sensitive_fields() {
        let dict = PrivilegeFieldsDictionary::new(500);
        
        assert!(dict.is_sensitive("is_admin"));
        assert!(dict.is_sensitive("role"));
        assert!(dict.is_sensitive("permissions"));
        assert!(dict.is_sensitive("tier"));
        assert!(!dict.is_sensitive("username"));
        assert!(!dict.is_sensitive("email"));
    }

    #[test]
    fn test_privilege_verbs() {
        let dict = PrivilegeFieldsDictionary::new(500);
        
        assert!(dict.is_privilege_verb("grant"));
        assert!(dict.is_privilege_verb("elevate"));
        assert!(dict.is_privilege_verb("impersonate"));
        assert!(!dict.is_privilege_verb("get"));
        assert!(!dict.is_privilege_verb("list"));
    }

    #[test]
    fn test_sensitivity_scoring() {
        let dict = PrivilegeFieldsDictionary::new(500);
        
        assert_eq!(dict.sensitivity_score("is_admin"), 100);
        assert_eq!(dict.sensitivity_score("role"), 100);
        assert_eq!(dict.sensitivity_score("is_superuser"), 80);
        assert_eq!(dict.sensitivity_score("verified"), 60);
        assert_eq!(dict.sensitivity_score("random_field"), 0);
    }

    #[test]
    fn test_json_analysis() {
        let dict = PrivilegeFieldsDictionary::new(500);
        let json_data = json!({
            "user": {
                "id": "123",
                "is_admin": false,
                "role": "user",
                "name": "John"
            },
            "settings": {
                "verified": true,
                "theme": "dark"
            }
        });
        
        let results = dict.analyze_json(&json_data);
        assert!(results.iter().any(|(path, _)| path.contains("is_admin")));
        assert!(results.iter().any(|(path, _)| path.contains("role")));
        assert!(results.iter().any(|(path, _)| path.contains("verified")));
    }

    #[test]
    fn test_custom_fields() {
        let dict = PrivilegeFieldsDictionary::new(500);
        
        assert!(!dict.is_sensitive("custom_privilege"));
        dict.add_custom_field("custom_privilege".to_string());
        assert!(dict.is_sensitive("custom_privilege"));
    }
}
