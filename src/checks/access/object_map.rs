//! Object Identifier Mapping Module
//! Builds object identifier maps from routes, JSON keys, and GraphQL fields.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// Maps object identifiers found in various contexts
pub struct ObjectIdentifierMap {
    /// Route patterns with ID placeholders
    route_ids: RwLock<HashMap<String, HashSet<String>>>,
    /// JSON keys that contain object IDs
    json_id_keys: RwLock<HashSet<String>>,
    /// GraphQL fields that reference objects
    graphql_fields: RwLock<HashSet<String>>,
    /// Discovered ID patterns
    id_patterns: RwLock<Vec<String>>,
    /// Maximum bounded size for memory efficiency
    max_entries: usize,
}

impl ObjectIdentifierMap {
    pub fn new(max_entries: usize) -> Self {
        Self {
            route_ids: RwLock::new(HashMap::new()),
            json_id_keys: RwLock::new(HashSet::new()),
            graphql_fields: RwLock::new(HashSet::new()),
            id_patterns: RwLock::new(Vec::new()),
            max_entries,
        }
    }

    /// Extract object IDs from URL routes
    pub fn extract_from_routes(&self, routes: &[String]) {
        let mut route_ids = self.route_ids.write().unwrap();
        
        let id_regex = regex::Regex::new(r"/(\d+|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|[a-zA-Z0-9_-]{8,})").unwrap();
        
        for route in routes {
            if let Some(captures) = id_regex.captures(route) {
                if let Some(m) = captures.get(1) {
                    let id = m.as_str().to_string();
                    let pattern = route.replace(&id, "{id}");
                    
                    // Enforce bounded size
                    if route_ids.len() < self.max_entries {
                        route_ids.entry(pattern).or_insert_with(HashSet::new).insert(id);
                    }
                }
            }
        }
    }

    /// Extract object ID keys from JSON responses
    pub fn extract_from_json(&self, json_data: &serde_json::Value) {
        let mut json_keys = self.json_id_keys.write().unwrap();
        self.extract_json_ids_recursive(json_data, &mut json_keys, "");
    }

    fn extract_json_ids_recursive(
        &self,
        value: &serde_json::Value,
        keys: &mut HashSet<String>,
        path: &str,
    ) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    
                    // Check if key looks like an ID field
                    if self.is_id_key(key) {
                        if keys.len() < self.max_entries {
                            keys.insert(new_path);
                        }
                    }
                    
                    self.extract_json_ids_recursive(val, keys, &new_path);
                }
            }
            serde_json::Value::Array(arr) => {
                for (idx, item) in arr.iter().enumerate() {
                    let new_path = format!("{}[{}]", path, idx);
                    self.extract_json_ids_recursive(item, keys, &new_path);
                }
            }
            _ => {}
        }
    }

    /// Check if a key name suggests it contains an object ID
    fn is_id_key(&self, key: &str) -> bool {
        let lower = key.to_lowercase();
        lower.contains("id") 
            || lower.contains("uuid")
            || lower.contains("ref")
            || lower.ends_with("_id")
            || lower == "oid"
            || lower == "object_id"
    }

    /// Extract object references from GraphQL schemas/queries
    pub fn extract_from_graphql(&self, graphql_content: &str) {
        let mut fields = self.graphql_fields.write().unwrap();
        
        // Match field patterns like: user(id: $id), post(id: ...)
        let field_regex = regex::Regex::new(r"(\w+)\s*\(\s*(?:id|objectId|userId|postId)\s*:").unwrap();
        
        for cap in field_regex.captures_iter(graphql_content) {
            if let Some(field) = cap.get(1) {
                if fields.len() < self.max_entries {
                    fields.insert(field.as_str().to_string());
                }
            }
        }
        
        // Match type definitions with ID fields
        let type_regex = regex::Regex::new(r"type\s+(\w+)\s*\{[^}]*id\s*:\s*ID!").unwrap();
        for cap in type_regex.captures_iter(graphql_content) {
            if let Some(type_name) = cap.get(1) {
                if fields.len() < self.max_entries {
                    fields.insert(format!("query {}", type_name.to_lowercase()));
                }
            }
        }
    }

    /// Get all discovered route patterns
    pub fn get_route_patterns(&self) -> HashMap<String, HashSet<String>> {
        self.route_ids.read().unwrap().clone()
    }

    /// Get all JSON ID keys
    pub fn get_json_id_keys(&self) -> HashSet<String> {
        self.json_id_keys.read().unwrap().clone()
    }

    /// Get all GraphQL fields
    pub fn get_graphql_fields(&self) -> HashSet<String> {
        self.graphql_fields.read().unwrap().clone()
    }

    /// Register a discovered ID pattern
    pub fn register_pattern(&self, pattern: String) {
        let mut patterns = self.id_patterns.write().unwrap();
        if patterns.len() < self.max_entries && !patterns.contains(&pattern) {
            patterns.push(pattern);
        }
    }

    /// Get all registered patterns
    pub fn get_patterns(&self) -> Vec<String> {
        self.id_patterns.read().unwrap().clone()
    }

    /// Build comprehensive object map from crawled data
    pub fn build_from_crawl_data(
        &self,
        routes: &[String],
        json_responses: &[serde_json::Value],
        graphql_schemas: &[&str],
    ) {
        self.extract_from_routes(routes);
        
        for json in json_responses {
            self.extract_from_json(json);
        }
        
        for schema in graphql_schemas {
            self.extract_from_graphql(schema);
        }
    }

    /// Generate test endpoints from the object map
    pub fn generate_test_endpoints(&self) -> Vec<String> {
        let mut endpoints = Vec::new();
        let route_ids = self.route_ids.read().unwrap();
        
        for (pattern, ids) in route_ids.iter() {
            for id in ids.iter().take(5) {
                endpoints.push(pattern.replace("{id}", id));
            }
        }
        
        endpoints
    }

    /// Clear the map (for memory management)
    pub fn clear(&self) {
        self.route_ids.write().unwrap().clear();
        self.json_id_keys.write().unwrap().clear();
        self.graphql_fields.write().unwrap().clear();
        self.id_patterns.write().unwrap().clear();
    }
}

impl Default for ObjectIdentifierMap {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_route_extraction() {
        let map = ObjectIdentifierMap::new(100);
        let routes = vec![
            "/api/users/123".to_string(),
            "/api/posts/abc-def-ghi".to_string(),
            "/api/comments/550e8400-e29b-41d4-a716-446655440000".to_string(),
        ];
        
        map.extract_from_routes(&routes);
        let patterns = map.get_route_patterns();
        
        assert!(patterns.contains_key("/api/users/{id}"));
        assert!(patterns.contains_key("/api/posts/{id}"));
    }

    #[test]
    fn test_json_extraction() {
        let map = ObjectIdentifierMap::new(100);
        let json_data = json!({
            "user": {
                "id": "123",
                "name": "John",
                "profile": {
                    "user_id": "456"
                }
            },
            "posts": [
                {"post_id": "789", "title": "Hello"}
            ]
        });
        
        map.extract_from_json(&json_data);
        let keys = map.get_json_id_keys();
        
        assert!(keys.contains("user.id"));
        assert!(keys.contains("user.profile.user_id"));
    }

    #[test]
    fn test_id_key_detection() {
        let map = ObjectIdentifierMap::new(100);
        
        assert!(map.is_id_key("user_id"));
        assert!(map.is_id_key("ID"));
        assert!(map.is_id_key("uuid"));
        assert!(map.is_id_key("objectRef"));
        assert!(!map.is_id_key("username"));
        assert!(!map.is_id_key("email"));
    }
}
