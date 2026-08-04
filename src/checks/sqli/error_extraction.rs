//! Error Extraction Module for SQL Injection
//! Extract leaked DBMS metadata from error messages without excessive requests.

use std::collections::HashMap;

/// Maximum metadata entries to cache (bounded memory)
const MAX_METADATA_ENTRIES: usize = 100;

/// Extracted database metadata
#[derive(Debug, Clone)]
pub struct DbmsMetadata {
    pub dbms_type: String,
    pub version: Option<String>,
    pub user: Option<String>,
    pub database_name: Option<String>,
    pub hostname: Option<String>,
    pub os_info: Option<String>,
    pub extraction_confidence: f64,
}

/// Metadata extraction patterns
struct ExtractionPattern {
    regex_pattern: &'static str,
    capture_group: usize,
    metadata_field: MetadataField,
}

#[derive(Debug, Clone, Copy)]
enum MetadataField {
    Version,
    User,
    DatabaseName,
    Hostname,
    OsInfo,
}

/// Error-based metadata extractor
pub struct MetadataExtractor {
    patterns: Vec<ExtractionPattern>,
    metadata_cache: HashMap<String, DbmsMetadata>,
}

impl MetadataExtractor {
    /// Create a new metadata extractor
    pub fn new() -> Self {
        let mut extractor = Self {
            patterns: Vec::new(),
            metadata_cache: HashMap::with_capacity(MAX_METADATA_ENTRIES),
        };
        extractor.initialize_patterns();
        extractor
    }

    /// Initialize extraction patterns for various DBMS
    fn initialize_patterns(&mut self) {
        // MySQL version patterns
        self.patterns.push(ExtractionPattern {
            regex_pattern: r"MySQL server version: ([\d.]+)",
            capture_group: 1,
            metadata_field: MetadataField::Version,
        });

        self.patterns.push(ExtractionPattern {
            regex_pattern: r"via MySQL ([\d.]+)",
            capture_group: 1,
            metadata_field: MetadataField::Version,
        });

        // PostgreSQL version patterns
        self.patterns.push(ExtractionPattern {
            regex_pattern: r"PostgreSQL ([\d.]+)",
            capture_group: 1,
            metadata_field: MetadataField::Version,
        });

        // MSSQL version patterns
        self.patterns.push(ExtractionPattern {
            regex_pattern: r"Microsoft SQL Server ([\d]+)",
            capture_group: 1,
            metadata_field: MetadataField::Version,
        });

        // Oracle version patterns
        self.patterns.push(ExtractionPattern {
            regex_pattern: r"Oracle Database.*?([\d.]+)",
            capture_group: 1,
            metadata_field: MetadataField::Version,
        });

        // User extraction patterns
        self.patterns.push(ExtractionPattern {
            regex_pattern: r"Access denied for user '([^']+)'",
            capture_group: 1,
            metadata_field: MetadataField::User,
        });

        self.patterns.push(ExtractionPattern {
            regex_pattern: r"user '([^']+)'@",
            capture_group: 1,
            metadata_field: MetadataField::User,
        });

        // Database name patterns
        self.patterns.push(ExtractionPattern {
            regex_pattern: r"database '?([^\s'\"]+)'?",
            capture_group: 1,
            metadata_field: MetadataField::DatabaseName,
        });

        self.patterns.push(ExtractionPattern {
            regex_pattern: r"schema '?([^\s'\"]+)'?",
            capture_group: 1,
            metadata_field: MetadataField::DatabaseName,
        });

        // Hostname patterns
        self.patterns.push(ExtractionPattern {
            regex_pattern: r"@ '([^']+)'",
            capture_group: 1,
            metadata_field: MetadataField::Hostname,
        });

        // OS info patterns
        self.patterns.push(ExtractionPattern {
            regex_pattern: r"on ((?:Win|Lin|Mac)[^\s]*)",
            capture_group: 1,
            metadata_field: MetadataField::OsInfo,
        });
    }

    /// Extract metadata from error content
    pub fn extract(&self, error_content: &str) -> Option<DbmsMetadata> {
        let mut metadata = DbmsMetadata {
            dbms_type: self.identify_dbms(error_content),
            version: None,
            user: None,
            database_name: None,
            hostname: None,
            os_info: None,
            extraction_confidence: 0.0,
        };

        let mut fields_found = 0;

        for pattern in &self.patterns {
            if let Some(value) = self.simple_match(error_content, pattern.regex_pattern, pattern.capture_group) {
                match pattern.metadata_field {
                    MetadataField::Version => metadata.version = Some(value),
                    MetadataField::User => metadata.user = Some(value),
                    MetadataField::DatabaseName => metadata.database_name = Some(value),
                    MetadataField::Hostname => metadata.hostname = Some(value),
                    MetadataField::OsInfo => metadata.os_info = Some(value),
                }
                fields_found += 1;
            }
        }

        // Calculate confidence based on fields found
        metadata.extraction_confidence = if fields_found > 0 {
            (fields_found as f64 / 5.0).min(1.0)
        } else {
            0.0
        };

        if fields_found > 0 {
            Some(metadata)
        } else {
            None
        }
    }

    /// Simple pattern matching without regex dependency
    fn simple_match(&self, content: &str, pattern: &str, _capture_group: usize) -> Option<String> {
        // Simplified matching - in production would use proper regex
        let lower_content = content.to_lowercase();
        let lower_pattern = pattern.to_lowercase();

        // Find pattern and extract value after it
        if let Some(pos) = lower_content.find(&lower_pattern) {
            let start = pos + pattern.len();
            let remaining = &content[start..];
            
            // Extract until common delimiters
            let end = remaining.find(|c: char| c == ')' || c == ',' || c == ';' || c == '\n')
                .unwrap_or(remaining.len());
            
            let value = remaining[..end].trim().to_string();
            if !value.is_empty() && value.len() < 256 {
                return Some(value);
            }
        }

        None
    }

    /// Identify DBMS type from error content
    fn identify_dbms(&self, content: &str) -> String {
        let lower = content.to_lowercase();

        if lower.contains("mysql") || lower.contains("mariadb") {
            "MySQL".to_string()
        } else if lower.contains("postgres") {
            "PostgreSQL".to_string()
        } else if lower.contains("sql server") || lower.contains("mssql") {
            "MSSQL".to_string()
        } else if lower.contains("oracle") || lower.contains("ora-") {
            "Oracle".to_string()
        } else if lower.contains("sqlite") {
            "SQLite".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    /// Cache extracted metadata for future reference
    pub fn cache_metadata(&mut self, key: &str, metadata: DbmsMetadata) {
        if self.metadata_cache.len() < MAX_METADATA_ENTRIES {
            self.metadata_cache.insert(key.to_string(), metadata);
        }
    }

    /// Get cached metadata
    pub fn get_cached(&self, key: &str) -> Option<&DbmsMetadata> {
        self.metadata_cache.get(key)
    }

    /// Clear metadata cache
    pub fn clear_cache(&mut self) {
        self.metadata_cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            entry_count: self.metadata_cache.len(),
            max_entries: MAX_METADATA_ENTRIES,
        }
    }
}

impl Default for MetadataExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entry_count: usize,
    pub max_entries: usize,
}

/// Metadata aggregation for multiple error samples
pub struct MetadataAggregator {
    samples: Vec<DbmsMetadata>,
    aggregated: Option<DbmsMetadata>,
}

impl MetadataAggregator {
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
            aggregated: None,
        }
    }

    /// Add a metadata sample
    pub fn add_sample(&mut self, metadata: DbmsMetadata) {
        if self.samples.len() < 20 {
            self.samples.push(metadata);
            self.recalculate_aggregate();
        }
    }

    /// Recalculate aggregated metadata from samples
    fn recalculate_aggregate(&mut self) {
        if self.samples.is_empty() {
            return;
        }

        let mut version_counts: HashMap<String, usize> = HashMap::new();
        let mut user_counts: HashMap<String, usize> = HashMap::new();
        let mut db_counts: HashMap<String, usize> = HashMap::new();

        for sample in &self.samples {
            if let Some(ref v) = sample.version {
                *version_counts.entry(v.clone()).or_insert(0) += 1;
            }
            if let Some(ref u) = sample.user {
                *user_counts.entry(u.clone()).or_insert(0) += 1;
            }
            if let Some(ref d) = sample.database_name {
                *db_counts.entry(d.clone()).or_insert(0) += 1;
            }
        }

        // Find most common values
        let version = version_counts.into_iter().max_by_key(|(_, v)| *v).map(|(k, _)| k);
        let user = user_counts.into_iter().max_by_key(|(_, v)| *v).map(|(k, _)| k);
        let database_name = db_counts.into_iter().max_by_key(|(_, v)| *v).map(|(k, _)| k);

        let avg_confidence = self.samples.iter().map(|s| s.extraction_confidence).sum::<f64>()
            / self.samples.len() as f64;

        self.aggregated = Some(DbmsMetadata {
            dbms_type: self.samples[0].dbms_type.clone(),
            version,
            user,
            database_name,
            hostname: self.samples.first().and_then(|s| s.hostname.clone()),
            os_info: self.samples.first().and_then(|s| s.os_info.clone()),
            extraction_confidence: avg_confidence,
        });
    }

    /// Get aggregated result
    pub fn get_aggregated(&self) -> Option<&DbmsMetadata> {
        self.aggregated.as_ref()
    }

    /// Reset aggregator
    pub fn reset(&mut self) {
        self.samples.clear();
        self.aggregated = None;
    }
}

impl Default for MetadataAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_extraction() {
        let extractor = MetadataExtractor::new();
        let content = "Error connecting to MySQL server version: 5.7.32";
        
        let metadata = extractor.extract(content);
        assert!(metadata.is_some());
        assert_eq!(metadata.unwrap().dbms_type, "MySQL");
    }

    #[test]
    fn test_user_extraction() {
        let extractor = MetadataExtractor::new();
        let content = "Access denied for user 'root'@'localhost'";
        
        let metadata = extractor.extract(content);
        assert!(metadata.is_some());
        assert!(metadata.unwrap().user.is_some());
    }

    #[test]
    fn test_cache_operations() {
        let mut extractor = MetadataExtractor::new();
        
        let metadata = DbmsMetadata {
            dbms_type: "MySQL".to_string(),
            version: Some("5.7".to_string()),
            user: None,
            database_name: None,
            hostname: None,
            os_info: None,
            extraction_confidence: 0.8,
        };
        
        extractor.cache_metadata("test_key", metadata);
        assert!(extractor.get_cached("test_key").is_some());
        
        extractor.clear_cache();
        assert!(extractor.get_cached("test_key").is_none());
    }

    #[test]
    fn test_aggregator() {
        let mut aggregator = MetadataAggregator::new();
        
        aggregator.add_sample(DbmsMetadata {
            dbms_type: "MySQL".to_string(),
            version: Some("5.7".to_string()),
            user: Some("root".to_string()),
            database_name: None,
            hostname: None,
            os_info: None,
            extraction_confidence: 0.8,
        });
        
        aggregator.add_sample(DbmsMetadata {
            dbms_type: "MySQL".to_string(),
            version: Some("5.7".to_string()),
            user: Some("root".to_string()),
            database_name: None,
            hostname: None,
            os_info: None,
            extraction_confidence: 0.9,
        });
        
        let aggregated = aggregator.get_aggregated();
        assert!(aggregated.is_some());
        assert_eq!(aggregated.unwrap().version, Some("5.7".to_string()));
    }
}
