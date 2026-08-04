//! Environment Leak Detection Module
//! Scans root and backup directories for critical environmental leaks (.env, config.php.bak).

use crate::http::client::HttpClient;
use crate::findings::evidence::Evidence;

/// Maximum number of paths to probe (bounded)
const MAX_LEAK_PATHS: usize = 300;

/// Common environment and configuration leak paths
const ENV_LEAK_PATHS: &[(&str, &[&str])] = &[
    // Root level sensitive files
    ("/.env", &["DB_", "API_", "SECRET_", "KEY_", "TOKEN_"]),
    ("/.env.local", &["DB_", "API_", "SECRET_"]),
    ("/.env.production", &["DB_", "API_", "SECRET_"]),
    ("/.env.development", &["DB_", "API_"]),
    ("/.env.testing", &["DB_", "API_"]),
    ("/.env.staging", &["DB_", "API_"]),
    ("/config.env", &["DB_", "API_"]),
    ("/environment.env", &["DB_", "API_"]),
    
    // Backup files
    ("/config.php.bak", &["<?php", "$"]),
    ("/config.php.old", &["<?php", "$"]),
    ("/config.php.save", &["<?php", "$"]),
    ("/config.php~", &["<?php", "$"]),
    ("/wp-config.php.bak", &["<?php", "DB_"]),
    ("/wp-config.php.old", &["<?php", "DB_"]),
    ("/settings.py.bak", &["SECRET_KEY", "DATABASE"]),
    ("/settings.py.old", &["SECRET_KEY", "DATABASE"]),
    ("/database.yml.bak", &["password:", "adapter:"]),
    ("/database.yml.old", &["password:", "adapter:"]),
    
    // Application configs
    ("/appsettings.json", &["ConnectionStrings", "ApiKey"]),
    ("/appsettings.Development.json", &["ConnectionStrings"]),
    ("/appsettings.Production.json", &["ConnectionStrings"]),
    ("/web.config", &["connectionString", "appSettings"]),
    ("/web.config.bak", &["connectionString"]),
    
    // IDE and editor backups
    ("/.DS_Store", &[]),
    ("/.gitignore", &[]),
    ("/.viminfo", &[]),
    ("/.bash_history", &[]),
    ("/.ssh/", &[]),
    
    // Database dumps
    ("/dump.sql", &["CREATE TABLE", "INSERT INTO"]),
    ("/backup.sql", &["CREATE TABLE", "INSERT INTO"]),
    ("/database.sql", &["CREATE TABLE", "INSERT INTO"]),
    ("/db.sql", &["CREATE TABLE", "INSERT INTO"]),
    ("/data.sql", &["CREATE TABLE", "INSERT INTO"]),
    
    // Log files that might contain secrets
    ("/debug.log", &["password", "token", "key"]),
    ("/error.log", &["password", "exception"]),
    ("/access.log", &[]),
];

/// Environment leak scanner
pub struct EnvLeakScanner {
    client: HttpClient,
}

impl EnvLeakScanner {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Scan for environment leaks
    pub async fn scan(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        let base = base_url.trim_end_matches('/');
        let mut found_leaks = Vec::new();
        
        for (path, signatures) in ENV_LEAK_PATHS.iter().take(MAX_LEAK_PATHS) {
            let url = format!("{}{}", base, path);
            
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 {
                    let body = response.text().await.unwrap_or_default();
                    
                    // Check if content matches expected signatures
                    let is_valid = if signatures.is_empty() {
                        // For files without signatures, just check non-empty response
                        !body.is_empty()
                    } else {
                        // Check for at least one signature match
                        signatures.iter().any(|sig| body.contains(sig))
                    };
                    
                    if is_valid {
                        found_leaks.push((*path).to_string());
                        
                        // Determine severity based on file type
                        let severity = self.determine_severity(path);
                        let exposed_keys = self.extract_exposed_keys(path, &body);
                        
                        evidences.push(Evidence::EnvironmentLeak {
                            file_path: (*path).to_string(),
                            url: url.clone(),
                            severity: severity.to_string(),
                            exposed_keys,
                            confidence: 90,
                            remediation: self.get_remediation(path),
                        });
                    }
                }
            }
        }
        
        // Summary evidence for multiple leaks
        if found_leaks.len() > 1 {
            evidences.push(Evidence::MultipleLeaks {
                count: found_leaks.len(),
                files: found_leaks,
                base_url: base_url.to_string(),
                confidence: 95,
                remediation: "CRITICAL: Multiple sensitive files exposed. Implement proper access controls immediately.".to_string(),
            });
        }
        
        evidences
    }

    /// Determine severity based on file type
    fn determine_severity(&self, path: &str) -> &'static str {
        if path.contains(".env") || path.contains("config.php") || path.contains("settings.py") {
            "Critical"
        } else if path.contains(".bak") || path.contains(".old") || path.contains("backup") {
            "High"
        } else if path.contains("log") || path.contains("sql") {
            "Medium"
        } else {
            "Low"
        }
    }

    /// Extract exposed key names (not values) from environment files
    fn extract_exposed_keys(&self, path: &str, body: &str) -> Vec<String> {
        let mut keys = Vec::new();
        
        if path.contains(".env") {
            for line in body.lines() {
                if let Some(eq_pos) = line.find('=') {
                    let key = line[..eq_pos].trim();
                    if !key.is_empty() && !key.starts_with('#') {
                        keys.push(key.to_string());
                        if keys.len() >= 10 {
                            break; // Limit exposed keys list
                        }
                    }
                }
            }
        } else if path.contains("config.php") || path.contains("wp-config") {
            // Look for constant definitions
            for line in body.lines() {
                if line.contains("define(") {
                    if let Some(start) = line.find('"') {
                        if let Some(end) = line[start + 1..].find('"') {
                            keys.push(line[start + 1..start + end + 1].to_string());
                            if keys.len() >= 10 {
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        keys
    }

    /// Get remediation guidance based on file type
    fn get_remediation(&self, path: &str) -> String {
        if path.contains(".env") {
            "Remove .env files from web-accessible directories. Use environment variables or secure secret management.".to_string()
        } else if path.contains(".bak") || path.contains(".old") {
            "Delete all backup files from production servers. Implement deployment processes that don't leave backups.".to_string()
        } else if path.contains("config.php") {
            "Move configuration files outside web root. Ensure web server blocks direct access to config files.".to_string()
        } else if path.contains(".sql") {
            "Never store database dumps in web-accessible locations. Use secure backup storage.".to_string()
        } else if path.contains("log") {
            "Configure logging to write outside web root. Rotate and secure log files properly.".to_string()
        } else {
            "Review and restrict access to sensitive files. Implement proper file permissions.".to_string()
        }
    }

    /// Quick check for any environment leak
    pub async fn has_leak(&self, base_url: &str) -> bool {
        let base = base_url.trim_end_matches('/');
        let quick_paths = ["/.env", "/.env.local", "/config.php.bak", "/wp-config.php.bak"];
        
        for path in quick_paths.iter() {
            let url = format!("{}{}", base, path);
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 {
                    return true;
                }
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let client = HttpClient::new();
        let _scanner = EnvLeakScanner::new(client);
    }

    #[test]
    fn test_bounded_paths() {
        assert!(ENV_LEAK_PATHS.len() <= MAX_LEAK_PATHS);
    }
}
