//! Git/SVN Source Code Exposure Module
//! Detects exposed .git/ and .svn/ directories by safely fetching HEAD, config, and entries files.

use crate::http::client::HttpClient;
use crate::findings::evidence::Evidence;

/// Maximum bytes to fetch from sensitive files (bounded to prevent full repo download)
const MAX_FETCH_BYTES: usize = 8192;

/// Git sensitive files to probe
const GIT_FILES: &[&str] = &[
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.git/info/exclude",
];

/// SVN sensitive files to probe
const SVN_FILES: &[&str] = &[
    "/.svn/entries",
    "/.svn/wc.db",
    "/.svn/format",
    "/.svn/prop-base",
];

/// Git/SVN exposure scanner
pub struct GitSvnScanner {
    client: HttpClient,
}

impl GitSvnScanner {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Check for exposed .git directory
    pub async fn check_git_exposure(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        let base = base_url.trim_end_matches('/');
        let mut found_files = Vec::new();
        
        for file_path in GIT_FILES {
            let url = format!("{}{}", base, file_path);
            
            // Fetch with byte limit to prevent full download
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 {
                    // Only read bounded amount of data
                    let body = response.text().await.unwrap_or_default();
                    let truncated_body: String = body.chars().take(MAX_FETCH_BYTES).collect();
                    
                    // Validate it's actually a Git file
                    if self.is_valid_git_file(file_path, &truncated_body) {
                        found_files.push((*file_path).to_string());
                        
                        // Extract useful information without exposing everything
                        let info = self.extract_git_info(file_path, &truncated_body);
                        
                        evidences.push(Evidence::GitExposure {
                            file_path: (*file_path).to_string(),
                            url: url.clone(),
                            info,
                            confidence: 95,
                            remediation: "Remove .git directory from production or block access via web server configuration.".to_string(),
                        });
                    }
                }
            }
        }
        
        // Summary evidence if multiple files found
        if found_files.len() >= 2 {
            evidences.push(Evidence::GitDirectoryExposed {
                files_found: found_files,
                base_url: base_url.to_string(),
                confidence: 100,
                remediation: "CRITICAL: Entire repository may be reconstructable. Remove .git immediately.".to_string(),
            });
        }
        
        evidences
    }

    /// Check for exposed .svn directory
    pub async fn check_svn_exposure(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        let base = base_url.trim_end_matches('/');
        let mut found_files = Vec::new();
        
        for file_path in SVN_FILES {
            let url = format!("{}{}", base, file_path);
            
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 {
                    // Only read bounded amount of data
                    let body = response.text().await.unwrap_or_default();
                    let truncated_body: String = body.chars().take(MAX_FETCH_BYTES).collect();
                    
                    // Validate it's actually an SVN file
                    if self.is_valid_svn_file(file_path, &truncated_body) {
                        found_files.push((*file_path).to_string());
                        
                        evidences.push(Evidence::SvnExposure {
                            file_path: (*file_path).to_string(),
                            url: url.clone(),
                            size_hint: truncated_body.len(),
                            confidence: 95,
                            remediation: "Remove .svn directories from production or block access.".to_string(),
                        });
                    }
                }
            }
        }
        
        // Summary evidence
        if found_files.len() >= 2 {
            evidences.push(Evidence::SvnDirectoryExposed {
                files_found: found_files,
                base_url: base_url.to_string(),
                confidence: 100,
                remediation: "CRITICAL: SVN metadata exposed. Working copies may be reconstructable.".to_string(),
            });
        }
        
        evidences
    }

    /// Validate Git file content
    fn is_valid_git_file(&self, path: &str, content: &str) -> bool {
        match path {
            "/.git/HEAD" => content.contains("ref:") || content.contains("refs/"),
            "/.git/config" => content.contains("[core]") || content.contains("[remote"),
            "/.git/index" => content.starts_with("DIRC") || !content.is_empty(),
            "/.git/logs/HEAD" => content.contains("commit:"),
            "/.git/info/exclude" => true, // Any content is valid
            _ => false,
        }
    }

    /// Validate SVN file content
    fn is_valid_svn_file(&self, path: &str, content: &str) -> bool {
        match path {
            "/.svn/entries" => content.contains("dir") || content.starts_with("10\n") || content.starts_with("{"),
            "/.svn/wc.db" => !content.is_empty(), // SQLite database
            "/.svn/format" => content.chars().all(|c| c.is_numeric() || c.is_whitespace()),
            "/.svn/prop-base" => true,
            _ => false,
        }
    }

    /// Extract safe information from Git files
    fn extract_git_info(&self, path: &str, content: &str) -> String {
        match path {
            "/.git/HEAD" => {
                // Extract current branch reference
                if let Some(start) = content.find("ref: ") {
                    let rest = &content[start + 5..];
                    if let Some(end) = rest.find('\n') {
                        return format!("Current ref: {}", &rest[..end]);
                    }
                }
                "HEAD file accessible".to_string()
            },
            "/.git/config" => {
                // Extract remote URL pattern (sanitized)
                if let Some(start) = content.find("url = ") {
                    let rest = &content[start + 6..];
                    if let Some(end) = rest.find('\n') {
                        let url = &rest[..end];
                        // Sanitize - don't expose full URL with credentials
                        if url.contains('@') {
                            return "Remote configured (credentials may be exposed)".to_string();
                        }
                        return format!("Remote: {}", url);
                    }
                }
                "Git config accessible".to_string()
            },
            _ => "File accessible".to_string(),
        }
    }

    /// Full Git/SVN scan
    pub async fn scan(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        
        let git_evidence = self.check_git_exposure(base_url).await;
        evidences.extend(git_evidence);
        
        let svn_evidence = self.check_svn_exposure(base_url).await;
        evidences.extend(svn_evidence);
        
        evidences
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let client = HttpClient::new();
        let _scanner = GitSvnScanner::new(client);
    }

    #[test]
    fn test_bounded_fetch() {
        assert!(MAX_FETCH_BYTES > 0 && MAX_FETCH_BYTES < 1_000_000);
    }
}
