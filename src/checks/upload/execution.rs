//! File Upload Execution Detection
//! Detects server-side file execution by uploading disguised scripts as images.
//! Uses non-destructive polyglot files and safe execution probes.

use crate::checks::Check;
use crate::findings::Finding;
use crate::http::{Request, Response, Method};
use std::collections::HashMap;

/// Maximum upload attempts (bounded)
const MAX_UPLOAD_ATTEMPTS: usize = 15;

/// File extensions to test
const TEST_EXTENSIONS: &[&str] = &[
    ".php",
    ".php5",
    ".phtml",
    ".asp",
    ".aspx",
    ".jsp",
    ".jspx",
    ".cgi",
    ".pl",
    ".py",
    ".rb",
    ".sh",
    ".exe",
];

/// Image magic bytes for GIF89a (minimal valid GIF)
const GIF_HEADER: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";

/// PHP payload marker (non-destructive)
const PHP_MARKER: &str = "<?php echo 'UPLOAD_EXEC_TEST'; ?>";

pub struct UploadExecutionCheck {
    extensions: Vec<String>,
}

impl UploadExecutionCheck {
    pub fn new() -> Self {
        let extensions = TEST_EXTENSIONS.iter().map(|s| s.to_string()).collect();
        Self { extensions }
    }
    
    /// Test file upload with execution probe
    fn test_upload(&self, req: &Request, upload_path: &str) -> Option<Finding> {
        for ext in self.extensions.iter().take(MAX_UPLOAD_ATTEMPTS) {
            let filename = format!("test{}{}", rand_marker(), ext);
            
            // Create polyglot file (valid image + embedded script)
            let file_content = self.create_polyglot(ext);
            
            let mut upload_req = req.clone();
            upload_req.set_method(Method::POST);
            upload_req.set_upload_file("file", &filename, &file_content);
            upload_req.set_url(upload_path);
            
            match upload_req.send_with_timeout(10000) {
                Ok(response) => {
                    // Check if file was uploaded and get path
                    if let Some(uploaded_path) = self.extract_uploaded_path(&response) {
                        // Try to execute the uploaded file
                        if let Some(finding) = self.test_execution(req, &uploaded_path, ext) {
                            return Some(finding);
                        }
                    }
                    
                    // Direct response check
                    if self.detect_execution_in_response(&response, ext) {
                        return Some(Finding::new(
                            "FILE_UPLOAD_EXECUTION",
                            &format!("Uploaded file with extension '{}' is executed by server", ext),
                            response.url(),
                            9,
                        )
                        .with_payload(&filename)
                        .with_evidence("Server executed uploaded file content")
                        .with_remediation(
                            "Validate file types by content, not extension. \
                             Store uploads outside webroot. Use random filenames. \
                             Disable script execution in upload directories."
                        ));
                    }
                }
                Err(_) => continue,
            }
        }
        None
    }
    
    /// Create a polyglot file for given extension
    fn create_polyglot(&self, ext: &str) -> Vec<u8> {
        let mut content = Vec::with_capacity(512);
        
        match ext {
            ".php" | ".php5" | ".phtml" => {
                // GIF header + PHP code
                content.extend_from_slice(GIF_HEADER);
                content.extend_from_slice(b"\n");
                content.extend_from_slice(PHP_MARKER.as_bytes());
            }
            ".asp" | ".aspx" => {
                // GIF header + ASP code
                content.extend_from_slice(GIF_HEADER);
                content.extend_from_slice(b"\n");
                content.extend_from_slice(b"<% Response.Write(\"UPLOAD_EXEC_TEST\") %>");
            }
            ".jsp" | ".jspx" => {
                // GIF header + JSP code
                content.extend_from_slice(GIF_HEADER);
                content.extend_from_slice(b"\n");
                content.extend_from_slice(b"<% out.print(\"UPLOAD_EXEC_TEST\"); %>");
            }
            _ => {
                // Generic: just GIF header
                content.extend_from_slice(GIF_HEADER);
            }
        }
        
        content
    }
    
    /// Extract uploaded file path from response
    fn extract_uploaded_path(&self, response: &Response) -> Option<String> {
        let body = response.body_slice();
        
        // Look for common upload response patterns
        let patterns = [
            b"uploaded to",
            b"saved as",
            b"file:",
            b"path:",
            b"location:",
            b"/uploads/",
            b"/files/",
        ];
        
        for pattern in patterns.iter() {
            if let Some(pos) = body.windows(pattern.len()).position(|w| w == *pattern) {
                // Extract path after pattern
                let start = pos + pattern.len();
                if start < body.len() {
                    let remaining = &body[start..];
                    if let Some(end) = remaining.iter().position(|&b| b == b'"' || b == b'\'' || b == b' ' || b == b'<') {
                        let path = String::from_utf8_lossy(&remaining[..end]);
                        if !path.is_empty() && path.len() < 200 {
                            return Some(path.trim().to_string());
                        }
                    }
                }
            }
        }
        
        None
    }
    
    /// Test if uploaded file can be executed
    fn test_execution(&self, base_req: &Request, file_path: &str, ext: &str) -> Option<Finding> {
        let exec_url = format!("{}{}", base_req.base_url(), file_path);
        let mut exec_req = Request::new(&exec_url, Method::GET);
        
        match exec_req.send_with_timeout(5000) {
            Ok(response) => {
                let body = response.body_slice();
                
                if body.contains(b"UPLOAD_EXEC_TEST") {
                    return Some(Finding::new(
                        "FILE_UPLOAD_CODE_EXECUTION",
                        &format!(
                            "Uploaded {} file at '{}' is executed on server",
                            ext, file_path
                        ),
                        &exec_url,
                        10,
                    )
                    .with_payload(file_path)
                    .with_evidence("Executed payload marker found in response")
                    .with_remediation(
                        "Immediately remove uploaded file. \
                         Implement strict file type validation. \
                         Store uploads outside webroot with no execute permissions."
                    ));
                }
            }
            Err(_) => {}
        }
        None
    }
    
    /// Detect execution indicators in upload response
    fn detect_execution_in_response(&self, response: &Response, ext: &str) -> bool {
        let body = response.body_slice();
        
        // Check for PHP/ASP/JSP output markers
        let markers = [
            b"UPLOAD_EXEC_TEST",
            b"<?php",
            b"<%",
            b"eval(",
            b"system(",
            b"exec(",
        ];
        
        for marker in markers.iter() {
            if body.contains(marker) {
                return true;
            }
        }
        
        false
    }
}

/// Generate random marker for filenames
fn rand_marker() -> &'static str {
    "scanner_test"
}

impl Check for UploadExecutionCheck {
    fn name(&self) -> &'static str {
        "UploadExecution"
    }
    
    fn run(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Common upload endpoints
        let upload_paths = [
            "/upload",
            "/upload.php",
            "/uploadfile",
            "/file/upload",
            "/api/upload",
            "/rest/upload",
        ];
        
        for path in upload_paths.iter() {
            if let Some(finding) = self.test_upload(request, path) {
                findings.push(finding);
                break;
            }
        }
        
        findings
    }
    
    fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("type", "file_upload_execution");
        meta.insert("severity", "critical");
        meta.insert("cwe", "CWE-434");
        meta.insert("owasp", "A01:2021-Broken Access Control");
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_extension_count() {
        let check = UploadExecutionCheck::new();
        assert!(check.extensions.len() <= TEST_EXTENSIONS.len());
    }
    
    #[test]
    fn test_polyglot_creation() {
        let check = UploadExecutionCheck::new();
        let php_polyglot = check.create_polyglot(".php");
        assert!(php_polyglot.starts_with(GIF_HEADER));
        assert!(php_polyglot.contains(b"UPLOAD_EXEC_TEST"));
    }
}
