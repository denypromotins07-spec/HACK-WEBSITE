//! JWT parsing utilities for header, payload, signature, and algorithm metadata.
//!
//! Provides zero-copy parsing of JSON Web Tokens without external dependencies,
//! extracting claims, validating structure, and identifying algorithms.

use std::collections::HashMap;
use std::fmt;

/// JWT header information.
#[derive(Debug, Clone)]
pub struct JwtHeader {
    /// Algorithm used (e.g., HS256, RS256).
    pub alg: String,
    /// Token type (usually "JWT").
    pub typ: Option<String>,
    /// Key ID for key selection.
    pub kid: Option<String>,
    /// Content type.
    pub cty: Option<String>,
    /// Raw header JSON.
    pub raw: String,
}

/// Parsed JWT with decoded components.
#[derive(Debug, Clone)]
pub struct JwtToken {
    /// Header information.
    pub header: JwtHeader,
    /// Claims from the payload.
    pub claims: HashMap<String, serde_json::Value>,
    /// Signature bytes (base64url encoded).
    pub signature: String,
    /// Original token string.
    pub raw: String,
    /// Whether the token is expired (based on exp claim).
    pub is_expired: bool,
}

/// Error types for JWT parsing.
#[derive(Debug)]
pub enum JwtError {
    /// Invalid token format (not 3 parts).
    InvalidFormat,
    /// Base64 decoding failed.
    InvalidBase64,
    /// Invalid UTF-8 in header/payload.
    InvalidUtf8,
    /// JSON parsing failed.
    InvalidJson,
    /// Missing required claim.
    MissingClaim(String),
    /// Unsupported algorithm.
    UnsupportedAlgorithm(String),
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtError::InvalidFormat => write!(f, "Invalid JWT format"),
            JwtError::InvalidBase64 => write!(f, "Invalid base64 encoding"),
            JwtError::InvalidUtf8 => write!(f, "Invalid UTF-8 data"),
            JwtError::InvalidJson => write!(f, "Invalid JSON"),
            JwtError::MissingClaim(claim) => write!(f, "Missing required claim: {}", claim),
            JwtError::UnsupportedAlgorithm(alg) => write!(f, "Unsupported algorithm: {}", alg),
        }
    }
}

impl std::error::Error for JwtError {}

/// Result type for JWT operations.
pub type JwtResult<T> = Result<T, JwtError>;

/// Parse a JWT token string into its components.
pub fn parse_jwt(token: &str) -> JwtResult<JwtToken> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    
    if parts.len() != 3 {
        return Err(JwtError::InvalidFormat);
    }
    
    // Decode header
    let header_bytes = decode_base64url(parts[0])?;
    let header_json = String::from_utf8(header_bytes).map_err(|_| JwtError::InvalidUtf8)?;
    let header_value: serde_json::Value = 
        serde_json::from_str(&header_json).map_err(|_| JwtError::InvalidJson)?;
    
    let alg = header_value["alg"]
        .as_str()
        .ok_or(JwtError::MissingClaim("alg".to_string()))?
        .to_string();
    
    let typ = header_value["typ"].as_str().map(String::from);
    let kid = header_value["kid"].as_str().map(String::from);
    let cty = header_value["cty"].as_str().map(String::from);
    
    let header = JwtHeader {
        alg,
        typ,
        kid,
        cty,
        raw: header_json,
    };
    
    // Decode payload
    let payload_bytes = decode_base64url(parts[1])?;
    let payload_json = String::from_utf8(payload_bytes).map_err(|_| JwtError::InvalidUtf8)?;
    let claims_value: serde_json::Value = 
        serde_json::from_str(&payload_json).map_err(|_| JwtError::InvalidJson)?;
    
    // Convert to HashMap
    let mut claims = HashMap::new();
    if let Some(obj) = claims_value.as_object() {
        for (k, v) in obj {
            claims.insert(k.clone(), v.clone());
        }
    }
    
    // Check expiry
    let is_expired = check_expiry(&claims);
    
    Ok(JwtToken {
        header,
        claims,
        signature: parts[2].to_string(),
        raw: token.to_string(),
        is_expired,
    })
}

/// Check if a JWT has expired based on the 'exp' claim.
fn check_expiry(claims: &HashMap<String, serde_json::Value>) -> bool {
    if let Some(exp) = claims.get("exp") {
        if let Some(exp_num) = exp.as_i64() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            return exp_num < now;
        }
    }
    false
}

/// Decode base64url encoded data.
fn decode_base64url(input: &str) -> Result<Vec<u8>, JwtError> {
    // Add padding if needed
    let padded = add_padding(input);
    
    // Use standard base64 decoder with URL-safe alphabet
    let decoded = base64_decode(&padded)?;
    Ok(decoded)
}

/// Add base64 padding if missing.
fn add_padding(input: &str) -> String {
    let len = input.len();
    let remainder = len % 4;
    
    if remainder == 0 {
        input.to_string()
    } else {
        format!("{}{}", input, "=".repeat(4 - remainder))
    }
}

/// Simple base64 decoder for URL-safe alphabet.
fn base64_decode(input: &str) -> Result<Vec<u8>, JwtError> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits_left = 0;
    
    for c in input.chars() {
        if c == '=' {
            break;
        }
        
        let val = ALPHABET.iter().position(|&x| x == c as u8)
            .ok_or(JwtError::InvalidBase64)? as u32;
        
        buffer = (buffer << 6) | val;
        bits_left += 6;
        
        if bits_left >= 8 {
            result.push((buffer >> (bits_left - 8)) as u8);
            bits_left -= 8;
        }
    }
    
    Ok(result)
}

/// Validate JWT structure without full parsing.
pub fn validate_jwt_structure(token: &str) -> bool {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    
    // Each part should be non-empty and valid base64url
    for part in parts {
        if part.is_empty() {
            return false;
        }
        // Check for valid base64url characters
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return false;
        }
    }
    
    true
}

/// Extract specific claim value from a JWT without full parsing.
pub fn get_claim(token: &str, claim_name: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    
    let payload_bytes = decode_base64url(parts[1]).ok()?;
    let payload_json = String::from_utf8(payload_bytes).ok()?;
    let claims: serde_json::Value = serde_json::from_str(&payload_json).ok()?;
    
    claims.get(claim_name).cloned()
}

/// Get the algorithm from a JWT header without full parsing.
pub fn get_algorithm(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    
    let header_bytes = decode_base64url(parts[0]).ok()?;
    let header_json = String::from_utf8(header_bytes).ok()?;
    let header: serde_json::Value = serde_json::from_str(&header_json).ok()?;
    
    header["alg"].as_str().map(String::from)
}

/// Check if an algorithm is symmetric (HMAC-based).
pub fn is_symmetric_algorithm(alg: &str) -> bool {
    alg.starts_with("HS")
}

/// Check if an algorithm is asymmetric (RSA/ECDSA-based).
pub fn is_asymmetric_algorithm(alg: &str) -> bool {
    alg.starts_with("RS") || alg.starts_with("ES") || alg.starts_with("PS")
}

/// Common JWT algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAlgorithm {
    /// HMAC with SHA-256.
    HS256,
    /// HMAC with SHA-384.
    HS384,
    /// HMAC with SHA-512.
    HS512,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RS512,
    /// ECDSA with P-256 and SHA-256.
    ES256,
    /// ECDSA with P-384 and SHA-384.
    ES384,
    /// ECDSA with P-521 and SHA-512.
    ES512,
    /// Unknown algorithm.
    Unknown(String),
}

impl From<&str> for JwtAlgorithm {
    fn from(s: &str) -> Self {
        match s {
            "HS256" => JwtAlgorithm::HS256,
            "HS384" => JwtAlgorithm::HS384,
            "HS512" => JwtAlgorithm::HS512,
            "RS256" => JwtAlgorithm::RS256,
            "RS384" => JwtAlgorithm::RS384,
            "RS512" => JwtAlgorithm::RS512,
            "ES256" => JwtAlgorithm::ES256,
            "ES384" => JwtAlgorithm::ES384,
            "ES512" => JwtAlgorithm::ES512,
            other => JwtAlgorithm::Unknown(other.to_string()),
        }
    }
}

impl fmt::Display for JwtAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtAlgorithm::HS256 => write!(f, "HS256"),
            JwtAlgorithm::HS384 => write!(f, "HS384"),
            JwtAlgorithm::HS512 => write!(f, "HS512"),
            JwtAlgorithm::RS256 => write!(f, "RS256"),
            JwtAlgorithm::RS384 => write!(f, "RS384"),
            JwtAlgorithm::RS512 => write!(f, "RS512"),
            JwtAlgorithm::ES256 => write!(f, "ES256"),
            JwtAlgorithm::ES384 => write!(f, "ES384"),
            JwtAlgorithm::ES512 => write!(f, "ES512"),
            JwtAlgorithm::Unknown(s) => write!(f, "{}", s),
        }
    }
}

/// Security assessment of a JWT.
#[derive(Debug, Clone)]
pub struct JwtSecurityAssessment {
    /// Algorithm security level.
    pub algorithm_risk: AlgorithmRisk,
    /// Token is expired.
    pub expired: bool,
    /// Missing recommended claims.
    pub missing_claims: Vec<String>,
    /// Potential vulnerabilities.
    pub vulnerabilities: Vec<String>,
}

/// Risk level for algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmRisk {
    /// Low risk (strong algorithms).
    Low,
    /// Medium risk (acceptable but not ideal).
    Medium,
    /// High risk (weak or deprecated algorithms).
    High,
    /// Critical risk (broken or dangerous).
    Critical,
}

/// Assess the security of a JWT.
pub fn assess_jwt_security(token: &str) -> JwtSecurityAssessment {
    let mut vulnerabilities = Vec::new();
    let mut missing_claims = Vec::new();
    
    // Parse token
    let jwt = match parse_jwt(token) {
        Ok(j) => j,
        Err(_) => {
            return JwtSecurityAssessment {
                algorithm_risk: AlgorithmRisk::Critical,
                expired: false,
                missing_claims: vec!["parse_failed".to_string()],
                vulnerabilities: vec!["Invalid JWT format".to_string()],
            };
        }
    };
    
    // Assess algorithm
    let alg_risk = match jwt.header.alg.as_str() {
        "none" => {
            vulnerabilities.push("'none' algorithm allows unsigned tokens".to_string());
            AlgorithmRisk::Critical
        }
        "HS256" | "HS384" | "HS512" => AlgorithmRisk::Low,
        "RS256" | "RS384" | "RS512" => AlgorithmRisk::Low,
        "ES256" | "ES384" | "ES512" => AlgorithmRisk::Low,
        _ => {
            vulnerabilities.push(format!("Unknown algorithm: {}", jwt.header.alg));
            AlgorithmRisk::Medium
        }
    };
    
    // Check for recommended claims
    let recommended = ["iss", "sub", "aud", "exp", "iat"];
    for claim in recommended {
        if !jwt.claims.contains_key(claim) {
            missing_claims.push(claim.to_string());
        }
    }
    
    // Check for algorithm confusion vulnerability indicators
    if jwt.header.alg.starts_with("HS") && jwt.header.kid.is_some() {
        vulnerabilities.push("HMAC algorithm with kid may be vulnerable to algorithm confusion".to_string());
    }
    
    JwtSecurityAssessment {
        algorithm_risk: alg_risk,
        expired: jwt.is_expired,
        missing_claims,
        vulnerabilities,
    }
}
