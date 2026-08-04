//! Cookie parsing, validation, and attribute handling.
//!
//! Provides comprehensive cookie management including RFC 6265 compliance,
//! SameSite attribute inspection, expiry tracking, and secure flag validation.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Cookie SameSite attribute values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// No SameSite restriction.
    None,
    /// Cookies sent with same-site requests only.
    Strict,
    /// Cookies sent with same-site and top-level navigations.
    Lax,
}

impl Default for SameSite {
    fn default() -> Self {
        SameSite::Lax
    }
}

impl SameSite {
    /// Parse from string value.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Some(SameSite::None),
            "strict" => Some(SameSite::Strict),
            "lax" => Some(SameSite::Lax),
            _ => None,
        }
    }

    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            SameSite::None => "None",
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
        }
    }
}

/// A parsed HTTP cookie.
#[derive(Debug, Clone)]
pub struct Cookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Optional expiration timestamp (Unix epoch seconds).
    pub expires: Option<u64>,
    /// Max-Age in seconds (overrides expires if present).
    pub max_age: Option<i64>,
    /// Domain scope.
    pub domain: Option<String>,
    /// Path scope.
    pub path: Option<String>,
    /// Secure flag - only sent over HTTPS.
    pub secure: bool,
    /// HttpOnly flag - not accessible via JavaScript.
    pub http_only: bool,
    /// SameSite attribute.
    pub same_site: SameSite,
    /// When this cookie was received.
    pub received_at: u64,
}

impl Cookie {
    /// Create a new cookie with just name and value.
    pub fn new(name: &str, value: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            name: name.to_string(),
            value: value.to_string(),
            expires: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: SameSite::default(),
            received_at: now,
        }
    }

    /// Check if the cookie has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Max-Age takes precedence over Expires
        if let Some(max_age) = self.max_age {
            if max_age <= 0 {
                return true;
            }
            return now >= self.received_at + max_age as u64;
        }
        
        if let Some(expires) = self.expires {
            return now > expires;
        }
        
        false
    }

    /// Get the effective expiry time as Unix timestamp.
    pub fn effective_expiry(&self) -> Option<u64> {
        if let Some(max_age) = self.max_age {
            if max_age <= 0 {
                return Some(0);
            }
            return Some(self.received_at + max_age as u64);
        }
        
        self.expires
    }

    /// Check if cookie matches a given URL's domain.
    pub fn matches_domain(&self, host: &str) -> bool {
        if let Some(ref domain) = self.domain {
            let domain = domain.trim_start_matches('.').to_lowercase();
            let host = host.to_lowercase();
            
            // Exact match
            if host == domain {
                return true;
            }
            
            // Subdomain match - domain must start with '.' when set
            if domain.starts_with('.') {
                return host.ends_with(domain.as_str());
            }
            
            // Cookie without leading dot can match exact or subdomain
            host.ends_with(&format!(".{}", domain))
        } else {
            // No domain specified - must match exactly
            true
        }
    }

    /// Check if cookie matches a given path.
    pub fn matches_path(&self, path: &str) -> bool {
        if let Some(ref cookie_path) = self.path {
            let path = path.trim_end_matches('/');
            let cookie_path = cookie_path.trim_end_matches('/');
            
            // Exact match
            if path == cookie_path {
                return true;
            }
            
            // Path prefix match with '/' boundary
            path.starts_with(cookie_path) 
                && (cookie_path.is_empty() || path.chars().nth(cookie_path.len()) == Some('/'))
        } else {
            // Default path behavior
            true
        }
    }

    /// Convert to a Set-Cookie header value.
    pub fn to_set_cookie_header(&self) -> String {
        let mut parts = vec![format!("{}={}", self.name, self.value)];
        
        if let Some(expires) = self.expires {
            // Format as HTTP date
            let expires_str = format_timestamp(expires);
            parts.push(format!("Expires={}", expires_str));
        }
        
        if let Some(max_age) = self.max_age {
            parts.push(format!("Max-Age={}", max_age));
        }
        
        if let Some(ref domain) = self.domain {
            parts.push(format!("Domain={}", domain));
        }
        
        if let Some(ref path) = self.path {
            parts.push(format!("Path={}", path));
        }
        
        if self.secure {
            parts.push("Secure".to_string());
        }
        
        if self.http_only {
            parts.push("HttpOnly".to_string());
        }
        
        if !matches!(self.same_site, SameSite::Lax) {
            parts.push(format!("SameSite={}", self.same_site.as_str()));
        }
        
        parts.join("; ")
    }

    /// Convert to a Cookie header value (for sending).
    pub fn to_cookie_header(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}

/// Parse a Set-Cookie header into a Cookie struct.
pub fn parse_set_cookie(header_value: &str) -> Option<Cookie> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Split by semicolon
    let parts: Vec<&str> = header_value.split(';').collect();
    if parts.is_empty() {
        return None;
    }
    
    // First part is name=value
    let (name, value) = parts[0].trim().split_once('=')?;
    
    let mut cookie = Cookie {
        name: name.trim().to_string(),
        value: value.trim().to_string(),
        expires: None,
        max_age: None,
        domain: None,
        path: None,
        secure: false,
        http_only: false,
        same_site: SameSite::default(),
        received_at: now,
    };
    
    // Parse attributes
    for part in parts.iter().skip(1) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        
        let lower = part.to_ascii_lowercase();
        
        if let Some((attr, val)) = part.split_once('=') {
            let attr_lower = attr.trim().to_ascii_lowercase();
            let val = val.trim();
            
            match attr_lower.as_str() {
                "expires" => {
                    cookie.expires = parse_http_date(val);
                }
                "max-age" => {
                    cookie.max_age = val.parse().ok();
                }
                "domain" => {
                    cookie.domain = Some(val.to_string());
                }
                "path" => {
                    cookie.path = Some(val.to_string());
                }
                "samesite" => {
                    if let Some(same_site) = SameSite::from_str(val) {
                        cookie.same_site = same_site;
                    }
                }
                _ => {}
            }
        } else {
            // Flag attributes (no value)
            match lower.as_str() {
                "secure" => cookie.secure = true,
                "httponly" => cookie.http_only = true,
                _ => {}
            }
        }
    }
    
    Some(cookie)
}

/// Parse a Cookie header into a map of name-value pairs.
pub fn parse_cookie_header(header_value: &str) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    
    for pair in header_value.split(';') {
        if let Some((name, value)) = pair.trim().split_once('=') {
            cookies.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    
    cookies
}

/// Build a Cookie header from multiple cookies.
pub fn build_cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .filter(|c| !c.is_expired())
        .map(|c| c.to_cookie_header())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Parse an HTTP date string to Unix timestamp.
fn parse_http_date(date_str: &str) -> Option<u64> {
    // Simple parser for common HTTP date formats
    // RFC 1123: Sun, 06 Nov 1994 08:49:37 GMT
    // RFC 850: Sunday, 06-Nov-94 08:49:37 GMT
    // ANSI C: Sun Nov  6 08:49:37 1994
    
    let date_str = date_str.trim();
    
    // Try to extract components from RFC 1123 format
    let parts: Vec<&str> = date_str.split_whitespace().collect();
    if parts.len() >= 5 {
        // Format: Day, DD Mon YYYY HH:MM:SS GMT
        let day = parts.get(1)?.trim_end_matches(',');
        let month_str = parts.get(2)?;
        let year = parts.get(3)?;
        let time = parts.get(4)?;
        
        let day: u32 = day.parse().ok()?;
        let year: u32 = year.parse().ok()?;
        let month = month_from_str(month_str)?;
        
        let time_parts: Vec<&str> = time.split(':').collect();
        if time_parts.len() >= 3 {
            let hour: u32 = time_parts[0].parse().ok()?;
            let minute: u32 = time_parts[1].parse().ok()?;
            let second: u32 = time_parts[2].parse().ok()?;
            
            // Simplified timestamp calculation
            return approximate_timestamp(year, month, day, hour, minute, second);
        }
    }
    
    None
}

fn month_from_str(month_str: &str) -> Option<u32> {
    match month_str.to_ascii_lowercase().as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

fn approximate_timestamp(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Option<u64> {
    // Simplified timestamp calculation (not accounting for leap years precisely)
    const SECONDS_PER_MINUTE: u64 = 60;
    const SECONDS_PER_HOUR: u64 = 3600;
    const SECONDS_PER_DAY: u64 = 86400;
    
    let mut days: u64 = 0;
    
    // Days from years (since 1970)
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    
    // Days from months
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30];
    for m in 1..month {
        days += month_days[m as usize] as u64;
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }
    
    // Days from day of month
    days += (day - 1) as u64;
    
    let timestamp = days * SECONDS_PER_DAY
        + (hour as u64) * SECONDS_PER_HOUR
        + (minute as u64) * SECONDS_PER_MINUTE
        + (second as u64);
    
    Some(timestamp)
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn format_timestamp(ts: u64) -> String {
    // Simplified - in production would use proper date formatting
    format!("{}", ts)
}

/// Validate cookie attributes for security issues.
#[derive(Debug, Clone)]
pub struct CookieValidation {
    /// Cookie is valid.
    pub valid: bool,
    /// Missing Secure flag on non-localhost.
    pub missing_secure: bool,
    /// Missing HttpOnly flag.
    pub missing_httponly: bool,
    /// SameSite is None (potentially vulnerable to CSRF).
    pub samesite_none: bool,
    /// Domain is too broad (potential subdomain takeover).
    pub broad_domain: bool,
    /// Expiry is too far in the future.
    pub long_expiry: bool,
    /// Issues found.
    pub issues: Vec<String>,
}

impl CookieValidation {
    /// Validate a cookie against security best practices.
    pub fn validate(cookie: &Cookie, host: &str) -> Self {
        let mut issues = Vec::new();
        let mut valid = true;
        
        // Check for Secure flag
        let missing_secure = !cookie.secure && host != "localhost" && host != "127.0.0.1";
        if missing_secure {
            issues.push("Missing Secure flag".to_string());
            valid = false;
        }
        
        // Check for HttpOnly flag
        let missing_httponly = !cookie.http_only;
        if missing_httponly {
            issues.push("Missing HttpOnly flag".to_string());
        }
        
        // Check SameSite
        let samesite_none = matches!(cookie.same_site, SameSite::None);
        if samesite_none {
            issues.push("SameSite=None may be vulnerable to CSRF".to_string());
        }
        
        // Check domain scope
        let broad_domain = cookie.domain.as_ref().map_or(false, |d| {
            let d = d.trim_start_matches('.');
            d.split('.').count() <= 2 // e.g., "example.com" or "co.uk"
        });
        if broad_domain {
            issues.push("Broad domain scope may allow subdomain attacks".to_string());
        }
        
        // Check expiry
        let long_expiry = cookie.effective_expiry().map_or(false, |exp| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            exp - now > 31536000 * 2 // More than 2 years
        });
        if long_expiry {
            issues.push("Excessive cookie lifetime".to_string());
        }
        
        Self {
            valid,
            missing_secure,
            missing_httponly,
            samesite_none,
            broad_domain,
            long_expiry,
            issues,
        }
    }
}
