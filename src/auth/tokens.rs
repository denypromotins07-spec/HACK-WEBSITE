//! Bearer token injection, refresh scheduling, and rotation handling.
//!
//! Provides mechanisms for managing bearer tokens including automatic
//! refresh, rotation strategies, and secure injection into requests.

use crate::auth::vault::SecureString;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Token state enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// Token is valid and active.
    Active,
    /// Token is being refreshed.
    Refreshing,
    /// Token has expired.
    Expired,
    /// Token was revoked.
    Revoked,
    /// Token refresh failed.
    Failed,
}

/// Configuration for token management.
#[derive(Debug, Clone)]
pub struct TokenConfig {
    /// Header name for token injection (default: Authorization).
    pub header_name: String,
    /// Token prefix (default: "Bearer").
    pub prefix: String,
    /// Refresh endpoint URL.
    pub refresh_url: Option<String>,
    /// How early to refresh before expiry (as fraction of lifetime).
    pub refresh_threshold: f64,
    /// Maximum number of refresh retries.
    pub max_refresh_retries: u32,
    /// Enable automatic rotation.
    pub auto_rotate: bool,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            header_name: "Authorization".to_string(),
            prefix: "Bearer".to_string(),
            refresh_url: None,
            refresh_threshold: 0.8, // Refresh when 80% of lifetime consumed
            max_refresh_retries: 3,
            auto_rotate: false,
        }
    }
}

/// Managed bearer token with lifecycle tracking.
pub struct ManagedToken {
    /// The actual token value (stored securely).
    token: Arc<RwLock<Option<SecureString>>>,
    /// Current token state.
    state: Arc<RwLock<TokenState>>,
    /// When the token was issued.
    issued_at: AtomicU64,
    /// Token lifetime in seconds (if known).
    expires_in: AtomicU64,
    /// Refresh token (if available).
    refresh_token: Arc<RwLock<Option<SecureString>>>,
    /// Number of refresh attempts.
    refresh_attempts: AtomicU64,
    /// Last refresh timestamp.
    last_refresh: AtomicU64,
    /// Configuration.
    config: TokenConfig,
}

impl ManagedToken {
    /// Create a new managed token.
    pub fn new(token: &str, config: TokenConfig) -> Self {
        let now = Instant::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            token: Arc::new(RwLock::new(Some(SecureString::new(token)))),
            state: Arc::new(RwLock::new(TokenState::Active)),
            issued_at: AtomicU64::new(now),
            expires_in: AtomicU64::new(0), // Unknown by default
            refresh_token: Arc::new(RwLock::new(None)),
            refresh_attempts: AtomicU64::new(0),
            last_refresh: AtomicU64::new(now),
            config,
        }
    }

    /// Create a token with explicit expiry.
    pub fn with_expiry(token: &str, expires_in_secs: u64, config: TokenConfig) -> Self {
        let inner = Self::new(token, config);
        inner.expires_in.store(expires_in_secs, Ordering::Relaxed);
        inner
    }

    /// Set the refresh token.
    pub fn set_refresh_token(&self, refresh_token: &str) {
        if let Ok(mut rt) = self.refresh_token.write() {
            *rt = Some(SecureString::new(refresh_token));
        }
    }

    /// Get the current token value for injection.
    pub fn get_header(&self) -> Option<(String, String)> {
        let token_guard = self.token.read().ok()?;
        let token_ref = token_guard.as_ref()?;
        
        let value = token_ref.with_inner(|t| format!("{} {}", self.config.prefix, t));
        Some((self.config.header_name.clone(), value))
    }

    /// Check if the token needs refresh.
    pub fn needs_refresh(&self) -> bool {
        let state = self.state.read().ok().map(|s| *s).unwrap_or(TokenState::Failed);
        if state != TokenState::Active {
            return false; // Can't refresh non-active tokens
        }
        
        let expires_in = self.expires_in.load(Ordering::Relaxed);
        if expires_in == 0 {
            return false; // No expiry known
        }
        
        let now = Instant::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let issued = self.issued_at.load(Ordering::Relaxed);
        
        let elapsed = now.saturating_sub(issued);
        let threshold = (expires_in as f64 * self.config.refresh_threshold) as u64;
        
        elapsed >= threshold
    }

    /// Check if the token is expired.
    pub fn is_expired(&self) -> bool {
        let expires_in = self.expires_in.load(Ordering::Relaxed);
        if expires_in == 0 {
            return false; // No expiry known
        }
        
        let now = Instant::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let issued = self.issued_at.load(Ordering::Relaxed);
        
        now.saturating_sub(issued) >= expires_in
    }

    /// Update the token value (after refresh).
    pub fn update_token(&self, new_token: &str, new_expires_in: Option<u64>) {
        if let Ok(mut token_guard) = self.token.write() {
            *token_guard = Some(SecureString::new(new_token));
        }
        
        let now = Instant::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.issued_at.store(now, Ordering::Relaxed);
        
        if let Some(expires) = new_expires_in {
            self.expires_in.store(expires, Ordering::Relaxed);
        }
        
        self.last_refresh.store(now, Ordering::Relaxed);
        self.refresh_attempts.store(0, Ordering::Relaxed);
        
        if let Ok(mut state) = self.state.write() {
            *state = TokenState::Active;
        }
    }

    /// Mark refresh as in progress.
    pub fn mark_refreshing(&self) {
        if let Ok(mut state) = self.state.write() {
            *state = TokenState::Refreshing;
        }
    }

    /// Mark refresh as failed.
    pub fn mark_refresh_failed(&self) {
        let attempts = self.refresh_attempts.fetch_add(1, Ordering::Relaxed) + 1;
        
        if attempts >= self.config.max_refresh_retries {
            if let Ok(mut state) = self.state.write() {
                *state = TokenState::Failed;
            }
        } else {
            if let Ok(mut state) = self.state.write() {
                *state = TokenState::Active;
            }
        }
    }

    /// Revoke the token.
    pub fn revoke(&self) {
        if let Ok(mut token_guard) = self.token.write() {
            *token_guard = None;
        }
        if let Ok(mut state) = self.state.write() {
            *state = TokenState::Revoked;
        }
    }

    /// Check if the token is active.
    pub fn is_active(&self) -> bool {
        matches!(*self.state.read().ok().unwrap_or(&TokenState::Failed), TokenState::Active)
    }

    /// Get time until expiry (if known).
    pub fn time_to_expiry(&self) -> Option<Duration> {
        let expires_in = self.expires_in.load(Ordering::Relaxed);
        if expires_in == 0 {
            return None;
        }
        
        let now = Instant::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let issued = self.issued_at.load(Ordering::Relaxed);
        
        let elapsed = now.saturating_sub(issued);
        if elapsed >= expires_in {
            return Some(Duration::ZERO);
        }
        
        Some(Duration::from_secs(expires_in - elapsed))
    }

    /// Get the refresh token if available.
    pub fn get_refresh_token(&self) -> Option<String> {
        let rt_guard = self.refresh_token.read().ok()?;
        let rt_ref = rt_guard.as_ref()?;
        Some(rt_ref.with_inner(|s| s.to_string()))
    }
}

/// Token manager for handling multiple tokens across different services.
#[derive(Default)]
pub struct TokenManager {
    /// Tokens indexed by service/audience identifier.
    tokens: Arc<RwLock<std::collections::HashMap<String, Arc<ManagedToken>>>>,
}

impl TokenManager {
    /// Create a new token manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new token.
    pub fn register(&self, service: &str, token: &str, config: TokenConfig) {
        let managed = Arc::new(ManagedToken::new(token, config));
        if let Ok(mut tokens) = self.tokens.write() {
            tokens.insert(service.to_string(), managed);
        }
    }

    /// Get a token by service name.
    pub fn get(&self, service: &str) -> Option<Arc<ManagedToken>> {
        let tokens = self.tokens.read().ok()?;
        tokens.get(service).cloned()
    }

    /// Get all tokens that need refresh.
    pub fn tokens_needing_refresh(&self) -> Vec<(String, Arc<ManagedToken>)> {
        let tokens = match self.tokens.read() {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        
        tokens
            .iter()
            .filter(|(_, token)| token.needs_refresh())
            .map(|(service, token)| (service.clone(), Arc::clone(token)))
            .collect()
    }

    /// Remove a token by service name.
    pub fn remove(&self, service: &str) -> Option<Arc<ManagedToken>> {
        let mut tokens = self.tokens.write().ok()?;
        tokens.remove(service)
    }

    /// Clear all tokens.
    pub fn clear(&self) {
        if let Ok(mut tokens) = self.tokens.write() {
            tokens.clear();
        }
    }
}
