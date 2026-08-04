//! Bounded session store for managing multiple concurrent sessions.
//!
//! Provides lock-free session management keyed by persona, target host,
//! and connection scope with automatic expiry and cleanup.

use crate::auth::persona::PersonaId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Unique session identifier.
pub type SessionId = u64;

/// Session state enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is new and not yet validated.
    New,
    /// Session is active and authenticated.
    Active,
    /// Session is being refreshed.
    Refreshing,
    /// Session has expired.
    Expired,
    /// Session was invalidated (logout).
    Invalidated,
}

/// Metadata for a single session.
#[derive(Debug, Clone)]
pub struct SessionMetadata {
    /// Unique session ID.
    pub id: SessionId,
    /// Associated persona ID.
    pub persona_id: PersonaId,
    /// Target host this session is for.
    pub target_host: String,
    /// Connection scope identifier.
    pub scope: String,
    /// Current session state.
    pub state: SessionState,
    /// When the session was created.
    pub created_at: Instant,
    /// Last activity timestamp.
    pub last_activity: Instant,
    /// Optional expiry time.
    pub expires_at: Option<Instant>,
    /// Number of requests made in this session.
    pub request_count: usize,
    /// Associated cookies count.
    pub cookie_count: usize,
    /// Has valid authentication.
    pub authenticated: bool,
}

impl SessionMetadata {
    /// Check if the session has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Instant::now() > expires
        } else {
            false
        }
    }

    /// Check if the session is idle too long.
    pub fn is_idle(&self, timeout: Duration) -> bool {
        Instant::now().duration_since(self.last_activity) > timeout
    }

    /// Update last activity timestamp.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
        self.request_count += 1;
    }
}

/// A session entry containing metadata and associated data.
#[derive(Debug)]
pub struct SessionEntry {
    /// Session metadata.
    pub metadata: SessionMetadata,
    /// Opaque session data (cookies, tokens, etc.).
    pub data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

/// Configuration for the session store.
#[derive(Debug, Clone)]
pub struct SessionStoreConfig {
    /// Maximum number of sessions allowed.
    pub max_sessions: usize,
    /// Default session timeout.
    pub default_timeout: Duration,
    /// Idle timeout before session is considered stale.
    pub idle_timeout: Duration,
    /// How often to run cleanup.
    pub cleanup_interval: Duration,
}

impl Default for SessionStoreConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1000,
            default_timeout: Duration::from_secs(3600), // 1 hour
            idle_timeout: Duration::from_secs(300),     // 5 minutes
            cleanup_interval: Duration::from_secs(60),  // 1 minute
        }
    }
}

/// Bounded session store with automatic cleanup.
pub struct SessionStore {
    /// Sessions indexed by ID.
    sessions: Arc<RwLock<HashMap<SessionId, SessionEntry>>>,
    /// Index by persona and host for quick lookup.
    index: Arc<RwLock<HashMap<(PersonaId, String, String), SessionId>>>,
    /// Configuration.
    config: SessionStoreConfig,
    /// Counter for generating session IDs.
    next_id: AtomicUsize,
    /// Current session count.
    count: AtomicUsize,
}

impl SessionStore {
    /// Create a new session store with default configuration.
    pub fn new() -> Self {
        Self::with_config(SessionStoreConfig::default())
    }

    /// Create a new session store with custom configuration.
    pub fn with_config(config: SessionStoreConfig) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            index: Arc::new(RwLock::new(HashMap::new())),
            config,
            next_id: AtomicUsize::new(1),
            count: AtomicUsize::new(0),
        }
    }

    /// Generate a new session ID.
    fn generate_id(&self) -> SessionId {
        self.next_id.fetch_add(1, Ordering::Relaxed) as SessionId
    }

    /// Create a new session.
    pub fn create_session(
        &self,
        persona_id: PersonaId,
        target_host: &str,
        scope: &str,
    ) -> Option<SessionId> {
        // Check capacity
        if self.count.load(Ordering::Relaxed) >= self.config.max_sessions {
            // Try to clean up expired sessions first
            self.cleanup();
            
            if self.count.load(Ordering::Relaxed) >= self.config.max_sessions {
                return None; // Still at capacity
            }
        }

        let id = self.generate_id();
        let now = Instant::now();

        let metadata = SessionMetadata {
            id,
            persona_id,
            target_host: target_host.to_string(),
            scope: scope.to_string(),
            state: SessionState::New,
            created_at: now,
            last_activity: now,
            expires_at: Some(now + self.config.default_timeout),
            request_count: 0,
            cookie_count: 0,
            authenticated: false,
        };

        let entry = SessionEntry {
            metadata,
            data: Arc::new(RwLock::new(HashMap::new())),
        };

        // Insert into sessions map
        {
            let mut sessions = self.sessions.write().ok()?;
            sessions.insert(id, entry);
        }

        // Insert into index
        {
            let mut index = self.index.write().ok()?;
            index.insert((persona_id, target_host.to_string(), scope.to_string()), id);
        }

        self.count.fetch_add(1, Ordering::Relaxed);
        Some(id)
    }

    /// Get a session by ID.
    pub fn get_session(&self, id: SessionId) -> Option<Arc<RwLock<HashMap<String, Vec<u8>>>>> {
        let sessions = self.sessions.read().ok()?;
        let entry = sessions.get(&id)?;
        
        // Check if expired
        if entry.metadata.is_expired() {
            return None;
        }
        
        Some(Arc::clone(&entry.data))
    }

    /// Get session metadata.
    pub fn get_metadata(&self, id: SessionId) -> Option<SessionMetadata> {
        let sessions = self.sessions.read().ok()?;
        let entry = sessions.get(&id)?;
        Some(entry.metadata.clone())
    }

    /// Find session by persona, host, and scope.
    pub fn find_session(
        &self,
        persona_id: PersonaId,
        target_host: &str,
        scope: &str,
    ) -> Option<SessionId> {
        let index = self.index.read().ok()?;
        let id = *index.get(&(persona_id, target_host.to_string(), scope.to_string()))?;
        
        // Verify session exists and is not expired
        let sessions = self.sessions.read().ok()?;
        let entry = sessions.get(&id)?;
        
        if entry.metadata.is_expired() {
            return None;
        }
        
        Some(id)
    }

    /// Update session state.
    pub fn set_state(&self, id: SessionId, state: SessionState) -> bool {
        let mut sessions = match self.sessions.write() {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        if let Some(entry) = sessions.get_mut(&id) {
            entry.metadata.state = state;
            entry.metadata.touch();
            true
        } else {
            false
        }
    }

    /// Mark session as authenticated.
    pub fn set_authenticated(&self, id: SessionId, authenticated: bool) -> bool {
        let mut sessions = match self.sessions.write() {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        if let Some(entry) = sessions.get_mut(&id) {
            entry.metadata.authenticated = authenticated;
            entry.metadata.state = if authenticated {
                SessionState::Active
            } else {
                SessionState::Invalidated
            };
            entry.metadata.touch();
            true
        } else {
            false
        }
    }

    /// Set session expiry.
    pub fn set_expiry(&self, id: SessionId, expires_at: Instant) -> bool {
        let mut sessions = match self.sessions.write() {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        if let Some(entry) = sessions.get_mut(&id) {
            entry.metadata.expires_at = Some(expires_at);
            true
        } else {
            false
        }
    }

    /// Extend session expiry by the default timeout.
    pub fn extend_expiry(&self, id: SessionId) -> bool {
        let mut sessions = match self.sessions.write() {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        if let Some(entry) = sessions.get_mut(&id) {
            entry.metadata.expires_at = Some(Instant::now() + self.config.default_timeout);
            entry.metadata.touch();
            true
        } else {
            false
        }
    }

    /// Invalidate a session (logout).
    pub fn invalidate(&self, id: SessionId) -> bool {
        let mut sessions = match self.sessions.write() {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        if let Some(entry) = sessions.get_mut(&id) {
            entry.metadata.state = SessionState::Invalidated;
            entry.metadata.authenticated = false;
            // Clear data
            if let Ok(mut data) = entry.data.write() {
                data.clear();
            }
            true
        } else {
            false
        }
    }

    /// Remove a session completely.
    pub fn remove(&self, id: SessionId) -> bool {
        let mut sessions = match self.sessions.write() {
            Ok(s) => s,
            Err(_) => return false,
        };
        
        if let Some(entry) = sessions.remove(&id) {
            // Remove from index
            let key = (
                entry.metadata.persona_id,
                entry.metadata.target_host.clone(),
                entry.metadata.scope.clone(),
            );
            if let Ok(mut index) = self.index.write() {
                index.remove(&key);
            }
            
            self.count.fetch_sub(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Clean up expired and idle sessions.
    pub fn cleanup(&self) -> usize {
        let mut removed = 0;
        let now = Instant::now();
        
        let mut sessions = match self.sessions.write() {
            Ok(s) => s,
            Err(_) => return 0,
        };
        
        let mut index_updates = Vec::new();
        
        sessions.retain(|id, entry| {
            if entry.metadata.is_expired() || entry.metadata.is_idle(self.config.idle_timeout) {
                index_updates.push((
                    entry.metadata.persona_id,
                    entry.metadata.target_host.clone(),
                    entry.metadata.scope.clone(),
                ));
                removed += 1;
                false
            } else {
                true
            }
        });
        
        // Update index
        if let Ok(mut index) = self.index.write() {
            for key in index_updates {
                index.remove(&key);
            }
        }
        
        self.count.fetch_sub(removed, Ordering::Relaxed);
        removed
    }

    /// Get the current number of sessions.
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get all active sessions for a persona.
    pub fn get_persona_sessions(&self, persona_id: PersonaId) -> Vec<SessionId> {
        let sessions = match self.sessions.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        
        sessions
            .iter()
            .filter(|(_, entry)| {
                entry.metadata.persona_id == persona_id
                    && !entry.metadata.is_expired()
                    && entry.metadata.state == SessionState::Active
            })
            .map(|(id, _)| *id)
            .collect()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
