//! User persona definitions for multi-context scanning.
//!
//! Personas represent different user roles and privilege levels
//! that the scanner can simulate during vulnerability assessment.

use crate::auth::config::{AuthConfig, AuthMode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a persona.
pub type PersonaId = u64;

/// Privilege level enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivilegeLevel {
    /// Unauthenticated guest access.
    Guest,
    /// Standard authenticated user.
    User,
    /// Elevated privileges (moderator, editor).
    Moderator,
    /// Full administrative access.
    Admin,
    /// Custom role with specific permissions.
    Custom(u32),
}

impl Default for PrivilegeLevel {
    fn default() -> Self {
        PrivilegeLevel::Guest
    }
}

/// A user persona representing a specific identity and privilege context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Persona {
    /// Unique identifier for this persona.
    pub id: PersonaId,
    /// Human-readable name.
    pub name: String,
    /// Description of the persona's purpose.
    pub description: Option<String>,
    /// Privilege level.
    pub privilege_level: PrivilegeLevel,
    /// Authentication configuration for this persona.
    pub auth_config: AuthConfig,
    /// Custom headers to inject for this persona.
    pub custom_headers: HashMap<String, String>,
    /// Tags for categorization.
    pub tags: Vec<String>,
    /// Whether this persona is active.
    pub active: bool,
    /// Maximum concurrent sessions for this persona.
    pub max_sessions: usize,
}

impl Persona {
    /// Create a new guest persona.
    pub fn guest(id: PersonaId) -> Self {
        Self {
            id,
            name: "Guest".to_string(),
            description: Some("Unauthenticated guest user".to_string()),
            privilege_level: PrivilegeLevel::Guest,
            auth_config: AuthConfig::new(AuthMode::None),
            custom_headers: HashMap::new(),
            tags: vec!["guest".to_string(), "public".to_string()],
            active: true,
            max_sessions: 10,
        }
    }

    /// Create a new standard user persona.
    pub fn user(id: PersonaId, name: &str, auth_config: AuthConfig) -> Self {
        Self {
            id,
            name: name.to_string(),
            description: Some("Standard authenticated user".to_string()),
            privilege_level: PrivilegeLevel::User,
            auth_config,
            custom_headers: HashMap::new(),
            tags: vec!["user".to_string(), "authenticated".to_string()],
            active: true,
            max_sessions: 5,
        }
    }

    /// Create a new admin persona.
    pub fn admin(id: PersonaId, name: &str, auth_config: AuthConfig) -> Self {
        Self {
            id,
            name: name.to_string(),
            description: Some("Administrative user with full privileges".to_string()),
            privilege_level: PrivilegeLevel::Admin,
            auth_config,
            custom_headers: HashMap::new(),
            tags: vec!["admin".to_string(), "privileged".to_string()],
            active: true,
            max_sessions: 2,
        }
    }

    /// Create a custom persona with specific role.
    pub fn custom(
        id: PersonaId,
        name: &str,
        privilege_code: u32,
        auth_config: AuthConfig,
    ) -> Self {
        Self {
            id,
            name: name.to_string(),
            description: Some(format!("Custom role with code {}", privilege_code)),
            privilege_level: PrivilegeLevel::Custom(privilege_code),
            auth_config,
            custom_headers: HashMap::new(),
            tags: vec!["custom".to_string()],
            active: true,
            max_sessions: 3,
        }
    }

    /// Check if this persona requires authentication.
    pub fn requires_auth(&self) -> bool {
        self.auth_config.requires_auth()
    }

    /// Check if this persona has admin privileges.
    pub fn is_admin(&self) -> bool {
        matches!(self.privilege_level, PrivilegeLevel::Admin)
    }

    /// Check if this persona is a guest.
    pub fn is_guest(&self) -> bool {
        matches!(self.privilege_level, PrivilegeLevel::Guest)
    }

    /// Add a custom header to this persona.
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.custom_headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Add a tag to this persona.
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }
}

/// Manager for multiple personas.
#[derive(Debug, Clone, Default)]
pub struct PersonaManager {
    /// Registered personas indexed by ID.
    personas: HashMap<PersonaId, Persona>,
    /// Next available ID.
    next_id: PersonaId,
}

impl PersonaManager {
    /// Create a new persona manager with default guest persona.
    pub fn new() -> Self {
        let mut manager = Self {
            personas: HashMap::new(),
            next_id: 1,
        };
        // Add default guest persona
        manager.add_persona(Persona::guest(0));
        manager
    }

    /// Add a new persona.
    pub fn add_persona(&mut self, persona: Persona) -> PersonaId {
        let id = persona.id;
        self.personas.insert(id, persona);
        if id >= self.next_id {
            self.next_id = id + 1;
        }
        id
    }

    /// Register a new persona and return its ID.
    pub fn register(&mut self, mut persona: Persona) -> PersonaId {
        persona.id = self.next_id;
        self.next_id += 1;
        self.personas.insert(persona.id, persona);
        persona.id
    }

    /// Get a persona by ID.
    pub fn get(&self, id: PersonaId) -> Option<&Persona> {
        self.personas.get(&id)
    }

    /// Get all active personas.
    pub fn active_personas(&self) -> Vec<&Persona> {
        self.personas
            .values()
            .filter(|p| p.active)
            .collect()
    }

    /// Get personas by privilege level.
    pub fn by_privilege_level(&self, level: PrivilegeLevel) -> Vec<&Persona> {
        self.personas
            .values()
            .filter(|p| p.privilege_level == level && p.active)
            .collect()
    }

    /// Get all admin personas.
    pub fn admins(&self) -> Vec<&Persona> {
        self.by_privilege_level(PrivilegeLevel::Admin)
    }

    /// Remove a persona by ID.
    pub fn remove(&mut self, id: PersonaId) -> Option<Persona> {
        self.personas.remove(&id)
    }

    /// Count registered personas.
    pub fn count(&self) -> usize {
        self.personas.len()
    }
}
