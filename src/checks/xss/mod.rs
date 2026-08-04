//! XSS Module Registration
//! 
//! Registers XSS modules with orchestrator, exports metadata, and wires learning caches.

pub mod context;
pub mod reflected;
pub mod stored;
pub mod dom;
pub mod blind;
pub mod cloaking;
pub mod dom_redirect;
pub mod prototype;
pub mod window_opener;
pub mod postmessage;
pub mod csrf;
pub mod cors;
pub mod clickjacking;
pub mod mxss;
pub mod csp_jsonp;

pub use context::XssContext;
pub use reflected::ReflectedXssDetector;
pub use stored::StoredXssDetector;
pub use dom::DomXssDetector;
pub use blind::BlindXssDetector;
pub use cloaking::DomCloakingDetector;
pub use dom_redirect::DomRedirectDetector;
pub use prototype::PrototypePollutionDetector;
pub use window_opener::WindowOpenerDetector;
pub use postmessage::PostMessageDetector;
pub use csrf::CsrfDetector;
pub use cors::CorsDetector;
pub use clickjacking::ClickjackingDetector;
pub use mxss::MxssDetector;
pub use csp_jsonp::CspJsonpDetector;

use crate::learning::xss_cache::XssCache;
use std::collections::HashMap;

/// XSS module metadata
#[derive(Debug, Clone)]
pub struct XssModuleMetadata {
    pub name: &'static str,
    pub description: &'static str,
    pub vulnerability_types: Vec<&'static str>,
    pub supports_god_mode: bool,
}

/// Registry of all XSS modules
pub fn get_xss_modules() -> HashMap<&'static str, XssModuleMetadata> {
    let mut modules = HashMap::new();
    
    modules.insert(
        "reflected",
        XssModuleMetadata {
            name: "Reflected XSS Detector",
            description: "Detects reflected XSS by tracking canary payloads through URL parameters and form inputs",
            vulnerability_types: vec!["Reflected XSS"],
            supports_god_mode: true,
        },
    );
    
    modules.insert(
        "stored",
        XssModuleMetadata {
            name: "Stored XSS Detector",
            description: "Detects stored XSS by submitting payloads to persistence endpoints",
            vulnerability_types: vec!["Stored XSS"],
            supports_god_mode: true,
        },
    );
    
    modules.insert(
        "dom",
        XssModuleMetadata {
            name: "DOM XSS Detector",
            description: "Analyzes client-side JavaScript sources and sinks for DOM-based XSS",
            vulnerability_types: vec!["DOM XSS"],
            supports_god_mode: true,
        },
    );
    
    modules.insert(
        "blind",
        XssModuleMetadata {
            name: "Blind XSS Detector",
            description: "Injects blind XSS payloads designed to trigger OOB callbacks",
            vulnerability_types: vec!["Blind XSS"],
            supports_god_mode: true,
        },
    );
    
    modules.insert(
        "cloaking",
        XssModuleMetadata {
            name: "DOM Cloaking Detector",
            description: "Detects DOM Cloaking vulnerabilities via global variable shadowing",
            vulnerability_types: vec!["DOM Cloaking"],
            supports_god_mode: false,
        },
    );
    
    modules.insert(
        "dom_redirect",
        XssModuleMetadata {
            name: "DOM Redirect Detector",
            description: "Identifies DOM-based open redirects",
            vulnerability_types: vec!["DOM Open Redirect"],
            supports_god_mode: false,
        },
    );
    
    modules.insert(
        "prototype",
        XssModuleMetadata {
            name: "Prototype Pollution Detector",
            description: "Detects Client-Side Prototype Pollution",
            vulnerability_types: vec!["Prototype Pollution"],
            supports_god_mode: false,
        },
    );
    
    modules.insert(
        "window_opener",
        XssModuleMetadata {
            name: "Window Opener Detector",
            description: "Identifies Window Opener Hijacking vulnerabilities",
            vulnerability_types: vec!["Window Opener Hijacking"],
            supports_god_mode: false,
        },
    );
    
    modules.insert(
        "postmessage",
        XssModuleMetadata {
            name: "PostMessage Detector",
            description: "Detects PostMessage Origin Validation Gaps",
            vulnerability_types: vec!["PostMessage XSS"],
            supports_god_mode: false,
        },
    );
    
    modules.insert(
        "csrf",
        XssModuleMetadata {
            name: "CSRF Detector",
            description: "Detects Cross-Site Request Forgery vulnerabilities",
            vulnerability_types: vec!["CSRF"],
            supports_god_mode: true,
        },
    );
    
    modules.insert(
        "cors",
        XssModuleMetadata {
            name: "CORS Detector",
            description: "Identifies CORS Misconfigurations",
            vulnerability_types: vec!["CORS Misconfiguration"],
            supports_god_mode: true,
        },
    );
    
    modules.insert(
        "clickjacking",
        XssModuleMetadata {
            name: "Clickjacking Detector",
            description: "Detects Clickjacking and XSSI vulnerabilities",
            vulnerability_types: vec!["Clickjacking", "XSSI"],
            supports_god_mode: true,
        },
    );
    
    modules.insert(
        "mxss",
        XssModuleMetadata {
            name: "MXSS Detector",
            description: "Detects Mutation XSS vulnerabilities",
            vulnerability_types: vec!["Mutation XSS"],
            supports_god_mode: false,
        },
    );
    
    modules.insert(
        "csp_jsonp",
        XssModuleMetadata {
            name: "CSP/JSONP Detector",
            description: "Detects CSP Nonce Leakage and JSONP Callback Manipulation",
            vulnerability_types: vec!["CSP Nonce Leakage", "JSONP Callback Manipulation"],
            supports_god_mode: true,
        },
    );
    
    modules
}

/// Get all vulnerability types covered by XSS modules
pub fn get_all_vulnerability_types() -> Vec<&'static str> {
    let mut types = Vec::new();
    
    for (_, metadata) in get_xss_modules() {
        types.extend(metadata.vulnerability_types);
    }
    
    types.sort();
    types.dedup();
    types
}

/// Create a shared XSS cache for learning
pub fn create_xss_cache() -> XssCache {
    XssCache::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_registration() {
        let modules = get_xss_modules();
        
        // Should have 15 modules registered
        assert_eq!(modules.len(), 15);
        
        // Check specific modules exist
        assert!(modules.contains_key("reflected"));
        assert!(modules.contains_key("stored"));
        assert!(modules.contains_key("dom"));
        assert!(modules.contains_key("csrf"));
        assert!(modules.contains_key("cors"));
    }

    #[test]
    fn test_vulnerability_types() {
        let types = get_all_vulnerability_types();
        
        assert!(!types.is_empty());
        assert!(types.contains(&"Reflected XSS"));
        assert!(types.contains(&"CSRF"));
        assert!(types.contains(&"CORS Misconfiguration"));
    }

    #[test]
    fn test_metadata_structure() {
        let modules = get_xss_modules();
        
        if let Some(metadata) = modules.get("reflected") {
            assert!(!metadata.name.is_empty());
            assert!(!metadata.description.is_empty());
            assert!(!metadata.vulnerability_types.is_empty());
        }
    }
}
