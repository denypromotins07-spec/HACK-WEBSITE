//! Crypto and Token Module Registration
//!
//! Registers crypto and token modules with the orchestrator and exports metadata.

use crate::checks::{VulnerabilityModule, CheckMetadata};
use std::sync::Arc;

// Crypto modules
pub mod cbc_bitflip;
pub mod bleichenbacher;
pub mod weak_kdf;

// Token modules
pub mod jwt_stripping;
pub mod jwt_jku;
pub mod oidc_confusion;

// OAuth modules
pub mod dynamic_reg;
pub mod scope_inflation;

// SAML modules
pub mod replay_destination;

// Session modules
pub mod entropy;
pub mod invalidation;
pub mod remember_me;

/// Get all crypto check modules
pub fn get_crypto_modules() -> Vec<Arc<dyn VulnerabilityModule + Send + Sync>> {
    vec![
        Arc::new(cbc_bitflip::CbcBitflipDetector::new()),
        Arc::new(bleichenbacher::BleichenbacherDetector::new()),
        Arc::new(weak_kdf::WeakKdfDetector::new()),
    ]
}

/// Get all token check modules
pub fn get_token_modules() -> Vec<Arc<dyn VulnerabilityModule + Send + Sync>> {
    vec![
        Arc::new(jwt_stripping::JwtStrippingDetector::new()),
        Arc::new(jwt_jku::JwtJkuDetector::new()),
        Arc::new(oidc_confusion::OidcConfusionDetector::new()),
    ]
}

/// Get all OAuth check modules
pub fn get_oauth_modules() -> Vec<Arc<dyn VulnerabilityModule + Send + Sync>> {
    vec![
        Arc::new(dynamic_reg::OAuthDynamicRegDetector::new()),
        Arc::new(scope_inflation::OAuthScopeInflationDetector::new()),
    ]
}

/// Get all SAML check modules
pub fn get_saml_modules() -> Vec<Arc<dyn VulnerabilityModule + Send + Sync>> {
    vec![
        Arc::new(replay_destination::SamlReplayDetector::new()),
    ]
}

/// Get all session check modules
pub fn get_session_modules() -> Vec<Arc<dyn VulnerabilityModule + Send + Sync>> {
    vec![
        Arc::new(entropy::SessionEntropyDetector::new()),
        Arc::new(invalidation::SessionInvalidationDetector::new()),
        Arc::new(remember_me::RememberMeDetector::new()),
    ]
}

/// Get all crypto and token modules combined
pub fn get_all_crypto_token_modules() -> Vec<Arc<dyn VulnerabilityModule + Send + Sync>> {
    let mut modules = Vec::new();
    modules.extend(get_crypto_modules());
    modules.extend(get_token_modules());
    modules.extend(get_oauth_modules());
    modules.extend(get_saml_modules());
    modules.extend(get_session_modules());
    modules
}

/// Export module metadata for documentation
pub fn export_module_metadata() -> Vec<CheckMetadata> {
    get_all_crypto_token_modules()
        .iter()
        .map(|m| m.metadata().clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_modules_count() {
        let modules = get_crypto_modules();
        assert_eq!(modules.len(), 3);
    }

    #[test]
    fn test_token_modules_count() {
        let modules = get_token_modules();
        assert_eq!(modules.len(), 3);
    }

    #[test]
    fn test_all_modules_have_metadata() {
        let modules = get_all_crypto_token_modules();
        for module in modules {
            let meta = module.metadata();
            assert!(!meta.id.is_empty());
            assert!(!meta.name.is_empty());
        }
    }
}
