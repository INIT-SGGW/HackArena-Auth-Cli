//! Secure OS credential store integration.

use std::fmt::Write as _;

use sha2::{Digest as _, Sha256};

use crate::{config::Settings, error::HaAuthError, output};

const SERVICE_PREFIX: &str = "ha-auth";
const LEGACY_SERVICE: &str = "ha-auth";
const USERNAME: &str = "refresh-token";

/// Stores the refresh token in the OS credential store.
pub fn store_refresh_token(settings: &Settings, token: &str) -> Result<(), HaAuthError> {
    let service = service_name(settings);
    let entry = keyring::Entry::new(service.as_str(), USERNAME)
        .map_err(|e| HaAuthError::Internal(e.to_string()))?;
    entry
        .set_password(token)
        .map_err(|e| HaAuthError::Internal(e.to_string()))?;
    match entry.get_password() {
        Ok(_) => output::info(&format!(
            "Stored refresh token in keyring service '{service}' (readback ok)."
        )),
        Err(e) => output::warn(&format!(
            "Stored refresh token in keyring service '{service}' (readback failed: {e})."
        )),
    }
    let _ = delete_legacy_refresh_token();
    Ok(())
}

/// Loads the refresh token from the OS credential store.
pub fn load_refresh_token(settings: &Settings) -> Result<Option<String>, HaAuthError> {
    let service = service_name(settings);
    let entry = keyring::Entry::new(service.as_str(), USERNAME)
        .map_err(|e| HaAuthError::Internal(e.to_string()))?;
    match entry.get_password() {
        Ok(token) => {
            output::info(&format!(
                "Loaded refresh token from keyring service '{service}'."
            ));
            Ok(Some(token))
        }
        Err(keyring::Error::NoEntry) => migrate_legacy_token_if_present(settings),
        Err(e) => Err(HaAuthError::Internal(e.to_string())),
    }
}

/// Deletes the refresh token from the OS credential store.
pub fn delete_refresh_token(settings: &Settings) -> Result<(), HaAuthError> {
    let service = service_name(settings);
    let entry = keyring::Entry::new(service.as_str(), USERNAME)
        .map_err(|e| HaAuthError::Internal(e.to_string()))?;
    match entry.delete_credential() {
        Ok(()) => {
            output::info(&format!(
                "Deleted refresh token from keyring service '{service}'."
            ));
            Ok(())
        }
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(HaAuthError::Internal(e.to_string())),
    }?;

    let _ = delete_legacy_refresh_token();
    Ok(())
}

fn service_name(settings: &Settings) -> String {
    let namespace = service_namespace(settings);
    format!("{SERVICE_PREFIX}-{namespace}")
}

fn service_namespace(settings: &Settings) -> String {
    // Include environment-defining fields so official/preprod tokens never collide.
    let input = format!(
        "{}|{}|{}",
        settings.base_url.trim(),
        settings.realm.trim(),
        settings.client_id.trim()
    );
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn legacy_entry() -> Result<keyring::Entry, HaAuthError> {
    keyring::Entry::new(LEGACY_SERVICE, USERNAME).map_err(|e| HaAuthError::Internal(e.to_string()))
}

fn delete_legacy_refresh_token() -> Result<(), HaAuthError> {
    let entry = legacy_entry()?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(HaAuthError::Internal(e.to_string())),
    }
}

fn migrate_legacy_token_if_present(settings: &Settings) -> Result<Option<String>, HaAuthError> {
    let legacy = legacy_entry()?;
    match legacy.get_password() {
        Ok(token) => {
            output::info("Migrating refresh token from legacy keyring namespace.");
            store_refresh_token(settings, token.as_str())?;
            let _ = delete_legacy_refresh_token();
            Ok(Some(token))
        }
        Err(keyring::Error::NoEntry) => {
            output::info("No refresh token found in keyring.");
            Ok(None)
        }
        Err(e) => Err(HaAuthError::Internal(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::service_name;
    use crate::config::{RedirectConfig, Settings};

    fn settings(base_url: &str, realm: &str, client_id: &str) -> Settings {
        Settings {
            base_url: base_url.to_string(),
            realm: realm.to_string(),
            client_id: client_id.to_string(),
            scopes: vec!["openid".to_string()],
            redirect: RedirectConfig::default(),
        }
    }

    #[test]
    fn service_name_is_stable_for_same_settings() {
        let a = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        let b = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        assert_eq!(service_name(&a), service_name(&b));
    }

    #[test]
    fn service_name_changes_between_environments() {
        let a = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        let b = settings("https://auth.hackarena.pl", "Prod", "hackarena-auth-cli");
        assert_ne!(service_name(&a), service_name(&b));
    }
}
