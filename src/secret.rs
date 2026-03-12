//! Refresh token storage with automatic keyring -> file fallback.

use std::sync::Once;

use crate::{
    config::{SecretBackend, Settings},
    error::HaAuthError,
    output,
};

mod file_backend;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod keyring_backend;
mod namespace;

#[cfg(any(target_os = "windows", target_os = "macos"))]
static KEYRING_FALLBACK_WARN_ONCE: Once = Once::new();

/// Stores the refresh token in the selected backend.
pub fn store_refresh_token(settings: &Settings, token: &str) -> Result<(), HaAuthError> {
    match settings.secret_backend {
        SecretBackend::Auto => store_refresh_token_auto(settings, token),
        SecretBackend::Keyring => store_refresh_token_keyring(settings, token),
        SecretBackend::File => file_backend::store_refresh_token(settings, token),
    }
}

/// Loads the refresh token from the selected backend.
pub fn load_refresh_token(settings: &Settings) -> Result<Option<String>, HaAuthError> {
    match settings.secret_backend {
        SecretBackend::Auto => load_refresh_token_auto(settings),
        SecretBackend::Keyring => load_refresh_token_keyring(settings),
        SecretBackend::File => file_backend::load_refresh_token(settings),
    }
}

/// Deletes the refresh token from the selected backend.
pub fn delete_refresh_token(settings: &Settings) -> Result<(), HaAuthError> {
    match settings.secret_backend {
        SecretBackend::Auto => delete_refresh_token_auto(settings),
        SecretBackend::Keyring => delete_refresh_token_keyring(settings),
        SecretBackend::File => file_backend::delete_refresh_token(settings),
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn store_refresh_token_auto(settings: &Settings, token: &str) -> Result<(), HaAuthError> {
    match keyring_backend::store_refresh_token(settings, token) {
        Ok(()) => {
            if let Err(err) = file_backend::delete_refresh_token(settings) {
                output::warn(&format!(
                    "Keyring store succeeded but failed to clean fallback file: {err}"
                ));
            }
            Ok(())
        }
        Err(err) if keyring_backend::is_fallback_error(&err) => {
            warn_keyring_fallback_once(settings, &err);
            file_backend::store_refresh_token(settings, token)
        }
        Err(err) => Err(HaAuthError::Internal(err.to_string())),
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn store_refresh_token_auto(settings: &Settings, token: &str) -> Result<(), HaAuthError> {
    file_backend::store_refresh_token(settings, token)
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn load_refresh_token_auto(settings: &Settings) -> Result<Option<String>, HaAuthError> {
    match keyring_backend::load_refresh_token(settings) {
        Ok(Some(token)) => {
            if let Err(err) = file_backend::delete_refresh_token(settings) {
                output::warn(&format!(
                    "Loaded token from keyring but failed to clean fallback file: {err}"
                ));
            }
            Ok(Some(token))
        }
        Ok(None) => {
            let file_token = file_backend::load_refresh_token(settings)?;
            if let Some(token) = file_token {
                match keyring_backend::store_refresh_token(settings, token.as_str()) {
                    Ok(()) => {
                        file_backend::delete_refresh_token(settings)?;
                    }
                    Err(err) if keyring_backend::is_fallback_error(&err) => {
                        warn_keyring_fallback_once(settings, &err);
                    }
                    Err(err) => return Err(HaAuthError::Internal(err.to_string())),
                }
                Ok(Some(token))
            } else {
                Ok(None)
            }
        }
        Err(err) if keyring_backend::is_fallback_error(&err) => {
            warn_keyring_fallback_once(settings, &err);
            file_backend::load_refresh_token(settings)
        }
        Err(err) => Err(HaAuthError::Internal(err.to_string())),
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn load_refresh_token_auto(settings: &Settings) -> Result<Option<String>, HaAuthError> {
    file_backend::load_refresh_token(settings)
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn delete_refresh_token_auto(settings: &Settings) -> Result<(), HaAuthError> {
    match keyring_backend::delete_refresh_token(settings) {
        Ok(()) => file_backend::delete_refresh_token(settings),
        Err(err) if keyring_backend::is_fallback_error(&err) => {
            warn_keyring_fallback_once(settings, &err);
            file_backend::delete_refresh_token(settings)
        }
        Err(err) => Err(HaAuthError::Internal(err.to_string())),
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn delete_refresh_token_auto(settings: &Settings) -> Result<(), HaAuthError> {
    file_backend::delete_refresh_token(settings)
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn store_refresh_token_keyring(settings: &Settings, token: &str) -> Result<(), HaAuthError> {
    keyring_backend::store_refresh_token(settings, token)
        .map_err(|e| HaAuthError::Internal(e.to_string()))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn store_refresh_token_keyring(_: &Settings, _: &str) -> Result<(), HaAuthError> {
    Err(HaAuthError::Internal(
        "keyring backend unavailable in this build".to_string(),
    ))
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn load_refresh_token_keyring(settings: &Settings) -> Result<Option<String>, HaAuthError> {
    keyring_backend::load_refresh_token(settings).map_err(|e| HaAuthError::Internal(e.to_string()))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn load_refresh_token_keyring(_: &Settings) -> Result<Option<String>, HaAuthError> {
    Err(HaAuthError::Internal(
        "keyring backend unavailable in this build".to_string(),
    ))
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn delete_refresh_token_keyring(settings: &Settings) -> Result<(), HaAuthError> {
    keyring_backend::delete_refresh_token(settings)
        .map_err(|e| HaAuthError::Internal(e.to_string()))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn delete_refresh_token_keyring(_: &Settings) -> Result<(), HaAuthError> {
    Err(HaAuthError::Internal(
        "keyring backend unavailable in this build".to_string(),
    ))
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn warn_keyring_fallback_once(settings: &Settings, err: &keyring::Error) {
    let fallback_path = file_backend::file_path(settings).ok();
    KEYRING_FALLBACK_WARN_ONCE.call_once(|| {
        if let Some(path) = fallback_path {
            output::warn(&format!(
                "Keyring unavailable ({err}). Falling back to file backend at '{}'. \
Set HA_AUTH_SECRET_BACKEND=keyring to force keyring or HA_AUTH_SECRET_BACKEND=file to force file.",
                path.display()
            ));
        } else {
            output::warn(&format!(
                "Keyring unavailable ({err}). Falling back to file backend. \
Set HA_AUTH_SECRET_BACKEND=keyring to force keyring or HA_AUTH_SECRET_BACKEND=file to force file."
            ));
        }
    });
}
