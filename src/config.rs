//! Configuration loading and validation.

use std::sync::Once;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::HaAuthError;

const OFFICIAL_BASE_URL: &str = "https://auth.hackarena.pl";
const OFFICIAL_REALM: &str = "Init";
const OFFICIAL_CLIENT_ID: &str = "hackarena-auth-cli";

const PREPROD_BASE_URL: &str = "https://auth.preprod.init.hackarena.pl";
const PREPROD_REALM: &str = "Init";
const PREPROD_CLIENT_ID: &str = "hackarena-auth-cli";

static PREPROD_NOTICE_ONCE: Once = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Official,
    Preprod,
}

impl Profile {
    fn parse(raw: &str) -> Option<Self> {
        if raw.eq_ignore_ascii_case("official")
            || raw.eq_ignore_ascii_case("prod")
            || raw.eq_ignore_ascii_case("production")
        {
            return Some(Profile::Official);
        }
        if raw.eq_ignore_ascii_case("preprod") {
            return Some(Profile::Preprod);
        }
        None
    }
}

/// Redirect/callback server settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectConfig {
    /// IP/host to bind the localhost callback server on.
    #[serde(default = "default_redirect_host")]
    pub host: String,
    /// First port to attempt binding on.
    #[serde(default = "default_redirect_port_start")]
    pub port_start: u16,
    /// Last port to attempt binding on.
    #[serde(default = "default_redirect_port_end")]
    pub port_end: u16,
    /// Callback path, e.g. `/callback`.
    #[serde(default = "default_redirect_path")]
    pub path: String,
}

/// Tool configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Keycloak base URL, e.g. `https://sso.example.com`.
    pub base_url: String,
    /// Keycloak realm.
    pub realm: String,
    /// OIDC client ID.
    pub client_id: String,
    /// OIDC scopes.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Redirect configuration for the temporary localhost callback server.
    #[serde(default)]
    pub redirect: RedirectConfig,
}

impl Default for RedirectConfig {
    fn default() -> Self {
        Self {
            host: default_redirect_host(),
            port_start: default_redirect_port_start(),
            port_end: default_redirect_port_end(),
            path: default_redirect_path(),
        }
    }
}

impl Settings {
    /// Loads settings from environment variables, falling back to built-in defaults.
    ///
    /// Supported environment variables:
    /// - `HA_AUTH_PROFILE` (`official` or `preprod`)
    /// - `HA_AUTH_BASE_URL`
    /// - `HA_AUTH_REALM`
    /// - `HA_AUTH_CLIENT_ID`
    /// - `HA_AUTH_SCOPES` (space-separated)
    /// - `HA_AUTH_REDIRECT_HOST`
    /// - `HA_AUTH_REDIRECT_PORT_START`
    /// - `HA_AUTH_REDIRECT_PORT_END`
    /// - `HA_AUTH_REDIRECT_PATH`
    /// - `HA_AUTH_PREPROD_URL`
    /// - `HA_AUTH_PREPROD_REALM`
    /// - `HA_AUTH_PREPROD_CLIENT_ID`
    pub fn from_env_or_defaults() -> Result<Self, HaAuthError> {
        let profile = current_profile()?;
        maybe_warn_preprod(profile);
        let mut settings = defaults_for_profile(profile);

        if let Ok(value) = std::env::var("HA_AUTH_BASE_URL") {
            settings.base_url = value;
        }
        if let Ok(value) = std::env::var("HA_AUTH_REALM") {
            settings.realm = value;
        }
        if let Ok(value) = std::env::var("HA_AUTH_CLIENT_ID") {
            settings.client_id = value;
        }
        if let Ok(value) = std::env::var("HA_AUTH_SCOPES") {
            settings.scopes = value
                .split_whitespace()
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string())
                .collect();
        }
        if let Ok(value) = std::env::var("HA_AUTH_REDIRECT_HOST") {
            settings.redirect.host = value;
        }
        if let Ok(value) = std::env::var("HA_AUTH_REDIRECT_PORT_START") {
            settings.redirect.port_start = value.parse::<u16>().map_err(|e| {
                HaAuthError::Internal(format!("invalid HA_AUTH_REDIRECT_PORT_START: {e}"))
            })?;
        }
        if let Ok(value) = std::env::var("HA_AUTH_REDIRECT_PORT_END") {
            settings.redirect.port_end = value.parse::<u16>().map_err(|e| {
                HaAuthError::Internal(format!("invalid HA_AUTH_REDIRECT_PORT_END: {e}"))
            })?;
        }
        if let Ok(value) = std::env::var("HA_AUTH_REDIRECT_PATH") {
            settings.redirect.path = value;
        }

        settings.base_url = normalize_base_url(&settings.base_url)?;
        validate(&settings)?;
        Ok(settings)
    }
}

fn current_profile() -> Result<Profile, HaAuthError> {
    match std::env::var("HA_AUTH_PROFILE") {
        Ok(raw) => Profile::parse(raw.as_str()).ok_or_else(|| {
            HaAuthError::Internal(format!(
                "invalid HA_AUTH_PROFILE '{raw}', expected 'official' or 'preprod'"
            ))
        }),
        Err(std::env::VarError::NotPresent) => Ok(Profile::Official),
        Err(e) => Err(HaAuthError::Internal(format!(
            "invalid HA_AUTH_PROFILE: {e}"
        ))),
    }
}

fn maybe_warn_preprod(profile: Profile) {
    if profile != Profile::Preprod {
        return;
    }

    PREPROD_NOTICE_ONCE.call_once(|| {
        eprintln!(
            "Warning: HA_AUTH_PROFILE=preprod active. To switch back to official unset HA_AUTH_PROFILE (PowerShell: Remove-Item Env:HA_AUTH_PROFILE, bash/zsh: unset HA_AUTH_PROFILE)."
        );
    });
}

fn defaults_for_profile(profile: Profile) -> Settings {
    let (base_url, realm, client_id) = match profile {
        Profile::Official => (
            OFFICIAL_BASE_URL.to_string(),
            OFFICIAL_REALM.to_string(),
            OFFICIAL_CLIENT_ID.to_string(),
        ),
        Profile::Preprod => (
            std::env::var("HA_AUTH_PREPROD_URL").unwrap_or_else(|_| PREPROD_BASE_URL.to_string()),
            std::env::var("HA_AUTH_PREPROD_REALM").unwrap_or_else(|_| PREPROD_REALM.to_string()),
            std::env::var("HA_AUTH_PREPROD_CLIENT_ID")
                .unwrap_or_else(|_| PREPROD_CLIENT_ID.to_string()),
        ),
    };

    Settings {
        base_url,
        realm,
        client_id,
        scopes: default_scopes(),
        redirect: RedirectConfig::default(),
    }
}

fn default_redirect_host() -> String {
    "127.0.0.1".to_string()
}

fn default_redirect_port_start() -> u16 {
    3000
}

fn default_redirect_port_end() -> u16 {
    3999
}

fn default_redirect_path() -> String {
    "/callback".to_string()
}

fn default_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "offline_access".to_string(),
    ]
}

fn validate(settings: &Settings) -> Result<(), HaAuthError> {
    if settings.realm.trim().is_empty() {
        return Err(HaAuthError::Internal(
            "config missing required realm field".to_string(),
        ));
    }
    if settings.client_id.trim().is_empty() {
        return Err(HaAuthError::Internal(
            "config missing required client_id field".to_string(),
        ));
    }
    if settings.redirect.path.trim().is_empty() || !settings.redirect.path.starts_with('/') {
        return Err(HaAuthError::Internal(
            "redirect.path must start with '/'".to_string(),
        ));
    }
    if settings.redirect.port_start > settings.redirect.port_end {
        return Err(HaAuthError::Internal(
            "redirect.port_start must be <= redirect.port_end".to_string(),
        ));
    }
    Ok(())
}

fn normalize_base_url(raw: &str) -> Result<String, HaAuthError> {
    let input = raw.trim();
    if input.is_empty() {
        return Err(HaAuthError::Internal(
            "config missing required base_url field".to_string(),
        ));
    }

    let mut url = Url::parse(input).map_err(HaAuthError::from)?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(HaAuthError::Internal(
            "base_url must use http:// or https://".to_string(),
        ));
    }
    if url.host_str().is_none() {
        return Err(HaAuthError::Internal(
            "base_url must include a host".to_string(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(HaAuthError::Internal(
            "base_url must not include credentials".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(HaAuthError::Internal(
            "base_url must not include query parameters or fragments".to_string(),
        ));
    }

    let normalized_path = url.path().trim_end_matches('/').to_string();
    if normalized_path.is_empty() {
        url.set_path("/");
    } else {
        url.set_path(normalized_path.as_str());
    }
    url.set_query(None);
    url.set_fragment(None);

    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::normalize_base_url;

    #[test]
    fn normalize_base_url_unifies_trailing_slash() {
        let with_slash = normalize_base_url("https://auth.example.com/").expect("with slash");
        let without_slash = normalize_base_url("https://auth.example.com").expect("without slash");
        assert_eq!(with_slash, without_slash);
        assert_eq!(with_slash, "https://auth.example.com/");
    }

    #[test]
    fn normalize_base_url_rejects_query_and_fragment() {
        let with_query = normalize_base_url("https://auth.example.com/base?x=1");
        assert!(with_query.is_err());
        let with_fragment = normalize_base_url("https://auth.example.com/base#frag");
        assert!(with_fragment.is_err());
    }
}
