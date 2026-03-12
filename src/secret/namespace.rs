use std::fmt::Write as _;

use sha2::{Digest as _, Sha256};

use crate::config::Settings;

#[cfg(any(target_os = "windows", target_os = "macos"))]
const SERVICE_PREFIX: &str = "ha-auth";

#[cfg(any(target_os = "windows", target_os = "macos"))]
pub(super) fn service_name(settings: &Settings) -> String {
    let namespace = service_namespace(settings);
    format!("{SERVICE_PREFIX}-{namespace}")
}

pub(super) fn service_namespace(settings: &Settings) -> String {
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
        // writing to String never fails
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    use super::service_name;
    use super::service_namespace;
    use crate::config::{RedirectConfig, SecretBackend, Settings};

    fn settings(base_url: &str, realm: &str, client_id: &str) -> Settings {
        Settings {
            base_url: base_url.to_string(),
            realm: realm.to_string(),
            client_id: client_id.to_string(),
            scopes: vec!["openid".to_string()],
            redirect: RedirectConfig::default(),
            secret_backend: SecretBackend::Auto,
            secret_file: None,
        }
    }

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    #[test]
    fn service_name_is_stable_for_same_settings() {
        let a = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        let b = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        assert_eq!(service_name(&a), service_name(&b));
    }

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    #[test]
    fn service_name_changes_between_environments() {
        let a = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        let b = settings("https://auth.hackarena.pl", "Prod", "hackarena-auth-cli");
        assert_ne!(service_name(&a), service_name(&b));
    }

    #[test]
    fn namespace_is_stable_for_same_settings() {
        let a = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        let b = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        assert_eq!(service_namespace(&a), service_namespace(&b));
    }

    #[test]
    fn namespace_changes_between_environments() {
        let a = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        let b = settings("https://auth.hackarena.pl", "Prod", "hackarena-auth-cli");
        assert_ne!(service_namespace(&a), service_namespace(&b));
    }
}
