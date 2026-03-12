use crate::{config::Settings, output};

use super::namespace::service_name;

const LEGACY_SERVICE: &str = "ha-auth";
const USERNAME: &str = "refresh-token";

pub(super) fn store_refresh_token(settings: &Settings, token: &str) -> Result<(), keyring::Error> {
    let service = service_name(settings);
    let entry = keyring::Entry::new(service.as_str(), USERNAME)?;
    entry.set_password(token)?;
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

pub(super) fn load_refresh_token(settings: &Settings) -> Result<Option<String>, keyring::Error> {
    let service = service_name(settings);
    let entry = keyring::Entry::new(service.as_str(), USERNAME)?;
    match entry.get_password() {
        Ok(token) => {
            output::info(&format!(
                "Loaded refresh token from keyring service '{service}'."
            ));
            Ok(Some(token))
        }
        Err(keyring::Error::NoEntry) => migrate_legacy_token_if_present(settings),
        Err(e) => Err(e),
    }
}

pub(super) fn delete_refresh_token(settings: &Settings) -> Result<(), keyring::Error> {
    let service = service_name(settings);
    let entry = keyring::Entry::new(service.as_str(), USERNAME)?;
    match entry.delete_credential() {
        Ok(()) => {
            output::info(&format!(
                "Deleted refresh token from keyring service '{service}'."
            ));
            Ok(())
        }
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e),
    }?;
    let _ = delete_legacy_refresh_token();
    Ok(())
}

pub(super) fn is_fallback_error(err: &keyring::Error) -> bool {
    matches!(
        err,
        keyring::Error::NoStorageAccess(_) | keyring::Error::PlatformFailure(_)
    )
}

fn legacy_entry() -> Result<keyring::Entry, keyring::Error> {
    keyring::Entry::new(LEGACY_SERVICE, USERNAME)
}

fn delete_legacy_refresh_token() -> Result<(), keyring::Error> {
    let entry = legacy_entry()?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e),
    }
}

fn migrate_legacy_token_if_present(settings: &Settings) -> Result<Option<String>, keyring::Error> {
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
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::is_fallback_error;

    #[test]
    fn fallback_classification_matches_expected_keyring_errors() {
        let no_storage = keyring::Error::NoStorageAccess(Box::new(std::io::Error::other("x")));
        let platform = keyring::Error::PlatformFailure(Box::new(std::io::Error::other("x")));
        let no_entry = keyring::Error::NoEntry;
        let invalid = keyring::Error::Invalid("service".to_string(), "bad".to_string());

        assert!(is_fallback_error(&no_storage));
        assert!(is_fallback_error(&platform));
        assert!(!is_fallback_error(&no_entry));
        assert!(!is_fallback_error(&invalid));
    }
}
