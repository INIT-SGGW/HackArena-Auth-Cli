use std::fs::{self, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{config::Settings, error::HaAuthError, output, secret::namespace::service_namespace};

const FILE_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct RefreshTokenFile {
    version: u32,
    refresh_token: String,
}

pub(super) fn store_refresh_token(settings: &Settings, token: &str) -> Result<(), HaAuthError> {
    let path = file_path(settings)?;
    let dir = path.parent().ok_or_else(|| {
        HaAuthError::Internal("invalid token file path: missing parent directory".to_string())
    })?;
    ensure_private_directory(dir)?;

    let payload = RefreshTokenFile {
        version: FILE_FORMAT_VERSION,
        refresh_token: token.to_string(),
    };
    let data = serde_json::to_vec(&payload).map_err(|e| HaAuthError::Internal(e.to_string()))?;
    write_file_atomically(&path, data.as_slice())?;
    output::info(&format!(
        "Stored refresh token in file backend at '{}'.",
        path.display()
    ));
    Ok(())
}

pub(super) fn load_refresh_token(settings: &Settings) -> Result<Option<String>, HaAuthError> {
    let path = file_path(settings)?;
    if !path.exists() {
        output::info("No refresh token found.");
        return Ok(None);
    }

    ensure_private_file_if_unix(&path)?;

    let raw = fs::read(&path).map_err(|e| HaAuthError::Internal(e.to_string()))?;
    let parsed: RefreshTokenFile =
        serde_json::from_slice(raw.as_slice()).map_err(|e| HaAuthError::Internal(e.to_string()))?;
    if parsed.version != FILE_FORMAT_VERSION {
        return Err(HaAuthError::Internal(format!(
            "unsupported token file version {}, expected {}",
            parsed.version, FILE_FORMAT_VERSION
        )));
    }
    if parsed.refresh_token.trim().is_empty() {
        return Err(HaAuthError::Internal(
            "token file is invalid: refresh_token is empty".to_string(),
        ));
    }

    output::info(&format!(
        "Loaded refresh token from file backend at '{}'.",
        path.display()
    ));
    Ok(Some(parsed.refresh_token))
}

pub(super) fn delete_refresh_token(settings: &Settings) -> Result<(), HaAuthError> {
    let path = file_path(settings)?;
    match fs::remove_file(&path) {
        Ok(()) => {
            output::info(&format!(
                "Deleted refresh token from file backend at '{}'.",
                path.display()
            ));
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(HaAuthError::Internal(err.to_string())),
    }
}

pub(super) fn file_path(settings: &Settings) -> Result<PathBuf, HaAuthError> {
    if let Some(path) = settings.secret_file.as_ref() {
        if !path.is_absolute() {
            return Err(HaAuthError::Internal(
                "HA_AUTH_SECRET_FILE must be an absolute path".to_string(),
            ));
        }
        return Ok(path.clone());
    }

    let mut dir = default_secret_directory()?;
    let namespace = service_namespace(settings);
    dir.push(format!("refresh-{namespace}.json"));
    Ok(dir)
}

fn write_file_atomically(path: &Path, contents: &[u8]) -> Result<(), HaAuthError> {
    let temp_path = temp_file_path(path)?;
    let write_result: Result<(), HaAuthError> = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|e| HaAuthError::Internal(e.to_string()))?;

        ensure_private_file_permissions_for_new_file_if_unix(&temp_path)?;
        file.write_all(contents)
            .map_err(|e| HaAuthError::Internal(e.to_string()))?;
        file.sync_all()
            .map_err(|e| HaAuthError::Internal(e.to_string()))?;
        replace_file(&temp_path, path)?;
        ensure_private_file_if_unix(path)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

fn temp_file_path(path: &Path) -> Result<PathBuf, HaAuthError> {
    let filename = path.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
        HaAuthError::Internal("invalid token file path: missing filename".to_string())
    })?;
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = format!(".{filename}.tmp-{}-{now_nanos}", std::process::id());
    let mut out = path.to_path_buf();
    out.set_file_name(tmp);
    Ok(out)
}

fn replace_file(from: &Path, to: &Path) -> Result<(), HaAuthError> {
    #[cfg(windows)]
    {
        if to.exists() {
            fs::remove_file(to).map_err(|e| HaAuthError::Internal(e.to_string()))?;
        }
    }
    fs::rename(from, to).map_err(|e| HaAuthError::Internal(e.to_string()))
}

fn default_secret_directory() -> Result<PathBuf, HaAuthError> {
    #[cfg(target_os = "windows")]
    {
        let local_app_data = std::env::var("LOCALAPPDATA").map_err(|_| {
            HaAuthError::Internal(
                "LOCALAPPDATA is not set; cannot determine token fallback path".to_string(),
            )
        })?;
        let mut path = PathBuf::from(local_app_data);
        path.push("HackArena");
        path.push("auth");
        return Ok(path);
    }

    #[cfg(target_os = "macos")]
    {
        let home = home_directory()?;
        let mut path = home;
        path.push("Library");
        path.push("Application Support");
        path.push("ha-auth");
        return Ok(path);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(value) = std::env::var("XDG_STATE_HOME") {
            let value = value.trim();
            if !value.is_empty() {
                let candidate = PathBuf::from(value);
                if candidate.is_absolute() {
                    let mut path = candidate;
                    path.push("ha-auth");
                    return Ok(path);
                }
            }
        }
        let home = home_directory()?;
        let mut path = home;
        path.push(".local");
        path.push("state");
        path.push("ha-auth");
        return Ok(path);
    }

    #[allow(unreachable_code)]
    {
        Err(HaAuthError::Internal(
            "unsupported platform for secret storage".to_string(),
        ))
    }
}

#[cfg(not(target_os = "windows"))]
fn home_directory() -> Result<PathBuf, HaAuthError> {
    let home =
        std::env::var("HOME").map_err(|_| HaAuthError::Internal("HOME is not set".to_string()))?;
    Ok(PathBuf::from(home))
}

fn ensure_private_directory(path: &Path) -> Result<(), HaAuthError> {
    fs::create_dir_all(path).map_err(|e| HaAuthError::Internal(e.to_string()))?;
    ensure_private_directory_if_unix(path)
}

#[cfg(unix)]
fn ensure_private_directory_if_unix(path: &Path) -> Result<(), HaAuthError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| HaAuthError::Internal(e.to_string()))?;
    let mode = fs::metadata(path)
        .map_err(|e| HaAuthError::Internal(e.to_string()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(HaAuthError::Internal(format!(
            "token directory '{}' must not be accessible by group/other (mode {:o})",
            path.display(),
            mode
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_directory_if_unix(_: &Path) -> Result<(), HaAuthError> {
    Ok(())
}

#[cfg(unix)]
fn ensure_private_file_permissions_for_new_file_if_unix(path: &Path) -> Result<(), HaAuthError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| HaAuthError::Internal(e.to_string()))?;
    ensure_private_file_if_unix(path)
}

#[cfg(not(unix))]
fn ensure_private_file_permissions_for_new_file_if_unix(_: &Path) -> Result<(), HaAuthError> {
    Ok(())
}

#[cfg(unix)]
fn ensure_private_file_if_unix(path: &Path) -> Result<(), HaAuthError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .map_err(|e| HaAuthError::Internal(e.to_string()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(HaAuthError::Internal(format!(
            "token file '{}' must not be accessible by group/other (mode {:o})",
            path.display(),
            mode
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_file_if_unix(_: &Path) -> Result<(), HaAuthError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::file_path;
    #[cfg(unix)]
    use super::store_refresh_token;
    use crate::config::{RedirectConfig, SecretBackend, Settings};
    use crate::secret::namespace::service_namespace;
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn file_path_uses_namespace_filename() {
        let s = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        let namespace = service_namespace(&s);
        let expected = format!("refresh-{namespace}.json");
        let path = file_path(&s).expect("default file path");
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(expected.as_str())
        );
    }

    #[test]
    fn file_path_rejects_relative_override() {
        let mut s = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        s.secret_file = Some(PathBuf::from("relative/token.json"));
        let err = file_path(&s).expect_err("relative override should fail");
        assert!(
            err.to_string()
                .contains("HA_AUTH_SECRET_FILE must be an absolute path"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_backend_sets_private_permissions() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "ha-auth-secret-test-{}-{nanos}",
            std::process::id()
        ));
        let token_file = root.join("refresh-test.json");
        let mut s = settings("https://auth.hackarena.pl", "Init", "hackarena-auth-cli");
        s.secret_backend = SecretBackend::File;
        s.secret_file = Some(token_file.clone());

        store_refresh_token(&s, "refresh-token").expect("store token");

        let dir_meta = fs::metadata(token_file.parent().expect("dir")).expect("dir metadata");
        let dir_mode = dir_meta.permissions().mode() & 0o777;
        assert_eq!(dir_mode & 0o077, 0, "dir mode should be private");

        let file_meta = fs::metadata(&token_file).expect("file metadata");
        let file_mode = file_meta.permissions().mode() & 0o777;
        assert_eq!(file_mode & 0o077, 0, "file mode should be private");

        let _ = fs::remove_file(&token_file);
        let _ = fs::remove_dir_all(&root);
    }
}
