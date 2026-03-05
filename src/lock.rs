use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::HaAuthError;

pub struct LockFile {
    path: PathBuf,
}

impl LockFile {
    pub fn acquire(name: &str) -> Result<Self, HaAuthError> {
        let mut path = std::env::temp_dir();
        path.push(format!("{name}.lock"));

        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if lock_is_stale(&path, 5 * 60) {
                    let _ = std::fs::remove_file(&path);
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .map_err(|e| HaAuthError::Internal(e.to_string()))?
                } else {
                    return Err(HaAuthError::Internal(format!(
                        "{name} already running (lock exists): {}",
                        path.display()
                    )));
                }
            }
            Err(err) => return Err(HaAuthError::Internal(err.to_string())),
        };

        let pid = std::process::id();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(file, "pid={pid}\nts={ts}");

        Ok(Self { path })
    }
}

fn lock_is_stale(path: &PathBuf, stale_after_secs: u64) -> bool {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return false;
    };

    let ts = contents
        .lines()
        .find_map(|line| line.strip_prefix("ts="))
        .and_then(|v| v.trim().parse::<u64>().ok());

    let Some(ts) = ts else {
        // If the lock file exists but has no timestamp (e.g. crash after create),
        // treat it as stale so login is not blocked indefinitely.
        return true;
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    now.saturating_sub(ts) > stale_after_secs
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::lock_is_stale;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_lock_path(suffix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!(
            "ha-auth-lock-test-{}-{nanos}-{suffix}.lock",
            std::process::id()
        ));
        path
    }

    #[test]
    fn malformed_lock_without_timestamp_is_stale() {
        let path = temp_lock_path("malformed");
        std::fs::write(&path, "pid=1234\n").expect("write lock file");

        assert!(lock_is_stale(&path, 300));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn lock_staleness_respects_timestamp_age() {
        let path = temp_lock_path("timestamp");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let stale_ts = now.saturating_sub(1_000);
        std::fs::write(&path, format!("pid=1\nts={stale_ts}\n")).expect("write stale lock");
        assert!(lock_is_stale(&path, 300));

        std::fs::write(&path, format!("pid=1\nts={now}\n")).expect("write fresh lock");
        assert!(!lock_is_stale(&path, 300));

        let _ = std::fs::remove_file(path);
    }
}
