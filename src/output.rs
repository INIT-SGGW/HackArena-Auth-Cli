use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

use crate::error::HaAuthError;

static QUIET: AtomicBool = AtomicBool::new(false);

/// Writes a single-line JSON value to stdout.
pub fn print_json_line<T: Serialize>(value: &T) -> Result<(), HaAuthError> {
    let line = serde_json::to_string(value).map_err(|e| HaAuthError::Internal(e.to_string()))?;
    println!("{line}");
    Ok(())
}

/// Writes a single line of plain text to stdout.
pub fn print_text_line(value: &str) {
    println!("{value}");
}

/// Enables or disables informational stderr messages.
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

/// Returns whether informational stderr messages are disabled.
pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Prints an informational message to stderr unless quiet mode is enabled.
pub fn info(message: &str) {
    if !is_quiet() {
        eprintln!("{message}");
    }
}

/// Prints a warning message to stderr unless quiet mode is enabled.
pub fn warn(message: &str) {
    if !is_quiet() {
        eprintln!("{message}");
    }
}

/// Prints an error to stderr in plain text or JSON format.
pub fn print_error(err: &HaAuthError, as_json: bool) {
    if !as_json {
        eprintln!("{err}");
        return;
    }

    let payload = ErrorOutput {
        error: err.kind(),
        message: err.to_string(),
        exit_code: err.exit_code().as_i32(),
    };

    match serde_json::to_string(&payload) {
        Ok(line) => eprintln!("{line}"),
        Err(_) => eprintln!("{err}"),
    }
}

/// Generic `{"status":"ok"}` output for commands without specific JSON payloads.
#[derive(Debug, Serialize)]
pub struct OkStatus<'a> {
    pub status: &'a str,
}

#[derive(Debug, Serialize)]
struct ErrorOutput {
    error: &'static str,
    message: String,
    exit_code: i32,
}
