use std::fmt;

/// Process exit codes for `ha-auth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Success.
    Success,
    /// Not logged in / login required.
    LoginRequired,
    /// Network or upstream error.
    Network,
    /// Internal error.
    Internal,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        match self {
            ExitCode::Success => 0,
            ExitCode::LoginRequired => 2,
            ExitCode::Network => 10,
            ExitCode::Internal => 11,
        }
    }
}

/// Top-level error type for `ha-auth`.
#[derive(Debug, thiserror::Error)]
pub enum HaAuthError {
    #[error("login required")]
    LoginRequired,

    #[error("network/upstream error: {0}")]
    Network(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl HaAuthError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            HaAuthError::LoginRequired => ExitCode::LoginRequired,
            HaAuthError::Network(_) => ExitCode::Network,
            HaAuthError::Internal(_) => ExitCode::Internal,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            HaAuthError::LoginRequired => "login_required",
            HaAuthError::Network(_) => "network_error",
            HaAuthError::Internal(_) => "internal_error",
        }
    }
}

impl From<std::io::Error> for HaAuthError {
    fn from(value: std::io::Error) -> Self {
        HaAuthError::Internal(value.to_string())
    }
}

impl From<reqwest::Error> for HaAuthError {
    fn from(value: reqwest::Error) -> Self {
        if value.is_timeout() || value.is_connect() || value.is_request() || value.is_body() {
            return HaAuthError::Network(value.to_string());
        }
        HaAuthError::Network(value.to_string())
    }
}

impl From<url::ParseError> for HaAuthError {
    fn from(value: url::ParseError) -> Self {
        HaAuthError::Internal(value.to_string())
    }
}

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_i32())
    }
}
