use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Token response from Keycloak.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Stable output for `ha-auth token`.
#[derive(Debug, Serialize)]
pub struct TokenOutput {
    pub token: String,
    pub expires_at: OffsetDateTime,
}

/// Stable output for `ha-auth whoami`.
#[derive(Debug, Serialize)]
pub struct WhoamiClaims {
    pub sub: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub iss: Option<String>,
}
