//! Decode an access token and print minimal claims (no signature validation).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::{error::HaAuthError, oidc::WhoamiClaims};

#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: Option<String>,
    preferred_username: Option<String>,
    email: Option<String>,
    iss: Option<String>,
}

/// Decodes the current access token (obtained via refresh) and returns minimal claims.
pub fn whoami() -> Result<WhoamiClaims, HaAuthError> {
    let token_output = crate::oidc::get_access_token()?;
    decode_claims(&token_output.token)
}

fn decode_claims(jwt: &str) -> Result<WhoamiClaims, HaAuthError> {
    let mut parts = jwt.split('.');
    let _header = parts
        .next()
        .ok_or_else(|| HaAuthError::Internal("invalid JWT".to_string()))?;
    let payload = parts
        .next()
        .ok_or_else(|| HaAuthError::Internal("invalid JWT".to_string()))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| HaAuthError::Internal(e.to_string()))?;
    let claims: JwtClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| HaAuthError::Internal(e.to_string()))?;

    Ok(WhoamiClaims {
        sub: claims.sub,
        preferred_username: claims.preferred_username,
        email: claims.email,
        iss: claims.iss,
    })
}
