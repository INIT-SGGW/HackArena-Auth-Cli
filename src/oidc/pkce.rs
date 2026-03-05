use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{TryRngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

use crate::error::HaAuthError;

/// Generates a PKCE verifier and S256 challenge.
pub fn generate_pkce_pair() -> Result<(String, String), HaAuthError> {
    let mut verifier_bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut verifier_bytes)
        .map_err(|e| HaAuthError::Internal(e.to_string()))?;
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let digest = hasher.finalize();
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);

    Ok((code_verifier, code_challenge))
}

/// Generates an opaque OAuth state value.
pub fn generate_state() -> Result<String, HaAuthError> {
    let mut state_bytes = [0u8; 16];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut state_bytes)
        .map_err(|e| HaAuthError::Internal(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(state_bytes))
}
