//! Keycloak OIDC client operations.

mod endpoints;
mod http;
mod pkce;
mod types;

use time::{Duration, OffsetDateTime};

use crate::{callback, config::Settings, error::HaAuthError, lock::LockFile, output, secret};

pub use types::{TokenOutput, WhoamiClaims};

/// Performs an Authorization Code + PKCE login, storing the resulting refresh token.
pub fn login_with_pkce() -> Result<(), HaAuthError> {
    let settings = Settings::from_env_or_defaults()?;
    let _login_lock = LockFile::acquire("ha-auth-login")?;

    let force_login = std::env::var("HA_AUTH_FORCE_LOGIN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !force_login && let Some(refresh) = secret::load_refresh_token(&settings)? {
        let settings_for_refresh = settings.clone();
        let rt =
            tokio::runtime::Runtime::new().map_err(|e| HaAuthError::Internal(e.to_string()))?;
        let refresh_result = rt.block_on(async move {
            http::refresh_access_token(&settings_for_refresh, &refresh).await
        });

        match refresh_result {
            Ok(token_response) => {
                if let Some(new_refresh) = token_response.refresh_token.as_deref() {
                    secret::store_refresh_token(&settings, new_refresh)?;
                }
                output::info("Already logged in (refresh token valid).");
                return Ok(());
            }
            Err(HaAuthError::LoginRequired) => {
                output::info("Stored refresh token invalid; continuing with login.");
            }
            Err(err) => return Err(err),
        }
    }

    let (code_verifier, code_challenge) = pkce::generate_pkce_pair()?;
    let state = pkce::generate_state()?;

    let rt = tokio::runtime::Runtime::new().map_err(|e| HaAuthError::Internal(e.to_string()))?;
    rt.block_on(async move {
        let callback_server = callback::start_callback_server(&settings.redirect, &state).await?;
        let redirect_uri = callback_server.redirect_uri().to_string();
        let auth_url =
            endpoints::authorization_url(&settings, &redirect_uri, &state, &code_challenge)?;

        output::info("Opening browser for login...");
        webbrowser::open(auth_url.as_str())
            .map_err(|e| HaAuthError::Internal(format!("unable to open browser: {e}")))?;

        let code = tokio::select! {
            res = callback_server.wait_for_code() => res?,
            _ = tokio::signal::ctrl_c() => {
                callback_server.shutdown().await;
                return Err(HaAuthError::Internal("login cancelled".to_string()));
            }
        };

        let token_response =
            http::exchange_code_for_tokens(&settings, &redirect_uri, &code, &code_verifier).await?;

        if let Some(refresh_token) = token_response.refresh_token.as_deref() {
            secret::store_refresh_token(&settings, refresh_token)?;
            Ok(())
        } else {
            Err(HaAuthError::Internal(
                "no refresh_token returned; ensure 'offline_access' scope is configured"
                    .to_string(),
            ))
        }
    })
}

/// Obtains an access token using the stored refresh token, returning stable JSON output.
pub fn get_access_token() -> Result<TokenOutput, HaAuthError> {
    let settings = Settings::from_env_or_defaults()?;
    let refresh = secret::load_refresh_token(&settings)?.ok_or(HaAuthError::LoginRequired)?;

    let rt = tokio::runtime::Runtime::new().map_err(|e| HaAuthError::Internal(e.to_string()))?;
    rt.block_on(async move {
        let token_response = http::refresh_access_token(&settings, &refresh).await?;
        if let Some(new_refresh) = token_response.refresh_token.as_deref() {
            secret::store_refresh_token(&settings, new_refresh)?;
        }
        let expires_at = compute_expires_at(token_response.expires_in)?;

        Ok(TokenOutput {
            token: token_response.access_token,
            expires_at,
        })
    })
}

/// Logs out by revoking the stored refresh token (best-effort) and deleting local secrets.
pub fn logout() -> Result<(), HaAuthError> {
    let settings = Settings::from_env_or_defaults()?;
    let refresh = secret::load_refresh_token(&settings)?;

    let rt = tokio::runtime::Runtime::new().map_err(|e| HaAuthError::Internal(e.to_string()))?;
    rt.block_on(async move {
        if let Some(token) = refresh.as_deref() {
            match http::revoke_refresh_token(&settings, token).await {
                Ok(()) => {}
                Err(err) => output::warn(&format!(
                    "Revoke failed (continuing with local logout): {err}"
                )),
            }
        }

        secret::delete_refresh_token(&settings)?;
        Ok(())
    })
}

fn compute_expires_at(expires_in: u64) -> Result<OffsetDateTime, HaAuthError> {
    let now = OffsetDateTime::now_utc();
    let dur = Duration::seconds(
        i64::try_from(expires_in).map_err(|e| HaAuthError::Internal(e.to_string()))?,
    );
    Ok(now + dur)
}
