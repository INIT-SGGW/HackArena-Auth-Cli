//! Keycloak OIDC client operations.

mod endpoints;
mod http;
mod pkce;
mod types;

use std::time::Duration as StdDuration;

use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::time::Instant;

use crate::{callback, config::Settings, error::HaAuthError, lock::LockFile, output, secret};

pub use types::{TokenOutput, WhoamiClaims};

const DEVICE_FLOW_DEFAULT_INTERVAL_SECS: u64 = 5;
const DEVICE_FLOW_SLOW_DOWN_INCREMENT_SECS: u64 = 5;

/// Performs a login, either via browser PKCE or no-browser device flow.
pub fn login(no_browser: bool) -> Result<(), HaAuthError> {
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

    if no_browser {
        login_with_device_flow(&settings)
    } else {
        login_with_pkce(&settings)
    }
}

/// Performs an Authorization Code + PKCE login, storing the resulting refresh token.
fn login_with_pkce(settings: &Settings) -> Result<(), HaAuthError> {
    let (code_verifier, code_challenge) = pkce::generate_pkce_pair()?;
    let state = pkce::generate_state()?;
    let settings = settings.clone();

    let rt = tokio::runtime::Runtime::new().map_err(|e| HaAuthError::Internal(e.to_string()))?;
    rt.block_on(async move {
        let callback_server = callback::start_callback_server(&settings.redirect, &state).await?;
        let redirect_uri = callback_server.redirect_uri().to_string();
        let auth_url =
            endpoints::authorization_url(&settings, &redirect_uri, &state, &code_challenge)?;

        output::info("Opening browser for login...");
        webbrowser::open(auth_url.as_str())
            .map_err(|e| HaAuthError::Internal(format!("unable to open browser: {e}")))?;

        let code_result = tokio::select! {
            res = callback_server.wait_for_code() => res,
            _ = tokio::signal::ctrl_c() => {
                callback_server.shutdown().await;
                return Err(HaAuthError::Internal("login cancelled".to_string()));
            }
        };

        let code = match code_result {
            Ok(code) => code,
            Err(err) => {
                callback_server.shutdown().await;
                return Err(err);
            }
        };

        let token_response =
            http::exchange_code_for_tokens(&settings, &redirect_uri, &code, &code_verifier).await;
        callback_server.shutdown().await;
        store_refresh_token_from_response(&settings, &token_response?)
    })
}

fn login_with_device_flow(settings: &Settings) -> Result<(), HaAuthError> {
    let (code_verifier, code_challenge) = pkce::generate_pkce_pair()?;
    let settings = settings.clone();
    let rt = tokio::runtime::Runtime::new().map_err(|e| HaAuthError::Internal(e.to_string()))?;

    rt.block_on(async move {
        let device = http::start_device_authorization(&settings, &code_challenge).await?;

        output::print_stderr_line("Browser login disabled. Complete authentication using:");
        if let Some(url) = device.verification_uri_complete.as_deref() {
            output::print_stderr_line(url);
        } else {
            output::print_stderr_line(&format!("Verification URL: {}", device.verification_uri));
            output::print_stderr_line(&format!("User code: {}", device.user_code));
        }
        output::print_stderr_line("Waiting for authorization...");

        let mut interval_secs = device
            .interval
            .unwrap_or(DEVICE_FLOW_DEFAULT_INTERVAL_SECS)
            .max(1);
        let deadline = Instant::now() + StdDuration::from_secs(device.expires_in.max(1));

        loop {
            let sleep = tokio::time::sleep(StdDuration::from_secs(interval_secs));
            tokio::pin!(sleep);

            tokio::select! {
                _ = &mut sleep => {}
                _ = tokio::signal::ctrl_c() => {
                    return Err(HaAuthError::Internal("login cancelled".to_string()));
                }
            }

            if Instant::now() >= deadline {
                output::print_stderr_line("Device authorization expired. Run login again.");
                return Err(HaAuthError::LoginRequired);
            }

            match http::poll_device_access_token(&settings, &device.device_code, &code_verifier)
                .await?
            {
                http::DeviceTokenPollResult::Complete(token_response) => {
                    return store_refresh_token_from_response(&settings, &token_response);
                }
                http::DeviceTokenPollResult::AuthorizationPending => {}
                http::DeviceTokenPollResult::SlowDown => {
                    interval_secs += DEVICE_FLOW_SLOW_DOWN_INCREMENT_SECS;
                }
                http::DeviceTokenPollResult::AccessDenied => {
                    output::print_stderr_line("Device authorization was denied.");
                    return Err(HaAuthError::LoginRequired);
                }
                http::DeviceTokenPollResult::Expired => {
                    output::print_stderr_line("Device authorization expired. Run login again.");
                    return Err(HaAuthError::LoginRequired);
                }
            }
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
    let dur = TimeDuration::seconds(
        i64::try_from(expires_in).map_err(|e| HaAuthError::Internal(e.to_string()))?,
    );
    Ok(now + dur)
}

fn store_refresh_token_from_response(
    settings: &Settings,
    token_response: &types::TokenResponse,
) -> Result<(), HaAuthError> {
    if let Some(refresh_token) = token_response.refresh_token.as_deref() {
        secret::store_refresh_token(settings, refresh_token)?;
        Ok(())
    } else {
        Err(HaAuthError::Internal(
            "no refresh_token returned; ensure 'offline_access' scope is configured".to_string(),
        ))
    }
}
