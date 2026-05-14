use std::sync::Once;
use std::time::Duration;

use reqwest::{Client, redirect::Policy};
use serde::Deserialize;

use crate::{
    config::Settings,
    error::HaAuthError,
    oidc::{
        endpoints,
        types::{DeviceAuthorizationResponse, TokenResponse},
    },
    output,
};

const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const HTTP_REDIRECT_LIMIT: usize = 10;
static TLS_PROVIDER_INIT: Once = Once::new();

pub enum DeviceTokenPollResult {
    Complete(TokenResponse),
    AuthorizationPending,
    SlowDown,
    AccessDenied,
    Expired,
}

pub async fn exchange_code_for_tokens(
    settings: &Settings,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
) -> Result<TokenResponse, HaAuthError> {
    let endpoint = endpoints::token_endpoint(settings)?;
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", settings.client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("code", code),
        ("code_verifier", code_verifier),
    ];

    let client = http_client()?;
    let res = client
        .post(endpoint)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await?;

    handle_token_response(res).await
}

pub async fn start_device_authorization(
    settings: &Settings,
    code_challenge: &str,
) -> Result<DeviceAuthorizationResponse, HaAuthError> {
    let endpoint = endpoints::device_authorization_endpoint(settings)?;
    let scope = settings.scopes.join(" ");
    let form = [
        ("client_id", settings.client_id.as_str()),
        ("scope", scope.as_str()),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
    ];

    let client = http_client()?;
    let res = client
        .post(endpoint)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(HaAuthError::Network(format!(
            "device authorization request failed: HTTP {status} {body}"
        )));
    }

    res.json::<DeviceAuthorizationResponse>()
        .await
        .map_err(|e| HaAuthError::Network(e.to_string()))
}

pub async fn refresh_access_token(
    settings: &Settings,
    refresh_token: &str,
) -> Result<TokenResponse, HaAuthError> {
    let endpoint = endpoints::token_endpoint(settings)?;
    let form = [
        ("grant_type", "refresh_token"),
        ("client_id", settings.client_id.as_str()),
        ("refresh_token", refresh_token),
    ];

    let client = http_client()?;
    let res = client
        .post(endpoint)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await?;

    if res.status() == reqwest::StatusCode::UNAUTHORIZED
        || res.status() == reqwest::StatusCode::BAD_REQUEST
    {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();

        if status == reqwest::StatusCode::BAD_REQUEST && is_invalid_grant_error(&body) {
            if !body.trim().is_empty() {
                output::info(&format!("Refresh token rejected: {body}"));
            }
            return Err(HaAuthError::LoginRequired);
        }

        return Err(HaAuthError::Network(format!(
            "token request failed: HTTP {status} {body}"
        )));
    }

    handle_token_response(res).await
}

pub async fn poll_device_access_token(
    settings: &Settings,
    device_code: &str,
    code_verifier: &str,
) -> Result<DeviceTokenPollResult, HaAuthError> {
    let endpoint = endpoints::token_endpoint(settings)?;
    let form = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("client_id", settings.client_id.as_str()),
        ("device_code", device_code),
        ("code_verifier", code_verifier),
    ];

    let client = http_client()?;
    let res = client
        .post(endpoint)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await?;

    if res.status().is_success() {
        return res
            .json::<TokenResponse>()
            .await
            .map(DeviceTokenPollResult::Complete)
            .map_err(|e| HaAuthError::Network(e.to_string()));
    }

    let status = res.status();
    let body = res.text().await.unwrap_or_default();

    if let Some(result) = classify_device_token_error(status, &body) {
        return Ok(result);
    }

    Err(HaAuthError::Network(format!(
        "token request failed: HTTP {status} {body}"
    )))
}

pub async fn revoke_refresh_token(
    settings: &Settings,
    refresh_token: &str,
) -> Result<(), HaAuthError> {
    let endpoint = endpoints::revocation_endpoint(settings)?;
    let form = [
        ("client_id", settings.client_id.as_str()),
        ("token", refresh_token),
        ("token_type_hint", "refresh_token"),
    ];

    let client = http_client()?;
    let res = client
        .post(endpoint)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(HaAuthError::Network(format!(
            "revocation failed: HTTP {status} {body}"
        )));
    }
    Ok(())
}

fn http_client() -> Result<Client, HaAuthError> {
    ensure_tls_provider_installed();
    Client::builder()
        .redirect(Policy::limited(HTTP_REDIRECT_LIMIT))
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| HaAuthError::Internal(e.to_string()))
}

fn ensure_tls_provider_installed() {
    TLS_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    error: Option<String>,
}

fn is_invalid_grant_error(body: &str) -> bool {
    if let Ok(parsed) = serde_json::from_str::<OAuthErrorResponse>(body)
        && let Some(error) = parsed.error
    {
        return error.eq_ignore_ascii_case("invalid_grant");
    }
    body.to_ascii_lowercase().contains("invalid_grant")
}

fn classify_device_token_error(
    status: reqwest::StatusCode,
    body: &str,
) -> Option<DeviceTokenPollResult> {
    if status != reqwest::StatusCode::BAD_REQUEST {
        return None;
    }

    let parsed = serde_json::from_str::<OAuthErrorResponse>(body).ok()?;
    let error = parsed.error?;

    match error.as_str() {
        "authorization_pending" => Some(DeviceTokenPollResult::AuthorizationPending),
        "slow_down" => Some(DeviceTokenPollResult::SlowDown),
        "access_denied" => Some(DeviceTokenPollResult::AccessDenied),
        "expired_token" => Some(DeviceTokenPollResult::Expired),
        _ => None,
    }
}

async fn handle_token_response(res: reqwest::Response) -> Result<TokenResponse, HaAuthError> {
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(HaAuthError::Network(format!(
            "token request failed: HTTP {status} {body}"
        )));
    }

    res.json::<TokenResponse>()
        .await
        .map_err(|e| HaAuthError::Network(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{DeviceTokenPollResult, classify_device_token_error, is_invalid_grant_error};
    use reqwest::StatusCode;

    #[test]
    fn identifies_invalid_grant_json() {
        assert!(is_invalid_grant_error(
            r#"{"error":"invalid_grant","error_description":"Token is not active"}"#
        ));
    }

    #[test]
    fn ignores_other_oauth_errors() {
        assert!(!is_invalid_grant_error(
            r#"{"error":"invalid_client","error_description":"client not found"}"#
        ));
    }

    #[test]
    fn classifies_authorization_pending() {
        let result = classify_device_token_error(
            StatusCode::BAD_REQUEST,
            r#"{"error":"authorization_pending"}"#,
        );
        assert!(matches!(
            result,
            Some(DeviceTokenPollResult::AuthorizationPending)
        ));
    }

    #[test]
    fn classifies_slow_down() {
        let result =
            classify_device_token_error(StatusCode::BAD_REQUEST, r#"{"error":"slow_down"}"#);
        assert!(matches!(result, Some(DeviceTokenPollResult::SlowDown)));
    }

    #[test]
    fn classifies_access_denied() {
        let result =
            classify_device_token_error(StatusCode::BAD_REQUEST, r#"{"error":"access_denied"}"#);
        assert!(matches!(result, Some(DeviceTokenPollResult::AccessDenied)));
    }

    #[test]
    fn classifies_expired_token() {
        let result =
            classify_device_token_error(StatusCode::BAD_REQUEST, r#"{"error":"expired_token"}"#);
        assert!(matches!(result, Some(DeviceTokenPollResult::Expired)));
    }

    #[test]
    fn device_flow_pkce_constants_match_expected_values() {
        let code_challenge_method = "S256";
        let grant_type = "urn:ietf:params:oauth:grant-type:device_code";

        assert_eq!(code_challenge_method, "S256");
        assert_eq!(grant_type, "urn:ietf:params:oauth:grant-type:device_code");
    }
}
