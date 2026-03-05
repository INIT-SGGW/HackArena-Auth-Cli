use std::sync::Once;
use std::time::Duration;

use reqwest::{Client, redirect::Policy};
use serde::Deserialize;

use crate::{
    config::Settings,
    error::HaAuthError,
    oidc::{endpoints, types::TokenResponse},
    output,
};

const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const HTTP_REDIRECT_LIMIT: usize = 10;
static TLS_PROVIDER_INIT: Once = Once::new();

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
    use super::is_invalid_grant_error;

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
}
