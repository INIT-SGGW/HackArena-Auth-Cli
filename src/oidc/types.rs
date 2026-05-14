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

/// Device authorization response from Keycloak.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    #[serde(default)]
    pub interval: Option<u64>,
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

#[cfg(test)]
mod tests {
    use super::DeviceAuthorizationResponse;

    #[test]
    fn parses_device_authorization_response() {
        let body = r#"{
            "device_code":"device-code",
            "user_code":"ABCD-EFGH",
            "verification_uri":"https://auth.example.com/device",
            "verification_uri_complete":"https://auth.example.com/device?user_code=ABCD-EFGH",
            "expires_in":600,
            "interval":5
        }"#;

        let parsed: DeviceAuthorizationResponse =
            serde_json::from_str(body).expect("device authorization response");

        assert_eq!(parsed.device_code, "device-code");
        assert_eq!(parsed.user_code, "ABCD-EFGH");
        assert_eq!(parsed.verification_uri, "https://auth.example.com/device");
        assert_eq!(
            parsed.verification_uri_complete.as_deref(),
            Some("https://auth.example.com/device?user_code=ABCD-EFGH")
        );
        assert_eq!(parsed.expires_in, 600);
        assert_eq!(parsed.interval, Some(5));
    }
}
