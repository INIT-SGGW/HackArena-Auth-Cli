use url::Url;

use crate::{config::Settings, error::HaAuthError};

pub fn authorization_url(
    settings: &Settings,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> Result<Url, HaAuthError> {
    let mut url = auth_endpoint(settings)?;
    url.query_pairs_mut()
        .append_pair("client_id", &settings.client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", &settings.scopes.join(" "))
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url)
}

pub fn auth_endpoint(settings: &Settings) -> Result<Url, HaAuthError> {
    build_endpoint(settings, "auth")
}

pub fn token_endpoint(settings: &Settings) -> Result<Url, HaAuthError> {
    build_endpoint(settings, "token")
}

pub fn revocation_endpoint(settings: &Settings) -> Result<Url, HaAuthError> {
    build_endpoint(settings, "revoke")
}

fn build_endpoint(settings: &Settings, leaf: &str) -> Result<Url, HaAuthError> {
    let mut url = Url::parse(&settings.base_url)?;
    let existing_segments: Vec<String> = url
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.is_empty())
                .map(|segment| segment.to_string())
                .collect()
        })
        .unwrap_or_default();

    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| HaAuthError::Internal("base_url cannot be a base URL".to_string()))?;
        path.clear();
        for segment in &existing_segments {
            path.push(segment.as_str());
        }
        path.push("realms");
        path.push(settings.realm.as_str());
        path.push("protocol");
        path.push("openid-connect");
        path.push(leaf);
    }

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::build_endpoint;
    use crate::config::{RedirectConfig, Settings};

    fn settings(base_url: &str) -> Settings {
        Settings {
            base_url: base_url.to_string(),
            realm: "Init".to_string(),
            client_id: "hackarena-auth-cli".to_string(),
            scopes: vec!["openid".to_string()],
            redirect: RedirectConfig::default(),
        }
    }

    #[test]
    fn keeps_base_path_prefix_without_trailing_slash() {
        let settings = settings("https://auth.example.com/auth");
        let token = build_endpoint(&settings, "token").expect("token endpoint");
        assert_eq!(
            token.as_str(),
            "https://auth.example.com/auth/realms/Init/protocol/openid-connect/token"
        );
    }

    #[test]
    fn keeps_base_path_prefix_with_trailing_slash() {
        let settings = settings("https://auth.example.com/auth/");
        let token = build_endpoint(&settings, "token").expect("token endpoint");
        assert_eq!(
            token.as_str(),
            "https://auth.example.com/auth/realms/Init/protocol/openid-connect/token"
        );
    }
}
