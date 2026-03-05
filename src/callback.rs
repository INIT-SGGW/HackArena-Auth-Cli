//! Localhost callback server to receive the OAuth authorization code.

use std::future::IntoFuture as _;
use std::{
    net::{IpAddr, SocketAddr},
    path::{Component, Path},
    sync::Arc,
};

use axum::{
    Router,
    extract::{Path as AxumPath, Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse},
    routing::get,
};
use rust_embed::RustEmbed;
use serde::Deserialize;
use tokio::{
    net::TcpListener,
    sync::{Mutex, oneshot},
};
use tokio::{net::TcpStream, time};
use url::Url;

use crate::{config::RedirectConfig, error::HaAuthError};

type CodeResult = Result<String, HaAuthError>;
type CodeSender = oneshot::Sender<CodeResult>;
type CodeReceiver = oneshot::Receiver<CodeResult>;
type ShutdownSender = oneshot::Sender<()>;
type ServerJoinHandle = tokio::task::JoinHandle<Result<(), std::io::Error>>;

#[derive(RustEmbed)]
#[folder = "assets/success/"]
struct SuccessAssets;

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Clone)]
struct AppState {
    expected_state: Arc<String>,
    tx: Arc<tokio::sync::Mutex<Option<CodeSender>>>,
    success_html: Arc<String>,
}

/// A running callback server.
pub struct CallbackServer {
    redirect_uri: String,
    rx: Arc<Mutex<Option<CodeReceiver>>>,
    shutdown_tx: Arc<Mutex<Option<ShutdownSender>>>,
    join: Arc<Mutex<Option<ServerJoinHandle>>>,
}

impl CallbackServer {
    /// Returns the redirect URI to send in the authorization request.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Waits for the authorization code.
    pub async fn wait_for_code(&self) -> Result<String, HaAuthError> {
        let mut rx_guard = self.rx.lock().await;
        let rx = rx_guard
            .take()
            .ok_or_else(|| HaAuthError::Internal("callback server already awaited".to_string()))?;

        let code_result = match rx.await {
            Ok(res) => res,
            Err(_) => Err(HaAuthError::Internal(
                "callback server stopped unexpectedly".to_string(),
            )),
        };

        code_result
    }

    pub async fn shutdown(&self) {
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.lock().await.take() {
            let _ = join.await;
        }
    }
}

/// Binds and runs a localhost callback server.
///
/// The server binds to `127.0.0.1` and probes ports from `port_start` upward until `port_end`.
pub async fn start_callback_server(
    redirect: &RedirectConfig,
    expected_state: &str,
) -> Result<CallbackServer, HaAuthError> {
    let (listener, addr) =
        bind_in_range(&redirect.host, redirect.port_start, redirect.port_end).await?;
    let redirect_uri = build_redirect_uri(&redirect.host, addr.port(), &redirect.path)?;
    let success_html = load_success_page_from_assets()?;

    let (tx, rx) = oneshot::channel();
    let state = AppState {
        expected_state: Arc::new(expected_state.to_string()),
        tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
        success_html: Arc::new(success_html),
    };

    let app = Router::new()
        .route(&redirect.path, get(handle_callback))
        .route("/{*asset}", get(handle_success_asset))
        .with_state(state);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
    });

    let join = tokio::spawn(async move { server.into_future().await });

    Ok(CallbackServer {
        redirect_uri,
        rx: Arc::new(Mutex::new(Some(rx))),
        shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
        join: Arc::new(Mutex::new(Some(join))),
    })
}

fn build_redirect_uri(host: &str, port: u16, path: &str) -> Result<String, HaAuthError> {
    let mut url = Url::parse("http://localhost").map_err(HaAuthError::from)?;
    match host.parse::<IpAddr>() {
        Ok(ip) => url
            .set_ip_host(ip)
            .map_err(|_| HaAuthError::Internal(format!("invalid redirect host: {host}")))?,
        Err(_) => url
            .set_host(Some(host))
            .map_err(|_| HaAuthError::Internal(format!("invalid redirect host: {host}")))?,
    }
    url.set_port(Some(port))
        .map_err(|_| HaAuthError::Internal(format!("invalid redirect port: {port}")))?;
    url.set_path(path);
    Ok(url.to_string())
}

async fn bind_in_range(
    host: &str,
    start: u16,
    end: u16,
) -> Result<(TcpListener, SocketAddr), HaAuthError> {
    let mut in_use_ports: Vec<u16> = Vec::new();
    for port in start..=end {
        if port_looks_in_use(host, port).await {
            in_use_ports.push(port);
            continue;
        }
        let addr = socket_addr_string(host, port);
        match TcpListener::bind(&addr).await {
            Ok(listener) => {
                let local = listener
                    .local_addr()
                    .map_err(|e| HaAuthError::Internal(e.to_string()))?;
                return Ok((listener, local));
            }
            Err(_) => continue,
        }
    }
    if !in_use_ports.is_empty() && in_use_ports.len() == (end - start + 1) as usize {
        return Err(HaAuthError::Internal(format!(
            "callback redirect port(s) already in use: {host} ports {start}-{end}"
        )));
    }
    Err(HaAuthError::Internal(format!(
        "unable to bind callback server on {host} ports {start}-{end}"
    )))
}

async fn port_looks_in_use(host: &str, port: u16) -> bool {
    let addr = socket_addr_string(host, port);
    let connect = TcpStream::connect(&addr);
    let duration = time::Duration::from_millis(200);
    matches!(time::timeout(duration, connect).await, Ok(Ok(_)))
}

fn socket_addr_string(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

async fn handle_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    let result = parse_callback(state.expected_state.as_str(), query);
    if let Some(tx) = state.tx.lock().await.take() {
        let _ = tx.send(result);
    }
    Html((*state.success_html).clone())
}

async fn handle_success_asset(
    State(_state): State<AppState>,
    AxumPath(asset): AxumPath<String>,
) -> impl IntoResponse {
    let Ok(asset_key) = sanitize_asset_path(asset.as_str()) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let Some(asset_file) = SuccessAssets::get(asset_key.as_str()) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let bytes = asset_file.data.into_owned();
    let content_type = content_type_for_path(asset_key.as_str());
    ([(header::CONTENT_TYPE, content_type)], bytes).into_response()
}

fn load_success_page_from_assets() -> Result<String, HaAuthError> {
    let html = SuccessAssets::get("success.html").ok_or_else(|| {
        HaAuthError::Internal("embedded success page missing: success.html".to_string())
    })?;
    String::from_utf8(html.data.into_owned())
        .map_err(|e| HaAuthError::Internal(format!("invalid embedded success page utf-8: {e}")))
}

fn sanitize_asset_path(asset: &str) -> Result<String, ()> {
    let path = Path::new(asset);
    if path.as_os_str().is_empty() {
        return Err(());
    }

    let mut segments: Vec<&str> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => segments.push(segment.to_str().ok_or(())?),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return Err(()),
        }
    }

    if segments.is_empty() {
        return Err(());
    }

    Ok(segments.join("/"))
}

fn content_type_for_path(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        _ => "application/octet-stream",
    }
}

fn parse_callback(expected_state: &str, query: CallbackQuery) -> Result<String, HaAuthError> {
    if let Some(err) = query.error {
        let desc = query.error_description.unwrap_or_default();
        return Err(HaAuthError::Network(format!(
            "authorization error: {err} {desc}"
        )));
    }
    let code = query
        .code
        .ok_or_else(|| HaAuthError::Internal("missing 'code' in callback".to_string()))?;
    let got_state = query
        .state
        .ok_or_else(|| HaAuthError::Internal("missing 'state' in callback".to_string()))?;
    if got_state != expected_state {
        return Err(HaAuthError::Internal(
            "state mismatch in callback".to_string(),
        ));
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use super::{
        bind_in_range, build_redirect_uri, load_success_page_from_assets, start_callback_server,
    };
    use crate::config::RedirectConfig;
    use tokio::net::TcpListener;

    #[test]
    fn redirect_uri_formats_ipv4_host() {
        let uri = build_redirect_uri("127.0.0.1", 3000, "/callback").expect("uri");
        assert_eq!(uri, "http://127.0.0.1:3000/callback");
    }

    #[test]
    fn redirect_uri_formats_ipv6_host() {
        let uri = build_redirect_uri("::1", 3000, "/callback").expect("uri");
        assert_eq!(uri, "http://[::1]:3000/callback");
    }

    #[test]
    fn embedded_success_page_exists() {
        let page = load_success_page_from_assets().expect("embedded success page");
        assert!(!page.trim().is_empty());
    }

    #[tokio::test]
    async fn bind_in_range_supports_ipv6_loopback() {
        // Skip on systems where IPv6 loopback is not available.
        let probe = match TcpListener::bind("[::1]:0").await {
            Ok(listener) => listener,
            Err(_) => return,
        };
        let start = probe.local_addr().expect("probe addr").port();
        drop(probe);

        let end = start.saturating_add(16);
        let (listener, addr) = bind_in_range("::1", start, end)
            .await
            .expect("bind in range on ::1");
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        drop(listener);
    }

    #[tokio::test]
    async fn callback_server_starts_with_asset_wildcard_route() {
        let redirect = RedirectConfig {
            host: "127.0.0.1".to_string(),
            port_start: 0,
            port_end: 0,
            path: "/callback".to_string(),
        };
        let server = start_callback_server(&redirect, "state")
            .await
            .expect("callback server start");
        server.shutdown().await;
    }
}
