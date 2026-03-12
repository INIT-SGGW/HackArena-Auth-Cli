# HackArena Auth CLI

Standalone cross-platform Rust CLI for Keycloak OIDC authentication (Authorization Code Flow with PKCE).

## Quick Start

- Run `ha-auth login` to authenticate in the browser.
- Use `ha-auth token` to print access token payload as JSON.

## Stable CLI contract (for integrations)

- Parse only `stdout` for machine output.
- Treat `stderr` as diagnostics/logs.
- Use process exit code for control flow.

Success outputs:
- `ha-auth login` -> `{"status":"ok"}`
- `ha-auth logout` -> `{"status":"ok"}`
- `ha-auth token` -> `{"token":"...","expires_at":"..."}`
- `ha-auth token --raw` -> `<access_token>`
- `ha-auth whoami` -> `{"sub":"...","preferred_username":"...","email":"...","iss":"..."}`

Exit codes:
- `0` success
- `2` login required
- `10` network/upstream error
- `11` internal/local error

Integration-friendly flags:
- `-q`, `--quiet` (or `HA_AUTH_QUIET=true`) to suppress informational logs on `stderr`
- `--errors-json` (or `HA_AUTH_ERRORS_JSON=true`) to print structured errors on `stderr`

Example structured error (`--errors-json`):
- `{"error":"login_required","message":"login required","exit_code":2}`

Default auth values:
- `HA_AUTH_BASE_URL=https://auth.hackarena.pl`
- `HA_AUTH_REALM=Init`
- `HA_AUTH_CLIENT_ID=hackarena-auth-cli`

Optional env overrides (advanced):
- `HA_AUTH_SCOPES` (space-separated)
- `HA_AUTH_REDIRECT_HOST` (default `127.0.0.1`)
- `HA_AUTH_REDIRECT_PORT_START` (default `3000`)
- `HA_AUTH_REDIRECT_PORT_END` (default `3999`)
- `HA_AUTH_REDIRECT_PATH` (default `/callback`)
- `HA_AUTH_SECRET_BACKEND` (`auto`, `keyring`, `file`; default: Windows/macOS `auto`, Linux `file`)
- `HA_AUTH_SECRET_FILE` (absolute path override for file backend storage)

## Developers

- Build local binary: `cargo build --release`
- Run tests: `cargo test`

## Release (organizers)

- Build artifacts per platform/arch:
  - Windows x64: `cargo build --release --target x86_64-pc-windows-msvc`
  - Windows ARM64: `cargo build --release --target aarch64-pc-windows-msvc`
  - macOS ARM64: `cargo build --release --target aarch64-apple-darwin`
  - macOS x64: `cargo build --release --target x86_64-apple-darwin`
  - Linux x64 (portable musl): `cargo build --release --target x86_64-unknown-linux-musl`
  - Linux ARM64 (portable musl): `cargo build --release --target aarch64-unknown-linux-musl`

## Production notes

- Refresh tokens are namespaced in keyring by `base_url + realm + client_id`, so environments do not overwrite each other.
- In `auto` mode, `ha-auth` uses keyring first and falls back to file storage when secure storage is unavailable.
- On Linux builds, keyring backend is not included; use `file` or `auto` (which resolves to file).
- File fallback location defaults:
  - Windows: `%LOCALAPPDATA%/HackArena/auth/refresh-<namespace>.json`
  - macOS: `~/Library/Application Support/ha-auth/refresh-<namespace>.json`
  - Linux: `$XDG_STATE_HOME/ha-auth/refresh-<namespace>.json` (or `~/.local/state/ha-auth/...`)
- Legacy keyring entries from older versions are migrated automatically on first use.
- `base_url` is normalized and validated (requires host, no query/fragment/credentials) to keep endpoint behavior stable.
- `whoami` decodes JWT claims for convenience and does not verify token signature.

## Preprod (organizers)

- Intended for organizers only (typically behind VPN).
- Activate with `HA_AUTH_PROFILE=preprod` in wrapper/launcher process.
- To go back to official, unset `HA_AUTH_PROFILE`.
- Optional preprod overrides: `HA_AUTH_PREPROD_URL`, `HA_AUTH_PREPROD_REALM`, `HA_AUTH_PREPROD_CLIENT_ID`.
