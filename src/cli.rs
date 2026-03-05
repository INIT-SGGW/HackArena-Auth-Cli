//! CLI command dispatch.

use clap::{Args, Subcommand};

use crate::{
    error::HaAuthError,
    output::{OkStatus, print_json_line, print_text_line},
};

#[derive(Debug, Args)]
pub struct TokenArgs {
    /// Print only the access token as plain text.
    #[arg(long)]
    raw: bool,
}

/// CLI subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a browser-based PKCE login and store a refresh token securely.
    Login,
    /// Print an access token (refreshing silently) as JSON to stdout.
    Token(TokenArgs),
    /// Revoke and/or delete local credentials.
    Logout,
    /// Decode current token claims (without signature verification).
    Whoami,
}

/// Dispatches a CLI command.
pub fn dispatch(command: Command) -> Result<(), HaAuthError> {
    match command {
        Command::Login => {
            crate::oidc::login_with_pkce()?;
            print_json_line(&OkStatus { status: "ok" })
        }
        Command::Token(args) => {
            let token = crate::oidc::get_access_token()?;
            if args.raw {
                print_text_line(token.token.as_str());
                Ok(())
            } else {
                print_json_line(&token)
            }
        }
        Command::Logout => {
            crate::oidc::logout()?;
            print_json_line(&OkStatus { status: "ok" })
        }
        Command::Whoami => {
            let claims = crate::whoami::whoami()?;
            print_json_line(&claims)
        }
    }
}
