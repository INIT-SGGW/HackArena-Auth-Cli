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

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Do not open a browser; use the OAuth device flow instead.
    #[arg(long = "no-browser")]
    no_browser: bool,
}

/// CLI subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Log in and store a refresh token securely.
    Login(LoginArgs),
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
        Command::Login(args) => {
            crate::oidc::login(args.no_browser)?;
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

#[cfg(test)]
mod tests {
    use super::Command;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: Command,
    }

    #[test]
    fn parses_login_no_browser_flag() {
        let parsed = TestCli::try_parse_from(["ha-auth", "login", "--no-browser"])
            .expect("login --no-browser should parse");

        match parsed.command {
            Command::Login(args) => assert!(args.no_browser),
            _ => panic!("expected login command"),
        }
    }
}
