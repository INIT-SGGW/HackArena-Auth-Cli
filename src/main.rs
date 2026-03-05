//! `ha-auth` CLI entrypoint.

use clap::Parser;
use ha_auth::error::{ExitCode, HaAuthError};

#[derive(Debug, Parser)]
#[command(
    name = "ha-auth",
    version,
    about = "HackArena Auth CLI",
    long_about = "HackArena Auth CLI\nPurpose: Authentication helper for HackArena tools.\n\nRuntime profile: default is official. Set HA_AUTH_PROFILE=preprod for organizer testing.\nFor full environment override list, see README."
)]
struct Args {
    /// Suppress informational stderr logs.
    #[arg(short = 'q', long, global = true, env = "HA_AUTH_QUIET")]
    quiet: bool,
    /// Print structured JSON errors to stderr.
    #[arg(long, global = true, env = "HA_AUTH_ERRORS_JSON")]
    errors_json: bool,
    #[command(subcommand)]
    command: ha_auth::cli::Command,
}

fn main() {
    let args = Args::parse();
    ha_auth::output::set_quiet(args.quiet);

    let exit_code = match run(args.command) {
        Ok(()) => ExitCode::Success,
        Err(err) => {
            ha_auth::output::print_error(&err, args.errors_json);
            err.exit_code()
        }
    };
    std::process::exit(exit_code.as_i32());
}

fn run(command: ha_auth::cli::Command) -> Result<(), HaAuthError> {
    ha_auth::cli::dispatch(command)
}
