//! `ha-auth` library crate.
//!
//! This crate is primarily consumed by the `ha-auth` binary.

pub mod callback;
pub mod cli;
pub mod config;
pub mod error;
pub mod lock;
pub mod oidc;
pub mod output;
pub mod secret;
pub mod whoami;
