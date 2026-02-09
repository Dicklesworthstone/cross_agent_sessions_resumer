//! Actionable typed errors for casr.
//!
//! Each error variant includes enough context for the user to understand
//! what went wrong and what to do next. Internal propagation uses `anyhow`;
//! the public API exposes these `thiserror` types.

use std::path::PathBuf;

/// Errors that casr surfaces to the user.
#[derive(Debug, thiserror::Error)]
pub enum CasrError {
    /// Session ID not found in any installed provider.
    #[error(
        "Session '{session_id}' not found. Checked: {providers_checked:?} ({sessions_scanned} sessions scanned). Run 'casr list' to see all sessions."
    )]
    SessionNotFound {
        session_id: String,
        providers_checked: Vec<String>,
        sessions_scanned: usize,
    },

    /// Target provider binary/directory not detected on this machine.
    #[error("{provider} is not installed. {install_hint}")]
    ProviderNotInstalled {
        provider: String,
        install_hint: String,
    },

    /// Unknown provider alias in CLI input.
    #[error("Unknown provider alias '{alias}'. Known aliases: {}", known_aliases.join(", "))]
    ProviderNotDetected {
        alias: String,
        known_aliases: Vec<String>,
    },

    /// Failed to parse a session from its native format.
    #[error("Failed to read {provider} session at {}: {detail}", path.display())]
    SessionReadError {
        path: PathBuf,
        provider: String,
        detail: String,
    },

    /// Failed to write a converted session to disk.
    #[error("Failed to write {provider} session to {}: {detail}", path.display())]
    SessionWriteError {
        path: PathBuf,
        provider: String,
        detail: String,
    },

    /// Target session file already exists and `--force` was not supplied.
    #[error(
        "Session already exists at {}. Use --force to overwrite (creates .bak backup).",
        existing_path.display()
    )]
    SessionConflict {
        session_id: String,
        existing_path: PathBuf,
    },

    /// Canonical session failed validation checks.
    #[error("Session validation failed: {}", errors.join("; "))]
    ValidationError { errors: Vec<String> },
}
