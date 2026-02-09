//! Provider detection and cross-provider session lookup.
//!
//! The [`ProviderRegistry`] knows about all supported providers and can
//! detect which ones are installed, then locate sessions by ID across
//! all of them.

use std::path::PathBuf;

use crate::providers::Provider;

/// Central registry of all known providers.
pub struct ProviderRegistry {
    providers: Vec<Box<dyn Provider>>,
}

impl ProviderRegistry {
    /// Create a registry with all known providers.
    pub fn new(providers: Vec<Box<dyn Provider>>) -> Self {
        Self { providers }
    }

    /// Probe each provider for installation status.
    pub fn detect_all(&self) -> Vec<(&dyn Provider, DetectionResult)> {
        todo!("bd-3my.1: detect_all")
    }

    /// Return only providers that are currently installed.
    pub fn installed_providers(&self) -> Vec<&dyn Provider> {
        todo!("bd-3my.1: installed_providers")
    }

    /// Find a provider by its slug (e.g. `"claude-code"`).
    pub fn find_by_slug(&self, _slug: &str) -> Option<&dyn Provider> {
        todo!("bd-3my.1: find_by_slug")
    }

    /// Find a provider by its CLI alias (e.g. `"cc"`).
    pub fn find_by_alias(&self, _alias: &str) -> Option<&dyn Provider> {
        todo!("bd-3my.1: find_by_alias")
    }

    /// Search all installed providers for a session matching `session_id`.
    pub fn find_session(&self, _session_id: &str) -> Option<(&dyn Provider, PathBuf)> {
        todo!("bd-3my.2: find_session")
    }
}

/// Result of probing a provider for installation.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub installed: bool,
    pub version: Option<String>,
    pub evidence: Vec<String>,
}
