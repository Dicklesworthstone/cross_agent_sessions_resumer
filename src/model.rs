//! Canonical session model — the IR (intermediate representation) for casr.
//!
//! Every provider's native format is parsed into these types, and every
//! target format is generated from them. This is the Rosetta Stone of
//! cross-provider session conversion.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A provider-agnostic representation of an AI coding agent session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalSession {
    /// Unique session identifier (provider-assigned or generated).
    pub session_id: String,
    /// Provider slug that originally created this session (e.g. `"claude-code"`).
    pub provider_slug: String,
    /// Project root directory, if known.
    pub workspace: Option<PathBuf>,
    /// Human-readable title (first user message or explicit title).
    pub title: Option<String>,
    /// Session start time as epoch milliseconds.
    pub started_at: Option<i64>,
    /// Session end time as epoch milliseconds.
    pub ended_at: Option<i64>,
    /// Ordered conversation messages.
    pub messages: Vec<CanonicalMessage>,
    /// Provider-specific extras that don't map to canonical fields.
    pub metadata: serde_json::Value,
    /// Filesystem path of the original session file.
    pub source_path: PathBuf,
    /// Convenience: most common model name in the session.
    pub model_name: Option<String>,
}

/// A single message in a canonical session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalMessage {
    /// Zero-based sequential index.
    pub idx: usize,
    /// Who sent this message.
    pub role: MessageRole,
    /// The textual content of the message.
    pub content: String,
    /// Message timestamp as epoch milliseconds.
    pub timestamp: Option<i64>,
    /// Model name or `"user"` or `"reasoning"`.
    pub author: Option<String>,
    /// Tool invocations made in this message.
    pub tool_calls: Vec<ToolCall>,
    /// Results returned from tool invocations.
    pub tool_results: Vec<ToolResult>,
    /// Provider-specific fields preserved for round-trip fidelity.
    pub extra: serde_json::Value,
}

/// The role of a message sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageRole {
    User,
    Assistant,
    Tool,
    System,
    Other(String),
}

/// A tool invocation within a message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: Option<String>,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// A tool result within a message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub call_id: Option<String>,
    pub content: String,
    pub is_error: bool,
}

// ---------------------------------------------------------------------------
// Helpers (implemented in bd-2rl.3)
// ---------------------------------------------------------------------------

/// Flatten heterogeneous content representations into a single string.
pub fn flatten_content(_value: &serde_json::Value) -> String {
    todo!("bd-2rl.3: flatten_content")
}

/// Parse a timestamp value (ISO-8601, epoch seconds, epoch millis) into epoch millis.
pub fn parse_timestamp(_value: &serde_json::Value) -> Option<i64> {
    todo!("bd-2rl.3: parse_timestamp")
}

/// Re-assign sequential idx values (0, 1, 2, …) after filtering/sorting.
pub fn reindex_messages(_messages: &mut Vec<CanonicalMessage>) {
    todo!("bd-2rl.3: reindex_messages")
}

/// Extract a title from message content (first line, truncated).
pub fn truncate_title(_text: &str, _max_len: usize) -> String {
    todo!("bd-2rl.3: truncate_title")
}

/// Map provider-specific role strings to canonical [`MessageRole`].
pub fn normalize_role(_role_str: &str) -> MessageRole {
    todo!("bd-2rl.3: normalize_role")
}
