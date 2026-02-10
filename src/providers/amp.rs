//! Amp provider — reads/writes threads from Amp's local JSON thread store.
//!
//! Amp stores each conversation "thread" as a single JSON file named by thread ID.
//! In recent versions the VS Code extension migrates threads from VS Code
//! `globalStorage` into a centralized data directory.
//!
//! ## Centralized thread storage (preferred)
//!
//! - Linux (default): `~/.local/share/amp/threads/<thread-id>.json`
//! - Controlled by `XDG_DATA_HOME` (and casr override `AMP_DATA_HOME`)
//! - Direct casr override: `AMP_HOME` points to the directory that contains `threads/`
//!
//! ## Legacy VS Code extension storage (fallback during migration)
//!
//! - `<HOST_CONFIG>/User/globalStorage/sourcegraph.amp/threads3/<thread-id>.json`
//! - Where `<HOST_CONFIG>` can be VS Code (`Code`, `Code - Insiders`, `VSCodium`),
//!   Cursor, or Windsurf.
//!
//! The thread JSON format is Amp-internal but resembles Anthropic-style message
//! blocks: messages have a `role` and an array `content` with blocks like
//! `{type:"text", text:"..."}`, `{type:"tool_use", ...}`, `{type:"tool_result", ...}`.

use std::path::{Path, PathBuf};

use anyhow::Context;
use tracing::{debug, trace};

use crate::discovery::DetectionResult;
use crate::model::{
    CanonicalMessage, CanonicalSession, MessageRole, ToolCall, ToolResult, flatten_content,
    normalize_role, reindex_messages, truncate_title,
};
use crate::providers::{Provider, WriteOptions, WrittenSession};

/// VS Code Marketplace extension identifier.
const AMP_EXTENSION_ID: &str = "sourcegraph.amp";

/// Centralized thread directory name.
const CENTRAL_THREADS_DIR: &str = "threads";
/// Legacy thread directory name under VS Code globalStorage.
const LEGACY_THREADS_DIR: &str = "threads3";

/// Amp provider implementation.
pub struct Amp;

impl Amp {
    fn amp_home_dir() -> Option<PathBuf> {
        if let Ok(home) = std::env::var("AMP_HOME") {
            return Some(PathBuf::from(home));
        }

        // Match Amp's own centralized storage behavior: XDG_DATA_HOME or ~/.local/share.
        if let Ok(data_home) = std::env::var("AMP_DATA_HOME") {
            return Some(PathBuf::from(data_home).join("amp"));
        }

        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return Some(PathBuf::from(xdg).join("amp"));
        }

        dirs::home_dir().map(|h| h.join(".local").join("share").join("amp"))
    }

    fn centralized_threads_root() -> Option<PathBuf> {
        Self::amp_home_dir().map(|h| h.join(CENTRAL_THREADS_DIR))
    }

    fn legacy_threads_roots() -> Vec<PathBuf> {
        // Editor config roots that can host VS Code-style `User/globalStorage`.
        // Probe both config_dir and data_dir to cover Linux/Windows vs macOS.
        let mut host_roots: Vec<PathBuf> = Vec::new();
        if let Some(cfg) = dirs::config_dir() {
            host_roots.push(cfg.join("Code"));
            host_roots.push(cfg.join("Code - Insiders"));
            host_roots.push(cfg.join("VSCodium"));
            host_roots.push(cfg.join("Cursor"));
            host_roots.push(cfg.join("Windsurf"));
        }
        if let Some(data) = dirs::data_dir() {
            host_roots.push(data.join("Code"));
            host_roots.push(data.join("Code - Insiders"));
            host_roots.push(data.join("VSCodium"));
            host_roots.push(data.join("Cursor"));
            host_roots.push(data.join("Windsurf"));
        }

        host_roots.sort();
        host_roots.dedup();

        host_roots
            .into_iter()
            .map(|host| {
                host.join("User")
                    .join("globalStorage")
                    .join(AMP_EXTENSION_ID)
                    .join(LEGACY_THREADS_DIR)
            })
            .filter(|p| p.is_dir())
            .collect()
    }

    fn looks_like_thread_id(session_id: &str) -> bool {
        let Some(rest) = session_id.strip_prefix("T-") else {
            return false;
        };
        uuid::Uuid::parse_str(rest).is_ok()
    }

    fn read_json(path: &Path) -> anyhow::Result<serde_json::Value> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&content).with_context(|| format!("invalid json: {}", path.display()))
    }

    fn file_uri_to_path(s: &str) -> Option<PathBuf> {
        let rest = s.strip_prefix("file://")?;
        // Handle file://localhost/... by stripping host component.
        let rest = rest.strip_prefix("localhost/").unwrap_or(rest);
        let decoded = urlencoding::decode(rest).ok()?.into_owned();
        // Keep leading slash if present (file:///... => rest starts with '/').
        Some(PathBuf::from(decoded))
    }

    fn extract_workspace(thread: &serde_json::Value) -> Option<PathBuf> {
        let env_init = thread
            .get("env")
            .and_then(|v| v.get("initial"))
            .and_then(|v| v.as_object())?;

        // 1) explicit cwd
        if let Some(cwd) = env_init.get("cwd").and_then(|v| v.as_str()) {
            return Some(PathBuf::from(cwd));
        }

        // 2) first workspace tree URI
        if let Some(serde_json::Value::Array(trees)) = env_init.get("trees") {
            for t in trees {
                let Some(obj) = t.as_object() else { continue };
                let Some(uri) = obj.get("uri") else { continue };
                match uri {
                    serde_json::Value::String(s) => {
                        if let Some(p) = Self::file_uri_to_path(s) {
                            return Some(p);
                        }
                        // Some builds may store plain paths.
                        if !s.is_empty() {
                            return Some(PathBuf::from(s));
                        }
                    }
                    serde_json::Value::Object(o) => {
                        if let Some(fs_path) = o.get("fsPath").and_then(|v| v.as_str()) {
                            return Some(PathBuf::from(fs_path));
                        }
                        if let Some(path) = o.get("path").and_then(|v| v.as_str()) {
                            return Some(PathBuf::from(path));
                        }
                    }
                    _ => {}
                }
            }
        }

        None
    }

    fn extract_tool_calls(content: &serde_json::Value) -> Vec<ToolCall> {
        let serde_json::Value::Array(blocks) = content else {
            return vec![];
        };
        blocks
            .iter()
            .filter_map(|block| {
                let obj = block.as_object()?;
                if obj.get("type")?.as_str()? != "tool_use" {
                    return None;
                }
                Some(ToolCall {
                    id: obj.get("id").and_then(|v| v.as_str()).map(String::from),
                    name: obj
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    arguments: obj.get("input").cloned().unwrap_or(serde_json::Value::Null),
                })
            })
            .collect()
    }

    fn render_tool_progress(progress: &serde_json::Value) -> Option<String> {
        match progress {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Array(arr) => {
                let parts: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                if parts.is_empty() {
                    None
                } else {
                    Some(parts.join("\n"))
                }
            }
            serde_json::Value::Object(obj) => {
                if let Some(out) = obj.get("output").and_then(|v| v.as_str()) {
                    return Some(out.to_string());
                }
                // Last resort: stringify structured progress.
                serde_json::to_string(obj).ok()
            }
            _ => None,
        }
    }

    fn extract_tool_results(content: &serde_json::Value) -> Vec<ToolResult> {
        let serde_json::Value::Array(blocks) = content else {
            return vec![];
        };

        blocks
            .iter()
            .filter_map(|block| {
                let obj = block.as_object()?;
                if obj.get("type")?.as_str()? != "tool_result" {
                    return None;
                }

                let call_id = obj
                    .get("toolUseID")
                    .or_else(|| obj.get("tool_use_id"))
                    .or_else(|| obj.get("tool_useId"))
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let run = obj.get("run").cloned().unwrap_or(serde_json::Value::Null);
                let status = run
                    .as_object()
                    .and_then(|r| r.get("status"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let is_error = matches!(status, "error" | "cancelled" | "rejected-by-user");

                let content_str = run
                    .as_object()
                    .and_then(|r| r.get("progress"))
                    .and_then(Self::render_tool_progress)
                    .or_else(|| {
                        run.as_object()
                            .and_then(|r| r.get("result"))
                            .map(flatten_content)
                    })
                    .unwrap_or_else(|| {
                        if status.is_empty() {
                            String::new()
                        } else {
                            format!("[tool_result status: {status}]")
                        }
                    });

                Some(ToolResult {
                    call_id,
                    content: content_str,
                    is_error,
                })
            })
            .collect()
    }

    fn extract_message_timestamp(msg: &serde_json::Value) -> Option<i64> {
        msg.get("meta")
            .and_then(|v| v.get("sentAt"))
            .and_then(|v| v.as_i64())
    }

    fn extract_info_summary_text(msg: &serde_json::Value) -> Option<String> {
        let role = msg.get("role").and_then(|v| v.as_str())?;
        if role != "info" {
            return None;
        }
        let serde_json::Value::Array(blocks) = msg.get("content")? else {
            return None;
        };
        for block in blocks {
            let Some(obj) = block.as_object() else {
                continue;
            };
            if obj.get("type").and_then(|v| v.as_str()) != Some("summary") {
                continue;
            }
            let Some(summary) = obj.get("summary").and_then(|v| v.as_object()) else {
                continue;
            };
            let stype = summary.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match stype {
                "message" => {
                    if let Some(text) = summary.get("summary").and_then(|v| v.as_str()) {
                        return Some(text.to_string());
                    }
                }
                "thread" => {
                    if let Some(id) = summary.get("thread").and_then(|v| v.as_str()) {
                        return Some(format!("[summary thread: {id}]"));
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn pick_threads_root_for_write() -> anyhow::Result<PathBuf> {
        if let Some(root) = Self::centralized_threads_root() {
            return Ok(root);
        }
        // Last-resort: write into first detected legacy root.
        Self::legacy_threads_roots()
            .into_iter()
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Amp storage not found. Set AMP_HOME (dir containing threads/) or ensure Amp has created its thread storage."
                )
            })
    }

    fn generate_thread_id() -> String {
        format!("T-{}", uuid::Uuid::new_v4())
    }

    fn amp_role_for_canonical(role: &MessageRole) -> &'static str {
        match role {
            MessageRole::Assistant => "assistant",
            MessageRole::User => "user",
            MessageRole::System | MessageRole::Tool | MessageRole::Other(_) => "info",
        }
    }

    fn build_amp_message(msg: &CanonicalMessage) -> serde_json::Value {
        let mut blocks: Vec<serde_json::Value> = Vec::new();
        if !msg.content.trim().is_empty() {
            blocks.push(serde_json::json!({"type":"text","text": msg.content}));
        }

        // Preserve tool invocations as assistant tool_use blocks when possible.
        if msg.role == MessageRole::Assistant {
            for call in &msg.tool_calls {
                let id = call
                    .id
                    .clone()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| format!("toolu_{}", uuid::Uuid::new_v4()));
                blocks.push(serde_json::json!({
                    "type": "tool_use",
                    "id": id,
                    "name": call.name,
                    "input": call.arguments,
                }));
            }
        }

        // Render tool results as Amp internal tool_result blocks (toolUseID + run).
        for tr in &msg.tool_results {
            let id = tr
                .call_id
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| format!("toolu_{}", uuid::Uuid::new_v4()));
            let status = if tr.is_error { "error" } else { "done" };
            blocks.push(serde_json::json!({
                "type": "tool_result",
                "toolUseID": id,
                "run": {
                    "status": status,
                    "progress": tr.content,
                }
            }));
        }

        let mut obj = serde_json::Map::new();
        obj.insert(
            "role".to_string(),
            serde_json::Value::String(Self::amp_role_for_canonical(&msg.role).to_string()),
        );
        obj.insert("content".to_string(), serde_json::Value::Array(blocks));
        if let Some(ts) = msg.timestamp {
            obj.insert("meta".to_string(), serde_json::json!({"sentAt": ts}));
        }
        serde_json::Value::Object(obj)
    }
}

impl Provider for Amp {
    fn name(&self) -> &str {
        "Amp"
    }

    fn slug(&self) -> &str {
        "amp"
    }

    fn cli_alias(&self) -> &str {
        "amp"
    }

    fn detect(&self) -> DetectionResult {
        let mut evidence = Vec::new();
        let mut installed = false;

        if let Ok(home) = std::env::var("AMP_HOME") {
            evidence.push(format!("AMP_HOME={home}"));
            let p = PathBuf::from(&home);
            if p.is_dir() {
                evidence.push(format!("{} exists", p.display()));
            } else {
                evidence.push(format!("{} missing", p.display()));
            }
        }
        if let Ok(data_home) = std::env::var("AMP_DATA_HOME") {
            evidence.push(format!("AMP_DATA_HOME={data_home}"));
        }

        if let Some(root) = Self::centralized_threads_root()
            && root.is_dir()
        {
            installed = true;
            evidence.push(format!("{} detected", root.display()));
        }
        let legacy = Self::legacy_threads_roots();
        if !legacy.is_empty() {
            installed = true;
            for r in &legacy {
                evidence.push(format!("{} detected", r.display()));
            }
        }

        trace!(provider = "amp", installed, ?evidence, "detection");
        DetectionResult {
            installed,
            version: None,
            evidence,
        }
    }

    fn session_roots(&self) -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = Vec::new();
        if let Some(root) = Self::centralized_threads_root()
            && root.is_dir()
        {
            roots.push(root);
        }
        roots.extend(Self::legacy_threads_roots());

        // Dedup preserving order.
        let mut seen = std::collections::HashSet::new();
        roots.retain(|p| seen.insert(p.clone()));
        roots
    }

    fn owns_session(&self, session_id: &str) -> Option<PathBuf> {
        if !Self::looks_like_thread_id(session_id) {
            return None;
        }
        for root in self.session_roots() {
            let candidate = root.join(format!("{session_id}.json"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }

    fn read_session(&self, path: &Path) -> anyhow::Result<CanonicalSession> {
        let thread = Self::read_json(path)?;
        let thread_obj = thread
            .as_object()
            .context("Amp thread JSON should be an object")?;

        let session_id = thread_obj
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .map(str::to_string)
            })
            .context("Amp thread missing id and filename has no stem")?;

        let created = thread_obj.get("created").and_then(|v| v.as_i64());
        let title = thread_obj
            .get("title")
            .and_then(|v| v.as_str())
            .map(|s| truncate_title(s, 100));

        let workspace = Self::extract_workspace(&thread);

        let mut messages: Vec<CanonicalMessage> = Vec::new();
        let serde_json::Value::Array(msgs) = thread_obj
            .get("messages")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]))
        else {
            anyhow::bail!("Amp thread messages must be an array");
        };

        for (idx, msg) in msgs.iter().enumerate() {
            let role_str = msg.get("role").and_then(|v| v.as_str()).unwrap_or("other");
            let role = normalize_role(role_str);
            let content_val = msg
                .get("content")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            let mut content = flatten_content(&content_val);
            if content.trim().is_empty()
                && let Some(summary_text) = Self::extract_info_summary_text(msg)
            {
                content = summary_text;
            }

            let tool_calls = Self::extract_tool_calls(&content_val);
            let tool_results = Self::extract_tool_results(&content_val);
            let timestamp = Self::extract_message_timestamp(msg);

            messages.push(CanonicalMessage {
                idx,
                role,
                content,
                timestamp,
                author: None,
                tool_calls,
                tool_results,
                extra: msg.clone(),
            });
        }

        reindex_messages(&mut messages);

        let started_at = created;
        let ended_at = messages
            .iter()
            .filter_map(|m| m.timestamp)
            .max()
            .or(started_at);

        // If the thread has no explicit title, fall back to the first user message.
        let title = title.or_else(|| {
            messages
                .iter()
                .find(|m| m.role == MessageRole::User && !m.content.trim().is_empty())
                .map(|m| truncate_title(&m.content, 100))
        });

        debug!(
            provider = "amp",
            session_id,
            msg_count = messages.len(),
            path = %path.display(),
            "read Amp thread"
        );

        Ok(CanonicalSession {
            session_id,
            provider_slug: "amp".to_string(),
            workspace,
            title,
            started_at,
            ended_at,
            messages,
            metadata: thread.clone(),
            source_path: path.to_path_buf(),
            model_name: None,
        })
    }

    fn write_session(
        &self,
        session: &CanonicalSession,
        opts: &WriteOptions,
    ) -> anyhow::Result<WrittenSession> {
        let threads_root = Self::pick_threads_root_for_write()?;
        let thread_id = Self::generate_thread_id();

        let created = session
            .started_at
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

        let title = session
            .title
            .as_ref()
            .map(|t| truncate_title(t, 100))
            .or_else(|| {
                session
                    .messages
                    .iter()
                    .find(|m| m.role == MessageRole::User && !m.content.trim().is_empty())
                    .map(|m| truncate_title(&m.content, 100))
            });

        let mut thread_obj = serde_json::Map::new();
        thread_obj.insert("v".to_string(), serde_json::Value::Number(0.into()));
        thread_obj.insert(
            "id".to_string(),
            serde_json::Value::String(thread_id.clone()),
        );
        thread_obj.insert(
            "created".to_string(),
            serde_json::Value::Number(created.into()),
        );
        if let Some(t) = title {
            thread_obj.insert("title".to_string(), serde_json::Value::String(t));
        }
        if let Some(ws) = session.workspace.as_ref() {
            let ws_str = ws.display().to_string();
            let file_uri = format!("file://{}", ws_str);
            thread_obj.insert(
                "env".to_string(),
                serde_json::json!({
                    "initial": {
                        "cwd": ws_str,
                        "trees": [{"uri": file_uri, "displayName": ws.file_name().and_then(|s| s.to_str()).unwrap_or("")}],
                    }
                }),
            );
        }

        let amp_messages: Vec<serde_json::Value> = session
            .messages
            .iter()
            .map(Self::build_amp_message)
            .collect();
        thread_obj.insert(
            "messages".to_string(),
            serde_json::Value::Array(amp_messages),
        );

        let thread_json = serde_json::Value::Object(thread_obj);
        let bytes = serde_json::to_vec_pretty(&thread_json)?;

        let target_path = threads_root.join(format!("{thread_id}.json"));
        let outcome = crate::pipeline::atomic_write(&target_path, &bytes, opts.force, self.slug())?;

        Ok(WrittenSession {
            paths: vec![outcome.target_path.clone()],
            session_id: thread_id.clone(),
            resume_command: self.resume_command(&thread_id),
            backup_path: outcome.backup_path,
        })
    }

    fn resume_command(&self, session_id: &str) -> String {
        // Amp doesn't have a stable "resume exact local thread file" CLI contract.
        // The most portable action is to reference the thread by ID in a new prompt.
        format!("amp threads continue --execute \"Continue from @{session_id}\"")
    }
}
