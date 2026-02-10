//! Cline provider — reads/writes sessions from VS Code-style `globalStorage`.
//!
//! Cline is the VS Code extension published as `saoudrizwan.claude-dev`.
//! Its session artifacts are stored under the editor's `User/globalStorage`:
//!
//! - `<HOST_CONFIG>/User/globalStorage/saoudrizwan.claude-dev/tasks/<taskId>/api_conversation_history.json`
//! - `<HOST_CONFIG>/User/globalStorage/saoudrizwan.claude-dev/tasks/<taskId>/ui_messages.json`
//! - `<HOST_CONFIG>/User/globalStorage/saoudrizwan.claude-dev/state/taskHistory.json`
//!
//! Where `<HOST_CONFIG>` can be VS Code (`Code`, `Code - Insiders`, `VSCodium`) or Cursor.
//!
//! ## Session IDs
//!
//! Task IDs are numeric strings (typically `Date.now()` / epoch millis).
//! casr therefore generates numeric IDs for Cline targets as well.

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
const CLINE_EXTENSION_ID: &str = "saoudrizwan.claude-dev";

const FILE_API_HISTORY: &str = "api_conversation_history.json";
const FILE_UI_MESSAGES: &str = "ui_messages.json";
const FILE_UI_MESSAGES_OLD: &str = "claude_messages.json";
const FILE_TASK_METADATA: &str = "task_metadata.json";
const FILE_TASK_HISTORY: &str = "taskHistory.json";

/// Cline provider implementation.
pub struct Cline;

impl Cline {
    /// Cline globalStorage root. Respects `CLINE_HOME` env var override.
    ///
    /// The value is expected to be the extension's globalStorage directory, i.e.
    /// the directory that contains `tasks/` and `state/`.
    fn storage_roots() -> Vec<PathBuf> {
        if let Ok(home) = std::env::var("CLINE_HOME") {
            return vec![PathBuf::from(home)];
        }

        // Editor config roots that can host VS Code-style `User/globalStorage`.
        // We probe both config_dir and data_dir to cover Linux/Windows vs macOS.
        let mut host_roots: Vec<PathBuf> = Vec::new();
        if let Some(cfg) = dirs::config_dir() {
            host_roots.push(cfg.join("Code"));
            host_roots.push(cfg.join("Code - Insiders"));
            host_roots.push(cfg.join("VSCodium"));
            host_roots.push(cfg.join("Cursor"));
        }
        if let Some(data) = dirs::data_dir() {
            host_roots.push(data.join("Code"));
            host_roots.push(data.join("Code - Insiders"));
            host_roots.push(data.join("VSCodium"));
            host_roots.push(data.join("Cursor"));
        }

        // Deduplicate while preserving order.
        host_roots.sort();
        host_roots.dedup();

        host_roots
            .into_iter()
            .map(|host| {
                host.join("User")
                    .join("globalStorage")
                    .join(CLINE_EXTENSION_ID)
            })
            .filter(|p| p.is_dir())
            .collect()
    }

    fn tasks_root(storage_root: &Path) -> PathBuf {
        storage_root.join("tasks")
    }

    fn state_dir(storage_root: &Path) -> PathBuf {
        storage_root.join("state")
    }

    fn task_history_path(storage_root: &Path) -> PathBuf {
        Self::state_dir(storage_root).join(FILE_TASK_HISTORY)
    }

    fn task_dir_from_api_path(path: &Path) -> Option<PathBuf> {
        // .../tasks/<taskId>/<file>
        let task_dir = path.parent()?.to_path_buf();
        if task_dir.parent()?.file_name()?.to_string_lossy() != "tasks" {
            return None;
        }
        Some(task_dir)
    }

    fn task_id_from_task_dir(task_dir: &Path) -> Option<String> {
        task_dir
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
    }

    fn find_storage_root_for_path(path: &Path) -> Option<PathBuf> {
        // Expect: <storage_root>/tasks/<taskId>/<file>
        let task_dir = Self::task_dir_from_api_path(path)?;
        let tasks_dir = task_dir.parent()?;
        let storage_root = tasks_dir.parent()?;
        Some(storage_root.to_path_buf())
    }

    fn read_json(path: &Path) -> anyhow::Result<serde_json::Value> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&content).with_context(|| format!("invalid json: {}", path.display()))
    }

    fn read_task_history_item(
        storage_root: &Path,
        task_id: &str,
    ) -> Option<serde_json::Map<String, serde_json::Value>> {
        let history_path = Self::task_history_path(storage_root);
        let Ok(root) = Self::read_json(&history_path) else {
            return None;
        };
        let serde_json::Value::Array(items) = root else {
            return None;
        };
        for item in items {
            let Some(obj) = item.as_object() else {
                continue;
            };
            if obj.get("id").and_then(|v| v.as_str()) == Some(task_id) {
                return Some(obj.clone());
            }
        }
        None
    }

    fn extract_tool_calls(content: Option<&serde_json::Value>) -> Vec<ToolCall> {
        let Some(serde_json::Value::Array(blocks)) = content else {
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

    fn extract_tool_results(content: Option<&serde_json::Value>) -> Vec<ToolResult> {
        let Some(serde_json::Value::Array(blocks)) = content else {
            return vec![];
        };
        blocks
            .iter()
            .filter_map(|block| {
                let obj = block.as_object()?;
                if obj.get("type")?.as_str()? != "tool_result" {
                    return None;
                }
                let content_value = obj
                    .get("content")
                    .or_else(|| obj.get("output"))
                    .unwrap_or(&serde_json::Value::Null);
                Some(ToolResult {
                    call_id: obj
                        .get("tool_use_id")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    content: flatten_content(content_value),
                    is_error: obj
                        .get("is_error")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                })
            })
            .collect()
    }

    fn pick_storage_root_for_write() -> anyhow::Result<PathBuf> {
        let roots = Self::storage_roots();
        roots.into_iter().next().ok_or_else(|| {
            anyhow::anyhow!(
                "Cline storage not found. Set CLINE_HOME to the extension globalStorage directory."
            )
        })
    }

    fn generate_task_id(storage_root: &Path) -> String {
        let tasks_root = Self::tasks_root(storage_root);
        let mut candidate: i64 = chrono::Utc::now().timestamp_millis();
        loop {
            let id = candidate.to_string();
            if !tasks_root.join(&id).exists() {
                return id;
            }
            candidate = candidate.saturating_add(1);
        }
    }

    fn build_api_history(session: &CanonicalSession) -> Vec<serde_json::Value> {
        let mut out = Vec::new();

        for msg in &session.messages {
            let role = match msg.role {
                MessageRole::Assistant => "assistant",
                MessageRole::User => "user",
                MessageRole::Tool | MessageRole::System | MessageRole::Other(_) => "user",
            };

            let mut blocks: Vec<serde_json::Value> = Vec::new();

            match role {
                "assistant" => {
                    if !msg.content.trim().is_empty() {
                        blocks.push(serde_json::json!({
                            "type": "text",
                            "text": msg.content,
                        }));
                    }
                    for tc in &msg.tool_calls {
                        blocks.push(serde_json::json!({
                            "type": "tool_use",
                            "id": tc.id.as_deref().unwrap_or(""),
                            "name": tc.name,
                            "input": tc.arguments,
                        }));
                    }
                }
                _ => {
                    if !msg.content.trim().is_empty() {
                        blocks.push(serde_json::json!({
                            "type": "text",
                            "text": msg.content,
                        }));
                    }
                    for tr in &msg.tool_results {
                        blocks.push(serde_json::json!({
                            "type": "tool_result",
                            "tool_use_id": tr.call_id.as_deref().unwrap_or(""),
                            "content": tr.content,
                            "is_error": tr.is_error,
                        }));
                    }
                }
            }

            out.push(serde_json::json!({
                "role": role,
                "content": blocks,
            }));
        }

        out
    }

    fn build_ui_messages(session: &CanonicalSession) -> Vec<serde_json::Value> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut cursor_ts = session.started_at.unwrap_or(now);

        // Cline's UI messages are not a simple chat transcript; we emit a minimal, plausible subset:
        // - a "task" say-message for the first user message
        // - "user_feedback" for subsequent user messages
        // - "text" for assistant messages
        let mut out = Vec::new();
        let mut first_task_emitted = false;

        for msg in &session.messages {
            let (say, text) = match msg.role {
                MessageRole::User => {
                    if !first_task_emitted {
                        first_task_emitted = true;
                        ("task", msg.content.clone())
                    } else {
                        ("user_feedback", msg.content.clone())
                    }
                }
                MessageRole::Assistant => ("text", msg.content.clone()),
                MessageRole::Tool | MessageRole::System | MessageRole::Other(_) => {
                    ("info", msg.content.clone())
                }
            };

            if text.trim().is_empty() {
                continue;
            }

            out.push(serde_json::json!({
                "ts": msg.timestamp.unwrap_or(cursor_ts),
                "type": "say",
                "say": say,
                "text": text,
            }));

            cursor_ts = cursor_ts.saturating_add(1);
        }

        out
    }

    fn update_task_history(
        storage_root: &Path,
        task_id: &str,
        session: &CanonicalSession,
        provider_slug: &str,
    ) -> anyhow::Result<Option<PathBuf>> {
        let history_path = Self::task_history_path(storage_root);

        let mut items: Vec<serde_json::Value> = match Self::read_json(&history_path) {
            Ok(serde_json::Value::Array(arr)) => arr,
            _ => Vec::new(),
        };

        // Remove any existing entry with the same id (defensive).
        items.retain(|v| v.get("id").and_then(|x| x.as_str()) != Some(task_id));

        let title = session
            .title
            .clone()
            .or_else(|| {
                session
                    .messages
                    .iter()
                    .find(|m| m.role == MessageRole::User)
                    .map(|m| truncate_title(&m.content, 100))
            })
            .unwrap_or_else(|| "Untitled Task".to_string());

        let ts = session
            .started_at
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

        let mut obj = serde_json::Map::new();
        obj.insert("id".into(), serde_json::Value::String(task_id.to_string()));
        obj.insert("ts".into(), serde_json::Value::Number(ts.into()));
        obj.insert("task".into(), serde_json::Value::String(title));
        obj.insert("tokensIn".into(), serde_json::Value::Number(0.into()));
        obj.insert("tokensOut".into(), serde_json::Value::Number(0.into()));
        obj.insert(
            "totalCost".into(),
            serde_json::Value::Number(
                serde_json::Number::from_f64(0.0).unwrap_or_else(|| 0.into()),
            ),
        );
        if let Some(ws) = session.workspace.as_ref() {
            obj.insert(
                "cwdOnTaskInitialization".into(),
                serde_json::Value::String(ws.display().to_string()),
            );
        }
        if let Some(model) = session.model_name.as_ref() {
            obj.insert("modelId".into(), serde_json::Value::String(model.clone()));
        }

        items.push(serde_json::Value::Object(obj));

        // Sort newest-first for determinism.
        items.sort_by(|a, b| {
            let ta = a.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
            let tb = b.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
            tb.cmp(&ta)
        });

        let bytes = serde_json::to_vec_pretty(&serde_json::Value::Array(items))
            .context("failed to serialize taskHistory.json")?;

        // `taskHistory.json` is a shared state file; we must overwrite it even when
        // `--force` is not used for the session itself. We still do an atomic write
        // with a `.bak` backup for safety.
        let outcome = crate::pipeline::atomic_write(&history_path, &bytes, true, provider_slug)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        Ok(outcome.backup_path)
    }
}

impl Provider for Cline {
    fn name(&self) -> &str {
        "Cline"
    }

    fn slug(&self) -> &str {
        "cline"
    }

    fn cli_alias(&self) -> &str {
        "cln"
    }

    fn detect(&self) -> DetectionResult {
        let mut evidence = Vec::new();
        let mut installed = false;

        if let Ok(home) = std::env::var("CLINE_HOME") {
            evidence.push(format!("CLINE_HOME={home}"));
            let p = PathBuf::from(&home);
            if p.is_dir() {
                installed = true;
                evidence.push(format!("{} exists", p.display()));
            } else {
                evidence.push(format!("{} missing", p.display()));
            }
        }

        let roots = Self::storage_roots();
        if !roots.is_empty() {
            installed = true;
            for r in &roots {
                evidence.push(format!("{} detected", r.display()));
            }
        }

        trace!(provider = "cline", installed, ?evidence, "detection");
        DetectionResult {
            installed,
            version: None,
            evidence,
        }
    }

    fn session_roots(&self) -> Vec<PathBuf> {
        Self::storage_roots()
            .into_iter()
            .map(|root| Self::tasks_root(&root))
            .collect()
    }

    fn owns_session(&self, session_id: &str) -> Option<PathBuf> {
        for storage_root in Self::storage_roots() {
            let task_dir = Self::tasks_root(&storage_root).join(session_id);
            let api = task_dir.join(FILE_API_HISTORY);
            if api.is_file() {
                return Some(api);
            }
            let ui = task_dir.join(FILE_UI_MESSAGES);
            if ui.is_file() {
                return Some(ui);
            }
            let old = task_dir.join(FILE_UI_MESSAGES_OLD);
            if old.is_file() {
                return Some(old);
            }
        }
        None
    }

    fn read_session(&self, path: &Path) -> anyhow::Result<CanonicalSession> {
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !matches!(
            file_name,
            FILE_API_HISTORY | FILE_UI_MESSAGES | FILE_UI_MESSAGES_OLD
        ) {
            return Err(anyhow::anyhow!(
                "unsupported Cline session path (expected task file): {}",
                path.display()
            ));
        }

        let task_dir = Self::task_dir_from_api_path(path)
            .ok_or_else(|| anyhow::anyhow!("not a Cline task path: {}", path.display()))?;
        let task_id = Self::task_id_from_task_dir(&task_dir)
            .ok_or_else(|| anyhow::anyhow!("could not derive task id: {}", task_dir.display()))?;
        let storage_root = Self::find_storage_root_for_path(path).ok_or_else(|| {
            anyhow::anyhow!("could not derive Cline storage root for {}", path.display())
        })?;

        // Prefer API history for canonical messages (and avoid duplicates in `casr list`).
        let api_path = task_dir.join(FILE_API_HISTORY);
        let api_source_path = if file_name == FILE_API_HISTORY {
            path.to_path_buf()
        } else if api_path.is_file() {
            // If we were asked to read `ui_messages.json` but `api_conversation_history.json` exists,
            // treat the UI file as a non-primary artifact to avoid duplicate sessions in discovery.
            return Err(anyhow::anyhow!(
                "non-primary Cline task artifact (use {}): {}",
                FILE_API_HISTORY,
                path.display()
            ));
        } else {
            // Fall back to UI messages only when the API history file is missing.
            path.to_path_buf()
        };

        let mut messages: Vec<CanonicalMessage> = Vec::new();
        let mut model_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        if api_source_path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n == FILE_API_HISTORY)
        {
            let root = Self::read_json(&api_source_path)?;
            let serde_json::Value::Array(items) = root else {
                return Err(anyhow::anyhow!("Cline api history is not an array"));
            };

            for item in items {
                let Some(obj) = item.as_object() else {
                    continue;
                };
                let role_str = obj.get("role").and_then(|v| v.as_str()).unwrap_or("user");
                let role = normalize_role(role_str);
                let content_value = obj.get("content").unwrap_or(&serde_json::Value::Null);
                let content = flatten_content(content_value);

                if content.trim().is_empty() {
                    continue;
                }

                let author = obj
                    .get("modelInfo")
                    .and_then(|v| v.get("modelId"))
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                if let Some(ref m) = author {
                    *model_counts.entry(m.clone()).or_insert(0) += 1;
                }

                let tool_calls = Self::extract_tool_calls(Some(content_value));
                let tool_results = Self::extract_tool_results(Some(content_value));

                messages.push(CanonicalMessage {
                    idx: 0,
                    role,
                    content,
                    timestamp: None,
                    author,
                    tool_calls,
                    tool_results,
                    extra: serde_json::Value::Object(obj.clone()),
                });
            }
        } else {
            // ui_messages.json fallback: extract a minimal conversational transcript.
            let root = Self::read_json(&api_source_path)?;
            let serde_json::Value::Array(items) = root else {
                return Err(anyhow::anyhow!("Cline ui messages is not an array"));
            };
            for item in items {
                let Some(obj) = item.as_object() else {
                    continue;
                };
                let msg_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or_default();
                if msg_type != "say" {
                    continue;
                }
                let say = obj.get("say").and_then(|v| v.as_str()).unwrap_or_default();
                let text = obj.get("text").and_then(|v| v.as_str()).unwrap_or_default();
                if text.trim().is_empty() {
                    continue;
                }

                let role = match say {
                    "task" | "user_feedback" | "user_feedback_diff" => MessageRole::User,
                    _ => MessageRole::Assistant,
                };
                let ts = obj.get("ts").and_then(|v| v.as_i64());
                messages.push(CanonicalMessage {
                    idx: 0,
                    role,
                    content: text.to_string(),
                    timestamp: ts,
                    author: None,
                    tool_calls: vec![],
                    tool_results: vec![],
                    extra: serde_json::Value::Object(obj.clone()),
                });
            }
        }

        reindex_messages(&mut messages);

        let history_item = Self::read_task_history_item(&storage_root, &task_id);
        let workspace = history_item
            .as_ref()
            .and_then(|h| h.get("cwdOnTaskInitialization"))
            .and_then(|v| v.as_str())
            .map(PathBuf::from);
        let started_at = history_item
            .as_ref()
            .and_then(|h| h.get("ts"))
            .and_then(|v| v.as_i64());

        let title = history_item
            .as_ref()
            .and_then(|h| h.get("task"))
            .and_then(|v| v.as_str())
            .map(|s| truncate_title(s, 100))
            .or_else(|| {
                messages
                    .iter()
                    .find(|m| m.role == MessageRole::User)
                    .map(|m| truncate_title(&m.content, 100))
            });

        let model_name = model_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(name, _)| name)
            .or_else(|| {
                history_item
                    .as_ref()
                    .and_then(|h| h.get("modelId"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

        let mut metadata = serde_json::Map::new();
        metadata.insert(
            "source".into(),
            serde_json::Value::String("cline".to_string()),
        );
        if let Some(h) = history_item {
            metadata.insert("taskHistoryItem".into(), serde_json::Value::Object(h));
        }

        debug!(task_id, messages = messages.len(), "Cline session parsed");

        Ok(CanonicalSession {
            session_id: task_id,
            provider_slug: "cline".to_string(),
            workspace,
            title,
            started_at,
            ended_at: started_at,
            messages,
            metadata: serde_json::Value::Object(metadata),
            source_path: api_source_path,
            model_name,
        })
    }

    fn write_session(
        &self,
        session: &CanonicalSession,
        opts: &WriteOptions,
    ) -> anyhow::Result<WrittenSession> {
        let storage_root = Self::pick_storage_root_for_write()?;

        let target_task_id = Self::generate_task_id(&storage_root);
        let task_dir = Self::tasks_root(&storage_root).join(&target_task_id);
        std::fs::create_dir_all(&task_dir)
            .with_context(|| format!("failed to create {}", task_dir.display()))?;

        // 1) api_conversation_history.json
        let api_history = Self::build_api_history(session);
        let api_bytes =
            serde_json::to_vec(&api_history).context("failed to serialize api history")?;
        let api_path = task_dir.join(FILE_API_HISTORY);
        let _ = crate::pipeline::atomic_write(&api_path, &api_bytes, opts.force, self.slug())?;

        // 2) ui_messages.json
        let ui_messages = Self::build_ui_messages(session);
        let ui_bytes =
            serde_json::to_vec(&ui_messages).context("failed to serialize ui messages")?;
        let ui_path = task_dir.join(FILE_UI_MESSAGES);
        let _ = crate::pipeline::atomic_write(&ui_path, &ui_bytes, opts.force, self.slug())?;

        // 3) task_metadata.json (minimal)
        let metadata_path = task_dir.join(FILE_TASK_METADATA);
        let metadata_bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "files_in_context": [],
            "model_usage": [],
            "environment_history": [],
        }))
        .context("failed to serialize task metadata")?;
        let _ = crate::pipeline::atomic_write(
            &metadata_path,
            &metadata_bytes,
            opts.force,
            self.slug(),
        )?;

        // 4) state/taskHistory.json (best-effort, but needed for Cline to list tasks)
        let backup_path =
            Self::update_task_history(&storage_root, &target_task_id, session, self.slug())?;

        debug!(
            task_id = target_task_id,
            api = %api_path.display(),
            "Cline session written"
        );

        Ok(WrittenSession {
            paths: vec![api_path, ui_path, metadata_path],
            session_id: target_task_id.clone(),
            resume_command: self.resume_command(&target_task_id),
            backup_path,
        })
    }

    fn resume_command(&self, _session_id: &str) -> String {
        // Cline has no CLI resume flag. Best effort: open the workspace in VS Code.
        "code .".to_string()
    }
}

// Integration tests for Cline live under `tests/` so they can safely isolate env vars.
