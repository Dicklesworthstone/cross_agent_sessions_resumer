//! Error path tests for provider read/write failures.
//!
//! Tests permission-denied, read-only targets, and unreadable sources
//! using real providers with chmod-restricted temp directories.

#[cfg(unix)]
mod unix_error_paths {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::{LazyLock, Mutex};

    use casr::providers::Provider;
    use casr::providers::claude_code::ClaudeCode;
    use casr::providers::codex::Codex;

    static CC_ENV: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    static CODEX_ENV: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &Path) -> Self {
            let original = std::env::var(key).ok();
            unsafe { std::env::set_var(key, value) };
            Self { key, original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(val) => unsafe { std::env::set_var(self.key, val) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn fixtures_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    /// Restore permissions so temp dir cleanup succeeds.
    struct PermGuard {
        path: std::path::PathBuf,
        mode: u32,
    }

    impl Drop for PermGuard {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode));
        }
    }

    #[test]
    fn read_unreadable_cc_session_file_returns_error() {
        let _lock = CC_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("CLAUDE_HOME", tmp.path());

        // Copy a real fixture then make it unreadable.
        let src = fixtures_dir().join("claude_code/cc_simple.jsonl");
        let first_line: serde_json::Value = {
            let content = fs::read_to_string(&src).unwrap();
            serde_json::from_str(content.lines().next().unwrap()).unwrap()
        };
        let session_id = first_line["sessionId"].as_str().unwrap();
        let cwd = first_line["cwd"].as_str().unwrap_or("/tmp");
        let project_key = cwd.replace(|c: char| !c.is_alphanumeric(), "-");
        let target_dir = tmp.path().join(format!("projects/{project_key}"));
        fs::create_dir_all(&target_dir).unwrap();
        let target_file = target_dir.join(format!("{session_id}.jsonl"));
        fs::copy(&src, &target_file).unwrap();

        // Remove read permission.
        fs::set_permissions(&target_file, fs::Permissions::from_mode(0o000)).unwrap();
        let _guard = PermGuard {
            path: target_file.clone(),
            mode: 0o644,
        };

        let err = ClaudeCode.read_session(&target_file);
        assert!(
            err.is_err(),
            "reading unreadable file should fail; got {:?}",
            err
        );
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("ermission denied") || msg.contains("access") || msg.contains("open"),
            "error should mention permission; got: {msg}"
        );
    }

    #[test]
    fn write_to_readonly_dir_returns_error() {
        let _lock = CODEX_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("CODEX_HOME", tmp.path());

        // Create the sessions dir, then make it read-only.
        let sessions_dir = tmp.path().join("sessions");
        fs::create_dir_all(&sessions_dir).unwrap();
        fs::set_permissions(&sessions_dir, fs::Permissions::from_mode(0o555)).unwrap();
        let _guard = PermGuard {
            path: sessions_dir,
            mode: 0o755,
        };

        // Build a minimal session to write.
        let session = casr::model::CanonicalSession {
            session_id: "test-write-perm".to_string(),
            provider_slug: "claude-code".to_string(),
            workspace: Some(std::path::PathBuf::from("/tmp")),
            title: Some("Permission test".to_string()),
            started_at: Some(1_700_000_000_000),
            ended_at: Some(1_700_000_010_000),
            messages: vec![
                casr::model::CanonicalMessage {
                    idx: 0,
                    role: casr::model::MessageRole::User,
                    content: "test question".to_string(),
                    timestamp: Some(1_700_000_000_000),
                    author: None,
                    tool_calls: vec![],
                    tool_results: vec![],
                    extra: serde_json::Value::Null,
                },
                casr::model::CanonicalMessage {
                    idx: 1,
                    role: casr::model::MessageRole::Assistant,
                    content: "test answer".to_string(),
                    timestamp: Some(1_700_000_010_000),
                    author: None,
                    tool_calls: vec![],
                    tool_results: vec![],
                    extra: serde_json::Value::Null,
                },
            ],
            metadata: serde_json::Value::Null,
            source_path: std::path::PathBuf::from("/tmp/source.jsonl"),
            model_name: None,
        };

        let err = Codex.write_session(
            &session,
            &casr::providers::WriteOptions { force: false },
        );
        assert!(
            err.is_err(),
            "writing to read-only dir should fail; got {:?}",
            err
        );
    }

    #[test]
    fn read_nonexistent_file_returns_error() {
        let err = ClaudeCode.read_session(Path::new("/tmp/nonexistent-casr-test-file.jsonl"));
        assert!(err.is_err(), "reading nonexistent file should fail");
    }
}
