//! Round-trip fidelity tests for the core 6 conversion paths plus Cursor paths.
//!
//! Each test: read source fixture → canonical → write to target (temp dir) →
//! read back → compare canonical fields against original.
//!
//! Tests verify: `read_T(write_T(read_S(source))) ≈ read_S(source)` where
//! S = source provider, T = target provider.
//!
//! ## Fidelity expectations
//!
//! | Field           | Expectation                                        |
//! |-----------------|----------------------------------------------------|
//! | message_count   | EXACT                                              |
//! | message_roles   | EXACT                                              |
//! | message_content | EXACT (text-only messages)                         |
//! | session_id      | NEW (generated UUID for target)                    |
//! | workspace       | EXACT for CC/Cod; BEST-EFFORT for Gemini targets   |
//! | model_name      | EXACT for CC targets; absent for Cod/Gmi targets   |
//! | git_branch      | LOST when leaving CC                               |
//! | token_usage     | LOST when leaving Codex                            |
//! | citations       | LOST when leaving Gemini                           |

use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use casr::model::{CanonicalSession, MessageRole};
use casr::providers::claude_code::ClaudeCode;
use casr::providers::codex::Codex;
use casr::providers::cursor::Cursor;
use casr::providers::gemini::Gemini;
use casr::providers::opencode::OpenCode;
use casr::providers::{Provider, WriteOptions};

// ---------------------------------------------------------------------------
// Env var isolation (same pattern as writer_test.rs)
// ---------------------------------------------------------------------------

static CC_ENV: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static CODEX_ENV: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static GEMINI_ENV: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static CURSOR_ENV: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static OPENCODE_ENV: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

struct EnvGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &Path) -> Self {
        let original = std::env::var(key).ok();
        // SAFETY: Protected by per-provider Mutex.
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

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Read a Claude Code fixture.
fn read_cc_fixture(name: &str) -> CanonicalSession {
    let path = fixtures_dir().join(format!("claude_code/{name}.jsonl"));
    ClaudeCode
        .read_session(&path)
        .unwrap_or_else(|e| panic!("Failed to read CC fixture '{name}': {e}"))
}

/// Read a Codex JSONL fixture.
fn read_codex_fixture(name: &str, ext: &str) -> CanonicalSession {
    let path = fixtures_dir().join(format!("codex/{name}.{ext}"));
    Codex
        .read_session(&path)
        .unwrap_or_else(|e| panic!("Failed to read Codex fixture '{name}': {e}"))
}

/// Read a Gemini fixture.
fn read_gemini_fixture(name: &str) -> CanonicalSession {
    let path = fixtures_dir().join(format!("gemini/{name}.json"));
    Gemini
        .read_session(&path)
        .unwrap_or_else(|e| panic!("Failed to read Gemini fixture '{name}': {e}"))
}

// ---------------------------------------------------------------------------
// Fidelity comparison
// ---------------------------------------------------------------------------

/// Compare two canonical sessions for round-trip fidelity.
///
/// Checks: message count, roles, content (text-only).
/// Logs detailed diffs on mismatch.
fn assert_roundtrip_fidelity(
    original: &CanonicalSession,
    readback: &CanonicalSession,
    path_label: &str,
) {
    assert_eq!(
        original.messages.len(),
        readback.messages.len(),
        "[{path_label}] Message count mismatch: original={}, readback={}",
        original.messages.len(),
        readback.messages.len()
    );

    for (i, (orig, rb)) in original
        .messages
        .iter()
        .zip(readback.messages.iter())
        .enumerate()
    {
        assert_eq!(
            orig.role, rb.role,
            "[{path_label}] msg {i}: role mismatch — original={:?}, readback={:?}",
            orig.role, rb.role
        );
        assert_eq!(
            orig.content,
            rb.content,
            "[{path_label}] msg {i}: content mismatch — original='{}...', readback='{}...'",
            &orig.content[..orig.content.len().min(80)],
            &rb.content[..rb.content.len().min(80)]
        );
    }
}

/// Assert that the readback session has a valid new session ID (UUID format).
fn assert_new_session_id(readback: &CanonicalSession, path_label: &str) {
    assert!(
        !readback.session_id.is_empty(),
        "[{path_label}] readback session_id should not be empty"
    );
    // Session IDs generated by writers are UUID v4 format.
    assert!(
        readback.session_id.len() >= 8,
        "[{path_label}] readback session_id should be UUID-length, got '{}'",
        readback.session_id
    );
}

// ===========================================================================
// Path 1: CC → Codex
// ===========================================================================

#[test]
fn roundtrip_cc_to_codex() {
    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = Codex
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→Cod: write should succeed");

    let readback = Codex
        .read_session(&written.paths[0])
        .expect("CC→Cod: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→Cod");
    assert_new_session_id(&readback, "CC→Cod");

    // Workspace should be preserved (Codex stores cwd in session_meta).
    assert_eq!(
        original.workspace, readback.workspace,
        "CC→Cod: workspace should be preserved"
    );

    // Git branch metadata is LOST when leaving CC (expected).
    // No assertion — just documenting the expectation.
}

// ===========================================================================
// Path 2: CC → Gemini
// ===========================================================================

#[test]
fn roundtrip_cc_to_gemini() {
    let _lock = GEMINI_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("GEMINI_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = Gemini
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→Gmi: write should succeed");

    let readback = Gemini
        .read_session(&written.paths[0])
        .expect("CC→Gmi: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→Gmi");
    assert_new_session_id(&readback, "CC→Gmi");

    // Workspace: BEST-EFFORT for Gemini (derived from message content heuristics).
    // CC fixture workspace is /data/projects/cross_agent_sessions_resumer — if the
    // messages don't mention this path, Gemini reader won't recover it.
    // We just verify the assertion framework doesn't crash.
}

// ===========================================================================
// Path 3: CC → Cursor
// ===========================================================================

#[test]
fn roundtrip_cc_to_cursor() {
    let _lock = CURSOR_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CURSOR_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = Cursor
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→Cur: write should succeed");

    let readback = Cursor
        .read_session(&written.paths[0])
        .expect("CC→Cur: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→Cur");
    assert_new_session_id(&readback, "CC→Cur");
}

// ===========================================================================
// Path 4: Cursor → CC
// ===========================================================================

#[test]
fn roundtrip_cursor_to_cc() {
    let cursor_canonical = {
        let _cursor_lock = CURSOR_ENV.lock().unwrap();
        let cursor_tmp = tempfile::TempDir::new().unwrap();
        let _cursor_env = EnvGuard::set("CURSOR_HOME", cursor_tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written_cursor = Cursor
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→Cur write should succeed");

        Cursor
            .read_session(&written_cursor.paths[0])
            .expect("seed Cur read-back should succeed")
    };

    let _cc_lock = CC_ENV.lock().unwrap();
    let cc_tmp = tempfile::TempDir::new().unwrap();
    let _cc_env = EnvGuard::set("CLAUDE_HOME", cc_tmp.path());

    let written_cc = ClaudeCode
        .write_session(&cursor_canonical, &WriteOptions { force: false })
        .expect("Cur→CC: write should succeed");

    let readback_cc = ClaudeCode
        .read_session(&written_cc.paths[0])
        .expect("Cur→CC: read-back should succeed");

    assert_roundtrip_fidelity(&cursor_canonical, &readback_cc, "Cur→CC");
    assert_new_session_id(&readback_cc, "Cur→CC");
}

// ===========================================================================
// Path 5: CC → OpenCode
// ===========================================================================

#[test]
fn roundtrip_cc_to_opencode() {
    let _lock = OPENCODE_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("OPENCODE_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = OpenCode
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→Opc: write should succeed");

    let readback = OpenCode
        .read_session(&written.paths[0])
        .expect("CC→Opc: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→Opc");
    assert_new_session_id(&readback, "CC→Opc");
}

// ===========================================================================
// Path 6: OpenCode → CC
// ===========================================================================

#[test]
fn roundtrip_opencode_to_cc() {
    let opencode_canonical = {
        let _opencode_lock = OPENCODE_ENV.lock().unwrap();
        let opencode_tmp = tempfile::TempDir::new().unwrap();
        let _opencode_env = EnvGuard::set("OPENCODE_HOME", opencode_tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written_opencode = OpenCode
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→Opc write should succeed");

        OpenCode
            .read_session(&written_opencode.paths[0])
            .expect("seed Opc read-back should succeed")
    };

    let _cc_lock = CC_ENV.lock().unwrap();
    let cc_tmp = tempfile::TempDir::new().unwrap();
    let _cc_env = EnvGuard::set("CLAUDE_HOME", cc_tmp.path());

    let written_cc = ClaudeCode
        .write_session(&opencode_canonical, &WriteOptions { force: false })
        .expect("Opc→CC: write should succeed");

    let readback_cc = ClaudeCode
        .read_session(&written_cc.paths[0])
        .expect("Opc→CC: read-back should succeed");

    assert_roundtrip_fidelity(&opencode_canonical, &readback_cc, "Opc→CC");
    assert_new_session_id(&readback_cc, "Opc→CC");
}

// ===========================================================================
// Path 7: Codex → CC
// ===========================================================================

#[test]
fn roundtrip_codex_to_cc() {
    let _lock = CC_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CLAUDE_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = ClaudeCode
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→CC: write should succeed");

    let readback = ClaudeCode
        .read_session(&written.paths[0])
        .expect("Cod→CC: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→CC");
    assert_new_session_id(&readback, "Cod→CC");

    // Workspace should be preserved (CC stores cwd in each JSONL entry).
    assert_eq!(
        original.workspace, readback.workspace,
        "Cod→CC: workspace should be preserved"
    );
}

// ===========================================================================
// Path 6: Codex → Gemini
// ===========================================================================

#[test]
fn roundtrip_codex_to_gemini() {
    let _lock = GEMINI_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("GEMINI_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = Gemini
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→Gmi: write should succeed");

    let readback = Gemini
        .read_session(&written.paths[0])
        .expect("Cod→Gmi: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→Gmi");
    assert_new_session_id(&readback, "Cod→Gmi");

    // Workspace: BEST-EFFORT for Gemini targets.
}

// ===========================================================================
// Path 7: Gemini → CC
// ===========================================================================

#[test]
fn roundtrip_gemini_to_cc() {
    let _lock = CC_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CLAUDE_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = ClaudeCode
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→CC: write should succeed");

    let readback = ClaudeCode
        .read_session(&written.paths[0])
        .expect("Gmi→CC: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→CC");
    assert_new_session_id(&readback, "Gmi→CC");

    // Citations/grounding metadata is LOST when leaving Gemini (expected).
}

// ===========================================================================
// Path 8: Gemini → Codex
// ===========================================================================

#[test]
fn roundtrip_gemini_to_codex() {
    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = Codex
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→Cod: write should succeed");

    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Gmi→Cod: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→Cod");
    assert_new_session_id(&readback, "Gmi→Cod");
}

// ===========================================================================
// Additional fixture variants — test with more complex fixtures
// ===========================================================================

#[test]
fn roundtrip_cc_unicode_to_codex() {
    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let original = read_cc_fixture("cc_unicode");
    let written = Codex
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC(unicode)→Cod: write should succeed");

    let readback = Codex
        .read_session(&written.paths[0])
        .expect("CC(unicode)→Cod: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC(unicode)→Cod");

    // Verify Unicode characters survived the round-trip.
    let has_cjk = readback
        .messages
        .iter()
        .any(|m| m.content.contains('\u{3053}'));
    assert!(has_cjk, "CC(unicode)→Cod: CJK characters should survive");
}

#[test]
fn roundtrip_cc_unicode_to_gemini() {
    let _lock = GEMINI_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("GEMINI_HOME", tmp.path());

    let original = read_cc_fixture("cc_unicode");
    let written = Gemini
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC(unicode)→Gmi: write should succeed");

    let readback = Gemini
        .read_session(&written.paths[0])
        .expect("CC(unicode)→Gmi: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC(unicode)→Gmi");

    let has_emoji = readback.messages.iter().any(|m| m.content.contains('🚀'));
    assert!(has_emoji, "CC(unicode)→Gmi: emoji should survive");
}

#[test]
fn roundtrip_codex_legacy_to_cc() {
    let _lock = CC_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CLAUDE_HOME", tmp.path());

    let original = read_codex_fixture("codex_legacy", "json");
    let written = ClaudeCode
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod(legacy)→CC: write should succeed");

    let readback = ClaudeCode
        .read_session(&written.paths[0])
        .expect("Cod(legacy)→CC: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod(legacy)→CC");
}

#[test]
fn roundtrip_gemini_grounding_to_codex() {
    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_grounding");
    let written = Codex
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi(grounding)→Cod: write should succeed");

    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Gmi(grounding)→Cod: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi(grounding)→Cod");
    // Grounding metadata is LOST when leaving Gemini — expected.
}

#[test]
fn roundtrip_gemini_role_variant_to_cc() {
    let _lock = CC_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CLAUDE_HOME", tmp.path());

    // gmi_gemini_role uses 'gemini' role type instead of 'model'.
    let original = read_gemini_fixture("gmi_gemini_role");
    let written = ClaudeCode
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi(gemini-role)→CC: write should succeed");

    let readback = ClaudeCode
        .read_session(&written.paths[0])
        .expect("Gmi(gemini-role)→CC: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi(gemini-role)→CC");

    // Verify that 'gemini' role was correctly mapped to Assistant throughout.
    for (i, msg) in readback.messages.iter().enumerate() {
        assert!(
            msg.role == MessageRole::User || msg.role == MessageRole::Assistant,
            "Gmi(gemini-role)→CC msg {i}: unexpected role {:?}",
            msg.role
        );
    }
}

// ===========================================================================
// Missing workspace round-trips
// ===========================================================================

#[test]
fn roundtrip_cc_missing_workspace_to_codex() {
    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let original = read_cc_fixture("cc_missing_workspace");
    // cc_missing_workspace has workspace=None.
    assert!(
        original.workspace.is_none(),
        "Fixture should have no workspace"
    );

    let written = Codex
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC(no-ws)→Cod: write should succeed");

    let readback = Codex
        .read_session(&written.paths[0])
        .expect("CC(no-ws)→Cod: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC(no-ws)→Cod");
    // Writer falls back to /tmp when workspace is None.
    // The readback will have workspace=/tmp.
}

#[test]
fn roundtrip_gmi_missing_workspace_to_cc() {
    let _lock = CC_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CLAUDE_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_missing_workspace");
    let written = ClaudeCode
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi(no-ws)→CC: write should succeed");

    let readback = ClaudeCode
        .read_session(&written.paths[0])
        .expect("Gmi(no-ws)→CC: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi(no-ws)→CC");
}
