//! Round-trip fidelity tests for core conversion paths plus extended provider paths.
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

mod test_env;

use std::path::{Path, PathBuf};

use casr::model::{CanonicalSession, MessageRole};
use casr::providers::aider::Aider;
use casr::providers::amp::Amp;
use casr::providers::chatgpt::ChatGpt;
use casr::providers::claude_code::ClaudeCode;
use casr::providers::clawdbot::ClawdBot;
use casr::providers::cline::Cline;
use casr::providers::codex::Codex;
use casr::providers::cursor::Cursor;
use casr::providers::factory::Factory;
use casr::providers::gemini::Gemini;
use casr::providers::openclaw::OpenClaw;
use casr::providers::opencode::OpenCode;
use casr::providers::pi_agent::PiAgent;
use casr::providers::vibe::Vibe;
use casr::providers::{Provider, WriteOptions};

// ---------------------------------------------------------------------------
// Env var isolation (see `tests/test_env.rs`)
// ---------------------------------------------------------------------------

static CC_ENV: test_env::EnvLock = test_env::EnvLock;
static CODEX_ENV: test_env::EnvLock = test_env::EnvLock;
static GEMINI_ENV: test_env::EnvLock = test_env::EnvLock;
static CURSOR_ENV: test_env::EnvLock = test_env::EnvLock;
static CLINE_ENV: test_env::EnvLock = test_env::EnvLock;
static AIDER_ENV: test_env::EnvLock = test_env::EnvLock;
static AMP_ENV: test_env::EnvLock = test_env::EnvLock;
static OPENCODE_ENV: test_env::EnvLock = test_env::EnvLock;
static CHATGPT_ENV: test_env::EnvLock = test_env::EnvLock;
static CLAWDBOT_ENV: test_env::EnvLock = test_env::EnvLock;
static VIBE_ENV: test_env::EnvLock = test_env::EnvLock;
static FACTORY_ENV: test_env::EnvLock = test_env::EnvLock;
static OPENCLAW_ENV: test_env::EnvLock = test_env::EnvLock;
static PIAGENT_ENV: test_env::EnvLock = test_env::EnvLock;

struct EnvGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &Path) -> Self {
        let original = std::env::var(key).ok();
        // SAFETY: Tests must hold an `_ENV` lock (see `test_env`) while mutating
        // the process environment and while invoking code that reads it.
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
    // CC fixture workspace is /data/projects/cross_agent_session_resumer — if the
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
// Additional provider paths: Cline and Amp
// ===========================================================================

#[test]
fn roundtrip_cc_to_cline() {
    let _lock = CLINE_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CLINE_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = Cline
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→Cln: write should succeed");

    let readback = Cline
        .read_session(&written.paths[0])
        .expect("CC→Cln: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→Cln");
    assert_new_session_id(&readback, "CC→Cln");
}

#[test]
fn roundtrip_cline_to_cc() {
    let cline_canonical = {
        let _cline_lock = CLINE_ENV.lock().unwrap();
        let cline_tmp = tempfile::TempDir::new().unwrap();
        let _cline_env = EnvGuard::set("CLINE_HOME", cline_tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written_cline = Cline
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→Cln write should succeed");

        Cline
            .read_session(&written_cline.paths[0])
            .expect("seed Cln read-back should succeed")
    };

    let _cc_lock = CC_ENV.lock().unwrap();
    let cc_tmp = tempfile::TempDir::new().unwrap();
    let _cc_env = EnvGuard::set("CLAUDE_HOME", cc_tmp.path());

    let written_cc = ClaudeCode
        .write_session(&cline_canonical, &WriteOptions { force: false })
        .expect("Cln→CC: write should succeed");

    let readback_cc = ClaudeCode
        .read_session(&written_cc.paths[0])
        .expect("Cln→CC: read-back should succeed");

    assert_roundtrip_fidelity(&cline_canonical, &readback_cc, "Cln→CC");
    assert_new_session_id(&readback_cc, "Cln→CC");
}

#[test]
fn roundtrip_cc_to_amp() {
    let _lock = AMP_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("AMP_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = Amp
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→Amp: write should succeed");

    let readback = Amp
        .read_session(&written.paths[0])
        .expect("CC→Amp: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→Amp");
    assert_new_session_id(&readback, "CC→Amp");
}

#[test]
fn roundtrip_amp_to_cc() {
    let amp_canonical = {
        let _amp_lock = AMP_ENV.lock().unwrap();
        let amp_tmp = tempfile::TempDir::new().unwrap();
        let _amp_env = EnvGuard::set("AMP_HOME", amp_tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written_amp = Amp
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→Amp write should succeed");

        Amp.read_session(&written_amp.paths[0])
            .expect("seed Amp read-back should succeed")
    };

    let _cc_lock = CC_ENV.lock().unwrap();
    let cc_tmp = tempfile::TempDir::new().unwrap();
    let _cc_env = EnvGuard::set("CLAUDE_HOME", cc_tmp.path());

    let written_cc = ClaudeCode
        .write_session(&amp_canonical, &WriteOptions { force: false })
        .expect("Amp→CC: write should succeed");

    let readback_cc = ClaudeCode
        .read_session(&written_cc.paths[0])
        .expect("Amp→CC: read-back should succeed");

    assert_roundtrip_fidelity(&amp_canonical, &readback_cc, "Amp→CC");
    assert_new_session_id(&readback_cc, "Amp→CC");
}

#[test]
fn roundtrip_cc_to_aider() {
    let _lock = AIDER_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("AIDER_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = Aider
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→Aid: write should succeed");

    let readback = Aider
        .read_session(&written.paths[0])
        .expect("CC→Aid: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→Aid");
    assert_new_session_id(&readback, "CC→Aid");
}

#[test]
fn roundtrip_aider_to_cc() {
    let aider_canonical = {
        let _aider_lock = AIDER_ENV.lock().unwrap();
        let aider_tmp = tempfile::TempDir::new().unwrap();
        let _aider_env = EnvGuard::set("AIDER_HOME", aider_tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written_aider = Aider
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→Aid write should succeed");

        Aider
            .read_session(&written_aider.paths[0])
            .expect("seed Aid read-back should succeed")
    };

    let _cc_lock = CC_ENV.lock().unwrap();
    let cc_tmp = tempfile::TempDir::new().unwrap();
    let _cc_env = EnvGuard::set("CLAUDE_HOME", cc_tmp.path());

    let written_cc = ClaudeCode
        .write_session(&aider_canonical, &WriteOptions { force: false })
        .expect("Aid→CC: write should succeed");

    let readback_cc = ClaudeCode
        .read_session(&written_cc.paths[0])
        .expect("Aid→CC: read-back should succeed");

    assert_roundtrip_fidelity(&aider_canonical, &readback_cc, "Aid→CC");
    assert_new_session_id(&readback_cc, "Aid→CC");
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

// ===========================================================================
// ChatGPT roundtrips
// ===========================================================================

#[test]
fn roundtrip_cc_to_chatgpt() {
    let _lock = CHATGPT_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CHATGPT_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = ChatGpt
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→ChatGPT: write should succeed");

    let readback = ChatGpt
        .read_session(&written.paths[0])
        .expect("CC→ChatGPT: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→ChatGPT");
    assert_new_session_id(&readback, "CC→ChatGPT");
}

#[test]
fn roundtrip_chatgpt_to_cc() {
    let _lock_gpt = CHATGPT_ENV.lock().unwrap();
    let _lock_cc = CC_ENV.lock().unwrap();
    let tmp_gpt = tempfile::TempDir::new().unwrap();
    let tmp_cc = tempfile::TempDir::new().unwrap();
    let _env_gpt = EnvGuard::set("CHATGPT_HOME", tmp_gpt.path());
    let _env_cc = EnvGuard::set("CLAUDE_HOME", tmp_cc.path());

    // Seed: CC → ChatGPT.
    let original = read_cc_fixture("cc_simple");
    let written = ChatGpt
        .write_session(&original, &WriteOptions { force: false })
        .expect("seed CC→ChatGPT write");

    let gpt_session = ChatGpt
        .read_session(&written.paths[0])
        .expect("read ChatGPT");

    // Target: ChatGPT → CC.
    let cc_written = ClaudeCode
        .write_session(&gpt_session, &WriteOptions { force: false })
        .expect("ChatGPT→CC write");

    let readback = ClaudeCode
        .read_session(&cc_written.paths[0])
        .expect("read CC back");

    assert_roundtrip_fidelity(&original, &readback, "ChatGPT→CC");
}

// ===========================================================================
// ClawdBot roundtrips
// ===========================================================================

#[test]
fn roundtrip_cc_to_clawdbot() {
    let _lock = CLAWDBOT_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CLAWDBOT_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = ClawdBot
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→ClawdBot: write should succeed");

    let readback = ClawdBot
        .read_session(&written.paths[0])
        .expect("CC→ClawdBot: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→ClawdBot");
}

#[test]
fn roundtrip_clawdbot_to_cc() {
    let _lock_cwb = CLAWDBOT_ENV.lock().unwrap();
    let _lock_cc = CC_ENV.lock().unwrap();
    let tmp_cwb = tempfile::TempDir::new().unwrap();
    let tmp_cc = tempfile::TempDir::new().unwrap();
    let _env_cwb = EnvGuard::set("CLAWDBOT_HOME", tmp_cwb.path());
    let _env_cc = EnvGuard::set("CLAUDE_HOME", tmp_cc.path());

    let original = read_cc_fixture("cc_simple");
    let written = ClawdBot
        .write_session(&original, &WriteOptions { force: false })
        .expect("seed CC→ClawdBot write");

    let cwb_session = ClawdBot
        .read_session(&written.paths[0])
        .expect("read ClawdBot");

    let cc_written = ClaudeCode
        .write_session(&cwb_session, &WriteOptions { force: false })
        .expect("ClawdBot→CC write");

    let readback = ClaudeCode
        .read_session(&cc_written.paths[0])
        .expect("read CC back");

    assert_roundtrip_fidelity(&original, &readback, "ClawdBot→CC");
}

// ===========================================================================
// Vibe roundtrips
// ===========================================================================

#[test]
fn roundtrip_cc_to_vibe() {
    let _lock = VIBE_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("VIBE_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = Vibe
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→Vibe: write should succeed");

    let readback = Vibe
        .read_session(&written.paths[0])
        .expect("CC→Vibe: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→Vibe");
}

#[test]
fn roundtrip_vibe_to_cc() {
    let _lock_vib = VIBE_ENV.lock().unwrap();
    let _lock_cc = CC_ENV.lock().unwrap();
    let tmp_vib = tempfile::TempDir::new().unwrap();
    let tmp_cc = tempfile::TempDir::new().unwrap();
    let _env_vib = EnvGuard::set("VIBE_HOME", tmp_vib.path());
    let _env_cc = EnvGuard::set("CLAUDE_HOME", tmp_cc.path());

    let original = read_cc_fixture("cc_simple");
    let written = Vibe
        .write_session(&original, &WriteOptions { force: false })
        .expect("seed CC→Vibe write");

    let vib_session = Vibe.read_session(&written.paths[0]).expect("read Vibe");

    let cc_written = ClaudeCode
        .write_session(&vib_session, &WriteOptions { force: false })
        .expect("Vibe→CC write");

    let readback = ClaudeCode
        .read_session(&cc_written.paths[0])
        .expect("read CC back");

    assert_roundtrip_fidelity(&original, &readback, "Vibe→CC");
}

// ===========================================================================
// Factory roundtrips
// ===========================================================================

#[test]
fn roundtrip_cc_to_factory() {
    let _lock = FACTORY_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("FACTORY_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = Factory
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→Factory: write should succeed");

    let readback = Factory
        .read_session(&written.paths[0])
        .expect("CC→Factory: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→Factory");
}

#[test]
fn roundtrip_factory_to_cc() {
    let _lock_fac = FACTORY_ENV.lock().unwrap();
    let _lock_cc = CC_ENV.lock().unwrap();
    let tmp_fac = tempfile::TempDir::new().unwrap();
    let tmp_cc = tempfile::TempDir::new().unwrap();
    let _env_fac = EnvGuard::set("FACTORY_HOME", tmp_fac.path());
    let _env_cc = EnvGuard::set("CLAUDE_HOME", tmp_cc.path());

    let original = read_cc_fixture("cc_simple");
    let written = Factory
        .write_session(&original, &WriteOptions { force: false })
        .expect("seed CC→Factory write");

    let fac_session = Factory
        .read_session(&written.paths[0])
        .expect("read Factory");

    let cc_written = ClaudeCode
        .write_session(&fac_session, &WriteOptions { force: false })
        .expect("Factory→CC write");

    let readback = ClaudeCode
        .read_session(&cc_written.paths[0])
        .expect("read CC back");

    assert_roundtrip_fidelity(&original, &readback, "Factory→CC");
}

// ===========================================================================
// OpenClaw roundtrips
// ===========================================================================

#[test]
fn roundtrip_cc_to_openclaw() {
    let _lock = OPENCLAW_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("OPENCLAW_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = OpenClaw
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→OpenClaw: write should succeed");

    let readback = OpenClaw
        .read_session(&written.paths[0])
        .expect("CC→OpenClaw: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→OpenClaw");
}

#[test]
fn roundtrip_openclaw_to_cc() {
    let _lock_ocl = OPENCLAW_ENV.lock().unwrap();
    let _lock_cc = CC_ENV.lock().unwrap();
    let tmp_ocl = tempfile::TempDir::new().unwrap();
    let tmp_cc = tempfile::TempDir::new().unwrap();
    let _env_ocl = EnvGuard::set("OPENCLAW_HOME", tmp_ocl.path());
    let _env_cc = EnvGuard::set("CLAUDE_HOME", tmp_cc.path());

    let original = read_cc_fixture("cc_simple");
    let written = OpenClaw
        .write_session(&original, &WriteOptions { force: false })
        .expect("seed CC→OpenClaw write");

    let ocl_session = OpenClaw
        .read_session(&written.paths[0])
        .expect("read OpenClaw");

    let cc_written = ClaudeCode
        .write_session(&ocl_session, &WriteOptions { force: false })
        .expect("OpenClaw→CC write");

    let readback = ClaudeCode
        .read_session(&cc_written.paths[0])
        .expect("read CC back");

    assert_roundtrip_fidelity(&original, &readback, "OpenClaw→CC");
}

// ===========================================================================
// Pi-Agent roundtrips
// ===========================================================================

#[test]
fn roundtrip_cc_to_piagent() {
    let _lock = PIAGENT_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("PI_AGENT_HOME", tmp.path());

    let original = read_cc_fixture("cc_simple");
    let written = PiAgent
        .write_session(&original, &WriteOptions { force: false })
        .expect("CC→PiAgent: write should succeed");

    let readback = PiAgent
        .read_session(&written.paths[0])
        .expect("CC→PiAgent: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "CC→PiAgent");
}

#[test]
fn roundtrip_piagent_to_cc() {
    let _lock_pi = PIAGENT_ENV.lock().unwrap();
    let _lock_cc = CC_ENV.lock().unwrap();
    let tmp_pi = tempfile::TempDir::new().unwrap();
    let tmp_cc = tempfile::TempDir::new().unwrap();
    let _env_pi = EnvGuard::set("PI_AGENT_HOME", tmp_pi.path());
    let _env_cc = EnvGuard::set("CLAUDE_HOME", tmp_cc.path());

    let original = read_cc_fixture("cc_simple");
    let written = PiAgent
        .write_session(&original, &WriteOptions { force: false })
        .expect("seed CC→PiAgent write");

    let pi_session = PiAgent
        .read_session(&written.paths[0])
        .expect("read PiAgent");

    let cc_written = ClaudeCode
        .write_session(&pi_session, &WriteOptions { force: false })
        .expect("PiAgent→CC write");

    let readback = ClaudeCode
        .read_session(&cc_written.paths[0])
        .expect("read CC back");

    assert_roundtrip_fidelity(&original, &readback, "PiAgent→CC");
}

// ===========================================================================
// All providers → Codex roundtrip tests
// ===========================================================================

#[test]
fn roundtrip_cursor_to_codex() {
    let cursor_session = {
        let _lock = CURSOR_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("CURSOR_HOME", tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = Cursor
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→Cursor");
        Cursor.read_session(&written.paths[0]).expect("read Cursor")
    };

    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let written = Codex
        .write_session(&cursor_session, &WriteOptions { force: false })
        .expect("Cursor→Codex write");
    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Codex read-back");

    assert_roundtrip_fidelity(&cursor_session, &readback, "Cursor→Codex");
}

#[test]
fn roundtrip_cline_to_codex() {
    let cline_session = {
        let _lock = CLINE_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("CLINE_HOME", tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = Cline
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→Cline");
        Cline.read_session(&written.paths[0]).expect("read Cline")
    };

    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let written = Codex
        .write_session(&cline_session, &WriteOptions { force: false })
        .expect("Cline→Codex write");
    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Codex read-back");

    assert_roundtrip_fidelity(&cline_session, &readback, "Cline→Codex");
}

#[test]
fn roundtrip_aider_to_codex() {
    let aider_session = {
        let _lock = AIDER_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("AIDER_HOME", tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = Aider
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→Aider");
        Aider.read_session(&written.paths[0]).expect("read Aider")
    };

    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let written = Codex
        .write_session(&aider_session, &WriteOptions { force: false })
        .expect("Aider→Codex write");
    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Codex read-back");

    assert_roundtrip_fidelity(&aider_session, &readback, "Aider→Codex");
}

#[test]
fn roundtrip_amp_to_codex() {
    let amp_session = {
        let _lock = AMP_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("AMP_HOME", tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = Amp
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→Amp");
        Amp.read_session(&written.paths[0]).expect("read Amp")
    };

    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let written = Codex
        .write_session(&amp_session, &WriteOptions { force: false })
        .expect("Amp→Codex write");
    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Codex read-back");

    assert_roundtrip_fidelity(&amp_session, &readback, "Amp→Codex");
}

#[test]
fn roundtrip_opencode_to_codex() {
    let opencode_session = {
        let _lock = OPENCODE_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("OPENCODE_HOME", tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = OpenCode
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→OpenCode");
        OpenCode
            .read_session(&written.paths[0])
            .expect("read OpenCode")
    };

    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let written = Codex
        .write_session(&opencode_session, &WriteOptions { force: false })
        .expect("OpenCode→Codex write");
    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Codex read-back");

    assert_roundtrip_fidelity(&opencode_session, &readback, "OpenCode→Codex");
}

#[test]
fn roundtrip_chatgpt_to_codex() {
    let chatgpt_session = {
        let _lock = CHATGPT_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("CHATGPT_HOME", tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = ChatGpt
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→ChatGPT");
        ChatGpt
            .read_session(&written.paths[0])
            .expect("read ChatGPT")
    };

    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let written = Codex
        .write_session(&chatgpt_session, &WriteOptions { force: false })
        .expect("ChatGPT→Codex write");
    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Codex read-back");

    assert_roundtrip_fidelity(&chatgpt_session, &readback, "ChatGPT→Codex");
}

#[test]
fn roundtrip_clawdbot_to_codex() {
    let clawdbot_session = {
        let _lock = CLAWDBOT_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("CLAWDBOT_HOME", tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = ClawdBot
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→ClawdBot");
        ClawdBot
            .read_session(&written.paths[0])
            .expect("read ClawdBot")
    };

    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let written = Codex
        .write_session(&clawdbot_session, &WriteOptions { force: false })
        .expect("ClawdBot→Codex write");
    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Codex read-back");

    assert_roundtrip_fidelity(&clawdbot_session, &readback, "ClawdBot→Codex");
}

#[test]
fn roundtrip_vibe_to_codex() {
    let vibe_session = {
        let _lock = VIBE_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("VIBE_HOME", tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = Vibe
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→Vibe");
        Vibe.read_session(&written.paths[0]).expect("read Vibe")
    };

    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let written = Codex
        .write_session(&vibe_session, &WriteOptions { force: false })
        .expect("Vibe→Codex write");
    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Codex read-back");

    assert_roundtrip_fidelity(&vibe_session, &readback, "Vibe→Codex");
}

#[test]
fn roundtrip_factory_to_codex() {
    let factory_session = {
        let _lock = FACTORY_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("FACTORY_HOME", tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = Factory
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→Factory");
        Factory
            .read_session(&written.paths[0])
            .expect("read Factory")
    };

    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let written = Codex
        .write_session(&factory_session, &WriteOptions { force: false })
        .expect("Factory→Codex write");
    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Codex read-back");

    assert_roundtrip_fidelity(&factory_session, &readback, "Factory→Codex");
}

#[test]
fn roundtrip_openclaw_to_codex() {
    let openclaw_session = {
        let _lock = OPENCLAW_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("OPENCLAW_HOME", tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = OpenClaw
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→OpenClaw");
        OpenClaw
            .read_session(&written.paths[0])
            .expect("read OpenClaw")
    };

    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let written = Codex
        .write_session(&openclaw_session, &WriteOptions { force: false })
        .expect("OpenClaw→Codex write");
    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Codex read-back");

    assert_roundtrip_fidelity(&openclaw_session, &readback, "OpenClaw→Codex");
}

#[test]
fn roundtrip_piagent_to_codex() {
    let piagent_session = {
        let _lock = PIAGENT_ENV.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set("PI_AGENT_HOME", tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = PiAgent
            .write_session(&seed, &WriteOptions { force: false })
            .expect("seed CC→PiAgent");
        PiAgent
            .read_session(&written.paths[0])
            .expect("read PiAgent")
    };

    let _lock = CODEX_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CODEX_HOME", tmp.path());

    let written = Codex
        .write_session(&piagent_session, &WriteOptions { force: false })
        .expect("PiAgent→Codex write");
    let readback = Codex
        .read_session(&written.paths[0])
        .expect("Codex read-back");

    assert_roundtrip_fidelity(&piagent_session, &readback, "PiAgent→Codex");
}

// ===========================================================================
// Codex → all non-CC targets (11 pairs)
// ===========================================================================

#[test]
fn roundtrip_codex_to_cursor() {
    let _lock = CURSOR_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CURSOR_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = Cursor
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→Cursor: write should succeed");

    let readback = Cursor
        .read_session(&written.paths[0])
        .expect("Cod→Cursor: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→Cursor");
    assert_new_session_id(&readback, "Cod→Cursor");
}

#[test]
fn roundtrip_codex_to_cline() {
    let _lock = CLINE_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CLINE_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = Cline
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→Cline: write should succeed");

    let readback = Cline
        .read_session(&written.paths[0])
        .expect("Cod→Cline: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→Cline");
    assert_new_session_id(&readback, "Cod→Cline");
}

#[test]
fn roundtrip_codex_to_aider() {
    let _lock = AIDER_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("AIDER_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = Aider
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→Aider: write should succeed");

    let readback = Aider
        .read_session(&written.paths[0])
        .expect("Cod→Aider: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→Aider");
    assert_new_session_id(&readback, "Cod→Aider");
}

#[test]
fn roundtrip_codex_to_amp() {
    let _lock = AMP_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("AMP_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = Amp
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→Amp: write should succeed");

    let readback = Amp
        .read_session(&written.paths[0])
        .expect("Cod→Amp: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→Amp");
    assert_new_session_id(&readback, "Cod→Amp");
}

#[test]
fn roundtrip_codex_to_opencode() {
    let _lock = OPENCODE_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("OPENCODE_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = OpenCode
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→OpenCode: write should succeed");

    let readback = OpenCode
        .read_session(&written.paths[0])
        .expect("Cod→OpenCode: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→OpenCode");
    assert_new_session_id(&readback, "Cod→OpenCode");
}

#[test]
fn roundtrip_codex_to_chatgpt() {
    let _lock = CHATGPT_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CHATGPT_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = ChatGpt
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→ChatGPT: write should succeed");

    let readback = ChatGpt
        .read_session(&written.paths[0])
        .expect("Cod→ChatGPT: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→ChatGPT");
    assert_new_session_id(&readback, "Cod→ChatGPT");
}

#[test]
fn roundtrip_codex_to_clawdbot() {
    let _lock = CLAWDBOT_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CLAWDBOT_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = ClawdBot
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→ClawdBot: write should succeed");

    let readback = ClawdBot
        .read_session(&written.paths[0])
        .expect("Cod→ClawdBot: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→ClawdBot");
    assert_new_session_id(&readback, "Cod→ClawdBot");
}

#[test]
fn roundtrip_codex_to_vibe() {
    let _lock = VIBE_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("VIBE_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = Vibe
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→Vibe: write should succeed");

    let readback = Vibe
        .read_session(&written.paths[0])
        .expect("Cod→Vibe: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→Vibe");
    assert_new_session_id(&readback, "Cod→Vibe");
}

#[test]
fn roundtrip_codex_to_factory() {
    let _lock = FACTORY_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("FACTORY_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = Factory
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→Factory: write should succeed");

    let readback = Factory
        .read_session(&written.paths[0])
        .expect("Cod→Factory: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→Factory");
    assert_new_session_id(&readback, "Cod→Factory");
}

#[test]
fn roundtrip_codex_to_openclaw() {
    let _lock = OPENCLAW_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("OPENCLAW_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = OpenClaw
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→OpenClaw: write should succeed");

    let readback = OpenClaw
        .read_session(&written.paths[0])
        .expect("Cod→OpenClaw: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→OpenClaw");
    assert_new_session_id(&readback, "Cod→OpenClaw");
}

#[test]
fn roundtrip_codex_to_piagent() {
    let _lock = PIAGENT_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("PI_AGENT_HOME", tmp.path());

    let original = read_codex_fixture("codex_modern", "jsonl");
    let written = PiAgent
        .write_session(&original, &WriteOptions { force: false })
        .expect("Cod→PiAgent: write should succeed");

    let readback = PiAgent
        .read_session(&written.paths[0])
        .expect("Cod→PiAgent: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Cod→PiAgent");
    assert_new_session_id(&readback, "Cod→PiAgent");
}

// ===========================================================================
// Gemini → all non-CC/Codex targets (11 pairs)
// ===========================================================================

#[test]
fn roundtrip_gemini_to_cursor() {
    let _lock = CURSOR_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CURSOR_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = Cursor
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→Cursor: write should succeed");

    let readback = Cursor
        .read_session(&written.paths[0])
        .expect("Gmi→Cursor: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→Cursor");
    assert_new_session_id(&readback, "Gmi→Cursor");
}

#[test]
fn roundtrip_gemini_to_cline() {
    let _lock = CLINE_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CLINE_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = Cline
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→Cline: write should succeed");

    let readback = Cline
        .read_session(&written.paths[0])
        .expect("Gmi→Cline: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→Cline");
    assert_new_session_id(&readback, "Gmi→Cline");
}

#[test]
fn roundtrip_gemini_to_aider() {
    let _lock = AIDER_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("AIDER_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = Aider
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→Aider: write should succeed");

    let readback = Aider
        .read_session(&written.paths[0])
        .expect("Gmi→Aider: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→Aider");
    assert_new_session_id(&readback, "Gmi→Aider");
}

#[test]
fn roundtrip_gemini_to_amp() {
    let _lock = AMP_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("AMP_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = Amp
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→Amp: write should succeed");

    let readback = Amp
        .read_session(&written.paths[0])
        .expect("Gmi→Amp: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→Amp");
    assert_new_session_id(&readback, "Gmi→Amp");
}

#[test]
fn roundtrip_gemini_to_opencode() {
    let _lock = OPENCODE_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("OPENCODE_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = OpenCode
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→OpenCode: write should succeed");

    let readback = OpenCode
        .read_session(&written.paths[0])
        .expect("Gmi→OpenCode: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→OpenCode");
    assert_new_session_id(&readback, "Gmi→OpenCode");
}

#[test]
fn roundtrip_gemini_to_chatgpt() {
    let _lock = CHATGPT_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CHATGPT_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = ChatGpt
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→ChatGPT: write should succeed");

    let readback = ChatGpt
        .read_session(&written.paths[0])
        .expect("Gmi→ChatGPT: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→ChatGPT");
    assert_new_session_id(&readback, "Gmi→ChatGPT");
}

#[test]
fn roundtrip_gemini_to_clawdbot() {
    let _lock = CLAWDBOT_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("CLAWDBOT_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = ClawdBot
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→ClawdBot: write should succeed");

    let readback = ClawdBot
        .read_session(&written.paths[0])
        .expect("Gmi→ClawdBot: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→ClawdBot");
    assert_new_session_id(&readback, "Gmi→ClawdBot");
}

#[test]
fn roundtrip_gemini_to_vibe() {
    let _lock = VIBE_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("VIBE_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = Vibe
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→Vibe: write should succeed");

    let readback = Vibe
        .read_session(&written.paths[0])
        .expect("Gmi→Vibe: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→Vibe");
    assert_new_session_id(&readback, "Gmi→Vibe");
}

#[test]
fn roundtrip_gemini_to_factory() {
    let _lock = FACTORY_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("FACTORY_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = Factory
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→Factory: write should succeed");

    let readback = Factory
        .read_session(&written.paths[0])
        .expect("Gmi→Factory: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→Factory");
    assert_new_session_id(&readback, "Gmi→Factory");
}

#[test]
fn roundtrip_gemini_to_openclaw() {
    let _lock = OPENCLAW_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("OPENCLAW_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = OpenClaw
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→OpenClaw: write should succeed");

    let readback = OpenClaw
        .read_session(&written.paths[0])
        .expect("Gmi→OpenClaw: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→OpenClaw");
    assert_new_session_id(&readback, "Gmi→OpenClaw");
}

#[test]
fn roundtrip_gemini_to_piagent() {
    let _lock = PIAGENT_ENV.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set("PI_AGENT_HOME", tmp.path());

    let original = read_gemini_fixture("gmi_simple");
    let written = PiAgent
        .write_session(&original, &WriteOptions { force: false })
        .expect("Gmi→PiAgent: write should succeed");

    let readback = PiAgent
        .read_session(&written.paths[0])
        .expect("Gmi→PiAgent: read-back should succeed");

    assert_roundtrip_fidelity(&original, &readback, "Gmi→PiAgent");
    assert_new_session_id(&readback, "Gmi→PiAgent");
}

// ===========================================================================
// Cross-provider pairs (representative selection among non-CC/Codex/Gemini)
// ===========================================================================

/// Helper: create a canonical session via CC→Source→read-back, then test Source→Target roundtrip.
fn cross_provider_roundtrip(
    source: &dyn Provider,
    source_env_key: &'static str,
    source_lock: &'static test_env::EnvLock,
    target: &dyn Provider,
    target_env_key: &'static str,
    target_lock: &'static test_env::EnvLock,
    label: &str,
) {
    // Step 1: Create source session (seed from CC fixture → write to source → read back).
    let source_session = {
        let _lock = source_lock.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = EnvGuard::set(source_env_key, tmp.path());

        let seed = read_cc_fixture("cc_simple");
        let written = source
            .write_session(&seed, &WriteOptions { force: false })
            .unwrap_or_else(|e| panic!("[{label}] seed write failed: {e}"));
        source
            .read_session(&written.paths[0])
            .unwrap_or_else(|e| panic!("[{label}] seed read-back failed: {e}"))
    };

    // Step 2: Write source session to target, read back, compare.
    let _lock = target_lock.lock().unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let _env = EnvGuard::set(target_env_key, tmp.path());

    let written = target
        .write_session(&source_session, &WriteOptions { force: false })
        .unwrap_or_else(|e| panic!("[{label}] target write failed: {e}"));
    let readback = target
        .read_session(&written.paths[0])
        .unwrap_or_else(|e| panic!("[{label}] target read-back failed: {e}"));

    assert_roundtrip_fidelity(&source_session, &readback, label);
    assert_new_session_id(&readback, label);
}

#[test]
fn roundtrip_cursor_to_cline() {
    cross_provider_roundtrip(
        &Cursor,
        "CURSOR_HOME",
        &CURSOR_ENV,
        &Cline,
        "CLINE_HOME",
        &CLINE_ENV,
        "Cursor→Cline",
    );
}

#[test]
fn roundtrip_cline_to_aider() {
    cross_provider_roundtrip(
        &Cline,
        "CLINE_HOME",
        &CLINE_ENV,
        &Aider,
        "AIDER_HOME",
        &AIDER_ENV,
        "Cline→Aider",
    );
}

#[test]
fn roundtrip_aider_to_amp() {
    cross_provider_roundtrip(
        &Aider,
        "AIDER_HOME",
        &AIDER_ENV,
        &Amp,
        "AMP_HOME",
        &AMP_ENV,
        "Aider→Amp",
    );
}

#[test]
fn roundtrip_amp_to_opencode() {
    cross_provider_roundtrip(
        &Amp,
        "AMP_HOME",
        &AMP_ENV,
        &OpenCode,
        "OPENCODE_HOME",
        &OPENCODE_ENV,
        "Amp→OpenCode",
    );
}

#[test]
fn roundtrip_opencode_to_chatgpt() {
    cross_provider_roundtrip(
        &OpenCode,
        "OPENCODE_HOME",
        &OPENCODE_ENV,
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        "OpenCode→ChatGPT",
    );
}

#[test]
fn roundtrip_chatgpt_to_clawdbot() {
    cross_provider_roundtrip(
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        &ClawdBot,
        "CLAWDBOT_HOME",
        &CLAWDBOT_ENV,
        "ChatGPT→ClawdBot",
    );
}

#[test]
fn roundtrip_clawdbot_to_vibe() {
    cross_provider_roundtrip(
        &ClawdBot,
        "CLAWDBOT_HOME",
        &CLAWDBOT_ENV,
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        "ClawdBot→Vibe",
    );
}

#[test]
fn roundtrip_vibe_to_factory() {
    cross_provider_roundtrip(
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        "Vibe→Factory",
    );
}

#[test]
fn roundtrip_factory_to_openclaw() {
    cross_provider_roundtrip(
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        "Factory→OpenClaw",
    );
}

#[test]
fn roundtrip_openclaw_to_piagent() {
    cross_provider_roundtrip(
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        &PiAgent,
        "PI_AGENT_HOME",
        &PIAGENT_ENV,
        "OpenClaw→PiAgent",
    );
}

#[test]
fn roundtrip_piagent_to_cursor() {
    cross_provider_roundtrip(
        &PiAgent,
        "PI_AGENT_HOME",
        &PIAGENT_ENV,
        &Cursor,
        "CURSOR_HOME",
        &CURSOR_ENV,
        "PiAgent→Cursor",
    );
}

// ===========================================================================
// Additional cross-provider pairs (diagonal coverage)
// ===========================================================================

#[test]
fn roundtrip_cursor_to_chatgpt() {
    cross_provider_roundtrip(
        &Cursor,
        "CURSOR_HOME",
        &CURSOR_ENV,
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        "Cursor→ChatGPT",
    );
}

#[test]
fn roundtrip_aider_to_factory() {
    cross_provider_roundtrip(
        &Aider,
        "AIDER_HOME",
        &AIDER_ENV,
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        "Aider→Factory",
    );
}

#[test]
fn roundtrip_amp_to_vibe() {
    cross_provider_roundtrip(
        &Amp,
        "AMP_HOME",
        &AMP_ENV,
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        "Amp→Vibe",
    );
}

#[test]
fn roundtrip_opencode_to_openclaw() {
    cross_provider_roundtrip(
        &OpenCode,
        "OPENCODE_HOME",
        &OPENCODE_ENV,
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        "OpenCode→OpenClaw",
    );
}

#[test]
fn roundtrip_chatgpt_to_piagent() {
    cross_provider_roundtrip(
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        &PiAgent,
        "PI_AGENT_HOME",
        &PIAGENT_ENV,
        "ChatGPT→PiAgent",
    );
}

#[test]
fn roundtrip_clawdbot_to_cline() {
    cross_provider_roundtrip(
        &ClawdBot,
        "CLAWDBOT_HOME",
        &CLAWDBOT_ENV,
        &Cline,
        "CLINE_HOME",
        &CLINE_ENV,
        "ClawdBot→Cline",
    );
}

#[test]
fn roundtrip_vibe_to_aider() {
    cross_provider_roundtrip(
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        &Aider,
        "AIDER_HOME",
        &AIDER_ENV,
        "Vibe→Aider",
    );
}

#[test]
fn roundtrip_factory_to_amp() {
    cross_provider_roundtrip(
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        &Amp,
        "AMP_HOME",
        &AMP_ENV,
        "Factory→Amp",
    );
}

#[test]
fn roundtrip_openclaw_to_opencode() {
    cross_provider_roundtrip(
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        &OpenCode,
        "OPENCODE_HOME",
        &OPENCODE_ENV,
        "OpenClaw→OpenCode",
    );
}

#[test]
fn roundtrip_piagent_to_clawdbot() {
    cross_provider_roundtrip(
        &PiAgent,
        "PI_AGENT_HOME",
        &PIAGENT_ENV,
        &ClawdBot,
        "CLAWDBOT_HOME",
        &CLAWDBOT_ENV,
        "PiAgent→ClawdBot",
    );
}

// ===========================================================================
// Newer-6 full pairwise matrix (bd-1bh.39)
// ChatGPT, ClawdBot, Vibe, Factory, OpenClaw, PiAgent — all 30 directed pairs.
// Tests above already cover 7: ChatGPT→ClawdBot, ChatGPT→PiAgent,
// ClawdBot→Vibe, Vibe→Factory, Factory→OpenClaw, OpenClaw→PiAgent,
// PiAgent→ClawdBot. Remaining 23 pairs below.
// ===========================================================================

#[test]
fn roundtrip_chatgpt_to_vibe() {
    cross_provider_roundtrip(
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        "ChatGPT→Vibe",
    );
}

#[test]
fn roundtrip_chatgpt_to_factory() {
    cross_provider_roundtrip(
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        "ChatGPT→Factory",
    );
}

#[test]
fn roundtrip_chatgpt_to_openclaw() {
    cross_provider_roundtrip(
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        "ChatGPT→OpenClaw",
    );
}

#[test]
fn roundtrip_clawdbot_to_chatgpt() {
    cross_provider_roundtrip(
        &ClawdBot,
        "CLAWDBOT_HOME",
        &CLAWDBOT_ENV,
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        "ClawdBot→ChatGPT",
    );
}

#[test]
fn roundtrip_clawdbot_to_factory() {
    cross_provider_roundtrip(
        &ClawdBot,
        "CLAWDBOT_HOME",
        &CLAWDBOT_ENV,
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        "ClawdBot→Factory",
    );
}

#[test]
fn roundtrip_clawdbot_to_openclaw() {
    cross_provider_roundtrip(
        &ClawdBot,
        "CLAWDBOT_HOME",
        &CLAWDBOT_ENV,
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        "ClawdBot→OpenClaw",
    );
}

#[test]
fn roundtrip_clawdbot_to_piagent() {
    cross_provider_roundtrip(
        &ClawdBot,
        "CLAWDBOT_HOME",
        &CLAWDBOT_ENV,
        &PiAgent,
        "PI_AGENT_HOME",
        &PIAGENT_ENV,
        "ClawdBot→PiAgent",
    );
}

#[test]
fn roundtrip_vibe_to_chatgpt() {
    cross_provider_roundtrip(
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        "Vibe→ChatGPT",
    );
}

#[test]
fn roundtrip_vibe_to_clawdbot() {
    cross_provider_roundtrip(
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        &ClawdBot,
        "CLAWDBOT_HOME",
        &CLAWDBOT_ENV,
        "Vibe→ClawdBot",
    );
}

#[test]
fn roundtrip_vibe_to_openclaw() {
    cross_provider_roundtrip(
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        "Vibe→OpenClaw",
    );
}

#[test]
fn roundtrip_vibe_to_piagent() {
    cross_provider_roundtrip(
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        &PiAgent,
        "PI_AGENT_HOME",
        &PIAGENT_ENV,
        "Vibe→PiAgent",
    );
}

#[test]
fn roundtrip_factory_to_chatgpt() {
    cross_provider_roundtrip(
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        "Factory→ChatGPT",
    );
}

#[test]
fn roundtrip_factory_to_clawdbot() {
    cross_provider_roundtrip(
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        &ClawdBot,
        "CLAWDBOT_HOME",
        &CLAWDBOT_ENV,
        "Factory→ClawdBot",
    );
}

#[test]
fn roundtrip_factory_to_vibe() {
    cross_provider_roundtrip(
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        "Factory→Vibe",
    );
}

#[test]
fn roundtrip_factory_to_piagent() {
    cross_provider_roundtrip(
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        &PiAgent,
        "PI_AGENT_HOME",
        &PIAGENT_ENV,
        "Factory→PiAgent",
    );
}

#[test]
fn roundtrip_openclaw_to_chatgpt() {
    cross_provider_roundtrip(
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        "OpenClaw→ChatGPT",
    );
}

#[test]
fn roundtrip_openclaw_to_clawdbot() {
    cross_provider_roundtrip(
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        &ClawdBot,
        "CLAWDBOT_HOME",
        &CLAWDBOT_ENV,
        "OpenClaw→ClawdBot",
    );
}

#[test]
fn roundtrip_openclaw_to_vibe() {
    cross_provider_roundtrip(
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        "OpenClaw→Vibe",
    );
}

#[test]
fn roundtrip_openclaw_to_factory() {
    cross_provider_roundtrip(
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        "OpenClaw→Factory",
    );
}

#[test]
fn roundtrip_piagent_to_chatgpt() {
    cross_provider_roundtrip(
        &PiAgent,
        "PI_AGENT_HOME",
        &PIAGENT_ENV,
        &ChatGpt,
        "CHATGPT_HOME",
        &CHATGPT_ENV,
        "PiAgent→ChatGPT",
    );
}

#[test]
fn roundtrip_piagent_to_vibe() {
    cross_provider_roundtrip(
        &PiAgent,
        "PI_AGENT_HOME",
        &PIAGENT_ENV,
        &Vibe,
        "VIBE_HOME",
        &VIBE_ENV,
        "PiAgent→Vibe",
    );
}

#[test]
fn roundtrip_piagent_to_factory() {
    cross_provider_roundtrip(
        &PiAgent,
        "PI_AGENT_HOME",
        &PIAGENT_ENV,
        &Factory,
        "FACTORY_HOME",
        &FACTORY_ENV,
        "PiAgent→Factory",
    );
}

#[test]
fn roundtrip_piagent_to_openclaw() {
    cross_provider_roundtrip(
        &PiAgent,
        "PI_AGENT_HOME",
        &PIAGENT_ENV,
        &OpenClaw,
        "OPENCLAW_HOME",
        &OPENCLAW_ENV,
        "PiAgent→OpenClaw",
    );
}
