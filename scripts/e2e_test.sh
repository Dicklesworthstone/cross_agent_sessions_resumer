#!/usr/bin/env bash
# scripts/e2e_test.sh — End-to-end test script for casr CLI.
#
# Exercises the full conversion matrix, error cases, flags, and JSON output.
# Uses temp directories with env overrides so real provider data is never touched.
#
# Usage: bash scripts/e2e_test.sh
# Optional: VERBOSE=1 bash scripts/e2e_test.sh  (show all output)
#           CASR_BIN=/path/to/casr bash scripts/e2e_test.sh  (custom binary)
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="$PROJECT_ROOT/tests/fixtures"
CARGO_TARGET="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
CASR="${CASR_BIN:-$CARGO_TARGET/debug/casr}"
VERBOSE="${VERBOSE:-0}"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
START_TIME=$(date +%s)

# Colors (disabled if NO_COLOR is set).
if [[ -z "${NO_COLOR:-}" ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN='' RED='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

# ---------------------------------------------------------------------------
# Temp directory + cleanup
# ---------------------------------------------------------------------------

TMPDIR_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/casr-e2e-XXXXXX")
trap 'rm -rf "$TMPDIR_ROOT"' EXIT

export CLAUDE_HOME="$TMPDIR_ROOT/claude"
export CODEX_HOME="$TMPDIR_ROOT/codex"
export GEMINI_HOME="$TMPDIR_ROOT/gemini"
export CURSOR_HOME="$TMPDIR_ROOT/cursor"
export CLINE_HOME="$TMPDIR_ROOT/cline"
export AIDER_HOME="$TMPDIR_ROOT/aider"
export AMP_HOME="$TMPDIR_ROOT/amp"
export OPENCODE_HOME="$TMPDIR_ROOT/opencode"
export NO_COLOR=1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { echo -e "${CYAN}${BOLD}=== $1 ===${RESET}"; }
pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo -e "  ${GREEN}PASS${RESET}: $1"; }
fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "  ${RED}FAIL${RESET}: $1"
    if [[ -n "${2:-}" ]]; then
        echo -e "    Expected: $2"
    fi
    if [[ -n "${3:-}" ]]; then
        echo -e "    Actual:   $3"
    fi
}
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); echo -e "  ${YELLOW}SKIP${RESET}: $1"; }

run_casr() {
    local desc="$1"; shift
    local stdout_file="$TMPDIR_ROOT/stdout.tmp"
    local stderr_file="$TMPDIR_ROOT/stderr.tmp"
    local cmd_str="$CASR $*"

    [[ "$VERBOSE" == "1" ]] && echo -e "  ${CYAN}CMD${RESET}: $cmd_str"

    local exit_code=0
    "$CASR" "$@" > "$stdout_file" 2> "$stderr_file" || exit_code=$?

    if [[ "$VERBOSE" == "1" ]] || [[ $exit_code -ne 0 && "${EXPECT_FAIL:-0}" != "1" ]]; then
        [[ -s "$stdout_file" ]] && echo "  stdout: $(head -5 "$stdout_file")"
        [[ -s "$stderr_file" ]] && echo "  stderr: $(head -5 "$stderr_file")"
    fi

    LAST_EXIT=$exit_code
    LAST_STDOUT=$(cat "$stdout_file")
    LAST_STDERR=$(cat "$stderr_file")
}

assert_exit_ok() {
    if [[ "$LAST_EXIT" -eq 0 ]]; then
        pass "$1"
    else
        fail "$1" "exit 0" "exit $LAST_EXIT"
        echo "    stderr: $(echo "$LAST_STDERR" | head -3)"
    fi
}

assert_exit_fail() {
    if [[ "$LAST_EXIT" -ne 0 ]]; then
        pass "$1"
    else
        fail "$1" "non-zero exit" "exit 0"
    fi
}

assert_stdout_contains() {
    if echo "$LAST_STDOUT" | grep -q "$2"; then
        pass "$1"
    else
        fail "$1" "stdout contains '$2'" "$(echo "$LAST_STDOUT" | head -3)"
    fi
}

assert_stderr_contains() {
    if echo "$LAST_STDERR" | grep -q "$2"; then
        pass "$1"
    else
        fail "$1" "stderr contains '$2'" "$(echo "$LAST_STDERR" | head -3)"
    fi
}

assert_valid_json() {
    if echo "$LAST_STDOUT" | jq . > /dev/null 2>&1; then
        pass "$1"
    else
        fail "$1" "valid JSON stdout" "$(echo "$LAST_STDOUT" | head -3)"
    fi
}

assert_file_exists() {
    if [[ -f "$2" ]]; then
        pass "$1"
    else
        fail "$1" "file exists: $2" "file not found"
    fi
}

assert_file_count() {
    local dir="$2"
    local expected="$3"
    local actual
    if [[ -d "$dir" ]]; then
        actual=$(find "$dir" -type f | wc -l)
    else
        actual=0
    fi
    if [[ "$actual" -eq "$expected" ]]; then
        pass "$1"
    else
        fail "$1" "$expected files in $dir" "$actual files"
    fi
}

# ---------------------------------------------------------------------------
# Fixture setup
# ---------------------------------------------------------------------------

setup_cc_fixture() {
    local fixture_name="$1"
    local src="$FIXTURES_DIR/claude_code/${fixture_name}.jsonl"
    local session_id cwd project_key

    session_id=$(head -1 "$src" | jq -r '.sessionId // "unknown"')
    cwd=$(head -1 "$src" | jq -r '.cwd // "/tmp"')
    project_key=$(echo "$cwd" | sed 's/[^a-zA-Z0-9]/-/g')

    local target_dir="$CLAUDE_HOME/projects/$project_key"
    mkdir -p "$target_dir"
    cp "$src" "$target_dir/${session_id}.jsonl"
    echo "$session_id"
}

setup_codex_fixture() {
    local fixture_name="$1"
    local ext="${2:-jsonl}"
    local src="$FIXTURES_DIR/codex/${fixture_name}.${ext}"
    local session_id

    if [[ "$ext" == "jsonl" ]]; then
        session_id=$(grep '"session_meta"' "$src" | jq -r '.payload.id // "unknown"')
    else
        session_id=$(jq -r '.session.id // "unknown"' "$src")
    fi

    local target_dir="$CODEX_HOME/sessions/2026/01/01"
    mkdir -p "$target_dir"
    cp "$src" "$target_dir/rollout-2026-01-01T00-00-00-${session_id}.${ext}"
    echo "$session_id"
}

setup_gemini_fixture() {
    local fixture_name="$1"
    local src="$FIXTURES_DIR/gemini/${fixture_name}.json"
    local session_id

    session_id=$(jq -r '.sessionId // "unknown"' "$src")

    local target_dir="$GEMINI_HOME/tmp/testhash000/chats"
    mkdir -p "$target_dir"
    cp "$src" "$target_dir/session-${session_id}.json"
    echo "$session_id"
}

reset_env() {
    rm -rf "$CLAUDE_HOME" "$CODEX_HOME" "$GEMINI_HOME" "$CURSOR_HOME" \
        "$CLINE_HOME" "$AIDER_HOME" "$AMP_HOME" "$OPENCODE_HOME"
}

# ---------------------------------------------------------------------------
# Ensure binary exists
# ---------------------------------------------------------------------------

if [[ ! -x "$CASR" ]]; then
    echo "Building casr..."
    (cd "$PROJECT_ROOT" && cargo build --quiet 2>&1)
fi

if [[ ! -x "$CASR" ]]; then
    echo "ERROR: casr binary not found at $CASR"
    echo "Run 'cargo build' first or set CASR_BIN."
    exit 1
fi

echo -e "${BOLD}casr e2e test suite${RESET}"
echo "Binary: $CASR"
echo "Fixtures: $FIXTURES_DIR"
echo "Temp: $TMPDIR_ROOT"
echo ""

# ===========================================================================
# TEST: Basic CLI
# ===========================================================================

log "TEST: Version output"
run_casr "version" --version
assert_exit_ok "casr --version succeeds"
assert_stdout_contains "version contains casr" "casr"

log "TEST: Help output"
run_casr "help" --help
assert_exit_ok "casr --help succeeds"
assert_stdout_contains "help mentions resume" "resume"
assert_stdout_contains "help mentions list" "list"

log "TEST: No args shows error"
EXPECT_FAIL=1 run_casr "no args" || true
assert_exit_fail "casr with no args fails"

# ===========================================================================
# TEST: Providers command
# ===========================================================================

log "TEST: Providers command"
reset_env
run_casr "providers" providers
assert_exit_ok "casr providers succeeds"
assert_stdout_contains "providers lists Claude Code" "Claude Code"
assert_stdout_contains "providers lists Codex" "Codex"
assert_stdout_contains "providers lists Gemini" "Gemini"
assert_stdout_contains "providers lists Cursor" "Cursor"
assert_stdout_contains "providers lists Cline" "Cline"
assert_stdout_contains "providers lists Aider" "Aider"
assert_stdout_contains "providers lists Amp" "Amp"
assert_stdout_contains "providers lists OpenCode" "OpenCode"

log "TEST: Providers --json"
run_casr "providers json" --json providers
assert_exit_ok "casr --json providers succeeds"
assert_valid_json "providers JSON is valid"

# ===========================================================================
# TEST: List command
# ===========================================================================

log "TEST: List with no sessions"
reset_env
run_casr "list empty" list
assert_exit_ok "casr list succeeds when empty"
assert_stdout_contains "list shows no sessions" "No sessions found"

log "TEST: List with CC session"
reset_env
cc_sid=$(setup_cc_fixture "cc_simple")
run_casr "list cc" list
assert_exit_ok "casr list with CC session succeeds"
assert_stdout_contains "list shows CC session" "$cc_sid"

log "TEST: List --json"
run_casr "list json" --json list
assert_exit_ok "casr --json list succeeds"
assert_valid_json "list JSON is valid"

log "TEST: List --limit"
setup_cc_fixture "cc_malformed" > /dev/null
run_casr "list limit" --json list --limit 1
assert_exit_ok "casr list --limit 1 succeeds"
local_count=$(echo "$LAST_STDOUT" | jq 'length')
if [[ "$local_count" -eq 1 ]]; then
    pass "list --limit 1 returns 1 session"
else
    fail "list --limit 1 returns 1 session" "1" "$local_count"
fi

# ===========================================================================
# TEST: Info command
# ===========================================================================

log "TEST: Info command"
reset_env
cc_sid=$(setup_cc_fixture "cc_simple")
run_casr "info" info "$cc_sid"
assert_exit_ok "casr info succeeds"
assert_stdout_contains "info shows session ID" "$cc_sid"
assert_stdout_contains "info shows provider" "claude-code"
assert_stdout_contains "info shows message count" "Messages:"

log "TEST: Info --json"
run_casr "info json" --json info "$cc_sid"
assert_exit_ok "casr --json info succeeds"
assert_valid_json "info JSON is valid"

log "TEST: Info unknown session"
EXPECT_FAIL=1 run_casr "info bad" info "nonexistent-id" || true
assert_exit_fail "casr info with bad ID fails"

log "TEST: Info unknown session --json"
EXPECT_FAIL=1 run_casr "info bad json" --json info "nonexistent-id" || true
assert_exit_fail "casr --json info with bad ID fails"
if echo "$LAST_STDERR" | jq -e '.error_type' > /dev/null 2>&1; then
    pass "JSON error has error_type field"
else
    fail "JSON error has error_type field" "error_type present" "$(echo "$LAST_STDERR" | head -1)"
fi

# ===========================================================================
# TEST: Resume — CC → Codex
# ===========================================================================

log "TEST: Resume CC → Codex (dry-run)"
reset_env
cc_sid=$(setup_cc_fixture "cc_simple")
run_casr "resume dry" resume cod "$cc_sid" --dry-run
assert_exit_ok "CC→Codex dry-run succeeds"
assert_stdout_contains "dry-run mentions 'Would convert'" "Would convert"
assert_file_count "dry-run writes no codex files" "$CODEX_HOME/sessions" 0

log "TEST: Resume CC → Codex (write)"
run_casr "resume write" resume cod "$cc_sid"
assert_exit_ok "CC→Codex write succeeds"
assert_stdout_contains "resume shows Converted" "Converted"
assert_stdout_contains "resume shows resume command" "Resume:"

# Check that exactly one codex session file was created.
codex_files=$(find "$CODEX_HOME/sessions" -type f -name '*.jsonl' 2>/dev/null | wc -l)
if [[ "$codex_files" -eq 1 ]]; then
    pass "Exactly one Codex session file created"
else
    fail "Exactly one Codex session file created" "1" "$codex_files"
fi

log "TEST: Resume CC → Codex --json"
reset_env
cc_sid=$(setup_cc_fixture "cc_simple")
run_casr "resume json" --json resume cod "$cc_sid" --dry-run
assert_exit_ok "CC→Codex JSON dry-run succeeds"
assert_valid_json "resume JSON is valid"
if echo "$LAST_STDOUT" | jq -e '.ok == true' > /dev/null 2>&1; then
    pass "resume JSON has ok=true"
else
    fail "resume JSON has ok=true" "ok: true" "$(echo "$LAST_STDOUT" | jq '.ok')"
fi

# ===========================================================================
# TEST: Resume — CC → Gemini
# ===========================================================================

log "TEST: Resume CC → Gemini"
reset_env
cc_sid=$(setup_cc_fixture "cc_simple")
run_casr "resume cc->gmi" resume gmi "$cc_sid"
assert_exit_ok "CC→Gemini write succeeds"
assert_stdout_contains "resume shows gemini" "gemini"

gemini_files=$(find "$GEMINI_HOME/tmp" -type f -name '*.json' 2>/dev/null | wc -l)
if [[ "$gemini_files" -eq 1 ]]; then
    pass "Exactly one Gemini session file created"
else
    fail "Exactly one Gemini session file created" "1" "$gemini_files"
fi

# ===========================================================================
# TEST: Resume — CC → Cursor
# ===========================================================================

log "TEST: Resume CC → Cursor"
reset_env
cc_sid=$(setup_cc_fixture "cc_simple")
run_casr "resume cc->cur" --json resume cur "$cc_sid"
assert_exit_ok "CC→Cursor write succeeds"
assert_valid_json "CC→Cursor JSON is valid"
cursor_sid=$(echo "$LAST_STDOUT" | jq -r '.target_session_id // empty')
if [[ -n "$cursor_sid" ]]; then
    pass "CC→Cursor JSON includes target_session_id"
else
    fail "CC→Cursor JSON includes target_session_id" "non-empty id" "<empty>"
fi
assert_file_exists "Cursor DB exists after conversion" "$CURSOR_HOME/User/globalStorage/state.vscdb"

log "TEST: Resume Cursor → CC"
run_casr "resume cur->cc" resume cc "$cursor_sid" --source cur
assert_exit_ok "Cursor→CC write succeeds"
assert_stdout_contains "cursor→cc shows claude-code" "claude-code"

# ===========================================================================
# TEST: Resume — CC → Cline
# ===========================================================================

log "TEST: Resume CC → Cline"
reset_env
cc_sid=$(setup_cc_fixture "cc_simple")
run_casr "resume cc->cln" --json resume cln "$cc_sid"
assert_exit_ok "CC→Cline write succeeds"
assert_valid_json "CC→Cline JSON is valid"
cline_sid=$(echo "$LAST_STDOUT" | jq -r '.target_session_id // empty')
if [[ -n "$cline_sid" ]]; then
    pass "CC→Cline JSON includes target_session_id"
else
    fail "CC→Cline JSON includes target_session_id" "non-empty id" "<empty>"
fi
assert_file_exists "Cline API history exists after conversion" \
    "$CLINE_HOME/tasks/$cline_sid/api_conversation_history.json"

log "TEST: Resume Cline → CC"
run_casr "resume cln->cc" resume cc "$cline_sid" --source cln
assert_exit_ok "Cline→CC write succeeds"
assert_stdout_contains "cline→cc shows claude-code" "claude-code"

# ===========================================================================
# TEST: Resume — CC → Amp
# ===========================================================================

log "TEST: Resume CC → Amp"
reset_env
cc_sid=$(setup_cc_fixture "cc_simple")
run_casr "resume cc->amp" --json resume amp "$cc_sid"
assert_exit_ok "CC→Amp write succeeds"
assert_valid_json "CC→Amp JSON is valid"
amp_sid=$(echo "$LAST_STDOUT" | jq -r '.target_session_id // empty')
if [[ -n "$amp_sid" ]]; then
    pass "CC→Amp JSON includes target_session_id"
else
    fail "CC→Amp JSON includes target_session_id" "non-empty id" "<empty>"
fi
assert_file_exists "Amp thread file exists after conversion" "$AMP_HOME/threads/${amp_sid}.json"

log "TEST: Resume Amp → CC"
run_casr "resume amp->cc" resume cc "$amp_sid" --source amp
assert_exit_ok "Amp→CC write succeeds"
assert_stdout_contains "amp→cc shows claude-code" "claude-code"

# ===========================================================================
# TEST: Resume — CC → Aider
# ===========================================================================

log "TEST: Resume CC → Aider"
reset_env
cc_sid=$(setup_cc_fixture "cc_simple")
run_casr "resume cc->aid" --json resume aid "$cc_sid"
assert_exit_ok "CC→Aider write succeeds"
assert_valid_json "CC→Aider JSON is valid"
aid_sid=$(echo "$LAST_STDOUT" | jq -r '.target_session_id // empty')
if [[ -n "$aid_sid" ]]; then
    pass "CC→Aider JSON includes target_session_id"
else
    fail "CC→Aider JSON includes target_session_id" "non-empty id" "<empty>"
fi
assert_file_exists "Aider history file exists after conversion" "$AIDER_HOME/.aider.chat.history.md"

log "TEST: Resume Aider → CC"
run_casr "resume aid->cc" resume cc "$aid_sid" --source aid
assert_exit_ok "Aider→CC write succeeds"
assert_stdout_contains "aider→cc shows claude-code" "claude-code"

# ===========================================================================
# TEST: Resume — CC → OpenCode
# ===========================================================================

log "TEST: Resume CC → OpenCode"
reset_env
cc_sid=$(setup_cc_fixture "cc_simple")
run_casr "resume cc->opc" --json resume opc "$cc_sid"
assert_exit_ok "CC→OpenCode write succeeds"
assert_valid_json "CC→OpenCode JSON is valid"
opc_sid=$(echo "$LAST_STDOUT" | jq -r '.target_session_id // empty')
if [[ -n "$opc_sid" ]]; then
    pass "CC→OpenCode JSON includes target_session_id"
else
    fail "CC→OpenCode JSON includes target_session_id" "non-empty id" "<empty>"
fi
assert_file_exists "OpenCode DB exists after conversion" "$OPENCODE_HOME/opencode.db"

log "TEST: Resume OpenCode → CC"
run_casr "resume opc->cc" resume cc "$opc_sid" --source opc
assert_exit_ok "OpenCode→CC write succeeds"
assert_stdout_contains "opencode→cc shows claude-code" "claude-code"

# ===========================================================================
# TEST: Resume — Codex → CC
# ===========================================================================

log "TEST: Resume Codex → CC"
reset_env
cod_sid=$(setup_codex_fixture "codex_modern" "jsonl")
run_casr "resume cod->cc" resume cc "$cod_sid"
assert_exit_ok "Codex→CC write succeeds"
assert_stdout_contains "codex→cc shows claude-code" "claude-code"

cc_files=$(find "$CLAUDE_HOME/projects" -type f -name '*.jsonl' 2>/dev/null | wc -l)
if [[ "$cc_files" -eq 1 ]]; then
    pass "Exactly one CC session file created"
else
    fail "Exactly one CC session file created" "1" "$cc_files"
fi

# ===========================================================================
# TEST: Resume — Codex → Gemini
# ===========================================================================

log "TEST: Resume Codex → Gemini"
reset_env
cod_sid=$(setup_codex_fixture "codex_modern" "jsonl")
run_casr "resume cod->gmi" resume gmi "$cod_sid"
assert_exit_ok "Codex→Gemini write succeeds"

# ===========================================================================
# TEST: Resume — Gemini → CC
# ===========================================================================

log "TEST: Resume Gemini → CC"
reset_env
gmi_sid=$(setup_gemini_fixture "gmi_simple")
run_casr "resume gmi->cc" resume cc "$gmi_sid"
assert_exit_ok "Gemini→CC write succeeds"

# ===========================================================================
# TEST: Resume — Gemini → Codex
# ===========================================================================

log "TEST: Resume Gemini → Codex"
reset_env
gmi_sid=$(setup_gemini_fixture "gmi_simple")
run_casr "resume gmi->cod" resume cod "$gmi_sid"
assert_exit_ok "Gemini→Codex write succeeds"

# ===========================================================================
# TEST: Error cases
# ===========================================================================

log "TEST: Resume unknown target"
reset_env
cc_sid=$(setup_cc_fixture "cc_simple")
EXPECT_FAIL=1 run_casr "bad target" resume nonexistent "$cc_sid" || true
assert_exit_fail "resume with unknown target fails"

log "TEST: Resume unknown session"
reset_env
EXPECT_FAIL=1 run_casr "bad session" resume cod "nonexistent-session" || true
assert_exit_fail "resume with unknown session ID fails"

# ===========================================================================
# TEST: Verbose and trace flags
# ===========================================================================

log "TEST: Verbose flag"
reset_env
run_casr "verbose" --verbose providers
assert_exit_ok "--verbose accepted"

log "TEST: Trace flag"
run_casr "trace" --trace providers
assert_exit_ok "--trace accepted"

# ===========================================================================
# TEST: Completions
# ===========================================================================

log "TEST: Completions bash"
run_casr "completions" completions bash
assert_exit_ok "completions bash succeeds"
assert_stdout_contains "completions mentions casr" "casr"

log "TEST: Completions zsh"
run_casr "completions zsh" completions zsh
assert_exit_ok "completions zsh succeeds"

log "TEST: Completions fish"
run_casr "completions fish" completions fish
assert_exit_ok "completions fish succeeds"

# ===========================================================================
# Summary
# ===========================================================================

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
TOTAL=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}Results:${RESET} ${GREEN}${PASS_COUNT} passed${RESET}, ${RED}${FAIL_COUNT} failed${RESET}, ${YELLOW}${SKIP_COUNT} skipped${RESET} (${TOTAL} total, ${ELAPSED}s)"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
