#!/usr/bin/env bash
#
# casr installer — Cross Agent Session Resumer
#
# One-liner install (with cache buster):
#   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/cross_agent_session_resumer/main/install.sh?$(date +%s)" | bash
#
# Or without cache buster:
#   curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/cross_agent_session_resumer/main/install.sh | bash
#
# Options:
#   --version vX.Y.Z   Install specific version (default: latest)
#   --dest DIR         Install to DIR (default: ~/.local/bin)
#   --system           Install to /usr/local/bin (requires sudo)
#   --easy-mode        Auto-update PATH in shell rc files
#   --verify           Run self-test after install
#   --from-source      Build from source instead of downloading binary
#   --quiet            Suppress non-error output
#   --no-gum           Disable gum formatting even if available
#   --no-verify        Skip checksum + signature verification (not recommended)
#   --offline TARBALL  Install from local tarball (airgap mode)
#   --force            Reinstall even if same version exists
#
set -euo pipefail
umask 022
shopt -s lastpipe 2>/dev/null || true

# Require bash >= 4.4 for safe empty-array expansion with set -u
if [[ "${BASH_VERSINFO[0]}" -lt 4 || ( "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -lt 4 ) ]]; then
  echo "Error: This installer requires bash >= 4.4 (yours is ${BASH_VERSION})." >&2
  echo "On macOS, install modern bash: brew install bash" >&2
  exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

VERSION="${VERSION:-}"
OWNER="${OWNER:-Dicklesworthstone}"
REPO="${REPO:-cross_agent_session_resumer}"
BINARY_NAME="casr"
DEST_DEFAULT="$HOME/.local/bin"
DEST="${DEST:-$DEST_DEFAULT}"
EASY=0
QUIET=0
VERIFY=0
FROM_SOURCE=0
CHECKSUM="${CHECKSUM:-}"
CHECKSUM_URL="${CHECKSUM_URL:-}"
SIGSTORE_BUNDLE_URL="${SIGSTORE_BUNDLE_URL:-}"
COSIGN_IDENTITY_RE="${COSIGN_IDENTITY_RE:-^https://github.com/${OWNER}/${REPO}/.github/workflows/dist.yml@refs/tags/.*$}"
COSIGN_OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
ARTIFACT_URL="${ARTIFACT_URL:-}"
LOCK_FILE="/tmp/casr-install.lock"
SYSTEM=0
NO_GUM=0
NO_CHECKSUM=0
FORCE_INSTALL=0
OFFLINE_TARBALL=""
PROVIDER_VERSION_TIMEOUT="${CASR_INSTALLER_PROVIDER_VERSION_TIMEOUT:-1}"

# ═══════════════════════════════════════════════════════════════════════════════
# Output System (Gum + ANSI Dual-Path)
# ═══════════════════════════════════════════════════════════════════════════════

HAS_GUM=0
if command -v gum &>/dev/null && [ -t 1 ]; then
  HAS_GUM=1
fi

log() { [ "$QUIET" -eq 1 ] && return 0; echo -e "$@"; }

info() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 39 "-> $*"
  else
    echo -e "\033[0;34m->\033[0m $*"
  fi
}

ok() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 42 "ok $*"
  else
    echo -e "\033[0;32mok\033[0m $*"
  fi
}

warn() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 214 "!! $*"
  else
    echo -e "\033[1;33m!!\033[0m $*"
  fi
}

err() {
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 196 "xx $*"
  else
    echo -e "\033[0;31mxx\033[0m $*"
  fi
}

run_with_spinner() {
  local title="$1"
  shift
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ] && [ "$QUIET" -eq 0 ]; then
    gum spin --spinner dot --title "$title" -- "$@"
  else
    info "$title"
    "$@"
  fi
}

# Draw a box around text with automatic width calculation
# Usage: draw_box "color_code" "line1" "line2" ...
draw_box() {
  local color="$1"
  shift
  local lines=("$@")
  local max_width=0
  local esc
  esc=$(printf '\033')
  local strip_ansi_sed="s/${esc}\\[[0-9;]*m//g"

  for line in "${lines[@]}"; do
    local stripped
    stripped=$(printf '%b' "$line" | LC_ALL=C sed "$strip_ansi_sed")
    local len=${#stripped}
    if [ "$len" -gt "$max_width" ]; then
      max_width=$len
    fi
  done

  local inner_width=$((max_width + 4))
  local border=""
  for ((i=0; i<inner_width; i++)); do
    border+="="
  done

  printf "\033[%sm+%s+\033[0m\n" "$color" "$border"

  for line in "${lines[@]}"; do
    local stripped
    stripped=$(printf '%b' "$line" | LC_ALL=C sed "$strip_ansi_sed")
    local len=${#stripped}
    local padding=$((max_width - len))
    local pad_str=""
    for ((i=0; i<padding; i++)); do
      pad_str+=" "
    done
    printf "\033[%sm|\033[0m  %b%s  \033[%sm|\033[0m\n" "$color" "$line" "$pad_str" "$color"
  done

  printf "\033[%sm+%s+\033[0m\n" "$color" "$border"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Proxy Support
# ═══════════════════════════════════════════════════════════════════════════════

PROXY_ARGS=()

setup_proxy() {
  PROXY_ARGS=()
  if [[ -n "${HTTPS_PROXY:-}" ]]; then
    PROXY_ARGS=(--proxy "$HTTPS_PROXY")
    info "Using HTTPS proxy: $HTTPS_PROXY"
  elif [[ -n "${HTTP_PROXY:-}" ]]; then
    PROXY_ARGS=(--proxy "$HTTP_PROXY")
    info "Using HTTP proxy: $HTTP_PROXY"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Provider Detection
# ═══════════════════════════════════════════════════════════════════════════════

DETECTED_PROVIDERS=()
CLAUDE_VERSION=""
CODEX_VERSION=""
GEMINI_VERSION=""
CURSOR_VERSION=""
AIDER_VERSION=""
AMP_VERSION=""
OPENCODE_VERSION=""

print_provider_scan_notice() {
  [ "$QUIET" -eq 1 ] && return 0

  local line1="Scanning for installed coding agent providers..."
  local line2="casr converts sessions between detected providers."

  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    echo ""
    gum style \
      --border normal \
      --border-foreground 244 \
      --padding "0 1" \
      "$(gum style --foreground 212 --bold 'Provider scan')" \
      "$(gum style --foreground 247 "$line1")" \
      "$(gum style --foreground 245 "$line2")"
    echo ""
  else
    echo ""
    draw_box "0;36" "$line1" "$line2"
    echo ""
  fi
}

try_version() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || return 0

  local timeout_secs="${PROVIDER_VERSION_TIMEOUT:-1}"
  if ! [[ "$timeout_secs" =~ ^[0-9]+$ ]]; then
    timeout_secs=1
  fi

  if command -v timeout >/dev/null 2>&1; then
    timeout "$timeout_secs" "$cmd" --version 2>/dev/null | head -1 || true
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$timeout_secs" "$cmd" --version 2>/dev/null | head -1 || true
  else
    "$cmd" --version 2>/dev/null | head -1 || true
  fi
}

detect_providers() {
  DETECTED_PROVIDERS=()

  # Claude Code (cc)
  if [[ -d "$HOME/.claude" ]] || command -v claude &>/dev/null; then
    DETECTED_PROVIDERS+=("claude-code")
    CLAUDE_VERSION=$(try_version claude)
  fi

  # Codex CLI (cod)
  if [[ -d "$HOME/.codex" ]] || command -v codex &>/dev/null; then
    DETECTED_PROVIDERS+=("codex")
    CODEX_VERSION=$(try_version codex)
  fi

  # Gemini CLI (gmi)
  if [[ -d "$HOME/.gemini" ]] || [[ -d "$HOME/.gemini-cli" ]] || command -v gemini &>/dev/null; then
    DETECTED_PROVIDERS+=("gemini")
    GEMINI_VERSION=$(try_version gemini)
  fi

  # Cursor (cur)
  local cursor_settings_mac="$HOME/Library/Application Support/Cursor/User/settings.json"
  local cursor_settings_linux="$HOME/.config/Cursor/User/settings.json"
  if [[ -d "$HOME/.cursor" ]] || [[ -f "$cursor_settings_mac" ]] || [[ -f "$cursor_settings_linux" ]] || command -v cursor &>/dev/null; then
    DETECTED_PROVIDERS+=("cursor")
    CURSOR_VERSION=$(try_version cursor)
  fi

  # Cline (cln)
  if [[ -d "$HOME/.config/Code/User/globalStorage/saoudrizwan.claude-dev" ]]; then
    DETECTED_PROVIDERS+=("cline")
  fi

  # Aider (aid)
  if command -v aider &>/dev/null; then
    DETECTED_PROVIDERS+=("aider")
    AIDER_VERSION=$(try_version aider)
  fi

  # Amp (amp)
  if [[ -d "$HOME/.local/share/amp" ]] || command -v amp &>/dev/null; then
    DETECTED_PROVIDERS+=("amp")
    AMP_VERSION=$(try_version amp)
  fi

  # OpenCode (opc)
  if [[ -d "$HOME/.opencode" ]] || command -v opencode &>/dev/null; then
    DETECTED_PROVIDERS+=("opencode")
    OPENCODE_VERSION=$(try_version opencode)
  fi

  # ChatGPT (gpt)
  if [[ -d "$HOME/.chatgpt" ]]; then
    DETECTED_PROVIDERS+=("chatgpt")
  fi
}

print_detected_providers() {
  if [[ ${#DETECTED_PROVIDERS[@]} -eq 0 ]]; then
    warn "No coding agent providers detected"
    info "Install at least two providers to use casr for session conversion"
    return
  fi

  local count=${#DETECTED_PROVIDERS[@]}
  local plural=""
  [[ $count -gt 1 ]] && plural="s"

  format_provider_line() {
    local name="$1"
    local alias="$2"
    local ver="$3"
    local ver_info=""
    [[ -n "$ver" ]] && ver_info=" ($ver)"
    if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
      gum style --foreground 42 "  ok ${name} [${alias}]${ver_info}"
    else
      echo -e "  \033[0;32mok\033[0m ${name} [${alias}]${ver_info}"
    fi
  }

  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    echo ""
    gum style --foreground 39 --bold "Detected ${count} Provider${plural} (casr conversion targets):"
  else
    echo ""
    echo -e "\033[1;34mDetected ${count} Provider${plural} (casr conversion targets):\033[0m"
  fi

  for provider in "${DETECTED_PROVIDERS[@]}"; do
    case "$provider" in
      claude-code) format_provider_line "Claude Code" "cc" "$CLAUDE_VERSION" ;;
      codex)       format_provider_line "Codex CLI"   "cod" "$CODEX_VERSION" ;;
      gemini)      format_provider_line "Gemini CLI"  "gmi" "$GEMINI_VERSION" ;;
      cursor)      format_provider_line "Cursor"      "cur" "$CURSOR_VERSION" ;;
      cline)       format_provider_line "Cline"       "cln" "" ;;
      aider)       format_provider_line "Aider"       "aid" "$AIDER_VERSION" ;;
      amp)         format_provider_line "Amp"         "amp" "$AMP_VERSION" ;;
      opencode)    format_provider_line "OpenCode"    "opc" "$OPENCODE_VERSION" ;;
      chatgpt)     format_provider_line "ChatGPT"     "gpt" "" ;;
    esac
  done
  echo ""

  if [ "$count" -ge 2 ]; then
    info "casr can convert sessions between any pair of detected providers"
  else
    info "Install a second provider to enable cross-provider session conversion"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Version Resolution
# ═══════════════════════════════════════════════════════════════════════════════

resolve_version() {
  if [ -n "$VERSION" ]; then return 0; fi

  info "Resolving latest version..."
  local latest_url="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"
  local tag
  if tag=$(curl -fsSL --connect-timeout 5 "${PROXY_ARGS[@]}" \
    -H "Accept: application/vnd.github.v3+json" "$latest_url" 2>/dev/null \
    | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'); then
    if [ -n "$tag" ]; then
      VERSION="$tag"
      info "Resolved latest version: $VERSION"
      return 0
    fi
  fi

  # Fallback: redirect-based resolution (handles GitHub API rate limits)
  local redirect_url="https://github.com/${OWNER}/${REPO}/releases/latest"
  if tag=$(curl -fsSL "${PROXY_ARGS[@]}" -o /dev/null -w '%{url_effective}' "$redirect_url" 2>/dev/null \
    | sed -E 's|.*/tag/||'); then
    if [ -n "$tag" ] && [[ "$tag" =~ ^v[0-9] ]] && [[ "$tag" != *"/"* ]]; then
      VERSION="$tag"
      info "Resolved latest version via redirect: $VERSION"
      return 0
    fi
  fi

  VERSION="v0.1.0"
  warn "Could not resolve latest version; defaulting to $VERSION"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Platform Detection
# ═══════════════════════════════════════════════════════════════════════════════

OS=""
ARCH=""
TARGET=""

detect_platform() {
  OS=$(uname -s | tr 'A-Z' 'a-z')
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="aarch64" ;;
    *) warn "Unknown architecture $ARCH, using as-is" ;;
  esac

  # WSL detection
  if [[ "$OS" == "linux" ]] && grep -qi microsoft /proc/version 2>/dev/null; then
    warn "WSL detected. casr will work normally; provider paths may differ from Windows host"
  fi

  TARGET=""
  case "${OS}-${ARCH}" in
    linux-x86_64)   TARGET="x86_64-unknown-linux-musl" ;;
    linux-aarch64)  TARGET="aarch64-unknown-linux-musl" ;;
    darwin-x86_64)  TARGET="x86_64-apple-darwin" ;;
    darwin-aarch64) TARGET="aarch64-apple-darwin" ;;
    *) :;;
  esac

  if [ -z "$TARGET" ] && [ "$FROM_SOURCE" -eq 0 ] && [ -z "$ARTIFACT_URL" ] && [ -z "$OFFLINE_TARBALL" ]; then
    warn "No prebuilt binary for ${OS}/${ARCH}; falling back to build-from-source"
    FROM_SOURCE=1
  fi
}

set_artifact_url() {
  TAR=""
  URL=""
  if [ "$FROM_SOURCE" -eq 0 ] && [ -z "$OFFLINE_TARBALL" ]; then
    if [ -n "$ARTIFACT_URL" ]; then
      TAR=$(basename "$ARTIFACT_URL")
      URL="$ARTIFACT_URL"
    elif [ -n "$TARGET" ]; then
      TAR="casr-${TARGET}.tar.xz"
      URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/${TAR}"
    else
      warn "No prebuilt artifact for ${OS}/${ARCH}; falling back to build-from-source"
      FROM_SOURCE=1
    fi
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Preflight Checks
# ═══════════════════════════════════════════════════════════════════════════════

check_disk_space() {
  local min_kb=10240  # 10 MB
  local path="$DEST"
  if [ ! -d "$path" ]; then
    path=$(dirname "$path")
  fi
  if command -v df >/dev/null 2>&1; then
    local avail_kb
    avail_kb=$(df -Pk "$path" | awk 'NR==2 {print $4}')
    if [ -n "$avail_kb" ] && [ "$avail_kb" -lt "$min_kb" ]; then
      err "Insufficient disk space in $path (need at least 10MB)"
      exit 1
    fi
  else
    warn "df not found; skipping disk space check"
  fi
}

check_write_permissions() {
  if [ ! -d "$DEST" ]; then
    if ! mkdir -p "$DEST" 2>/dev/null; then
      err "Cannot create $DEST (insufficient permissions)"
      err "Try running with sudo or choose a writable --dest"
      exit 1
    fi
  fi
  if [ ! -w "$DEST" ]; then
    err "No write permission to $DEST"
    err "Try running with sudo or choose a writable --dest"
    exit 1
  fi
}

check_existing_install() {
  if [ -x "$DEST/$BINARY_NAME" ]; then
    local current
    current=$("$DEST/$BINARY_NAME" --version 2>/dev/null | head -1 || echo "")
    if [ -n "$current" ]; then
      info "Existing casr detected: $current"
    fi
  fi
}

check_network() {
  if [ -n "$OFFLINE_TARBALL" ]; then
    info "Offline mode; skipping network preflight"
    return 0
  fi
  if [ "$FROM_SOURCE" -eq 1 ]; then
    return 0
  fi
  if [ -z "$URL" ]; then
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not found; skipping network check"
    return 0
  fi
  if ! curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 3 --max-time 5 -o /dev/null "$URL" 2>/dev/null; then
    warn "Network check failed for $URL"
    warn "Continuing; download may fail"
  fi
}

preflight_checks() {
  info "Running preflight checks"
  check_disk_space
  check_write_permissions
  check_existing_install
  check_network
}

# ═══════════════════════════════════════════════════════════════════════════════
# Version Comparison
# ═══════════════════════════════════════════════════════════════════════════════

check_installed_version() {
  local target_version="$1"
  if [ ! -x "$DEST/$BINARY_NAME" ]; then
    return 1
  fi

  local installed_version
  installed_version=$("$DEST/$BINARY_NAME" --version 2>/dev/null | head -1 | sed -E 's/.*([0-9]+\.[0-9]+\.[0-9]+).*/\1/')

  if [ -z "$installed_version" ]; then
    return 1
  fi

  local target_clean="${target_version#v}"
  local installed_clean="${installed_version#v}"

  if [ "$target_clean" = "$installed_clean" ]; then
    return 0
  fi
  return 1
}

# ═══════════════════════════════════════════════════════════════════════════════
# Checksum & Signature Verification
# ═══════════════════════════════════════════════════════════════════════════════

verify_checksum() {
  local file="$1"
  local expected="$2"
  local actual=""

  if [ ! -f "$file" ]; then
    err "File not found: $file"
    return 1
  fi

  if command -v sha256sum &>/dev/null; then
    actual=$(sha256sum "$file" | cut -d' ' -f1)
  elif command -v shasum &>/dev/null; then
    actual=$(shasum -a 256 "$file" | cut -d' ' -f1)
  else
    warn "No SHA256 tool found (sha256sum or shasum); skipping verification"
    return 0
  fi

  if [ "$actual" != "$expected" ]; then
    err "Checksum verification FAILED!"
    err "Expected: $expected"
    err "Got:      $actual"
    err "The downloaded file may be corrupted or tampered with."
    rm -f "$file"
    return 1
  fi

  ok "Checksum verified: ${actual:0:16}..."
  return 0
}

verify_sigstore_bundle() {
  local file="$1"
  local artifact_url="$2"

  if ! command -v cosign &>/dev/null; then
    warn "cosign not found; skipping signature verification (install cosign for stronger authenticity checks)"
    return 0
  fi

  local bundle_url="$SIGSTORE_BUNDLE_URL"
  if [ -z "$bundle_url" ]; then
    bundle_url="${artifact_url}.sigstore.json"
  fi

  local bundle_file="$TMP/$(basename "$bundle_url")"
  info "Fetching sigstore bundle from ${bundle_url}"
  if ! curl -fsSL "${PROXY_ARGS[@]}" "$bundle_url" -o "$bundle_file" 2>/dev/null; then
    warn "Sigstore bundle not found; skipping signature verification"
    return 0
  fi

  if ! cosign verify-blob \
    --bundle "$bundle_file" \
    --certificate-identity-regexp "$COSIGN_IDENTITY_RE" \
    --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
    "$file" 2>/dev/null; then
    return 1
  fi

  ok "Signature verified (cosign)"
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# Rust Toolchain (for build-from-source)
# ═══════════════════════════════════════════════════════════════════════════════

ensure_rust() {
  if [ "${RUSTUP_INIT_SKIP:-0}" != "0" ]; then
    info "Skipping rustup install (RUSTUP_INIT_SKIP set)"
    return 0
  fi
  if command -v cargo >/dev/null 2>&1 && rustc --version 2>/dev/null | grep -q nightly; then return 0; fi
  if [ "$EASY" -ne 1 ]; then
    if [ -t 0 ]; then
      echo -n "Install Rust nightly via rustup? (y/N): "
      read -r ans
      case "$ans" in y|Y) :;; *) warn "Skipping rustup install"; return 0;; esac
    fi
  fi
  info "Installing rustup (nightly) — casr requires Rust nightly (edition 2024)"
  curl --proto '=https' --tlsv1.2 -sSf "${PROXY_ARGS[@]}" https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain nightly --profile minimal
  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
  export PATH="$HOME/.cargo/bin:$PATH"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PATH Management
# ═══════════════════════════════════════════════════════════════════════════════

maybe_add_path() {
  case ":$PATH:" in
    *:"$DEST":*) return 0 ;;
    *)
      if [ "$EASY" -eq 1 ]; then
        UPDATED=0
        for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
          if [ -e "$rc" ] && [ -w "$rc" ]; then
            if ! grep -F "$DEST" "$rc" >/dev/null 2>&1; then
              echo "export PATH=\"$DEST:\$PATH\"" >> "$rc"
            fi
            UPDATED=1
          fi
        done
        if [ "$UPDATED" -eq 1 ]; then
          warn "PATH updated in ~/.zshrc/.bashrc; restart shell to use casr"
        else
          warn "Add $DEST to PATH to use casr"
        fi
      else
        warn "Add $DEST to PATH to use casr"
      fi
    ;;
  esac
}

# ═══════════════════════════════════════════════════════════════════════════════
# Shell Completions
# ═══════════════════════════════════════════════════════════════════════════════

detect_default_shell() {
  local shell="${SHELL:-}"
  [ -z "$shell" ] && return 1
  shell=$(basename "$shell")
  case "$shell" in
    bash|zsh|fish) echo "$shell"; return 0 ;;
    *) return 1 ;;
  esac
}

install_completions_for_shell() {
  local shell="$1"
  local bin="$DEST/$BINARY_NAME"
  if [ ! -x "$bin" ]; then
    warn "casr binary not found at $bin; skipping completions"
    return 1
  fi

  # Check if the completions subcommand exists
  if ! "$bin" completions --help >/dev/null 2>&1; then
    info "Shell completions: skipped (not supported in this version)"
    return 0
  fi

  local target=""
  case "$shell" in
    bash)
      target="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/casr"
      ;;
    zsh)
      target="${XDG_DATA_HOME:-$HOME/.local/share}/zsh/site-functions/_casr"
      ;;
    fish)
      target="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/casr.fish"
      ;;
    *)
      return 1
      ;;
  esac

  if ! mkdir -p "$(dirname "$target")" 2>/dev/null; then
    warn "Failed to create completions directory for $shell"
    return 1
  fi

  local output
  if output=$("$bin" completions "$shell" 2>&1) && [ -n "$output" ]; then
    printf '%s\n' "$output" > "$target"
    ok "Installed $shell completions to $target"
    return 0
  fi

  warn "Failed to generate $shell completions"
  return 1
}

maybe_install_completions() {
  local shell=""
  if ! shell=$(detect_default_shell); then
    info "Shell completions: skipped (unknown shell)"
    return 0
  fi

  install_completions_for_shell "$shell" || true
}

# ═══════════════════════════════════════════════════════════════════════════════
# Self-Test
# ═══════════════════════════════════════════════════════════════════════════════

run_self_test() {
  local bin="$DEST/$BINARY_NAME"
  if [ ! -x "$bin" ]; then
    err "Self-test: binary not found at $bin"
    return 1
  fi

  info "Running self-test..."

  # Test 1: --version
  local ver_output
  if ver_output=$("$bin" --version 2>&1); then
    ok "Self-test: --version works ($ver_output)"
  else
    err "Self-test: --version failed"
    return 1
  fi

  # Test 2: providers command
  local prov_output
  if prov_output=$("$bin" providers 2>&1); then
    ok "Self-test: providers command works"
  else
    warn "Self-test: providers command returned non-zero (some providers may not be installed)"
  fi

  # Test 3: list command
  if "$bin" list --limit 1 >/dev/null 2>&1; then
    ok "Self-test: list command works"
  else
    warn "Self-test: list command returned non-zero (no sessions found, which is normal)"
  fi

  ok "Self-test complete"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Usage
# ═══════════════════════════════════════════════════════════════════════════════

usage() {
  cat <<EOFU
Usage: install.sh [OPTIONS]

Options:
  --version vX.Y.Z   Install specific version (default: latest)
  --dest DIR         Install to DIR (default: ~/.local/bin)
  --system           Install to /usr/local/bin (requires sudo)
  --easy-mode        Auto-update PATH in shell rc files
  --verify           Run self-test after install
  --from-source      Build from source instead of downloading binary
  --quiet            Suppress non-error output
  --no-gum           Disable gum formatting even if available
  --no-verify        Skip checksum + signature verification (not recommended)
  --offline TARBALL  Install from local tarball (airgap mode)
  --force            Force reinstall even if same version is installed

Environment:
  VERSION            Override version to install
  ARTIFACT_URL       Override artifact download URL
  CHECKSUM           Override expected SHA256 checksum
  HTTPS_PROXY        HTTPS proxy URL
  HTTP_PROXY         HTTP proxy URL

Examples:
  # Install latest release
  curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/cross_agent_session_resumer/main/install.sh?$(date +%s)" | bash

  # Install specific version with self-test
  bash install.sh --version v0.2.0 --verify

  # Install system-wide with auto-PATH
  sudo bash install.sh --system --easy-mode

  # Offline / airgap install
  bash install.sh --offline ./casr-x86_64-unknown-linux-musl.tar.xz

  # Build from source (requires Rust nightly)
  bash install.sh --from-source
EOFU
}

# ═══════════════════════════════════════════════════════════════════════════════
# Argument Parsing
# ═══════════════════════════════════════════════════════════════════════════════

needs_arg() { if [ $# -lt 2 ] || [[ "$2" == --* ]]; then err "Missing value for $1"; usage; exit 1; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version)      needs_arg "$@"; VERSION="$2"; shift 2 ;;
    --dest)         needs_arg "$@"; DEST="$2"; shift 2 ;;
    --system)       SYSTEM=1; DEST="/usr/local/bin"; shift ;;
    --easy-mode)    EASY=1; shift ;;
    --verify)       VERIFY=1; shift ;;
    --artifact-url) needs_arg "$@"; ARTIFACT_URL="$2"; shift 2 ;;
    --checksum)     needs_arg "$@"; CHECKSUM="$2"; shift 2 ;;
    --checksum-url) needs_arg "$@"; CHECKSUM_URL="$2"; shift 2 ;;
    --from-source)  FROM_SOURCE=1; shift ;;
    --quiet|-q)     QUIET=1; shift ;;
    --no-gum)       NO_GUM=1; shift ;;
    --no-verify)    NO_CHECKSUM=1; shift ;;
    --force)        FORCE_INSTALL=1; shift ;;
    --offline)      needs_arg "$@"; OFFLINE_TARBALL="$2"; shift 2 ;;
    -h|--help)      usage; exit 0 ;;
    *)              warn "Unknown option: $1 (ignored)"; shift ;;
  esac
done

# ═══════════════════════════════════════════════════════════════════════════════
# Main Installation Flow
# ═══════════════════════════════════════════════════════════════════════════════

# Show branded header
if [ "$QUIET" -eq 0 ]; then
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style \
      --border normal \
      --border-foreground 39 \
      --padding "0 1" \
      --margin "1 0" \
      "$(gum style --foreground 42 --bold 'casr installer')" \
      "$(gum style --foreground 245 'Cross Agent Session Resumer')" \
      "$(gum style --foreground 245 'Resume AI coding sessions across providers')"
  else
    echo ""
    echo -e "\033[1;32mcasr installer\033[0m"
    echo -e "\033[0;90mCross Agent Session Resumer\033[0m"
    echo -e "\033[0;90mResume AI coding sessions across providers\033[0m"
    echo ""
  fi
fi

# Detect providers early (informational display)
print_provider_scan_notice
detect_providers
if [ "$QUIET" -eq 0 ]; then
  print_detected_providers
fi

# Setup proxy
setup_proxy

# Resolve version and platform
resolve_version
detect_platform
set_artifact_url

# Ensure destination directory exists
mkdir -p "$DEST" 2>/dev/null || true

# Preflight
preflight_checks

# Check if already at target version
if [ "$FORCE_INSTALL" -eq 0 ] && check_installed_version "$VERSION"; then
  ok "casr $VERSION is already installed at $DEST/$BINARY_NAME"
  info "Use --force to reinstall"
  maybe_install_completions
  if [ "$VERIFY" -eq 1 ]; then
    run_self_test
  fi
  exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Atomic Locking (mkdir-based, cross-platform)
# ═══════════════════════════════════════════════════════════════════════════════

LOCK_DIR="${LOCK_FILE}.d"
LOCKED=0
if mkdir "$LOCK_DIR" 2>/dev/null; then
  LOCKED=1
  echo $$ > "$LOCK_DIR/pid"
else
  if [ -f "$LOCK_DIR/pid" ]; then
    OLD_PID=$(cat "$LOCK_DIR/pid" 2>/dev/null || echo "")
    if [ -n "$OLD_PID" ] && ! kill -0 "$OLD_PID" 2>/dev/null; then
      rm -rf "$LOCK_DIR"
      if mkdir "$LOCK_DIR" 2>/dev/null; then
        LOCKED=1
        echo $$ > "$LOCK_DIR/pid"
      fi
    fi
  fi
  if [ "$LOCKED" -eq 0 ]; then
    err "Another casr installer is running (lock $LOCK_DIR)"
    exit 1
  fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Temp Directory & Cleanup Trap
# ═══════════════════════════════════════════════════════════════════════════════

TMP=$(mktemp -d)
cleanup() {
  rm -rf "$TMP"
  if [ "$LOCKED" -eq 1 ]; then rm -rf "$LOCK_DIR"; fi
}
trap cleanup EXIT

# ═══════════════════════════════════════════════════════════════════════════════
# Offline Install Path
# ═══════════════════════════════════════════════════════════════════════════════

INSTALL_SOURCE=""

if [ -n "$OFFLINE_TARBALL" ]; then
  if [ ! -f "$OFFLINE_TARBALL" ]; then
    err "Offline tarball not found: $OFFLINE_TARBALL"
    exit 1
  fi
  info "Installing from offline tarball: $OFFLINE_TARBALL"
  cp "$OFFLINE_TARBALL" "$TMP/artifact.tar.xz"
  tar -xf "$TMP/artifact.tar.xz" -C "$TMP"

  BIN="$TMP/$BINARY_NAME"
  if [ ! -x "$BIN" ] && [ -n "$TARGET" ]; then
    BIN="$TMP/casr-${TARGET}/$BINARY_NAME"
  fi
  if [ ! -x "$BIN" ]; then
    BIN=$(find "$TMP" -maxdepth 3 -type f -name "$BINARY_NAME" -perm -111 | head -n 1)
  fi
  [ -x "$BIN" ] || { err "Binary not found in tarball"; exit 1; }

  install -m 0755 "$BIN" "$DEST/$BINARY_NAME"
  ok "Installed to $DEST/$BINARY_NAME (offline)"
  INSTALL_SOURCE="offline tarball"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Download Binary (with build-from-source fallback)
# ═══════════════════════════════════════════════════════════════════════════════

if [ -z "$INSTALL_SOURCE" ] && [ "$FROM_SOURCE" -eq 0 ] && [ -n "$URL" ]; then
  info "Downloading $URL"
  DOWNLOAD_OK=0
  if run_with_spinner "Downloading casr..." \
    curl -fsSL "${PROXY_ARGS[@]}" "$URL" -o "$TMP/$TAR"; then
    DOWNLOAD_OK=1
  fi

  if [ "$DOWNLOAD_OK" -eq 0 ]; then
    # Tier 2: unversioned latest
    TIER2_URL="https://github.com/${OWNER}/${REPO}/releases/latest/download/casr-${TARGET}.tar.xz"
    info "Trying unversioned latest: $TIER2_URL"
    if curl -fsSL "${PROXY_ARGS[@]}" "$TIER2_URL" -o "$TMP/$TAR" 2>/dev/null; then
      DOWNLOAD_OK=1
    fi
  fi

  if [ "$DOWNLOAD_OK" -eq 0 ]; then
    # Tier 3: simple naming
    TIER3_URL="https://github.com/${OWNER}/${REPO}/releases/latest/download/casr-${OS}-${ARCH}.tar.xz"
    info "Trying simple naming: $TIER3_URL"
    if curl -fsSL "${PROXY_ARGS[@]}" "$TIER3_URL" -o "$TMP/$TAR" 2>/dev/null; then
      DOWNLOAD_OK=1
    fi
  fi

  if [ "$DOWNLOAD_OK" -eq 0 ]; then
    warn "No prebuilt binary found; falling back to build-from-source"
    FROM_SOURCE=1
  fi
fi

if [ -z "$INSTALL_SOURCE" ] && [ "$FROM_SOURCE" -eq 1 ]; then
  info "Building from source (requires git, Rust nightly)"
  ensure_rust
  run_with_spinner "Cloning repository..." \
    git clone --depth 1 "https://github.com/${OWNER}/${REPO}.git" "$TMP/src"
  run_with_spinner "Building from source (this takes a few minutes)..." \
    bash -c "cd '$TMP/src' && cargo build --release"
  BIN="$TMP/src/target/release/$BINARY_NAME"
  [ -x "$BIN" ] || { err "Build failed: binary not found at $BIN"; exit 1; }
  install -m 0755 "$BIN" "$DEST/$BINARY_NAME"
  ok "Installed to $DEST/$BINARY_NAME (source build)"
  INSTALL_SOURCE="built from source (Rust nightly)"
fi

# Binary download path (not offline, not from-source)
if [ -z "$INSTALL_SOURCE" ]; then
  # ═════════════════════════════════════════════════════════════════════════════
  # Verify Downloaded Artifact
  # ═════════════════════════════════════════════════════════════════════════════

  if [ "$NO_CHECKSUM" -eq 1 ]; then
    warn "Verification skipped (--no-verify)"
  else
    # Fetch checksum
    if [ -z "$CHECKSUM" ]; then
      [ -z "$CHECKSUM_URL" ] && CHECKSUM_URL="${URL}.sha256"
      info "Fetching checksum from ${CHECKSUM_URL}"
      CHECKSUM_FILE="$TMP/checksum.sha256"
      if curl -fsSL "${PROXY_ARGS[@]}" "$CHECKSUM_URL" -o "$CHECKSUM_FILE" 2>/dev/null; then
        CHECKSUM=$(awk '{print $1}' "$CHECKSUM_FILE")
        if [ -z "$CHECKSUM" ]; then
          warn "Empty checksum file; skipping verification"
        fi
      else
        warn "Checksum file not found; skipping checksum verification"
      fi
    fi

    # Verify checksum if available
    if [ -n "$CHECKSUM" ]; then
      if ! verify_checksum "$TMP/$TAR" "$CHECKSUM"; then
        err "Installation aborted due to checksum failure"
        exit 1
      fi
    fi

    # Verify sigstore bundle (best-effort)
    if ! verify_sigstore_bundle "$TMP/$TAR" "$URL"; then
      err "Signature verification failed"
      err "The downloaded file may be corrupted or tampered with."
      exit 1
    fi
  fi

  # ═════════════════════════════════════════════════════════════════════════════
  # Extract & Install Binary
  # ═════════════════════════════════════════════════════════════════════════════

  info "Extracting"
  tar -xf "$TMP/$TAR" -C "$TMP"

  BIN="$TMP/$BINARY_NAME"
  if [ ! -x "$BIN" ] && [ -n "$TARGET" ]; then
    BIN="$TMP/casr-${TARGET}/$BINARY_NAME"
  fi
  if [ ! -x "$BIN" ]; then
    BIN=$(find "$TMP" -maxdepth 3 -type f -name "$BINARY_NAME" -perm -111 | head -n 1)
  fi
  [ -x "$BIN" ] || { err "Binary not found in archive"; exit 1; }

  install -m 0755 "$BIN" "$DEST/$BINARY_NAME"
  ok "Installed to $DEST/$BINARY_NAME"
  INSTALL_SOURCE="prebuilt binary ($VERSION)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Post-Install (shared across all install paths)
# ═══════════════════════════════════════════════════════════════════════════════

maybe_add_path
maybe_install_completions

if [ "$VERIFY" -eq 1 ]; then
  run_self_test
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Final Summary
# ═══════════════════════════════════════════════════════════════════════════════

PROV_LIST=""
if [[ ${#DETECTED_PROVIDERS[@]} -gt 0 ]]; then
  for p in "${DETECTED_PROVIDERS[@]}"; do
    case "$p" in
      claude-code) PROV_LIST+="cc " ;;
      codex)       PROV_LIST+="cod " ;;
      gemini)      PROV_LIST+="gmi " ;;
      cursor)      PROV_LIST+="cur " ;;
      cline)       PROV_LIST+="cln " ;;
      aider)       PROV_LIST+="aid " ;;
      amp)         PROV_LIST+="amp " ;;
      opencode)    PROV_LIST+="opc " ;;
      chatgpt)     PROV_LIST+="gpt " ;;
    esac
  done
  PROV_LIST="${PROV_LIST% }"
else
  PROV_LIST="none detected"
fi

echo ""

if [ "$QUIET" -eq 0 ]; then
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    {
      gum style --foreground 42 --bold 'casr installed successfully!'
      echo ""
      gum style --foreground 245 "Binary:    $DEST/$BINARY_NAME"
      gum style --foreground 245 "Version:   $VERSION"
      gum style --foreground 245 "Source:    $INSTALL_SOURCE"
      gum style --foreground 245 "Providers: $PROV_LIST"
      echo ""
      gum style --foreground 245 'Get started:'
      gum style --foreground 39 '  casr providers          # see detected providers'
      gum style --foreground 39 '  casr list               # find sessions'
      gum style --foreground 39 '  casr cc resume <id>     # convert a session'
      echo ""
      gum style --foreground 245 --italic "To uninstall: rm $DEST/$BINARY_NAME"
    } | gum style --border normal --border-foreground 42 --padding "1 2"
  else
    draw_box "0;32" \
      "\033[1;32mcasr installed successfully!\033[0m" \
      "" \
      "Binary:    $DEST/$BINARY_NAME" \
      "Version:   $VERSION" \
      "Source:    $INSTALL_SOURCE" \
      "Providers: $PROV_LIST" \
      "" \
      "Get started:" \
      "  \033[0;36mcasr providers\033[0m          # see detected providers" \
      "  \033[0;36mcasr list\033[0m               # find sessions" \
      "  \033[0;36mcasr cc resume <id>\033[0m     # convert a session" \
      "" \
      "\033[0;90mTo uninstall: rm $DEST/$BINARY_NAME\033[0m"
  fi
fi
