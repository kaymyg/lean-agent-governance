#!/bin/bash
# ==============================================================================
# Runtime Orchestrator: Enforces Split-Phase Lifecycle Topologies (v8.0)
# ==============================================================================
set -euo pipefail

WORKSPACE_DIR="$(pwd)"
AGENT_TOOL="${1:-aider}"
USER_PROMPT="${2:-""}"

SESSION_UUID=$(python3 -c "import uuid; print(uuid.uuid4())")

# Pull tunables from config so ops can adjust without touching this script.
MAX_PATCH_SIZE=$(python3 -c "import json; print(json.load(open('config/security_profiles.json'))['system_settings']['max_patch_size_bytes'])")
RUNTIME_TIMEOUT=$(python3 -c "import json; print(json.load(open('config/security_profiles.json'))['system_settings']['agent_runtime_timeout_seconds'])")

PATCH_DIR="/tmp/agent_patches_${SESSION_UUID}"
mkdir -p "$PATCH_DIR"

# 1. PHASE A: Pre-Runtime Validation Gate
python3 core_engine.py "pre" "$SESSION_UUID" "$USER_PROMPT"

echo "🔒 Spawning Hardened Linux Kernel Container Space ($SESSION_UUID)..."

# 2. PHASE B: Secure Sandbox Perimeter Execution
#
# FIX (Medium): the container now copies only *git-tracked* files instead of
# `cp -r .`, which was slow and memory-heavy on monorepos and could balloon
# on untracked build artifacts / node_modules. `git archive` streams tracked
# content straight into the tmpfs copy without walking ignored directories.
#
# FIX (High): `timeout` wraps the whole docker invocation so a hung agent
# process or stuck inference call can't hold the sandbox (and its resources)
# open indefinitely — it gets killed and treated as a failed run.
timeout --signal=KILL "${RUNTIME_TIMEOUT}s" docker run --rm \
  --name "secure_agent_$SESSION_UUID" \
  --network none \
  --memory="2g" \
  --cpus="1.5" \
  --pids-limit="128" \
  --read-only \
  --cap-drop ALL \
  --security-opt=no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --tmpfs /home/agent:rw,noexec,nosuid,size=32m \
  --tmpfs /workspace:rw,nosuid,size=512m \
  --user "1000:1000" \
  -v "$WORKSPACE_DIR":/workspace_ro:ro \
  -v "$PATCH_DIR":/patches:rw \
  --mount type=bind,source=/dev/null,target=/workspace_ro/.env \
  -w /workspace \
  coder-agent-image:latest bash -c "
    git --git-dir=/workspace_ro/.git --work-tree=/workspace_ro archive HEAD | tar -x -C /workspace &&
    cd /workspace &&
    $AGENT_TOOL '$USER_PROMPT' || true;
    git init -q &&
    git add -A &&
    git diff --cached > /patches/session.patch 2>/dev/null || true;
    git diff --cached --name-only > /patches/modified_files.txt 2>/dev/null || true
  " || echo "⚠️  Agent runtime terminated (timeout or nonzero exit) — evaluating whatever telemetry was captured."

# 3. PHASE C: Post-Runtime Metric Evaluation & Active Routing
#
# FIX (High): guard against oversized patches *before* the host git process
# ever tries to parse them. A 40k-line / 500-file patch shouldn't be handed
# to `git apply` at all — reject it outright and let it fall straight into
# quarantine scoring instead.
PATCH_APPLY_FAILED=false
MODIFIED_FILE_COUNT=0

if [ -f "$PATCH_DIR/modified_files.txt" ]; then
  MODIFIED_FILE_COUNT=$(wc -l < "$PATCH_DIR/modified_files.txt" | tr -d ' ')
fi

if [ -s "$PATCH_DIR/session.patch" ]; then
  PATCH_SIZE=$(wc -c < "$PATCH_DIR/session.patch")
  if [ "$PATCH_SIZE" -gt "$MAX_PATCH_SIZE" ]; then
    echo "❌ Patch rejected: ${PATCH_SIZE} bytes exceeds max_patch_size_bytes (${MAX_PATCH_SIZE}). Not applying to host repo."
    PATCH_APPLY_FAILED=true
  elif git apply --check "$PATCH_DIR/session.patch" 2>/dev/null; then
    git apply "$PATCH_DIR/session.patch"
    git add -A
  else
    echo "⚠️  Patch failed git apply --check — not applying to host repo."
    PATCH_APPLY_FAILED=true
  fi
fi

# FIX (Medium): even when the patch can't be applied, don't lose the evidence.
# Export a small telemetry file the engine can read to score against what the
# container reported, instead of silently defaulting every signal to zero.
TELEMETRY_PATH="$PATCH_DIR/telemetry.json"
# FIX (HIGH): bash's lowercase `false`/`true` are not valid Python literals.
# Interpolating them into generated Python source raised
#   NameError: name 'false' is not defined
# and because this script runs under `set -euo pipefail`, that aborted the run
# BEFORE `core_engine.py post` was ever reached -- meaning the entire
# post-runtime risk-scoring phase silently never executed on the normal path.
# Emit the JSON directly from the shell; no Python source generation needed.
printf '{"modified_file_count": %d, "patch_apply_failed": %s}\n' \
  "${MODIFIED_FILE_COUNT}" "${PATCH_APPLY_FAILED}" > "${TELEMETRY_PATH}"
export AGENT_TELEMETRY_PATH="$TELEMETRY_PATH"

python3 core_engine.py "post" "$SESSION_UUID" "$USER_PROMPT"

rm -rf "$PATCH_DIR"
