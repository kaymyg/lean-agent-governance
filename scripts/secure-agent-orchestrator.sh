#!/bin/bash
# ==============================================================================
# Runtime Orchestrator: Enforces Split-Phase Lifecycle Topologies (v7.2)
# ==============================================================================
set -euo pipefail

WORKSPACE_DIR="$(pwd)"
AGENT_TOOL="${1:-aider}"
USER_PROMPT="${2:-""}"

# FIX #1 (High): timestamp-second granularity collided on concurrent/rapid runs.
# uuid4 guarantees uniqueness for /tmp/pre_score files, SQLite session rows, and
# quarantine branch names.
SESSION_UUID=$(python3 -c "import uuid; print(uuid.uuid4())")

PATCH_DIR="/tmp/agent_patches_${SESSION_UUID}"
mkdir -p "$PATCH_DIR"

# 1. PHASE A: Pre-Runtime Validation Gate
python3 core_engine.py "pre" "$SESSION_UUID" "$USER_PROMPT"

echo "🔒 Spawning Hardened Linux Kernel Container Space ($SESSION_UUID)..."

# 2. PHASE B: Secure Sandbox Perimeter Execution
# FIX #4 (High): the repo itself is now mounted READ-ONLY. The agent only gets a
# writable copy inside the container's own tmpfs (never bind-mounted from host),
# so it cannot tamper with git internals, refs, or history on the real repo.
# On exit, the container emits a patch file into the one narrow RW mount point
# (PATCH_DIR) — that's the only thing that crosses back to the host filesystem.
docker run -it --rm \
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
    cp -r /workspace_ro/. /workspace/ &&
    cd /workspace &&
    $AGENT_TOOL '$USER_PROMPT' || true;
    git diff > /patches/session.patch 2>/dev/null || true
  "

# 3. PHASE C: Post-Runtime Metric Evaluation & Active Routing
# The JRI is computed against the *outside* repo state plus the pending patch,
# so quarantine/block decisions never depend on code that only exists inside
# the now-destroyed container.
if [ -s "$PATCH_DIR/session.patch" ]; then
  git apply --check "$PATCH_DIR/session.patch" 2>/dev/null && \
    git apply "$PATCH_DIR/session.patch" && \
    git add -A
fi

python3 core_engine.py "post" "$SESSION_UUID" "$USER_PROMPT"

rm -rf "$PATCH_DIR"
