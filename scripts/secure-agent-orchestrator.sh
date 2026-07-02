#!/bin/bash
# ==============================================================================
# Runtime Orchestrator: Enforces Split-Phase Lifecycle Topologies
# ==============================================================================
set -euo pipefail

WORKSPACE_DIR="$(pwd)"
AGENT_TOOL="${1:-aider}"
USER_PROMPT="${2:-""}"
SESSION_UUID="session_$(date +%s)"

# 1. PHASE A: Pre-Runtime Validation Gate
python3 core_engine.py "pre" "$SESSION_UUID" "$USER_PROMPT"

echo "🔒 Spawning Hardened Linux Kernel Container Space ($SESSION_UUID)..."

# 2. PHASE B: Secure Sandbox Perimeter Execution
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
  --user "1000:1000" \
  -v "$WORKSPACE_DIR":/workspace:rw \
  -v "$WORKSPACE_DIR"/.git:/workspace/.git:rw \
  -w /workspace \
  --mount type=bind,source=/dev/null,target=/workspace/.env \
  coder-agent-image:latest "$AGENT_TOOL" || true

# 3. PHASE C: Post-Runtime Metric Evaluation & Active Routing
python3 core_engine.py "post" "$SESSION_UUID" "$USER_PROMPT"
