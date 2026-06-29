#!/bin/bash
set -e

WORKSPACE_DIR="$(pwd)"
AGENT_TOOL="${1:-aider}" # Defaults to aider, or pass 'claude'

echo "🔒 Initializing Hardened Agent Sandbox Session for $AGENT_TOOL..."

# 1. Generate an unprivileged, clean context environment file
# Excludes local host user env vars, cloud tokens, and sensitive system paths
env -i HOME="/home/agent" PATH="/usr/local/bin:/usr/bin:/bin" USER="agent" \
  LC_ALL="en_US.UTF-8" LANG="en_US.UTF-8" \
  GIT_AUTHOR_NAME="AI-Agent-$AGENT_TOOL" \
  GIT_AUTHOR_EMAIL="agents+$AGENT_TOOL@internal.net" \
  GIT_COMMITTER_NAME="AI-Agent-$AGENT_TOOL" \
  GIT_COMMITTER_EMAIL="agents+$AGENT_TOOL@internal.net" \
  > /tmp/clean_agent_env.env

# 2. Execute container with hard resource limits, masked secrets, and dropped privileges
docker run -it --rm \
  --name "agent_session_$(date +%s)" \
  --network none \
  --memory="2g" \
  --cpus="1.5" \
  --pids-limit="128" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --tmpfs /home/agent:rw,noexec,nosuid,size=32m \
  --user "1000:1000" \
  --env-file /tmp/clean_agent_env.env \
  -v "$WORKSPACE_DIR":/workspace:rw \
  -v "$WORKSPACE_DIR"/.git:/workspace/.git:rw \
  -w /workspace \
  --mount type=bind,source=/dev/null,target=/workspace/.env \
  --mount type=bind,source=/dev/null,target=/workspace/config/secrets.json \
  coder-agent-image:latest "$AGENT_TOOL"
