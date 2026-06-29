# =============================================================================
# upload-to-hf.ps1
# Ultra-Lean Agent Governance Framework — Hugging Face Space Uploader
# Run from the folder containing this script.
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$HFToken,

    [string]$HFUser  = "sahek",
    [string]$RepoName = "agent-governance-framework"
)

$ErrorActionPreference = "Stop"
$BaseDir = $PSScriptRoot   # folder where this script lives (same as project root)

# ---------------------------------------------------------------------------
# Helper: upload one file to HF via the commit API
# ---------------------------------------------------------------------------
function Upload-HFFile {
    param(
        [string]$LocalPath,   # absolute path on disk
        [string]$HFPath,      # destination path inside the HF repo
        [string]$CommitMsg
    )

    if (-not (Test-Path $LocalPath)) {
        Write-Error "❌  Local file not found: $LocalPath"
        return
    }

    $bytes  = [System.IO.File]::ReadAllBytes($LocalPath)
    $b64    = [Convert]::ToBase64String($bytes)

    $payload = @{
        operations   = @(@{
            key   = $HFPath
            type  = "addOrUpdate"
            value = $b64
        })
        commit_title = $CommitMsg
    } | ConvertTo-Json -Depth 5

    Write-Host "⬆️  Uploading: $HFPath  ← $LocalPath"

    $response = Invoke-RestMethod `
        -Uri "https://huggingface.co/api/spaces/$HFUser/$RepoName/commit/main" `
        -Method POST `
        -Headers @{
            Authorization  = "Bearer $HFToken"
            "Content-Type" = "application/json"
        } `
        -Body $payload

    Write-Host "✅  Done: $HFPath ($($response.commitUrl ?? 'committed'))`n"
}

# ---------------------------------------------------------------------------
# Step 1 — Create the Space (safe to re-run; will 409 if already exists)
# ---------------------------------------------------------------------------
Write-Host "🚀  Creating Space: $HFUser/$RepoName ..."

try {
    $createBody = @{
        name    = $RepoName
        type    = "space"
        sdk     = "static"
        private = $false
    } | ConvertTo-Json

    Invoke-RestMethod `
        -Uri "https://huggingface.co/api/repos/create" `
        -Method POST `
        -Headers @{
            Authorization  = "Bearer $HFToken"
            "Content-Type" = "application/json"
        } `
        -Body $createBody | Out-Null

    Write-Host "✅  Space created.`n"
} catch {
    if ($_.Exception.Response.StatusCode -eq 409) {
        Write-Host "ℹ️  Space already exists — continuing with uploads.`n"
    } else {
        throw
    }
}

# ---------------------------------------------------------------------------
# Step 2 — Upload files in priority order
# ---------------------------------------------------------------------------

# 1. README / Space card  (must go first so HF renders the Space correctly)
Upload-HFFile `
    -LocalPath "$BaseDir\README.md" `
    -HFPath    "README.md" `
    -CommitMsg "Add Space card and README"

# 2. CLAUDE.md
Upload-HFFile `
    -LocalPath "$BaseDir\CLAUDE.md" `
    -HFPath    "CLAUDE.md" `
    -CommitMsg "Add CLAUDE.md input firewall"

# 3. .cursorrules
Upload-HFFile `
    -LocalPath "$BaseDir\.cursorrules" `
    -HFPath    ".cursorrules" `
    -CommitMsg "Add .cursorrules input firewall"

# 4. .aiderignore
Upload-HFFile `
    -LocalPath "$BaseDir\.aiderignore" `
    -HFPath    ".aiderignore" `
    -CommitMsg "Add .aiderignore vision barrier"

# 5. .claude/settings.json
Upload-HFFile `
    -LocalPath "$BaseDir\.claude\settings.json" `
    -HFPath    ".claude/settings.json" `
    -CommitMsg "Add Claude Code execution guard settings"

# 6. scripts/run-agent.sh
Upload-HFFile `
    -LocalPath "$BaseDir\scripts\run-agent.sh" `
    -HFPath    "scripts/run-agent.sh" `
    -CommitMsg "Add Docker sandbox runtime script"

# 7. hooks/pre-commit  (stored as hooks/ since HF rejects .git/ paths)
Upload-HFFile `
    -LocalPath "$BaseDir\hooks\pre-commit" `
    -HFPath    "hooks/pre-commit" `
    -CommitMsg "Add pre-commit local gatekeeper"

# 8. .github/workflows/agent-governance.yml
Upload-HFFile `
    -LocalPath "$BaseDir\.github\workflows\agent-governance.yml" `
    -HFPath    ".github/workflows/agent-governance.yml" `
    -CommitMsg "Add CI governance workflow"

# ---------------------------------------------------------------------------
Write-Host "🎉  All files uploaded."
Write-Host "    View your Space at: https://huggingface.co/spaces/$HFUser/$RepoName"
