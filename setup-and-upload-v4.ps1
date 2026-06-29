# =============================================================================
# setup-and-upload.ps1
# Run this from anywhere -- point it at your downloads folder.
# It will organize files into the correct structure, then upload to HF.
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$HFToken,

    [string]$BaseDir  = "C:\Users\you\Downloads\lean-agent-governance-architecture",
    [string]$HFUser   = "Sahek",
    [string]$RepoName = "lean-agent-governance-architecture"
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Step 1 -- Create subfolders
# ---------------------------------------------------------------------------
Write-Host "`n[DIR]  Creating folder structure inside $BaseDir ..."

$folders = @(
    ".claude",
    "scripts",
    "hooks",
    ".github\workflows"
)

foreach ($f in $folders) {
    $full = Join-Path $BaseDir $f
    if (-not (Test-Path $full)) {
        New-Item -ItemType Directory -Path $full | Out-Null
        Write-Host "   Created: $f"
    } else {
        Write-Host "   Already exists: $f"
    }
}

# ---------------------------------------------------------------------------
# Step 2 -- Move flat downloaded files into their correct locations
# ---------------------------------------------------------------------------
Write-Host "`n[MOVE]  Organizing files ..."

$moves = @(
    @{ From = "settings.json";        To = ".claude\settings.json" },
    @{ From = "run-agent.sh";         To = "scripts\run-agent.sh" },
    @{ From = "pre-commit";           To = "hooks\pre-commit" },
    @{ From = "agent-governance.yml"; To = ".github\workflows\agent-governance.yml" }
)

foreach ($m in $moves) {
    $src  = Join-Path $BaseDir $m.From
    $dest = Join-Path $BaseDir $m.To

    if (Test-Path $src) {
        Move-Item -Path $src -Destination $dest -Force
        Write-Host "   Moved: $($m.From) -> $($m.To)"
    } elseif (Test-Path $dest) {
        Write-Host "   Already in place: $($m.To)"
    } else {
        Write-Warning "   [WARN]  Not found (skipping): $($m.From)"
    }
}

Write-Host "`n[OK]  Folder structure ready.`n"

# ---------------------------------------------------------------------------
# Helper: upload one file to HF via the commit API
# ---------------------------------------------------------------------------
function Upload-HFFile {
    param(
        [string]$LocalPath,
        [string]$HFPath,
        [string]$CommitMsg
    )

    if (-not (Test-Path $LocalPath)) {
        Write-Warning "[WARN]  Skipping (file not found): $LocalPath"
        return
    }

    $bytes   = [System.IO.File]::ReadAllBytes($LocalPath)
    $b64     = [Convert]::ToBase64String($bytes)

    $payload = @{
        operations   = @(@{
            key   = $HFPath
            type  = "addOrUpdate"
            value = $b64
        })
        summary = $CommitMsg
    } | ConvertTo-Json -Depth 5

    Write-Host "[UPLOAD]  Uploading -> $HFPath"

    $response = Invoke-RestMethod `
        -Uri     "https://huggingface.co/api/spaces/$HFUser/$RepoName/commit/main" `
        -Method  POST `
        -Headers @{
            Authorization  = "Bearer $HFToken"
            "Content-Type" = "application/json"
        } `
        -Body $payload

    Write-Host "   Committed OK"
}

# ---------------------------------------------------------------------------
# Step 3 -- Create the Space
# ---------------------------------------------------------------------------
Write-Host "[START]  Creating HF Space: $HFUser/$RepoName ..."

try {
    $createBody = @{
        name    = $RepoName
        type    = "space"
        sdk     = "static"
        private = $false
    } | ConvertTo-Json

    Invoke-RestMethod `
        -Uri     "https://huggingface.co/api/repos/create" `
        -Method  POST `
        -Headers @{
            Authorization  = "Bearer $HFToken"
            "Content-Type" = "application/json"
        } `
        -Body $createBody | Out-Null

    Write-Host "[OK]  Space created.`n"
} catch {
    if ($_.Exception.Response.StatusCode -eq 409) {
        Write-Host "[INFO]  Space already exists -- continuing with uploads.`n"
    } else {
        throw
    }
}

# ---------------------------------------------------------------------------
# Step 4 -- Upload in priority order
# ---------------------------------------------------------------------------
Write-Host "[SEND]  Starting uploads ...`n"

Upload-HFFile `
    -LocalPath "$BaseDir\README.md" `
    -HFPath    "README.md" `
    -CommitMsg "Add Space card and README"

Upload-HFFile `
    -LocalPath "$BaseDir\CLAUDE.md" `
    -HFPath    "CLAUDE.md" `
    -CommitMsg "Add CLAUDE.md input firewall"

Upload-HFFile `
    -LocalPath "$BaseDir\.cursorrules" `
    -HFPath    ".cursorrules" `
    -CommitMsg "Add .cursorrules input firewall"

Upload-HFFile `
    -LocalPath "$BaseDir\.aiderignore" `
    -HFPath    ".aiderignore" `
    -CommitMsg "Add .aiderignore vision barrier"

Upload-HFFile `
    -LocalPath "$BaseDir\.claude\settings.json" `
    -HFPath    ".claude/settings.json" `
    -CommitMsg "Add Claude Code execution guard settings"

Upload-HFFile `
    -LocalPath "$BaseDir\scripts\run-agent.sh" `
    -HFPath    "scripts/run-agent.sh" `
    -CommitMsg "Add Docker sandbox runtime script"

Upload-HFFile `
    -LocalPath "$BaseDir\hooks\pre-commit" `
    -HFPath    "hooks/pre-commit" `
    -CommitMsg "Add pre-commit local gatekeeper"

Upload-HFFile `
    -LocalPath "$BaseDir\.github\workflows\agent-governance.yml" `
    -HFPath    ".github/workflows/agent-governance.yml" `
    -CommitMsg "Add CI governance workflow"

# ---------------------------------------------------------------------------
Write-Host "[DONE]  All done!"
Write-Host "    https://huggingface.co/spaces/$HFUser/$RepoName"
