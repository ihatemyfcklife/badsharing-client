$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..'))
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'GitHub CLI is required. Install gh and sign in with gh auth login.'
}
& gh auth status | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Run gh auth login first.' }
if (Test-Path .git) { throw 'A Git repository already exists here. Review before publishing.' }
$repo = 'ihatemyfcklife/badsharing-client'
& gh repo view $repo 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { throw "$repo already exists; refusing to replace it." }
& git init -b main
if ($LASTEXITCODE -ne 0) { throw 'git init failed' }
& git add .
& git commit -m 'feat: initial Linux and Windows desktop P2P client'
if ($LASTEXITCODE -ne 0) { throw 'git commit failed: configure your Git identity.' }
& gh repo create $repo --public --description 'Native encrypted P2P desktop client for Linux and Windows, powered by badsharing and WebRTC' --source . --remote origin --push
if ($LASTEXITCODE -ne 0) { throw 'GitHub repository creation failed' }
Write-Host "Created https://github.com/$repo"
