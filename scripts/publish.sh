#!/usr/bin/env bash
set -euo pipefail

# This script requires GitHub CLI authentication with permission to create repos.
# Run only after reviewing the project contents.
cd "$(dirname "$0")/.."
if ! command -v gh >/dev/null; then
  echo 'Install GitHub CLI (gh) and run gh auth login first.' >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo 'You must sign in: gh auth login' >&2
  exit 1
fi
if [ -d .git ]; then
  echo 'This folder already has a .git repository; review it before publishing.' >&2
  exit 1
fi
repo="ihatemyfcklife/badsharing-client"
if gh repo view "$repo" >/dev/null 2>&1; then
  echo "$repo already exists; refusing to overwrite an existing repository." >&2
  exit 1
fi
git init -b main
git add .
git commit -m 'feat: initial Linux and Windows desktop P2P client'
gh repo create "$repo" --public --description 'Native encrypted P2P desktop client for Linux and Windows, powered by badsharing and WebRTC' --source . --remote origin --push
echo "Created https://github.com/$repo"
