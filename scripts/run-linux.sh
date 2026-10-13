#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v go >/dev/null 2>&1; then
  echo 'Go 1.24+ is required for source builds. End users should install the .deb package instead.' >&2
  exit 1
fi

# Fyne/GLFW source builds require graphics *development* headers. Normal users
# never need them: GitHub release .deb packages contain a precompiled binary.
if ! command -v pkg-config >/dev/null 2>&1 || ! pkg-config --exists wayland-client xkbcommon gl x11 xrandr xcursor xi xinerama || ! command -v gcc >/dev/null 2>&1; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo 'Install your distro OpenGL, X11, Wayland and C compiler development packages.' >&2
    exit 1
  fi
  echo 'Installing one-time Linux developer build prerequisites...'
  sudo apt-get update
  sudo apt-get install -y build-essential pkg-config libgl1-mesa-dev xorg-dev \
    libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev \
    libwayland-dev libxkbcommon-dev wayland-protocols
fi

# Linux Mint: if UFW is enabled, a Polkit authorization prompt is required
# for a temporary LAN-only sharing rule. Install the standard OS helper once.
if [[ -r /etc/ufw/ufw.conf ]] && grep -qiE '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes([[:space:]]*(#.*)?)?$' /etc/ufw/ufw.conf; then
  if ! command -v pkexec >/dev/null 2>&1; then
    echo 'Installing the Linux authorization helper for automatic LAN firewall setup...'
    sudo apt-get install -y pkexec
  fi
fi

go mod tidy
go run ./cmd/badsharing-client
