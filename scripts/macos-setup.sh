#!/usr/bin/env bash
set -euo pipefail

export PATH="${HOME}/.cargo/bin:${PATH}"

if ! xcode-select -p >/dev/null 2>&1; then
  echo "Install Xcode Command Line Tools first:"
  echo "  xcode-select --install"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "Missing required command: curl"
  exit 1
fi

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

if [[ -f "${HOME}/.cargo/env" ]]; then
  # shellcheck disable=SC1090
  source "${HOME}/.cargo/env"
fi

rustup toolchain install stable
rustup default stable

echo "macOS Rust setup complete."
