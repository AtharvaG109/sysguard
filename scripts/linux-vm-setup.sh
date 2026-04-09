#!/usr/bin/env bash
set -euo pipefail

export PATH="${HOME}/.cargo/bin:${PATH}"

require_command() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required command: ${cmd}"
    exit 1
  fi
}

install_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y \
      build-essential \
      clang \
      llvm \
      pkg-config \
      libelf-dev \
      curl \
      git \
      ca-certificates
    return
  fi

  if command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y \
      gcc \
      gcc-c++ \
      make \
      clang \
      llvm \
      elfutils-libelf-devel \
      curl \
      git \
      ca-certificates
    return
  fi

  echo "Unsupported package manager. Install Rust, clang/llvm, curl, git, and libelf manually."
  exit 1
}

install_rustup() {
  if command -v rustup >/dev/null 2>&1; then
    return
  fi

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
}

load_cargo_env() {
  if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck disable=SC1090
    source "${HOME}/.cargo/env"
  fi
}

install_packages
install_rustup
load_cargo_env

require_command rustup
require_command cargo

rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

if ! command -v bpf-linker >/dev/null 2>&1; then
  cargo install bpf-linker --locked
fi

require_command bpf-linker

echo "Linux VM setup complete."
