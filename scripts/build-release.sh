#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LINUX_SETUP_SCRIPT="${ROOT_DIR}/scripts/linux-vm-setup.sh"
MACOS_SETUP_SCRIPT="${ROOT_DIR}/scripts/macos-setup.sh"
OS_NAME="$(uname -s)"

export PATH="${HOME}/.cargo/bin:${PATH}"

require_command() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required command: ${cmd}."
    exit 1
  fi
}

if [[ -f "${HOME}/.cargo/env" ]]; then
  # shellcheck disable=SC1090
  source "${HOME}/.cargo/env"
fi

bootstrap_toolchain() {
  local missing=0

  if ! command -v cargo >/dev/null 2>&1; then
    missing=1
  fi
  if ! command -v rustup >/dev/null 2>&1; then
    missing=1
  fi
  if [[ "${OS_NAME}" == "Linux" ]] && ! command -v bpf-linker >/dev/null 2>&1; then
    missing=1
  fi

  if [[ "${missing}" -eq 1 ]]; then
    if [[ "${OS_NAME}" == "Linux" ]]; then
      echo "Bootstrapping Linux Rust/eBPF build dependencies..."
      "${LINUX_SETUP_SCRIPT}"
    elif [[ "${OS_NAME}" == "Darwin" ]]; then
      echo "Bootstrapping macOS Rust build dependencies..."
      "${MACOS_SETUP_SCRIPT}"
    else
      echo "Unsupported operating system: ${OS_NAME}"
      exit 1
    fi
    export PATH="${HOME}/.cargo/bin:${PATH}"
    if [[ -f "${HOME}/.cargo/env" ]]; then
      # shellcheck disable=SC1090
      source "${HOME}/.cargo/env"
    fi
  fi
}

bootstrap_toolchain
require_command cargo
require_command rustup

cd "${ROOT_DIR}"
echo "Cleaning old build artifacts..."
cargo clean

if [[ "${OS_NAME}" == "Linux" ]]; then
  require_command bpf-linker
  rustup toolchain install nightly
  rustup component add rust-src --toolchain nightly
  cargo xtask build-ebpf --release
  cargo build --release -p sysguard
elif [[ "${OS_NAME}" == "Darwin" ]]; then
  cargo build --release -p sysguard
else
  echo "Unsupported operating system: ${OS_NAME}"
  exit 1
fi

echo "Build complete: ${ROOT_DIR}/target/release/sysguard"
