#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="${ROOT_DIR}/target/release/sysguard"
POLICY_PATH="${ROOT_DIR}/policy.yaml"
OS_NAME="$(uname -s)"

if [[ ! -x "${BIN_PATH}" ]]; then
  echo "Missing binary at ${BIN_PATH}. Run ./scripts/build-release.sh first."
  exit 1
fi

if [[ ! -f "${POLICY_PATH}" ]]; then
  echo "Missing policy file at ${POLICY_PATH}."
  exit 1
fi

if [[ "${OS_NAME}" == "Linux" ]]; then
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this script with sudo so the eBPF program can attach."
    exit 1
  fi

  if [[ ! -e /sys/kernel/btf/vmlinux ]]; then
    echo "Missing /sys/kernel/btf/vmlinux. Use a Linux kernel with BTF enabled."
    exit 1
  fi
elif [[ "${OS_NAME}" == "Darwin" ]]; then
  echo "Running macOS fallback mode using process polling."
else
  echo "Unsupported operating system: ${OS_NAME}"
  exit 1
fi

exec "${BIN_PATH}" --policy "${POLICY_PATH}" "$@"
