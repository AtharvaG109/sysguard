#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

missing=0

check_command() {
  local name="$1"
  local hint="$2"

  if command -v "$name" >/dev/null 2>&1; then
    printf '[ok] %s found\n' "$name"
  else
    printf '[missing] %s - %s\n' "$name" "$hint"
    missing=1
  fi
}

printf 'sysguard development preflight\n'
printf '==============================\n'

check_command cargo 'install Rust from https://rustup.rs'
check_command rustup 'install Rust from https://rustup.rs'
check_command clang 'install clang/LLVM for eBPF builds'

if [ "$(uname -s)" = "Linux" ]; then
  check_command bpftool 'install bpftool from your Linux package manager'
  check_command sudo 'required for loading eBPF programs and cgroup enforcement'
else
  printf '[info] Linux-only eBPF checks skipped on %s\n' "$(uname -s)"
fi

if command -v cargo >/dev/null 2>&1; then
  printf '[info] cargo version: '
  cargo --version
fi

if [ "$missing" -eq 0 ]; then
  printf '\npreflight passed: required development tools are available.\n'
else
  printf '\npreflight found missing tools. Install them before running Linux eBPF workflows.\n'
fi

exit "$missing"
