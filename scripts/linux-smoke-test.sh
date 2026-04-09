#!/usr/bin/env bash
set -euo pipefail

echo "Generating execve event..."
/bin/echo "sysguard smoke test" >/dev/null

echo "Generating openat event..."
/bin/cat /etc/hosts >/dev/null

echo "Generating connect event..."
if command -v curl >/dev/null 2>&1; then
  curl -I https://example.com >/dev/null 2>&1 || true
elif command -v wget >/dev/null 2>&1; then
  wget --spider https://example.com >/dev/null 2>&1 || true
else
  echo "Skipping connect event: neither curl nor wget is installed."
fi

echo "Smoke test events generated."
