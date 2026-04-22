#!/usr/bin/env bash
set -euo pipefail

echo "Run sysguard in alert mode in one terminal:"
echo "  sudo ./scripts/run.sh --uid 1000"
echo
echo "Then generate a test event in another terminal:"
echo "  ./scripts/linux-smoke-test.sh"
