#!/usr/bin/env bash
set -euo pipefail

echo "Run sysguard with connect enforcement:"
echo "  sudo ./scripts/run.sh --enforce-connect --uid 1000"
echo
echo "Then verify HTTPS blocking:"
echo "  ./scripts/linux-enforce-test.sh"
