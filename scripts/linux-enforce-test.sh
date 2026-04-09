#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_POLICY_PATH="${ROOT_DIR}/.sysguard-enforce-test-policy.yaml"
TEST_UID="$(id -u)"

write_test_policy() {
  cat > "${TEST_POLICY_PATH}" <<EOF
version: 1
default_action: log

ignore:
  comm:
    - "systemd*"
    - "vmtoolsd"
    - "gnome-shell"
    - "gnome-terminal-*"
    - "Xwayland"
    - "xdg-desktop-por*"
    - "gsd-*"
  filename:
    - "/proc/*"
    - "/sys/*"
    - "/run/*"
    - "/usr/share/icons/*"
  ports:
    - 53
  addr:
    - "127.*"

rules:
  - name: block_https_for_current_user
    event: connect
    action: block
    match:
      uid: ${TEST_UID}
      port: 443
EOF
}

run_probe() {
  local output_file
  output_file="$(mktemp)"

  echo "Testing outbound HTTPS block with curl..."
  set +e
  curl -I --max-time 8 https://example.com >"${output_file}" 2>&1
  local status=$?
  set -e

  if [[ ${status} -eq 0 ]]; then
    echo "FAIL: curl succeeded, so HTTPS was not blocked."
    echo
    cat "${output_file}"
    rm -f "${output_file}"
    return 1
  fi

  echo "PASS: curl failed as expected while the blocker was active."
  echo
  cat "${output_file}"
  rm -f "${output_file}"
}

write_test_policy

echo "Wrote test policy to ${TEST_POLICY_PATH}"
echo
echo "Start Sysguard in another terminal with:"
echo "  cd ${ROOT_DIR}"
echo "  sudo ./target/release/sysguard --policy ${TEST_POLICY_PATH} --enforce-connect --uid ${TEST_UID}"
echo
echo "Then rerun this script to validate blocking:"
echo "  ./scripts/linux-enforce-test.sh"
echo

if pgrep -f "sysguard.*--policy ${TEST_POLICY_PATH}.*--enforce-connect" >/dev/null 2>&1; then
  run_probe
else
  echo "Sysguard enforcement process not detected yet. Run the command above first."
fi
