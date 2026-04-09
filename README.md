# sysguard

`sysguard` is a Rust + eBPF prototype for monitoring Linux process, file, and network activity, with a first enforcement path for outbound IPv4 connects.

Status: public prototype, Linux-first, tested in Ubuntu VM workflows.

It is designed to stay honest about current scope:
- Linux is the primary supported platform.
- macOS support is a fallback process-polling mode for development only.
- Kernel-level blocking currently applies only to a subset of `connect` rules.

## Current Capabilities
- Trace `execve`, `openat`, and `connect` events on Linux with eBPF.
- Apply YAML policy rules to classify activity as `ALLOW`, `LOG`, `ALERT`, or `BLOCK`.
- Suppress noisy system events, deduplicate repeated output, and emit JSON when needed.
- Enforce outbound IPv4 `connect` block rules through a cgroup `connect4` hook.

## Example Policies
- [`policy.yaml`](./policy.yaml): default sample policy used by the helper scripts
- [`examples/alert-only-policy.yaml`](./examples/alert-only-policy.yaml): monitor and alert without kernel blocking
- [`examples/block-https-for-user.yaml`](./examples/block-https-for-user.yaml): minimal example of outbound HTTPS blocking for uid `1000`

## Quick Start
On a Linux VM:
```bash
./scripts/linux-vm-setup.sh
./scripts/build-release.sh
sudo ./scripts/run.sh --uid 1000
```

## Current Limits
- `execve` and `openat` are monitored and classified, but not blocked in-kernel.
- Connect enforcement currently supports exact IPv4 addr and/or port matches.
- The project has been tested as a Linux VM workflow first, especially on Ubuntu.

## Architecture
- **Kernel Space (eBPF)**: Linux tracepoints hook `execve`, `openat`, and `connect`, parse syscall arguments, and stream structured events through an eBPF RingBuffer.
- **Userspace**: Async `tokio` processor loads a YAML policy, matches rules against events, and emits classified outputs such as `ALLOW`, `LOG`, `ALERT`, and `BLOCK`.
- **Linux Enforcement**: An optional cgroup `connect4` eBPF program can enforce a subset of `connect` block rules at kernel level.

## Prerequisites
Linux eBPF mode:
```bash
./scripts/linux-vm-setup.sh
```

macOS fallback mode:
```bash
./scripts/macos-setup.sh
```

## Building
Use the helper script from the workspace root:
```bash
./scripts/build-release.sh
```

## Running
Linux eBPF mode must run on a Linux host with modern kernel BTF support:
```bash
sudo ./scripts/run.sh
```

To enable kernel-level outbound connect blocking for enforceable `action: block` connect rules:
```bash
sudo ./scripts/run.sh --enforce-connect
```

To quickly generate test events in a second terminal:
```bash
./scripts/linux-smoke-test.sh
```

To generate a temporary “block HTTPS for my current user” policy and verify that `curl` gets denied:
```bash
./scripts/linux-enforce-test.sh
```

To show the full unsuppressed Linux event stream:
```bash
sudo ./target/release/sysguard --policy ./policy.yaml --verbose
```

To focus on a single uid:
```bash
sudo ./target/release/sysguard --policy ./policy.yaml --uid 1000
```

To emit machine-readable JSON:
```bash
sudo ./target/release/sysguard --policy ./policy.yaml --output json
```

To attach the connect blocker to a custom cgroup:
```bash
sudo ./target/release/sysguard --policy ./policy.yaml --enforce-connect --cgroup-path /sys/fs/cgroup
```

macOS fallback mode runs without eBPF and polls `ps` for new process launches:
```bash
./scripts/run.sh
```

## Manual Build Steps
If you prefer running the commands yourself:
```bash
cargo xtask build-ebpf --release
cargo build --release -p sysguard
sudo ./target/release/sysguard --policy ./policy.yaml
```

## Publishing
Before pushing this repo publicly:
```bash
git init
git add .
git status
```

Make sure `target/`, temporary test policies, and machine-specific files are not staged. This repository includes a `.gitignore` for those paths.

## Notes
- `cargo build --release` builds the userspace app by default from the workspace root.
- The sample [`policy.yaml`](./policy.yaml) includes example rules for `execve`, `openat`, and `connect`.
- The sample policy also includes a configurable `ignore:` section for noisy processes, paths, ports, and addresses.
- The project is pinned to currently published Aya crate versions so `cargo` can resolve dependencies on a fresh Linux VM.
- On macOS, Sysguard uses a userspace process-polling backend instead of Linux eBPF tracepoints.
- Linux `action: block` rules are classified in userspace, and `connect` rules with exact IPv4 addr and/or port matches can also be enforced at kernel level with `--enforce-connect`.
- Current kernel enforcement is intentionally narrow: outbound IPv4 `connect` only. `execve` and `openat` rules still monitor and classify; they are not blocked in-kernel yet.
- [`scripts/linux-enforce-test.sh`](./scripts/linux-enforce-test.sh) writes a temporary test policy for your current uid and checks that `curl https://example.com` fails when enforcement is active.
- Linux quiet mode suppresses common desktop and system noise by default; use `--verbose` to see everything.
- Linux deduplicates repeated events and emits periodic summary lines instead of spamming identical entries.
