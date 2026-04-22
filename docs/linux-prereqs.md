# Linux Prerequisites

`sysguard` is Linux-first when you want kernel eBPF tracing and connect blocking.

## Recommended environment

- Ubuntu VM or host with BTF support
- recent kernel with cgroup and eBPF features enabled
- `clang`, `llvm`, `bpftool`, and Rust toolchain installed

## First run

```bash
./scripts/linux-vm-setup.sh
./scripts/build-release.sh
sudo ./scripts/run.sh --uid 1000
```

## Validation

```bash
./scripts/linux-smoke-test.sh
./scripts/linux-enforce-test.sh
```
