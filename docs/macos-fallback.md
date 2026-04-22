# macOS Fallback Mode

macOS support is intentionally limited to development and demos.

## What it does

- polls `ps` for process launches
- applies the same YAML policy classification in userspace
- does not provide kernel eBPF enforcement

## Quick start

```bash
./scripts/macos-setup.sh
./scripts/run.sh
```

Use this mode to iterate on policy files or presentation output before validating on Linux.
